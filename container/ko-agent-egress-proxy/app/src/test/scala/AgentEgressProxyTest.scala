package agentsandbox.egress

import java.io.{ByteArrayInputStream, IOException}
import java.net.InetAddress
import java.nio.charset.StandardCharsets

import AgentEgressProxy.*
import HTTPHelper.*
import IPAddrHelper.*
import TLSHelper.*

class AgentEgressProxyTest extends munit.FunSuite:

  test("normalizeHost lowercases and removes one trailing dot"):
    assertEquals(
      normalizeHost("API.Anthropic.COM."),
      "api.anthropic.com"
    )

  test("normalizeHost converts IDN to ASCII"):
    assertEquals(
      normalizeHost("bücher.example"),
      "xn--bcher-kva.example"
    )

  test("CONNECT parser accepts a normal HTTP/1.1 CONNECT"):
    val request = parseConnect(
      "CONNECT api.anthropic.com:443 HTTP/1.1\r\n" +
        "Host: api.anthropic.com:443\r\n" +
        "Proxy-Connection: keep-alive\r\n" +
        "\r\n"
    )

    assertEquals(
      request,
      ConnectRequest("api.anthropic.com", 443)
    )

  test("CONNECT parser rejects a request body framing header"):
    intercept[BadRequest]:
      parseConnect(
        "CONNECT api.anthropic.com:443 HTTP/1.1\r\n" +
          "Content-Length: 0\r\n" +
          "\r\n"
      )

  test("CONNECT parser rejects a non-CONNECT method"):
    intercept[BadRequest]:
      parseConnect("GET https://api.anthropic.com/ HTTP/1.1\r\n\r\n")

  test("the pull hosts are reachable and read-only inspected"):
    // The registry APIs and blob CDNs have no unauthenticated write of their own; membership in
    // the read-only tier is defense in depth plus a method-and-path log line per pull. The one
    // member that needs the tier is storage.googleapis.com — its own test below.
    Vector(
      "registry-1.docker.io", "auth.docker.io",
      "production.cloudflare.docker.com", "production.cloudfront.docker.com",
      "gcr.io", "storage.googleapis.com", "public.ecr.aws",
      "d2glxqk2uabbnd.cloudfront.net", "d5l0dvt14r5h8.cloudfront.net"
    ).foreach: host =>
      assertEquals(authorize(host, 443), host)
      assert(DefaultReadOnlyHosts.contains(host), host)

  test("authorizeRequest rejects ports other than 443"):
    intercept[PolicyViolation]:
      authorize("api.anthropic.com", 8443)

  test("authorizeRequest rejects a hostname outside the allowlist"):
    intercept[PolicyViolation]:
      authorize("example.com", 443)

  test("authorizeRequest rejects every spelling of an IP-literal target"):
    // The first four all resolve to 127.0.0.1 through InetAddress on JDK 25; 8.8.8.8 shows a public literal is
    // refused just the same — the rule is "hostnames only", not "no private targets".
    val literals =
      Vector("127.0.0.1", "2130706433", "127.1", "0177.0.0.1", "8.8.8.8")

    literals.foreach: literal =>
      assert(isIpLiteral(literal), literal)

      intercept[PolicyViolation]:
        authorize(literal, 443)

  test("Smokescreen-class canonicalization tricks reach no non-allowed host"):
    // Permanent regression inputs from Smokescreen's deny-list bypasses: bracketed hostname (GHSA-qwrf-gfpj-qvj6),
    // trailing dot / letter case (GHSA-gcj7-j438-hjj2). An allowlist with one normalizeHost chokepoint keeps every
    // dressing of a non-listed host refused.
    Vector(
      "[example.com]:443",
      "example.com.:443",
      "EXAMPLE.COM:443",
      "ExAmPlE.CoM.:443"
    ).foreach: authority =>
      intercept[PolicyViolation]:
        authorizeRequest(
          ConnectRequest.parse(ascii(s"CONNECT $authority HTTP/1.1\r\n\r\n")),
          DefaultAllowedHosts
        )

  test("an allowed host authorizes to one canonical form however it is spelled"):
    // The other half: every spelling of an allowed host collapses to one canonical name — the one later bound to SNI
    // (validateTlsIdentity).
    Vector(
      "github.com:443",
      "GitHub.COM:443",
      "github.com.:443",
      "[github.com]:443"
    ).foreach: authority =>
      assertEquals(
        authorizeRequest(
          ConnectRequest.parse(ascii(s"CONNECT $authority HTTP/1.1\r\n\r\n")),
          DefaultAllowedHosts
        ),
        "github.com"
      )

  test("isIpLiteral leaves ordinary hostnames alone"):
    Vector(
      "api.anthropic.com",
      "files.pythonhosted.org",
      "xn--bcher-kva.example",
      "host123.example.com"
    ).foreach(host => assert(!isIpLiteral(host), host))

  // ---------------------------------------------------------------------------
  // Policy resolution: one +/- delta per tier, tags on read-only additions,
  // blocked applied last
  // ---------------------------------------------------------------------------

  private def tiersOf(
    readWrite: String = "",
    readOnly: String = "",
    blocked: String = ""
  ): HostTiers =
    def opt(value: String) = Option(value).filter(_.nonEmpty)
    resolveTiers(opt(readWrite), opt(readOnly), opt(blocked))

  test("with no variables set the tiers are the built-in lists"):
    assertEquals(tiersOf(), HostTiers(DefaultReadWriteHosts, DefaultReadOnlyHosts))

  test("a tier delta adds to and removes from its own built-in list"):
    val tiers = tiersOf(readOnly = "+html.spec.whatwg.org -pypi.org")
    assertEquals(
      tiers.readOnly,
      DefaultReadOnlyHosts - "pypi.org" + ("html.spec.whatwg.org" -> Set.empty[String])
    )
    assertEquals(tiers.readWrite, DefaultReadWriteHosts)
    // Normalization applies after the prefix is stripped, and tags after the host.
    assertEquals(
      tiersOf(readOnly = "-GitLab.COM. +Git.Example=git-fetch").readOnly,
      DefaultReadOnlyHosts - "gitlab.com" + ("git.example" -> Set("git-fetch"))
    )

  test("tier entries are enforced in the normalized form they resolve to"):
    // The launcher flattens the files, resolveTiers normalizes the entries, and authorizeRequest normalizes the
    // CONNECT target: whatever spelling either side used, enforcement compares one canonical form.
    val resolved = tiersOf(readOnly = "+Example.ORG.").allowed
    assertEquals(authorizeRequest(ConnectRequest("EXAMPLE.ORG.", 443), resolved), "example.org")
    intercept[PolicyViolation]:
      authorizeRequest(ConnectRequest("example.com", 443), resolved)

  test("an entry without its +/- prefix is refused, and names where replacement lives"):
    // A forgotten prefix must not flip a line's meaning unseen — and the refusal points at where
    // whole-list replacement is spelled instead.
    val ex = intercept[IllegalArgumentException](tiersOf(readOnly = "pypi.org +docs.example"))
    assert(ex.getMessage.contains(".defaults"), ex.getMessage)

  test("a present-but-empty tier variable is refused"):
    intercept[IllegalArgumentException](resolveTiers(Some("   \n "), None, None))
    intercept[IllegalArgumentException](resolveTiers(None, None, Some(" ")))

  test("restating a built-in entry identically is a harmless no-op"):
    // Deliberately not an error: a defensively added host must not start failing when a later image adopts it into the
    // built-in list.
    assertEquals(tiersOf(readOnly = "+pypi.org").readOnly, DefaultReadOnlyHosts)
    assertEquals(tiersOf(readOnly = "+github.com=git-fetch").readOnly, DefaultReadOnlyHosts)

  test("a =git-fetch tag admits git fetch, and retagging is one restated entry"):
    // An addition states its host's complete tagging and overrides the built-in entry for that
    // host — explicit, printed as written at launch, never a merge.
    val mirror = tiersOf(readOnly = "+mirror.example=git-fetch")
    assert(mirror.tagged("git-fetch").contains("mirror.example"))
    authorizeInspectedRequest(
      "mirror.example",
      head(
        "POST /owner/repo.git/git-upload-pack HTTP/1.1\r\n" +
          "Host: mirror.example\r\nContent-Length: 0\r\n\r\n"
      ),
      Set("git-fetch")
    )
    // Revoking: a bare restatement strips the built-in =git-fetch; the host stays read-only.
    val demoted = tiersOf(readOnly = "+gitlab.com")
    assert(!demoted.tagged("git-fetch").contains("gitlab.com"))
    assert(demoted.readOnly.contains("gitlab.com"))
    // Granting is just as explicit — legal, and the entry says exactly what it opens.
    assert(tiersOf(readOnly = "+pypi.org=git-fetch").tagged("git-fetch").contains("pypi.org"))

  test("one host, one tagging: two project entries that disagree are refused"):
    val ex =
      intercept[IllegalArgumentException](tiersOf(readOnly = "+docs.example +docs.example=git-fetch"))
    assert(ex.getMessage.contains("two different taggings"), ex.getMessage)

  test("an unknown tag is refused with the tag list in hand"):
    // The closed set is the guardrail: a tag names a fixed treatment, never describes one — and
    // the port habit (host=8443) fails closed here too.
    val ex = intercept[IllegalArgumentException](tiersOf(readOnly = "+mirror.example=lfs"))
    assert(ex.getMessage.contains("the tags are: git-fetch, npm-audit"), ex.getMessage)
    intercept[IllegalArgumentException](tiersOf(readOnly = "+mirror.example=8443"))

  test("a tag belongs on a read-only addition and nowhere else"):
    intercept[IllegalArgumentException](tiersOf(readWrite = "+api.example=git-fetch"))
    intercept[IllegalArgumentException](tiersOf(readOnly = "-github.com=git-fetch"))
    intercept[IllegalArgumentException](tiersOf(blocked = "github.com=git-fetch"))

  test("adding and removing the same host in one tier is refused"):
    intercept[IllegalArgumentException](tiersOf(readOnly = "+pypi.org -pypi.org"))

  test("a removal matching nothing in its own tier is refused, not a silent no-op"):
    // The sharp fail-open edge: a typo'd '-githib.example' that removed nothing would read as a narrowing that never
    // happened...
    intercept[IllegalArgumentException](tiersOf(readOnly = "-githib.example"))
    // ...and a removal aimed at the wrong tier is the same error: api.anthropic.com is read-write.
    intercept[IllegalArgumentException](tiersOf(readOnly = "-api.anthropic.com"))

  test("delta entries reject IP literals and malformed hostnames like any other"):
    intercept[IllegalArgumentException](tiersOf(readWrite = "+10.0.0.1"))
    intercept[IllegalArgumentException](tiersOf(readOnly = "-pypi.org +api..example"))

  test("a comma joins nothing: entries split on whitespace alone, like the policy files"):
    // A comma-joined pair must not silently become two entries — it stays one token and fails
    // hostname validation, so the mistake is a refused launch, not a policy nobody wrote.
    intercept[IllegalArgumentException](tiersOf(readOnly = "+a.example,+b.example"))
    intercept[IllegalArgumentException](tiersOf(blocked = "gitlab.com,chatgpt.com"))

  test("a -**.domain removal drops the domain and everything under it"):
    val tiers = tiersOf(readOnly = "-**.github.com")
    assert(!tiers.readOnly.contains("github.com"))
    assert(!tiers.readOnly.contains("api.github.com"))
    assert(!tiers.readOnly.contains("codeload.github.com"))
    // A label boundary, not a suffix match: the .githubusercontent.com hosts stay.
    assert(tiers.readOnly.contains("raw.githubusercontent.com"))

  test("a -**.domain matching nothing in its tier is refused"):
    intercept[IllegalArgumentException](tiersOf(readWrite = "-**.github.com"))

  test("a + that falls under a -**.domain is a contradiction, not a precedence"):
    intercept[IllegalArgumentException](tiersOf(readOnly = "-**.github.com +api.github.com=git-fetch"))

  test("a bare -* is not a subtree pattern and is refused"):
    // Only -**.domain is a wildcard; -* is neither a valid pattern nor a host.
    intercept[IllegalArgumentException](tiersOf(readOnly = "-*"))

  test("the undotted -**domain spelling is refused, never suffix-matched"):
    // The pattern's dot is load-bearing: without it the spelling reads as a suffix match (barfoo.com), so it is not a
    // second way to write the subtree removal.
    intercept[IllegalArgumentException](tiersOf(readOnly = "-**pypi.org"))

  test("blocked removes a host from whichever tier holds it"):
    val tiers = tiersOf(blocked = "gitlab.com developer.mozilla.org chatgpt.com")
    assert(!tiers.readOnly.contains("gitlab.com"))
    assert(!tiers.readOnly.contains("developer.mozilla.org"))
    assert(!tiers.readWrite.contains("chatgpt.com"))

  test("blocked beats an addition"):
    assert(!tiersOf(readOnly = "+docs.example", blocked = "docs.example").allowed.contains("docs.example"))

  test("a blocked **.domain subtree crosses tier boundaries"):
    val tiers = tiersOf(blocked = "**.googleapis.com")
    assert(!tiers.readOnly.contains("storage.googleapis.com"))
    assert(!tiers.readWrite.contains("oauth2.googleapis.com"))
    assert(!tiers.readWrite.contains("cloudcode-pa.googleapis.com"))

  test("a blocked entry matching nothing is refused"):
    intercept[IllegalArgumentException](tiersOf(blocked = "example.org"))
    intercept[IllegalArgumentException](tiersOf(blocked = "**.absent.example"))

  test("a +/- prefix in blocked is refused"):
    intercept[IllegalArgumentException](tiersOf(blocked = "-gitlab.com"))

  test(".defaults removes the built-in contribution, never the project's own + entries"):
    // The replacement form: block the defaults, then + back what the project needs. .defaults is
    // not a host matcher — it names the built-in lists, and a host a tier delta explicitly +adds
    // is the project's own entry even when the same host is built in.
    val tiers = tiersOf(
      readWrite = "+api.anthropic.com +claude.ai +platform.claude.com",
      readOnly = "+docs.python.org",
      blocked = ".defaults"
    )
    assertEquals(tiers.readWrite, Set("api.anthropic.com", "claude.ai", "platform.claude.com"))
    assertEquals(tiers.readOnly, Map("docs.python.org" -> Set.empty[String]))

    // An explicit blocked host matches by name and beats everything, the re-add included.
    assertEquals(
      tiersOf(readWrite = "+api.anthropic.com +claude.ai", blocked = ".defaults claude.ai").readWrite,
      Set("api.anthropic.com")
    )

  test(".defaults alone would allow nothing and is refused"):
    intercept[IllegalArgumentException](tiersOf(blocked = ".defaults"))

  test("a host claimed by both tiers is refused"):
    val ex = intercept[IllegalArgumentException](tiersOf(readOnly = "+api.anthropic.com"))
    assert(ex.getMessage.contains("api.anthropic.com is in both read-write and read-only"), ex.getMessage)

  test("--print-policy is one line per tier, in the shape the launcher mints the leaf from"):
    val lines = tierLines(tiersOf())
    assertEquals(lines.length, 2)
    assert(lines(0).startsWith(s"read-write hosts (${DefaultReadWriteHosts.size}): "), lines(0))
    assert(lines(1).startsWith(s"read-only hosts (${DefaultReadOnlyHosts.size}): "), lines(1))
    // Tags travel in the line; the launcher strips them when minting the leaf's names.
    assert(lines(1).contains(" github.com=git-fetch "), lines(1))
    assert(lines(1).contains(" registry.npmjs.org=npm-audit "), lines(1))
    assert(lines(1).contains(" pypi.org "), lines(1))

  test("an emptied tier prints a zero count, parseable like any other line"):
    val emptied = tiersOf(readWrite = "+api.anthropic.com", blocked = ".defaults")
    assertEquals(tierLines(emptied)(1), "read-only hosts (0):")

  test("IPv4 public-destination policy"):
    assert(isPublicDestination(InetAddress.getByName("8.8.8.8")))
    assert(!isPublicDestination(InetAddress.getByName("10.0.0.1")))
    assert(!isPublicDestination(InetAddress.getByName("100.64.0.1")))
    assert(!isPublicDestination(InetAddress.getByName("169.254.169.254")))
    assert(!isPublicDestination(InetAddress.getByName("192.0.2.1")))
    assert(!isPublicDestination(InetAddress.getByName("198.18.0.1")))
    assert(!isPublicDestination(InetAddress.getByName("224.0.0.1")))
    assert(!isPublicDestination(InetAddress.getByName("255.255.255.255")))

  test("IPv6 public-destination policy"):
    assert(
      isPublicDestination(
        InetAddress.getByName("2606:4700:4700::1111")
      )
    )
    assert(!isPublicDestination(InetAddress.getByName("::1")))
    assert(!isPublicDestination(InetAddress.getByName("fc00::1")))
    assert(!isPublicDestination(InetAddress.getByName("fe80::1")))
    assert(!isPublicDestination(InetAddress.getByName("2001:db8::1")))

  test("CIDR handles non-byte-aligned prefixes"):
    val cgnat = Cidr("100.64.0.0", 10)

    assert(cgnat.contains(InetAddress.getByName("100.64.0.1")))
    assert(cgnat.contains(InetAddress.getByName("100.127.255.254")))
    assert(!cgnat.contains(InetAddress.getByName("100.128.0.1")))

  test("readHttpHeader stops exactly at CRLF CRLF"):
    val remaining = Array[Byte](1, 2, 3, 4)
    val input =
      ByteArrayInputStream(
        ascii("CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\n") ++ remaining
      )

    val header = readHttpHeader(input, 4096)

    assertEquals(
      String(header, StandardCharsets.ISO_8859_1),
      "CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\n"
    )
    assertEquals(input.readAllBytes().toVector, remaining.toVector)

  test("readHttpHeader enforces its size bound"):
    intercept[BadRequest]:
      readHttpHeader(
        ByteArrayInputStream(ascii("0123456789\r\n\r\n")),
        8
      )

  test("readHttpHeader tells an unused connection from a half-sent header"):
    // Zero bytes then EOF is routine pooled-client behavior and must not read as a refused
    // request; EOF inside a header stays the BadRequest it always was.
    intercept[ClosedWithoutRequest](readHttpHeader(ByteArrayInputStream(Array.emptyByteArray), 4096))
    intercept[BadRequest](readHttpHeader(ByteArrayInputStream(ascii("GET / HT")), 4096))

  test("a response head parses for status and framing, and malformations blame the origin"):
    val head = HttpResponseHead.parse(
      ascii("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n")
    )
    assertEquals(head.status, 200)
    assertEquals(head.bodyFraming("GET"), BodyFraming.Length(5))
    // Origin-side malformations are IOExceptions — the 502 blames the world, never the client.
    intercept[IOException](HttpResponseHead.parse(ascii("ICY 200 OK\r\n\r\n")))
    intercept[IOException](HttpResponseHead.parse(ascii("HTTP/1.1 abc OK\r\n\r\n")))

  test("response framing: HEAD and status codes without bodies, chunked, and the refusals"):
    def head(lines: String): HttpResponseHead = HttpResponseHead.parse(ascii(lines))

    assertEquals(head("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n").bodyFraming("HEAD"), BodyFraming.Empty)
    assertEquals(head("HTTP/1.1 304 Not Modified\r\n\r\n").bodyFraming("GET"), BodyFraming.Empty)
    assertEquals(head("HTTP/1.1 204 No Content\r\n\r\n").bodyFraming("GET"), BodyFraming.Empty)
    assertEquals(
      head("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n").bodyFraming("GET"),
      BodyFraming.Chunked
    )
    // No framing header: the body runs to the connection's end — this proxy sends
    // Connection: close upstream, so EOF is the terminator there, not a truncation.
    assertEquals(head("HTTP/1.1 200 OK\r\n\r\n").bodyFraming("GET"), BodyFraming.UntilClose)
    assertEquals(head("HTTP/1.1 100 Continue\r\n\r\n").bodyFraming("GET"), BodyFraming.Empty)
    // The request side's ambiguity refusals, as origin faults.
    intercept[IOException](
      head("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n").bodyFraming("GET")
    )
    intercept[IOException](
      head("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n").bodyFraming("GET")
    )
    intercept[IOException](
      head("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n").bodyFraming("GET")
    )

  test("the relayed response head speaks this hop's own Connection: close"):
    // The origin's connection options describe the origin↔proxy leg; the client must hear close
    // from this proxy, whatever the origin sent — a client that misses it reuses or pipelines,
    // and its next request turns the proxy's close into an RST that eats the response's tail.
    val head = HttpResponseHead.parse(
      ascii(
        "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nKeep-Alive: timeout=5\r\n" +
          "Content-Length: 5\r\nETag: \"abc\"\r\n\r\n"
      )
    )
    val relayed = String(head.toClientBytes, StandardCharsets.ISO_8859_1)
    assert(relayed.startsWith("HTTP/1.1 200 OK\r\n"), relayed)
    assert(relayed.endsWith("Connection: close\r\n\r\n"), relayed)
    assert(!relayed.toLowerCase.contains("keep-alive"), relayed)
    assert(relayed.contains("Content-Length: 5\r\n"), relayed)
    assert(relayed.contains("ETag: \"abc\"\r\n"), relayed)

  test("headers the message's own Connection header names are this hop's to remove, both ways"):
    // RFC 9110 §7.6.1's second half: hop-by-hop is not only the fixed set — a peer can declare
    // any header hop-by-hop by naming it in Connection, and forwarding it would leak this hop's
    // negotiation to the other side.
    val request = HttpRequestHead.parse(
      ascii(
        "GET /x HTTP/1.1\r\nHost: docs.python.org\r\nConnection: x-tracing, close\r\n" +
          "X-Tracing: abc\r\nAccept: */*\r\n\r\n"
      )
    )
    val upstream = String(request.toUpstreamBytes, StandardCharsets.ISO_8859_1)
    assert(!upstream.contains("X-Tracing"), upstream)
    assert(upstream.contains("Accept: */*\r\n"), upstream)

    val response = HttpResponseHead.parse(
      ascii("HTTP/1.1 200 OK\r\nConnection: x-server-hint\r\nX-Server-Hint: h2\r\nVary: A\r\n\r\n")
    )
    val relayed = String(response.toClientBytes, StandardCharsets.ISO_8859_1)
    assert(!relayed.contains("X-Server-Hint"), relayed)
    assert(relayed.contains("Vary: A\r\n"), relayed)

  test("HTTP/1.0 is refused by name, at CONNECT and inside the tunnel"):
    // No such client exists here, and half-supporting one — it could not parse a relayed
    // chunked response — would be a silent gap instead of this log line.
    val connect = intercept[BadRequest](
      ConnectRequest.parse(ascii("CONNECT github.com:443 HTTP/1.0\r\n\r\n"))
    )
    assertEquals(connect.getMessage, "HTTP/1.0 is not supported")
    val inTunnel = intercept[BadRequest](
      HttpRequestHead.parse(ascii("GET / HTTP/1.0\r\nHost: github.com\r\n\r\n"))
    )
    assertEquals(inTunnel.getMessage, "HTTP/1.0 is not supported")

  test("Expect: 100-continue is answered by this proxy and never forwarded"):
    // The proxy forwards every body unconditionally, so an origin must not be left waiting for
    // one — and the client must not stall until its own 100 timeout (git's large fetch
    // negotiation sends the Expect).
    val head = HttpRequestHead.parse(
      ascii(
        "POST /r.git/git-upload-pack HTTP/1.1\r\nHost: github.com\r\nExpect: 100-continue\r\n" +
          "Content-Length: 4\r\n\r\n"
      )
    )
    assert(head.expectsContinue)
    val upstream = String(head.toUpstreamBytes, StandardCharsets.ISO_8859_1)
    assert(!upstream.toLowerCase.contains("expect"), upstream)
    assert(!HttpRequestHead.parse(ascii("GET /x HTTP/1.1\r\nHost: a.example\r\n\r\n")).expectsContinue)

  test("forwardResponseBody relays complete bodies and turns early EOF into TruncatedResponse"):
    // The invisible-kill fix: an upstream close inside a declared length must become a loggable
    // failure, never a quiet end the client can mistake for a completed response.
    def relay(bytes: Array[Byte], framing: BodyFraming): Array[Byte] =
      val out = java.io.ByteArrayOutputStream()
      forwardResponseBody(ByteArrayInputStream(bytes), out, framing)
      out.toByteArray

    assertEquals(relay(ascii("hello"), BodyFraming.Length(5)).toVector, ascii("hello").toVector)
    assertEquals(relay(ascii("anything"), BodyFraming.Empty).toVector, Vector.empty)
    assertEquals(relay(ascii("to the end"), BodyFraming.UntilClose).toVector, ascii("to the end").toVector)
    assertEquals(
      relay(ascii("5\r\nhello\r\n0\r\n\r\n"), BodyFraming.Chunked).toVector,
      ascii("5\r\nhello\r\n0\r\n\r\n").toVector
    )

    val short = intercept[TruncatedResponse](relay(ascii("hel"), BodyFraming.Length(5)))
    assert(short.getMessage.contains("truncated"), short.getMessage)
    intercept[TruncatedResponse](relay(ascii("5\r\nhel"), BodyFraming.Chunked))
    // An origin whose chunking cannot be parsed is the same abort, not a 400 at the client.
    intercept[TruncatedResponse](relay(ascii("zz\r\n"), BodyFraming.Chunked))

  // ---------------------------------------------------------------------------
  // The relay on real sockets: loopback pairs, a thread playing the origin, the in-tunnel client
  // observed on the wire. These are the tests that catch what head-level assertions cannot — the
  // bytes a client actually receives, and what a straggling client does to the close.

  private def socketPair(): (java.net.Socket, java.net.Socket) =
    val server = java.net.ServerSocket(0, 1, InetAddress.getLoopbackAddress)
    val connecting = java.net.Socket(InetAddress.getLoopbackAddress, server.getLocalPort)
    val accepted = server.accept()
    server.close()
    (connecting, accepted)

  private def playOrigin(socket: java.net.Socket, response: Array[Byte]): Thread =
    Thread.startVirtualThread: () =>
      try
        readHttpHeader(socket.getInputStream, 64 * 1024)
        socket.getOutputStream.write(response)
        socket.getOutputStream.close()
      catch case _: Exception => ()

  test("relayInspected puts this hop's close on the wire and survives a pipelined straggler"):
    val (client, clientPeer) = socketPair()
    val (upstream, upstreamPeer) = socketPair()
    val origin = playOrigin(
      upstreamPeer,
      ascii("HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 5\r\n\r\nhello")
    )
    // The client pipelines a second request past the close notice, then half-closes: the drain
    // must consume it so the proxy's close stays a clean FIN, never an RST eating the tail.
    clientPeer.getOutputStream.write(ascii("GET /again HTTP/1.1\r\nHost: docs.python.org\r\n\r\n"))
    clientPeer.shutdownOutput()

    val head = HttpRequestHead.parse(ascii("GET /f HTTP/1.1\r\nHost: docs.python.org\r\n\r\n"))
    relayInspected(client, upstream, "docs.python.org", head)
    client.close()
    origin.join()

    val received = String(clientPeer.getInputStream.readAllBytes(), StandardCharsets.ISO_8859_1)
    assert(received.contains("Connection: close\r\n"), received)
    assert(!received.toLowerCase.contains("keep-alive"), received)
    assert(received.endsWith("\r\n\r\nhello"), received)

  test("relayInspected turns an origin that quits mid-body into TruncatedResponse"):
    val (client, clientPeer) = socketPair()
    val (upstream, upstreamPeer) = socketPair()
    val origin = playOrigin(
      upstreamPeer,
      ascii("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhalf")
    )
    clientPeer.shutdownOutput()

    val head = HttpRequestHead.parse(ascii("GET /f HTTP/1.1\r\nHost: docs.python.org\r\n\r\n"))
    intercept[TruncatedResponse]:
      relayInspected(client, upstream, "docs.python.org", head)
    origin.join()

  test("relayInspected answers Expect: 100-continue before the origin says anything"):
    val (client, clientPeer) = socketPair()
    val (upstream, upstreamPeer) = socketPair()
    // The origin answers only after the whole request (head and body) arrives, so a 100 in front
    // of its response can only have come from the proxy.
    val origin = Thread.startVirtualThread: () =>
      try
        readHttpHeader(upstreamPeer.getInputStream, 64 * 1024)
        val body = new Array[Byte](4)
        upstreamPeer.getInputStream.readNBytes(body, 0, 4)
        upstreamPeer.getOutputStream.write(ascii("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
        upstreamPeer.getOutputStream.close()
      catch case _: Exception => ()
    clientPeer.getOutputStream.write(ascii("ping"))
    clientPeer.shutdownOutput()

    val head = HttpRequestHead.parse(
      ascii(
        "POST /r.git/git-upload-pack HTTP/1.1\r\nHost: github.com\r\nExpect: 100-continue\r\n" +
          "Content-Length: 4\r\n\r\n"
      )
    )
    relayInspected(client, upstream, "github.com", head)
    client.close()
    origin.join()

    val received = String(clientPeer.getInputStream.readAllBytes(), StandardCharsets.ISO_8859_1)
    assert(received.startsWith("HTTP/1.1 100 Continue\r\n\r\n"), received)
    assert(received.endsWith("\r\n\r\nok"), received)

  test("relayInspected forwards an origin's own 1xx and frames the body by the final head"):
    val (client, clientPeer) = socketPair()
    val (upstream, upstreamPeer) = socketPair()
    val origin = playOrigin(
      upstreamPeer,
      ascii(
        "HTTP/1.1 100 Continue\r\n\r\n" +
          "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndata"
      )
    )
    clientPeer.shutdownOutput()

    val head = HttpRequestHead.parse(ascii("GET /f HTTP/1.1\r\nHost: docs.python.org\r\n\r\n"))
    relayInspected(client, upstream, "docs.python.org", head)
    client.close()
    origin.join()

    val received = String(clientPeer.getInputStream.readAllBytes(), StandardCharsets.ISO_8859_1)
    assert(received.startsWith("HTTP/1.1 100 Continue\r\n\r\n"), received)
    assert(received.contains("HTTP/1.1 200 OK\r\n"), received)
    assert(received.endsWith("\r\n\r\ndata"), received)

  test("TLS ClientHello extracts SNI"):
    val bytes = clientHello("api.anthropic.com")
    val hello = TlsClientHello.read(
      ByteArrayInputStream(bytes),
      64 * 1024
    )

    assertEquals(hello.serverName, Some("api.anthropic.com"))
    assertEquals(hello.echPresent, false)
    assertEquals(hello.wireBytes.toVector, bytes.toVector)

  test("TLS ClientHello can be fragmented across TLS records"):
    val bytes = clientHello("api.anthropic.com", splitAt = Some(17))
    val hello = TlsClientHello.read(
      ByteArrayInputStream(bytes),
      64 * 1024
    )

    assertEquals(hello.serverName, Some("api.anthropic.com"))
    assertEquals(hello.wireBytes.toVector, bytes.toVector)

  test("TLS parser refuses bytes trailing the ClientHello in its record"):
    intercept[BadTls]:
      TlsClientHello.read(
        ByteArrayInputStream(
          clientHello("api.anthropic.com", trailingInRecord = Array[Byte](0, 0))
        ),
        64 * 1024
      )

  test("TLS ClientHello detects ECH"):
    val hello = TlsClientHello.read(
      ByteArrayInputStream(
        clientHello("api.anthropic.com", ech = true)
      ),
      64 * 1024
    )

    assert(hello.echPresent)

  test("TLS identity validation accepts CONNECT host == SNI"):
    val hello = TlsClientHello.read(
      ByteArrayInputStream(clientHello("api.anthropic.com")),
      64 * 1024
    )

    validateTlsIdentity("api.anthropic.com", hello)

  test("TLS identity validation rejects SNI mismatch"):
    val hello = TlsClientHello.read(
      ByteArrayInputStream(clientHello("example.com")),
      64 * 1024
    )

    intercept[PolicyViolation]:
      validateTlsIdentity("api.anthropic.com", hello)

  test("TLS identity validation rejects ECH"):
    val hello = TlsClientHello.read(
      ByteArrayInputStream(
        clientHello("api.anthropic.com", ech = true)
      ),
      64 * 1024
    )

    intercept[PolicyViolation]:
      validateTlsIdentity("api.anthropic.com", hello)

  test("TLS identity validation rejects a ClientHello carrying no SNI"):
    // The third refusal beside the mismatch and the ECH above. Built directly rather than read off
    // the wire: what is under test is the identity check, and a hello with no server_name extension
    // is exactly the absence the case class already models.
    intercept[PolicyViolation]:
      validateTlsIdentity(
        "api.anthropic.com",
        TlsClientHello(Array.emptyByteArray, None, echPresent = false)
      )

  test("TLS parser rejects a truncated ClientHello"):
    val bytes = clientHello("api.anthropic.com")

    intercept[java.io.EOFException]:
      TlsClientHello.read(
        ByteArrayInputStream(bytes.dropRight(3)),
        64 * 1024
      )

  test("the built-in tiers are disjoint, read-write is the agent endpoints, tags pinned"):
    // Disjointness is load-bearing (resolveTiers would refuse an overlap the lists shipped
    // with); the read-write pin is the privacy boundary: the opaque tier is the hosts whose TLS
    // must not be read — the agent endpoints — and not one host more. The tag pins bound each
    // POST allowance to the hosts that genuinely serve the operation.
    assertEquals(DefaultReadWriteHosts.intersect(DefaultReadOnlyHosts.keySet), Set.empty[String])
    assertEquals(
      DefaultReadWriteHosts,
      Set(
        "api.anthropic.com", "claude.ai", "platform.claude.com",
        "api.openai.com", "auth.openai.com", "chatgpt.com",
        "accounts.google.com", "oauth2.googleapis.com", "cloudcode-pa.googleapis.com"
      )
    )
    assertEquals(
      builtinGitHosts,
      Set(
        "github.com", "raw.githubusercontent.com", "objects.githubusercontent.com",
        "codeload.github.com", "api.github.com", "codeberg.org", "gitlab.com"
      )
    )
    assertEquals(tiersOf().tagged("npm-audit"), Set("registry.npmjs.org"))

  test("the leaf must name exactly the inspected hosts, in either direction"):
    val required = Set("github.com", "gitlab.com")

    assertEquals(TlsInspection.inspectedNamesError(required, required), None)

    // Under-coverage would fail later anyway, as a certificate error inside the sandbox; refusing names it here.
    val missing = TlsInspection.inspectedNamesError(Set("github.com"), required)
    assert(missing.exists(_.contains("does not cover gitlab.com")), missing.toString)

    // Over-coverage is the fail-open direction: a launcher minting a name this proxy does not inspect believes that
    // host is read-only while it tunnels opaquely, writable.
    val extra = TlsInspection.inspectedNamesError(required + "gist.github.com", required)
    assert(extra.exists(_.contains("gist.github.com")), extra.toString)

    // Both at once report both.
    val both = TlsInspection.inspectedNamesError(Set("github.com", "gist.github.com"), required)
    assert(both.exists(r => r.contains("gitlab.com") && r.contains("gist.github.com")), both.toString)

  test("a read-only inspected host allows reading and nothing else"):
    // The tier exists for storage.googleapis.com: all of GCS, where an attacker-signed URL
    // accepts writes — so unlike a =git-fetch host there is no POST exception at all. The sharp case is a
    // POST whose path mimics git-upload-pack: an object name is anyone's to choose, and it must
    // NOT ride the =git-fetch rule through.
    def storage(request: String): Unit =
      authorizeInspectedRequest("storage.googleapis.com", head(request), Set.empty)

    storage("GET /bucket/blobs/sha256:abc?X-Goog-Signature=x HTTP/1.1\r\nHost: storage.googleapis.com\r\n\r\n")
    storage("HEAD /bucket/object HTTP/1.1\r\nHost: storage.googleapis.com\r\n\r\n")

    Vector("PUT", "POST", "PATCH", "DELETE").foreach: method =>
      intercept[PolicyViolation]:
        storage(
          s"$method /bucket/object HTTP/1.1\r\nHost: storage.googleapis.com\r\nContent-Length: 0\r\n\r\n"
        )
    intercept[PolicyViolation]:
      storage(
        "POST /bucket/x/git-upload-pack HTTP/1.1\r\n" +
          "Host: storage.googleapis.com\r\nContent-Length: 0\r\n\r\n"
      )
    // The user-facing concern is not the method name but the channel: a GET carrying a body is
    // an upload wearing a read method, and is refused on every inspected host — the fact named,
    // never a git host blamed for one that is not.
    val bodied = intercept[PolicyViolation]:
      storage(
        "GET /bucket/object HTTP/1.1\r\n" +
          "Host: storage.googleapis.com\r\nContent-Length: 9\r\n\r\n"
      )
    assert(bodied.getMessage.contains("request body"), bodied.getMessage)

    // The other refusal branches carry the tier in their wording too.
    val optioned = intercept[PolicyViolation]:
      storage(
        "OPTIONS /bucket HTTP/1.1\r\nHost: storage.googleapis.com\r\nContent-Length: 0\r\n\r\n"
      )
    assert(optioned.getMessage.contains("read-only host"), optioned.getMessage)

    // Uniform deny-side rules still apply: push ref discovery is refused here as anywhere.
    intercept[PolicyViolation]:
      storage(
        "GET /x/info/refs?service=git-receive-pack HTTP/1.1\r\n" +
          "Host: storage.googleapis.com\r\n\r\n"
      )

    // A documentation site wears the same tier: reads pass, anything else does not.
    authorizeInspectedRequest(
      "developer.mozilla.org",
      head("GET /en-US/docs/Web HTTP/1.1\r\nHost: developer.mozilla.org\r\n\r\n"),
      Set.empty
    )
    intercept[PolicyViolation]:
      authorizeInspectedRequest(
        "developer.mozilla.org",
        head("POST /api/x HTTP/1.1\r\nHost: developer.mozilla.org\r\nContent-Length: 0\r\n\r\n"),
        Set.empty
      )

    // A package registry wears the tier too — security is not traded for performance — so a
    // fetch reads, npm's measured install-time audit POST is its =npm-audit allowance, and an
    // older npm's endpoint (or any other POST) earns an honest refusal.
    authorizeInspectedRequest(
      "registry.npmjs.org",
      head("GET /lodash HTTP/1.1\r\nHost: registry.npmjs.org\r\n\r\n"),
      Set("npm-audit")
    )
    authorizeInspectedRequest(
      "registry.npmjs.org",
      head(
        s"POST $NpmAuditPath HTTP/1.1\r\n" +
          "Host: registry.npmjs.org\r\nContent-Length: 0\r\n\r\n"
      ),
      Set("npm-audit")
    )
    val oldNpm = intercept[PolicyViolation]:
      authorizeInspectedRequest(
        "registry.npmjs.org",
        head(
          "POST /-/npm/v1/security/audits/quick HTTP/1.1\r\n" +
            "Host: registry.npmjs.org\r\nContent-Length: 0\r\n\r\n"
        ),
        Set("npm-audit")
      )
    assert(oldNpm.getMessage.contains("read-only path"), oldNpm.getMessage)
    // The =npm-audit allowance opens nothing on a =git-fetch host, and vice versa.
    intercept[PolicyViolation]:
      authorizeInspectedRequest(
        "github.com",
        head(
          s"POST $NpmAuditPath HTTP/1.1\r\nHost: github.com\r\nContent-Length: 0\r\n\r\n"
        ),
        Set("git-fetch")
      )

  test("HTTP request head parses a request line and its headers"):
    val request = head(
      "GET /owner/repo HTTP/1.1\r\n" +
        "Host: github.com\r\n" +
        "User-Agent: git/2.51.0\r\n" +
        "\r\n"
    )

    assertEquals(request.method, "GET")
    assertEquals(request.target, "/owner/repo")
    assertEquals(request.values("host"), Vector("github.com"))
    assertEquals(request.values("User-Agent"), Vector("git/2.51.0"))

  test("HTTP request head splits a target into path and query"):
    val request = head(
      "GET /owner/repo.git/info/refs?service=git-upload-pack HTTP/1.1\r\n" +
        "Host: github.com\r\n\r\n"
    )

    assertEquals(request.path, "/owner/repo.git/info/refs")
    assertEquals(request.query, "service=git-upload-pack")

  test("HTTP request head rejects an obsolete folded header"):
    intercept[BadRequest]:
      head("GET / HTTP/1.1\r\nHost: github.com\r\n continued\r\n\r\n")

  test("reading a =git-fetch host is allowed"):
    inspected("GET /owner/repo HTTP/1.1\r\nHost: github.com\r\n\r\n")
    inspected("HEAD /owner/repo HTTP/1.1\r\nHost: github.com\r\n\r\n")
    inspected(
      "GET /owner/repo.git/info/refs?service=git-upload-pack HTTP/1.1\r\n" +
        "Host: github.com\r\n\r\n"
    )

  test("a read method may not carry a request body"):
    Vector("GET", "HEAD").foreach: method =>
      intercept[PolicyViolation]:
        inspected(
          s"$method /owner/repo HTTP/1.1\r\nHost: github.com\r\nContent-Length: 5\r\n\r\n"
        )

  test("git fetch is allowed and git push is not"):
    inspected(
      "POST /owner/repo.git/git-upload-pack HTTP/1.1\r\n" +
        "Host: github.com\r\nContent-Length: 0\r\n\r\n"
    )

    intercept[PolicyViolation]:
      inspected(
        "POST /owner/repo.git/git-receive-pack HTTP/1.1\r\n" +
          "Host: github.com\r\nContent-Length: 0\r\n\r\n"
      )

  test("git fetch from a nested GitLab subgroup is allowed, push is not"):
    // gitlab.com nests a repository under arbitrarily deep subgroups; the whole-path rule admits the depth, never a
    // different final segment.
    authorizeInspectedRequest(
      "gitlab.com",
      head(
        "POST /group/subgroup/project.git/git-upload-pack HTTP/1.1\r\n" +
          "Host: gitlab.com\r\nContent-Length: 0\r\n\r\n"
      ),
      Set("git-fetch")
    )

    intercept[PolicyViolation]:
      authorizeInspectedRequest(
        "gitlab.com",
        head(
          "POST /group/subgroup/project.git/git-receive-pack HTTP/1.1\r\n" +
            "Host: gitlab.com\r\nContent-Length: 0\r\n\r\n"
        ),
        Set("git-fetch")
      )

  test("git push ref discovery is refused even though it is a GET"):
    intercept[PolicyViolation]:
      inspected(
        "GET /owner/repo.git/info/refs?service=git-receive-pack HTTP/1.1\r\n" +
          "Host: github.com\r\n\r\n"
      )

  test("git push ref discovery is refused in percent-encoded spellings too"):
    // The origin server decodes before routing, so an encoded spelling asks for the same service; the classification
    // decodes the same way.
    Vector(
      "/owner/repo.git/info/refs?service=git%2Dreceive-pack",
      "/owner/repo.git/info/refs?%73ervice=git-receive-pack",
      "/owner/repo.git/inf%6F/refs?service=git-receive-pack"
    ).foreach: target =>
      intercept[PolicyViolation]:
        inspected(s"GET $target HTTP/1.1\r\nHost: github.com\r\n\r\n")

  test("a malformed percent escape is no receive-pack discovery"):
    // Kept as it is by the decode, it matches nothing an origin would route to receive-pack either; the GET stays an
    // ordinary read.
    inspected(
      "GET /owner/repo.git/info/refs?service=git-receive%2xpack HTTP/1.1\r\n" +
        "Host: github.com\r\n\r\n"
    )

  test("no other method reaches an inspected host"):
    Vector("PUT", "PATCH", "DELETE", "OPTIONS", "TRACE").foreach: method =>
      intercept[PolicyViolation]:
        inspected(
          s"$method /owner/repo HTTP/1.1\r\nHost: github.com\r\nContent-Length: 0\r\n\r\n"
        )

  test("no other path accepts a POST"):
    Vector(
      "/graphql",
      "/owner/repo/issues",
      "/owner/repo.git/git-upload-pack/x",
      // At least owner/repo before the service segment: a single segment is no repository on any forge, and the bare
      // name is not a path.
      "/x/git-upload-pack",
      "/git-upload-pack"
    ).foreach: path =>
      intercept[PolicyViolation]:
        inspected(
          s"POST $path HTTP/1.1\r\nHost: github.com\r\nContent-Length: 0\r\n\r\n"
        )

  test("a write path may not be spelled ambiguously"):
    Vector(
      "/owner/repo.git/%2e%2e/git-upload-pack",
      "/owner/repo.git/../git-upload-pack",
      "/owner/repo.git/./git-upload-pack"
    ).foreach: path =>
      intercept[PolicyViolation]:
        inspected(
          s"POST $path HTTP/1.1\r\nHost: github.com\r\nContent-Length: 0\r\n\r\n"
        )

  test("the Host header must name the host the connection was authorized for"):
    intercept[PolicyViolation]:
      inspected("GET /x HTTP/1.1\r\nHost: evil.example\r\n\r\n")

    inspected("GET /x HTTP/1.1\r\nHost: GitHub.com:443\r\n\r\n")

  test("a Host header naming another port is refused"):
    intercept[BadRequest]:
      inspected("GET /x HTTP/1.1\r\nHost: github.com:8443\r\n\r\n")

  test("only origin-form request targets are accepted"):
    intercept[PolicyViolation]:
      inspected("GET https://github.com/x HTTP/1.1\r\nHost: github.com\r\n\r\n")

  test("HTTP Upgrade is refused"):
    intercept[PolicyViolation]:
      inspected("GET /x HTTP/1.1\r\nHost: github.com\r\nUpgrade: websocket\r\n\r\n")

  test("ambiguous message framing is refused rather than resolved"):
    intercept[BadRequest]:
      inspected(
        "POST /owner/repo.git/git-upload-pack HTTP/1.1\r\nHost: github.com\r\n" +
          "Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"
      )

    intercept[BadRequest]:
      inspected(
        "POST /owner/repo.git/git-upload-pack HTTP/1.1\r\nHost: github.com\r\n" +
          "Content-Length: 5\r\nContent-Length: 6\r\n\r\n"
      )

    intercept[BadRequest]:
      inspected(
        "POST /owner/repo.git/git-upload-pack HTTP/1.1\r\nHost: github.com\r\n" +
          "Transfer-Encoding: gzip\r\n\r\n"
      )

  test("message framing is read from the headers"):
    assertEquals(
      head("GET /x HTTP/1.1\r\nHost: github.com\r\n\r\n").bodyFraming,
      BodyFraming.Empty
    )
    assertEquals(
      head("POST /x HTTP/1.1\r\nHost: github.com\r\nContent-Length: 12\r\n\r\n").bodyFraming,
      BodyFraming.Length(12)
    )
    assertEquals(
      head(
        "POST /x HTTP/1.1\r\nHost: github.com\r\nTransfer-Encoding: chunked\r\n\r\n"
      ).bodyFraming,
      BodyFraming.Chunked
    )

  test("the forwarded request is HTTP/1.1, closes, and drops hop-by-hop headers"):
    val forwarded =
      String(
        head(
          "GET /owner/repo HTTP/1.1\r\n" +
            "Host: github.com\r\n" +
            "Proxy-Connection: keep-alive\r\n" +
            "Proxy-Authorization: Basic x\r\n" +
            "Keep-Alive: timeout=5\r\n" +
            "Accept: */*\r\n" +
            "\r\n"
        ).toUpstreamBytes,
        StandardCharsets.ISO_8859_1
      )

    assertEquals(
      forwarded,
      "GET /owner/repo HTTP/1.1\r\n" +
        "Host: github.com\r\n" +
        "Accept: */*\r\n" +
        "Connection: close\r\n\r\n"
    )

  test("chunked lines are read up to CRLF and bounded"):
    val input = ByteArrayInputStream(ascii("1a;ext\r\nrest"))

    assertEquals(readCrLfLine(input, 64), "1a;ext")

    intercept[BadRequest]:
      readCrLfLine(ByteArrayInputStream(ascii("0123456789\r\n")), 4)

  test("audit lines are verb host method [target] tail, with - for fields never learned"):
    // The stable head SECURITY.md ("The audit line grammar") documents: fields 1-3 always
    // present, the target exactly when a parsed inspected request exists, the rest human text.
    assertEquals(
      auditLine("allow", "github.com", "GET", "/r?tab=readme", "-> 140.82.112.3"),
      "allow github.com GET /r?tab=readme -> 140.82.112.3"
    )
    assertEquals(
      auditLine("allow", "api.anthropic.com", "CONNECT", "", "-> 160.79.104.10"),
      "allow api.anthropic.com CONNECT -> 160.79.104.10"
    )
    assertEquals(
      auditLine("deny", "tracker.example", "CONNECT", "", "host not allowed"),
      "deny tracker.example CONNECT host not allowed"
    )
    assertEquals(
      auditLine("deny", "-", "-", "", "invalid CONNECT port"),
      "deny - - invalid CONNECT port"
    )
    assertEquals(
      auditLine("deny", "github.com", "POST", "/r.git/git-receive-pack", "read-only path"),
      "deny github.com POST /r.git/git-receive-pack read-only path"
    )

  test("the audit tee writes and flushes every byte to both sinks"):
    val a = java.io.ByteArrayOutputStream()
    val b = java.io.ByteArrayOutputStream()
    val tee = java.io.PrintStream(teeOutput(a, b), true)

    tee.println("allow github.com")
    tee.write('x')
    tee.flush()

    assertEquals(a.toByteArray.toVector, b.toByteArray.toVector)
    assert(String(a.toByteArray, StandardCharsets.US_ASCII).startsWith("allow github.com"))

  private def head(value: String): HttpRequestHead =
    HttpRequestHead.parse(ascii(value))

  /** The built-in =git-fetch hosts, as the resolved default policy carries them. */
  private lazy val builtinGitHosts: Set[String] = tiersOf().tagged("git-fetch")

  private def inspected(value: String): Unit =
    authorizeInspectedRequest("github.com", head(value), Set("git-fetch"))

  private def parseConnect(value: String): ConnectRequest =
    ConnectRequest.parse(ascii(value))

  private def authorize(host: String, port: Int): String =
    authorizeRequest(
      ConnectRequest(host, port),
      DefaultAllowedHosts
    )

  private def clientHello(
    serverName: String,
    ech: Boolean = false,
    splitAt: Option[Int] = None,
    trailingInRecord: Array[Byte] = Array.emptyByteArray
  ): Array[Byte] =
    val sniBytes = ascii(serverName)

    val serverNameEntry =
      Array[Byte](0) ++ u16(sniBytes.length) ++ sniBytes

    val serverNameExtensionData =
      u16(serverNameEntry.length) ++ serverNameEntry

    val serverNameExtension =
      u16(0x0000) ++
        u16(serverNameExtensionData.length) ++
        serverNameExtensionData

    val echExtension =
      if ech then u16(0xfe0d) ++ u16(1) ++ Array[Byte](0)
      else Array.emptyByteArray

    val extensions = serverNameExtension ++ echExtension

    val payload =
      u16(0x0303) ++                    // legacy_version
        Array.fill[Byte](32)(0x42) ++   // random
        Array[Byte](0) ++               // legacy_session_id
        u16(2) ++ u16(0x1301) ++        // one cipher suite
        Array[Byte](1, 0) ++             // compression_methods = { null }
        u16(extensions.length) ++
        extensions

    val handshake =
      Array[Byte](1) ++ u24(payload.length) ++ payload

    splitAt match
      case None => tlsRecord(handshake ++ trailingInRecord)
      case Some(index) =>
        require(index > 0 && index < handshake.length)
        tlsRecord(handshake.take(index)) ++
          tlsRecord(handshake.drop(index))

  private def tlsRecord(payload: Array[Byte]): Array[Byte] =
    Array[Byte](22, 3, 3) ++ u16(payload.length) ++ payload

  private def ascii(value: String): Array[Byte] =
    value.getBytes(StandardCharsets.US_ASCII)

  private def u16(value: Int): Array[Byte] =
    Array(
      ((value >>> 8) & 0xff).toByte,
      (value & 0xff).toByte
    )

  private def u24(value: Int): Array[Byte] =
    Array(
      ((value >>> 16) & 0xff).toByte,
      ((value >>> 8) & 0xff).toByte,
      (value & 0xff).toByte
    )
