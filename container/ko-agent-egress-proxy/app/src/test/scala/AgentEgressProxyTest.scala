package agentsandbox.egress

import java.io.ByteArrayInputStream
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

  test("authorizeRequest accepts an allowed host on port 443"):
    assertEquals(
      authorize("API.Anthropic.com.", 443),
      "api.anthropic.com"
    )

  test("authorizeRequest accepts the forge read hosts in the default list"):
    assertEquals(authorize("github.com", 443), "github.com")
    assertEquals(
      authorize("raw.githubusercontent.com", 443),
      "raw.githubusercontent.com"
    )
    assertEquals(authorize("gitlab.com", 443), "gitlab.com")
    assertEquals(authorize("codeberg.org", 443), "codeberg.org")

  test("the default list carries each agent's sign-in and model endpoints"):
    Vector(
      // Claude Code
      "api.anthropic.com", "claude.ai", "platform.claude.com",
      // Codex: API-key use, and the ChatGPT device-code sign-in the README documents
      "api.openai.com", "auth.openai.com", "chatgpt.com",
      // Antigravity
      "accounts.google.com", "oauth2.googleapis.com", "cloudcode-pa.googleapis.com"
    ).foreach: host =>
      assertEquals(authorize(host, 443), host)

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
  // Policy resolution: the replacement form, and the +host / -host delta
  // against the built-in list
  // ---------------------------------------------------------------------------

  private val builtin = Set("github.com", "pypi.org", "docs.python.org")

  test("a replacement policy splits, normalizes and de-duplicates"):
    assertEquals(
      resolvePolicy(" api.anthropic.com, PyPI.org\n  api.anthropic.com. ", builtin),
      Set("api.anthropic.com", "pypi.org")
    )

  test("policy entries are enforced in the normalized form they resolve to"):
    // The launcher flattens the file, resolvePolicy normalizes the entries, and authorizeRequest normalizes the
    // CONNECT target: whatever spelling either side used, enforcement compares one canonical form.
    val resolved = resolvePolicy("GitHub.COM. Example.org", builtin)
    assertEquals(authorizeRequest(ConnectRequest("github.com", 443), resolved), "github.com")
    assertEquals(authorizeRequest(ConnectRequest("EXAMPLE.ORG.", 443), resolved), "example.org")
    intercept[PolicyViolation]:
      authorizeRequest(ConnectRequest("example.com", 443), resolved)

  test("an empty policy is refused"):
    intercept[IllegalArgumentException]:
      resolvePolicy("   \n ", builtin)

  test("a replacement policy rejects an IP literal"):
    intercept[IllegalArgumentException]:
      resolvePolicy("api.anthropic.com 10.0.0.1", builtin)

  test("a replacement policy rejects a malformed hostname"):
    intercept[IllegalArgumentException]:
      resolvePolicy("api..anthropic.com", builtin)

  test("a replacement policy is the whole allowlist, ignoring the built-in list"):
    assertEquals(resolvePolicy("api.anthropic.com pypi.org", builtin), Set("api.anthropic.com", "pypi.org"))

  test("a delta adds to and removes from the built-in list"):
    // + adds a new host, - drops one; the rest of the built-in list stays.
    assertEquals(
      resolvePolicy("+api.anthropic.com -github.com", builtin),
      Set("api.anthropic.com", "pypi.org", "docs.python.org")
    )
    // Normalization applies after the prefix is stripped.
    assertEquals(
      resolvePolicy("-GitHub.COM. +Extra.Example", builtin),
      Set("pypi.org", "docs.python.org", "extra.example")
    )

  test("a delta adding a host already built in is a harmless no-op"):
    // Deliberately not an error: a defensively added host must not start failing when a later image adopts it into the
    // built-in list.
    assertEquals(resolvePolicy("+pypi.org", builtin), builtin)

  test("mixing delta and replacement entries is refused"):
    intercept[IllegalArgumentException]:
      resolvePolicy("+api.anthropic.com pypi.org", builtin)

  test("adding and removing the same host is refused"):
    intercept[IllegalArgumentException]:
      resolvePolicy("+github.com -github.com", builtin)

  test("removing a host the built-in list lacks is refused, not a silent no-op"):
    // The sharp fail-open edge: a typo'd '-githib.com' that removed nothing would read as a narrowing that never
    // happened.
    intercept[IllegalArgumentException]:
      resolvePolicy("-githib.com", builtin)

  test("a delta that empties the allowlist is refused"):
    intercept[IllegalArgumentException]:
      resolvePolicy("-github.com -pypi.org -docs.python.org", builtin)

  test("delta entries reject IP literals and malformed hostnames like any other"):
    intercept[IllegalArgumentException]:
      resolvePolicy("+10.0.0.1", builtin)
    intercept[IllegalArgumentException]:
      resolvePolicy("-github.com +api..example", builtin)

  test("a -**.domain removal drops the domain and everything under it"):
    // Apex and subdomains go; a look-alike that only shares a suffix without a label boundary stays (evilgithub.com is
    // not under github.com).
    val tree = Set("github.com", "api.github.com", "codeberg.org", "evilgithub.com")
    assertEquals(
      resolvePolicy("-**.github.com", tree),
      Set("codeberg.org", "evilgithub.com")
    )

  test("a -**.domain matching nothing in the built-in list is refused"):
    intercept[IllegalArgumentException]:
      resolvePolicy("-**.absent.example", builtin)

  test("a + that falls under a -**.domain is a contradiction, not a precedence"):
    intercept[IllegalArgumentException]:
      resolvePolicy("-**.github.com +api.github.com", Set("github.com", "api.github.com"))

  test("a -**.domain composes with adds and exact removals"):
    assertEquals(
      resolvePolicy("-**.github.com -pypi.org +docs.rs", builtin ++ Set("api.github.com")),
      Set("docs.python.org", "docs.rs")
    )

  test("a bare -* is not a subtree pattern and is refused"):
    // Only -**.domain is a wildcard; -* is neither a valid pattern nor a host.
    intercept[IllegalArgumentException]:
      resolvePolicy("-*", builtin)

  test("the undotted -**domain spelling is refused, never suffix-matched"):
    // The pattern's dot is load-bearing: without it the spelling reads as a suffix match (barfoo.com), so it is not a
    // second way to write the subtree removal.
    intercept[IllegalArgumentException]:
      resolvePolicy("-**github.com", builtin)

  test("--proxy-allowed's inspection line is the forges left after resolution"):
    // What printPolicy reports for inspection: DefaultInspectedHosts ∩ the
    // resolved allowlist. A delta dropping one forge drops exactly it; the
    // launcher prints this same line in every launch banner, from its
    // --print-policy dry run of this image.
    assertEquals(
      DefaultInspectedHosts.intersect(resolvePolicy("-github.com", DefaultAllowedHosts)),
      DefaultInspectedHosts - "github.com"
    )
    assertEquals(
      DefaultInspectedHosts.intersect(resolvePolicy("+docs.example", DefaultAllowedHosts)),
      DefaultInspectedHosts
    )

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

  test("TLS parser rejects a truncated ClientHello"):
    val bytes = clientHello("api.anthropic.com")

    intercept[java.io.EOFException]:
      TlsClientHello.read(
        ByteArrayInputStream(bytes.dropRight(3)),
        64 * 1024
      )

  test("every inspected host is one the proxy is allowed to reach"):
    assertEquals(
      DefaultInspectedHosts -- DefaultAllowedHosts,
      Set.empty[String]
    )

  test("the leaf must name exactly the built-in inspected set, in either direction"):
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

  test("reading a forge is allowed"):
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
      )
    )

    intercept[PolicyViolation]:
      authorizeInspectedRequest(
        "gitlab.com",
        head(
          "POST /group/subgroup/project.git/git-receive-pack HTTP/1.1\r\n" +
            "Host: gitlab.com\r\nContent-Length: 0\r\n\r\n"
        )
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
          "GET /owner/repo HTTP/1.0\r\n" +
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

  private def inspected(value: String): Unit =
    authorizeInspectedRequest("github.com", head(value))

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
