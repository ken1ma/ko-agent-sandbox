// The upstream transport: HTTPS_PROXY's parser, and the CONNECT state machine against a
// scripted upstream proxy on loopback. Every failure here is asserted twice — for the outcome
// and for the credential's absence from it — because the message is what reaches the audit log
// and the sandbox's 502 body.

package agentsandbox.egress

import java.io.{ByteArrayOutputStream, IOException, PrintStream}
import java.net.{InetAddress, ServerSocket, Socket}
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.time.Instant
import java.util.Base64
import java.util.concurrent.atomic.AtomicReference

import AgentEgressProxy.*
import HTTPHelper.*
import RulesetHelper.*
import TLSHelper.*
import TransportHelper.*

class TransportHelperTest extends munit.FunSuite:

  private val Secret = "s3cr%40t"
  private val SecretDecoded = "s3cr@t"
  private val Basic =
    "Basic " + Base64.getEncoder.encodeToString(s"alice:$SecretDecoded".getBytes(StandardCharsets.UTF_8))

  private def parse(value: String): UpstreamEndpoint = UpstreamEndpoint.parse(value, "HTTPS_PROXY")

  private def refusal(value: String): String =
    val message = intercept[IllegalArgumentException](parse(value)).getMessage
    assert(message.startsWith("HTTPS_PROXY "), message)
    assert(!message.contains(Secret) && !message.contains(SecretDecoded) && !message.contains("alice"), message)
    message

  test("HTTPS_PROXY's accepted forms: scheme, name or literal, explicit port, an optional slash"):
    assertEquals(
      parse("http://Proxy.Corp.Example:3128"),
      UpstreamEndpoint("HTTPS_PROXY", false, "proxy.corp.example", None, 3128, None),
    )
    assertEquals(
      parse("https://proxy.corp.example:8443/"),
      UpstreamEndpoint("HTTPS_PROXY", true, "proxy.corp.example", None, 8443, None),
    )
    val v4 = InetAddress.getByName("10.1.2.3")
    assertEquals(
      parse("http://10.1.2.3:3128"),
      UpstreamEndpoint("HTTPS_PROXY", false, "10.1.2.3", Some(v4), 3128, None),
    )
    val v6 = InetAddress.getByName("2001:db8::1")
    assertEquals(
      parse("http://[2001:db8::1]:3128"),
      UpstreamEndpoint("HTTPS_PROXY", false, "2001:db8::1", Some(v6), 3128, None),
    )
    assertEquals(parse("http://[2001:db8::1]:3128").spelled, "http://[2001:db8::1]:3128")
    assertEquals(parse("http://bücher.example:1").host, "xn--bcher-kva.example")

  test("userinfo becomes one Basic value, percent-decoded, and is absent from what is printed"):
    val endpoint = parse(s"http://alice:$Secret@proxy.corp.example:3128")
    assertEquals(endpoint.authorization, Some(Basic))
    assertEquals(endpoint.spelled, "http://proxy.corp.example:3128")
    def basic(credential: String): Option[String] =
      Some("Basic " + Base64.getEncoder.encodeToString(credential.getBytes(StandardCharsets.UTF_8)))
    // A user alone is a user with an empty password, as curl sends it.
    assertEquals(parse("http://alice@proxy.corp.example:3128").authorization, basic("alice:"))
    // The password may hold a colon; only the user may not, being what the colon delimits.
    assertEquals(parse("http://alice:a:b@proxy.corp.example:3128").authorization, basic("alice:a:b"))
    // A literal non-ASCII character and its percent-encoding are one credential, a supplementary
    // character included.
    assertEquals(parse("http://alice:pässword@proxy.corp.example:3128").authorization, basic("alice:pässword"))
    assertEquals(parse("http://alice:p%C3%A4ssword@proxy.corp.example:3128").authorization, basic("alice:pässword"))
    assertEquals(parse("http://alice:\uD83D\uDD11@proxy.corp.example:3128").authorization, basic("alice:\uD83D\uDD11"))
    assert(refusal(s"http://ali%3Ace:$Secret@proxy.corp.example:3128").contains("':'"))
    assert(refusal(s"http://:$Secret@proxy.corp.example:3128").contains("empty user"))
    assert(refusal(s"http://alice:%zz@proxy.corp.example:3128").contains("percent-escape"))
    assert(refusal(s"http://alice:%4@proxy.corp.example:3128").contains("percent-escape"))
    assert(refusal(s"http://alice:%00@proxy.corp.example:3128").contains("control character"))

  test("HTTPS_PROXY's refusals name the part that is wrong, never the value"):
    assert(refusal("proxy.corp.example:3128").contains("http:// or https://"))
    assert(refusal(s"ftp://alice:$Secret@proxy.corp.example:3128").contains("http:// or https://"))
    assert(refusal(s"http://alice:$Secret@proxy.corp.example").contains("port must be explicit"))
    assert(refusal("http://proxy.corp.example:0").contains("port must be explicit"))
    assert(refusal("http://proxy.corp.example:65536").contains("port must be explicit"))
    assert(refusal("http://proxy.corp.example:abc").contains("port must be explicit"))
    assert(refusal("http://proxy.corp.example:3128/path").contains("path"))
    assert(refusal("http://proxy.corp.example:3128/?x").contains("query or fragment"))
    assert(refusal("http://proxy.corp.example:3128#f").contains("query or fragment"))
    assert(refusal(s"http://alice:$Secret@proxy.corp.example:3128 ").contains("whitespace"))
    assert(refusal("http://proxy.corp.example:3128\r").contains("control character"))
    assert(refusal("http://2001:db8::1:3128").contains("brackets"))
    assert(refusal("http://[10.0.0.1]:3128").contains("IPv6 literal"))
    assert(refusal("http://[2001:db8::1]").contains("without a port"))
    assert(refusal("http://:3128").contains("empty host"))
    assert(refusal("http://127.0.0.1.1:3128").contains("neither a hostname nor an IP literal"))
    assert(refusal("http://-bad-.example:3128").contains("not a hostname"))

  test("the variable is read uppercase first, then lowercase; empty is unset"):
    def read(values: Map[String, String]): Option[UpstreamEndpoint] = UpstreamEndpoint.configured(values.get)
    assertEquals(read(Map.empty), None)
    assertEquals(read(Map("HTTPS_PROXY" -> "")), None)
    assertEquals(read(Map("https_proxy" -> "http://lower.example:1")).map(_.host), Some("lower.example"))
    // The lowercase variable is diagnosed and reported as itself.
    val lower = intercept[IllegalArgumentException](read(Map("https_proxy" -> "http://lower.example"))).getMessage
    assert(lower.startsWith("https_proxy "), lower)
    assertEquals(
      originTransport(Map("https_proxy" -> "http://10.1.2.3:3128").get).summary,
      "egress transport: upstream proxy http://10.1.2.3:3128 -> 10.1.2.3 (https_proxy)",
    )
    assertEquals(
      read(Map("HTTPS_PROXY" -> "http://upper.example:1", "https_proxy" -> "http://lower.example:1")).map(_.host),
      Some("upper.example"),
    )
    assertEquals(originTransport(Map.empty[String, String].get), Direct)
    assertEquals(
      originTransport(Map("HTTPS_PROXY" -> "http://10.1.2.3:3128").get).summary,
      "egress transport: upstream proxy http://10.1.2.3:3128 -> 10.1.2.3 (HTTPS_PROXY)",
    )

  test("the endpoint may be private or loopback; an unresolvable name ends the start"):
    assertEquals(parse("http://10.1.2.3:3128").resolve().map(_.getHostAddress), Vector("10.1.2.3"))
    assertEquals(parse("http://127.0.0.1:3128").resolve().map(_.getHostAddress), Vector("127.0.0.1"))
    val unresolvable = intercept[IOException](parse("http://no-such-proxy.invalid:3128").resolve())
    assert(unresolvable.getMessage.startsWith("the upstream proxy http://no-such-proxy.invalid:3128 does not resolve"))

  // ---------------------------------------------------------------------------
  // The CONNECT state machine, against a scripted upstream proxy on loopback
  // ---------------------------------------------------------------------------

  private val loopback = InetAddress.getLoopbackAddress
  private val OriginV4 = InetAddress.getByName("93.184.216.34")
  private val OriginV4Other = InetAddress.getByName("93.184.216.35")
  private val OriginV6 = InetAddress.getByName("2606:2800:220:1:248:1893:25c8:1946")
  private val Established = "HTTP/1.1 200 Connection established\r\n\r\n"
  private val TunnelBanner = "tunnel-open"

  /**
   * One scripted connection per response: the CONNECT head is recorded, the response written —
   * cut to `truncateAt` bytes when set — and after a 2xx the banner follows on the same stream,
   * which is how a test proves the socket it got back is the tunnel. The listener closes after
   * the script, so an attempt the script did not expect is a refused connection, not a hang.
   */
  private class ScriptedProxy(script: Vector[String], truncateAt: Option[Int] = None):
    private val server = ServerSocket(0, 8, loopback)
    val port: Int = server.getLocalPort
    val received = AtomicReference(Vector.empty[String])
    private val thread = Thread.startVirtualThread: () =>
      try
        script.foreach: response =>
          val socket = server.accept()
          try
            val head = String(readHttpHeader(socket.getInputStream, 64 * 1024), StandardCharsets.ISO_8859_1)
            received.updateAndGet(_ :+ head)
            val bytes = ascii(response)
            socket.getOutputStream.write(bytes, 0, truncateAt.fold(bytes.length)(math.min(_, bytes.length)))
            socket.getOutputStream.flush()
            if truncateAt.isEmpty && response.startsWith("HTTP/1.1 2") then
              socket.getOutputStream.write(ascii(TunnelBanner))
              socket.getOutputStream.flush()
          finally socket.close()
      catch case _: Exception => ()
      finally server.close()

    def endpoint(authorization: Option[String] = None): UpstreamProxy =
      val endpoint = UpstreamEndpoint("HTTPS_PROXY", false, "127.0.0.1", Some(loopback), port, authorization)
      UpstreamProxy(endpoint, Vector(loopback))

    /** Ends the script: whatever it still expected is not coming, and a connection it did not
      * expect is refused from here on. */
    def close(): Unit =
      server.close()
      thread.join()

  private def ascii(value: String): Array[Byte] = value.getBytes(StandardCharsets.US_ASCII)

  /** The failure's message, after asserting it names the credential nowhere and that `attempted`
    * is exactly the addresses the upstream proxy was asked for. */
  private def failure(
    proxy: ScriptedProxy,
    addresses: Vector[InetAddress],
    authorization: Option[String] = None,
    attempted: Vector[InetAddress] = Vector(OriginV4),
  ): String =
    val failure = intercept[TransportFailure](proxy.endpoint(authorization).connect(addresses, 443))
    val message = failure.getMessage
    assert(!message.contains(Basic) && !message.contains(SecretDecoded), message)
    assertEquals(failure.attempted, attempted, message)
    proxy.close()
    message

  test("a 2xx yields the tunnel socket, the vetted address, and a numeric CONNECT with the credential alone"):
    val proxy = ScriptedProxy(Vector(Established, Established))
    val origin = proxy.endpoint(Some(Basic)).connect(Vector(OriginV4), 443)
    assertEquals(origin.address, OriginV4)
    assertEquals(String(origin.socket.getInputStream.readAllBytes(), StandardCharsets.US_ASCII), TunnelBanner)
    origin.socket.close()
    val v6 = proxy.endpoint().connect(Vector(OriginV6), 443)
    assertEquals(v6.address, OriginV6)
    v6.socket.close()
    proxy.close()
    assertEquals(
      proxy.received.get,
      Vector(
        s"CONNECT 93.184.216.34:443 HTTP/1.1\r\nHost: 93.184.216.34:443\r\nProxy-Authorization: $Basic\r\n\r\n",
        "CONNECT [2606:2800:220:1:248:1893:25c8:1946]:443 HTTP/1.1\r\n" +
          "Host: [2606:2800:220:1:248:1893:25c8:1946]:443\r\n\r\n",
      ),
    )

  test("a 5xx meaning the origin was unreachable moves to the next vetted address; any other status ends it"):
    val next = ScriptedProxy(Vector("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n", Established))
    val origin = next.endpoint().connect(Vector(OriginV4, OriginV4Other), 443)
    assertEquals(origin.address, OriginV4Other)
    origin.socket.close()
    next.close()
    assertEquals(
      next.received.get.map(_.takeWhile(_ != '\r')),
      Vector("CONNECT 93.184.216.34:443 HTTP/1.1", "CONNECT 93.184.216.35:443 HTTP/1.1"),
    )

    val exhausted = ScriptedProxy(Vector("HTTP/1.1 504 Gateway Timeout\r\n\r\n", "HTTP/1.1 503 Down\r\n\r\n"))
    assertEquals(
      failure(exhausted, Vector(OriginV4, OriginV4Other), attempted = Vector(OriginV4, OriginV4Other)),
      "upstream proxy returned 503",
    )

    // A second scripted 200 would be reached by a retry; these must not retry, so it is never read.
    Vector(
      "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"corp\"\r\n\r\n" ->
        "upstream proxy authentication required",
      "HTTP/1.1 403 Forbidden\r\nContent-Length: 11\r\n\r\nsecret-body" -> "upstream proxy returned 403",
      "HTTP/1.1 301 Moved\r\nLocation: http://elsewhere.example/\r\n\r\n" -> "upstream proxy returned 301",
      "HTTP/1.1 100 Continue\r\n\r\n" -> "upstream proxy answered a CONNECT with an informational response",
      "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello" -> "upstream proxy answered 2xx with body framing",
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" -> "upstream proxy answered 2xx with body framing",
    ).foreach: (response, expected) =>
      val proxy = ScriptedProxy(Vector(response, Established))
      val message = failure(proxy, Vector(OriginV4, OriginV4Other), Some(Basic))
      assertEquals(message, expected, response)
      assert(!message.contains("secret-body") && !message.contains("elsewhere"), message)
      assertEquals(proxy.received.get.size, 1, response)

  test("a malformed, truncated or oversized response head is a failure naming the upstream proxy"):
    assertEquals(
      failure(ScriptedProxy(Vector("HTTP/2 200\r\n\r\n")), Vector(OriginV4)),
      "upstream proxy response head: status line 'HTTP/2 200'",
    )
    assertEquals(
      failure(ScriptedProxy(Vector("HTTP/1.1 abc\r\n\r\n")), Vector(OriginV4)),
      "upstream proxy response head: status 'abc'",
    )
    assertEquals(
      failure(ScriptedProxy(Vector("HTTP/1.1 200 OK\r\nbad header\r\n\r\n")), Vector(OriginV4)),
      "upstream proxy response head: malformed HTTP header",
    )
    assertEquals(
      failure(
        ScriptedProxy(Vector("HTTP/1.1 200 OK\r\n" + "X: " + "y" * (MaxHttpHeaderBytes + 1) + "\r\n\r\n")),
        Vector(OriginV4),
      ),
      s"upstream proxy response head: HTTP header exceeds $MaxHttpHeaderBytes bytes",
    )
    // Close at every byte of a 200: none of them is a tunnel.
    (0 until Established.length).foreach: cut =>
      val message = failure(ScriptedProxy(Vector(Established), truncateAt = Some(cut)), Vector(OriginV4), Some(Basic))
      val expected =
        if cut == 0 then "upstream proxy closed before answering the CONNECT"
        else "upstream proxy response head: connection closed before HTTP header completed"
      assertEquals(message, expected, s"cut at $cut")

  test("an unreachable endpoint ends the attempt, naming the endpoint and nothing else"):
    val closed = ServerSocket(0, 1, loopback)
    val port = closed.getLocalPort
    closed.close()
    val endpoint = UpstreamEndpoint("HTTPS_PROXY", false, "127.0.0.1", Some(loopback), port, Some(Basic))
    val transport = UpstreamProxy(endpoint, Vector(loopback))
    val failure = intercept[TransportFailure](transport.connect(Vector(OriginV4, OriginV4Other), 443))
    val message = failure.getMessage
    assertEquals(failure.attempted, Vector(OriginV4))
    assert(message.startsWith(s"upstream proxy http://127.0.0.1:$port: "), message)
    assert(!message.contains(Basic), message)
    assertEquals(
      transport.summary,
      s"egress transport: upstream proxy http://127.0.0.1:$port -> 127.0.0.1 (HTTPS_PROXY)",
    )

  test("an https endpoint the image's roots do not chain to fails before a byte, the credential included, is sent"):
    val directory = Files.createTempDirectory("upstream-endpoint")
    val (ca, caKey) = X509HelperTest.testCa(Instant.now(), 30)
    val leaf = X509Helper.mintLeaf("proxy.corp.example", ca, caKey)
    val (certificate, key) = X509HelperTest.writePem(directory, "endpoint", leaf.certificate, leaf.privateKey)
    val serving = TlsInspection.load(certificate, key, Set("proxy.corp.example"))

    val server = ServerSocket(0, 1, loopback)
    val afterHandshake = AtomicReference("not reached")
    val thread = Thread.startVirtualThread: () =>
      try
        val socket = server.accept()
        try
          val tls = serving.accept(socket, Array.emptyByteArray, "proxy.corp.example")
          afterHandshake.set(String(tls.getInputStream.readAllBytes(), StandardCharsets.ISO_8859_1))
        catch case ex: IOException => afterHandshake.set(s"handshake failed: ${ex.getClass.getSimpleName}")
        finally socket.close()
      finally server.close()

    val endpoint = UpstreamEndpoint("HTTPS_PROXY", true, "proxy.corp.example", None, server.getLocalPort, Some(Basic))
    val message =
      intercept[IOException](UpstreamProxy(endpoint, Vector(loopback)).connect(Vector(OriginV4), 443)).getMessage
    thread.join()
    assert(message.startsWith(s"upstream proxy https://proxy.corp.example:${server.getLocalPort}: "), message)
    assert(!message.contains(Basic), message)
    assert(afterHandshake.get.startsWith("handshake failed"), afterHandshake.get)

  test("a locally refused CONNECT reaches no upstream proxy"):
    val proxy = ScriptedProxy(Vector(Established))
    val (client, server) = socketPair()
    val log = ByteArrayOutputStream()
    val saved = System.err
    System.setErr(PrintStream(log, true))
    val received =
      try
        val run =
          Run(resolveRuleset(Some("deny-unless-allowed"), None, None), None, proxy.endpoint(Some(Basic)))
        val handling = Thread.startVirtualThread(() => handle(server, run))
        client.getOutputStream.write(ascii("CONNECT tracker.example:443 HTTP/1.1\r\nHost: tracker.example:443\r\n\r\n"))
        val received = String(client.getInputStream.readAllBytes(), StandardCharsets.UTF_8)
        handling.join()
        received
      finally
        System.setErr(saved)
        client.close()
    assert(received.startsWith("HTTP/1.1 403 Forbidden\r\n"), received)
    assertEquals(proxy.received.get, Vector.empty)
    assert(!String(log.toByteArray, StandardCharsets.UTF_8).contains(Basic))

  private def socketPair(): (Socket, Socket) =
    val server = ServerSocket(0, 1, loopback)
    val connecting = Socket(loopback, server.getLocalPort)
    val accepted = server.accept()
    server.close()
    (connecting, accepted)
