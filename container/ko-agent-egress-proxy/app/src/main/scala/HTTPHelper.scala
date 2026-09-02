package agentsandbox.egress

import java.io.{ByteArrayOutputStream, EOFException, IOException, InputStream, OutputStream}
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.Locale
import scala.annotation.tailrec

import IPAddrHelper.normalizeHost

/**
 * HTTP parsing, framing and relay. Everything here refuses ambiguity rather than resolving
 * it — folded headers, Content-Length beside Transfer-Encoding, conflicting
 * Content-Lengths, bare CR or LF — because a proxy and an origin reading
 * the same bytes differently is what request smuggling exploits. (The
 * duplicate-Host refusal is the policy's: authorizeInspectedRequest.)
 *
 * Clients speak HTTP/1.1, and an HTTP/1.0 request is refused by name: no
 * such client exists here, and half-supporting one — it could not parse a
 * relayed chunked response — would be a silent gap instead of a log line.
 * Origin responses are accepted at any HTTP/1.x, which framing covers.
 */
object HTTPHelper:

  val MaxChunkLineBytes = 1024

  /** TLSPlaintext is capped at 16 KiB, and JDK 25's InputStream.transferTo uses the same buffer size.
    * A larger relay buffer would multiply per-connection memory without carrying a larger TLS record.
    * https://www.rfc-editor.org/rfc/rfc8446#section-5.1
    * https://github.com/openjdk/jdk/blob/master/src/java.base/share/classes/java/io/InputStream.java
    */
  val RelayBufferBytes = 16 * 1024

  def readHttpHeader(
    in: InputStream,
    maxBytes: Int,
  ): Array[Byte] =
    require(maxBytes >= 4)

    val out = ByteArrayOutputStream()
    val marker = Array[Byte](13, 10, 13, 10)

    @tailrec
    def loop(matched: Int, count: Int): Array[Byte] =
      if count >= maxBytes then
        throw BadRequest(s"HTTP header exceeds $maxBytes bytes")

      val value = in.read()
      if value < 0 then
        // ClosedWithoutRequest has why zero bytes is not a refused request.
        if count == 0 then throw ClosedWithoutRequest()
        else throw BadRequest("connection closed before HTTP header completed")

      val byte = value.toByte
      out.write(value)

      val nextMatched =
        if byte == marker(matched) then matched + 1
        else if byte == marker(0) then 1
        else 0

      if nextMatched == marker.length then out.toByteArray
      else loop(nextMatched, count + 1)

    loop(0, 0)

  case class ConnectRequest(host: String, port: Int)

  object ConnectRequest:
    def parse(bytes: Array[Byte]): ConnectRequest =
      val text = String(bytes, StandardCharsets.ISO_8859_1)

      if !text.endsWith("\r\n\r\n") then
        throw BadRequest("incomplete HTTP header")

      val withoutCrLf = text.replace("\r\n", "")
      if withoutCrLf.exists(ch => ch == '\r' || ch == '\n') then
        throw BadRequest("bare CR or LF in HTTP header")

      val lines = text.dropRight(4).split("\r\n", -1).toVector
      val requestLine = lines.headOption.getOrElse(throw BadRequest("missing request line"))

      val request = parseRequestLine(requestLine)
      validateHeaders(lines.drop(1))
      request

    def parseRequestLine(line: String): ConnectRequest =
      line.split(" ", -1).toList match
        case "CONNECT" :: authority :: "HTTP/1.1" :: Nil =>
          parseAuthority(authority)

        case _ :: _ :: "HTTP/1.0" :: Nil =>
          throw BadRequest("HTTP/1.0 is not supported")

        case method :: _ :: version :: Nil
            if version.startsWith("HTTP/") && method.nonEmpty && method.forall(_.isLetter) =>
          throw BadRequest(s"$method non-CONNECT request")

        case _ =>
          throw BadRequest("expected CONNECT authority HTTP/1.1")

    def parseAuthority(authority: String): ConnectRequest =
      // `isWhitespace` misses the controls that matter most in the audit log — ESC and BEL are not
      // whitespace, and DEL is not above 0x7f — and this authority is logged as requested on every
      // refusal, before any normalization has vouched for it.
      if authority.isEmpty ||
          authority.exists(ch => ch.isWhitespace || ch > 0x7f || isForbiddenControl(ch))
      then
        throw BadRequest("invalid CONNECT authority")

      if authority.contains('/') || authority.contains('@') then
        throw BadRequest("invalid CONNECT authority")

      if authority.startsWith("[") then
        val close = authority.indexOf(']')

        if close <= 1 || close + 1 >= authority.length || authority.charAt(close + 1) != ':' then
          throw BadRequest("invalid bracketed CONNECT authority")

        val host = authority.substring(1, close)
        val portText = authority.substring(close + 2)
        ConnectRequest(host, parsePort(portText))
      else
        val colon = authority.lastIndexOf(':')

        if colon <= 0 || colon == authority.length - 1 then
          throw BadRequest("CONNECT authority must include a port")

        if authority.substring(0, colon).contains(':') then
          throw BadRequest("IPv6 literals must use brackets")

        ConnectRequest(
          authority.substring(0, colon),
          parsePort(authority.substring(colon + 1)),
        )

    def parsePort(value: String): Int =
      value.toIntOption
        .filter(port => port >= 1 && port <= 65535)
        .getOrElse(throw BadRequest("invalid CONNECT port"))

    def validateHeaders(lines: Vector[String]): Unit =
      lines.foreach: line =>
        if line.startsWith(" ") || line.startsWith("\t") then
          throw BadRequest("obsolete folded HTTP header is not allowed")

        val colon = line.indexOf(':')
        if colon <= 0 then
          throw BadRequest("malformed HTTP header")

        val name = line.substring(0, colon)
        if !name.forall(isHttpTokenChar) then
          throw BadRequest("invalid HTTP header name")

        name.toLowerCase(Locale.ROOT) match
          case "content-length" | "transfer-encoding" =>
            throw BadRequest("CONNECT request bodies are not allowed")
          case _ => ()

  enum BodyFraming:
    case Empty
    case Length(count: Long)
    case Chunked
    /** Response-only: no framing header, so the body runs to the connection's end — the one
      * framing where EOF is the terminator rather than a possible truncation. Request parsing
      * never produces it (a request without framing headers has no body). */
    case UntilClose

  case class HttpRequestHead(
    method: String,
    target: String,
    version: String,
    headers: Vector[(String, String)],
  ):
    def path: String = target.takeWhile(_ != '?')

    def query: String = target.dropWhile(_ != '?').drop(1)

    def values(name: String): Vector[String] =
      val wanted = name.toLowerCase(Locale.ROOT)

      headers.collect:
        case (header, value) if header.toLowerCase(Locale.ROOT) == wanted => value

    /** Ambiguous framing is refused rather than resolved, per the file
      * header. */
    def bodyFraming: BodyFraming =
      protectedConnectionNomination(values("Connection")).foreach: name =>
        throw BadRequest(s"Connection nominates $name, which this proxy reads")

      val encodings = values("Transfer-Encoding")
      val lengths = values("Content-Length")

      if encodings.nonEmpty && lengths.nonEmpty then
        throw BadRequest("both Transfer-Encoding and Content-Length are present")

      if encodings.nonEmpty then
        if encodings.size != 1 ||
          encodings.head.trim.toLowerCase(Locale.ROOT) != "chunked"
        then throw BadRequest("only chunked Transfer-Encoding is supported")

        BodyFraming.Chunked
      else if lengths.nonEmpty then
        val declared =
          lengths.map: value =>
            value.trim.toLongOption
              .filter(_ >= 0)
              .getOrElse(throw BadRequest("invalid Content-Length"))

        if declared.distinct.size != 1 then
          throw BadRequest("conflicting Content-Length headers")

        BodyFraming.Length(declared.head)
      else BodyFraming.Empty

    /** The client is waiting for a 100 before it sends its body (RFC 9110 §10.1.1). This proxy
      * answers the 100 itself (relayInspected) and forwards the body unconditionally, so
      * toUpstreamBytes drops the Expect — an origin must not be left waiting for a body this
      * proxy sends regardless. Without this, the client stalls until its own 100 timeout on
      * every large POST (git's fetch negotiation past http.postBuffer sends it). */
    def expectsContinue: Boolean =
      values("Expect").exists(_.trim.equalsIgnoreCase("100-continue"))

    /** HTTP/1.1, this hop's headers removed — the fixed hop-by-hop set plus whatever the
      * message's own Connection header names — and `Connection: close` added: end-of-stream
      * then frames the response. */
    def toUpstreamBytes: Array[Byte] =
      val builder = StringBuilder()

      builder.append(s"$method $target HTTP/1.1\r\n")

      val dropped =
        HopByHopHeaders ++ connectionNamedHeaders(values("Connection"))
          ++ (if expectsContinue then Set("expect") else Set.empty)
      headers
        .filterNot((name, _) => dropped.contains(name.toLowerCase(Locale.ROOT)))
        .foreach((name, value) => builder.append(s"$name: $value\r\n"))

      builder.append("Connection: close\r\n\r\n")

      builder.toString.getBytes(StandardCharsets.ISO_8859_1)

  val HopByHopHeaders =
    Set(
      "connection",
      "keep-alive",
      "proxy-authenticate",
      "proxy-authorization",
      "proxy-connection",
      "te",
      "trailer",
      "upgrade",
    )

  /** The header names a message's own Connection header declares hop-by-hop (RFC 9110 §7.6.1):
    * those are this hop's to remove too, not just the fixed set above. */
  def connectionNamedHeaders(values: Vector[String]): Set[String] =
    values
      .flatMap(_.split(','))
      .map(_.trim.toLowerCase(Locale.ROOT))
      .filter(_.nonEmpty)
      .toSet

  /** The headers this hop reads for itself — the framing pair, and the Host the policy checked. A
    * Connection header nominating one asks this hop to strip a header it has already acted on: the
    * body would go out framed by a header the message no longer carries, which is a smuggling
    * primitive, not a hop-by-hop courtesy. Both bodyFraming implementations refuse it — they are
    * the framing authorities, and each runs before a byte of its message is forwarded. */
  val ConnectionProtectedHeaders: Set[String] = Set("content-length", "transfer-encoding", "host")

  def protectedConnectionNomination(connection: Vector[String]): Option[String] =
    connectionNamedHeaders(connection).intersect(ConnectionProtectedHeaders).toVector.sorted.headOption

  object HttpRequestHead:
    def parse(bytes: Array[Byte]): HttpRequestHead =
      val text = String(bytes, StandardCharsets.ISO_8859_1)

      if !text.endsWith("\r\n\r\n") then
        throw BadRequest("incomplete HTTP request head")

      val withoutCrLf = text.replace("\r\n", "")
      if withoutCrLf.exists(ch => ch == '\r' || ch == '\n') then
        throw BadRequest("bare CR or LF in HTTP request head")

      val lines = text.dropRight(4).split("\r\n", -1).toVector

      val requestLine = lines.headOption.getOrElse(throw BadRequest("missing request line"))

      requestLine.split(" ", -1).toList match
        case method :: target :: "HTTP/1.1" :: Nil =>
          if method.isEmpty || !method.forall(isHttpTokenChar) then
            throw BadRequest("invalid HTTP method")

          if target.isEmpty then throw BadRequest("empty request target")
          if target.exists(isForbiddenControl) then
            throw BadRequest("control character in request target")

          HttpRequestHead(method, target, "HTTP/1.1", parseHeaders(lines.drop(1)))

        case _ :: _ :: "HTTP/1.0" :: Nil =>
          throw BadRequest("HTTP/1.0 is not supported")

        case _ =>
          throw BadRequest("malformed HTTP request line")

    def parseHeaders(lines: Vector[String]): Vector[(String, String)] =
      lines.map: line =>
        if line.startsWith(" ") || line.startsWith("\t") then
          throw BadRequest("obsolete folded HTTP header is not allowed")

        val colon = line.indexOf(':')
        if colon <= 0 then throw BadRequest("malformed HTTP header")

        val name = line.substring(0, colon)
        if !name.forall(isHttpTokenChar) then
          throw BadRequest("invalid HTTP header name")

        val value = line.substring(colon + 1).trim
        if value.exists(ch => isForbiddenControl(ch) && ch != '\t') then
          throw BadRequest("control character in HTTP header value")

        (name, value)

  /**
   * The response head, parsed for status and framing only — just enough to tell a completed body
   * from a truncated one — and relayed with only its hop-by-hop headers replaced (toClientBytes):
   * this proxy verifies response framing and speaks its own hop; it never rewrites or filters
   * response content, because that would grow into the policy language this proxy refuses to
   * have. Origin-side malformations are IOExceptions, never BadRequests: the world failed, and
   * the 502 should blame the origin.
   */
  case class HttpResponseHead(
    statusLine: String,
    status: Int,
    headers: Vector[(String, String)],
    rawBytes: Array[Byte],
  ):
    def values(name: String): Vector[String] =
      val wanted = name.toLowerCase(Locale.ROOT)

      headers.collect:
        case (header, value) if header.toLowerCase(Locale.ROOT) == wanted => value

    /** The head as the client receives it: status line and end-to-end headers unchanged, but the
      * hop-by-hop headers are this hop's own (they describe the origin↔proxy leg), and this
      * proxy's answer is always `Connection: close` — a session is one request, and the client
      * must hear that even when the origin's headers omit it. A client that misses it reuses or
      * pipelines, its next request meets the closed socket's RST, and the RST destroys this
      * response's unread tail in the client's buffer — measured as apt's intermittent
      * mid-download EOFs, invisible in the proxy's own log. */
    def toClientBytes: Array[Byte] =
      val builder = StringBuilder()

      builder.append(s"$statusLine\r\n")

      val dropped = HopByHopHeaders ++ connectionNamedHeaders(values("Connection"))
      headers
        .filterNot((name, _) => dropped.contains(name.toLowerCase(Locale.ROOT)))
        .foreach((name, value) => builder.append(s"$name: $value\r\n"))

      builder.append("Connection: close\r\n\r\n")

      builder.toString.getBytes(StandardCharsets.ISO_8859_1)

    /** RFC 9112 §6.3 for the one-request sessions this proxy runs. Mirrors the request side's
      * refusals of ambiguity, as IOExceptions; the no-framing default differs by design —
      * UntilClose, because this proxy sends `Connection: close` upstream. */
    def bodyFraming(requestMethod: String): BodyFraming =
      protectedConnectionNomination(values("Connection")).foreach: name =>
        throw IOException(s"origin's Connection nominates $name, which this proxy reads")

      if requestMethod == "HEAD" || status / 100 == 1 || status == 204 || status == 304 then
        BodyFraming.Empty
      else
        val encodings = values("Transfer-Encoding")
        val lengths = values("Content-Length")

        if encodings.nonEmpty && lengths.nonEmpty then
          throw IOException("origin sent both Transfer-Encoding and Content-Length")

        if encodings.nonEmpty then
          if encodings.size != 1 ||
            encodings.head.trim.toLowerCase(Locale.ROOT) != "chunked"
          then throw IOException("origin sent a Transfer-Encoding other than chunked")

          BodyFraming.Chunked
        else if lengths.nonEmpty then
          val declared =
            lengths.map: value =>
              value.trim.toLongOption
                .filter(_ >= 0)
                .getOrElse(throw IOException("origin sent an invalid Content-Length"))

          if declared.distinct.size != 1 then
            throw IOException("origin sent conflicting Content-Length headers")

          BodyFraming.Length(declared.head)
        else BodyFraming.UntilClose

  object HttpResponseHead:
    def parse(bytes: Array[Byte]): HttpResponseHead =
      def malformed(reason: String): Nothing =
        throw IOException(s"origin response head: $reason")

      val text = String(bytes, StandardCharsets.ISO_8859_1)

      if !text.endsWith("\r\n\r\n") then malformed("incomplete")

      val withoutCrLf = text.replace("\r\n", "")
      if withoutCrLf.exists(ch => ch == '\r' || ch == '\n') then malformed("bare CR or LF")

      val lines = text.dropRight(4).split("\r\n", -1).toVector
      val statusLine = lines.headOption.getOrElse(malformed("missing status line"))

      statusLine.split(" ", 3).toList match
        case version :: statusText :: _ if version.startsWith("HTTP/1.") =>
          val status =
            statusText.toIntOption
              .filter(value => value >= 100 && value <= 599)
              .getOrElse(malformed(s"status '$statusText'"))

          val headers =
            try HttpRequestHead.parseHeaders(lines.drop(1))
            catch case ex: BadRequest => malformed(ex.getMessage)

          HttpResponseHead(statusLine, status, headers, bytes)

        case _ => malformed(s"status line '$statusLine'")

  /**
   * A control character is invalid in a request target and in a field value alike (RFC 9112 §3.2,
   * RFC 9110 §5.5), and this proxy refuses one rather than passing it on. Two things ride on that.
   * The target is written verbatim into the audit log, so a tab would break the field grammar
   * tooling greps and an escape sequence would let a request choose how the record of itself reads
   * on the operator's terminal. And an origin is entitled to a well-formed request: CR and LF are
   * already refused above, which is what closes smuggling, but forwarding NUL or DEL into a header
   * hands the origin's parser a decision this one did not make. HTAB is the single exception, legal
   * inside a field value and nowhere else.
   */
  def isForbiddenControl(ch: Char): Boolean = ch < 0x20 || ch == 0x7f

  def isHttpTokenChar(ch: Char): Boolean =
    (ch >= 'A' && ch <= 'Z') ||
      (ch >= 'a' && ch <= 'z') ||
      (ch >= '0' && ch <= '9') ||
      "!#$%&'*+-.^_`|~".contains(ch)

  /**
   * A Host header may carry the default port, and nothing else: this proxy
   * only ever reaches port 443, so any other port names a destination the
   * CONNECT was not authorized for.
   */
  def normalizeHostHeader(value: String): String =
    val trimmed = value.trim

    if trimmed.startsWith("[") then
      throw BadRequest("IP-literal Host header is not allowed")

    val (name, port) =
      trimmed.lastIndexOf(':') match
        case -1    => (trimmed, None)
        case colon => (trimmed.substring(0, colon), Some(trimmed.substring(colon + 1)))

    port.foreach: declared =>
      if declared != "443" then
        throw BadRequest(s"Host header names port $declared")

    normalizeHost(name)

  def forwardRequestBody(
    in: InputStream,
    out: OutputStream,
    framing: BodyFraming,
  ): Unit =
    framing match
      case BodyFraming.Empty         => ()
      case BodyFraming.Length(count) => copyExactly(in, out, count)
      case BodyFraming.Chunked       => copyChunked(in, out)
      case BodyFraming.UntilClose =>
        // Request parsing never produces it (see the enum case); reaching here is a proxy bug.
        throw IllegalStateException("request bodies cannot be close-delimited")

  /**
   * The response-body relay, framing enforced: an upstream EOF inside a declared length or an
   * unterminated chunk sequence is TruncatedResponse — the caller must end the connection so the
   * stump cannot read as the whole — never a quiet end. UntilClose is the one framing where EOF
   * is the terminator.
   */
  def forwardResponseBody(
    in: InputStream,
    out: OutputStream,
    framing: BodyFraming,
  ): Unit =
    framing match
      case BodyFraming.Empty => ()

      case BodyFraming.Length(count) =>
        try copyExactly(in, out, count)
        catch
          case ex: EOFException =>
            throw TruncatedResponse(s"$count-byte response truncated: ${ex.getMessage}")

      case BodyFraming.Chunked =>
        try copyChunked(in, out)
        catch
          case _: EOFException =>
            throw TruncatedResponse("response truncated inside a chunked body")
          case ex: BadRequest =>
            throw TruncatedResponse(s"origin chunking unparseable: ${ex.getMessage}")

      case BodyFraming.UntilClose =>
        copyUntilEof(in, out)

  def copyExactly(in: InputStream, out: OutputStream, count: Long): Unit =
    copyExactly(in, out, count, new Array[Byte](RelayBufferBytes))

  private def copyExactly(
    in: InputStream,
    out: OutputStream,
    count: Long,
    buffer: Array[Byte],
  ): Unit =

    @tailrec
    def loop(remaining: Long): Unit =
      if remaining > 0 then
        val wanted = math.min(remaining, buffer.length.toLong).toInt
        val read = in.read(buffer, 0, wanted)

        if read < 0 then
          throw EOFException(s"body ended $remaining bytes early")

        out.write(buffer, 0, read)
        loop(remaining - read)

    loop(count)

  /** Re-emitted canonically — extensions and trailers dropped — so nothing
    * in it reads differently at the two ends. */
  def copyChunked(in: InputStream, out: OutputStream): Unit =
    val buffer = new Array[Byte](RelayBufferBytes)

    @tailrec
    def loop(): Unit =
      val header = readCrLfLine(in, MaxChunkLineBytes)
      val size =
        try java.lang.Long.parseLong(header.takeWhile(_ != ';').trim, 16)
        catch
          case _: NumberFormatException =>
            throw BadRequest("invalid chunk size")

      if size < 0 then throw BadRequest("negative chunk size")

      if size == 0 then
        @tailrec
        def skipTrailers(): Unit =
          if readCrLfLine(in, MaxChunkLineBytes).nonEmpty then skipTrailers()

        skipTrailers()
        out.write("0\r\n\r\n".getBytes(StandardCharsets.US_ASCII))
      else
        out.write(
          s"${java.lang.Long.toHexString(size)}\r\n".getBytes(StandardCharsets.US_ASCII),
        )
        copyExactly(in, out, size, buffer)

        if readCrLfLine(in, MaxChunkLineBytes).nonEmpty then
          throw BadRequest("chunk not terminated by CRLF")

        out.write("\r\n".getBytes(StandardCharsets.US_ASCII))
        loop()

    loop()

  def copyUntilEof(in: InputStream, out: OutputStream): Unit =
    val buffer = new Array[Byte](RelayBufferBytes)

    @tailrec
    def loop(): Unit =
      val read = in.read(buffer)
      if read >= 0 then
        out.write(buffer, 0, read)
        loop()

    loop()

  def readCrLfLine(in: InputStream, maxBytes: Int): String =
    val out = ByteArrayOutputStream()

    @tailrec
    def loop(previousWasCr: Boolean): String =
      if out.size() > maxBytes then throw BadRequest(s"line exceeds $maxBytes bytes")

      val value = in.read()
      if value < 0 then throw EOFException("connection closed inside a chunked body")

      if value == '\n' then
        if !previousWasCr then throw BadRequest("bare LF in chunked body")
        String(out.toByteArray, StandardCharsets.US_ASCII).dropRight(1)
      else
        out.write(value)
        loop(value == '\r')

    loop(false)

  /** The refusal's body: the audit line's tail, and under it the next step when the refusal is
    * the policy's (PolicyViolation.advice). One line each, so a client that prints the body —
    * curl as it is, git as `remote:` lines, since the type is text/plain — prints the step. */
  def refusalBody(detail: String, advice: Option[String]): Array[Byte] =
    (s"ko-agent-egress-proxy: $detail\n" + advice.map(_ + "\n").getOrElse(""))
      .getBytes(StandardCharsets.UTF_8)

  /** The refusal as curl and git see it: a reason inside the tunnel beats a dropped connection.
    * Socket rather than SSLSocket, like relayInspected: nothing here is TLS-specific. */
  def respondInsideTls(
    socket: Socket,
    status: Int,
    reason: String,
    detail: String,
    advice: Option[String] = None,
  ): Unit =
    respondQuietly(socket, status, reason, refusalBody(detail, advice))

  def respondQuietly(
    client: Socket,
    status: Int,
    reason: String,
    body: Array[Byte] = Array.emptyByteArray,
  ): Unit =
    try respond(client, status, reason, body)
    catch case _: IOException => ()

  def respond(client: Socket, status: Int, reason: String, body: Array[Byte]): Unit =
    val out = client.getOutputStream
    writeAscii(
      out,
      s"HTTP/1.1 $status $reason\r\n" +
        (if body.isEmpty then "" else "Content-Type: text/plain; charset=utf-8\r\n") +
        s"Content-Length: ${body.length}\r\n" +
        "Connection: close\r\n\r\n",
    )
    out.write(body)
    out.flush()

  def writeAscii(out: OutputStream, value: String): Unit =
    out.write(value.getBytes(StandardCharsets.US_ASCII))
    out.flush()
