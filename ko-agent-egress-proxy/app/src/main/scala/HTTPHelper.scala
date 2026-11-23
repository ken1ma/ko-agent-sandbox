package agentsandbox.egress

import java.io.{ByteArrayOutputStream, EOFException, IOException, InputStream, OutputStream}
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.Locale
import scala.annotation.tailrec

import IPAddrHelper.normalizeHost
import Refusals.{proxyStatus, refusalBody}

/**
 * HTTP parsing, framing and relay. Everything here refuses ambiguity rather than resolving it: folded headers,
 * Content-Length beside Transfer-Encoding, conflicting Content-Lengths, bare CR or LF. Request smuggling exploits a
 * proxy and an origin that read the same bytes differently. The ruleset refuses a duplicate Host
 * (authorizeInspectedRequest).
 *
 * - Clients speak HTTP/1.1, and the proxy refuses an HTTP/1.0 request by name. No such client exists here, and
 *   half-supporting one would be a silent gap instead of a log line: an HTTP/1.0 client could not parse a relayed
 *   chunked response.
 * - The proxy accepts origin responses at any HTTP/1.x, which framing covers.
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
        // ClosedWithoutRequest explains why zero bytes is not a refused request.
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

  /** A head readHttpHeader returned, as its start line and its field lines. */
  def splitHead(bytes: Array[Byte], incomplete: => Nothing, bareCrOrLf: => Nothing): (String, Vector[String]) =
    val text = String(bytes, StandardCharsets.ISO_8859_1)
    if !text.endsWith("\r\n\r\n") then incomplete
    if text.replace("\r\n", "").exists(ch => ch == '\r' || ch == '\n') then bareCrOrLf
    // Never empty: a head with no start line splits into an empty one, which each start-line
    // parser refuses.
    val lines = text.dropRight(4).split("\r\n", -1).toVector
    (lines.head, lines.tail)

  case class ConnectRequest(host: String, port: Int)

  object ConnectRequest:
    def parse(bytes: Array[Byte]): ConnectRequest =
      val (requestLine, fieldLines) = splitHead(
        bytes,
        incomplete = throw BadRequest("incomplete HTTP header"),
        bareCrOrLf = throw BadRequest("bare CR or LF in HTTP header"),
      )
      val request = parseRequestLine(requestLine)
      validateHeaders(fieldLines)
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
      // `isWhitespace` misses ESC, BEL and DEL, which no authority holds either.
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
      parseDecimal(value)
        .filter(port => port >= 1 && port <= 65535)
        .map(_.toInt)
        .getOrElse(throw BadRequest("invalid CONNECT port"))

    /** Values go unchecked: ConnectRequest keeps only the host and port, so no CONNECT header is
      * read or forwarded. */
    def validateHeaders(lines: Vector[String]): Unit =
      lines.foreach: line =>
        headerName(line).toLowerCase(Locale.ROOT) match
          case "content-length" | "transfer-encoding" =>
            throw BadRequest("CONNECT request bodies are not allowed")
          case _ => ()

  enum BodyFraming:
    case Empty
    case Length(count: Long)
    case Chunked
    /** Response-only: no framing header, so the body runs to the connection's end. UntilClose is the one framing where
      * EOF is the terminator rather than a possible truncation. Request parsing never produces this case, since a
      * request without framing headers has no body. */
    case UntilClose

  case class HttpRequestHead(
    method: String,
    target: String,
    headers: Vector[(String, String)],
  ):
    def path: String = target.takeWhile(_ != '?')

    def query: String = target.dropWhile(_ != '?').drop(1)

    def values(name: String): Vector[String] = headerValues(headers, name)

    /** Refuses ambiguous framing rather than resolving it, as HTTPHelper's Scaladoc explains. */
    def bodyFraming: BodyFraming =
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
        val declared = contentLengths(lengths).getOrElse(throw BadRequest("invalid Content-Length"))

        if declared.distinct.size != 1 then
          throw BadRequest("conflicting Content-Length headers")

        BodyFraming.Length(declared.head)
      else BodyFraming.Empty

    /** HTTP/1.1, with this hop's headers removed and `Connection: close` added. This hop's headers are the fixed
      * hop-by-hop set plus whatever the message's own Connection header names. End-of-stream then frames the
      * response. */
    def toOriginBytes: Array[Byte] =
      serialized(s"$method $target HTTP/1.1", headers, ConnectionProtectedHeaders, "Connection: close\r\n")

    /** A granted WebSocket handshake as toOriginBytes sends a request, with the upgrade's pair in place of
      * `Connection: close`: the origin upgrades only on seeing them (RFC 6455 §4.1). */
    def toOriginUpgradeBytes(upgrade: String): Array[Byte] =
      serialized(s"$method $target HTTP/1.1", headers, ConnectionProtectedHeaders, upgradePair(upgrade))

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

  /** A head with this hop's headers removed (endToEnd), a repeated length declared once (withOneContentLength), and
    * `hop`, this hop's own header lines, after the rest. */
  private def serialized(
    startLine: String,
    headers: Vector[(String, String)],
    carried: Set[String],
    hop: String,
  ): Array[Byte] =
    val builder = StringBuilder()
    builder.append(s"$startLine\r\n")
    withOneContentLength(endToEnd(headers, carried)).foreach: (name, value) =>
      builder.append(s"$name: $value\r\n")
    builder.append(s"$hop\r\n")
    builder.toString.getBytes(StandardCharsets.ISO_8859_1)

  /** The GUID that RFC 6455 §1.3 appends to the key before hashing. */
  private val WebSocketGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

  /** The `Sec-WebSocket-Accept` that an origin derives from the handshake's key (RFC 6455 §4.2.2). */
  def webSocketAccept(key: String): String =
    val digest = java.security.MessageDigest.getInstance("SHA-1")
      .digest(s"$key$WebSocketGuid".getBytes(StandardCharsets.US_ASCII))
    java.util.Base64.getEncoder.encodeToString(digest)

  private def upgradePair(upgrade: String): String = s"Upgrade: $upgrade\r\nConnection: Upgrade\r\n"

  /** The name of a header line, refusing a folded line and a name that is empty or not a token. */
  private def headerName(line: String): String =
    if line.startsWith(" ") || line.startsWith("\t") then throw BadRequest("obsolete folded HTTP header is not allowed")
    val colon = line.indexOf(':')
    if colon <= 0 then throw BadRequest("malformed HTTP header")
    val name = line.substring(0, colon)
    if !name.forall(isHttpTokenChar) then throw BadRequest("invalid HTTP header name")
    name

  /** The values of every `name` header, its name matched without case. */
  def headerValues(headers: Vector[(String, String)], name: String): Vector[String] =
    val wanted = name.toLowerCase(Locale.ROOT)
    headers.collect:
      case (header, value) if header.toLowerCase(Locale.ROOT) == wanted => value

  /** The headers less this hop's: the fixed hop-by-hop set and whatever the Connection header names, except
    * `carried`, the headers that this hop read and forwards the message by (ConnectionProtectedHeaders). */
  private def endToEnd(headers: Vector[(String, String)], carried: Set[String]): Vector[(String, String)] =
    val connectionNamed = connectionNamedHeaders(headerValues(headers, "Connection")) -- carried
    val dropped = HopByHopHeaders ++ connectionNamed
    headers.filterNot((name, _) => dropped.contains(name.toLowerCase(Locale.ROOT)))

  /** The header names a message's own Connection header declares hop-by-hop (RFC 9110 §7.6.1):
    * those are this hop's to remove too, not just HopByHopHeaders. */
  def connectionNamedHeaders(values: Vector[String]): Set[String] =
    values
      .flatMap(_.split(','))
      .map(_.trim.toLowerCase(Locale.ROOT))
      .filter(_.nonEmpty)
      .toSet

  /** The counts that Content-Length field lines declare, each line a comma-separated list, or None when an element
    * is not a decimal count. bodyFraming accepts the counts when they are all equal (RFC 9112 §6.3 item 5).
    *
    * - Senders repeat an equal count: undici 6's fetch sends `Content-Length: 36, 36` (nodejs/undici#5993), and
    *   servers repeat the field line (golang/go#16490, nodejs/node#6517).
    * - An empty element is refused, though RFC 9110 §5.6.1 lets a list carry one: none of those senders emits it. */
  def contentLengths(lines: Vector[String]): Option[Vector[Long]] =
    val elements = lines.flatMap(_.split(",", -1)).map(stripOptionalWhitespace)
    val counts = elements.flatMap(parseDecimal)
    Option.when(counts.size == elements.size)(counts)

  /** `headers` with an equal count repeated in Content-Length declared once: the first element, as the sender spelled
    * it, in the first Content-Length line, and no other Content-Length line.
    *
    * - llhttp, Node's parser, refuses a second Content-Length line, and undici refuses `36, 36`.
    * - A single count stays as sent: a rewritten count would break a message signature over the field (RFC 9421).
    * - Counts that differ stay as sent. bodyFraming refuses them where they frame the body.
    * - On a response without a body (HEAD, 1xx, 204, 304), Content-Length frames nothing (RFC 9112 §6.3, rule 1), so
    *   this hop forwards differing counts there and declares an equal repeated count once.
    *   - A client that misreads those counts meets no second message: this hop relays nothing after the head, then
    *     closes.
    *   - curl ignores Content-Length on 1xx, 204 and 304 responses, so a refusal there would fail curl only through
    *     this proxy. */
  private def withOneContentLength(headers: Vector[(String, String)]): Vector[(String, String)] =
    def isContentLength(name: String) = name.equalsIgnoreCase("Content-Length")
    val lines = headers.collect { case (name, value) if isContentLength(name) => value }
    contentLengths(lines) match
      case Some(counts) if counts.size > 1 && counts.distinct.size == 1 =>
        val first = headers.indexWhere((name, _) => isContentLength(name))
        val spelled = stripOptionalWhitespace(lines.head.split(",", -1).head)
        headers.zipWithIndex.collect:
          case ((name, _), index) if index == first          => (name, spelled)
          case ((name, value), _) if !isContentLength(name) => (name, value)
      case _ => headers

  /** The headers that this hop reads for itself: the framing pair, and the Host that must match the authorized
    * CONNECT host. A Connection header's nomination leaves such a header in the forwarded head (endToEnd) where
    * this hop forwards the message by it: on a request, all three; on a response, the one that frames its body.
    *
    * - This hop forwards the body in the framing that it read, to the Host that the ruleset checked. The header that
    *   it read therefore describes the next hop's message too, so the forwarded head carries the same header.
    * - Removing it would forward the body without its framing, where the body could read to the origin as a second
    *   request, or the request without the Host that the ruleset checked.
    * - Elsewhere the nomination removes the header, as RFC 9110 §7.6.1 has it: a response's Host, and a framing
    *   header on a response without a body (HttpResponseHead.bodyFraming).
    * - The nomination itself goes no further: endToEnd drops the Connection header, and this hop sends its own. */
  val ConnectionProtectedHeaders: Set[String] = Set("content-length", "transfer-encoding", "host")

  object HttpRequestHead:
    def parse(bytes: Array[Byte]): HttpRequestHead =
      val (requestLine, fieldLines) = splitHead(
        bytes,
        incomplete = throw BadRequest("incomplete HTTP request head"),
        bareCrOrLf = throw BadRequest("bare CR or LF in HTTP request head"),
      )

      requestLine.split(" ", -1).toList match
        case method :: target :: "HTTP/1.1" :: Nil =>
          if method.isEmpty || !method.forall(isHttpTokenChar) then
            throw BadRequest("invalid HTTP method")

          if target.isEmpty then throw BadRequest("empty request target")
          if target.exists(isForbiddenControl) then
            throw BadRequest("control character in request target")

          HttpRequestHead(method, target, parseHeaders(fieldLines))

        case _ :: _ :: "HTTP/1.0" :: Nil =>
          throw BadRequest("HTTP/1.0 is not supported")

        case _ =>
          throw BadRequest("malformed HTTP request line")

    def parseHeaders(lines: Vector[String]): Vector[(String, String)] =
      lines.map: line =>
        val name = headerName(line)
        // The check runs before the optional whitespace is stripped. Java's `trim` removes every character up to
        // SP, so trimming first would drop an edge NUL, VT or FF where the check should refuse the head.
        val raw = line.substring(name.length + 1)
        if raw.exists(ch => isForbiddenControl(ch) && ch != '\t') then
          throw BadRequest("control character in HTTP header value")

        (name, stripOptionalWhitespace(raw))

  /** A field value without its optional whitespace, SP and HTAB at either end (RFC 9110 §5.5). The origin
    * receives this value, and the decision reads it. */
  def stripOptionalWhitespace(value: String): String =
    value.dropWhile(ch => ch == ' ' || ch == '\t').reverse.dropWhile(ch => ch == ' ' || ch == '\t').reverse

  /**
   * The response head, parsed for status and framing only: just enough to tell a completed body from a truncated
   * one. The proxy relays the head with only its version and hop-by-hop headers replaced, and a repeated length
   * declared once (toClientBytes).
   *
   * - This proxy verifies response framing and sets its own connection's headers. The proxy never rewrites or
   *   filters response content, because that would require the response-content rule language that this proxy
   *   refuses to have.
   * - Origin-side malformations are IOExceptions, never BadRequests: the origin failed, and the 502 should say so.
   */
  case class HttpResponseHead(
    status: Int,
    reason: String,
    headers: Vector[(String, String)],
  ):
    def values(name: String): Vector[String] = headerValues(headers, name)

    def interim: Boolean = status / 100 == 1

    /** The head as the client receives it, an interim head as well as the final one.
      *
      * - The status, the reason and the end-to-end headers stay unchanged, except that a repeated length reaches the
      *   client once (withOneContentLength).
      * - The version is this hop's own: RFC 9112 §2.3 has an intermediary send its version, not the origin's.
      * - The hop-by-hop headers are this hop's own too, since the origin's hop-by-hop headers describe the
      *   origin↔proxy leg.
      * - On the final head, this proxy always answers `Connection: close`. Each connection carries one request, and
      *   the client must hear that even when the origin's headers omit it.
      *   - A client that misses `Connection: close` reuses the connection or pipelines. The client's next request
      *     meets the closed socket's RST, and the RST destroys this response's unread tail in the client's buffer.
      *   - apt shows this failure as intermittent mid-download EOFs, which the proxy's own log does not record.
      * - An interim head carries no Connection at all: the final head states the disposition.
      *
      * `framing` is bodyFraming's result, which the body's relay uses too; an interim head passes Empty. */
    def toClientBytes(framing: BodyFraming): Array[Byte] =
      val carried = framing match
        case BodyFraming.Chunked   => Set("transfer-encoding")
        case BodyFraming.Length(_) => Set("content-length")
        case _                     => Set()
      val hop = if interim then "" else "Connection: close\r\n"
      serialized(s"HTTP/1.1 $status $reason", headers, carried, hop)

    /** A checked `101` as toClientBytes sends a head, with the upgrade's pair that the client checks (RFC 6455
      * §4.1). `upgrade` is the client's own spelling from its handshake. */
    def toClientUpgradeBytes(upgrade: String): Array[Byte] =
      serialized(s"HTTP/1.1 $status $reason", headers, Set(), upgradePair(upgrade))

    /** RFC 9112 §6.3 for the connections that this proxy closes after one request.
      *
      * - This method mirrors the request side's refusals of ambiguity, as IOExceptions.
      * - The no-framing default differs by design: UntilClose, because this proxy sends `Connection: close` to the
      *   origin.
      * - This method stays separate from the request's: every refusal's wording differs, so one implementation
      *   would take four messages as parameters. */
    def bodyFraming(requestMethod: String): BodyFraming =
      if requestMethod == "HEAD" || interim || status == 204 || status == 304 then
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
          val declared = contentLengths(lengths).getOrElse(throw IOException("origin sent an invalid Content-Length"))

          if declared.distinct.size != 1 then
            throw IOException("origin sent conflicting Content-Length headers")

          BodyFraming.Length(declared.head)
        else BodyFraming.UntilClose

  object HttpResponseHead:
    def parse(bytes: Array[Byte], subject: String = "origin response head"): HttpResponseHead =
      def malformed(reason: String): Nothing =
        throw IOException(s"$subject: $reason")

      val (statusLine, fieldLines) =
        splitHead(bytes, incomplete = malformed("incomplete"), bareCrOrLf = malformed("bare CR or LF"))

      statusLine.split(" ", 3).toList match
        case version :: statusText :: rest if isHttp1Version(version) =>
          // Three digits exactly (RFC 9112 §4): toClientBytes writes the parsed number, and the client must not
          // receive a status line that the origin did not send.
          val status =
            Option.when(statusText.length == 3)(statusText).flatMap(parseDecimal)
              .filter(value => value >= 100 && value <= 599)
              .map(_.toInt)
              .getOrElse(malformed(s"status '$statusText'"))

          val reason = rest.headOption.getOrElse("")
          if reason.exists(ch => isForbiddenControl(ch) && ch != '\t') then
            malformed("control character in reason phrase")

          val headers =
            try HttpRequestHead.parseHeaders(fieldLines)
            catch case ex: BadRequest => malformed(ex.getMessage)

          HttpResponseHead(status, reason, headers)

        case _ => malformed(s"status line '$statusLine'")

  /** ASCII digits and nothing else.
    *
    * - ASCII digits are all that the grammars of Content-Length, a port and a status code allow. ASCII digits are
    *   also the one spelling that the credential pipe, the run-on-host channel and the clipboard relay take for
    *   their counts.
    * - `toLongOption` alone also accepts a sign and any script's digits (`+1`, `١`). A forwarded
    *   `Content-Length: +1` leaves the origin free to read a length other than the one that this proxy framed the
    *   body by. */
  def parseDecimal(text: String): Option[Long] = Option.when(isDecimal(text))(text.toLongOption).flatten

  def isDecimal(text: String): Boolean = text.nonEmpty && text.forall(ch => ch >= '0' && ch <= '9')

  /** `HTTP/1.` and one digit, the grammar of RFC 9112 §2.3. Every minor version passes, since the framing rules
    * cover them all. */
  def isHttp1Version(text: String): Boolean =
    text.length == 8 && text.startsWith("HTTP/1.") && text(7) >= '0' && text(7) <= '9'

  /**
   * A control character is invalid in a request target and in a field value alike (RFC 9112 §3.2, RFC 9110 §5.5).
   * This proxy refuses such a character rather than passing it on: an origin is entitled to a well-formed request.
   *
   * - CR and LF are already refused above, which is what closes smuggling. But forwarding NUL or DEL into a header
   *   hands the origin's parser a decision that this proxy's parser did not make.
   * - HTAB is the single exception, legal inside a field value and nowhere else.
   * - The audit log escapes controls itself (LogHelper.auditLine), including the C1 controls that this check lets
   *   through.
   */
  def isForbiddenControl(ch: Char): Boolean = ch < 0x20 || ch == 0x7f

  def isHttpTokenChar(ch: Char): Boolean =
    (ch >= 'A' && ch <= 'Z') ||
      (ch >= 'a' && ch <= 'z') ||
      (ch >= '0' && ch <= '9') ||
      "!#$%&'*+-.^_`|~".contains(ch)

  /**
   * A Host header may carry the default port, and nothing else. This proxy only ever reaches port 443, so any other
   * port names a destination that the CONNECT was not authorized for.
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
    // Takes the payload, while `out` takes the chunk framing (Upload counts the payload).
    payload: OutputStream,
  ): Unit =
    framing match
      case BodyFraming.Empty         => ()
      case BodyFraming.Length(count) => copyExactly(in, payload, count)
      case BodyFraming.Chunked       => copyChunked(in, out, payload)
      case BodyFraming.UntilClose =>
        // Request parsing never produces UntilClose (see the enum case), so reaching here is a proxy bug.
        throw IllegalStateException("request bodies cannot be close-delimited")

  /** A failed write to the client. The JDK names a reset alike on either leg, so only this type tells a relay's
    * failure at the client from one at the origin. */
  final class ClientWriteFailure(cause: IOException) extends IOException(cause.getMessage, cause)

  /** The client's output, whose failures are ClientWriteFailures. */
  final class ClientOutput(out: OutputStream) extends OutputStream:
    override def write(byte: Int): Unit = marked(out.write(byte))
    override def write(bytes: Array[Byte], offset: Int, length: Int): Unit = marked(out.write(bytes, offset, length))
    override def flush(): Unit = marked(out.flush())

    private def marked(write: => Unit): Unit =
      try write
      catch case ex: IOException => throw ClientWriteFailure(ex)

  /**
   * Premature EOF and invalid chunk framing require TruncatedResponse's abortive close.
   * Other I/O failures reach relayInspected, which handles them across all framings. UntilClose accepts EOF as
   * completion, so UntilClose depends on that caller to preserve timeouts and resets.
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
        try copyChunked(in, out, out)
        catch
          case _: EOFException =>
            throw TruncatedResponse("response truncated inside a chunked body")
          case ex: BadRequest =>
            throw TruncatedResponse(s"origin chunking unparseable: ${ex.getMessage}")

      case BodyFraming.UntilClose =>
        in.transferTo(out)

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

  /** Re-emits the chunked body canonically: extensions and trailers are checked against their grammar, then
    * dropped. So nothing in the body reads differently at the two ends. */
  def copyChunked(in: InputStream, out: OutputStream, payload: OutputStream): Unit =
    val buffer = new Array[Byte](RelayBufferBytes)

    @tailrec
    def loop(): Unit =
      val size = parseChunkHeader(readCrLfLine(in, MaxChunkLineBytes))

      if size == 0 then
        @tailrec
        def skipTrailers(): Unit =
          val trailer = readCrLfLine(in, MaxChunkLineBytes)
          if trailer.nonEmpty then
            HttpRequestHead.parseHeaders(Vector(trailer))
            skipTrailers()

        skipTrailers()
        out.write("0\r\n\r\n".getBytes(StandardCharsets.US_ASCII))
      else
        out.write(
          s"${java.lang.Long.toHexString(size)}\r\n".getBytes(StandardCharsets.US_ASCII),
        )
        copyExactly(in, payload, size, buffer)

        if readCrLfLine(in, MaxChunkLineBytes).nonEmpty then
          throw BadRequest("chunk not terminated by CRLF")

        out.write("\r\n".getBytes(StandardCharsets.US_ASCII))
        loop()

    loop()

  private val ChunkHeader =
    val token = "[!#$%&'*+.^_`|~0-9A-Za-z-]+"
    val quotedString = "\"(?:[\t \\x21\\x23-\\x5B\\x5D-\\x7E\\x80-\\xFF]|\\\\[\t \\x21-\\x7E\\x80-\\xFF])*\""
    val extension = s"[ \t]*;[ \t]*$token(?:[ \t]*=[ \t]*(?:$token|$quotedString))?"
    s"([0-9A-Fa-f]+)(?:$extension)*".r

  /** The size of a `chunk-size [ chunk-ext ]` line (RFC 9112 §7.1). */
  def parseChunkHeader(line: String): Long =
    line match
      case ChunkHeader(size) =>
        try java.lang.Long.parseLong(size, 16)
        catch case _: NumberFormatException => throw BadRequest("invalid chunk size")
      case _ => throw BadRequest("invalid chunk size")

  def readCrLfLine(in: InputStream, maxBytes: Int): String =
    val out = ByteArrayOutputStream()

    @tailrec
    def loop(previousWasCr: Boolean): String =
      // The CRLF counts: `maxBytes` bounds what the line consumes from the stream.
      if out.size() >= maxBytes then throw BadRequest(s"line exceeds $maxBytes bytes")

      val value = in.read()
      if value < 0 then throw EOFException("connection closed inside a chunked body")

      if value == '\n' then
        if !previousWasCr then throw BadRequest("bare LF in chunked body")
        String(out.toByteArray, StandardCharsets.ISO_8859_1).dropRight(1)
      else
        out.write(value)
        loop(value == '\r')

    loop(false)

  /** The refusal as curl and git see it: a reason inside the tunnel beats a dropped connection.
    *
    * - The parameter is a Socket rather than an SSLSocket, as in relayInspected: nothing here is TLS-specific.
    * - A response to a HEAD keeps the header section and omits the body (RFC 9110 §9.3.2). The reason stays in
    *   Proxy-Status.
    * - `requestMethod` is `-` when the head did not parse, and that answer has a body. */
  def respondInsideTls(
    socket: Socket,
    requestMethod: String,
    status: Int,
    reason: String,
    proxyError: String,
    detail: String,
    advice: Option[String] = None,
  ): Unit =
    respondQuietly(socket, status, reason, proxyError, Some(detail), advice, answersHead = requestMethod == "HEAD")

  /** `detail` is the Proxy-Status `details` and, unless `bodyless`, the body's first line (refusalBody).
    * `bodyless` sends no body and says so (Content-Length: 0). `answersHead` sends the header section that a GET
    * would have received, Content-Length included, without the body. */
  def respondQuietly(
    client: Socket,
    status: Int,
    reason: String,
    proxyError: String,
    detail: Option[String] = None,
    advice: Option[String] = None,
    bodyless: Boolean = false,
    answersHead: Boolean = false,
  ): Unit =
    val body = detail.filterNot(_ => bodyless).fold(Array.emptyByteArray)(refusalBody(_, advice))
    try
      val out = client.getOutputStream
      writeAscii(
        out,
        s"HTTP/1.1 $status $reason\r\n" +
          s"Proxy-Status: ${proxyStatus(proxyError, detail)}\r\n" +
          (if body.isEmpty then "" else "Content-Type: text/plain; charset=utf-8\r\n") +
          s"Content-Length: ${body.length}\r\n" +
          "Connection: close\r\n\r\n",
      )
      if !answersHead then out.write(body)
      out.flush()
    catch case _: IOException => ()

  def writeAscii(out: OutputStream, value: String): Unit =
    out.write(value.getBytes(StandardCharsets.US_ASCII))
    out.flush()
