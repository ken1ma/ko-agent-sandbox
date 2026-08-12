package agentsandbox.egress

import java.io.{ByteArrayOutputStream, EOFException, IOException, InputStream, OutputStream}
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.Locale
import javax.net.ssl.SSLSocket
import scala.annotation.tailrec

import IPAddrHelper.normalizeHost

/**
 * The HTTP surface. Everything here refuses ambiguity rather than resolving
 * it — folded headers, Content-Length beside Transfer-Encoding, conflicting
 * Content-Lengths, bare CR or LF — because a proxy and an origin reading
 * the same bytes differently is what request smuggling exploits. (The
 * duplicate-Host refusal is the policy's: authorizeInspectedRequest.)
 */
object HTTPHelper:

  val MaxChunkLineBytes = 1024

  def readHttpHeader(
    in: InputStream,
    maxBytes: Int
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
        throw BadRequest("connection closed before HTTP header completed")

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
        case "CONNECT" :: authority :: version :: Nil
            if version == "HTTP/1.1" || version == "HTTP/1.0" =>
          parseAuthority(authority)

        case _ =>
          throw BadRequest("expected CONNECT authority HTTP/1.1 or HTTP/1.0")

    def parseAuthority(authority: String): ConnectRequest =
      if authority.isEmpty ||
          authority.exists(ch => ch.isWhitespace || ch > 0x7f)
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
          parsePort(authority.substring(colon + 1))
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

  case class HttpRequestHead(
    method: String,
    target: String,
    version: String,
    headers: Vector[(String, String)]
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

    /** HTTP/1.1, hop-by-hop headers removed, `Connection: close` added —
      * end-of-stream then frames the response. */
    def toUpstreamBytes: Array[Byte] =
      val builder = StringBuilder()

      builder.append(s"$method $target HTTP/1.1\r\n")

      headers
        .filterNot((name, _) => HopByHopHeaders.contains(name.toLowerCase(Locale.ROOT)))
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
      "upgrade"
    )

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
        case method :: target :: version :: Nil
            if version == "HTTP/1.1" || version == "HTTP/1.0" =>
          if method.isEmpty || !method.forall(isHttpTokenChar) then
            throw BadRequest("invalid HTTP method")

          if target.isEmpty then throw BadRequest("empty request target")

          HttpRequestHead(method, target, version, parseHeaders(lines.drop(1)))

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

        (name, line.substring(colon + 1).trim)

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
    framing: BodyFraming
  ): Unit =
    framing match
      case BodyFraming.Empty         => ()
      case BodyFraming.Length(count) => copyExactly(in, out, count)
      case BodyFraming.Chunked       => copyChunked(in, out)

  def copyExactly(in: InputStream, out: OutputStream, count: Long): Unit =
    val buffer = new Array[Byte](16 * 1024)

    @tailrec
    def loop(remaining: Long): Unit =
      if remaining > 0 then
        val wanted = math.min(remaining, buffer.length.toLong).toInt
        val read = in.read(buffer, 0, wanted)

        if read < 0 then
          throw EOFException(s"request body ended $remaining bytes early")

        out.write(buffer, 0, read)
        loop(remaining - read)

    loop(count)

  /** Re-emitted canonically — extensions and trailers dropped — so nothing
    * in it reads differently at the two ends. */
  def copyChunked(in: InputStream, out: OutputStream): Unit =
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
          s"${java.lang.Long.toHexString(size)}\r\n".getBytes(StandardCharsets.US_ASCII)
        )
        copyExactly(in, out, size)

        if readCrLfLine(in, MaxChunkLineBytes).nonEmpty then
          throw BadRequest("chunk not terminated by CRLF")

        out.write("\r\n".getBytes(StandardCharsets.US_ASCII))
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

  /** The refusal curl and git surface: a reason inside the tunnel beats a
    * dropped connection. */
  def respondInsideTls(
    socket: SSLSocket,
    status: Int,
    reason: String,
    detail: String
  ): Unit =
    try
      // encoded once: declared length == bytes sent, non-ASCII included
      val body = s"ko-agent-egress-proxy: $detail\n".getBytes(StandardCharsets.UTF_8)

      val out = socket.getOutputStream
      writeAscii(
        out,
        s"HTTP/1.1 $status $reason\r\n" +
          "Content-Type: text/plain; charset=utf-8\r\n" +
          s"Content-Length: ${body.length}\r\n" +
          "Connection: close\r\n\r\n"
      )
      out.write(body)
      out.flush()
    catch case _: IOException => ()

  def respondQuietly(client: Socket, status: Int, reason: String): Unit =
    try respond(client, status, reason)
    catch case _: IOException => ()

  def respond(client: Socket, status: Int, reason: String): Unit =
    writeAscii(
      client.getOutputStream,
      s"HTTP/1.1 $status $reason\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    )

  def writeAscii(out: OutputStream, value: String): Unit =
    out.write(value.getBytes(StandardCharsets.US_ASCII))
    out.flush()
