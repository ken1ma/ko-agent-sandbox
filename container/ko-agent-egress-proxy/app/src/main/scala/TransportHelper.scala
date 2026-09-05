// How an authorized origin address is reached: directly, or through the upstream proxy
// HTTPS_PROXY names. The ruleset decides before either runs, and neither resolves a name: both take
// the addresses resolvePublic vetted. The upstream proxy is a transport the host user's
// environment selected, never an authority — it cannot add a destination, and a failure through
// it is a 502, never a direct retry (SECURITY.md, "Egress proxy").

package agentsandbox.egress

import java.io.IOException
import java.net.{Inet6Address, InetAddress, InetSocketAddress, Socket, UnknownHostException}
import java.nio.charset.StandardCharsets
import java.util.Base64
import javax.net.ssl.{SNIHostName, SNIServerName, SSLContext, SSLSocket}
import scala.annotation.tailrec

import HTTPHelper.*
import IPAddrHelper.*

object TransportHelper:

  /** Read in that order: the launcher passes through whichever of the two its own environment
    * has, uppercase first, and this is the same order. */
  val ProxyVariables = Vector("HTTPS_PROXY", "https_proxy")

  /** A connected origin socket and the vetted address behind it. The address is carried apart
    * from the socket because through the upstream proxy the socket's peer is the proxy, and the
    * audit line records the origin reached. */
  case class OriginSocket(socket: Socket, address: InetAddress)

  /** No origin socket: `attempted` are the vetted addresses actually tried, in order — every one
    * for the direct dial, and through the upstream proxy only those up to the refusal that ended
    * the attempt — so the audit line's `tried` names no address that was never reached for. */
  class TransportFailure(val attempted: Vector[InetAddress], message: String) extends IOException(message)

  trait OriginTransport:
    /** `addresses` are resolvePublic's answer for one authorized host, tried in order. */
    def connect(addresses: Vector[InetAddress], port: Int): OriginSocket

    /** The startup line naming this run's transport (SECURITY.md, "The audit line grammar"). */
    def summary: String

  /** The existing dial loop: each address in turn, the last failure reported when none connects. */
  def dial(addresses: Vector[InetAddress], port: Int): Socket =
    @tailrec
    def loop(remaining: List[InetAddress], lastFailure: Option[IOException]): Socket =
      remaining match
        case Nil =>
          throw lastFailure.getOrElse(IOException("no resolved address could be connected"))

        case address :: rest =>
          val socket = Socket()
          try
            socket.connect(InetSocketAddress(address, port), AgentEgressProxy.ConnectTimeoutMillis)
            socket.setTcpNoDelay(true)
            socket
          catch
            case ex: IOException =>
              closeQuietly(socket)
              loop(rest, Some(ex))

    loop(addresses.toList, None)

  object Direct extends OriginTransport:
    def connect(addresses: Vector[InetAddress], port: Int): OriginSocket =
      val socket =
        try dial(addresses, port)
        catch case ex: IOException => throw TransportFailure(addresses, ex.getMessage)
      OriginSocket(socket, socket.getInetAddress)

    val summary = "egress transport: direct"

  /**
   * The upstream proxy as `variable` — HTTPS_PROXY or its lowercase — spelled it, parsed once at
   * startup. `host` is the normalized name, or a literal as written; `authorization` is the whole
   * `Proxy-Authorization` value, `Basic` and the encoded credential, and the one place the
   * credential lives. Nothing here prints it: `spelled` is the endpoint without userinfo, and
   * every refusal names the part that is wrong, never the value.
   */
  case class UpstreamEndpoint(
    variable: String,
    tls: Boolean,
    host: String,
    literal: Option[InetAddress],
    port: Int,
    authorization: Option[String],
  ):
    def spelled: String =
      val authority = if host.contains(':') then s"[$host]" else host
      s"${if tls then "https" else "http"}://$authority:$port"

    /** Resolved once, before `bind`, and pinned for the run. A private address is fine here —
      * reaching the upstream proxy is the feature — and so is loopback, which the host-served
      * proxy of a `--run-on-host` build may legitimately name; in the container it is the
      * container's own, and connecting fails there per request, naming the endpoint. */
    def resolve(): Vector[InetAddress] =
      literal match
        case Some(address) => Vector(address)
        case None =>
          try InetAddress.getAllByName(host).toVector
          catch
            case ex: UnknownHostException =>
              throw IOException(s"the upstream proxy $spelled does not resolve: ${ex.getMessage}")

  object UpstreamEndpoint:

    def configured(read: String => Option[String]): Option[UpstreamEndpoint] =
      ProxyVariables.iterator
        .flatMap(variable => read(variable).filter(_.nonEmpty).map(value => parse(value, variable)))
        .nextOption()

    def parse(value: String, variable: String): UpstreamEndpoint =
      def refuse(problem: String): Nothing =
        throw IllegalArgumentException(s"$variable $problem; the form is http[s]://[user:password@]host:port")

      if value.exists(ch => ch.isWhitespace || isForbiddenControl(ch)) then
        refuse("contains whitespace or a control character")

      val (tls, afterScheme) =
        if value.startsWith("http://") then (false, value.drop("http://".length))
        else if value.startsWith("https://") then (true, value.drop("https://".length))
        else refuse("does not start with http:// or https://")

      if afterScheme.exists(ch => ch == '?' || ch == '#') then refuse("carries a query or fragment")
      val (authority, path) = afterScheme.indexOf('/') match
        case -1 => (afterScheme, "")
        case i  => (afterScheme.substring(0, i), afterScheme.substring(i))
      if path != "" && path != "/" then refuse("carries a path")

      val (userinfo, hostPort) = authority.lastIndexOf('@') match
        case -1 => (None, authority)
        case i  => (Some(authority.substring(0, i)), authority.substring(i + 1))

      val (hostText, portText) =
        if hostPort.startsWith("[") then
          hostPort.indexOf("]:") match
            case -1 => refuse("has a bracketed host without a port after it")
            case i  => (hostPort.substring(1, i), hostPort.substring(i + 2))
        else
          hostPort.lastIndexOf(':') match
            case -1                              => refuse("has no port; the port must be explicit")
            case i if hostPort.indexOf(':') != i => refuse("has an IPv6 literal without brackets")
            case i                               => (hostPort.substring(0, i), hostPort.substring(i + 1))
      if hostText.isEmpty then refuse("has an empty host")
      val port =
        portText.toIntOption
          .filter(p => 1 <= p && p <= 65535)
          .getOrElse(refuse("has no port; the port must be explicit"))

      val (host, literal) =
        if hostPort.startsWith("[") then
          val address =
            try InetAddress.ofLiteral(hostText)
            catch case _: IllegalArgumentException => refuse("has a bracketed host that is not an IPv6 literal")
          if !address.isInstanceOf[Inet6Address] then refuse("has a bracketed host that is not an IPv6 literal")
          (hostText, Some(address))
        else if isIpLiteral(hostText) then
          val address =
            try InetAddress.ofLiteral(hostText)
            catch case _: IllegalArgumentException => refuse("has a host that is neither a hostname nor an IP literal")
          (hostText, Some(address))
        else
          val name =
            try normalizeHost(hostText)
            catch case ex: BadRequest => refuse(s"has a host that is not a hostname: ${ex.getMessage}")
          (name, None)

      UpstreamEndpoint(variable, tls, host, literal, port, userinfo.map(basicAuthorization(_, refuse)))

    /** RFC 7617: `user:password`, each part as the URL percent-encoded it, the user-id free of
      * `:` since that is the separator. UTF-8, as curl sends it. */
    def basicAuthorization(userinfo: String, refuse: String => Nothing): String =
      val (user, password) = userinfo.indexOf(':') match
        case -1 => (userinfo, "")
        case i  => (userinfo.substring(0, i), userinfo.substring(i + 1))
      if user.isEmpty then refuse("has userinfo with an empty user")
      val decodedUser = percentDecode(user, refuse)
      if decodedUser.contains(':') then refuse("has a user containing ':'")
      val credential = s"$decodedUser:${percentDecode(password, refuse)}"
      if credential.exists(isForbiddenControl) then refuse("has a credential containing a control character")
      "Basic " + Base64.getEncoder.encodeToString(credential.getBytes(StandardCharsets.UTF_8))

    /** Escapes to their bytes, everything else — a literal non-ASCII character included — to its
      * UTF-8 bytes, so the two spellings of one credential decode alike. */
    def percentDecode(text: String, refuse: String => Nothing): String =
      val out = java.io.ByteArrayOutputStream()
      @tailrec
      def loop(i: Int): Unit =
        if i < text.length then
          if text.charAt(i) == '%' then
            val hex = Option.when(i + 3 <= text.length)(text.substring(i + 1, i + 3))
            val byte = hex.filter(_.forall(ch => Character.digit(ch, 16) >= 0)).map(Integer.parseInt(_, 16))
            out.write(byte.getOrElse(refuse("has a malformed percent-escape in its userinfo")))
            loop(i + 3)
          else
            val codePoint = text.codePointAt(i)
            out.write(Character.toString(codePoint).getBytes(StandardCharsets.UTF_8))
            loop(i + Character.charCount(codePoint))
      loop(0)
      String(out.toByteArray, StandardCharsets.UTF_8)

  /**
   * One CONNECT to the upstream proxy per origin address, naming the vetted numeric address —
   * never the hostname, which would let the upstream proxy resolve it to something the
   * private-range check never saw. The tunnel socket then carries the same TLS the direct socket
   * would: the client's own hello on an opaque host, the inspected connection with the origin's
   * name as SNI otherwise.
   */
  class UpstreamProxy(val endpoint: UpstreamEndpoint, val pinned: Vector[InetAddress]) extends OriginTransport:

    val summary = s"egress transport: upstream proxy ${endpoint.spelled} -> " +
      s"${pinned.map(_.getHostAddress).mkString(" ")} (${endpoint.variable})"

    def connect(addresses: Vector[InetAddress], port: Int): OriginSocket =
      @tailrec
      def loop(
        remaining: List[InetAddress],
        attempted: Vector[InetAddress],
        lastFailure: Option[IOException],
      ): OriginSocket =
        remaining match
          case Nil =>
            throw TransportFailure(
              attempted,
              lastFailure.fold("no resolved address could be connected")(_.getMessage),
            )

          case address :: rest =>
            val outcome =
              try tunnelTo(address, port)
              catch case ex: IOException => throw TransportFailure(attempted :+ address, ex.getMessage)
            outcome match
              case Right(socket) => OriginSocket(socket, address)
              case Left(ex)      => loop(rest, attempted :+ address, Some(ex))

      loop(addresses.toList, Vector.empty, None)

    /** Left is the retryable outcome — the upstream proxy could not reach this address, as a
      * failed direct connect is — so the next address is tried; anything else ends the attempt. */
    private def tunnelTo(address: InetAddress, port: Int): Either[IOException, Socket] =
      val link =
        val socket =
          try dial(pinned, endpoint.port)
          catch case ex: IOException => throw IOException(s"upstream proxy ${endpoint.spelled}: ${ex.getMessage}")
        if !endpoint.tls then socket
        else
          try secure(socket)
          catch
            case ex: IOException =>
              closeQuietly(socket)
              throw IOException(s"upstream proxy ${endpoint.spelled}: ${ex.getMessage}")

      try
        link.setSoTimeout(AgentEgressProxy.HandshakeTimeoutMillis)
        writeAscii(link.getOutputStream, connectRequest(address, port))
        val head = responseHead(link)
        head.status match
          case status if status / 100 == 2 =>
            if head.values("Content-Length").nonEmpty || head.values("Transfer-Encoding").nonEmpty then
              throw IOException("upstream proxy answered 2xx with body framing")
            link.setSoTimeout(0)
            Right(link)
          case 407 =>
            throw IOException("upstream proxy authentication required")
          case status @ (502 | 503 | 504) =>
            closeQuietly(link)
            Left(IOException(s"upstream proxy returned $status"))
          case status if status / 100 == 1 =>
            throw IOException("upstream proxy answered a CONNECT with an informational response")
          case status =>
            throw IOException(s"upstream proxy returned $status")
      catch
        case ex: IOException =>
          closeQuietly(link)
          throw ex

    def connectRequest(address: InetAddress, port: Int): String =
      val authority = address match
        case v6: Inet6Address => s"[${v6.getHostAddress}]:$port"
        case v4               => s"${v4.getHostAddress}:$port"
      s"CONNECT $authority HTTP/1.1\r\nHost: $authority\r\n" +
        endpoint.authorization.fold("")(value => s"Proxy-Authorization: $value\r\n") +
        "\r\n"

    private def responseHead(link: Socket): HttpResponseHead =
      val bytes =
        try readHttpHeader(link.getInputStream, AgentEgressProxy.MaxHttpHeaderBytes)
        catch
          case _: ClosedWithoutRequest => throw IOException("upstream proxy closed before answering the CONNECT")
          case ex: BadRequest          => throw IOException(s"upstream proxy response head: ${ex.getMessage}")
      HttpResponseHead.parse(bytes, "upstream proxy response head")

    /** The endpoint's own TLS, verified against the image's public roots for the name or literal
      * HTTPS_PROXY spelled, before a byte — the credential included — is sent. */
    private def secure(socket: Socket): SSLSocket =
      val tls =
        SSLContext.getDefault.getSocketFactory
          .createSocket(socket, endpoint.host, endpoint.port, true)
          .asInstanceOf[SSLSocket]
      val parameters = tls.getSSLParameters
      parameters.setEndpointIdentificationAlgorithm("HTTPS")
      if endpoint.literal.isEmpty then
        parameters.setServerNames(java.util.List.of[SNIServerName](SNIHostName(endpoint.host)))
      tls.setSSLParameters(parameters)
      tls.setSoTimeout(AgentEgressProxy.HandshakeTimeoutMillis)
      tls.startHandshake()
      tls

  /** The transport a run uses, from its environment: direct unless HTTPS_PROXY is set. Parse
    * refusals are IllegalArgumentException, a failed endpoint resolution IOException — both end
    * the start before `bind`. */
  def originTransport(read: String => Option[String]): OriginTransport =
    UpstreamEndpoint.configured(read) match
      case None           => Direct
      case Some(endpoint) => UpstreamProxy(endpoint, endpoint.resolve())

  def closeQuietly(socket: Socket): Unit =
    try socket.close()
    catch case _: IOException => ()
