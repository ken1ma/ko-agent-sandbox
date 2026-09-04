// The egress proxy: the listening loop, the flow from CONNECT to tunnel, and the one-request
// inspected session. The policy and its decisions live in PolicyHelper.scala, the audit log's form
// in LogHelper.scala, the refusal types and advice in Refusals.scala, HTTP handling in
// HTTPHelper.scala, TLS handling in TLSHelper.scala, leaf minting in X509Helper.scala, git protocol
// knowledge in GitHelper.scala, and hostname/address vetting in IPAddrHelper.scala.

package agentsandbox.egress

import java.io.{FileOutputStream, IOException, InputStream, OutputStream, PrintStream}
import java.net.{InetAddress, InetSocketAddress, ServerSocket, Socket, SocketException}
import java.nio.file.Path
import java.time.Instant
import java.security.GeneralSecurityException
import java.util.concurrent.{CountDownLatch, Executors, Semaphore}
import scala.annotation.tailrec
import scala.util.control.NonFatal

import HTTPHelper.*
import IPAddrHelper.*
import LogHelper.*
import PolicyHelper.*
import TLSHelper.*

object AgentEgressProxy:

  val ListenPort = 3128

  /** Printed after `bind` and before any policy line, so a reader that saw it has a proxy
    * accepting connections; every refusal made before then ends the process instead. The
    * launcher gates the sandbox on this spelling, after the stamp every line here starts with
    * (AgentSandboxLauncher.isProxyReadyLine); ProxyContainerTest holds the two together.
    * The port printed is the bound one, so a caller that set EGRESS_BIND with port 0 reads
    * its ephemeral port from this line. */
  def readyLine(port: Int) = s"agent-egress-proxy listening on :$port"
  val ReadyLine = readyLine(ListenPort)

  val ConnectTimeoutMillis = 10_000
  val HandshakeTimeoutMillis = 10_000
  val MaxHttpHeaderBytes = 16 * 1024
  val MaxClientHelloBytes = 64 * 1024
  val MaxConcurrentConnections = 256

  /*
   * An inspected session is one HTTP request and its response, so this bounds
   * inactivity rather than total duration: a `git clone` of a large repository
   * transfers continuously and never approaches it, while GitHub counting
   * objects before the first byte can legitimately take minutes.
   */
  val InspectedIdleTimeoutMillis = 300_000

  val CertificateVariable = "EGRESS_TLS_CERTIFICATE"
  val PrivateKeyVariable = "EGRESS_TLS_PRIVATE_KEY"
  val CaCertificateVariable = "EGRESS_TLS_CA_CERTIFICATE"
  val CaPrivateKeyVariable = "EGRESS_TLS_CA_PRIVATE_KEY"
  val LogFileVariable = "EGRESS_LOG_FILE"
  val BindVariable = "EGRESS_BIND"

  val executor = Executors.newVirtualThreadPerTaskExecutor()
  val connectionSlots = Semaphore(MaxConcurrentConnections)

  def main(args: Array[String]): Unit =
    args.toList match
      case Nil                                       => serve()
      case "--print-policy" :: Nil                   => printPolicy(provenance = false)
      case "--print-policy" :: "--provenance" :: Nil => printPolicy(provenance = true)
      case "--check-host" :: host :: Nil             => checkHost(host)
      case _ =>
        System.err.println(
          "agent-egress-proxy takes no arguments, --print-policy [--provenance] to " +
            "resolve the policy, print it, and exit, or --check-host <host> to report " +
            "one host's policy decision and current resolution",
        )
        sys.exit(2)

  /*
   * The dry run behind --egress-effective and every launch: no port, no log, a
   * pure computation the launcher runs --network=none to read back what would
   * be enforced. The policy lines are also where the launcher reads the leaf
   * certificate's names from. Warnings — a deny matching nothing, a redundant
   * grant, a selected provider the profile does not fully admit — go to
   * stderr, so the data lines pipe cleanly.
   *
   * The lines say what this policy *would* inspect, not what a given
   * run will: unlike serve() this reads no certificate, because the dry run
   * is not given one. Every launch mounts the leaf, or under allow-unless-denied
   * the run CA, so the two agree there; only the standalone image run without
   * material logs the inspected hosts as opaque.
   */
  def printPolicy(provenance: Boolean): Unit =
    try
      val resolved = configuredPolicy()
      policyLines(resolved).foreach(println)
      metadataLines(resolved).foreach(println)
      if provenance then provenanceLines(resolved).foreach(println)
      resolved.warnings.foreach(warning => System.err.println(s"warning: $warning"))
    catch
      case ex: IllegalArgumentException =>
        System.err.println(ex.getMessage)
        sys.exit(2)

  /*
   * One host's fate under the resolved policy, plus the current resolution
   * evidence — separately, because the policy decision is fixed per run
   * while a connection resolves and validates the destination again when it
   * is made. Run by the launcher's --egress-check through a one-shot
   * container on a network built as the session's egress network is, so the
   * resolver path is enforcement's, never the launcher host's.
   */
  def checkHost(rawHost: String): Unit =
    val resolved =
      try configuredPolicy()
      catch
        case ex: IllegalArgumentException =>
          System.err.println(ex.getMessage)
          sys.exit(2)

    val host =
      try normalizeHost(rawHost)
      catch
        case ex: BadRequest =>
          System.err.println(s"'$rawHost' is not a hostname: ${ex.getMessage}")
          sys.exit(2)

    // The decision is authorizeRequest's own — the very function a CONNECT meets — so this
    // diagnostic cannot disagree with enforcement: an IP-literal target, a denied host and a
    // non-admitted host all answer here exactly as they would on the wire, in enforcement's
    // words. Only an accepted host's treatment is looked up on top, its resolved lines, one
    // per scope.
    val decisions =
      try
        val authorized = authorizeRequest(ConnectRequest(host, 443), resolved)
        resolved.hosts.get(authorized) match
          case Some(treatment) => ruleLines(authorized, treatment)
          case None            => Vector("read (the public-HTTPS default)")
      catch case ex: PolicyViolation => Vector(s"refused: ${ex.getMessage}")
    decisions.foreach(decision => println(s"policy: $host $decision"))

    try println(s"resolves: ${resolvePublic(host).map(_.getHostAddress).mkString(" ")}")
    catch
      case ex: PolicyViolation => println(s"resolves: refused: ${ex.getMessage}")
      case ex: IOException     => println(s"resolves: failed: ${ex.getMessage}")

  def configuredPolicy(read: String => Option[String] = variable => Option(System.getenv(variable))): ResolvedEgress =
    RetiredVariables.filter(variable => read(variable).nonEmpty).foreach: variable =>
      throw IllegalArgumentException(
        s"$variable is set, which this proxy no longer reads; the policy is one file, in $RuleVariable",
      )
    resolvePolicy(read(ProfileVariable), read(ModelProviderVariable), read(RuleVariable))

  /**
   * EGRESS_BIND is the listen address: `<ip-literal>:<port>`, IPv6 in brackets, port 0 for an
   * ephemeral one read back from the ready line. Unset is the wildcard on ListenPort, which the
   * container's own network namespace makes safe. A hostname is refused: this is a bind address,
   * and a name would make where the proxy listens depend on the environment's resolver.
   */
  def parseBind(value: Option[String]): InetSocketAddress =
    value.filter(_.nonEmpty) match
      case None => InetSocketAddress(ListenPort)
      case Some(spelled) =>
        def refuse(): Nothing = throw IllegalArgumentException(
          s"$BindVariable is '$spelled'; the form is <ip-literal>:<port>, IPv6 in brackets, port 0 for ephemeral",
        )
        val (address, portText) = spelled match
          case s if s.startsWith("[") =>
            s.indexOf("]:") match
              case -1 => refuse()
              case i  => (s.substring(1, i), s.substring(i + 2))
          case s =>
            s.lastIndexOf(':') match
              case -1                       => refuse()
              case i if s.indexOf(':') != i => refuse() // an unbracketed IPv6 literal
              case i                        => (s.substring(0, i), s.substring(i + 1))
        val port = portText.toIntOption.filter(p => 0 <= p && p <= 65535).getOrElse(refuse())
        val literal =
          try InetAddress.ofLiteral(address)
          catch case _: IllegalArgumentException => refuse()
        InetSocketAddress(literal, port)

  def serve(): Unit =
    /*
     * Everything reported goes to stderr and, with EGRESS_LOG_FILE set, to
     * that host file too. Set up first so the startup lines land in it, and
     * failing loudly: an enforcement point whose audit trail cannot be
     * written should not start.
     */
    val sinks = Option(System.getenv(LogFileVariable)).filter(_.nonEmpty) match
      case Some(path) => teeOutput(System.err, FileOutputStream(path, true))
      case None       => System.err
    System.setErr(PrintStream(stampLines(sinks, () => Instant.now()), true))

    /*
     * Resolved before binding the port: a malformed policy or bind address is
     * a container that fails to start, with the one-line reason — a stack
     * trace would read as a proxy bug. Launches never get here (the launcher
     * dry-runs the same variables first); this is the standalone-image path,
     * or inspection material that cannot be read or names a set other than
     * the one this policy inspects.
     */
    val (policy, bind) =
      try
        val resolved = configuredPolicy()
        (EgressPolicy(resolved, loadInspection(resolved)), parseBind(Option(System.getenv(BindVariable))))
      catch
        case ex: IllegalArgumentException =>
          System.err.println(ex.getMessage)
          sys.exit(2)

        // What TlsInspection.load throws for material that exists but cannot be read or parsed.
        case ex: (IOException | GeneralSecurityException) =>
          System.err.println(s"cannot load the TLS inspection material: ${ex.getMessage}")
          sys.exit(2)

    val server = ServerSocket()
    server.setReuseAddress(true)
    server.bind(bind)

    System.err.println(readyLine(server.getLocalPort))
    val lines = policyLines(policy.resolved)
    lines.foreach(System.err.println)
    // The digest gives the audit log one stable, grep-able line naming which policy this run
    // enforced, comparable across runs without diffing the lines above.
    System.err.println(s"resolved-policy digest: ${sha256Hex(lines.mkString("\n"))}")
    metadataLines(policy.resolved).foreach(System.err.println)
    policy.resolved.warnings.foreach(warning => System.err.println(s"warning: $warning"))
    System.err.println(policy.inspectionSummary)

    acceptForever(server, policy)

  /*
   * The material a proxy starts with is keyed by profile. Under the three finite profiles the
   * leaf and its key are present exactly when the policy inspects a host: both absent is the
   * image running on its own, inspection off and said so; material for a policy that inspects
   * nothing is an error, not a narrower policy, since the launcher never mints a leaf for such a
   * policy and a supplied one means the two disagree about what this policy is. Under
   * allow-unless-denied the run CA and its key are present, and no leaf: every unlisted host is
   * inspected, and without the CA each would be the writable tunnel this profile no longer admits,
   * so their absence refuses the start. Either pair under the other profile is refused likewise
   * (SECURITY.md, "Who holds the CA key").
   */
  def loadInspection(
    resolved: ResolvedEgress,
    read: String => Option[String] = variable => Option(System.getenv(variable)),
  ): Option[TlsInspection] =
    def pair(certificateVariable: String, keyVariable: String): Option[(Path, Path)] =
      (read(certificateVariable).filter(_.nonEmpty), read(keyVariable).filter(_.nonEmpty)) match
        case (Some(certificate), Some(key)) => Some((Path.of(certificate), Path.of(key)))
        case (None, None)                   => None
        case _ => throw IllegalArgumentException(s"$certificateVariable and $keyVariable must be set together")
    val leaf = pair(CertificateVariable, PrivateKeyVariable)
    val ca = pair(CaCertificateVariable, CaPrivateKeyVariable)

    if resolved.publicDefault then
      if leaf.nonEmpty then
        throw IllegalArgumentException(
          s"$CertificateVariable is set under ${resolved.profile}, which mints every leaf from " +
            s"$CaCertificateVariable and takes none",
        )
      val (certificate, key) = ca.getOrElse(
        throw IllegalArgumentException(
          s"$CaCertificateVariable and $CaPrivateKeyVariable are unset under ${resolved.profile}, which " +
            "inspects every unlisted host and mints their leaves from the run CA",
        ),
      )
      Some(TlsInspection.minting(certificate, key))
    else
      if ca.nonEmpty then
        throw IllegalArgumentException(
          s"$CaCertificateVariable is set under ${resolved.profile}, which mints nothing; the CA key never " +
            "enters this container there",
        )
      leaf.map: (certificate, key) =>
        if resolved.inspected.isEmpty then
          throw IllegalArgumentException(
            s"$CertificateVariable is set, but this policy restricts no host; " +
              "with nothing to inspect the material can only be a mistake",
          )
        TlsInspection.load(certificate, key, resolved.inspected)

  case class EgressPolicy(
    resolved: ResolvedEgress,
    inspection: Option[TlsInspection],
  ):
    def inspectionSummary: String =
      inspection match
        case Some(_) if resolved.publicDefault =>
          s"tls inspection: every admitted host, except the ${resolved.tunnelHosts.size} tunnel hosts"
        case Some(_) =>
          s"tls inspection: active for the ${resolved.inspected.size} inspected hosts"
        case None =>
          "tls inspection: off; every allowed host is an opaque, writable tunnel"

  @tailrec
  def acceptForever(server: ServerSocket, policy: EgressPolicy): Unit =
    /*
     * A failed accept must not take the proxy down: every agent behind it
     * would lose network access until someone noticed. A closed listening
     * socket is the one unrecoverable case, and ends the loop rather than
     * spinning on it.
     */
    val accepted =
      try Some(server.accept())
      catch
        case ex: IOException =>
          System.err.println(s"accept failed: ${ex.getMessage}")
          None

    accepted.foreach(client => dispatch(client, policy))

    if !server.isClosed then acceptForever(server, policy)

  def dispatch(client: Socket, policy: EgressPolicy): Unit =
    if !connectionSlots.tryAcquire() then
      try respondQuietly(client, 503, "Service Unavailable")
      finally closeQuietly(client)
    else
      try
        executor.execute(() =>
          try handle(client, policy)
          finally connectionSlots.release(),
        )
      catch
        case NonFatal(ex) =>
          // The permit was acquired above and this connection will never run.
          connectionSlots.release()
          closeQuietly(client)
          System.err.println(s"could not start connection handler: ${ex.getMessage}")

  def handle(client: Socket, policy: EgressPolicy): Unit =
    // The audit context, filled in as parsing learns it: a `-` in the line marks a field the
    // connection ended before revealing. The host is the target as the sandbox requested it —
    // what was asked for, not a name the policy vouches for. auditLine has the grammar.
    var host = "-"
    var addresses = Vector.empty[InetAddress]
    try
      // An IO failure while reading the request is the client's, not upstream's; rethrown as a
      // BadRequest so the log does not blame an upstream the proxy never dialled, with a 502.
      val request =
        try
          client.setSoTimeout(HandshakeTimeoutMillis)
          client.setTcpNoDelay(true)
          ConnectRequest.parse(
            readHttpHeader(client.getInputStream, MaxHttpHeaderBytes),
          )
        catch
          case ex: IOException =>
            throw BadRequest(s"unreadable CONNECT request: ${ex.getMessage}")

      host = request.host
      host = authorizeRequest(request, policy.resolved)
      addresses = resolvePublic(host)
      val upstream = connect(addresses, request.port)

      try runEstablishedTunnel(client, upstream, host, policy)
      finally closeQuietly(upstream)

    catch
      case _: ClosedWithoutRequest =>
        System.err.println(auditLine("error", host, "-", "", "client closed before sending a request"))

      case ex: BadRequest =>
        // Parse failures keep `-` in the method field: it never holds a token the proxy did not
        // admit, so a refused method is named in the text, not promoted to the vocabulary.
        System.err.println(auditLine("deny", host, "-", "", ex.getMessage))
        respondQuietly(client, 400, "Bad Request")

      case ex: PolicyViolation =>
        System.err.println(auditLine("deny", host, "CONNECT", "", ex.getMessage))
        // A failed CONNECT may carry a body (RFC 9110 §9.3.6 forbids one on a 2xx only). No client
        // shows it; the image's sandbox-egress-check reads it, and is the only way this refusal's
        // reason reaches the sandbox.
        respondQuietly(client, 403, "Forbidden", refusalBody(ex.getMessage, Some(ex.advice)))

      case ex: IOException =>
        val stage =
          if addresses.isEmpty then "resolution:"
          else s"tried ${addresses.map(_.getHostAddress).mkString(" ")}:"
        System.err.println(auditLine("error", host, "CONNECT", "", s"$stage ${ex.getMessage}"))
        respondQuietly(client, 502, "Bad Gateway")

      case NonFatal(ex) =>
        System.err.println(
          auditLine("error", host, "CONNECT", "", s"internal: ${ex.getClass.getSimpleName}: ${ex.getMessage}"),
        )
        respondQuietly(client, 500, "Internal Server Error")

    finally
      closeQuietly(client)

  def runEstablishedTunnel(
    client: Socket,
    upstream: Socket,
    connectHost: String,
    policy: EgressPolicy,
  ): Unit =
    writeAscii(client.getOutputStream, "HTTP/1.1 200 Connection Established\r\n\r\n")

    try
      val hello =
        TlsClientHello.read(
          client.getInputStream,
          MaxClientHelloBytes,
        )

      validateTlsIdentity(connectHost, hello)

      // A tunnel host is opaque; every other admitted host is inspected, with its lines' scopes or
      // the public default's (ResolvedPolicy.scopesOf) — unless this run has no material at all.
      policy.inspection.filter(_ => !policy.resolved.tunnelHosts.contains(connectHost)) match
        case Some(inspection) =>
          runInspectedSession(
            client, upstream, connectHost, hello, inspection,
            policy.resolved.scopesOf(connectHost),
            policy.resolved.admits,
          )

        case None =>
          System.err.println(
            auditLine("allow", connectHost, "CONNECT", "", s"-> ${upstream.getInetAddress.getHostAddress}"),
          )

          /*
           * TlsClientHello.read consumed the records needed to inspect the
           * ClientHello. Forward those exact bytes unchanged before switching
           * to an opaque bidirectional tunnel.
           */
          upstream.getOutputStream.write(hello.wireBytes)
          upstream.getOutputStream.flush()

          client.setSoTimeout(0)
          upstream.setSoTimeout(0)

          tunnel(client, upstream)

    catch
      /*
       * HTTP 200 has already been sent, so an HTTP error response would be
       * protocol garbage at this point. Fail closed by dropping the tunnel.
       */
      case ex: BadTls =>
        System.err.println(auditLine("deny", connectHost, "CONNECT", "", ex.getMessage))

      case ex: BadRequest =>
        System.err.println(auditLine("deny", connectHost, "CONNECT", "", ex.getMessage))

      case ex: PolicyViolation =>
        System.err.println(auditLine("deny", connectHost, "CONNECT", "", ex.getMessage))

      case ex: IOException =>
        System.err.println(auditLine("error", connectHost, "CONNECT", "", s"tunnel: ${ex.getMessage}"))

      case NonFatal(ex) =>
        System.err.println(
          auditLine(
            "error", connectHost, "CONNECT", "",
            s"internal: ${ex.getClass.getSimpleName}: ${ex.getMessage}",
          ),
        )

  /*
   * One request and its response, then the connection ends — and both peers are told: the
   * request goes upstream with `Connection: close` (end-of-stream then frames the response),
   * and the response reaches the client with this proxy's own `Connection: close`, whatever the
   * origin's hop said (toClientBytes). Keeping the connection alive would mean agreeing with
   * the origin about where each message ends — the exact disagreement request smuggling
   * exploits. After the response the client is only drained (drainClient), never answered
   * again. Cost: a handshake per request — `git fetch` is two.
   */
  def runInspectedSession(
    client: Socket,
    upstream: Socket,
    host: String,
    hello: TlsClientHello,
    inspection: TlsInspection,
    hostScopes: Map[String, Set[String]],
    admitted: String => Boolean,
  ): Unit =
    val clientTls = inspection.accept(client, hello.wireBytes, host)

    // The in-tunnel audit context, like handle()'s: `-` until the request head parses. The allow
    // line prints only after the origin leg connects, so a failing request's method and target
    // must ride the deny/error line or they would never be recorded.
    var method = "-"
    var target = ""

    try
      try
        val head =
          HttpRequestHead.parse(
            readHttpHeader(clientTls.getInputStream, MaxHttpHeaderBytes),
          )
        method = head.method
        target = head.target

        authorizeInspectedRequest(host, head, hostScopes, admitted)

        val upstreamTls = inspection.connect(upstream, host)

        try
          System.err.println(
            auditLine("allow", host, method, target, s"-> ${upstream.getInetAddress.getHostAddress}"),
          )

          relayInspected(clientTls, upstreamTls, host, head)
        finally closeQuietly(upstreamTls)

      catch
        case _: ClosedWithoutRequest =>
          // Logged even so: a TLS-handshaked connection must not vanish without a line. No
          // response; peer gone.
          System.err.println(
            auditLine("error", host, method, target, "client closed before sending a request"),
          )

        case ex: TruncatedResponse =>
          System.err.println(auditLine("error", host, method, target, s"relay: ${ex.getMessage}"))
          // The head already reached the client, so there is no 502 to send; the abortive close
          // (linger 0: RST, no clean TLS end) is what keeps the stump from reading as the whole.
          try client.setSoLinger(true, 0)
          catch case _: SocketException => ()

        case ex: BadRequest =>
          System.err.println(auditLine("deny", host, method, target, ex.getMessage))
          respondInsideTls(clientTls, 400, "Bad Request", ex.getMessage)

        case ex: PolicyViolation =>
          System.err.println(auditLine("deny", host, method, target, ex.getMessage))
          respondInsideTls(clientTls, 403, "Forbidden", ex.getMessage, Some(ex.advice))

        case ex: IOException =>
          System.err.println(auditLine("error", host, method, target, s"origin: ${ex.getMessage}"))
          respondInsideTls(clientTls, 502, "Bad Gateway", ex.getMessage)

    finally closeQuietly(clientTls)

  /*
   * Up to and including the response head, an IOException is still reportable as a 502 and left
   * to the caller — which is why the head is parsed here before a byte of it reaches the client:
   * its framing is what tells a completed body from a truncated one. Once the head is forwarded
   * there is no status to send; a body failure is logged here, except a framing violation, which
   * escapes as TruncatedResponse for the caller's abortive close.
   */
  // Socket rather than SSLSocket: nothing here is TLS-specific — the sockets arrive already
  // inside the tunnel — and plain sockets are what lets the relay be tested on loopback pairs.
  def relayInspected(
    clientTls: Socket,
    upstreamTls: Socket,
    host: String,
    head: HttpRequestHead,
  ): Unit =
    val toUpstream = upstreamTls.getOutputStream

    clientTls.setSoTimeout(InspectedIdleTimeoutMillis)
    upstreamTls.setSoTimeout(InspectedIdleTimeoutMillis)

    toUpstream.write(head.toUpstreamBytes)
    // The 100 the client is waiting for is this proxy's to send: the Expect never goes upstream
    // (toUpstreamBytes has the why), and without an answer the client stalls before its body.
    if head.expectsContinue then
      writeAscii(clientTls.getOutputStream, "HTTP/1.1 100 Continue\r\n\r\n")
    forwardRequestBody(clientTls.getInputStream, toUpstream, head.bodyFraming)
    toUpstream.flush()

    val fromUpstream = upstreamTls.getInputStream
    val toClient = clientTls.getOutputStream

    @tailrec
    def finalResponseHead(): HttpResponseHead =
      val bytes =
        try readHttpHeader(fromUpstream, MaxHttpHeaderBytes)
        catch
          case _: ClosedWithoutRequest => throw IOException("origin closed before the response head")
          case ex: BadRequest          => throw IOException(s"origin response head: ${ex.getMessage}")

      val response = HttpResponseHead.parse(bytes)
      if response.status / 100 == 1 then
        toClient.write(response.rawBytes)
        finalResponseHead()
      else response

    val response = finalResponseHead()
    val framing = response.bodyFraming(head.method) // before the head is forwarded: still 502able

    toClient.write(response.toClientBytes)
    try
      forwardResponseBody(fromUpstream, toClient, framing)
      toClient.flush()
      drainClient(clientTls)
    catch
      case ex: IOException =>
        System.err.println(
          auditLine("error", host, head.method, head.target, s"relay: ${ex.getMessage}"),
        )

  val DrainTimeoutMillis = 2_000

  /**
   * Consume whatever the client still sends, until its EOF, bounded: closing with unread bytes
   * in the receive buffer turns the close into an RST, and an RST destroys the just-written
   * response's unread tail in the client's stack. A request pipelined past `Connection: close`
   * lands here and is discarded unanswered; a client still flooding at the cap gets the RST it
   * asked for.
   */
  def drainClient(clientTls: Socket): Unit =
    try
      clientTls.setSoTimeout(DrainTimeoutMillis)
      val buffer = new Array[Byte](8 * 1024)

      @tailrec
      def loop(remaining: Int): Unit =
        if remaining > 0 then
          val read = clientTls.getInputStream.read(buffer, 0, math.min(buffer.length, remaining))
          if read >= 0 then loop(remaining - read)

      loop(64 * 1024)
    catch case _: IOException => ()

  def connect(
    addresses: Vector[InetAddress],
    port: Int,
  ): Socket =
    @tailrec
    def loop(
      remaining: List[InetAddress],
      lastFailure: Option[IOException],
    ): Socket =
      remaining match
        case Nil =>
          throw lastFailure.getOrElse(
            IOException("no resolved address could be connected"),
          )

        case address :: rest =>
          val socket = Socket()
          try
            socket.connect(
              InetSocketAddress(address, port),
              ConnectTimeoutMillis,
            )
            socket.setTcpNoDelay(true)
            socket
          catch
            case ex: IOException =>
              closeQuietly(socket)
              loop(rest, Some(ex))

    loop(addresses.toList, None)

  def tunnel(client: Socket, upstream: Socket): Unit =
    val done = CountDownLatch(2)

    def pump(
      in: InputStream,
      out: OutputStream,
      halfClose: () => Unit,
    ): Unit =
      try
        copyUntilEof(in, out)
        out.flush()
      catch
        case _: SocketException => ()
        case _: IOException     => ()
      finally
        try halfClose()
        catch case _: IOException => ()
        done.countDown()

    executor.execute(() =>
      pump(
        client.getInputStream,
        upstream.getOutputStream,
        () => upstream.shutdownOutput(),
      ),
    )

    executor.execute(() =>
      pump(
        upstream.getInputStream,
        client.getOutputStream,
        () => client.shutdownOutput(),
      ),
    )

    try done.await()
    catch
      case _: InterruptedException =>
        Thread.currentThread().interrupt()

  def closeQuietly(socket: Socket): Unit =
    try socket.close()
    catch case _: IOException => ()
