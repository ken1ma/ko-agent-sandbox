// The egress proxy: the listening loop, the steps from CONNECT to tunnel, and the one-request inspected connection.
//
// The other files hold the rest:
//
// - RulesetHelper.scala: the ruleset and its decisions;
// - LogHelper.scala: the audit log's form; RequestAudit.scala: an inspected request's fields past the target;
// - Refusals.scala: the refusal types, advice and response wording;
// - HTTPHelper.scala: HTTP handling;
// - TLSHelper.scala: TLS handling;
// - GitHelper.scala: git protocol knowledge;
// - CredentialGrammar.scala: brokered credentials; CredentialRewrite.scala: their rewrite;
// - IPAddrHelper.scala: hostname and address vetting;
// - TransportHelper.scala: how a vetted address is reached, directly or through the upstream proxy that
//   HTTPS_PROXY names.
//
// The proxy issues no certificate. The launcher compiles X509Helper.scala in to issue the leaf, and the file sits in
// the proxy's sources because the proxy's tests issue their leaves with it.

package agentsandbox.egress

import java.io.{FileInputStream, FileOutputStream, IOException, InputStream, OutputStream, PrintStream}
import java.net.{InetAddress, InetSocketAddress, ServerSocket, Socket, SocketException}
import java.nio.file.{AccessDeniedException, NoSuchFileException, Path}
import java.time.{Duration, Instant}
import java.security.GeneralSecurityException
import java.util.concurrent.{CountDownLatch, Executors, Semaphore}
import scala.annotation.tailrec
import scala.util.control.NonFatal

import CredentialRewrite.*
import HTTPHelper.*
import IPAddrHelper.*
import LogHelper.*
import Refusals.*
import RulesetHelper.*
import TLSHelper.*
import TransportHelper.*

object AgentEgressProxy:

  val ListenPort = 3128

  /** Printed after `bind` and before any ruleset line, so a reader that saw this line has a proxy accepting
    * connections.
    *
    * - Every refusal made before this line ends the process instead. After this line, only an audit log that
    *   stopped taking the startup lines ends the process (serve).
    * - The launcher starts the sandbox only after this spelling, which follows the stamp that every line here
    *   starts with (AgentSandboxLauncher.isProxyReadyLine). ProxyContainerTest holds the two together.
    * - The line prints the bound port, so a caller that set EGRESS_BIND with port 0 reads its ephemeral port from
    *   this line. */
  def readyLine(port: Int) = s"$ReadyText$port"
  private val ReadyText = "ko-agent-egress-proxy listening on :"
  val ReadyLine = readyLine(ListenPort)

  private val ReadyPort = s"${java.util.regex.Pattern.quote(ReadyText)}(\\d+)".r

  /** The port out of a ready line, stamped or not (RunOnHostProxy.awaitProxyPort,
    * AgentSandboxLauncher.isProxyReadyLine). */
  def readyPort(line: String): Option[Int] =
    LogHelper.unstamped(line).getOrElse(line) match
      case ReadyPort(port) => port.toIntOption
      case _               => None

  val ConnectTimeoutMillis = 10_000
  val HandshakeTimeoutMillis = 10_000
  val MaxHttpHeaderBytes = 16 * 1024
  val MaxClientHelloBytes = 64 * 1024
  val MaxConcurrentConnections = 256

  /*
   * An inspected connection is one HTTP request and its response, so this timeout bounds inactivity rather than
   * total duration. A `git clone` of a large repository transfers continuously and never approaches the timeout,
   * while GitHub can legitimately take minutes counting objects before the first byte.
   */
  val InspectedIdleTimeoutMillis = 300_000

  /** Interim responses read past before a final one: a CONNECT's (TransportHelper) or an inspected request's
    * (relayInspected). The bound is a count, because the timeouts bound each read and not the exchange. */
  val MaxInterimResponses = 8

  /** The pause after a failed accept, before the next accept. A failure that persists, such as the process at its
    * descriptor limit, then costs a line per pause in the audit log and no CPU, while connections wait in the listen
    * backlog. A failure that passes delays the next accept by this much. */
  val AcceptFailurePauseMillis = 100

  val CertificateVariable = "EGRESS_TLS_CERTIFICATE"
  val PrivateKeyVariable = "EGRESS_TLS_PRIVATE_KEY"
  val LogFileVariable = "EGRESS_LOG_FILE"
  val BindVariable = "EGRESS_BIND"

  val executor = Executors.newVirtualThreadPerTaskExecutor()
  val connectionSlots = Semaphore(MaxConcurrentConnections)

  val PrintRulesetFlag = "--print-ruleset"
  val ProvenanceFlag = "--provenance"
  val CheckHostFlag = "--check-host"

  def main(args: Array[String]): Unit =
    args.toList match
      case Nil                                       => serve()
      case PrintRulesetFlag :: Nil                   => printRuleset(provenance = false)
      case PrintRulesetFlag :: ProvenanceFlag :: Nil => printRuleset(provenance = true)
      case CheckHostFlag :: host :: Nil              => checkHost(host)
      case _ =>
        System.err.println(
          s"ko-agent-egress-proxy takes no arguments, $PrintRulesetFlag [$ProvenanceFlag] to " +
            s"resolve the ruleset, print it, and exit, or $CheckHostFlag <host> to report " +
            "one host's ruleset decision and current DNS resolution",
        )
        sys.exit(2)

  /*
   * The dry run behind --egress-effective and every launch: no port, no log. The launcher runs this pure
   * computation with --network=none to read back what would be enforced.
   *
   * - The launcher also reads the leaf certificate's names from the ruleset lines.
   * - Warnings (RulesetHelper, `resolveRuleset`) go to stderr, so the data lines pipe cleanly.
   *
   * The dry run receives no inspection material, so these counts describe the configured treatments. serve()
   * reports actual inspection separately: a host-command proxy or a standalone image without material forwards even
   * the configured inspected hosts without inspection.
   */
  def printRuleset(provenance: Boolean): Unit =
    try
      val resolved = configuredRuleset()
      rulesetLines(resolved).foreach(println)
      metadataLines(resolved).foreach(println)
      if provenance then provenanceLines(resolved).foreach(println)
      resolved.warnings.foreach(warning => System.err.println(s"warning: $warning"))
    catch
      case ex: IllegalArgumentException =>
        System.err.println(ex.getMessage)
        sys.exit(2)

  /*
   * One host's decision under the resolved ruleset, plus the current DNS resolution as evidence. The two are
   * separate, because the ruleset's decision is fixed per run, while a connection resolves and validates the
   * destination again when it is made.
   * The launcher's --egress-check runs this through a one-shot container on a network built as the session's egress
   * network is. So the resolver path is enforcement's, never the launcher host's.
   */
  def checkHost(rawHost: String): Unit =
    val resolved =
      try configuredRuleset()
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

    // The decision is authorizeRequest's own, the very function that a CONNECT meets, so this diagnostic cannot
    // disagree with enforcement. An IP-literal target, a denied host and a non-allowed host all answer here exactly
    // as they would on the wire, in enforcement's words. Only an accepted host's treatment is looked up on top: its
    // resolved lines, one per scope.
    val decisions =
      try
        val authorized = authorizeRequest(ConnectRequest(host, 443), resolved)
        ruleLines(authorized, resolved.hosts(authorized))
      catch case ex: Refusal => Vector(s"refused: ${ex.getMessage}")
    decisions.foreach(decision => println(s"ruleset: $host $decision"))

    val addresses =
      try
        val resolved = resolvePublic(host)
        println(s"resolves: ${resolved.map(_.getHostAddress).mkString(" ")}")
        resolved
      catch
        case ex: Refusal =>
          println(s"resolves: refused: ${ex.getMessage}")
          Vector.empty
        case ex: IOException =>
          println(s"resolves: failed: ${ex.getMessage}")
          Vector.empty

    // The check uses the transport that a launch would use, through the same parser, resolution and CONNECT. The check
    // opens one tunnel to the first vetted address and closes the tunnel before any TLS. One tunnel is enough to say
    // whether the upstream proxy allows a numeric CONNECT to this host, without asking the origin anything.
    UpstreamEndpoint.configured(variable => Option(System.getenv(variable))).foreach: endpoint =>
      val transport =
        try UpstreamProxy(endpoint, endpoint.resolve())
        catch
          case ex: (IllegalArgumentException | IOException) =>
            println(s"upstream proxy: refused: ${ex.getMessage}")
            sys.exit(2)
      println(transport.summary.stripPrefix(TransportLineHead))
      addresses.headOption.foreach: address =>
        try
          transport.connect(Vector(address), 443).close()
          println(s"upstream tunnel: established to ${address.getHostAddress}")
        catch case ex: IOException => println(s"upstream tunnel: failed: ${ex.getMessage}")

  def configuredRuleset(read: String => Option[String] = variable => Option(System.getenv(variable))): ResolvedEgress =
    resolveRuleset(read(ProfileVariable), read(ModelProviderVariable), read(RuleVariable))

  /**
   * EGRESS_BIND is the listen address: `<ip-literal>:<port>`, IPv6 in brackets, port 0 for an ephemeral port read
   * back from the ready line.
   *
   * - Unset means the wildcard on ListenPort, which the container's own network namespace makes safe.
   * - A hostname is refused: this is a bind address, and a name would make where the proxy listens depend on the
   *   environment's resolver.
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
        val port = parseDecimal(portText).filter(p => 0 <= p && p <= 65535).map(_.toInt).getOrElse(refuse())
        val literal =
          try InetAddress.ofLiteral(address)
          catch case _: IllegalArgumentException => refuse()
        InetSocketAddress(literal, port)

  def serve(): Unit =
    /*
     * Everything reported goes to stderr and, with EGRESS_LOG_FILE set, to that host file too.
     *
     * - This setup comes first, so the startup lines reach the log, and the setup fails loudly. An enforcement point
     *   whose audit trail cannot be written should not start, and an enforcement point whose log stops being
     *   written serves nothing more (Run.requireAuditLog).
     * - Where a file is set, the file is the log. stderr is then a copy that podman removes with the container, and
     *   stderr's failed writes are not kept.
     * - Without a file, stderr is the log: the run-on-host supervisor redirects stderr into a file.
     * - The sink is the descriptor, not System.err: that PrintStream catches the failure before keepingFirstFailure
     *   could keep it.
     */
    val processStderr = FileOutputStream(java.io.FileDescriptor.err)
    val firstLogFailure = java.util.concurrent.atomic.AtomicReference[IOException]()
    def logFailure = Option(firstLogFailure.get)
    val sinks = Option(System.getenv(LogFileVariable)).filter(_.nonEmpty) match
      case Some(path) =>
        teeOutput(
          keepingFirstFailure(processStderr, java.util.concurrent.atomic.AtomicReference[IOException]()),
          keepingFirstFailure(FileOutputStream(path, true), firstLogFailure),
        )
      case None => keepingFirstFailure(processStderr, firstLogFailure)
    System.setErr(PrintStream(stampLines(sinks, () => Instant.now()), true))

    /*
     * The ruleset resolves before the port is bound. A malformed ruleset or bind address is then a container that
     * fails to start with the one-line reason; a stack trace would read as a proxy bug.
     * Launches never get here, since the launcher dry-runs the same variables first. The branch is the standalone
     * image's path, or the path of inspection material that cannot be read or names a set other than the one this
     * ruleset inspects.
     */
    val (run, bind) =
      try
        val resolved = configuredRuleset()
        val inspection = loadInspection(resolved)
        val credentials = readCredentials(resolved, inspection.isDefined, FileInputStream(java.io.FileDescriptor.in))
        // Last, so a variable's refusal is reported before an endpoint that the proxy cannot resolve.
        val transport =
          try originTransport(variable => Option(System.getenv(variable)))
          catch
            case ex: IOException =>
              System.err.println(ex.getMessage)
              sys.exit(2)
        (
          Run(resolved, inspection, transport, () => logFailure, credentials),
          parseBind(Option(System.getenv(BindVariable))),
        )
      catch
        case ex: IllegalArgumentException =>
          System.err.println(ex.getMessage)
          sys.exit(2)

        case ex: (IOException | GeneralSecurityException) =>
          System.err.println(inspectionLoadFailure(ex))
          sys.exit(2)

    // Before the ready line: the launcher reads the log once the ready line is written, and relays this line.
    System.err.println(run.transport.summary)

    val server = ServerSocket()
    server.setReuseAddress(true)
    server.bind(bind)

    val lines = rulesetLines(run.resolved)
    lines.foreach(System.err.println)
    // The digest gives the audit log one stable, grep-able line that names the ruleset this run enforced. The line
    // compares across runs without diffing the lines above.
    System.err.println(s"ruleset digest: ${sha256Hex(lines.mkString("\n"))}")
    metadataLines(run.resolved).foreach(System.err.println)
    run.resolved.warnings.foreach(warning => System.err.println(s"warning: $warning"))
    System.err.println(run.inspectionSummary)
    if run.credentials.nonEmpty then
      System.err.println(s"brokered credentials: ${run.credentials.map(_.binding.spelled).mkString(" ")}")

    logFailure.foreach: ex =>
      System.err.println(s"${auditLogFailure(ex)}; not starting")
      sys.exit(2)

    // Last: the launcher (AgentSandboxLauncher.awaitProxyReady) and the host runner (RunOnHostProxy.awaitProxyPort)
    // act on the ready line as soon as it is written. So the ready line comes after every line whose failed write
    // exits above.
    System.err.println(readyLine(server.getLocalPort))

    acceptForever(server, run)

  /*
   * The leaf and its key are present exactly when the ruleset inspects a host.
   *
   * - Both absent means that the image runs on its own, with inspection off, and says so.
   * - Material for a ruleset that inspects nothing is an error, not a narrower ruleset. The launcher never issues a
   *   leaf for such a ruleset, so supplied material means that the two disagree about what this ruleset is
   *   (SECURITY.md, "Who holds the CA key").
   */
  def loadInspection(
    resolved: ResolvedEgress,
    read: String => Option[String] = variable => Option(System.getenv(variable)),
  ): Option[TlsInspection] =
    (read(CertificateVariable).filter(_.nonEmpty), read(PrivateKeyVariable).filter(_.nonEmpty)) match
      case (Some(certificate), Some(key)) =>
        if resolved.inspected.isEmpty then
          throw IllegalArgumentException(
            s"$CertificateVariable is set, but this ruleset inspects no host; " +
              "with nothing to inspect the material can only be a mistake",
          )
        Some(TlsInspection.load(Path.of(certificate), Path.of(key), resolved.inspected))
      case (None, None) => None
      case _ => throw IllegalArgumentException(s"$CertificateVariable and $PrivateKeyVariable must be set together")

  /**
   * The brokered credentials, read from `in` only with EGRESS_CREDS=stdin (CredentialGrammar.readBindings), and only
   * before the ready line. A binding whose host this proxy does not inspect is refused, and so is a binding without the
   * material to inspect its host. Either binding would show as a 401 inside the sandbox, with nothing in the log to
   * explain it.
   */
  def readCredentials(
    resolved: ResolvedEgress,
    inspecting: Boolean,
    in: => InputStream,
    read: String => Option[String] = variable => Option(System.getenv(variable)),
  ): Vector[BrokeredCredential] =
    read(CredentialGrammar.StdinVariable).filter(_.nonEmpty) match
      case None => Vector.empty
      case Some(CredentialGrammar.StdinValue) =>
        val credentials = CredentialGrammar.readBindings(in) match
          case Right(bindings) => bindings
          case Left(reason) => throw IllegalArgumentException(s"cannot read the brokered credentials: $reason")
        credentials.find(credential => !resolved.inspected.contains(credential.binding.host)).foreach: credential =>
          throw IllegalArgumentException(
            s"${credential.binding.spelled}: this proxy does not inspect ${credential.binding.host}, " +
              "so nothing would be substituted there",
          )
        if credentials.nonEmpty && !inspecting then
          throw IllegalArgumentException(
            s"brokered credentials need TLS inspection; set $CertificateVariable and $PrivateKeyVariable",
          )
        credentials
      case Some(other) =>
        throw IllegalArgumentException(
          s"${CredentialGrammar.StdinVariable} is '$other'; " +
            s"the only value it accepts is ${CredentialGrammar.StdinValue}",
        )

  /**
   * What loadInspection throws for material that cannot be read or parsed. A missing file and a denied one get
   * their reason spelled out, since the JDK's message for both is the path alone.
   * A denied file is the case whose path misleads: podman mounts a file that the container cannot read without
   * complaint, so the path exists on the host and in the container.
   */
  def inspectionLoadFailure(ex: IOException | GeneralSecurityException): String =
    val reason = ex match
      case denied: AccessDeniedException =>
        s"${denied.getFile}: permission denied; check the file's mode and owner against this " +
          "container's user, and on an SELinux-enforcing host the file's label"
      case missing: NoSuchFileException => s"${missing.getFile}: no such file"
      case _                            => ex.getMessage
    s"cannot load the TLS inspection material: $reason"

  case class Run(
    resolved: ResolvedEgress,
    inspection: Option[TlsInspection],
    transport: OriginTransport,
    // Set by serve(): the first write to the log that failed. The log is the file where one is set, else stderr.
    auditLogFailure: () => Option[IOException] = () => None,
    credentials: Vector[BrokeredCredential] = Vector.empty,
    audit: RequestAudit = RequestAudit(),
  ):
    /**
     * Refuses for the rest of the run once a line failed to be written to the log: a log that resumed would lack
     * the lines between, and nothing in the log would say so.
     *
     * - The proxy calls this before it authorizes a connection, and again after the connection's `allow` line and
     *   before its first relayed byte. So no connection is served whose line was not written.
     * - A connection already past that point writes at most an `error` line at its end, and continues
     *   (SECURITY.md, "Egress proxy").
     */
    def requireAuditLog(): Unit =
      auditLogFailure().foreach: ex =>
        throw Refusal(Refusals.auditLogFailure(ex), RefusalAdvice.auditLog, "proxy_internal_error")

    def inspectionSummary: String =
      inspection match
        case Some(_) =>
          s"tls inspection: active for the ${resolved.inspected.size} inspected hosts"
        case None =>
          "tls inspection: off; every allowed host is an opaque, writable tunnel"

  @tailrec
  def acceptForever(server: ServerSocket, run: Run): Unit =
    /*
     * A failed accept must not take the proxy down: every agent behind the proxy would lose network access until
     * someone noticed. A closed listening socket is the one unrecoverable case, and it ends the loop rather than
     * spinning on it.
     */
    val accepted =
      try Some(server.accept())
      catch
        case ex: IOException =>
          System.err.println(s"accept failed: ${ex.getMessage}")
          if !server.isClosed then Thread.sleep(AcceptFailurePauseMillis)
          None

    accepted.foreach(client => dispatch(client, run))

    if !server.isClosed then acceptForever(server, run)

  def dispatch(client: Socket, run: Run): Unit =
    if !connectionSlots.tryAcquire() then
      try respondQuietly(client, 503, "Service Unavailable", "connection_limit_reached")
      finally closeQuietly(client)
    else
      try
        executor.execute(() =>
          try handle(client, run)
          finally connectionSlots.release(),
        )
      catch
        case NonFatal(ex) =>
          // The permit was acquired above and this connection will never run.
          connectionSlots.release()
          closeQuietly(client)
          System.err.println(s"could not start connection handler: ${ex.getMessage}")

  def handle(client: Socket, run: Run): Unit =
    // The audit context, filled in as parsing learns it: a `-` in the line marks a field that the connection ended
    // before revealing. The host is the target as the sandbox requested it: what was asked for, not necessarily a
    // hostname that the ruleset allows. auditLine has the grammar.
    var host = "-"
    var addresses = Vector.empty[InetAddress]
    try
      // An IO failure while reading the request is the client's, not the origin's. The failure is rethrown as a
      // BadRequest, so the log does not record a 502 against an origin that the proxy never dialled.
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
      // Before the ruleset: a failed log is a reason to refuse every host, whatever this host's rules are.
      run.requireAuditLog()
      host = authorizeRequest(request, run.resolved)
      addresses = resolvePublic(host)
      val origin = run.transport.connect(addresses, request.port)

      try runEstablishedTunnel(client, origin, host, run)
      finally origin.close()

    catch
      case _: ClosedWithoutRequest =>
        System.err.println(auditLine("error", host, "-", "", "client closed before sending a request"))

      case ex: BadRequest =>
        // Parse failures keep `-` in the method field: the field never holds a token that the proxy did not allow, so
        // a refused method is named in the text, not promoted to the vocabulary.
        System.err.println(auditLine("deny", host, "-", "", ex.getMessage))
        // After a failed log write, every request is answered with that reason, this one included. The run-on-host
        // supervisor asks with a request that is no CONNECT, so a proxy that is still logging records no refused host
        // for the request (RunOnHostProxy.unwritableProxyLog).
        try
          run.requireAuditLog()
          respondQuietly(client, 400, "Bad Request", "http_request_error", Some(ex.getMessage), bodyless = true)
        catch
          case refusal: Refusal =>
            respondQuietly(
              client, 403, "Forbidden", refusal.proxyError, Some(refusal.getMessage), Some(refusal.advice),
            )

      case ex: Refusal =>
        System.err.println(auditLine("deny", host, "CONNECT", "", ex.getMessage))
        // A failed CONNECT may carry a body (RFC 9110 §9.3.6 forbids one on a 2xx only). Clients discard the body.
        // The image's ko-sandbox-egress-check reads the body, and is the way this refusal's reason reaches the
        // sandbox.
        respondQuietly(client, 403, "Forbidden", ex.proxyError, Some(ex.getMessage), Some(ex.advice))

      case ex: IOException =>
        val stage = ex match
          case failure: TransportFailure => s"tried ${failure.attempted.map(_.getHostAddress).mkString(" ")}:"
          case _ if addresses.isEmpty    => "resolution:"
          case _                         => s"resolved ${addresses.map(_.getHostAddress).mkString(" ")}:"
        System.err.println(auditLine("error", host, "CONNECT", "", s"$stage ${ex.getMessage}"))
        // The body carries the stage, as a refusal's body carries its reason. The ruleset allowed this host, so the
        // agent's next step is to report what failed, and only ko-sandbox-egress-check shows the body.
        val proxyError = if stage == "resolution:" then "dns_error" else "destination_unavailable"
        respondQuietly(client, 502, "Bad Gateway", proxyError, Some(s"$stage ${ex.getMessage}"))

      case NonFatal(ex) =>
        System.err.println(
          auditLine("error", host, "CONNECT", "", s"internal: ${ex.getClass.getSimpleName}: ${ex.getMessage}"),
        )
        // The class alone: the message of an exception that nobody planned for may hold what the sandbox should not
        // read, and the log has the message.
        respondQuietly(
          client, 500, "Internal Server Error", "proxy_internal_error",
          Some(s"internal: ${ex.getClass.getSimpleName}"), bodyless = true,
        )

    finally
      closeQuietly(client)

  def runEstablishedTunnel(
    client: Socket,
    origin: OriginSocket,
    connectHost: String,
    run: Run,
  ): Unit =
    writeAscii(client.getOutputStream, "HTTP/1.1 200 Connection Established\r\n\r\n")

    try
      val hello =
        TlsClientHello.read(
          client.getInputStream,
          MaxClientHelloBytes,
        )

      validateTlsIdentity(connectHost, hello)

      // A tunnel host is opaque. Every other allowed host is inspected with its lines' scopes (Ruleset.scopesOf),
      // unless this run has no material at all.
      run.inspection.filter(_ => !run.resolved.tunnelHosts.contains(connectHost)) match
        case Some(inspection) =>
          runInspectedConnection(
            client, origin, connectHost, hello, inspection,
            run.resolved.scopesOf(connectHost),
            run.resolved.allows,
            run.requireAuditLog,
            run.credentials,
            run.audit,
          )

        case None =>
          System.err.println(
            auditLine("allow", connectHost, "CONNECT", "", s"-> ${origin.address.getHostAddress}"),
          )
          run.requireAuditLog()

          /*
           * TlsClientHello.read consumed the records needed to inspect the ClientHello. Those exact bytes go out
           * unchanged before the switch to an opaque bidirectional tunnel.
           */
          origin.socket.getOutputStream.write(hello.wireBytes)
          origin.socket.getOutputStream.flush()

          client.setSoTimeout(0)
          origin.socket.setSoTimeout(0)

          tunnel(client, origin.socket)

    catch
      /*
       * HTTP 200 has already been sent, so an HTTP error response would be protocol garbage at this point. The proxy
       * fails closed by dropping the tunnel.
       */
      case ex: BadTls =>
        System.err.println(auditLine("deny", connectHost, "CONNECT", "", ex.getMessage))

      case ex: BadRequest =>
        System.err.println(auditLine("deny", connectHost, "CONNECT", "", ex.getMessage))

      case ex: Refusal =>
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
   * One request and its response, then the connection ends, and both peers are told.
   *
   * - The request goes to the origin with `Connection: close`, so end-of-stream frames the response.
   * - The response reaches the client with this proxy's own `Connection: close`, whatever the origin's hop said
   *   (toClientBytes).
   * - Keeping the connection alive would mean agreeing with the origin about where each message ends: the exact
   *   disagreement that request smuggling exploits.
   * - After the response, the proxy only drains the client (drainClient) and never answers the client again.
   * - The exception is a granted WebSocket handshake: its checked 101 hands the connection to relayStream, which
   *   parses nothing more.
   *
   * The cost is a handshake per request; a `git fetch` costs two.
   */
  def runInspectedConnection(
    client: Socket,
    origin: OriginSocket,
    host: String,
    hello: TlsClientHello,
    inspection: TlsInspection,
    hostScopes: Map[String, Set[String]],
    allowed: String => Boolean,
    requireAuditLog: () => Unit,
    credentials: Vector[BrokeredCredential] = Vector.empty,
    audit: RequestAudit = RequestAudit(),
  ): Unit =
    val clientTls = inspection.accept(client, hello.wireBytes)

    // The in-tunnel audit context, like handle()'s: `-` until the request head parses. The allow line prints only
    // after the origin leg connects, so a failing request's method and target must go on the deny or error line, or
    // they would never be recorded.
    var method = "-"
    var target = ""

    try
      try
        // The credentials are substituted before authorization and framing, so the decision and the origin see the
        // same head: a bound `service` parameter is read as what it becomes (GitHelper). Keep the substitution first:
        // a check that read the head before the substitution would judge a request that the origin never receives.
        // A read failure is rethrown as handle() rethrows an unreadable CONNECT: the failure is the client's, not an
        // origin's.
        val raw =
          try readHttpHeader(clientTls.getInputStream, MaxHttpHeaderBytes)
          catch case ex: IOException => throw BadRequest(s"unreadable request head: ${ex.getMessage}")
        val asSent = HttpRequestHead.parse(raw)
        val substituted = asSent.withCredentials(host, credentials)
        val head = substituted.head
        method = head.method
        target = substituted.printedTarget

        authorizeInspectedRequest(host, head, hostScopes, allowed)

        val originTls = inspection.connect(origin.socket, host)

        try
          val injected = Option.when(substituted.injected.nonEmpty)(s"inject=${substituted.injected.mkString(",")} ")
          // After the origin leg connects, so a request that never reaches the origin takes no id.
          val fields = audit.allowFields(asSent, head.bodyFraming)
          System.err.println(
            auditLine(
              "allow", host, method, target,
              s"${injected.getOrElse("")}${fields.text}-> ${origin.address.getHostAddress}",
            ),
          )
          requireAuditLog()

          val printedMethod = method
          val printedTarget = target
          val switched = relayInspected(
            clientTls, originTls, origin.transport, head,
            relayed =>
              fields.id.foreach(id =>
                System.err.println(RequestAudit.chunkedEndLine(host, printedMethod, printedTarget, id, relayed)),
              ),
          )
          if switched then
            val streamed = relayStream(clientTls, client, originTls, origin.transport)
            fields.id.foreach(id =>
              System.err.println(RequestAudit.webSocketEndLine(host, printedMethod, printedTarget, id, streamed)),
            )
        finally closeTlsOutput(originTls, origin.transport)

      catch
        case _: ClosedWithoutRequest =>
          // Logged even so: a connection that completed the TLS handshake must not vanish without a line. No
          // response goes out, since the peer is gone.
          System.err.println(
            auditLine("error", host, method, target, "client closed before sending a request"),
          )

        case ex: TruncatedResponse =>
          System.err.println(auditLine("error", host, method, target, s"relay: ${ex.getMessage}"))
          abortiveClose(client)

        case ex: BadRequest =>
          System.err.println(auditLine("deny", host, method, target, ex.getMessage))
          respondInsideTls(clientTls, method, 400, "Bad Request", "http_request_error", ex.getMessage)

        case ex: Refusal =>
          System.err.println(auditLine("deny", host, method, target, ex.getMessage))
          val (status, reason) = if ex.upgradeRequired then (426, "Upgrade Required") else (403, "Forbidden")
          respondInsideTls(clientTls, method, status, reason, ex.proxyError, ex.getMessage, Some(ex.advice))

        case ex: IOException =>
          System.err.println(auditLine("error", host, method, target, s"origin: ${ex.getMessage}"))
          respondInsideTls(clientTls, method, 502, "Bad Gateway", originProxyError(ex), ex.getMessage)

    finally closeTlsOutput(clientTls, client)

  /*
   * Parses the final response's framing before forwarding its head, while an invalid head can still be reported as
   * a 502. Body relay failures require TruncatedResponse's abortive close.
   *
   * `originTransport` is the TCP connection under every TLS layer of the origin leg (OriginSocket.transport).
   * Closing the transport is what ends I/O blocked in a layer. The layer's own close cannot end that I/O
   * (closeTlsOutput), and over a socket that the layer does not own (TlsInspection), the layer's close does not
   * close the transport either.
   */
  // Socket rather than SSLSocket: nothing here is TLS-specific, since the sockets arrive already inside the tunnel.
  // Plain sockets also let the tests run the relay on loopback pairs.
  // True when the origin switched a granted WebSocket handshake to its stream, which the caller relays
  // (relayStream). An `Upgrade` in `head` is one that authorizeInspectedRequest granted.
  def relayInspected(
    clientTls: Socket,
    originTls: Socket,
    originTransport: Socket,
    head: HttpRequestHead,
    // Called once for a request with a body, from the upload's thread when the body ends.
    bodyRelayed: BodyRelayed => Unit = _ => (),
  ): Boolean =
    val toOrigin = originTls.getOutputStream
    val fromOrigin = originTls.getInputStream
    val toClient = clientTls.getOutputStream

    clientTls.setSoTimeout(InspectedIdleTimeoutMillis)
    originTls.setSoTimeout(InspectedIdleTimeoutMillis)

    val framing = head.bodyFraming
    val upgrade = head.values("Upgrade").headOption

    try
      toOrigin.write(upgrade.fold(head.toOriginBytes)(head.toOriginUpgradeBytes))
      toOrigin.flush()
    catch
      case ex: IOException =>
        if framing != BodyFraming.Empty then bodyRelayed(BodyRelayed(0, complete = false))
        throw ex

    val upload =
      Option.when(framing != BodyFraming.Empty):
        Upload(clientTls.getInputStream, toOrigin, originTransport, framing, bodyRelayed)

    /** The upload's failure, in the origin's place, when the upload failed first. The client's malformed chunking
      * is the client's 400, not the origin's 502, and the client's broken connection is named. */
    def failed(ex: IOException): Exception =
      upload.flatMap(_.failureBeforeAnswer) match
        case Some(bad: BadRequest) => bad
        case Some(broken)          => IOException(s"request body: ${broken.getMessage}")
        case None                  => ex

    def responseHead(): HttpResponseHead =
      val bytes =
        try readHttpHeader(fromOrigin, MaxHttpHeaderBytes)
        catch
          case _: ClosedWithoutRequest => throw failed(IOException("origin closed before the response head"))
          case ex: BadRequest          => throw failed(IOException(s"origin response head: ${ex.getMessage}"))
          case ex: IOException         => throw failed(ex)
      HttpResponseHead.parse(bytes)

    /** Every interim head reaches the client, the origin's 100 among them, and none is this proxy's own.
      *
      * - The Expect went to the origin whole (toOriginBytes drops only this hop's headers). So a client that holds
      *   its body back for a 100 that the origin never sends is where it would be against that origin directly: the
      *   client sends on its own timer, which is 1 s for curl.
      * - A 101 to a request without an Upgrade is refused before it is forwarded: what follows a 101 is no longer
      *   HTTP.
      * - A 101 to a granted handshake ends the HTTP exchange once its `Sec-WebSocket-Accept` matches the key. An
      *   origin that answers 101 without computing the value would let the client send requests that this proxy
      *   neither authorizes nor logs.
      * - The 101 must also name the WebSocket in its own `Upgrade`, since toClientUpgradeBytes writes the client's
      *   pair: the client cannot check what the origin switched to. */
    @tailrec
    def finalResponseHead(interimRead: Int = 0): HttpResponseHead =
      val response = responseHead()
      if response.status == 101 then
        if upgrade.isEmpty then
          throw IOException("origin answered 101 Switching Protocols to a request sent without Upgrade")
        val key = head.values("Sec-WebSocket-Key").head
        if response.values("Sec-WebSocket-Accept") != Vector(webSocketAccept(key)) then
          throw IOException("origin answered 101 without the Sec-WebSocket-Accept of the handshake's key")
        if !response.values("Upgrade").map(_.toLowerCase(java.util.Locale.ROOT)).sameElements(Vector("websocket")) then
          throw IOException("origin answered 101 without Upgrade: websocket")
        response
      else if !response.interim then
        upload.foreach(_.originAnswered())
        response
      else if interimRead == MaxInterimResponses then
        throw IOException(s"origin sent more than $MaxInterimResponses interim responses")
      else
        toClient.write(response.toClientBytes)
        toClient.flush()
        finalResponseHead(interimRead + 1)

    try
      val response = finalResponseHead()
      if response.status == 101 then
        toClient.write(response.toClientUpgradeBytes(upgrade.get))
        toClient.flush()
        true
      else
        val responseFraming = response.bodyFraming(head.method)

        toClient.write(response.toClientBytes)
        try
          forwardResponseBody(fromOrigin, toClient, responseFraming)
          toClient.flush()
        catch case ex: IOException => throw TruncatedResponse(ex.getMessage)
        // The client's input belongs to the upload until the upload ends. An upload still running means that the
        // client uploads past the final head or holds a body back after it, and that client gets the close as it is.
        if upload.forall(_.ended(DrainTimeoutMillis)) then drainClient(clientTls)
        false
    finally
      // Whatever ends this, an upload still blocked on writing to an origin that stopped reading would hold the TLS
      // layer's close for its whole deadline (closeTlsOutput). So the transport is closed first.
      if !upload.forall(_.ended(0)) then closeQuietly(originTransport)

  /**
   * The request body, sent to the origin as the client sends it, on its own thread, so that the origin's answer is
   * read meanwhile.
   *
   * - An origin that refuses before or during the upload (RFC 9112 §9.5) reaches the client at once, and the
   *   client then stops.
   * - After the final head, nothing more goes to the origin. A write to an origin that answered and closed resets
   *   the connection, and a reset destroys what of the answer is still unread. The client is still read on, so the
   *   client's close does not meet unread bytes.
   * - A write that the origin refuses is left for the origin's answer, or its absence, to report.
   * - A failure before the answer closes the origin's transport. So the head read reports the failure
   *   (failureBeforeAnswer) instead of waiting out the origin's own timeout for a body that stopped coming.
   * - The thread's last act reports the payload bytes that reached the origin's TLS layer, and whether every byte
   *   of the body did (`bodyRelayed`).
   */
  private final class Upload(
    fromClient: InputStream,
    toOrigin: OutputStream,
    originTransport: Socket,
    framing: BodyFraming,
    bodyRelayed: BodyRelayed => Unit,
  ):
    @volatile private var answered = false
    private var failure: Option[Exception] = None
    // Only the upload's thread touches these three.
    private var refused = false
    private var withheld = false
    private var payloadBytes = 0L

    /** True when the bytes went to the origin. A refused or skipped write marks the body withheld. */
    private def sent(buffer: Array[Byte], offset: Int, length: Int): Boolean =
      val going = !answered && !refused
      if going then
        try toOrigin.write(buffer, offset, length)
        catch case _: IOException => refused = true
      val wrote = going && !refused
      if !wrote then withheld = true
      wrote

    private val toOriginUntilAnswered = new OutputStream:
      override def write(byte: Int): Unit = write(Array(byte.toByte), 0, 1)

      override def write(buffer: Array[Byte], offset: Int, length: Int): Unit = sent(buffer, offset, length)

      override def flush(): Unit =
        if !answered && !refused then
          try toOrigin.flush()
          catch
            case _: IOException =>
              refused = true
              withheld = true

    /** The body's payload, as distinct from the chunk framing that toOriginUntilAnswered carries. */
    private val payloadUntilAnswered = new OutputStream:
      override def write(byte: Int): Unit = write(Array(byte.toByte), 0, 1)

      override def write(buffer: Array[Byte], offset: Int, length: Int): Unit =
        if sent(buffer, offset, length) then payloadBytes += length

      override def flush(): Unit = toOriginUntilAnswered.flush()

    private val thread = Thread.startVirtualThread: () =>
      var bodyEnded = false
      try
        forwardRequestBody(fromClient, toOriginUntilAnswered, framing, payloadUntilAnswered)
        toOriginUntilAnswered.flush()
        bodyEnded = true
      catch
        case ex: (IOException | BadRequest) =>
          synchronized:
            failure = Some(ex)
            if !answered then closeQuietly(originTransport)
      finally bodyRelayed(BodyRelayed(payloadBytes, complete = bodyEnded && !withheld))

    def originAnswered(): Unit = synchronized { answered = true }

    def failureBeforeAnswer: Option[Exception] = synchronized(if answered then None else failure)

    def ended(withinMillis: Int): Boolean = thread.join(Duration.ofMillis(withinMillis))

  val DrainTimeoutMillis = 2_000

  /**
   * Consumes whatever the client still sends, until its EOF, bounded. Closing with unread bytes in the receive
   * buffer turns the close into an RST, and an RST destroys the just-written response's unread tail in the client's
   * stack.
   *
   * - A request pipelined past `Connection: close` arrives here and is discarded unanswered.
   * - A client still flooding at the cap gets the RST it asked for.
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

  /**
   * A WebSocket's bytes both ways after a checked 101, parsed no further.
   *
   * - When either direction ends, both transports close. A WebSocket peer may never end the other direction, so a
   *   half-close as tunnel() keeps would leave the connection open.
   * - No idle limit applies: InspectedIdleTimeoutMillis would end a dictation during which the origin sends nothing.
   *   A tunnel has no idle limit either.
   */
  def relayStream(
    clientTls: Socket,
    clientTransport: Socket,
    originTls: Socket,
    originTransport: Socket,
  ): StreamRelayed =
    clientTls.setSoTimeout(0)
    originTls.setSoTimeout(0)

    def pump(in: InputStream, out: OutputStream): Long =
      val buffer = new Array[Byte](RelayBufferBytes)
      var written = 0L
      try
        var read = in.read(buffer)
        while read >= 0 do
          out.write(buffer, 0, read)
          out.flush()
          written += read
          read = in.read(buffer)
      catch case _: IOException => ()
      finally
        closeQuietly(clientTransport)
        closeQuietly(originTransport)
      written

    // Taken before either pump runs: a socket that the other pump closed refuses to hand out a stream.
    val (fromClient, toOrigin) = (clientTls.getInputStream, originTls.getOutputStream)
    val (fromOrigin, toClient) = (originTls.getInputStream, clientTls.getOutputStream)
    val sent = java.util.concurrent.atomic.AtomicLong()
    val sending = Thread.startVirtualThread(() => sent.set(pump(fromClient, toOrigin)))
    val received = pump(fromOrigin, toClient)
    sending.join()
    StreamRelayed(sent.get, received)

  def tunnel(client: Socket, origin: Socket): Unit =
    val done = CountDownLatch(2)

    def pump(
      in: InputStream,
      out: OutputStream,
      halfClose: () => Unit,
    ): Unit =
      try
        in.transferTo(out)
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
        origin.getOutputStream,
        () => origin.shutdownOutput(),
      ),
    )

    executor.execute(() =>
      pump(
        origin.getInputStream,
        client.getOutputStream,
        () => client.shutdownOutput(),
      ),
    )

    try done.await()
    catch
      case _: InterruptedException =>
        Thread.currentThread().interrupt()
