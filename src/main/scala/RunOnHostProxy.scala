// A host command's egress proxy: the launcher re-invoked under the proxy profile with the program's
// rules, its port read from its ready line, its audit log linked into the project's log directory,
// and the refusals read back from that log after a command.

package agentsandbox.launcher

import java.io.IOException
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path, StandardOpenOption}

import agentsandbox.egress.{BrokeredCredential, CredentialGrammar, LogHelper, Refusals}

import RunOnHostPrereqs.*
import RunOnHostSandbox.*
import FileHelper.realPath

object RunOnHostProxy:

  /** The bound port, from the ready line the proxy prints after `bind`; its log file is its
    * stderr, so the line is written where this polls. */
  def awaitProxyPort(log: Path, deadlineMillis: Long): Either[String, Int] =
    val Ready = agentsandbox.egress.AgentEgressProxy.ReadyPort
    val deadline = System.nanoTime + deadlineMillis * 1_000_000
    // Decoded leniently: the log carries what the proxy's clients asked for.
    def text = if Files.exists(log) then String(Files.readAllBytes(log), UTF_8) else ""
    var found: Option[Int] = None
    while found.isEmpty && System.nanoTime < deadline do
      text.linesIterator.collectFirst { case Ready(port) => port.toInt } match
        case Some(port) => found = Some(port)
        case None       => Thread.sleep(50)
    found.toRight:
      val said =
        if Files.exists(log) then text.linesIterator.take(5).mkString("\n")
        else "(no log was written)"
      s"the proxy did not report ready within ${deadlineMillis / 1000}s:\n$said"

  /** The proxy registered at `record`, logging to `proxyLog`: its bound port. */
  private[launcher] def createProxy(
    systemPaths: SeatbeltProfile.SystemPaths,
    credentials: Seq[BrokeredCredential],
    channelLog: Option[Path],
  )(
    program: Program, fileHosts: Vector[String], record: Path, proxyLog: Path,
  ): Either[String, Int] =
    startProxy(record, program, fileHosts, proxyLog, systemPaths, credentialsFor(program, fileHosts, credentials))
      .map(_ => channelLog.foreach(linkAuditLog(_, proxyLog)))
      .flatMap(_ => awaitProxyPort(proxyLog, deadlineMillis = 30_000))

  /**
   * The proxy profile's inputs for this executable (SeatbeltProfile.ProxyInputs): the native
   * image alone, or the JDK and each class-path entry of the jar form — what
   * RunOnHostSandbox.selfInvocation runs, the executable itself checked first
   * (RunOnHostSandbox.selfPresent, both forms). Any other entry that does not exist is skipped, as the
   * JVM skips it; a relative or empty one is resolved as RunOnHostSandbox.selfClassPath spells it.
   * The JDK and class path are parameters for the acceptance test's emitter, which renders the
   * profile from inside sbt's JVM for the java it runs the rows with.
   */
  def proxyInputs(
    systemPaths: SeatbeltProfile.SystemPaths,
    javaHome: String = System.getProperty("java.home"),
    classPath: String = System.getProperty("java.class.path"),
    self: Option[Path] = launchFile,
  ): Either[String, SeatbeltProfile.ProxyInputs] =
    selfPresent(self).flatMap: executable =>
      if isNativeImage then
        executable.toRight("the native image cannot name itself")
          .map(binary => SeatbeltProfile.ProxyInputs(Seq(binary), Seq.empty, systemPaths))
      else
        realPath(Path.of(javaHome)).toRight(s"the JDK $javaHome is not readable").map: jdk =>
          SeatbeltProfile.ProxyInputs(Seq(jdk), selfClassPath(classPath).map(Path.of(_)).flatMap(realPath), systemPaths)

  /**
   * Where a host proxy's audit log is also found: beside the launch's channel log, in the project's
   * log directory, named as `--egress-log` lists a proxy's log and the launch's pruning keeps it while
   * its run is live (EgressRules.logsToPrune). `run-on-host-<stamp>-<run>.log` and a session's
   * `proxy-sbt-<hash>.log` give `proxy-<stamp>-<session>-proxy-sbt-<hash>-<run>.log`.
   */
  def projectAuditLog(channelLog: Path, proxyLog: Path): Option[Path] =
    channelLog.getFileName.toString match
      case s"run-on-host-$stampAndRun.log" if stampAndRun.contains('-') =>
        val stamp = stampAndRun.take(stampAndRun.lastIndexOf('-'))
        val run = stampAndRun.drop(stampAndRun.lastIndexOf('-') + 1)
        val stem = proxyLog.getFileName.toString.stripSuffix(".log")
        Some(channelLog.resolveSibling(s"proxy-$stamp-${proxyLog.getParent.getFileName}-$stem-$run.log"))
      case _ => None

  /** A second name for the proxy's log, a hard link, so its lines are there while it writes them and stay
    * when its session's directory goes. A link that cannot be made is reported in the channel log, where the
    * session's end appends the log's tail (RunOnHostSandbox.appendSessionLogs). */
  private def linkAuditLog(channelLog: Path, proxyLog: Path): Unit =
    projectAuditLog(channelLog, proxyLog).foreach: link =>
      // Owner-only, as the container proxy's log is: the targets it records are what a GET carries out.
      try
        Files.setPosixFilePermissions(proxyLog, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"))
        Files.createLink(link, proxyLog)
      catch
        case ex: (IOException | UnsupportedOperationException) =>
          try
            Files.writeString(
              channelLog,
              s"${java.time.Instant.now()} the proxy's audit log $proxyLog is not linked as $link: ${ex.getMessage}\n",
              UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND,
            )
          catch case _: IOException => ()

  /** The proxy's profile, beside its log. */
  private[launcher] def proxyProfileFile(proxyLog: Path): Path =
    proxyLog.resolveSibling(proxyLog.getFileName.toString.stripSuffix(".log") + ".sb")

  /** The proxy under its profile (SeatbeltProfile.renderProxy), beside its log. */
  private def startProxy(
    record: Path, program: Program, fileHosts: Vector[String], proxyLog: Path,
    systemPaths: SeatbeltProfile.SystemPaths, credentials: Vector[BrokeredCredential],
  ): Either[String, Process] =
    for
      names <- RunOnHostInspection.leafNames(egressRuleText(program, fileHosts))
      _ <- RunOnHostInspection.create(proxyLog, names)
      inputs <- proxyInputs(systemPaths)
      profile <- SeatbeltProfile.renderProxy(
        inputs.copy(reads = inputs.reads :+ RunOnHostInspection.leafDirectory(proxyLog)),
      )
      started <- startProxyUnder(profile, record, program, fileHosts, proxyLog, credentials)
    yield started

  private def startProxyUnder(
    profile: String, record: Path, program: Program, fileHosts: Vector[String], proxyLog: Path,
    credentials: Vector[BrokeredCredential],
  ): Either[String, Process] =
    try
      val profileFile = proxyProfileFile(proxyLog)
      Files.writeString(profileFile, profile, UTF_8)
      // The property the command's environment sets (RunOnHostSandbox.commandEnvironment), on the
      // command line since the proxy's environment is closed: a dual-stack JVM binds
      // ::ffff:127.0.0.1, which the profile's "localhost" class does not cover (measured: the
      // acceptance test's proxy rows).
      val invocation = selfInvocation("--serve-proxy-on-host")
      val command = RunOnHostSession.registeredSpawn(
        record,
        sandboxExec(profileFile, invocation.head +: "-Djava.net.preferIPv4Stack=true" +: invocation.tail),
      )
      val builder = ProcessBuilder(command*)
      // The JVM asks for its working directory at start (SystemProps), and the profile grants
      // no directory of the starter's; the root it does grant.
      builder.directory(java.io.File("/"))
      // Closed like the command's: the proxy needs its own settings and, to leave through an
      // upstream proxy as the container's copy does, the one selected variable. Nothing else of
      // the launcher's environment has a reader here.
      builder.environment.clear()
      agentsandbox.egress.TransportHelper.upstreamProxyVariable(name => Option(System.getenv(name)))
        .foreach(builder.environment.put(_, _))
      import agentsandbox.egress.RulesetHelper
      builder.environment.put(RulesetHelper.ProfileVariable, RulesetHelper.DefaultProfile)
      builder.environment.put(RulesetHelper.RuleVariable, egressRuleText(program, fileHosts))
      builder.environment.put(agentsandbox.egress.AgentEgressProxy.BindVariable, "127.0.0.1:0")
      // The leaf is why `read` in the rules is enforced: a proxy given none tunnels its hosts
      // without inspecting them.
      builder.environment.put(
        agentsandbox.egress.AgentEgressProxy.CertificateVariable,
        RunOnHostInspection.leafCertificate(proxyLog).toString,
      )
      builder.environment.put(
        agentsandbox.egress.AgentEgressProxy.PrivateKeyVariable, RunOnHostInspection.leafKey(proxyLog).toString,
      )
      // The credentials by pipe, never an environment or an argument (SECURITY.md, "Who holds a brokered value").
      if credentials.nonEmpty then
        builder.environment.put(CredentialGrammar.StdinVariable, CredentialGrammar.StdinValue)
      builder.redirectOutput(ProcessBuilder.Redirect.DISCARD)
      // Its stderr is its log, opened here and inherited: the profile grants no write
      // (RunOnHostSbtServer.serverLog), and what sandbox-exec or the JVM says before the proxy prints anything
      // lands where the ready line is awaited.
      builder.redirectError(ProcessBuilder.Redirect.appendTo(proxyLog.toFile))
      val process = builder.start()
      // On its own thread, so the wait for its port bounds it: up to 256 bindings exceed a pipe's
      // buffer, and a proxy that stops before reading them would hold a blocking write. A proxy gone
      // already is reported by that wait.
      Thread.startVirtualThread: () =>
        try
          if credentials.nonEmpty then
            process.getOutputStream.write(CredentialGrammar.bindingBytes(credentials))
          process.getOutputStream.close()
        catch case _: IOException => ()
      Right(process)
    catch case ex: IOException => Left(s"starting the proxy: ${ex.getMessage}")

  /** The hosts the proxy refused, from its audit log's `deny <host> CONNECT` lines at byte
    * offset `from` and after. */
  def deniedHosts(proxyLog: Path, from: Long = 0): Vector[String] =
    proxyLogLines(proxyLog, from).flatMap(LogHelper.auditFields)
      .collect { case LogHelper.AuditFields("deny", host, "CONNECT", _) => host }.distinct

  /** A request the proxy refused inside a tunnel, and the audit line's reason. */
  case class RefusedRequest(method: String, host: String, target: String, reason: String):
    /** An origin-form target is a path; any other form is refused for being one, and shown as sent. */
    def spelled: String =
      if target.startsWith("/") then s"$method https://$host$target" else s"$method $target ($host)"

  /** The requests the proxy refused inside a tunnel, once each (SECURITY.md, "The audit line
    * grammar"): a line with a method and a target, where a refused CONNECT has an empty target. */
  def refusedRequests(proxyLog: Path, from: Long = 0): Vector[RefusedRequest] =
    proxyLogLines(proxyLog, from).flatMap(LogHelper.auditFields)
      .collect:
        case LogHelper.AuditFields("deny", host, method, rest)
            if method != "CONNECT" && method.nonEmpty && method.forall(ch => ch >= 'A' && ch <= 'Z') =>
          rest.split(" ", 2) match
            case Array(target, reason) => Some(RefusedRequest(method, host, target, reason.trim))
            case _                     => None
      .flatten.distinct

  private def proxyLogLines(proxyLog: Path, from: Long): Vector[String] =
    if !Files.exists(proxyLog) then Vector.empty
    else
      val bytes = Files.readAllBytes(proxyLog)
      String(bytes, math.min(from, bytes.length).toInt, bytes.length - math.min(from, bytes.length).toInt, UTF_8)
        .linesIterator.toVector

  /**
   * The reason the proxy on `port` serves nothing, when a write to its log failed: the `details`
   * of its Proxy-Status field (Refusals.proxyStatus). Asked of the proxy, since the log that
   * would say so is what failed, and the programs need not print it (run-on-host.md has what
   * sbt and mill print). `OPTIONS *` is HTTP's request about the server itself, and no
   * CONNECT: a proxy still logging answers 400 and logs `deny - -`, which deniedHosts does not
   * read as a refused host. `Max-Forwards: 0` is for a recipient that is not this proxy, should
   * the proxy have died and another program taken its port: an HTTP proxy there must answer
   * itself, not forward (RFC 9110, 7.6.2). This proxy forwards no OPTIONS and does not read it.
   */
  def unwritableProxyLog(port: Int): Option[String] =
    try
      scala.util.Using.resource(java.net.Socket()): socket =>
        socket.connect(java.net.InetSocketAddress(java.net.InetAddress.getLoopbackAddress, port), 2_000)
        socket.setSoTimeout(2_000)
        socket.getOutputStream.write("OPTIONS * HTTP/1.1\r\nHost: localhost\r\nMax-Forwards: 0\r\n\r\n".getBytes(UTF_8))
        socket.getOutputStream.flush()
        String(socket.getInputStream.readNBytes(4096), UTF_8).linesIterator.takeWhile(_.nonEmpty)
          .flatMap(Refusals.proxyStatusDetails).nextOption()
          .filter(_.startsWith(Refusals.AuditLogUnwritable))
    catch case _: IOException => None

  private[launcher] def reportUnwritableProxyLog(runtime: Runtime, log: String => Unit): Unit =
    unwritableProxyLog(runtime.proxyPort).foreach: reason =>
      log(
        s"The host command sandbox's proxy serves no new connection: $reason.\n" +
          s"Tell the user: make ${runtime.proxyLog} writable again, then relaunch.",
      )

  /** The denied-host report, once per refused host, and the refused requests, after the command — never an
    * automatic addition. A program need not print a 403's body, so each request carries what that body
    * said: the reason, and for a refusal the command answers by changing the request, that step
    * (RefusalAdvice.requestStep). The user's step follows only a refusal of a grant, which the
    * rule file cannot give. */
  private[launcher] def reportDenied(proxyLog: Path, from: Long, program: Program, log: String => Unit): Unit =
    val hosts = deniedHosts(proxyLog, from)
    if hosts.nonEmpty then
      log((("Command requested network access to:" +: hosts.map(host => s"  $host")) :+
        ("Not permitted by the host command sandbox. If the command should reach it, add an" +
          s" `$ProgramRuleForm` line to .ko-agent-sandbox/run-on-host/${program.name}/egress/rule."))
        .mkString("\n"))
    val requests = refusedRequests(proxyLog, from)
    if requests.nonEmpty then
      import agentsandbox.egress.RefusalAdvice
      val listed = requests.map: request =>
        val step = RefusalAdvice.requestStep(request.reason).fold("")(text => s". $text")
        s"  ${request.spelled}: ${request.reason}$step"
      val ungranted = Option.when(requests.exists(request => RefusalAdvice.grantRefused(request.reason))):
        "Its rules grant `read`, a GET or HEAD without a body, and its rule file takes no other grant. If the" +
          " command should send the requests no grant covers, ask the user to run it themselves, outside the sandbox."
      log((("Command sent requests the host command sandbox refuses:" +: listed) ++ ungranted).mkString("\n"))
