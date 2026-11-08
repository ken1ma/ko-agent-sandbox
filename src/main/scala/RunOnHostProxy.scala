// A host command's egress proxy:
//
// - The proxy is the launcher, re-invoked under the proxy profile with the program's rules.
// - The runner reads the proxy's port from the proxy's ready line.
// - The proxy's audit log is kept in the run's log directory.
// - After a command, the runner reads the refusals back from that log.

package agentsandbox.launcher

import java.io.IOException
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{FileAlreadyExistsException, Files, Path}
import java.nio.file.attribute.PosixFilePermissions

import agentsandbox.egress.{BrokeredCredential, CredentialGrammar, LogHelper, Refusals}

import RunOnHostPrereqs.*
import RunOnHostSandbox.*
import FileHelper.realPath

object RunOnHostProxy:

  /** The bound port, read from the ready line that the proxy prints after `bind`.
    *
    *   - The proxy's log file is its stderr, so the proxy writes the line where this method polls.
    *   - `ended` says how the proxy ended, once it has. A proxy that refuses at start is then reported at once, with
    *     its log, instead of after the deadline. A proxy gone after its ready line gives no port. */
  def awaitProxyPort(log: Path, deadlineMillis: Long, ended: () => Option[String] = () => None): Either[String, Int] =
    val deadline = System.nanoTime + deadlineMillis * 1_000_000
    // Decoded leniently, because the log carries what the proxy's clients asked for.
    def text = if Files.exists(log) then String(Files.readAllBytes(log), UTF_8) else ""
    def said =
      if Files.exists(log) then text.linesIterator.take(5).mkString("\n")
      else "(no log was written)"
    var outcome: Option[Either[String, Int]] = None
    while outcome.isEmpty && System.nanoTime < deadline do
      val port = text.linesIterator.flatMap(agentsandbox.egress.AgentEgressProxy.readyPort).nextOption()
      // Asked after reading the log, so a proxy that ends right after its ready line reads as ended, not ready.
      ended() match
        case Some(how) =>
          val when = if port.isDefined then "after" else "before"
          outcome = Some(Left(s"the proxy ended ($how) $when reporting ready:\n$said"))
        case None if port.isDefined => outcome = Some(Right(port.get))
        case None                   => Thread.sleep(50)
    outcome.getOrElse(Left(s"the proxy did not report ready within ${deadlineMillis / 1000}s:\n$said"))

  /** Starts the proxy registered at `record` and logging to `proxyLog`, and returns its bound port. */
  private[launcher] def createProxy(
    systemPaths: SeatbeltProfile.SystemPaths,
    credentials: Seq[BrokeredCredential],
    channelLog: Option[Path],
  )(
    program: Program, fileHosts: Vector[String], record: Path, proxyLog: Path,
  ): Either[String, Int] =
    startProxy(
      record, program, fileHosts, proxyLog, systemPaths, credentialsFor(program, fileHosts, credentials), channelLog,
    ).flatMap: leader =>
      // The leader stays after its command (RunOnHostSession.registeredSpawn), so the exit record, not the handle,
      // says whether the proxy ended.
      def ended(): Option[String] =
        RunOnHostSession.exitSoFar(RunOnHostSession.exitRecord(record), leader)
          .map(_.fold(identity, status => s"exit $status"))
      awaitProxyPort(proxyLog, deadlineMillis = 30_000, ended)

  /**
   * The proxy profile's inputs for this executable (SeatbeltProfile.ProxyInputs): what
   * RunOnHostSandbox.selfInvocation runs.
   *
   *   - The inputs are the native image alone, or the JDK and each class-path entry of the jar form.
   *   - The executable itself is checked first, in both forms (RunOnHostSandbox.selfPresent).
   *   - Any other entry that does not exist is skipped, as the JVM skips it.
   *   - A relative or empty entry is resolved as RunOnHostSandbox.selfClassPath spells it.
   *   - The JDK and class path are parameters for the acceptance test's emitter. The emitter renders the profile
   *     from inside sbt's JVM, for the java that runs the test's rows.
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
   * The name of a host proxy's audit log in the run's log directory, split into the two parts between which a later
   * start's number goes (workspaceAuditLog).
   *
   *   - For example, a session `r123`'s `proxy-sbt-<hash>.log` gives `proxy-sbt-<hash>-r123` and `.log`.
   *   - The session's name tells the runner's proxy log apart from a command's proxy log of the same name.
   *   - `--egress-log` lists a name beginning with `proxy` as a proxy's log (EgressRules.proxyLogsOf).
   */
  private def auditLogName(proxyLog: Path): Option[(String, String)] =
    Option(proxyLog.getParent).flatMap(session => Option(session.getFileName)).map: session =>
      (s"${proxyLog.getFileName.toString.stripSuffix(".log")}-$session", ".log")

  /**
   * The file for the session's `proxyLog` in the channel log's directory, which is the run's log directory
   * (auditLogName).
   *
   * A runtime's proxy may start again in the launch, when the earlier proxy died or its runtime's creation failed
   * (RunnerRuntimes.prepared, created). The new proxy's session file has the same name, and the earlier proxy's log
   * keeps its own file here. From the second start on, the `start`-th file has `-<start>` before `.log`.
   */
  def workspaceAuditLog(channelLog: Path, proxyLog: Path, start: Int = 1): Option[Path] =
    auditLogName(proxyLog).map: (prefix, suffix) =>
      channelLog.resolveSibling(prefix + (if start == 1 then "" else s"-$start") + suffix)

  /**
   * Before the proxy starts, creates the proxy's log as a file in the run's log directory, and makes the session's
   * `proxyLog` a symbolic link to that file.
   *
   *   - The file takes the first name of workspaceAuditLog that no earlier proxy's log has.
   *   - The lines are in the file while the proxy writes them, and they stay however the session's directory is
   *     removed.
   *   - The link is symbolic, not hard, because XDG_STATE_HOME can place the log directory on a different filesystem
   *     than the session's.
   *
   * The result is Left when the file or the link cannot be made, so that the caller starts no proxy. A proxy that
   * logs to the session's file alone loses its lines with that directory. Such a proxy loses all of its lines when a
   * command's own session ends without a signal (RunOnHostSandbox.appendSessionLogs).
   */
  private[launcher] def keepAuditLog(channelLog: Path, proxyLog: Path): Either[String, Unit] =
    // Owner-only, as the container proxy's log is, because the targets the log records are what a GET carries out.
    val ownerOnly = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))
    def created(start: Int): Option[Path] =
      workspaceAuditLog(channelLog, proxyLog, start).flatMap: kept =>
        try Some(Files.createFile(kept, ownerOnly))
        catch case _: FileAlreadyExistsException => created(start + 1)
    try
      created(start = 1).foreach: kept =>
        try
          Files.deleteIfExists(proxyLog)
          Files.createSymbolicLink(proxyLog, kept)
        catch
          case ex: (IOException | UnsupportedOperationException) =>
            // No line was written to the file. Without the link, the file would read as a proxy that logged nothing.
            try Files.deleteIfExists(kept)
            catch case _: IOException => ()
            throw ex
      Right(())
    catch
      case ex: (IOException | UnsupportedOperationException) =>
        val directory = channelLog.getParent
        Left(
          s"The host command sandbox's proxy is not started: its audit log cannot be created in $directory " +
            s"(${ex.getClass.getSimpleName}: ${ex.getMessage}).\n" +
            s"Tell the user: make $directory writable, then run the command again.",
        )

  /**
   * The file that keepAuditLog made the session's `sessionLog` a link to. The session's end reads this file in the
   * link's place.
   *
   *   - The result is None unless the link names an audit log of `sessionLog` in the channel log's directory. A link
   *     naming anything else is not followed.
   *   - The sandboxed command cannot write to the link's directory or to the file's: the session directory outside
   *     `tmp/`, and the log directory.
   */
  def keptAuditLog(channelLog: Path, sessionLog: Path): Option[Path] =
    auditLogName(sessionLog).flatMap: (prefix, suffix) =>
      try
        Some(Files.readSymbolicLink(sessionLog)).filter: kept =>
          val name = kept.getFileName.toString
          kept.getParent == channelLog.getParent && name.startsWith(prefix) && name.endsWith(suffix)
            && name.length >= prefix.length + suffix.length
            && name.substring(prefix.length, name.length - suffix.length).matches("(-[1-9][0-9]*)?")
      catch case _: (IOException | UnsupportedOperationException) => None

  /** The proxy's profile, beside its log. */
  private[launcher] def proxyProfileFile(proxyLog: Path): Path = RunOnHostInspection.sibling(proxyLog, ".sb")

  /** Starts the proxy under its profile (SeatbeltProfile.renderProxy), which lies beside the proxy's log. */
  private def startProxy(
    record: Path, program: Program, fileHosts: Vector[String], proxyLog: Path,
    systemPaths: SeatbeltProfile.SystemPaths, credentials: Vector[BrokeredCredential], channelLog: Option[Path],
  ): Either[String, Process] =
    for
      names <- RunOnHostInspection.leafNames(egressRuleText(program, fileHosts))
      _ <- RunOnHostInspection.create(proxyLog, names)
      inputs <- proxyInputs(systemPaths)
      profile <- SeatbeltProfile.renderProxy(
        inputs.copy(reads = inputs.reads :+ RunOnHostInspection.leafDirectory(proxyLog)),
      )
      // Last before the start, so that a start refused above leaves no empty log in the log directory.
      _ <- channelLog.fold(Right(()))(keepAuditLog(_, proxyLog))
      started <- startProxyUnder(profile, record, program, fileHosts, proxyLog, credentials)
    yield started

  private def startProxyUnder(
    profile: String, record: Path, program: Program, fileHosts: Vector[String], proxyLog: Path,
    credentials: Vector[BrokeredCredential],
  ): Either[String, Process] =
    try
      val profileFile = proxyProfileFile(proxyLog)
      Files.writeString(profileFile, profile, UTF_8)
      // The command's environment sets the same property (RunOnHostSandbox.commandEnvironment). The proxy gets it on
      // the command line, since the proxy's environment is closed. A dual-stack JVM binds ::ffff:127.0.0.1, which the
      // profile's "localhost" class does not cover (measured by the acceptance test's proxy rows).
      val invocation = selfInvocation("--serve-proxy-on-host")
      val command = RunOnHostSession.registeredSpawn(
        record,
        sandboxExec(profileFile, invocation.head +: "-Djava.net.preferIPv4Stack=true" +: invocation.tail),
      )
      val builder = ProcessBuilder(command*)
      // The JVM asks for its working directory at start (SystemProps). The profile grants no directory of the
      // starter's, but it does grant the root.
      builder.directory(java.io.File("/"))
      // Closed like the command's environment. The proxy needs its own settings, and the one selected variable to leave
      // through an upstream proxy as the container's copy does. Nothing else of the launcher's environment has a reader
      // here.
      builder.environment.clear()
      agentsandbox.egress.TransportHelper.upstreamProxyVariable(name => Option(System.getenv(name)))
        .foreach(builder.environment.put(_, _))
      import agentsandbox.egress.RulesetHelper
      builder.environment.put(RulesetHelper.ProfileVariable, RulesetHelper.DefaultProfile)
      builder.environment.put(RulesetHelper.RuleVariable, egressRuleText(program, fileHosts))
      builder.environment.put(agentsandbox.egress.AgentEgressProxy.BindVariable, "127.0.0.1:0")
      // The leaf makes the proxy enforce `read` in the rules. A proxy given no leaf tunnels its hosts without
      // inspecting them.
      builder.environment.put(
        agentsandbox.egress.AgentEgressProxy.CertificateVariable,
        RunOnHostInspection.leafCertificate(proxyLog).toString,
      )
      builder.environment.put(
        agentsandbox.egress.AgentEgressProxy.PrivateKeyVariable, RunOnHostInspection.leafKey(proxyLog).toString,
      )
      // The credentials go by pipe, never by an environment variable or an argument (SECURITY.md, "Who holds a
      // brokered value").
      if credentials.nonEmpty then
        builder.environment.put(CredentialGrammar.StdinVariable, CredentialGrammar.StdinValue)
      builder.redirectOutput(ProcessBuilder.Redirect.DISCARD)
      // The proxy's stderr is its log, opened here and inherited, because the profile grants no write
      // (RunOnHostSbtServer.serverLog). What sandbox-exec or the JVM says before the proxy prints anything thus lands
      // where the ready line is awaited.
      builder.redirectError(ProcessBuilder.Redirect.appendTo(proxyLog.toFile))
      val process = builder.start()
      // The write runs on its own thread, so that the wait for the proxy's port bounds it. Up to 256 bindings exceed a
      // pipe's buffer, and a proxy that stops before reading them would hold a blocking write. The wait for the port
      // reports a proxy that is already gone.
      Thread.startVirtualThread: () =>
        try
          if credentials.nonEmpty then
            process.getOutputStream.write(CredentialGrammar.bindingBytes(credentials))
          process.getOutputStream.close()
        catch case _: IOException => ()
      Right(process)
    catch case ex: IOException => Left(s"starting the proxy: ${ex.getMessage}")

  /** The hosts the proxy refused, read from its audit log's `deny <host> CONNECT` lines at byte offset `from` and
    * after. */
  def deniedHosts(proxyLog: Path, from: Long = 0): Vector[String] =
    proxyLogLines(proxyLog, from).flatMap(LogHelper.auditFields)
      .collect { case LogHelper.AuditFields("deny", host, "CONNECT", _) => host }.distinct

  /** A request the proxy refused inside a tunnel, and the audit line's reason. */
  case class RefusedRequest(method: String, host: String, target: String, reason: String):
    /** An origin-form target is a path. A target of any other form is refused for its form, and shown as sent. */
    def spelled: String =
      if target.startsWith("/") then s"$method https://$host$target" else s"$method $target ($host)"

  /** The requests the proxy refused inside a tunnel, once each (SECURITY.md, "The audit line grammar"). Such a line
    * has a method and a target, where a refused CONNECT has an empty target. */
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
   * The reason the proxy on `port` serves nothing when a write to its log failed: the `details` of its Proxy-Status
   * field (Refusals.proxyStatus).
   *
   *   - This method asks the proxy, since the log that would say so is what failed. The programs need not print the
   *     reason; run-on-host-internals.md has what sbt and mill print.
   *   - `OPTIONS *` is HTTP's request about the server itself, and it is no CONNECT. A proxy that still logs answers
   *     400 and logs `deny - -`, which deniedHosts does not read as a refused host.
   *   - `Max-Forwards: 0` is for a recipient that is not this proxy, in case the proxy died and another program took
   *     its port. An HTTP proxy there must answer itself, not forward (RFC 9110, 7.6.2). This proxy forwards no
   *     OPTIONS and does not read the header.
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

  /** The file that the proxy writing to the session's `proxyLog` appends to. The result is the file in the run's
    * log directory (keptAuditLog), not the session's link to it, which goes with the session. */
  private[launcher] def proxyLogFile(channelLog: Option[Path], proxyLog: Path): Path =
    channelLog.flatMap(keptAuditLog(_, proxyLog)).getOrElse(proxyLog)

  // The user's step is a relaunch, because a proxy that cannot log keeps running, and the runner keeps reusing its
  // runtime (RunnerRuntimes.prepared).
  private[launcher] def reportUnwritableProxyLog(
    runtime: Runtime, channelLog: Option[Path], log: String => Unit,
  ): Unit =
    unwritableProxyLog(runtime.proxyPort).foreach: reason =>
      log(
        s"The host command sandbox's proxy serves no new connection: $reason.\n" +
          s"Tell the user: make ${proxyLogFile(channelLog, runtime.proxyLog)} writable again, then relaunch.",
      )

  /** Reports the denied hosts, once per refused host, and the refused requests, after the command. The report never
    * adds a rule automatically.
    *
    *   - A program need not print a 403's body, so each request carries what that body said: the reason, and the step
    *     for a refusal that the command answers by changing the request (RefusalAdvice.requestStep).
    *   - The user's step follows only a refusal of a grant, which the rule file cannot give. */
  private[launcher] def reportDenied(proxyLog: Path, from: Long, program: Program, log: String => Unit): Unit =
    val hosts = deniedHosts(proxyLog, from)
    if hosts.nonEmpty then
      log((("Command requested network access to:" +: hosts.map(host => s"  $host")) :+
        ("Not permitted by the host command sandbox. If the command should reach it, add an" +
          s" `$ProgramRuleForm` line to ${programRuleFileShown(program.name)}."))
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
