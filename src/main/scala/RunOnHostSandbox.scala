// The §4 wrapper: from a project and a tool to a confined build's exit code, through the thirteen
// steps — validate, scavenge, publish, proxy, profile, run, end what was started, remove. macOS
// only, like everything it drives; the assembly and refusal logic lives in RunOnHostPolicy and
// is unit-tested there, so this file is choreography plus the host observations no Linux test can
// make.

package agentsandbox.launcher

import java.io.IOException
import java.nio.charset.StandardCharsets.{ISO_8859_1, UTF_8}
import java.nio.file.{Files, Path}

import scala.jdk.CollectionConverters.*

import RunOnHostPolicy.*
import RunOnHostSession.Session
import HostCommands.Os
import SandboxProject.{isMetadataEntry, projectIdOf}

object RunOnHostSandbox:

  case class Assembled(
    policy: BuildPolicy,
    sbtDistribution: Option[Path],
    sbtGlobal: Option[Path],
  )

  private def isExecutableFile(path: Path) = Files.isExecutable(path) && Files.isRegularFile(path)

  /** Absent is None; existing-but-unreadable throws and fails the assembly, never falls to the
    * next source — Mill would select the file and then fail reading it. */
  private def readLines(path: Path): Option[Seq[String]] =
    Option.when(Files.exists(path))(Files.readAllLines(path).toArray(Array.empty[String]).toSeq)

  /** Steps 1–5: everything §2.1 derives authority from, decided before anything runs. */
  def assemble(project: Path, tool: Tool, env: String => Option[String]): Either[String, Assembled] =
    val os = Os.Mac
    def context[A](step: String)(value: Either[Any, A]): Either[String, A] =
      value.left.map(reason => s"$step: $reason")

    for
      coursierCache <- coursierCacheRoot(os, env).toRight("no Coursier cache root")
      jdk <- context("jvm")(resolveJdkHome(env, coursierCache, realPath, isExecutableFile))
      launcherAndDistribution <- tool match
        case Tool.Sbt =>
          for
            installDir <- coursierInstallDir(os, env).toRight("no Coursier install directory")
            sbt <- context("sbt launcher")(
              validateSbtLauncher(installDir.resolve("sbt"), installDir, realPath, isExecutableFile),
            )
            // ISO-8859-1, not UTF-8: cs appends a jar to its launchers, so the file is not text.
            // Every byte maps to a char, which leaves the ASCII path this searches for intact.
            inner <- SeatbeltProfile
              .sbtDistribution(String(Files.readAllBytes(sbt), ISO_8859_1), coursierCache)
              .toRight(s"$sbt names no distribution inside $coursierCache")
            home <- context("sbt distribution")(
              validateSbtDistribution(inner, coursierCache, realPath, isExecutableFile),
            )
          yield (sbt, Some(home))
        case Tool.Mill =>
          for
            _ <- context("mill bootstrap")(validateMillBootstrap(project, isExecutableFile))
            _ <- context("mill jvm")(millJvmIsSystem(project, readLines))
            version <- context("mill version")(millVersion(project, env, readLines))
            downloads <- millDownloadDir(env).toRight("no Mill download folder")
            arch = System.getProperty("os.arch") match
              case "aarch64" => "arm64"
              case other     => other
            provisioned <- context("mill launcher")(
              millLauncher(downloads, version, arch, isExecutableFile),
            )
            real <- realPath(provisioned).toRight(s"$provisioned vanished")
          yield (real, None)
      (launcher, distribution) = launcherAndDistribution
      configuredRoot <- context("cache root")(cacheRootOf(os, env))
      cacheRoot <- context("cache root")(
        cacheRootOutsideProject(configuredRoot, project, os, HostCommands.canonicalizedFuturePath),
      )
      projectId = projectIdOf(project, os)
      v1 = agentCoursierV1(cacheRoot, projectId)
      _ = Files.createDirectories(v1)
      sbtGlobal = Option.when(tool == Tool.Sbt):
        Files.createDirectories(agentSbtGlobal(cacheRoot, projectId)).toRealPath()
    yield Assembled(
      BuildPolicy(
        project = project,
        jdkHome = jdk,
        coursierV1 = v1.toRealPath(),
        tool = tool,
        launcher = launcher,
      ),
      distribution,
      sbtGlobal,
    )

  /**
   * host-command/ is a closed namespace inside a closed namespace, the same rule its parent
   * applies (SandboxProject.policyDirError): the tools this wrapper serves, egress/ inside each,
   * allowed inside that — a stray name or a symlinked component refuses the build, never sits as
   * ignored config.
   */
  def hostCommandStray(project: Path): Option[String] =
    val dir = project.resolve(".ko-agent-sandbox").resolve("host-command")
    val tools = Vector("sbt", "mill")
    def strays(path: Path, admitted: Set[String]): Vector[String] =
      if !Files.isDirectory(path) then Vector.empty
      else
        val stream = Files.list(path)
        val entries =
          try stream.iterator().asScala.toVector
          finally stream.close()
        entries.map(_.getFileName.toString).filterNot(isMetadataEntry).filterNot(admitted).sorted
          .map(name => s"$path/$name")

    if !Files.exists(dir, java.nio.file.LinkOption.NOFOLLOW_LINKS) then None
    else
      val components = dir +: tools.flatMap: name =>
        Vector(dir.resolve(name), dir.resolve(name).resolve("egress"),
          dir.resolve(name).resolve("egress").resolve("allowed"))
      components.find(Files.isSymbolicLink) match
        case Some(link) =>
          Some(s"$link is a symlink; boundary configuration is read plainly or not at all")
        case None =>
          val stray = strays(dir, tools.toSet) ++ tools.flatMap: name =>
            strays(dir.resolve(name), Set("egress")) ++
              strays(dir.resolve(name).resolve("egress"), Set("allowed"))
          Option.when(stray.nonEmpty):
            s"${stray.mkString(", ")}: not configuration this launcher reads — " +
              "a typo, or a newer launcher's file; check the spelling or update the launcher"

  /** The project file's hosts, validated to §11's grammar; an absent file contributes nothing. */
  def readAllowlist(project: Path, tool: Tool): Either[String, Vector[String]] =
    hostCommandStray(project).toLeft(()).flatMap: _ =>
      val file = buildAllowlistPath(project, tool)
      if !Files.exists(file) then Right(Vector.empty)
      else
        try
          buildAllowlist(Files.readString(file, UTF_8)).left.map:
            case Refusal.AllowlistEntryOutsideGrammar(entry) =>
              s"$file: '$entry' is outside the allowlist grammar — one `+host <host>` per line"
            case other => s"$file: $other"
        catch case ex: IOException => Left(s"$file: ${ex.getMessage}")

  /**
   * The runtime-authority file: one absolute path per line, `#` comments, `x ` prefix for a path
   * that must also be executable. It starts empty — §2.1 admits a runtime path only where testing
   * proves the read is stable, and probe/build-profile-gate.sh discovers them.
   */
  def readRuntimeAuthority(file: Option[Path]): SeatbeltProfile.RuntimeAuthority =
    file match
      case None => SeatbeltProfile.RuntimeAuthority(Seq.empty, Seq.empty)
      case Some(path) =>
        val lines = Files.readAllLines(path).toArray(Array.empty[String]).toSeq
          .map(_.trim).filter(line => line.nonEmpty && !line.startsWith("#"))
        val executes = lines.filter(_.startsWith("x ")).map(line => Path.of(line.drop(2).trim))
        val reads = lines.filterNot(_.startsWith("x ")).map(Path.of(_))
        SeatbeltProfile.RuntimeAuthority(reads.flatMap(realPath), executes.flatMap(realPath))

  /** How the wrapper re-invokes its own vehicle for --serve-proxy-on-host: the running JVM and
    * classpath, or the native image binary itself. */
  def selfInvocation(): Seq[String] =
    if System.getProperty("org.graalvm.nativeimage.imagecode") != null then
      val self = ProcessHandle.current().info().command()
      Seq(self.orElseThrow(() => IllegalStateException("the native image cannot name itself")),
        "--serve-proxy-on-host")
    else
      Seq(
        Path.of(System.getProperty("java.home")).resolve("bin").resolve("java").toString,
        "-cp", System.getProperty("java.class.path"),
        "agentsandbox.launcher.AgentSandboxLauncher", "--serve-proxy-on-host",
      )

  /** The bound port, from the ready line the proxy prints after `bind`; its log file is the tee
    * of its stderr, so the line lands where this polls. */
  def awaitProxyPort(log: Path, deadlineMillis: Long): Either[String, Int] =
    val Ready = raw""".*agent-egress-proxy listening on :(\d+).*""".r
    val deadline = System.nanoTime + deadlineMillis * 1_000_000
    var found: Option[Int] = None
    while found.isEmpty && System.nanoTime < deadline do
      val line =
        if Files.exists(log) then
          Files.readString(log, UTF_8).linesIterator.collectFirst { case Ready(port) => port.toInt }
        else None
      line match
        case Some(port) => found = Some(port)
        case None       => Thread.sleep(50)
    found.toRight:
      val said =
        if Files.exists(log) then Files.readString(log, UTF_8).linesIterator.take(5).mkString("\n")
        else "(no log was written)"
      s"the build proxy did not report ready within ${deadlineMillis / 1000}s:\n$said"

  /**
   * §3.2's launch refusal: one server per project. A live server reached through the project's
   * portfile belongs to someone — the user's shell, another session — and a build that attached
   * to it would run outside this profile. Live means connectable; a stale portfile is left for
   * sbt, which replaces it.
   */
  def livePortfileServer(project: Path): Option[Path] =
    val portfile = project.resolve("project").resolve("target").resolve("active.json")
    if !Files.isRegularFile(portfile) then None
    else
      try
        RunOnHostSession.portfileSocket(Files.readString(portfile, UTF_8)).filter: socket =>
          Files.exists(socket) && connectable(socket)
      catch case _: IOException => None

  private def connectable(socket: Path): Boolean =
    try
      val channel = java.nio.channels.SocketChannel.open(java.net.StandardProtocolFamily.UNIX)
      try
        channel.connect(java.net.UnixDomainSocketAddress.of(socket))
        true
      finally channel.close()
    catch case _: IOException => false

  // ---------------------------------------------------------------------------
  // The thirteen steps
  // ---------------------------------------------------------------------------

  def run(
    projectArg: Path,
    tool: Tool,
    buildArgs: Seq[String],
    runtime: SeatbeltProfile.RuntimeAuthority,
    uid: Int,
    log: String => Unit,
  ): Int =
    val env: String => Option[String] = name => Option(System.getenv(name))
    val root = Path.of(s"/private/tmp/ko-agent-$uid")

    val prepared: Either[String, (Assembled, Vector[String])] =
      for
        project <-
          try Right(projectArg.toAbsolutePath.toRealPath())
          catch case ex: IOException => Left(s"$projectArg: ${ex.getMessage}")
        assembled <- assemble(project, tool, env)
        fileHosts <- readAllowlist(project, tool)
        _ <- RunOnHostSession.ensureRoot(root, uid)
        // Scavenge before the one-server refusal: an orphan a kill left is ours to end here,
        // and only a server that survives the scavenge belongs to someone else.
        _ = RunOnHostSession
          .scavenge(root, RunOnHostSession.HostProcesses, SbtServerShutdown.shutdown(_))
          .foreach: (entry, actions) =>
            log(s"scavenged ${entry.getFileName}: ${actions.mkString(", ")}")
        _ <-
          if tool != Tool.Sbt then Right(())
          else
            livePortfileServer(project).toLeft(()).left.map: socket =>
              s"a live sbt server holds this project's portfile (socket $socket); " +
                "run `sbt shutdown` there and retry"
      yield (assembled, fileHosts)

    prepared match
      case Left(reason) =>
        log(s"refused: $reason")
        2
      case Right((assembled, fileHosts)) =>
        RunOnHostSession.publish(root, assembled.policy.project) match
          case Left(reason) =>
            log(s"refused: $reason")
            2
          case Right(session) =>
            val outcome =
              try
                sessionTmpFits(session.tmp) match
                  case Left(reason) => Left(reason.toString)
                  case Right(_) => runInSession(session, assembled, fileHosts, buildArgs, runtime, log)
              finally
                RunOnHostSession.endRecordedGroups(session.records, RunOnHostSession.HostProcesses)
                RunOnHostSession.remove(session)
            outcome match
              case Left(reason) =>
                log(s"refused: $reason")
                2
              case Right(exit) => exit

  private def runInSession(
    session: Session,
    assembled: Assembled,
    fileHosts: Vector[String],
    buildArgs: Seq[String],
    runtime: SeatbeltProfile.RuntimeAuthority,
    log: String => Unit,
  ): Either[String, Int] =
    assembled.sbtGlobal.foreach: sbtGlobal =>
      val swept = cleanForeignTargetLinks(assembled.policy.project, Seq(assembled.policy.project, sbtGlobal))
      if swept.nonEmpty then
        log(s"removed ${swept.size} target/ links into another venue's store (first: ${swept.head})")
    for
      _ <- startProxy(session, fileHosts)
      port <- awaitProxyPort(session.directory.resolve("proxy.log"), deadlineMillis = 30_000)
      profile <- SeatbeltProfile.render(
        SeatbeltProfile.ProfileInputs(
          policy = assembled.policy,
          sessionTmp = session.tmp,
          sbtDistribution = assembled.sbtDistribution,
          sbtGlobal = assembled.sbtGlobal,
          proxyPort = port,
          runtime = runtime,
        ),
      )
      exit <- runBuild(session, assembled, profile, port, buildArgs)
    yield
      reportDenied(session.directory.resolve("proxy.log"), assembled.policy.tool, log)
      if assembled.policy.tool == Tool.Sbt then shutdownSessionServer(session, assembled.policy, log)
      exit

  private def startProxy(session: Session, fileHosts: Vector[String]): Either[String, Process] =
    val command = RunOnHostSession.registeredSpawn(session.records.resolve("proxy"), selfInvocation())
    val builder = ProcessBuilder(command*)
    builder.environment.put("EGRESS_PROFILE", "deny-unless-allowed")
    builder.environment.put("EGRESS_ALLOWED", egressAllowedText(fileHosts))
    builder.environment.put("EGRESS_BIND", "127.0.0.1:0")
    builder.environment.put("EGRESS_LOG_FILE", session.directory.resolve("proxy.log").toString)
    builder.redirectOutput(ProcessBuilder.Redirect.DISCARD)
    builder.redirectError(ProcessBuilder.Redirect.DISCARD) // the log file is the tee
    try Right(builder.start())
    catch case ex: IOException => Left(s"starting the build proxy: ${ex.getMessage}")

  private def runBuild(
    session: Session,
    assembled: Assembled,
    profile: String,
    proxyPort: Int,
    buildArgs: Seq[String],
  ): Either[String, Int] =
    val policy = assembled.policy
    val profileFile = session.directory.resolve("profile.sb")
    Files.writeString(profileFile, profile, UTF_8)

    val toolCommand = policy.tool match
      case Tool.Sbt =>
        Seq(policy.launcher.toString, "--jvm-client", "-batch",
          "-java-home", policy.jdkHome.toString) ++ buildArgs
      case Tool.Mill =>
        Seq(policy.project.resolve("mill").toString, "--no-daemon") ++ buildArgs

    val command = RunOnHostSession.registeredSpawn(
      session.records.resolve("client"),
      Seq("/usr/bin/sandbox-exec", "-f", profileFile.toString) ++ toolCommand,
    )
    val builder = ProcessBuilder(command*)
    builder.directory(policy.project.toFile)
    builder.inheritIO()
    val environment = builder.environment
    environment.put("PATH",
      s"${policy.jdkHome.resolve("bin")}:${Option(System.getenv("PATH")).getOrElse("/usr/bin:/bin")}")
    environment.put("JAVA_TOOL_OPTIONS", (Seq(
      s"-Djava.io.tmpdir=${session.tmp}",
      s"-Djava.util.prefs.userRoot=${session.tmp}",
    ) ++ assembled.sbtGlobal.map(base => s"-Dsbt.global.base=$base") ++ Seq(
      "-Dhttps.proxyHost=127.0.0.1", s"-Dhttps.proxyPort=$proxyPort",
      "-Dhttp.proxyHost=127.0.0.1", s"-Dhttp.proxyPort=$proxyPort",
      // Without this a JVM reaches 127.0.0.1 through a dual-stack AF_INET6 socket as v4-mapped
      // ::ffff:127.0.0.1, which the profile's "localhost" class does not cover: the connect to
      // the proxy dies with EPERM (measured, probe/jvm-proxy-rule.sh).
      "-Djava.net.preferIPv4Stack=true",
    )).mkString(" "))
    environment.put("XDG_RUNTIME_DIR", session.tmp.toString)
    environment.put("SBT_GLOBAL_SERVER_DIR", session.tmp.toString)
    environment.put("COURSIER_CACHE", policy.coursierV1.toString)

    try Right(builder.start().waitFor())
    catch case ex: IOException => Left(s"starting the build: ${ex.getMessage}")

  /**
   * §9.2's venue cost, automated at the confined venue's door. sbt 2 leaves `target/` outputs as
   * symlinks into its global base's content-addressed store, so a tree the user's own sbt built
   * links into a store this profile cannot reach — and zinc treats the unreadable state as an
   * error, not a cold start (measured: `previousCompile` fails on `inc_compile_3.zip`). Every
   * symlink under a `target/` directory that does not resolve inside a granted root — the
   * dangling included — is removed before the build; the artifacts it named still exist in the
   * store of the venue that made it, which relinks on its own next run.
   */
  def cleanForeignTargetLinks(project: Path, granted: Seq[Path]): Vector[Path] =
    val removed = Vector.newBuilder[Path]
    def walk(dir: Path, inTarget: Boolean): Unit =
      val stream =
        try Files.list(dir)
        catch case _: IOException => return
      val entries =
        try stream.iterator().asScala.toVector
        finally stream.close()
      entries.foreach: entry =>
        val name = entry.getFileName.toString
        if Files.isSymbolicLink(entry) then
          if inTarget then
            val resolvesInside =
              try granted.exists(entry.toRealPath().startsWith)
              catch case _: IOException => false
            if !resolvesInside then
              try
                Files.delete(entry)
                removed += entry
              catch case _: IOException => ()
        else if Files.isDirectory(entry) && name != ".git" && name != ".ko-agent-sandbox" then
          walk(entry, inTarget || name == "target")
    walk(project, inTarget = false)
    removed.result()

  /** The hosts the proxy refused, from its audit log's `deny <host> CONNECT` lines. */
  def deniedHosts(proxyLog: Path): Vector[String] =
    val Deny = raw""".*\bdeny (\S+) CONNECT.*""".r
    if !Files.exists(proxyLog) then Vector.empty
    else
      Files.readString(proxyLog, UTF_8).linesIterator
        .collect { case Deny(host) => host }.toVector.distinct

  /** §8.4's report, once per refused host, after the build — never an automatic addition. */
  private def reportDenied(proxyLog: Path, tool: Tool, log: String => Unit): Unit =
    val hosts = deniedHosts(proxyLog)
    if hosts.nonEmpty then
      val toolName = tool.toString.toLowerCase(java.util.Locale.ROOT)
      log((("Build requested network access to:" +: hosts.map(host => s"  $host")) :+
        ("Not permitted by the Scala build sandbox. If the build should reach it, add a" +
          s" `+host` line to .ko-agent-sandbox/host-command/$toolName/egress/allowed.")).mkString("\n"))

  /** Step 11's server half: this session's server, found through the portfile it owns and asked
    * to stop; the group ending in `run`'s finally is the belt behind it. */
  private def shutdownSessionServer(session: Session, policy: BuildPolicy, log: String => Unit): Unit =
    val portfile = policy.project.resolve("project").resolve("target").resolve("active.json")
    if Files.isRegularFile(portfile) then
      try
        RunOnHostSession.portfileSocket(Files.readString(portfile, UTF_8))
          .filter(_.startsWith(session.tmp))
          .foreach: socket =>
            SbtServerShutdown.shutdown(socket).left.foreach: reason =>
              log(s"the session's sbt server did not answer shutdown: $reason")
      catch case ex: IOException => log(s"reading $portfile: ${ex.getMessage}")
