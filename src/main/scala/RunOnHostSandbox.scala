// The wrapper: from a project and a tool to a confined build's exit code, through the thirteen
// steps — validate, scavenge, publish, proxy, profile, run, end what was started, remove. macOS
// only, like everything it drives; the assembly and refusal logic lives in RunOnHostPrereqs and
// is unit-tested there, so this file is choreography plus the host observations no Linux test can
// make.

package agentsandbox.launcher

import java.io.IOException
import java.nio.charset.StandardCharsets.{ISO_8859_1, UTF_8}
import java.nio.file.{Files, Path}

import scala.jdk.CollectionConverters.*

import RunOnHostPrereqs.*
import RunOnHostSession.{ServerAnswer, Session}
import HostCommands.Os
import SandboxProject.{isMetadataEntry, projectIdOf}

object RunOnHostSandbox:

  case class Assembled(
    prereqs: BuildPrereqs,
    sbtDistribution: Option[Path],
    /** The per-project sbt global base: created and granted for an sbt build (`sbtGlobalGranted`),
      * and for a mill build a path nothing reads, named all the same so the environment is one
      * shape for both tools — as `millDownloads` is for sbt. */
    sbtGlobal: Path,
    /** Where mill's bootstrap keeps launchers, as derived from this environment: what a mill
      * build is granted, and what the build's own script is pointed at (buildEnvironment). */
    millDownloads: Option[Path],
  ):
    def sbtGlobalGranted: Option[Path] = Option.when(prereqs.tool == Tool.Sbt)(sbtGlobal)

  private def isExecutableFile(path: Path) = Files.isExecutable(path) && Files.isRegularFile(path)

  /** Absent is None; existing-but-unreadable throws and fails the assembly, never falls to the
    * next source — mill would select the file and then fail reading it. */
  private def readLines(path: Path): Option[Seq[String]] =
    Option.when(Files.exists(path))(Files.readAllLines(path).toArray(Array.empty[String]).toSeq)

  /** Steps 1–5: everything the profile derives authority from, decided before anything runs. */
  def assemble(project: Path, tool: Tool, env: String => Option[String]): Either[String, Assembled] =
    val os = Os.Mac
    def context[A](step: String)(value: Either[Any, A]): Either[String, A] =
      value.left.map(reason => s"$step: $reason")

    for
      coursierCache <- coursierCacheRoot(os, env).toRight("no Coursier cache root")
      jdk <- context("jvm")(resolveJdkHome(env, coursierCache, realPath, isExecutableFile))
      executableAndDistribution <- tool match
        case Tool.Sbt =>
          for
            installDir <- coursierInstallDir(os, env).toRight("no Coursier install directory")
            sbt <- context("sbt executable")(
              validateSbtExecutable(installDir.resolve("sbt"), installDir, realPath, isExecutableFile),
            )
            // ISO-8859-1, not UTF-8: cs appends a jar to the scripts it installs, so the file is not text.
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
            version <- context("mill version")(millVersion(project, readLines))
            downloads <- millDownloadDir(env).toRight("no mill download folder")
            arch = System.getProperty("os.arch") match
              case "aarch64" => "arm64"
              case other     => other
            provisioned <- context("mill executable")(
              millExecutable(downloads, version, arch, isExecutableFile),
            )
            real <- realPath(provisioned).toRight(s"$provisioned vanished")
          yield (real, None)
      (executable, distribution) = executableAndDistribution
      configuredRoot <- context("cache root")(cacheRootOf(os, env))
      cacheRoot <- context("cache root")(
        cacheRootOutsideProject(configuredRoot, project, os, HostCommands.canonicalizedFuturePath),
      )
      projectId = projectIdOf(project, os)
      v1 = buildCoursierV1(cacheRoot, projectId)
      _ = Files.createDirectories(v1)
      sbtGlobal =
        if tool == Tool.Sbt then Files.createDirectories(buildSbtGlobal(cacheRoot, projectId)).toRealPath()
        else buildSbtGlobal(cacheRoot, projectId)
    yield Assembled(
      BuildPrereqs(
        project = project,
        jdkHome = jdk,
        coursierV1 = v1.toRealPath(),
        tool = tool,
        executable = executable,
      ),
      distribution,
      sbtGlobal,
      millDownloadDir(env),
    )

  /**
   * host-command/ is a closed namespace inside a closed namespace, the same rule its parent
   * applies (SandboxProject.boundaryDirError): the tools this wrapper serves, egress/ inside each,
   * rule inside that — a stray name, the retired grammar's file among them, a symlinked component,
   * or a component of the wrong type refuses the build, never sits as ignored config. The type rule
   * prevents real failures: a file where a directory belongs would read as absent configuration,
   * and a FIFO where the file belongs would block the read forever.
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
      val directories = dir +: tools.flatMap: name =>
        Vector(dir.resolve(name), dir.resolve(name).resolve("egress"))
      val ruleFiles = tools.map(name => dir.resolve(name).resolve("egress").resolve("rule"))
      val retiredFiles = tools.map(name => dir.resolve(name).resolve("egress").resolve("allowed"))
      def wrongType(path: Path, directory: Boolean): Boolean =
        Files.exists(path, java.nio.file.LinkOption.NOFOLLOW_LINKS) &&
          (if directory then !Files.isDirectory(path) else !Files.isRegularFile(path))
      (directories ++ ruleFiles).find(Files.isSymbolicLink)
        .map(link => s"$link is a symlink; boundary configuration is read plainly or not at all")
        .orElse(directories.find(wrongType(_, directory = true))
          .map(p => s"$p is not a directory; boundary configuration is read plainly or not at all"))
        .orElse(ruleFiles.find(wrongType(_, directory = false))
          .map(p => s"$p is not a regular file; boundary configuration is read plainly or not at all"))
        .orElse(retiredFiles.find(Files.exists(_, java.nio.file.LinkOption.NOFOLLOW_LINKS))
          .map(p => s"$p is a file of the retired grammar; the build's rules are egress/rule, one " +
            s"`$BuildRuleForm` per line — rewrite the lines there and delete this file"))
        .orElse:
          val stray = strays(dir, tools.toSet) ++ tools.flatMap: name =>
            strays(dir.resolve(name), Set("egress")) ++
              strays(dir.resolve(name).resolve("egress"), Set("rule"))
          Option.when(stray.nonEmpty):
            s"${stray.mkString(", ")}: not configuration this launcher reads — " +
              "a typo, or a newer launcher's file; check the spelling or update the launcher"

  /** The project file's hosts, validated to the build's rule grammar (run-on-host.md
    * "Configuration"); an absent file contributes nothing. */
  def readBuildRules(project: Path, tool: Tool): Either[String, Vector[String]] =
    hostCommandStray(project).toLeft(()).flatMap: _ =>
      val file = buildRulePath(project, tool)
      if !Files.exists(file) then Right(Vector.empty)
      else
        try
          buildRuleHosts(Files.readString(file, UTF_8)).left.map:
            case Refusal.RuleOutsideBuildGrammar(line) =>
              s"$file: '$line' is outside the build's rule grammar — one `$BuildRuleForm` per line"
            case other => s"$file: $other"
        catch case ex: IOException => Left(s"$file: ${ex.getMessage}")

  /**
   * The runtime-authority grammar: one absolute path per line, `#` comments, `x ` prefix for a
   * path that must also be executable. A runtime path is admitted only where testing proves the
   * read is stable; the resource agentsandbox/runtime-authority.txt is the measured set, and
   * src/probe/build-profile-iterate.sh is how it grows.
   */
  def parseRuntimeAuthority(all: Seq[String]): SeatbeltProfile.RuntimeAuthority =
    val lines = all.map(_.trim).filter(line => line.nonEmpty && !line.startsWith("#"))
    val executes = lines.filter(_.startsWith("x ")).map(line => Path.of(line.drop(2).trim))
    val reads = lines.filterNot(_.startsWith("x ")).map(Path.of(_))
    SeatbeltProfile.RuntimeAuthority(reads.flatMap(realPath), executes.flatMap(realPath))

  def readRuntimeAuthority(file: Option[Path]): SeatbeltProfile.RuntimeAuthority =
    file match
      case None => SeatbeltProfile.RuntimeAuthority(Seq.empty, Seq.empty)
      case Some(path) =>
        parseRuntimeAuthority(Files.readAllLines(path).toArray(Array.empty[String]).toSeq)

  def bundledRuntimeAuthority(): SeatbeltProfile.RuntimeAuthority =
    val stream = getClass.getResourceAsStream("/agentsandbox/runtime-authority.txt")
    if stream == null then
      throw IllegalStateException("this jar bundles no runtime-authority.txt; rebuild it")
    val text =
      try String(stream.readAllBytes(), UTF_8)
      finally stream.close()
    parseRuntimeAuthority(text.linesIterator.toSeq)

  /** How the wrapper re-invokes its own vehicle — the running JVM and classpath, or the native
    * image binary itself — under one of the launcher's private verbs. */
  def selfInvocation(verbAndArguments: String*): Seq[String] =
    if System.getProperty("org.graalvm.nativeimage.imagecode") != null then
      val self = ProcessHandle.current().info().command()
      self.orElseThrow(() => IllegalStateException("the native image cannot name itself"))
        +: verbAndArguments
    else
      Seq(
        Path.of(System.getProperty("java.home")).resolve("bin").resolve("java").toString,
        "-cp", System.getProperty("java.class.path"),
        "agentsandbox.launcher.AgentSandboxLauncher",
      ) ++ verbAndArguments

  /** `--run-build-on-host <tool> <project> <cwd> [--auto-shutdown-foreign-sbt-on-host] [--env=<name>...] --
    * <args...>`: one channel request as a process of its own, so the broker's cancel is a
    * SIGTERM whose answer is this wrapper's shutdown hook. */
  def runBuildMain(args: Seq[String]): Unit =
    def start(
      toolName: String,
      project: String,
      workingDirectory: String,
      options: List[String],
      buildArgs: List[String],
    ): Unit =
      val tool = toolName match
        case "sbt"  => Tool.Sbt
        case "mill" => Tool.Mill
        case other =>
          Console.err.println(s"--run-build-on-host: unknown tool $other")
          sys.exit(2)
      val uid = com.sun.security.auth.module.UnixSystem().getUid.toInt
      val stray = options.filterNot(option => option == AutoShutdownForeignSbtOption || option.startsWith(EnvOption))
      if stray.nonEmpty then
        Console.err.println(s"--run-build-on-host: unexpected arguments: ${stray.mkString(" ")}")
        sys.exit(2)
      sys.exit(
        run(
          Path.of(project), tool, buildArgs, bundledRuntimeAuthority(), uid,
          Console.err.println, workingDirectory = Some(Path.of(workingDirectory)),
          autoShutdownForeignSbt = options.contains(AutoShutdownForeignSbtOption),
          forwarded = forwardedNames(options),
        ),
      )
    args.toList match
      case toolName :: project :: workingDirectory :: rest if rest.contains("--") =>
        val (options, buildArgs) = rest.span(_ != "--")
        start(toolName, project, workingDirectory, options, buildArgs.drop(1))
      case other =>
        Console.err.println(s"--run-build-on-host: unexpected arguments: ${other.mkString(" ")}")
        sys.exit(2)

  /** `--env=<name>` as the broker and the build receive it: the name alone, the value read from
    * the receiving process's own environment under `carrierName` (RunOnHostChannel.spawnBroker).
    * A forward is thus never an argument with a secret in it below the launcher. */
  val EnvOption = "--env="

  def forwardedNames(options: Seq[String]): Vector[String] =
    options.filter(_.startsWith(EnvOption)).map(_.stripPrefix(EnvOption)).toVector

  /** Where a forwarded value rides from the launcher to the confined build: a name nothing reads
    * by accident. The broker and the wrapper are unconfined JVMs of the launcher's own code, and an
    * explicit `--env=NAME=VALUE` installed under its own name — a loader variable, say — would be
    * read by them first; the requested name is restored inside the build's environment alone,
    * where the wrapper's own settings still win over it. */
  def carrierName(name: String): String = s"KO_AGENT_RUN_ON_HOST_ENV_$name"

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
   * The launch refusal SECURITY.md "Run on host" records: one sbt server per project. A live
   * server reached through the project's portfile belongs to someone — the user's shell, another
   * session — and a build that attached to it would run outside this profile. Live means
   * connectable; a stale portfile is left for sbt, which replaces it. The socket here is wherever
   * the portfile points, uncontained on purpose — the user's own server lives outside any
   * session — and the probe only connects and closes, writing nothing to what it reaches.
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

  val AutoShutdownForeignSbtOption = "--auto-shutdown-foreign-sbt-on-host"

  def foreignServerRefusal(socket: Path): String =
    s"a live sbt server holds this project's portfile (socket $socket); " +
      "run `sbt shutdown` there and retry"

  /**
   * Where the user's own sbt 2 keeps this project's server socket:
   * `<serverDir>/<half SHA-1 hex of the portfile path's Path.toUri spelling>/sock`, with
   * serverDir `$SBT_GLOBAL_SERVER_DIR`, else the global base versioned `/2`, then `/server`.
   * Each input is taken as sbt takes it, because a divergence here is a divergence in what gets
   * shut down: `SBT_GLOBAL_SERVER_DIR` verbatim, present-but-empty included
   * (`CommandExchange.scala`), while the global base's own sources are trimmed and empty-filtered
   * — `SBT_CONFIG_HOME`, else `XDG_CONFIG_HOME/sbt`, else `user.home/.config/sbt`
   * (`SysProp.defaultGlobalBaseDirectory`). `user.home`, not `$HOME`: sbt reads the property, and
   * the two can differ. `-Dsbt.global.base`, first in sbt's order, lives in the user's JVM and is
   * invisible from this process, so a server launched with it derives elsewhere and is never
   * found at this socket — the refusal below, not a wrong shutdown.
   */
  def sbtServerSocket(project: Path, env: String => Option[String], userHome: Path): Path =
    // java.io.File joins throughout, as sbt's `/` does: an empty parent resolves against the
    // root, where Path.resolve would keep the result relative.
    def file(value: String) = java.io.File(value)
    extension (parent: java.io.File) def /(child: String) = java.io.File(parent, child)
    def trimmed(name: String): Option[java.io.File] =
      env(name).filter(_.nonEmpty).map(value => file(value.trim))
    val uri = project.resolve("project").resolve("target").resolve("active.json").toUri.toString
    val digest = java.security.MessageDigest.getInstance("SHA-1").digest(uri.getBytes(UTF_8))
    val hash = digest.map(byte => f"$byte%02x").mkString.take(20)
    val globalBase =
      trimmed("SBT_CONFIG_HOME")
        .orElse(trimmed("XDG_CONFIG_HOME").map(_ / "sbt"))
        .getOrElse(file(userHome.toString) / ".config" / "sbt")
        .getAbsoluteFile
    val serverDir = env("SBT_GLOBAL_SERVER_DIR").map(file).getOrElse(globalBase / "2" / "server")
    (serverDir / hash / "sock").toPath

  /** A chain longer than this is a cycle or an attempt at one; either way, unanswerable. */
  private val MaxSymlinkHops = 40

  /**
   * Whether a path the wrapper is about to send to could have been planted by a build. The
   * question is not where the path ends but whether resolving it ever *enters* somewhere a build
   * writes: from the first component inside, the build chooses what every later component means,
   * and a link there can send the rest anywhere — including straight back out, which is why the
   * fully resolved endpoint answers nothing. So the walk follows one hop at a time, checking
   * where each link *sits* before reading where it points, and answers yes the moment a step
   * lands in a writable root — the leaf included, since the socket itself may be the planted
   * link. It stops at the first component absent even as a link: nothing exists beneath it, and
   * creating it would need a write to the last resolved prefix, outside every writable root by
   * then.
   *
   * The roots are the profile's writable set (`SeatbeltProfile.render`): the project, and the
   * per-project caches that persist across sessions, so a socket an *earlier* agent's build
   * planted in a cache is caught as well. Each is compared in both of its macOS spellings, the
   * firmlink aliasing every containment check here shares
   * (`SandboxProject.withMacDataVolumeAliases`). A cache that does not resolve holds nothing and
   * is skipped; the project is mandatory, so its silence, a relative target, and any unanswerable
   * walk all count as reachable. A target already lexically inside a root is reachable whatever
   * the filesystem currently shows, so that is answered before the walk begins.
   */
  def reachableThroughBuildWritable(target: Path, project: Path, caches: Seq[Path]): Boolean =
    def real(path: Path): Option[Path] =
      try Some(path.toRealPath())
      catch case _: IOException => None
    real(project) match
      case None => true
      case Some(projectRoot) =>
        val roots =
          SandboxProject.withMacDataVolumeAliases(projectRoot +: caches.flatMap(real))
        def inside(path: Path) = roots.exists(path.normalize.startsWith)
        if target.getRoot == null || inside(target) then true
        else
          try
            var resolved = target.getRoot
            var pending = target.iterator.asScala.map(_.toString).toList
            var hops = 0
            var reachable = false
            var absent = false
            while pending.nonEmpty && !reachable && !absent do
              val name = pending.head
              pending = pending.tail
              if name == "." then ()
              else if name == ".." then Option(resolved.getParent).foreach(resolved = _)
              else
                val step = resolved.resolve(name)
                if inside(step) then reachable = true
                else if !Files.exists(step, java.nio.file.LinkOption.NOFOLLOW_LINKS) then
                  absent = true
                else if Files.isSymbolicLink(step) then
                  hops += 1
                  if hops > MaxSymlinkHops then reachable = true
                  else
                    // One hop only: its target's own components are walked, and checked, next.
                    val link = Files.readSymbolicLink(step)
                    if link.isAbsolute then resolved = link.getRoot
                    pending = link.iterator.asScala.map(_.toString).toList ++ pending
                else resolved = step
            reachable
          catch case _: IOException => true

  /**
   * The consented resolution: under the launch option, end the foreign server instead of
   * refusing. The socket the shutdown is sent to is derived from the project path the way sbt
   * derives it, never read from the portfile, and the portfile's word is only compared against it: workspace
   * content must not choose where an unconfined write-and-parse lands. The derivation is
   * authorization, so it is checked as well as computed — a derived socket the project could
   * have planted is refused, since the project chooses its own content and would then be
   * choosing the target. Every doubt falls back to the refusal, naming what stopped the shutdown.
   */
  def autoShutdownForeignServer(
    project: Path,
    portfileSocket: Path,
    env: String => Option[String],
    log: String => Unit,
    buildCaches: Seq[Path] = Seq.empty,
    userHome: Path = Path.of(System.getProperty("user.home")),
    shutdownDeadlineMillis: Long = 120_000,
    releaseDeadlineMillis: Long = 10_000,
  ): Either[String, Unit] =
    def refused(cause: String) = Left(s"${foreignServerRefusal(portfileSocket)} — $cause")
    val derived = sbtServerSocket(project, env, userHome)
    if reachableThroughBuildWritable(derived, project, buildCaches) then
      refused(
        s"the socket sbt derives for this project ($derived) is reachable through what a build " +
          s"writes, so $AutoShutdownForeignSbtOption does not apply",
      )
    else if !samePath(derived, portfileSocket) then
      refused(
        s"its socket is not the one sbt derives for this project ($derived), " +
          s"so $AutoShutdownForeignSbtOption does not apply",
      )
    else
      log(s"shutting down the foreign sbt server at $derived ($AutoShutdownForeignSbtOption)")
      SbtServerShutdown.shutdown(derived, shutdownDeadlineMillis) match
        case ServerAnswer.Unanswered(reason) => refused(s"the shutdown went unanswered: $reason")
        // Unreachable is the server gone between the liveness probe and now — the outcome sought.
        case ServerAnswer.ShutDown | ServerAnswer.Unreachable(_) =>
          val deadline = System.nanoTime + releaseDeadlineMillis * 1_000_000
          while livePortfileServer(project).isDefined && System.nanoTime < deadline do
            Thread.sleep(50)
          if livePortfileServer(project).isEmpty then Right(())
          else refused("the server answered the shutdown but still holds the portfile")

  private def samePath(a: Path, b: Path): Boolean =
    a == b || (try a.toRealPath() == b.toRealPath() catch case _: IOException => false)

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
    // The channel's validated WORKING_DIRECTORY: only the child's cwd, never a grant.
    workingDirectory: Option[Path] = None,
    // Launch-typed consent, never a request's: the channel forwards what the user launched with.
    autoShutdownForeignSbt: Boolean = false,
    // What `--env` named at launch, the same authority; the values are in this process's
    // environment under carrierName.
    forwarded: Vector[String] = Vector.empty,
  ): Int =
    val env: String => Option[String] = name => Option(System.getenv(name))
    val root = Path.of(s"/private/tmp/ko-agent-$uid")

    val prepared: Either[String, (Assembled, Vector[String])] =
      for
        project <-
          try Right(projectArg.toAbsolutePath.toRealPath())
          catch case ex: IOException => Left(s"$projectArg: ${ex.getMessage}")
        assembled <- assemble(project, tool, env)
        fileHosts <- readBuildRules(project, tool)
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
            livePortfileServer(project) match
              case None => Right(())
              case Some(socket) if autoShutdownForeignSbt =>
                // The profile's own persistent writable set, so a socket an earlier build planted
                // in a cache is no more a shutdown target than one planted in the project.
                autoShutdownForeignServer(
                  project, socket, env, log,
                  buildCaches = Seq(assembled.prereqs.coursierV1) ++ assembled.sbtGlobalGranted,
                )
              case Some(socket) =>
                Left(s"${foreignServerRefusal(socket)}, or relaunch with $AutoShutdownForeignSbtOption")
      yield (assembled, fileHosts)

    prepared match
      case Left(reason) =>
        log(s"refused: $reason")
        2
      case Right((assembled, fileHosts)) =>
        RunOnHostSession.publish(root, assembled.prereqs.project) match
          case Left(reason) =>
            log(s"refused: $reason")
            2
          case Right(session) =>
            // Also on a shutdown hook: SIGINT and SIGTERM end a JVM through its hooks, never by
            // unwinding to `finally` — and the registered groups sit outside the terminal's own,
            // so nothing but this would end them on a Ctrl-C. Synchronized, not merely once: the
            // JVM halts when its hooks return, so the losing caller must block until the whole
            // cleanup is done, never return early into a halting JVM.
            object teardown:
              private var done = false
              def apply(): Unit = synchronized:
                if !done then
                  done = true
                  RunOnHostSession
                    .endSession(root, session, RunOnHostSession.HostProcesses,
                      SbtServerShutdown.shutdown(_))
                    .collect { case kept: RunOnHostSession.Collected.ServerUnanswered => kept }
                    .foreach(kept => log(s"kept for the next start to retry: $kept"))
            val hook = Thread(() => teardown())
            Runtime.getRuntime.addShutdownHook(hook)
            val outcome =
              try
                sessionTmpFits(session.tmp) match
                  case Left(reason) => Left(reason.toString)
                  case Right(_) =>
                    runInSession(
                      session, assembled, fileHosts, buildArgs, runtime, workingDirectory, log,
                      forwarded.flatMap(name => env(carrierName(name)).map(name -> _)),
                    )
              finally
                teardown()
                try Runtime.getRuntime.removeShutdownHook(hook)
                catch case _: IllegalStateException => () // already shutting down; the hook ran
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
    workingDirectory: Option[Path],
    log: String => Unit,
    forwards: Vector[(String, String)],
  ): Either[String, Int] =
    assembled.sbtGlobalGranted.foreach: sbtGlobal =>
      val swept = cleanForeignTargetLinks(assembled.prereqs.project, Seq(assembled.prereqs.project, sbtGlobal))
      if swept.nonEmpty then
        log(s"removed ${swept.size} target/ links resolving outside this build's roots (first: ${swept.head})")
    for
      _ <- startProxy(session, fileHosts)
      port <- awaitProxyPort(session.directory.resolve("proxy.log"), deadlineMillis = 30_000)
      profile <- SeatbeltProfile.render(
        SeatbeltProfile.ProfileInputs(
          prereqs = assembled.prereqs,
          sessionTmp = session.tmp,
          sbtDistribution = assembled.sbtDistribution,
          sbtGlobal = assembled.sbtGlobalGranted,
          proxyPort = port,
          runtime = runtime,
        ),
      )
      exit <- runBuild(session, assembled, profile, port, buildArgs, workingDirectory, forwards)
    yield
      reportDenied(session.directory.resolve("proxy.log"), assembled.prereqs.tool, log)
      exit

  private def startProxy(session: Session, fileHosts: Vector[String]): Either[String, Process] =
    val command = RunOnHostSession
      .registeredSpawn(session.records.resolve("proxy"), selfInvocation("--serve-proxy-on-host"))
    val builder = ProcessBuilder(command*)
    // Closed like the build's: the proxy needs its own settings and, to leave through an upstream
    // proxy as the container's copy does, the one selected variable. Nothing else of the
    // launcher's environment has a reader here.
    builder.environment.clear()
    upstreamProxyVariable(name => Option(System.getenv(name))).foreach(builder.environment.put(_, _))
    builder.environment.put("EGRESS_PROFILE", "deny-unless-allowed")
    builder.environment.put("EGRESS_RULE", egressRuleText(fileHosts))
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
    workingDirectory: Option[Path],
    forwards: Vector[(String, String)],
  ): Either[String, Int] =
    val prereqs = assembled.prereqs
    val profileFile = session.directory.resolve("profile.sb")
    Files.writeString(profileFile, profile, UTF_8)

    val toolCommand = prereqs.tool match
      case Tool.Sbt =>
        Seq(prereqs.executable.toString, "--jvm-client", "-batch",
          "-java-home", prereqs.jdkHome.toString) ++ buildArgs
      case Tool.Mill =>
        Seq(prereqs.project.resolve("mill").toString, "--no-daemon") ++ buildArgs

    val record = session.records.resolve("client")
    val command = RunOnHostSession.registeredSpawn(
      record,
      Seq("/usr/bin/sandbox-exec", "-f", profileFile.toString) ++ toolCommand,
    )
    val builder = ProcessBuilder(command*)
    builder.directory(workingDirectory.getOrElse(prereqs.project).toFile)
    builder.inheritIO()
    builder.environment.clear()
    builder.environment.putAll(
      buildEnvironment(
        name => Option(System.getenv(name)), forwards, prereqs, assembled.sbtGlobal, assembled.millDownloads,
        session.tmp, proxyPort, System.getProperty("user.name"),
      ).asJava,
    )

    // The spawn publishes the build's exit status and then stays as the group's provable leader
    // (RunOnHostSession), so the answer is the exit file, never the spawn's own end.
    try RunOnHostSession.awaitExit(RunOnHostSession.exitRecord(record), builder.start())
    catch case ex: IOException => Left(s"starting the build: ${ex.getMessage}")

  val PassedThrough = Vector("HOME", "LANG", "LC_ALL")

  /** Absent even when forwarded: the wrapper resolved the version from the project alone and
    * granted that executable (RunOnHostPrereqs.millVersion), and either of these would make the
    * bootstrap select another. */
  val MillVersionOverrides = Set("MILL_VERSION", "DEFAULT_MILL_VERSION")

  /** The variable the host-served proxy leaves through, as the proxy itself selects it
    * (TransportHelper.UpstreamProxyVariables): uppercase first, an empty value as unset. */
  def upstreamProxyVariable(read: String => Option[String]): Option[(String, String)] =
    agentsandbox.egress.TransportHelper.UpstreamProxyVariables.iterator
      .flatMap(name => read(name).filter(_.nonEmpty).map(name -> _))
      .nextOption()

  /**
   * The build's whole environment, a closed set: `PassedThrough`, then what `--env` named, then
   * the wrapper's own settings, which win. doc/run-on-host.md, "The session", has the table of
   * what is in it; SECURITY.md, "Run on host", has why it is closed.
   */
  def buildEnvironment(
    host: String => Option[String],
    forwards: Vector[(String, String)],
    prereqs: BuildPrereqs,
    sbtGlobal: Path,
    millDownloads: Option[Path],
    sessionTmp: Path,
    proxyPort: Int,
    userName: String,
  ): Map[String, String] =
    val passed = PassedThrough.flatMap(name => host(name).map(name -> _)).toMap
    // The settings must reach the JVMs the build forks — a forked test or `run` — and such a JVM
    // inherits the environment and nothing else: its options come from the build definition, so
    // SBT_OPTS and JAVA_OPTS, which the sbt script and the mill executable do read, would confine
    // the tool's own JVMs alone. The cost is the "Picked up JAVA_TOOL_OPTIONS" line every JVM
    // started this way prints, which HotSpot has no flag to quiet; the shim drops it from the relay.
    val javaToolOptions = (Seq(
      s"-Djava.io.tmpdir=$sessionTmp",
      s"-Djava.util.prefs.userRoot=$sessionTmp",
      s"-Dsbt.global.base=$sbtGlobal",
      "-Dhttps.proxyHost=127.0.0.1", s"-Dhttps.proxyPort=$proxyPort",
      "-Dhttp.proxyHost=127.0.0.1", s"-Dhttp.proxyPort=$proxyPort",
      // Without this a JVM reaches 127.0.0.1 through a dual-stack AF_INET6 socket as v4-mapped
      // ::ffff:127.0.0.1, which the profile's "localhost" class does not cover: the connect to
      // the proxy dies with EPERM (measured, src/probe/jvm-proxy-rule.sh).
      "-Djava.net.preferIPv4Stack=true",
    )).mkString(" ")
    val own = Map(
      // The JDK, then the system directories the runtime authority lets a build execute from
      // (runtime-authority.txt) — never the host's PATH: an entry of it the confinement refuses,
      // a version manager's shim or a Homebrew tool ahead of the system one, fails the lookup
      // with EPERM at that entry, and the shell tries no further, so a build the system PATH
      // serves would break on the shell's.
      "PATH" -> s"${prereqs.jdkHome.resolve("bin")}:/usr/bin:/bin:/usr/sbin:/sbin",
      "JAVA_HOME" -> prereqs.jdkHome.toString,
      "JAVA_TOOL_OPTIONS" -> javaToolOptions,
      "TMPDIR" -> sessionTmp.toString,
      "XDG_RUNTIME_DIR" -> sessionTmp.toString,
      "SBT_GLOBAL_SERVER_DIR" -> sessionTmp.toString,
      "COURSIER_CACHE" -> prereqs.coursierV1.toString,
      "USER" -> userName,
      "LOGNAME" -> userName,
    ) ++
      // Set for every tool, not mill alone: sbt ignores it, and one unconditional setting is
      // simpler than a conditional. Mill's bootstrap otherwise derives the folder from HOME and
      // XDG_CACHE_HOME, and this pins it to the folder holding the executable the build is granted.
      millDownloads.map(dir => "MILL_FINAL_DOWNLOAD_FOLDER" -> dir.toString) ++
      buildProxyVariables(proxyPort)
    passed ++ (forwards.toMap -- MillVersionOverrides) ++ own

  /**
   * The proxy variables the build's environment gets, both spellings, as the sandbox container
   * gets its own: the build's proxy for the tools that read the environment rather than the JVM
   * properties, loopback exempt so a test server on it is reached directly. The rest of the
   * family — ALL_PROXY, FTP_PROXY — is simply absent, as the launcher's own HTTPS_PROXY is: that
   * one names an upstream proxy the confinement refuses, with a credential the build has no
   * business reading.
   */
  def buildProxyVariables(proxyPort: Int): Map[String, String] =
    val proxy = s"http://127.0.0.1:$proxyPort"
    Map(
      "HTTPS_PROXY" -> proxy, "https_proxy" -> proxy, "HTTP_PROXY" -> proxy, "http_proxy" -> proxy,
      "NO_PROXY" -> "localhost,127.0.0.1", "no_proxy" -> "localhost,127.0.0.1",
    )

  /**
   * The cost of switching where a build runs, paid before each confined build. sbt 2 leaves `target/` outputs as
   * symlinks into its global base's content-addressed store, so a tree the user's own sbt built
   * links into a store this profile cannot reach — and zinc treats the unreadable state as an
   * error, not a cold start (measured: `previousCompile` fails on `inc_compile_3.zip`). Every
   * symlink under a `target/` directory that does not resolve inside a granted root — the
   * dangling included — is removed before the build; the artifacts it named still exist in the
   * store of the sbt that made them, which relinks on its own next run. The roots are compared
   * resolved, as the links are: a root reached through a symlink, macOS's `/var`, would
   * otherwise match nothing and the sweep would take every link.
   */
  def cleanForeignTargetLinks(project: Path, granted: Seq[Path]): Vector[Path] =
    val roots = granted.flatMap(root => try Some(root.toRealPath()) catch case _: IOException => None)
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
              try roots.exists(entry.toRealPath().startsWith)
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

  /** The denied-host report, once per refused host, after the build — never an automatic addition. */
  private def reportDenied(proxyLog: Path, tool: Tool, log: String => Unit): Unit =
    val hosts = deniedHosts(proxyLog)
    if hosts.nonEmpty then
      val toolName = tool.toString.toLowerCase(java.util.Locale.ROOT)
      log((("Build requested network access to:" +: hosts.map(host => s"  $host")) :+
        ("Not permitted by the Scala build sandbox. If the build should reach it, add an" +
          s" `$BuildRuleForm` line to .ko-agent-sandbox/host-command/$toolName/egress/rule."))
        .mkString("\n"))
