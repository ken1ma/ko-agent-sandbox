// What the run-on-host checks (src/test/run-on-host/*Check.scala) share. This is not a program of its own. Each check's
// driver pulls it in with `//> using file`, together with HostDriver.scala and RunOnHostIdle.scala, which this file
// calls. sbt compiles this file with the tests, which keeps it compiling without a driver run.
//
// It holds:
//
// - the options, the checkout's fixtures and the copies on older releases;
// - the machine block, the preflight and the setup that emits the profiles (EmitRunOnHostProfile's checks form);
// - the command's environment, and running a command under a profile;
// - finding the servers and daemons that the rows start, and ending them;
// - the rows' report and the run's cleanup.
//
// Each check keeps what is its own: its rows and what only its rows make.

package agentsandbox.launcher

import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path}
import java.util.Properties
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

import scala.jdk.CollectionConverters.*
import scala.util.Using

import HostDriver.*

object RunOnHostChecks:

  val ChecksPath = "src/test/run-on-host"
  val SystemPathsFile = "src/main/resources/agentsandbox/SeatbeltProfile.SystemPaths.txt"

  enum Program:
    case Sbt, Mill, Gradle, Mvn
    def name: String = toString.toLowerCase

  object Program:
    def named(name: String): Option[Program] = values.find(_.name == name)

  /** The last Mill with a daemon (RunOnHostPrereqs.MillDaemonReadsLauncherSince). The mill rows run on the fixture's
    * Mill and again on a copy pinned to this release. */
  val DaemonMill = "1.1.10"

  /** The last Gradle 8 release (run-on-host-evidence.md, "Gradle releases"). The gradle rows run on the fixture's
    * Gradle and again on a copy pinned to this release. */
  val OlderGradle = "8.14.6"

  /** A check's options: the programs whose rows a run selects, `--program sbt|mill|gradle|mvn|all`, all by default;
    * and how many groups of rows run at once, `--jobs N`, the check's own default when absent. */
  case class Options(programs: Set[Program], jobs: Option[Int])

  def parseOptions(args: Seq[String], usage: String): Either[String, Options] =
    def loop(rest: Seq[String], options: Options): Either[String, Options] = rest match
      case Seq() => Right(options)
      case Seq("--program", "all", more*) => loop(more, options.copy(programs = Program.values.toSet))
      case Seq("--program", name, more*) =>
        Program.named(name).toRight(s"unknown program $name\n$usage").flatMap(program =>
          loop(more, options.copy(programs = Set(program))))
      case Seq("--jobs", count, more*) =>
        count.toIntOption.filter(_ > 0).toRight(s"--jobs takes a positive number: $count\n$usage").flatMap(jobs =>
          loop(more, options.copy(jobs = Some(jobs))))
      case _ => Left(usage)
    loop(args, Options(Program.values.toSet, None))

  /** The checkout's fixtures, and the copies on older releases at fixed paths: the run-on-host cache is kept per
    * workspace path, so a new path in each run would leave a cache behind each time. */
  case class Checkout(root: Path):
    val fixtures: Path = root / ChecksPath / "fixtures"
    val sbtFixture: Path = fixtures / "sbt"
    val millFixture: Path = fixtures / "mill"
    val gradleFixture: Path = fixtures / "gradle"
    val mvnFixture: Path = fixtures / "mvn"
    /** The unlisted-host rows' build: its resolution must reach a host that the proxy refuses. */
    val denyFixture: Path = fixtures / "deny"
    /** The inter-project row's build: resolving a dependsOn edge enters Ivy, whose lock file lives in the Ivy home,
      * and this repository has no such edge. */
    val ivyFixture: Path = fixtures / "ivy"
    val millCopy: Path = root / "target" / s"run-on-host-mill-$DaemonMill"
    val gradleCopy: Path = root / "target" / s"run-on-host-gradle-$OlderGradle"
    /** The pinned-JVM rows' build for a mill target, a copy of that target's workspace. */
    def pinnedMill(id: String): Path = root / "target" / s"run-on-host-pinned-$id"
    val systemPaths: Path = root / SystemPathsFile

  /** One build whose profile a check emits. The id names the profile's files and the rows' sections. */
  case class Target(id: String, program: Program, workspace: Path)

  /** The targets of the selected programs: the sbt rows build this repository, and each other program builds its
    * fixture, then the copy on the older release. A mill, Gradle or Maven build of this repository would be a second
    * build definition rather than a measurement. */
  def targetsOf(checkout: Checkout, programs: Set[Program]): Vector[Target] =
    Vector(
      Option.when(programs(Program.Sbt))(Target("sbt", Program.Sbt, checkout.root)),
      Option.when(programs(Program.Mill))(Target("mill", Program.Mill, checkout.millFixture)),
      Option.when(programs(Program.Mill))(Target(s"mill-$DaemonMill", Program.Mill, checkout.millCopy)),
      Option.when(programs(Program.Gradle))(Target("gradle", Program.Gradle, checkout.gradleFixture)),
      Option.when(programs(Program.Gradle))(Target(s"gradle-$OlderGradle", Program.Gradle, checkout.gradleCopy)),
      Option.when(programs(Program.Mvn))(Target("mvn", Program.Mvn, checkout.mvnFixture)),
    ).flatten

  /** An emitted profile, with the values of EmitRunOnHostProfile's checks form. */
  case class Emitted(target: Target, profile: Path, values: Properties):
    private def path(key: String): Path = Path.of(values.getProperty(key))
    def sessionTmp: Path = path("session.tmp")
    /** The run-on-host cache's Coursier v1, `<cache root>/run-on-host/<workspace id>/coursier/v1`. */
    def coursierV1: Path = path("run-on-host.cache")
    /** This workspace's run-on-host cache directory, `<cache root>/run-on-host/<workspace id>`. */
    def runOnHostCache: Path = coursierV1.getParent.getParent
    def executable: Path = path("executable")
    def sbtGlobal: Path = path("sbt.global.base")
    def ivyHome: Path = path("ivy.home")
    def gradleUserHome: Path = path("gradle.user.home")
    def m2Repository: Path = path("m2.repository")

  /** The user's own paths that the rows name, after every environment override. */
  case class HostPaths(
    home: Path, javaHome: Path, stateRoot: Path, coursier: Path, sbtExecutable: Path, millDownloads: Path,
  ):
    def userV1: Path = coursier / "v1"
    def userArc: Path = coursier / "arc"

  object HostPaths:
    def of(env: String => Option[String]): Either[String, HostPaths] =
      for
        home <- env("HOME").map(Path.of(_)).toRight("HOME is not set")
        javaHome <- env("JAVA_HOME").map(Path.of(_)).filter(home => Files.isExecutable(home / "bin" / "java"))
          .toRight("JAVA_HOME does not name a JDK")
      yield
        val cacheHome = env("XDG_CACHE_HOME").map(Path.of(_)).getOrElse(home / ".cache")
        HostPaths(
          home = home,
          javaHome = javaHome,
          stateRoot = env("XDG_STATE_HOME").map(Path.of(_)).getOrElse(home / ".local" / "state") / "ko-agent-sandbox",
          coursier = env("COURSIER_CACHE").map(Path.of(_)).getOrElse(home / "Library" / "Caches" / "Coursier"),
          sbtExecutable = env("COURSIER_BIN_DIR").map(Path.of(_))
            .getOrElse(home / "Library" / "Application Support" / "Coursier" / "bin") / "sbt",
          // As the bootstrap derives it (RunOnHostPrereqs.millDownloadDir); MILL_USER_CACHE_DIR is not an input.
          millDownloads = env("MILL_FINAL_DOWNLOAD_FOLDER").map(Path.of(_)).getOrElse(cacheHome / "mill" / "download"),
        )

  /** A path as one word of a /bin/sh command, whatever it holds. */
  def shellQuoted(text: String): String = "'" + text.replace("'", "'\\''") + "'"

  def shellQuoted(path: Path): String = shellQuoted(path.toString)

  /** The Mill version as the supervisor reads it (RunOnHostPrereqs.millVersion): the copy's .mill-version, or else
    * the bootstrap's default, without the launcher suffix. */
  def millVersionOf(workspace: Path): Option[String] =
    val pinned = workspace / ".mill-version"
    val version =
      if Files.isRegularFile(pinned) then Files.readAllLines(pinned).asScala.headOption.map(_.trim)
      else """DEFAULT_MILL_VERSION="([^"]+)"""".r.findFirstMatchIn(Files.readString(workspace / "mill")).map(_.group(1))
    version.map(_.stripSuffix("-jvm"))

  /** Whether that Mill runs its build without a daemon: 1.2 or later (RunOnHostPrereqs.millRunsWithoutDaemon). */
  def millWithoutDaemon(version: String): Boolean =
    version.split("[.]").toSeq.take(2).map(_.takeWhile(_.isDigit).toIntOption) match
      case Seq(Some(major), Some(minor)) => major > 1 || major == 1 && minor >= 2
      case _ => false

  def wrapperRelease(properties: Path, artifact: String): Option[String] =
    raw"(?m)^distributionUrl=.*/$artifact-(.*)-bin\.zip$$".r.findFirstMatchIn(Files.readString(properties))
      .map(_.group(1))

  /** The run's directory, `out-macos/<check>/` beside the drivers, emptied first. The rows grant the workspace, so
    * a script the rows run from there runs under the profile. */
  def checkOut(root: Path, check: String): Path =
    val out = root / ChecksPath / "out-macos" / check
    removeTree(out)
    Files.createDirectories(out)

  def removeTree(path: Path): Unit =
    if Files.exists(path, java.nio.file.LinkOption.NOFOLLOW_LINKS) then
      if Files.isDirectory(path, java.nio.file.LinkOption.NOFOLLOW_LINKS) then
        Using.resource(Files.list(path))(_.iterator.asScala.toVector).foreach(removeTree)
      Files.delete(path)

  /** The cleanup steps of a run, run once in the reverse of their registration, whether the run ends normally, by an
    * exception or by a signal. A failing step does not stop the later ones. The tally ends the transcript. */
  class Cleanups(transcript: Transcript) extends AutoCloseable:
    private val closed = AtomicBoolean(false)
    private var steps = List.empty[(String, () => Unit)]
    def add(name: String)(step: => Unit): Unit = synchronized { steps = (name, () => step) :: steps }
    def close(): Unit = if closed.compareAndSet(false, true) then
      synchronized(steps).foreach: (name, step) =>
        try step()
        catch case ex: Exception => transcript.log(s"cleanup: $name failed: ${ex.getMessage}")
      transcript.log("")
      transcript.log(s"passed=${transcript.passed} failed=${transcript.failed} skipped=${transcript.skipped} " +
        s"transcript=${transcript.path}")

  /**
   * A Unix-domain listener that counts the connections it accepts and the bytes each sends, for a row that must show
   * that nothing spoke to a planted socket.
   *
   *   - Each connection is read for up to 5 s without blocking: a Unix-domain channel has no Socket to set a read
   *     timeout on (SocketChannel.socket throws UnsupportedOperationException for it).
   *   - Any failure but the close at the end is kept, so that it fails the row instead of reading as "no bytes".
   *   - `acceptDelayMillis` holds each accept back, for a test of `observed`.
   */
  class CountingListener(socket: Path, acceptDelayMillis: Long = 0) extends AutoCloseable:
    private val server = java.nio.channels.ServerSocketChannel.open(java.net.StandardProtocolFamily.UNIX)
    server.bind(java.net.UnixDomainSocketAddress.of(socket))
    private val accepted = java.util.concurrent.atomic.AtomicInteger()
    private val bytesRead = java.util.concurrent.atomic.AtomicInteger()
    private val finished = java.util.concurrent.atomic.AtomicInteger()
    private val failed = java.util.concurrent.atomic.AtomicReference[Throwable]()
    def connects: Int = accepted.get
    def bytes: Int = bytesRead.get
    def failure: Option[Throwable] = Option(failed.get)
    private val acceptor = Thread(() =>
      try
        while true do
          if acceptDelayMillis > 0 then Thread.sleep(acceptDelayMillis)
          val client = server.accept()
          accepted.incrementAndGet()
          try
            client.configureBlocking(false)
            val buffer = java.nio.ByteBuffer.allocate(4096)
            val deadline = System.nanoTime + 5_000_000_000L
            var open = true
            while open && System.nanoTime < deadline do
              buffer.clear()
              val count = client.read(buffer)
              if count < 0 then open = false
              else if count > 0 then bytesRead.addAndGet(count)
              else Thread.sleep(50)
          finally
            client.close()
            finished.incrementAndGet()
      catch
        case _: java.nio.channels.ClosedChannelException => ()
        case ex: Throwable => failed.set(ex))
    acceptor.setDaemon(true)
    acceptor.start()

    /** Whether at least `expected` connections arrived, each read to its end, within 10 s. */
    def observed(expected: Int): Boolean =
      within(10, intervalMillis = 100)(accepted.get >= expected && finished.get == accepted.get)

    /** Forgets what it counted, once `observed` says that no connection is being read. */
    def reset(): Unit =
      accepted.set(0)
      bytesRead.set(0)
      finished.set(0)

    def close(): Unit = server.close()

  /** A command under a profile: whether it succeeded, whether it was killed at the timeout, and its first stderr
    * line. */
  case class ProfileOutcome(ok: Boolean, timedOut: Boolean, firstError: String)

  /** A command started in the background, whose output goes to a file. */
  case class Started(process: Process, log: Path):
    def pid: Long = process.pid
    def output: String = if Files.exists(log) then Files.readString(log) else ""

  /**
   * One check's run: its transcript, its cleanup and the operations its rows share.
   *
   *   - Every server, daemon and proxy that a row starts is ended at exit, unless a live runner claims its working
   *     directory (RunOnHostIdle.endUnclaimed).
   *   - A row reports PASS, FAIL or SKIP with what it observed. INFO is a measurement with no expected answer.
   */
  class CheckRun(val transcript: Transcript, val checkout: Checkout, val out: Path, val programs: Set[Program],
      val host: HostPaths, val cleanup: Cleanups):
    def this(transcript: Transcript, checkout: Checkout, out: Path, programs: Set[Program], host: HostPaths) =
      this(transcript, checkout, out, programs, host, Cleanups(transcript))

    /** This run, with its rows reported to `part` (Transcript.part), for rows measured on a thread of their own. */
    def reportingTo(part: Transcript): CheckRun = CheckRun(part, checkout, out, programs, host, cleanup)

    /**
     * Runs each group's rows on a thread of its own, at most `jobs` at once, each group reporting to `<name>.log`
     * (Transcript.part).
     *
     *   - It returns only once every group has ended, so that no cleanup runs under a group still at work.
     *   - A group that throws reports a FAIL row of its own, and the other groups go on.
     */
    def inParallel(groups: Seq[(String, CheckRun => Unit)], jobs: Int): Unit =
      val pool = java.util.concurrent.Executors.newFixedThreadPool(jobs.max(1))
      try
        val tasks = groups.map: (name, rows) =>
          transcript.log(s"the $name group's rows: ${out / s"$name.log"}")
          val part = reportingTo(transcript.part(out / s"$name.log", name))
          val task: java.util.concurrent.Callable[Unit] = () =>
            try rows(part)
            catch case ex: Throwable => part.fail(s"the $name group", s"it failed: $ex")
          name -> task
        val futures = pool.invokeAll(tasks.map(_._2).asJava).asScala
        // A task's own catch reports what it throws; a future still holds what escaped it, such as a cancellation.
        tasks.map(_._1).zip(futures).foreach: (name, future) =>
          try future.get()
          catch case ex: Exception => fail(s"the $name group", s"it ended abnormally: $ex")
      finally pool.shutdown()

    val uid: Int = com.sun.security.auth.module.UnixSystem().getUid.toInt
    /** The supervisor's root, where every command's session and every runner's session lives. */
    val commandRoot: Path = RunOnHostIdle.supervisorRoot(uid)
    def want(program: Program): Boolean = programs(program)

    // --- The report --------------------------------------------------------------------------------------------

    private def described(label: String, detail: String): String =
      if detail.isEmpty then label else s"$label: ${detail.linesIterator.nextOption().getOrElse("").take(110)}"
    def pass(label: String, detail: String = ""): Unit = transcript.pass(described(label, detail))
    def fail(label: String, detail: String = ""): Unit = transcript.fail(described(label, detail))
    def skip(label: String, reason: String): Unit = transcript.skip(described(label, reason))
    def info(label: String, detail: String): Unit = transcript.info(described(label, detail))
    def check(label: String, ok: Boolean, detail: String = ""): Unit = if ok then pass(label, detail)
      else fail(label, detail)

    // --- The machine and the preflight -------------------------------------------------------------------------

    /** Prints the machine before any row, because a run with no machine recorded is not evidence for the next
      * release. Returns whether the workspace volume folds case, which the .GIT rows need. */
    def machine(): Boolean =
      transcript.step("machine")
      def line(text: String): Unit = transcript.log("  " + text)
      line(s"macOS ${command("sw_vers", "-productVersion").trim}, ${command("uname", "-m").trim}")
      line(s"${command((host.javaHome / "bin" / "java").toString, "-version").linesIterator.nextOption()
          .getOrElse("")} (${host.javaHome})")
      val sbtVersion = "(?m)^sbt.version=(.*)$".r.findFirstMatchIn(Files.readString(checkout.root / "project" /
        "build.properties")).map(_.group(1)).getOrElse("unread")
      line(s"sbt $sbtVersion")
      if want(Program.Mill) then
        for workspace <- Seq(checkout.millFixture, checkout.millCopy) if Files.exists(workspace / "mill") do
          val version = millVersionOf(workspace).getOrElse("unread")
          line(s"mill $version${if millWithoutDaemon(version) then ", without a daemon" else ""}")
      if want(Program.Gradle) then
        for workspace <- Seq(checkout.gradleFixture, checkout.gradleCopy)
            if Files.exists(workspace / "gradle" / "wrapper" / "gradle-wrapper.properties") do
          line(s"gradle ${wrapperRelease(workspace / "gradle" / "wrapper" / "gradle-wrapper.properties", "gradle")
              .getOrElse("unread")}")
      if want(Program.Mvn) then
        line(s"maven ${wrapperRelease(checkout.mvnFixture / ".mvn" / "wrapper" / "maven-wrapper.properties",
            "apache-maven").getOrElse("unread")}")
      val podman = command("podman", "--version").trim
      if podman.isEmpty then line("podman: absent")
      else line(s"$podman, machine provider: ${command("podman", "machine", "info", "--format",
          "{{.Host.VMType}}").trim}")
      val probe = Files.createTempDirectory(out, "case")
      Files.writeString(probe / "a", "")
      val folding = Files.exists(probe / "A")
      removeTree(probe)
      line(s"workspace filesystem: ${if folding then "case-insensitive" else "case-sensitive"}")
      folding

    /** The output of a host command that the machine block or a row reads, empty when it cannot run. */
    def command(arguments: String*): String =
      try HostDriver.host(transcript, arguments, record = false, timeoutSeconds = Some(60)).text
      catch case _: java.io.IOException => ""

    /** Refuses a run that a live runner, a server or a daemon of these workspaces would disturb. The emitter starts an
      * unconfined sbt in this checkout, and one sbt server runs per build directory (SECURITY.md, "Run on host"). */
    def preflight(workspaces: Seq[Path]): Either[Int, Unit] =
      val claimed = RunOnHostIdle.requireIdle(commandRoot, workspaces)
      val servers = workspaces.flatMap(sbtServers)
      val daemons = workspaces.flatMap(millDaemons)
      val gradles = launchGradleDaemons
      for
        _ <- claimed.left.map(refusal => { transcript.log(refusal); 2 })
        _ <- transcript.refuse(servers.isEmpty,
          s"an sbt server is already running for a workspace of this run (pid ${servers.mkString(" ")}): run " +
            "'sbt shutdown' in its build directory, or kill it if its portfile is gone")
        _ <- transcript.refuse(daemons.isEmpty,
          s"a mill daemon is already running in a fixture (pid ${daemons.mkString(" ")}): run './mill shutdown' " +
            "there, or kill it")
        _ <- transcript.refuse(gradles.isEmpty,
          s"a gradle daemon of a launch is running under $commandRoot (pid ${gradles.mkString(" ")}): end that " +
            "launch, or kill it")
      yield ()

    // --- The copies on older releases --------------------------------------------------------------------------

    /** Makes the copies of the selected programs' fixtures on the older releases, and provisions the Gradle copy's
      * distribution, which `./gradlew --version` unpacks when it is missing. The cleanup removes each copy, because
      * the next launch's provisioning would meet a build directory left under the workspace. */
    def makeOlderCopies(): Either[Int, Unit] =
      if want(Program.Mill) then
        cleanup.add("remove the mill copy")(removeTree(checkout.millCopy))
        copyFixture(checkout.millFixture, checkout.millCopy, Seq("mill", "build.mill.yaml", "src", "test"))
        Files.writeString(checkout.millCopy / ".mill-version", DaemonMill + "\n")
      if !want(Program.Gradle) then Right(())
      else
        cleanup.add("remove the gradle copy")(removeTree(checkout.gradleCopy))
        copyFixture(checkout.gradleFixture, checkout.gradleCopy,
          Seq("gradlew", "build.gradle", "settings.gradle", "gradle", "src"))
        val properties = checkout.gradleCopy / "gradle" / "wrapper" / "gradle-wrapper.properties"
        Files.writeString(properties,
          Files.readString(properties).replaceAll("(?m)/gradle-[^/]*-bin\\.zip$", s"/gradle-$OlderGradle-bin.zip"))
        val provisioned = HostDriver.host(transcript, Seq("./gradlew", "--version"), cwd = checkout.gradleCopy,
          record = false, timeoutSeconds = Some(900))
        transcript.refuse(provisioned.ok,
          s"./gradlew --version failed in ${checkout.gradleCopy}:\n${provisioned.text.linesIterator.toSeq
              .takeRight(20).mkString("\n")}")

    private def copyFixture(from: Path, to: Path, entries: Seq[String]): Unit =
      removeTree(to)
      Files.createDirectories(to)
      entries.foreach(entry => copyTree(from / entry, to / entry))

    def copyTree(from: Path, to: Path): Unit =
      if Files.isDirectory(from) then
        Files.createDirectories(to)
        Using.resource(Files.list(from))(_.iterator.asScala.toVector).foreach(child =>
          copyTree(child, to / child.getFileName.toString))
      else Files.copy(from, to, java.nio.file.StandardCopyOption.COPY_ATTRIBUTES)

    // --- The setup ----------------------------------------------------------------------------------------------

    /**
     * Emits every target's profile, the classpath and the proxy's profile in one sbt run, and ends that run's sbt
     * server before any row runs: a supervisor would find the server holding this project's portfile and refuse.
     *
     *   - The emitter first checks every target for a missing host run, and the run refuses with every one it found.
     *   - The emitter writes each profile's command temporary directory under its own root; the cleanup removes it.
     *   - sbt's command parser reads the arguments, where a `"` would end a quoted path.
     */
    def setup(targets: Vector[Target]): Either[Int, Map[String, Emitted]] =
      val emitted = out / "emitted"
      val paths = (emitted +: checkout.root +: targets.map(_.workspace)).map(_.toString)
      val specs = targets.map(target => s"${target.id},${target.program.name},${target.workspace}")
      val runMain = (Seq("Test/runMain agentsandbox.launcher.EmitRunOnHostProfile --checks", s"\"$emitted\"",
        SystemPathsFile) ++ specs.map(spec => s"\"$spec\"")).mkString(" ")
      for
        _ <- transcript.refuse(!paths.exists(_.contains('"')),
          "a path of this run contains a double quote, which sbt's command parser cannot take: " +
            paths.mkString(", "))
        _ = transcript.step("setup")
        _ = transcript.log(s"emitting the profiles of ${targets.map(_.id).mkString(", ")}")
        result = HostDriver.host(transcript, Seq("sbt", "-batch", runMain), timeoutSeconds = Some(1800))
        _ = cleanup.add("end the emitter's sbt server")(endSbtServer())
        _ = targets.foreach: target =>
          cleanup.add(s"remove ${target.id}'s command temporary directory"):
            emittedOf(emitted, target).foreach(found => removeTree(found.sessionTmp.getParent))
        missing = result.text.linesIterator.filter(_.startsWith("missing: ")).toVector
        _ <- transcript.refuse(missing.isEmpty,
          ("Run each missing host run once on the host, then rerun this check:" +: missing.map("  " + _))
            .mkString("\n"))
        _ <- transcript.refuse(result.ok,
          s"the emitter failed:\n${result.text.linesIterator.toSeq.takeRight(20).mkString("\n")}")
        _ = endSbtServer()
        _ = within(60)(sbtServers(checkout.root).isEmpty)
        _ <- preflight(Seq(checkout.root) ++ targets.map(_.workspace))
      yield targets.flatMap(target => emittedOf(emitted, target).map(target.id -> _)).toMap

    private def emittedOf(dir: Path, target: Target): Option[Emitted] =
      val file = dir / s"${target.id}.properties"
      Option.when(Files.isRegularFile(file)):
        val values = Properties()
        Using.resource(Files.newBufferedReader(file))(values.load)
        Emitted(target, dir / s"${target.id}.sb", values)

    /** The classpath that the setup copied, which the supervisor and the runner run on. */
    def classpath: String = Files.readString(out / "emitted" / "classpath.txt").trim

    def proxyProfile: Path = out / "emitted" / "proxy.sb"

    private def endSbtServer(): Unit =
      HostDriver.host(transcript, Seq("sbt", "--jvm-client", "-batch", "shutdown"), record = false,
        timeoutSeconds = Some(120))

    // --- Running under a profile --------------------------------------------------------------------------------

    /**
     * The command's environment as the supervisor builds it (RunOnHostSandbox.commandEnvironment;
     * run-on-host-internals.md, "The command's lifetime and environment", has the table), for a command that a row
     * runs under an emitted profile without a supervisor.
     *
     *   - The set is closed: a row that passes on a variable that production withholds would prove nothing.
     *   - PATH starts with the JDK, because sbt's client starts the server by rerunning the sbt script, which takes
     *     `java` from PATH, as mill's `mill-jvm-version: system` does. /usr/bin/java is the stub that the profile
     *     denies.
     *   - The JVM settings travel in _JAVA_OPTIONS, which the server that sbt's client forks inherits. The same -D
     *     flags on the command line reach the client alone.
     *   - XDG_RUNTIME_DIR and SBT_GLOBAL_SERVER_DIR keep sbt's sockets inside the command's temporary directory.
     *   - It deviates from the supervisor's in two ways: no proxy runs behind it, and clients and servers share one
     *     temporary directory.
     */
    def commandEnvironment(emitted: Emitted): Map[String, String] =
      val tmp = emitted.sessionTmp.toString
      val account = sys.props("user.name")
      val javaOptions = Seq(
        s"-Djava.io.tmpdir=\"$tmp\"", s"-Djava.util.prefs.userRoot=\"$tmp\"",
        s"-Dsbt.global.base=\"${emitted.sbtGlobal}\"", s"-Dsbt.ivy.home=\"${emitted.ivyHome}\"",
        s"-Dmaven.repo.local=\"${emitted.m2Repository}\"", "-Daether.connector.http.useSystemProperties=true",
        "-Djava.net.preferIPv4Stack=true",
      ).mkString(" ")
      Map(
        "PATH" -> s"${host.javaHome}/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "JAVA_HOME" -> host.javaHome.toString,
        "HOME" -> host.home.toString,
        "TMPDIR" -> tmp,
        "XDG_RUNTIME_DIR" -> tmp,
        "SBT_GLOBAL_SERVER_DIR" -> tmp,
        "COURSIER_CACHE" -> emitted.coursierV1.toString,
        "USER" -> account,
        "LOGNAME" -> account,
        "MILL_FINAL_DOWNLOAD_FOLDER" -> host.millDownloads.toString,
        "GRADLE_USER_HOME" -> emitted.gradleUserHome.toString,
        "_JAVA_OPTIONS" -> javaOptions,
        // RunOnHostSandbox.HostCommandVariable, spelled out: the Scala CLI drivers that pull this file in compile
        // without RunOnHostSandbox.
        "KO_AGENT_SANDBOX_RUN_ON_HOST_COMMAND" -> "1",
      ) ++ Seq("LANG", "LC_ALL").flatMap(name => sys.env.get(name).map(name -> _))

    /** The command under the profile, in the command's environment. A hang is a FAIL, not a stalled run: a client
      * whose server never came up waits forever. */
    def sandboxed(emitted: Emitted, command: Seq[String], cwd: Path, timeoutSeconds: Int = 600): Output =
      HostDriver.host(transcript, Seq("/usr/bin/sandbox-exec", "-f", emitted.profile.toString) ++ command, cwd = cwd,
        environment = commandEnvironment(emitted), inheritEnvironment = false, timeoutSeconds = Some(timeoutSeconds))

    /** A /bin/sh command under the profile, as a build's script would run it: whether it succeeded, whether it timed
      * out, and the first line it wrote on stderr, which names a denial. Its stdout is discarded. */
    def underProfile(profile: Path, shell: String, cwd: Path = checkout.root): ProfileOutcome =
      val err = Files.createTempFile(out, "row", ".err")
      val process = ProcessBuilder("/usr/bin/sandbox-exec", "-f", profile.toString, "/bin/sh", "-c", shell)
        .directory(cwd.toFile).redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(err.toFile).start()
      process.getOutputStream.close()
      val finished = process.waitFor(120, TimeUnit.SECONDS)
      if !finished then process.destroyForcibly().waitFor()
      val firstError = Files.readAllLines(err, UTF_8).asScala.headOption.getOrElse("")
      Files.delete(err)
      ProfileOutcome(finished && process.exitValue == 0, !finished, firstError)

    def expectDenied(profile: Path, label: String, shell: String, cwd: Path = checkout.root): Unit =
      reportDenied(label, underProfile(profile, shell, cwd))

    def expectAllowed(profile: Path, label: String, shell: String, cwd: Path = checkout.root): Unit =
      reportAllowed(label, underProfile(profile, shell, cwd))

    /** A timeout fails the row: a command that the profile wrongly allows can hang, and a hang proves no denial. */
    def reportDenied(label: String, outcome: ProfileOutcome): Unit =
      if outcome.timedOut then fail(label, "timed out after 120 s")
      else if outcome.ok then fail(label, "allowed")
      else pass(label, s"denied: ${outcome.firstError}")

    def reportAllowed(label: String, outcome: ProfileOutcome): Unit =
      check(label, outcome.ok && !outcome.timedOut, if outcome.timedOut then "timed out after 120 s"
        else outcome.firstError)

    /** Whether the path exists. A path that a negative row names must exist on the host, or "denied" and "absent"
      * read the same; the row is skipped otherwise. */
    def presentOrSkip(label: String, path: Path): Boolean =
      val present = Files.exists(path, java.nio.file.LinkOption.NOFOLLOW_LINKS)
      if !present then skip(label, s"$path does not exist on this host")
      present

    /** A command started in the background with its output in a file under the run's directory. */
    def start(name: String, command: Seq[String], cwd: Path = checkout.root,
        environment: Map[String, String] = Map.empty): Started =
      val log = out / s"$name.log"
      val builder = ProcessBuilder(command*).directory(cwd.toFile).redirectErrorStream(true)
        .redirectOutput(log.toFile)
      environment.foreach(builder.environment.put(_, _))
      val process = builder.start()
      process.getOutputStream.close()
      Started(process, log)

    // --- The supervisor -------------------------------------------------------------------------------------------

    private def javaCommand: String = (host.javaHome / "bin" / "java").toString

    /** What the command prints on stdout alone: a JVM prints `Picked up _JAVA_OPTIONS` on stderr. */
    def stdoutOf(command: String*): String =
      val process = ProcessBuilder(command*).redirectError(ProcessBuilder.Redirect.DISCARD).start()
      process.getOutputStream.close()
      val text = String(process.getInputStream.readAllBytes(), UTF_8)
      process.waitFor()
      text

    /** The perl lock holder that the runner runs a command under (RunOnHostSession.lockedSpawn). */
    lazy val lockScript: String =
      stdoutOf(javaCommand, "-cp", classpath, "agentsandbox.launcher.RunOnHost", "--lock-script")

    private val buildLocks = java.util.concurrent.ConcurrentHashMap[(Program, Path), String]()

    /** The build directory's lock file, whose name ends in the hash that also names the runner's records for the
      * directory (RunOnHostSession.buildHash). */
    def buildLock(program: Program, workspace: Path): String =
      buildLocks.computeIfAbsent((program, workspace), _ =>
        stdoutOf(javaCommand, "-cp", classpath, "agentsandbox.launcher.RunOnHost", "--build-lock", program.name,
          workspace.toString).trim)

    /** The supervisor's own exports, which its proxy's certificates need
      * (RunOnHostSandbox.CertificateBuilderExports). */
    val CertificateExports: Seq[String] = Seq(
      "--add-exports=java.base/sun.security.x509=ALL-UNNAMED",
      "--add-exports=java.base/sun.security.util=ALL-UNNAMED",
    )

    /** The supervisor's command line under the build lock: perl takes the lock and execs the supervisor JVM, so the
      * process is the supervisor's, and a TERM to it reaches the supervisor's shutdown hook. */
    def supervisorCommand(program: Program, workspace: Path, arguments: Seq[String]): Seq[String] =
      Seq("/usr/bin/perl", "-e", lockScript, buildLock(program, workspace), "0", javaCommand) ++ CertificateExports ++
        Seq("-cp", classpath, "agentsandbox.launcher.RunOnHost", program.name, workspace.toString,
          checkout.systemPaths.toString, "--") ++ arguments

    /**
     * Runs the command through the supervisor (RunOnHost): it scavenges, publishes a command directory, starts the
     * command's proxy and, for sbt, its server, runs the program under the generated profile, ends what it started,
     * and preserves the exit code. Its output, the supervisor's own lines included, goes to `<name>.log`.
     *
     *   - A hang is a FAIL, not a stalled run: the command gets TERM after `timeoutSeconds`, and KILL 30 s later.
     */
    def supervisor(name: String, program: Program, workspace: Path, arguments: Seq[String],
        timeoutSeconds: Int = 900): Output =
      val started = start(name, supervisorCommand(program, workspace, arguments))
      transcript.record(s"${arguments.mkString(" ")} in $workspace through the supervisor: ${started.log}")
      val finished = started.process.waitFor(timeoutSeconds.toLong, TimeUnit.SECONDS)
      if !finished then
        started.process.destroy()
        if !started.process.waitFor(30, TimeUnit.SECONDS) then started.process.destroyForcibly().waitFor()
      Output(if finished then started.process.exitValue else -1,
        started.output + (if finished then "" else s"\n(killed after $timeoutSeconds s)"))

    /** The command sessions under the supervisor's root. The runners' sessions (`r<digits>`), the build and
      * retirement locks and the root's own entries are not commands (RunOnHostSession's layout). */
    def commandsNow: Int =
      val notCommands = Set("staging", "condemned", "root-lock", "build-lock", "retire-lock")
      val entries =
        try Using.resource(Files.list(commandRoot))(_.iterator.asScala.map(_.getFileName.toString).toVector)
        catch case _: java.io.IOException => Vector.empty
      entries.count(name => !notCommands(name) && !name.matches("r[0-9]+"))

    // --- Servers and daemons -------------------------------------------------------------------------------------

    /** The processes matching the pattern whose working directory is `dir`, or lies under it. A row never learns
      * the pid of a server that sbt's client forks, or of the daemon that the mill executable starts, but each runs
      * in its build directory. */
    def withCwd(pattern: String, dir: Path, under: Boolean): Vector[Long] =
      pids(pattern).filter: pid =>
        RunOnHostIdle.workingDirectory(pid).exists(cwd => if under then cwd.startsWith(dir) && cwd != dir
          else cwd == dir)

    /** `pgrep -f` of the pattern. */
    def pids(pattern: String): Vector[Long] =
      command("/usr/bin/pgrep", "-f", "--", pattern).linesIterator.flatMap(_.trim.toLongOption).toVector

    /** An sbt server's working directory is its build directory, exactly: a nested build's server is another
      * build's. */
    def sbtServers(dir: Path): Vector[Long] = withCwd("-Dsbt.script=", dir, under = false)

    /** A mill daemon's working directory is out/mill-daemon/<id>/sandbox (MillProcessLauncher). */
    def millDaemons(workspace: Path): Vector[Long] =
      withCwd("mill.daemon.MillDaemonMain", workspace / "out" / "mill-daemon", under = true)

    /** The gradle daemons of every launch under the supervisor's root, this run's included: a launch's daemons carry
      * the launch's tmp/ as java.io.tmpdir in their initial environment (RunOnHostGradleDaemons). */
    def launchGradleDaemons: Vector[Long] =
      pids("org.gradle.launcher.daemon.bootstrap.GradleDaemon").filter: pid =>
        command("/bin/ps", "-wwE", "-o", "command=", "-p", pid.toString).split(" ")
          .exists(_.contains(s"=-Djava.io.tmpdir=\"$commandRoot/"))

    /** This run's proxies: their command line carries this run's classpath, which lies under its directory. A
      * concurrent run's or a real command's proxy carries another path, and ending it is not this run's job. */
    def strayProxies: Vector[Long] =
      pids("--serve-proxy-on-host").filter(pid =>
        command("/bin/ps", "-ww", "-o", "command=", "-p", pid.toString).contains(out.toString))

    /** A `ps -o <field>=` value of the process, trimmed, in the C locale, as the launcher's records spell a start
      * time (RunOnHostSession.Record); empty when the process is gone. */
    def psField(pid: Long, field: String): String =
      HostDriver.host(transcript, Seq("/bin/ps", "-o", s"$field=", "-p", pid.toString), record = false,
        timeoutSeconds = Some(30), environment = Map("LC_ALL" -> "C")).text.trim

    /** What a command may leave behind, by kind: the sbt servers of `sbtDirectories`, the mill daemons of
      * `millWorkspaces`, every launch's gradle daemons, and this run's proxies. */
    def leftovers(sbtDirectories: Seq[Path], millWorkspaces: Seq[Path]): Vector[(String, Vector[Long])] =
      Vector(
        "sbt server" -> sbtDirectories.flatMap(sbtServers).toVector,
        "mill daemon" -> millWorkspaces.flatMap(millDaemons).toVector,
        "gradle daemon" -> launchGradleDaemons,
        "proxy" -> strayProxies,
      )

    /** The row after every supervisor row: no process or command directory outlives its command. */
    def checkNothingSurvives(sbtDirectories: Seq[Path], millWorkspaces: Seq[Path]): Unit =
      val left = leftovers(sbtDirectories, millWorkspaces).filter(_._2.nonEmpty)
      val directories = commandsNow
      check("no proxy, sbt server, mill daemon or gradle daemon survives its command",
        left.isEmpty && directories == 0,
        (left.map((what, pids) => s"$what: ${pids.mkString(" ")}") ++
          Option.when(directories > 0)(s"command directories: $directories")).mkString("; "))

    /** Ends each process that no live runner claims, and reports it. */
    def endUnclaimed(processes: Seq[Long]): Unit =
      processes.distinct.foreach: pid =>
        if RunOnHostIdle.endUnclaimed(commandRoot, pid, transcript.log) then
          transcript.log(s"ended process $pid")
