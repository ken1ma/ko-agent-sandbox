#!/usr/bin/env -S scala shebang
//> using scala 3.10.0
//> using file ../scala/HostDriver.scala
//> using file ../scala/RunOnHostIdle.scala
//> using file ../scala/RunOnHostChecks.scala

/*
  The run-on-host channel check: the real shim against the real runner, with a local script as the `podman exec`
  transport and this host as the sandbox. The supervisor behind the runner is the one that the other checks measure.
  These rows add:

  - the channel: framing, streamed output and the command's own exit code, the working-directory boundary, and
    teardown by descriptor lifetime;
  - the runner's runtimes: the proxy and the sbt server, mill daemon or gradle daemon that the commands of one build
    directory share, what retires them, and what two launches on one workspace do with each other's
    (doc/run-on-host-internals.md, "sbt", "mill", "Gradle" and "The channel and the command").

  Run it on the macOS HOST, from the repository root, with no sandbox session of this workspace running with
  --run-on-host:

      src/test/run-on-host/ChannelCheck.scala [--program sbt|mill|gradle|all]

  - The sbt rows always run: the channel's own rows are sbt's. --program mill or gradle adds that program's rows, on
    the fixture's release and on the older one, as the other checks do; all, the default, adds both.
  - The groups run in parallel, each with a runner and a channel of its own: sbt, each mill target and each gradle
    target. A group's rows run one at a time, and each reads only its own runner's commands, records and processes
    (Channel says how they are told apart). The channel's ends run alone afterwards, since they check that
    everything is gone.
  - The console shows every row as it runs, prefixed with its group. The files go to
    src/test/run-on-host/out-macos/channel/, which each run empties first: transcript.log holds the machine, the
    setup, the ends and the totals, <group>.log each group's rows, channel-<group>.log each runner's own log, and
    each command's stdout and stderr have files of their own.
  - Before the first run, provision each fixture once on the host, as SeatbeltCheck.scala says.

  The stubs, under the run's directory:
  - macOS has neither flock(1) nor timeout(1). The check stubs out the shim's serialization, because a channel's
    rows are serial, and the shim's exit-read bound runs unbounded, which only a runner that dies mid-command would
    notice.
  - The runner's writers open each FIFO with `dd conv=nocreat` (RunOnHostChannel.writer), a GNU conversion that the
    container's dd has and macOS's dd lacks (file_cmds, dd/args.c). A stand-in dd opens the existing FIFO without
    creating it.
  - The stub podman runs S of `podman exec -i --detach-keys= C sh -c S` (HostCommands.ExecWithInput) here, and a file
    that the check flips stands for the container's liveness. Each exec records its pid and start, so the rows can
    stage "the container died, taking every exec with it", and clean up, against exactly this run's processes. A
    pattern kill would match every live session's own `podman exec` command lines too.
*/

import agentsandbox.launcher.HostDriver.*
import agentsandbox.launcher.RunOnHostIdle
import agentsandbox.launcher.RunOnHostChecks.*

import java.net.{InetAddress, InetSocketAddress, ServerSocket, UnixDomainSocketAddress}
import java.nio.ByteBuffer
import java.nio.file.{Files, Path}
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

import scala.jdk.CollectionConverters.*
import scala.jdk.OptionConverters.*
import scala.util.chaining.*

@main def check(args: String*): Unit = ChannelCheck.run(args)

object ChannelCheck:
  val usage = "usage: src/test/run-on-host/ChannelCheck.scala [--program sbt|mill|gradle|all]"

  def run(args: Seq[String]): Unit =
    val root = orExit(repositoryRoot(ChecksPath))
    val options = orExit(parseOptions(args, usage))
    orExit(Either.cond(options.programs != Set(Program.Mvn), (), "the channel serves sbt, mill and gradle\n" + usage))
    val programs = options.programs - Program.Mvn + Program.Sbt
    val hostPaths = orExit(HostPaths.of(sys.env.get))
    orExit(Either.cond(scala.util.Properties.isMac, (), "Run this on macOS."))
    val checkout = Checkout(root)
    val out = checkOut(root, "channel")
    val transcript = Transcript(out / "transcript.log", timestamps = true)
    val checkRun = CheckRun(transcript, checkout, out, programs, hostPaths)
    runMeasured(transcript, checkRun.cleanup):
      val targets = targetsOf(checkout, programs)
      val workspaces = Seq(root, checkout.sbtFixture, checkout.denyFixture, checkout.ivyFixture) ++
        targets.map(_.workspace)
      val measured =
        for
          _ <- checkRun.preflight(workspaces)
          _ <- checkRun.makeOlderCopies()
          _ = checkRun.machine()
          emitted <- checkRun.setup(targets)
        yield ChannelGroups(checkRun, emitted).measure()
      measured.fold(identity, identity)

/** A command's result through the shim: its exit status, stdout and stderr. */
case class Shimmed(status: Int, out: String, err: String):
  def ok: Boolean = status == 0
  def has(needle: String): Boolean = out.contains(needle) || err.contains(needle)
  def lastErr: String = err.linesIterator.filterNot(line => line.isBlank || line.startsWith("Picked up")).toVector
    .lastOption.getOrElse("").take(70)

/** The groups of rows, in parallel, each with its runner and channel of its own; then the channel's ends, alone. */
class ChannelGroups(run: CheckRun, emitted: Map[String, Emitted]):
  private val checkout = run.checkout
  private val root = checkout.root
  private val millTargets = emitted.values.filter(_.target.program == Program.Mill).toVector.sortBy(_.target.id)
  private val gradleTargets = emitted.values.filter(_.target.program == Program.Gradle).toVector.sortBy(_.target.id)
  private val millWorkspaces = millTargets.map(_.target.workspace)
  private val sbtDirectories = Seq(root, checkout.sbtFixture, checkout.denyFixture, checkout.ivyFixture)

  def measure(): Int =
    run.cleanup.add("end what the rows started")(run.endUnclaimed(
      run.leftovers(sbtDirectories, millWorkspaces).flatMap(_._2)))
    // Each group's runner has a channel of its own, with a rewritten shim and stub, since the shim and the runner
    // spell the channel's directory as one constant. The sbt group's runner keeps the constant and the real shim.
    val groups = Vector("sbt" -> ((rows: GroupRows) => { rows.sbtRows(); rows.twoLaunches() })) ++
      millTargets.map(target => target.target.id -> ((rows: GroupRows) => rows.millRows(target))) ++
      gradleTargets.map(target => target.target.id -> ((rows: GroupRows) => rows.gradleRows(target)))
    run.inParallel(
      groups.map: (name, rows) =>
        name -> ((part: CheckRun) =>
          val channel = Channel(part, name, if name == "sbt" then Channel.Directory else Channel.privateDirectory(),
            if name == "sbt" then sbtDirectories else Seq.empty)
          try
            if !channel.start() then part.fail(s"channel: the $name group's runner starts",
              s"the runner made no FIFOs: ${channel.lastLogLine}")
            else rows(GroupRows(part, emitted, channel))
          finally channel.close()),
      groups.size,
    )
    // The channel's ends check that everything is gone, so they run alone, with a runner of their own.
    val ends = Channel(run, "ends", Channel.Directory, sbtDirectories)
    if !ends.start() then run.fail("channel: the ends' runner starts", s"the runner made no FIFOs: ${ends.lastLogLine}")
    else GroupRows(run, emitted, ends).endRows()
    ends.close()
    GroupRows(run, emitted, Channel(run, "planted", Channel.Directory, sbtDirectories)).plantedRows()
    run.transcript.step("after every row")
    run.checkNothingSurvives(sbtDirectories, millWorkspaces)
    if run.transcript.failed == 0 then 0 else 1

/**
 * One runner, with the channel's directory, the stubs, the runner's log and what the rows read of the runner.
 *
 *   - Its session is the one whose lock the runner holds: a session's lock belongs to the JVM that published it
 *     (RunOnHostSession.publish). Telling sessions apart by which one appeared would race with the other groups'.
 *   - Its commands are the command sessions whose lock holder, a supervisor, descends from the runner, and the
 *     sessions that no process holds any more, which are mid-teardown.
 *   - Its proxies descend from the runner; its gradle daemons carry the runner's tmp/ as java.io.tmpdir in their
 *     initial environment (RunOnHostGradleDaemons). Its sbt servers run in `sbtDirectories`.
 *   - Only this run's sleeping fixtures may be collected after a cancellation, and only this channel's: each channel
 *     tags the fixtures that its rows start.
 */
class Channel(run: CheckRun, val name: String, val directory: Path, sbtDirectories: Seq[Path],
    environment: Map[String, String] = Map.empty) extends AutoCloseable:
  private val out = run.out
  private val stubs = out / s"stubs-$name"
  val log: Path = out / s"channel-$name.log"
  val running: Path = stubs / "running"
  private val execPids = stubs / "exec.pids"
  private val stubBin = stubs / "bin"
  private val sandboxBin = stubs / "sandbox-bin"
  private val podman = stubs / "podman"
  val tag: String = s"run-on-host-${ProcessHandle.current.pid}-$name"
  val fixtureSleep: String = s"fixture[.]Main sleep $tag([[:space:]]|$$)"
  val shim: Path =
    if directory == Channel.Directory then Channel.shimFile(run.checkout.root)
    else
      val rewritten = stubs / "shim"
      Channel.executable(rewritten, Files.readString(Channel.shimFile(run.checkout.root))
        .replace(s"\ndir=${Channel.Directory}\n", s"\ndir=$directory\n"))
      rewritten
  private var runner: Option[Process] = None
  var session: Option[Path] = None

  Channel.executable(stubBin / "flock", "#!/bin/sh\nexit 0\n")
  Channel.executable(stubBin / "timeout", "#!/bin/sh\nshift\nexec \"$@\"\n")
  Channel.executable(sandboxBin / "dd",
    """#!/bin/sh
      |for arg; do case "$arg" in of=*) of=${arg#of=} ;; esac; done
      |[ -p "${of:-}" ] || { echo "dd: ${of:-no of=}: no such FIFO" >&2; exit 1; }
      |exec cat > "$of"
      |""".stripMargin)
  Channel.executable(podman, podmanScript)
  run.cleanup.add(s"end the $name runner and its execs")(close())

  /** The stub podman. Off the constant directory, it rewrites the directory in each script that it execs. Each exec's
    * start is the C locale's, as the check reads it. */
  private def podmanScript: String =
    val exec =
      if directory == Channel.Directory then s"""shift 4; PATH="$sandboxBin:$$PATH" exec "$$@" ;;"""
      else
        s"""script=$$(printf '%s' "$$7" | sed 's|${Channel.Directory}|$directory|g')
           |        PATH="$sandboxBin:$$PATH" exec sh -c "$$script" ;;""".stripMargin
    s"""#!/bin/sh
       |case "$$1 $$2" in
       |    "exec -i")
       |        echo "$$$$|$$(LC_ALL=C ps -o lstart= -p $$$$)" >> ${shellQuoted(execPids)}
       |        [ "$$3" = --detach-keys= ] || { echo "podman stub: exec -i without --detach-keys=" >&2; exit 125; }
       |        $exec
       |    "container inspect") cat ${shellQuoted(running)} ;;
       |esac
       |""".stripMargin

  /** Starts the runner; false when it made no FIFO or published no session. */
  def start(extra: String*): Boolean =
    Files.writeString(running, "true\n")
    removeTree(directory)
    val command = Seq((run.host.javaHome / "bin" / "java").toString) ++ run.CertificateExports ++ Seq("-cp",
      run.classpath, "agentsandbox.launcher.AgentSandboxLauncher", "--serve-run-on-host", podman.toString,
      s"C-$name", run.checkout.root.toString, "sbt,mill,gradle", log.toString) ++ extra ++
      Seq(run.checkout.root.toString)
    val builder = ProcessBuilder(command*)
      .redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD)
    environment.foreach(builder.environment.put(_, _))
    val started = builder.start()
    runner = Some(started)
    session = None
    within(30, intervalMillis = 200):
      if session.isEmpty then session = Channel.runnerSessions(run).find(session =>
        RunOnHostIdle.lockHolders(session / "lock").contains(started.pid))
      Files.exists(directory / "req") && session.nonEmpty

  def alive: Boolean = runner.exists(_.isAlive)

  /** Sends the runner TERM or KILL, and waits up to 2 minutes for it to end. */
  def stop(signal: String): Unit = runner.foreach: process =>
    if signal == "KILL" then process.destroyForcibly() else process.destroy()
    within(120, intervalMillis = 500)(!process.isAlive)

  /** Ends the runner, its execs and its fixtures, and removes the channel's directory. */
  def close(): Unit =
    runner.foreach: process =>
      process.destroy()
      if !process.waitFor(60, java.util.concurrent.TimeUnit.SECONDS) then process.destroyForcibly()
    killExecs()
    run.command("/usr/bin/pkill", "-f", fixtureSleep)
    removeTree(directory)

  def lastLogLine: String =
    if Files.exists(log) then Files.readAllLines(log).asScala.lastOption.getOrElse("").take(60) else ""

  def count(needle: String): Int =
    if Files.exists(log) then Files.readAllLines(log).asScala.count(_.contains(needle)) else 0

  /** A shim started in the background, from `cwd`, with the stubs first on its PATH. */
  def startShim(label: String, cwd: Path, arguments: Seq[String]): Process =
    val builder = ProcessBuilder((shim.toString +: arguments)*).directory(cwd.toFile)
      .redirectOutput((out / s"$name-$label.log").toFile).redirectError((out / s"$name-$label.log.err").toFile)
    builder.environment.put("PATH", s"$stubBin:${sys.env.getOrElse("PATH", "/usr/bin:/bin")}")
    val process = builder.start()
    process.getOutputStream.close()
    process

  def outputOf(label: String): Shimmed =
    def read(file: Path) = if Files.exists(file) then Files.readString(file) else ""
    Shimmed(-1, read(out / s"$name-$label.log"), read(out / s"$name-$label.log.err"))

  /** A command through the shim. A hang is a FAIL: the shim gets TERM after `timeoutSeconds`. */
  def run(label: String, cwd: Path, arguments: Seq[String], timeoutSeconds: Int): Shimmed =
    val process = startShim(label, cwd, arguments)
    val finished = process.waitFor(timeoutSeconds.toLong, java.util.concurrent.TimeUnit.SECONDS)
    if !finished then
      process.destroy()
      process.waitFor(30, java.util.concurrent.TimeUnit.SECONDS)
    outputOf(label).copy(status = if finished then process.exitValue else -1)

  def killShim(process: Process): Unit =
    process.destroyForcibly()
    process.waitFor()

  /** Kills only the execs that this channel's stub recorded, checked by pid and start, as the supervisor's scavenger
    * checks. Never by pattern, which would match a real session's own `podman exec` command lines, and never by pid
    * alone, which a recycled pid defeats. Each owned tree goes descendants first: the shell behind an exec may have
    * forked its command, and a surviving orphan keeps the FIFO and pipe open (RunOnHostChannel.end answers the same
    * measured behavior on the runner's side). */
  def killExecs(): Unit =
    if Files.exists(execPids) then
      Files.readAllLines(execPids).asScala.foreach: line =>
        line.split("\\|", 2) match
          case Array(pid, start) if pid.toLongOption.nonEmpty =>
            val owned = run.psField(pid.toLong, "lstart") == start.trim &&
              run.psField(pid.toLong, "command").contains(directory.toString)
            if owned then ProcessHandle.of(pid.toLong).ifPresent: handle =>
              handle.descendants.iterator.asScala.toVector.reverse.foreach(_.destroyForcibly())
              handle.destroyForcibly()
          case _ => ()

  // --- What the rows read of the runner ---------------------------------------------------------------------------

  private def descendsFromRunner(pid: Long): Boolean = runner.exists: process =>
    Iterator.iterate(ProcessHandle.of(pid).toScala)(_.flatMap(_.parent.toScala)).take(20).takeWhile(_.nonEmpty)
      .exists(_.exists(_.pid == process.pid))

  /** A runner's record for the build directory in the session, this runner's by default: `<pgid> <start>`, such as
    * `server-sbt` or `daemon-mill`. */
  def record(kind: String, dir: Path, in: Option[Path] = None): String =
    in.orElse(session).map(_ / "records" / s"$kind-${Channel.hash(run, dir)}").filter(Files.isRegularFile(_))
      .map(Channel.readTrimmed).getOrElse("")

  def recordsStartingWith(prefix: String, sessions: Seq[Path] = session.toSeq): Vector[String] =
    sessions.toVector.flatMap: session =>
      try scala.util.Using.resource(Files.list(session / "records"))(_.iterator.asScala.toVector)
      catch case _: java.io.IOException => Vector.empty
    .filter: file =>
      val name = file.getFileName.toString
      name.startsWith(prefix) && !name.endsWith(".exit") && !name.endsWith(".pending")
    .map(Channel.readTrimmed)

  def gradleRecords: Vector[String] = recordsStartingWith("daemon-gradle-")

  def gradleDaemons: Vector[Long] = session.toVector.flatMap: session =>
    run.pids("org.gradle.launcher.daemon.bootstrap.GradleDaemon").filter: pid =>
      run.command("/bin/ps", "-wwE", "-o", "command=", "-p", pid.toString).split(" ")
        .exists(_.contains(s"=-Djava.io.tmpdir=\"$session/"))

  /** This runner's commands, and the sessions mid-teardown. */
  def commandsNow: Int =
    val notCommands = Set("staging", "condemned", "root-lock", "build-lock", "retire-lock")
    val entries =
      try scala.util.Using.resource(Files.list(run.commandRoot))(_.iterator.asScala.toVector)
      catch case _: java.io.IOException => Vector.empty
    entries.count: entry =>
      val name = entry.getFileName.toString
      !notCommands(name) && !name.matches("r[0-9]+") && Files.isDirectory(entry) &&
        RunOnHostIdle.lockHolders(entry / "lock").pipe(holders => holders.isEmpty || holders.exists(descendsFromRunner))

  /** The sbt servers of this channel's directories that the runner's sessions do not record: a command's own. */
  def commandServers(sessions: Seq[Path] = session.toSeq): Vector[Long] =
    val recorded = recordsStartingWith("server-sbt-", sessions).map(_.takeWhile(_ != ' ')).toSet
    sbtDirectories.flatMap(run.sbtServers).toVector.filterNot(pid => recorded(run.psField(pid, "pgid")))

  /** The proxies under this runner that its sessions do not record: a command's own. A runner's proxy outlives each
    * command. */
  def commandProxies(sessions: Seq[Path] = session.toSeq): Vector[Long] =
    val recorded = recordsStartingWith("proxy-", sessions).map(_.takeWhile(_ != ' ')).toSet
    run.strayProxies.filter(descendsFromRunner).filterNot(pid => recorded(run.psField(pid, "pgid")))

  /** Awaits the runner between rows: no command directory, command server or command proxy. */
  def settled(): Unit =
    within(120, intervalMillis = 500)(commandsNow == 0 && commandServers().isEmpty && commandProxies().isEmpty)

object Channel:
  /** The channel's directory that the shim and the runner both spell. */
  val Directory: Path = Path.of("/tmp/ko-agent-sandbox/run-on-host")

  def shimFile(root: Path): Path = root / "container" / "ko-agent-sandbox" / "ko-sandbox-run-on-host"

  /** A channel's directory of this run's own under /tmp, with a name that is safe for the rewrites and for the shim's
    * unquoted uses; the checkout's path may carry a space or a sed delimiter. */
  def privateDirectory(): Path = Files.createTempDirectory(Path.of("/tmp"), "ko-agent-run-on-host-channel")

  def executable(file: Path, text: String): Unit =
    Files.createDirectories(file.getParent)
    Files.writeString(file, text)
    file.toFile.setExecutable(true)

  def readTrimmed(file: Path): String =
    try Files.readString(file).trim
    catch case _: java.io.IOException => ""

  /** The hash that names a build directory's lock and the runner's records for it (RunOnHostSession.buildHash). */
  def hash(run: CheckRun, dir: Path): String = run.buildLock(Program.Sbt, dir).split('-').last

  def runnerSessions(run: CheckRun): Vector[Path] =
    try scala.util.Using.resource(Files.list(run.commandRoot))(_.iterator.asScala
      .filter(path => path.getFileName.toString.matches("r[0-9]+")).toVector)
    catch case _: java.io.IOException => Vector.empty

/** One group's rows, through its channel. */
class GroupRows(run: CheckRun, emitted: Map[String, Emitted], ch: Channel):
  private val transcript = run.transcript
  private val checkout = run.checkout
  private val root = checkout.root
  private val out = run.out
  private val javaBinary = (run.host.javaHome / "bin" / "java").toString
  private val millTargets = emitted.values.filter(_.target.program == Program.Mill).toVector.sortBy(_.target.id)
  private def millVersion(target: Emitted): String = millVersionOf(target.target.workspace).getOrElse("unread")
  private val millWorkspaces = millTargets.map(_.target.workspace)
  private val tag = ch.tag
  private val fixtureSleep = ch.fixtureSleep
  private val sbtDirectories = Seq(root, checkout.sbtFixture, checkout.denyFixture, checkout.ivyFixture)
  /** The mill target whose Mill keeps a daemon, for the planted rendezvous. */
  private val daemonMill = millTargets.find(target => !millWithoutDaemon(millVersion(target)))

  def millRows(target: Emitted): Unit =
    if millWithoutDaemon(millVersion(target)) then millWithoutDaemonRows(target)
    else
      millTwoLaunches(target)
      millDaemonRows(target)

  private def readTrimmed(file: Path): String = Channel.readTrimmed(file)

  private def hash(dir: Path): String = Channel.hash(run, dir)

  private def leaderOf(record: String): String = record.takeWhile(_ != ' ')

  /** Whether the record's group leader lives: its pid has the recorded start. */
  private def alive(record: String): Boolean = record.split(" ", 2) match
    case Array(pgid, start) => pgid.toLongOption.exists(run.psField(_, "lstart") == start.trim)
    case _ => false

  private def aliveWord(record: String): String = if alive(record) then "alive" else "gone"

  private def pgidOf(pid: Long): String = run.psField(pid, "pgid")

  private def isAlive(pid: Long): Boolean = ProcessHandle.of(pid).map(_.isAlive).orElse(false)

  /** The sbt servers in the record's group, which holds a supervisor and the JVM that it starts. */
  private def serverInGroup(record: String): Vector[Long] =
    if record.isEmpty then Vector.empty
    else sbtDirectories.flatMap(run.sbtServers).toVector.filter(pgidOf(_) == leaderOf(record))

  /** The mill daemon in the record's group, which is the starter's. */
  private def daemonInGroup(record: String, workspace: Path): Vector[Long] =
    if record.isEmpty then Vector.empty else run.millDaemons(workspace).filter(pgidOf(_) == leaderOf(record))

  private def count(file: Path, needle: String): Int =
    if Files.exists(file) then Files.readAllLines(file).asScala.count(_.contains(needle)) else 0

  private def lastLine(file: Path): String =
    if Files.exists(file) then Files.readAllLines(file).asScala.lastOption.getOrElse("").take(60) else ""

  private def thisIsSbt(result: Shimmed): Option[String] = "This is sbt [0-9.]+".r.findFirstIn(result.out)

  private def printsMillVersion(result: Shimmed, version: String): Boolean =
    result.out.linesIterator.exists(_.trim == version)

  // --- sbt ----------------------------------------------------------------------------------------------------------

  def sbtRows(): Unit =
    transcript.step("the channel and the runner's sbt server")
    // The exit criterion's row: an `sbt test` that the agent invokes returns the command's own exit code, the passing
    // test's 0 and the failing test's 1. The tests are fixtures/sbt's, since this repository's own bind TCP listeners,
    // which the profile refuses.
    val passing = ch.run("test", checkout.sbtFixture, Seq("sbt", "testFull"), 1800)
    ch.settled()
    val failing = ch.run("test-failing", checkout.sbtFixture, Seq("sbt", "failing/testFull"), 900)
    ch.settled()
    run.check("channel: sbt test returns the command's own exit code",
      passing.ok && passing.out.linesIterator.exists(_.startsWith("[success]")) && failing.status == 1 &&
        failing.has("fixture.FailingTest"),
      s"passing exit ${passing.status}, failing exit ${failing.status}; ${
          if passing.ok then failing.lastErr else passing.lastErr}")

    // The runner holds one server record and one proxy record for the build directory, each unchanged after the next
    // command of the same directory. No runtime of either kind runs in a command's own session.
    ch.run("warm", root, Seq("sbt", "about"), 900)
    ch.settled()
    val rootServer = ch.record("server-sbt", root)
    val rootProxy = ch.record("proxy-sbt", root)
    val reuse = ch.run("reuse", root, Seq("sbt", "about"), 300)
    ch.settled()
    // The record's group is still alive, and no sbt server runs outside a runner's recorded group. A second server
    // would be a group of its own, which ch.commandServers() would name.
    run.check("channel: the runner's sbt server serves the commands of one build directory",
      rootServer.nonEmpty && alive(rootServer) && ch.record("server-sbt", root) == rootServer &&
        serverInGroup(rootServer).nonEmpty && ch.commandServers().isEmpty && thisIsSbt(reuse).nonEmpty,
      s"record before: ${rootServer}, after: ${ch.record("server-sbt", root)}, group: " +
        s"${serverInGroup(rootServer).mkString(" ")}, command servers: ${ch.commandServers().mkString(" ")}")
    run.check("channel: the runner's proxy serves the commands of one build directory",
      rootProxy.nonEmpty && alive(rootProxy) && ch.record("proxy-sbt", root) == rootProxy &&
        ch.commandProxies().isEmpty,
      s"record before: $rootProxy, after: ${ch.record("proxy-sbt", root)}, command proxies: " +
        ch.commandProxies().mkString(" "))

    // The request that starts a server gives it its -D (RunOnHostSbtServer.serverCommand). `shutdown` ends the
    // server, and the next request starts a new one.
    ch.run("shutdown", root, Seq("sbt", "shutdown"), 300)
    ch.settled()
    val probe = ch.run("probe", root,
      Seq("sbt", "-Drun-on-host.probe=probe-set", """eval sys.props.getOrElse("run-on-host.probe", "unset")"""), 600)
    ch.settled()
    run.check("channel: the starting request's -D reaches the build", probe.has("probe-set"),
      probe.out.linesIterator.find(line => line.contains("probe-") || line.contains("unset")).getOrElse("").take(40))

    cancelledSbtCommand()
    deniedHostPerCommand()
    secondBuildDirectory()
    editedSbtVersion()

  /**
   * A client disconnect mid-task follows stock sbt, as in a terminal: sbt detaches the channel (removeChannel,
   * force = false) without stopping the running task, which runs to completion on the warm server. The runner does not
   * retire the server, so the same server, its record unchanged, serves the next command once the task finishes.
   *
   *   - The task runs on the task engine, not as `eval`, which runs on the command thread. The task writes a marker,
   *     so that the disconnect lands while the task still runs.
   *   - The sleep is short, so the next command waits it out rather than the check.
   *   - The supervisor hands sbt all of its arguments as one command, so the `set` and the task invocation ride one
   *     string joined by `;`. The task body is a single expression, with the marker written inside the sleep's
   *     argument, so no inner `;` or newline meets sbt's command splitter. Def.uncached makes the marker and the sleep
   *     run on every invocation; otherwise sbt 2 reuses the Unit result without running either side effect.
   */
  private def cancelledSbtCommand(): Unit =
    val label = "channel: a cancelled command's warm server survives, and the next command reuses it"
    val marker = root / "target" / "run-on-host-cancel-started"
    Files.deleteIfExists(marker)
    run.cleanup.add("remove the cancel marker")(Files.deleteIfExists(marker))
    val task = """set TaskKey[Unit]("koRunOnHostSleep") := Def.uncached(java.lang.Thread.sleep(""" +
      s"""if (java.nio.file.Files.writeString(java.nio.file.Paths.get("$marker"), "started")""" +
      ".toString.nonEmpty) 20000L else 20000L))"
    val cancelled = ch.startShim("cancel", root, Seq("sbt", s"$task; koRunOnHostSleep"))
    val started = within(600, intervalMillis = 500)(Files.exists(marker) || !cancelled.isAlive) && cancelled.isAlive
    if !started then
      run.fail(label, s"no running task to cancel; see ${out / "chan-cancel.log"}{,.err}")
      ch.killShim(cancelled)
    else
      // The marker proves that the task runs on a server. The row records that server now, whether the task reused a
      // warm one or started its own, and compares the same group after the cancel.
      val oldRecord = ch.record("server-sbt", root)
      val oldServer = serverInGroup(oldRecord)
      ch.killShim(cancelled)
      ch.settled()
      val after = ch.run("after-cancel", root, Seq("sbt", "about"), 600)
      ch.settled()
      val newServer = serverInGroup(ch.record("server-sbt", root))
      run.check(label, oldServer.nonEmpty && newServer == oldServer && ch.record("server-sbt", root) == oldRecord &&
          thisIsSbt(after).nonEmpty,
        if newServer == oldServer then s"server ${oldServer.mkString(" ")} kept across the cancel"
        else s"old server ${oldServer.mkString(" ")}, after cancel: ${newServer.mkString(" ")} (record before " +
          s"$oldRecord, after ${ch.record("server-sbt", root)})")
    Files.deleteIfExists(marker)

  /** The report reads only what the command added to the shared proxy log (the reportFrom offset), never the whole
    * log. fixtures/deny cannot load without its refused resolver, so every command, update and about alike,
    * re-requests the resolver and reports its own denial. The second command's report holds only its own request, not
    * the first's carried over, so its count never exceeds the first's. */
  private def deniedHostPerCommand(): Unit =
    val first = ch.run("deny1", checkout.denyFixture, Seq("sbt", "update"), 600)
    ch.settled()
    val second = ch.run("deny2", checkout.denyFixture, Seq("sbt", "about"), 300)
    ch.settled()
    def reports(result: Shimmed) = result.err.linesIterator.count(_.contains("Command requested network access"))
    val (firstCount, secondCount) = (reports(first), reports(second))
    run.check("channel: the denied-host report is per command",
      !first.ok && first.err.contains("denied.example.com") && second.err.contains("denied.example.com") &&
        secondCount >= 1 && secondCount <= firstCount,
      s"each command reports its own denial ($firstCount, then $secondCount); update exit ${first.status}")

  /** Both directories are warm: this repository has a runtime, and fixtures/deny has one. Visiting each again reuses
    * its own runtime; neither retires the other. */
  private def secondBuildDirectory(): Unit =
    val denyRecord = ch.record("proxy-sbt", checkout.denyFixture)
    val rootRecord = ch.record("proxy-sbt", root)
    ch.run("root", root, Seq("sbt", "about"), 600)
    ch.settled()
    val rootSame = ch.record("proxy-sbt", root) == rootRecord
    val denyAfterRoot = ch.record("proxy-sbt", checkout.denyFixture) == denyRecord && alive(denyRecord)
    ch.run("deny3", checkout.denyFixture, Seq("sbt", "update"), 600)
    ch.settled()
    val denyReused = ch.record("proxy-sbt", checkout.denyFixture) == denyRecord
    run.check("channel: a second build directory stays warm beside the first, each reused",
      rootRecord.nonEmpty && rootSame && denyAfterRoot && denyReused && alive(rootRecord),
      s"root reused: $rootSame (${aliveWord(rootRecord)}), deny alive after root: $denyAfterRoot, deny reused: " +
        denyReused)

  /** After `shutdown`, the next command's server is assembled from the build directory afresh. The row edits
    * fixtures/ivy's pin under a live server, and the cleanup restores the pin. */
  private def editedSbtVersion(): Unit =
    val pinFile = checkout.ivyFixture / "project" / "build.properties"
    val saved = Files.readString(pinFile)
    run.cleanup.add("restore fixtures/ivy's sbt.version")(Files.writeString(pinFile, saved))
    val before = ch.run("pin1", checkout.ivyFixture, Seq("sbt", "about"), 900)
    ch.settled()
    Files.writeString(pinFile, "sbt.version=1.12.13\n")
    ch.run("pin3", checkout.ivyFixture, Seq("sbt", "shutdown"), 300)
    ch.settled()
    val after = ch.run("pin4", checkout.ivyFixture, Seq("sbt", "about"), 900)
    ch.settled()
    Files.writeString(pinFile, saved)
    val (beforeEdit, afterShutdown) = (thisIsSbt(before), thisIsSbt(after))
    run.check("channel: an edited sbt.version takes effect after shutdown",
      beforeEdit.nonEmpty && !beforeEdit.contains("This is sbt 1.12.13") &&
        afterShutdown.contains("This is sbt 1.12.13"),
      s"${beforeEdit.getOrElse("none")}, then ${afterShutdown.getOrElse("none")}")

  // --- Two launches on one workspace ------------------------------------------------------------------------------

  /**
   * A second runner's commands on the same workspace attach to the first runner's server and daemon when they would
   * start one under the same confinement and environment. Otherwise they end the first runner's server and daemon by
   * its records and start their own (RunnerRuntimes.attached, takeOver).
   *
   *   - The second runner has a channel of its own (Channel). A name-only forward's value travels under its carrier
   *     name in the runner's own environment (RunOnHostChannel.spawnRunner). The launcher sets that variable; here the
   *     check sets it.
   *   - Between rows, both runners settle, and the servers and proxies that either runner records are the runners'.
   */
  private def secondChannel(): Channel =
    Channel(run, s"${ch.name}-second", Channel.privateDirectory(), Seq.empty,
      Map("KO_AGENT_RUN_ON_HOST_ENV_CHECK_SHARE" -> "1"))

  private def bothSettled(second: Channel): Unit =
    val sessions = ch.session.toSeq ++ second.session
    within(120, intervalMillis = 500)(ch.commandsNow == 0 && second.commandsNow == 0 &&
      ch.commandServers(sessions).isEmpty && ch.commandProxies(sessions).isEmpty &&
      second.commandProxies(sessions).isEmpty)

  private def recordNames(session: Option[Path]): String =
    session.map(dir => scala.util.Using.resource(Files.list(dir / "records"))(_.iterator.asScala
      .map(_.getFileName.toString).mkString(" "))).getOrElse("")

  private def rootNow: String =
    scala.util.Using.resource(Files.list(run.commandRoot))(_.iterator.asScala.map(_.getFileName).mkString(" "))

  /** The sbt rows of two launches. The first runner's server for the workspace is warm from the rows before. */
  def twoLaunches(): Unit =
    transcript.step("two launches on one workspace")
    val share = "channel: a second launch attaches to the first's sbt server, recording nothing"
    val takeover = "channel: a second launch forwarding a variable the first did not takes the sbt server over"
    val takeback = "channel: the first launch's next command takes the sbt server back"
    val teardown = "channel: the first launch's command during the second's teardown starts its own server"
    val second = secondChannel()
    def recordedServers = ch.commandServers(ch.session.toSeq ++ second.session)
    if !second.start() then
      run.fail(share, s"the second runner made no FIFOs: ${second.lastLogLine}")
      Seq(takeover, takeback, teardown).foreach(run.skip(_, "no second runner"))
      second.close()
      return
    // The second launch's `about` runs in the first runner's server: the record and its group stay unchanged, no
    // second server starts, and nothing is recorded in the second runner's session.
    val shareBefore = ch.record("server-sbt", root)
    val shared = second.run("share-sbt", root, Seq("sbt", "about"), 600)
    bothSettled(second)
    run.check(share, shared.ok && thisIsSbt(shared).nonEmpty && shareBefore.nonEmpty && alive(shareBefore) &&
        ch.record("server-sbt", root) == shareBefore && serverInGroup(shareBefore).nonEmpty &&
        recordedServers.isEmpty && recordNames(second.session).isEmpty && second.count("attached to") > 0,
      if shared.ok then "attached to [^ ]*".r.findFirstIn(Files.readString(second.log)).getOrElse("")
      else s"exit ${shared.status}, record before $shareBefore, after ${ch.record("server-sbt", root)}, command " +
        s"servers: ${recordedServers.mkString(" ")}, second session records: ${recordNames(second.session)}; " +
        shared.lastErr)
    second.close()

    // The second launch forwards a variable that the first did not, so the server that it would start has another
    // environment. The second launch therefore ends the first runner's server by its record, under the retirement
    // lock, and starts its own; the first runner's record stays, with its group gone. The first launch's next command
    // finds its group dead and takes the server back the same way: two launches whose runtimes differ alternate
    // restarts.
    if !second.start("--env=CHECK_SHARE") then
      run.fail(takeover, s"the second runner made no FIFOs: ${second.lastLogLine}")
      Seq(takeback, teardown).foreach(run.skip(_, "no second runner"))
      second.close()
      return
    val takenBefore = ch.record("server-sbt", root)
    val taken = second.run("share-takeover", root, Seq("sbt", "about"), 600)
    bothSettled(second)
    val takenAfter = second.record("server-sbt", root)
    run.check(takeover, taken.ok && thisIsSbt(taken).nonEmpty && takenBefore.nonEmpty && !alive(takenBefore) &&
        serverInGroup(takenBefore).isEmpty && takenAfter.nonEmpty && alive(takenAfter) &&
        serverInGroup(takenAfter).nonEmpty && recordedServers.isEmpty && second.count("took over") > 0,
      if taken.ok then "took over [^ ]*".r.findFirstIn(Files.readString(second.log)).getOrElse("")
      else s"exit ${taken.status}, first's record $takenBefore ${aliveWord(takenBefore)}, second's $takenAfter " +
        s"${aliveWord(takenAfter)}, command servers: ${recordedServers.mkString(" ")}, root: $rootNow; " +
        taken.lastErr)

    val back = ch.run("share-takeback", root, Seq("sbt", "about"), 600)
    bothSettled(second)
    val takenBack = ch.record("server-sbt", root)
    run.check(takeback, back.ok && thisIsSbt(back).nonEmpty && takenBack.nonEmpty && takenBack != takenBefore &&
        alive(takenBack) && serverInGroup(takenBack).nonEmpty && takenAfter.nonEmpty && !alive(takenAfter) &&
        serverInGroup(takenAfter).isEmpty && recordedServers.isEmpty && ch.count("took over") > 0,
      if back.ok then "took over [^ ]*".r.findFirstIn(Files.readString(ch.log)).getOrElse("")
      else s"exit ${back.status}, first's record $takenBack ${aliveWord(takenBack)}, second's $takenAfter " +
        s"${aliveWord(takenAfter)}, root: $rootNow; ${back.lastErr}")

    // With the second launch owning the server again, the row ends the second runner while the first launch's command
    // runs. The taker waits on the retirement lock that the teardown holds, finds the group ended or ends it, and
    // starts its own server. The row expects one server, whose record is the first runner's, no signal sent twice, and
    // the second runner's session collected.
    val retake = second.run("share-retake", root, Seq("sbt", "about"), 600)
    bothSettled(second)
    val retaken = second.record("server-sbt", root)
    val secondSession = second.session
    val secondName = secondSession.map(_.getFileName.toString).getOrElse("")
    val takeoversBefore = ch.count(s"took over $secondName")
    val torn = scala.concurrent.Future(second.stop("TERM"))(using scala.concurrent.ExecutionContext.global)
    val during = ch.run("share-teardown", root, Seq("sbt", "about"), 600)
    scala.concurrent.Await.ready(torn, scala.concurrent.duration.Duration.Inf)
    second.close()
    ch.settled()
    val tornDown = ch.record("server-sbt", root)
    val sessionGone = secondSession.forall(session => !Files.exists(session) &&
      !Files.exists(run.commandRoot / "condemned" / session.getFileName.toString))
    run.check(teardown, retake.ok && during.ok && thisIsSbt(during).nonEmpty && retaken.nonEmpty && !alive(retaken) &&
        serverInGroup(retaken).isEmpty && tornDown.nonEmpty && alive(tornDown) && serverInGroup(tornDown).nonEmpty &&
        ch.commandServers().isEmpty && sessionGone,
      if during.ok && sessionGone then
        if ch.count(s"took over $secondName") > takeoversBefore then "took the group over"
        else "found the group ended by the teardown"
      else s"exits ${retake.status}/${during.status}, second's record $retaken ${aliveWord(retaken)}, first's " +
        s"$tornDown ${aliveWord(tornDown)}, second's session ${if sessionGone then "gone" else "kept"}, root: " +
        s"$rootNow; ${during.lastErr}")

  /** The mill rows of two launches: the daemon follows as the sbt server does. The first runner's own `version` starts
    * its daemon before each row and shuts it down after, so that the daemon rows still measure a start of their own. */
  private def millTwoLaunches(target: Emitted): Unit =
    val workspace = target.target.workspace
    val version = millVersion(target)
    transcript.step(s"two launches on one workspace, mill $version")
    val share = s"channel: mill $version: a second launch attaches to the first's mill daemon"
    val takeover = s"channel: mill $version: a second launch forwarding a variable the first did not takes the mill " +
      "daemon over"
    val second = secondChannel()
    if !second.start() then
      run.fail(share, s"the second runner made no FIFOs: ${second.lastLogLine}")
      run.skip(takeover, "no second runner")
      second.close()
      return
    ch.run("share-mill1", workspace, Seq("mill", "version"), 900)
    ch.settled()
    val daemonRecord = ch.record("daemon-mill", workspace)
    val daemon = daemonInGroup(daemonRecord, workspace)
    val attached = second.run("share-mill", workspace, Seq("mill", "version"), 600)
    bothSettled(second)
    run.check(share, attached.ok && printsMillVersion(attached, version) && daemon.nonEmpty && alive(daemonRecord) &&
        ch.record("daemon-mill", workspace) == daemonRecord && daemonInGroup(daemonRecord, workspace) == daemon &&
        run.millDaemons(workspace).size == 1 && recordNames(second.session).isEmpty &&
        Files.readString(second.log).matches("(?s).*attached to .* mill runtime.*"),
      s"daemon ${daemon.mkString(" ")} in group ${leaderOf(daemonRecord)}; all: " +
        s"${run.millDaemons(workspace).mkString(" ")}; ${attached.lastErr}")
    ch.run("share-mill2", workspace, Seq("mill", "shutdown"), 300)
    ch.settled()
    second.close()

    if !second.start("--env=CHECK_SHARE") then
      run.fail(takeover, s"the second runner made no FIFOs: ${second.lastLogLine}")
      second.close()
      return
    ch.run("share-mill-takeover0", workspace, Seq("mill", "version"), 900)
    ch.settled()
    val before = ch.record("daemon-mill", workspace)
    val daemonBefore = daemonInGroup(before, workspace)
    val taken = second.run("share-mill-takeover", workspace, Seq("mill", "version"), 600)
    bothSettled(second)
    val after = second.record("daemon-mill", workspace)
    run.check(takeover, taken.ok && printsMillVersion(taken, version) && daemonBefore.nonEmpty && !alive(before) &&
        !daemonBefore.exists(isAlive) && after.nonEmpty && alive(after) && daemonInGroup(after, workspace).nonEmpty &&
        run.millDaemons(workspace).size == 1 &&
        Files.readString(second.log).matches("(?s).*took over .* mill daemon.*"),
      s"daemon before ${daemonBefore.mkString(" ")}, second's record $after, all: " +
        s"${run.millDaemons(workspace).mkString(" ")}; ${taken.lastErr}")
    // The first runner's `shutdown` ends the second runner's daemon by its record and stops its own.
    ch.run("share-mill-takeover1", workspace, Seq("mill", "shutdown"), 600)
    bothSettled(second)
    second.close()

  // --- mill ---------------------------------------------------------------------------------------------------------

  /** Records the pid and start of the build of yours that a mill row starts unconfined. The cleanup signals that pid
    * only while it is still that process. */
  private def foreignStart(name: String, workspace: Path, command: String*): Started =
    val log = out / s"$name.log"
    val builder = ProcessBuilder(command*).directory(workspace.toFile).redirectErrorStream(true)
      .redirectOutput(log.toFile)
    Seq("JAVA_OPTS", "JDK_JAVA_OPTIONS", "GRADLE_OPTS").foreach(builder.environment.remove(_))
    foreignEnvironment.foreach(builder.environment.put(_, _))
    val started = Started(builder.start(), log)
    started.process.getOutputStream.close()
    val start = run.psField(started.pid, "lstart")
    run.cleanup.add(s"end $name")(if run.psField(started.pid, "lstart") == start then started.process.destroy())
    started

  /** An unconfined build of yours: the JDK that the profile grants first on PATH, and none of the JVM option
    * variables that would make its fingerprint the runner's or another's. */
  private def foreignEnvironment: Map[String, String] =
    Map("PATH" -> s"${run.host.javaHome}/bin:${sys.env.getOrElse("PATH", "/usr/bin:/bin")}")

  private def foreignCommand(workspace: Path, environment: Map[String, String], command: String*): Output =
    val builder = ProcessBuilder(command*).directory(workspace.toFile).redirectErrorStream(true)
    Seq("JAVA_OPTS", "JDK_JAVA_OPTIONS", "GRADLE_OPTS").foreach(builder.environment.remove(_))
    (foreignEnvironment ++ environment).foreach(builder.environment.put(_, _))
    val process = builder.start()
    process.getOutputStream.close()
    val text = String(process.getInputStream.readAllBytes())
    Output(process.waitFor(), text)

  /** A Mill without a daemon: each command runs the build in its own profile (RunOnHostPrereqs.millRunsWithoutDaemon),
    * the runner keeps only the proxy, and the supervisor says why on the command's stderr. */
  private def millWithoutDaemonRows(target: Emitted): Unit =
    val workspace = target.target.workspace
    val version = millVersion(target)
    transcript.step(s"mill $version without a daemon, through the channel")
    val compile = ch.run(s"${target.target.id}-nodaemon1", workspace, Seq("mill", "__.compile"), 900)
    ch.settled()
    val test = ch.run(s"${target.target.id}-nodaemon2", workspace, Seq("mill", "__.test"), 600)
    ch.settled()
    run.check(s"channel: mill $version without a daemon builds in each command, and the runner starts no daemon",
      compile.ok && test.ok && ch.record("daemon-mill", workspace).isEmpty && run.millDaemons(workspace).isEmpty &&
        compile.err.contains("runs the build without a daemon"),
      s"exits ${compile.status}/${test.status}, record ${ch.record("daemon-mill", workspace)}, daemons: " +
        s"${run.millDaemons(workspace).mkString(" ")}; ${compile.lastErr}")

    // A build through a daemon of yours, outside any profile, holds out/mill-out-lock and records its launcher. Mill's
    // own wait would read that launcher's start time and throw under the profile, so the supervisor waits instead
    // (RunOnHostSandbox.awaitMillOutLock), and the command runs once the build ends. The supervisor leaves the daemon,
    // idle by then, alone; the row ends the daemon, and the cleanup ends it and the build on any exit.
    val label = s"channel: mill $version without a daemon: a build through a mill daemon of yours is waited for, " +
      "then the command runs"
    val yours = foreignStart(s"foreign-lock-${target.target.id}", workspace, "./mill", "run", "sleep", tag)
    within(300, intervalMillis = 500)(yours.output.contains("fixture-main"))
    val foreign = run.millDaemons(workspace).headOption
    val waitingShim = ch.startShim(s"${target.target.id}-lock", workspace, Seq("mill", "__.compile"))
    Thread.sleep(20_000)
    val waiting = waitingShim.isAlive
    // The row ends the run JVM, not the launcher: a launcher's disconnect mid-command shuts its daemon down.
    run.command("/usr/bin/pkill", "-f", fixtureSleep)
    yours.process.waitFor(60, TimeUnit.SECONDS)
    waitingShim.waitFor()
    val locked = ch.outputOf(s"${target.target.id}-lock").copy(status = waitingShim.exitValue)
    ch.settled()
    val foreignAlive = foreign.exists(isAlive)
    foreign.foreach(pid => ProcessHandle.of(pid).ifPresent(_.destroy()))
    foreign.foreach(pid => within(60, intervalMillis = 500)(!isAlive(pid)))
    run.check(label, foreign.nonEmpty && waiting && locked.ok && foreignAlive &&
        locked.err.matches("(?s).*waiting up to .* for the Mill process that holds.*"),
      if locked.ok && waiting then s"waited 20s on foreign daemon ${foreign.mkString}'s build, then built"
      else s"foreign daemon ${foreign.mkString} alive after: $foreignAlive, waiting after 20s: $waiting, exit " +
        s"${locked.status}; ${locked.lastErr}")

  /**
   * The runner's daemon (doc/run-on-host-internals.md, "mill"): it serves every mill command of the build directory,
   * and each client runs under a profile that names that daemon's port and no other.
   *
   *   - The first row also meets the `mill-daemon-classpath` file that the builds check left. The file names the
   *     run-on-host cache of the workspace as a workspace of its own, which this runner's profile denies, because the
   *     profile treats it as this repository's build directory. The start deletes the file
   *     (RunOnHostMillDaemons.discardForeignClasspath), or the daemon dies unable to open its jars.
   *   - The fixture's `run` prints the TMPDIR that the build sees and, with `sleep`, stays up for the cancel and
   *     busy-daemon rows.
   */
  private def millDaemonRows(target: Emitted): Unit =
    val workspace = target.target.workspace
    val version = millVersion(target)
    val id = target.target.id
    def mill(name: String, timeoutSeconds: Int, arguments: String*): Shimmed =
      val result = ch.run(s"$id-$name", workspace, "mill" +: arguments, timeoutSeconds)
      ch.settled()
      result
    def row(text: String) = s"channel: mill $version: $text"
    transcript.step(s"mill $version's daemon, through the channel")

    // The start TERMs its starter once the daemon listens (RunOnHostMillDaemons.endStarter). The channel log says that
    // the TERM was sent; the row counts those lines before and after, because the log accumulates. The starter's exit
    // record, beside the daemon record, says that the starter ended on the TERM, with 143.
    val termedBefore = ch.count("TERM to the mill starter")
    val compile = mill("compile", 900, "__.compile")
    val daemonRecord = ch.record("daemon-mill", workspace)
    val daemon = daemonInGroup(daemonRecord, workspace)
    val termed = ch.count("TERM to the mill starter")
    val starterExit = ch.session.toVector.map(_ / "records" / s"daemon-mill-${hash(workspace)}.exit")
      .find(Files.isRegularFile(_)).map(readTrimmed).getOrElse("none")
    val again = mill("version", 300, "version")
    run.check(row("compile starts the runner's daemon, and the next command reuses it"),
      compile.ok && daemon.nonEmpty && alive(daemonRecord) && ch.record("daemon-mill", workspace) == daemonRecord &&
        daemonInGroup(daemonRecord, workspace) == daemon && run.millDaemons(workspace).size == 1 &&
        printsMillVersion(again, version) && termed > termedBefore && starterExit == "143",
      s"daemon ${daemon.mkString(" ")} in group ${leaderOf(daemonRecord)}; all: " +
        s"${run.millDaemons(workspace).mkString(" ")}; TERMs $termed (before $termedBefore), starter exit $starterExit")

    // A forked JVM, such as a `run` or a test, inherits the daemon's profile but gets the command's environment
    // (RunModule.scala, ctx.env). The fixture's main creates a temporary file where that environment says, and prints
    // the file's path.
    val forked = mill("tmp", 600, "run")
    val tmpfile = "tmpfile=[^ ]*".r.findFirstIn(forked.out)
    run.check(row("a mill build's forked JVM writes temporary files where the daemon's profile allows"),
      forked.ok && tmpfile.nonEmpty, tmpfile.getOrElse(s"exit ${forked.status}; ${forked.lastErr}"))

    // The build may write socketPort, and the file authorizes nothing: the client's profile does not admit a planted
    // port, so the client's connect is denied, and the daemon stays.
    val portFile = workspace / "out" / "mill-daemon" / "socketPort"
    val savedPort = readTrimmed(portFile)
    run.cleanup.add(s"restore $portFile"):
      if Files.exists(portFile.getParent) then Files.writeString(portFile, savedPort)
    Files.writeString(portFile, (savedPort.toLongOption.getOrElse(0L) + 1).toString)
    val planted = mill("planted-port", 300, "version")
    Files.writeString(portFile, savedPort)
    run.check(row("a planted socketPort reaches no daemon: the client is denied, the daemon untouched"),
      !planted.ok && planted.has("Operation not permitted") && daemonInGroup(daemonRecord, workspace) == daemon,
      s"exit ${planted.status}; daemon now " +
        daemonInGroup(ch.record("daemon-mill", workspace), workspace).mkString(" "))

    // After a client disconnect mid-command, the next command runs, whatever the daemon did on the disconnect. Stock
    // Mill shuts the daemon down (Server.scala; measured by src/probe/run-on-host-runner-session.sh M5), and the wait
    // lets that shutdown finish.
    val cancelled = ch.startShim(s"$id-cancel", workspace, Seq("mill", "run", "sleep", tag))
    val ready = within(300, intervalMillis = 500)(ch.outputOf(s"$id-cancel").out.contains("fixture-main") ||
      !cancelled.isAlive) && cancelled.isAlive
    val cancelDaemon = daemonInGroup(ch.record("daemon-mill", workspace), workspace)
    ch.killShim(cancelled)
    ch.settled()
    cancelDaemon.foreach(pid => within(60, intervalMillis = 500)(!isAlive(pid)))
    val leftFork = run.pids(fixtureSleep)
    run.info("forked run JVM after the cancel", if leftFork.isEmpty then "gone" else s"alive (${leftFork.mkString(" ")
      }); killed")
    leftFork.foreach(pid => ProcessHandle.of(pid).ifPresent(_.destroy()))
    val afterCancel = mill("after-cancel", 300, "version")
    val newDaemon = daemonInGroup(ch.record("daemon-mill", workspace), workspace)
    run.check(row("after a cancelled mill command, the next command runs"),
      ready && cancelDaemon.nonEmpty && newDaemon.nonEmpty && printsMillVersion(afterCancel, version),
      s"ready to cancel: $ready; daemon before ${cancelDaemon.mkString(" ")}, after ${newDaemon.mkString(" ")}")

    // A file that Mill's launcher restarts the daemon on (RunOnHostPrereqs.millDaemonConfig) replaces the daemon
    // before the command, and removing the file replaces the daemon again. The cleanup removes the file too.
    val optsFile = workspace / ".mill-jvm-opts"
    val optsRecord = ch.record("daemon-mill", workspace)
    run.cleanup.add(s"remove $optsFile")(Files.deleteIfExists(optsFile))
    Files.writeString(optsFile, "-Dko.run-on-host.opts=1\n")
    val opts1 = mill("opts1", 600, "version")
    val editedRecord = ch.record("daemon-mill", workspace)
    Files.deleteIfExists(optsFile)
    val opts2 = mill("opts2", 600, "version")
    run.check(row("a mill option-file edit replaces the daemon, and the next command runs under it"),
      opts1.ok && opts2.ok && editedRecord.nonEmpty && editedRecord != optsRecord &&
        ch.record("daemon-mill", workspace) != editedRecord && alive(ch.record("daemon-mill", workspace)) &&
        ch.count("its configuration changed") > 0,
      s"exits ${opts1.status}/${opts2.status}; records: $optsRecord -> $editedRecord -> " +
        ch.record("daemon-mill", workspace))

    // A link at out/mill-daemon would point Mill's launcher at another build directory's daemon, past the ownership
    // and idleness checks (RunOnHostMillDaemons.rendezvousIsOwn). The runner refuses the link before any of that runs.
    // The row shuts the runner's daemon down first, because the daemon reads its processId by path and would exit
    // while the directory is aside.
    mill("shutdown0", 300, "shutdown")
    val daemonDir = workspace / "out" / "mill-daemon"
    val aside = workspace / "out" / "mill-daemon.run-on-host"
    val elsewhere = Files.createTempDirectory(workspace, "run-on-host-scratch")
    run.cleanup.add(s"put $daemonDir back"):
      if Files.isSymbolicLink(daemonDir) then Files.delete(daemonDir)
      if Files.exists(aside) then Files.move(aside, daemonDir)
      removeTree(elsewhere)
    Files.move(daemonDir, aside)
    Files.createSymbolicLink(daemonDir, elsewhere)
    val redirected = mill("redirect", 300, "version")
    Files.delete(daemonDir)
    Files.move(aside, daemonDir)
    run.check(row("a redirected out/mill-daemon is refused before Mill's launcher acts on it"),
      redirected.status == 2 && redirected.err.contains("redirected mill daemon directory is refused") &&
        run.millDaemons(workspace).isEmpty,
      s"exit ${redirected.status}, daemons: ${run.millDaemons(workspace).mkString(" ")}; ${redirected.lastErr}")

    // A daemon of yours, started from a terminal outside any launch, is ended after its start-time check, once idle,
    // before the runner's daemon starts, and the channel log says so.
    // - The row first shuts the runner's own daemon down through Mill's own command, because only a start meets a
    //   foreign daemon.
    // - Then an unconfined ./mill leaves a daemon, twice: once with a JAVA_OPTS that the closed environment lacks, so
    //   that its fingerprint differs from the runner's, and once with none, so that it matches. Each time, the next
    //   channel command ends that daemon and starts the runner's.
    def foreignRow(label: String, environment: Map[String, String]): Unit =
      mill("shutdown", 300, "shutdown")
      foreignCommand(workspace, environment, "./mill", "version")
      val foreign = run.millDaemons(workspace).headOption
      val endedBefore = ch.count("ended the mill daemon")
      val result = mill("foreign", 600, "version")
      val ours = daemonInGroup(ch.record("daemon-mill", workspace), workspace)
      run.check(row(label), foreign.nonEmpty && !foreign.exists(isAlive) && result.ok &&
          ch.count("ended the mill daemon") > endedBefore && ours.nonEmpty && !foreign.exists(ours.contains),
        s"foreign ${foreign.mkString} ${if foreign.exists(isAlive) then "alive" else "gone"}, exit ${result.status}, " +
          s"ours ${ours.mkString(" ")}")
    foreignRow("a mill daemon of yours, mismatched, is ended once idle before the runner's starts",
      Map("JAVA_OPTS" -> "-Dko.run-on-host.foreign=1"))
    foreignRow("a mill daemon of yours, matching, is ended once idle before the runner's starts", Map.empty)

    // A daemon of yours that runs a command, seen as an established connection on its port, is left until its client
    // disconnects. The channel command waits, and completes once the daemon is idle or gone; a client's disconnect
    // mid-command ends the daemon, as above.
    mill("shutdown2", 300, "shutdown")
    val busy = foreignStart(s"foreign-run-$id", workspace, "./mill", "run", "sleep", tag)
    within(300, intervalMillis = 500)(busy.output.contains("fixture-main"))
    val busyForeign = run.millDaemons(workspace).headOption
    val busyShim = ch.startShim(s"$id-busy", workspace, Seq("mill", "version"))
    Thread.sleep(20_000)
    val busyWaiting = busyShim.isAlive
    val busyAlive = busyForeign.exists(isAlive)
    busy.process.destroy()
    run.command("/usr/bin/pkill", "-f", fixtureSleep)
    busyShim.waitFor()
    val busyResult = ch.outputOf(s"$id-busy").copy(status = busyShim.exitValue)
    ch.settled()
    val busyOurs = daemonInGroup(ch.record("daemon-mill", workspace), workspace)
    run.check(row("a mill daemon of yours mid-command is left until its client disconnects"),
      busyForeign.nonEmpty && busyWaiting && busyAlive && busyResult.ok && !busyForeign.exists(isAlive) &&
        busyOurs.nonEmpty && !busyForeign.exists(busyOurs.contains),
      s"foreign ${busyForeign.mkString} alive while busy: $busyAlive, command waiting: $busyWaiting, exit " +
        s"${busyResult.status}, ours ${busyOurs.mkString(" ")}")

    // A daemon of yours that stays busy past the bound (RunOnHostMillDaemons.ForeignIdleDeadlineMillis): the runner
    // refuses the command, naming the daemon, and leaves the daemon and its build alone. The row shuts the runner's
    // daemon down first: a ./mill of yours with matching settings attaches to a live daemon of the launch's, and the
    // row needs a daemon of its own to be busy.
    mill("shutdown3", 300, "shutdown")
    val bound = foreignStart(s"foreign-run2-$id", workspace, "./mill", "run", "sleep", tag)
    within(300, intervalMillis = 500)(bound.output.contains("fixture-main"))
    val boundForeign = run.millDaemons(workspace).headOption
    val refused = mill("bound", 300, "version")
    val boundAlive = boundForeign.exists(isAlive)
    bound.process.destroy()
    run.command("/usr/bin/pkill", "-f", fixtureSleep)
    boundForeign.foreach(pid => within(60, intervalMillis = 500)(!isAlive(pid)))
    boundForeign.foreach(pid => ProcessHandle.of(pid).ifPresent(_.destroy()))
    run.check(row("a mill daemon of yours busy past the bound is refused, and left alive"),
      boundForeign.nonEmpty && refused.status == 2 && boundAlive && refused.err.contains("has been running a command"),
      s"foreign ${boundForeign.mkString} alive after: $boundAlive, exit ${refused.status}: ${refused.lastErr}")
    ch.settled()

  // --- gradle -------------------------------------------------------------------------------------------------------

  /** The gradle daemons of the "yours" row, which run unconfined in a registry under the run's directory, found by
    * their log open there (DaemonMain). */
  private def yourGradleDaemons: Vector[Long] =
    run.pids("org.gradle.launcher.daemon.bootstrap.GradleDaemon").filter: pid =>
      run.command("/usr/sbin/lsof", "-a", "-p", pid.toString, "-Fn").linesIterator
        .exists(_.startsWith(s"n${out / s"your-registry-${ch.name}"}/"))

  /**
   * The launch's gradle daemons (doc/run-on-host-internals.md, "Gradle"): Gradle's own client starts the daemon in
   * the launch's registry under the runner's tmp/, and later clients match the daemon there. The runner records each
   * daemon after every command and ends the records' groups with its session (RunOnHostGradleDaemons). The fixture's
   * `run` prints the TMPDIR that the forked JVM sees and, with `sleep`, stays up for the cancel and teardown rows.
   */
  def gradleRows(target: Emitted): Unit =
    val workspace = target.target.workspace
    val id = target.target.id
    val release = wrapperRelease(workspace / "gradle" / "wrapper" / "gradle-wrapper.properties", "gradle")
      .getOrElse("unread")
    def gradle(name: String, timeoutSeconds: Int, arguments: String*): Shimmed =
      val result = ch.run(s"$id-$name", workspace, "gradle" +: arguments, timeoutSeconds)
      ch.settled()
      result
    def row(text: String) = s"channel: gradle $release: $text"
    transcript.step(s"gradle $release's daemons, through the channel")

    val build = gradle("build", 900, "build")
    val daemonRecord = ch.gradleRecords.headOption.getOrElse("")
    val daemon = ch.gradleDaemons.headOption
    val help = gradle("help", 300, "help")
    run.check(row("gradle build starts a daemon in the launch's registry, and the next command reuses it"),
      build.ok && help.ok && daemon.nonEmpty && daemon.map(_.toString).contains(leaderOf(daemonRecord)) &&
        alive(daemonRecord) && ch.gradleRecords == Vector(daemonRecord) && ch.gradleDaemons.size == 1 &&
        build.out.contains("BUILD SUCCESSFUL"),
      s"exits ${build.status}/${help.status}, daemon ${daemon.mkString}, records: ${ch.gradleRecords.mkString(" ")}, " +
        s"all: ${ch.gradleDaemons.mkString(" ")}")

    // Gradle unpacks its native libraries under the user home and loads them from there: the daemon has one mapped,
    // from the directory that the profile grants read-write. The launch's user home belongs to the runner's workspace
    // and lies under its run-on-host cache (RunOnHostPrereqs.gradleUserHomeOf); the launcher gives it its name.
    val native = daemon.toVector.flatMap(pid => run.command("/usr/sbin/lsof", "-p", pid.toString).linesIterator)
      .find(_.contains("/gradle-user-home/native/")).map(_.split("\\s+").last)
    run.check(row("the daemon maps Gradle's native libraries from the user home's read-write grant"), native.nonEmpty,
      native.map(path => Path.of(path).getFileName.toString)
        .getOrElse(s"nothing under a gradle-user-home/native/ mapped in daemon ${daemon.mkString}"))

    // The toolchain inventory holds the launch's JDK alone, with auto-detection and auto-download off
    // (RunOnHostSandbox.gradleCommand). A project that asks for another feature version fails and names the version,
    // before any denial could.
    val granted = "java.specification.version = (\\d+)".r
      .findFirstMatchIn(run.command(javaBinary, "-XshowSettings:properties", "-version")).map(_.group(1))
    val other = if granted.contains("21") then "17" else "21"
    val toolchain = gradle("toolchain", 600, "compileJava", s"-PcheckToolchain=$other")
    val said = (toolchain.out.linesIterator ++ toolchain.err.linesIterator).find(_.toLowerCase.contains("toolchain"))
    run.check(row("a toolchain the project asks for, not the launch's JDK, fails by name"),
      !toolchain.ok && said.nonEmpty && !toolchain.has("Operation not permitted"),
      said.getOrElse(s"exit ${toolchain.status}: ${toolchain.lastErr}").take(70))

    // A daemon of yours lives in a registry that the launch does not name, so the launch's commands neither attach to
    // it nor end it. The fixture's own gradlew starts and stops it unconfined, in a registry of this run's. The
    // registry is not your home's, where `--stop` would stop every daemon of yours of that version
    // (DaemonStopClient), unrelated builds' included.
    val registry = s"-Dorg.gradle.daemon.registry.base=${out / s"your-registry-${ch.name}"}"
    val started = foreignCommand(workspace, Map.empty, "./gradlew", "help", registry)
    val yours = yourGradleDaemons.headOption
    val own = gradle("own", 300, "help")
    val yoursAlive = yours.exists(isAlive)
    val launchs = ch.gradleDaemons
    foreignCommand(workspace, Map.empty, "./gradlew", "--stop", registry)
    run.check(row("a gradle daemon of yours, in a registry of your own, is neither attached to nor ended"),
      yours.nonEmpty && yoursAlive && own.ok && launchs.nonEmpty &&
        !ch.gradleRecords.exists(record => yours.map(_.toString).contains(leaderOf(record))),
      if own.ok && yoursAlive then s"yours ${yours.mkString} untouched; the launch's ${launchs.mkString(" ")}"
      else s"yours ${yours.mkString} alive after: $yoursAlive, exit ${own.status}, the launch's: " +
        s"${launchs.mkString(" ")}; ${started.text.linesIterator.toVector.lastOption.getOrElse("")}")

    // On a client disconnect mid-build, Gradle cancels the build and, if the daemon is still busy after its ten-second
    // grace, stops the daemon (DaemonStateCoordinator, WatchForDisconnection). The next command attaches to a daemon or
    // starts one, and the records follow: the runner forgets a stopped daemon's record and writes a fresh daemon's.
    val cancelled = ch.startShim(s"$id-cancel", workspace, Seq("gradle", "run", s"--args=sleep $tag"))
    val ready = within(300, intervalMillis = 500)(ch.outputOf(s"$id-cancel").out.contains("fixture-main") ||
      !cancelled.isAlive) && cancelled.isAlive
    val cancelDaemon = ch.gradleDaemons.headOption
    ch.killShim(cancelled)
    ch.settled()
    within(60, intervalMillis = 500)(run.pids(fixtureSleep).isEmpty)
    val leftFork = run.pids(fixtureSleep)
    run.info("forked run JVM after the cancel", if leftFork.isEmpty then "gone" else s"alive (${leftFork.mkString(" ")
      }); killed")
    leftFork.foreach(pid => ProcessHandle.of(pid).ifPresent(_.destroy()))
    val after = gradle("after-cancel", 300, "help")
    run.check(row("after a cancelled gradle command, the next command runs, the records following the daemons"),
      ready && cancelDaemon.nonEmpty && after.ok && ch.gradleDaemons.size == 1 && ch.gradleRecords.size == 1 &&
        alive(ch.gradleRecords.head),
      s"ready to cancel: $ready; daemon before ${cancelDaemon.mkString}, exit ${after.status}, daemons after: " +
        s"${ch.gradleDaemons.mkString(" ")}, records: ${ch.gradleRecords.mkString(" ")}")

  // --- The channel's ends -----------------------------------------------------------------------------------------

  def endRows(): Unit =
    transcript.step("the channel's ends")
    val refused = ch.run("refused", Path.of("/private/tmp"), Seq("sbt", "about"), 120)
    run.check("channel: a working directory outside the workspace is refused",
      refused.status == 2 && refused.err.contains("CHANNEL_UNAVAILABLE"), s"exit ${refused.status}: ${refused.lastErr}")

    // The shim dies. The runner sees the descriptor close, ends the command's client group, and leaves the warm
    // server, as stock sbt does on a disconnect (doc/run-on-host.md). So the command's own group and directory go,
    // while the runner, its proxy and its warm server stay. The teardown appends the command's logs to the channel log
    // before it removes the command's directory (appendSessionLogs). This runner's server is warmed first.
    ch.run("warm", root, Seq("sbt", "about"), 900)
    ch.settled()
    val dying = ch.startShim("kill", root, Seq("sbt", "compile"))
    within(300, intervalMillis = 500)(run.commandsNow > 0)
    val serverBefore = ch.record("server-sbt", root)
    ch.killShim(dying)
    ch.settled()
    run.check("channel: a dead shim ends the running command",
      run.commandsNow == 0 && ch.commandServers().isEmpty && ch.commandProxies().isEmpty && ch.alive &&
        ch.count("ended by signal") > 0 && alive(ch.record("proxy-sbt", root)) && serverBefore.nonEmpty &&
        alive(serverBefore),
      s"commands: ${run.commandsNow}, command servers: ${ch.commandServers().mkString(" ")}, runner " +
        s"${if ch.alive then "alive" else "gone"}, logs kept: ${ch.count("ended by signal")}, " +
        s"warm server: $serverBefore ${aliveWord(serverBefore)}")

    // The sandbox dies, and every exec dies with it, the shim included. The runner ends the command and, with the
    // container gone, ends itself, its session, server and proxy with it. With gradle, the command is a `run` whose
    // forked JVM sleeps in the daemon's group, which is the group that the runner's end signals behind the daemon's
    // record.
    val gradleTarget = emitted.get("gradle")
    val gradleEnd = "channel: the runner's end takes the gradle daemon, and the JVM its build forked"
    val dead = gradleTarget match
      case Some(target) =>
        val started = ch.startShim("dead", target.target.workspace, Seq("gradle", "run", s"--args=sleep $tag"))
        within(300, intervalMillis = 500)(ch.outputOf("dead").out.contains("fixture-main"))
        started
      case None =>
        val started = ch.startShim("dead", root, Seq("sbt", "compile"))
        within(300, intervalMillis = 500)(run.commandsNow > 0)
        started
    val gradleRunDaemon = gradleTarget.flatMap(_ => run.launchGradleDaemons.headOption)
    val runnerSession = ch.session
    Files.writeString(ch.running, "false\n")
    ch.killShim(dead)
    ch.killExecs()
    ch.settled()
    within(60, intervalMillis = 500)(!ch.alive)
    run.check("channel: a dead sandbox ends the channel, its command and the runner's runtimes",
      run.commandsNow == 0 && run.sbtServers(root).isEmpty && millWorkspaces.forall(run.millDaemons(_).isEmpty) &&
        !ch.alive && run.strayProxies.isEmpty && runnerSession.exists(session => !Files.exists(session)),
      s"commands: ${run.commandsNow}, servers: ${run.sbtServers(root).mkString(" ")}, runner " +
        s"${if ch.alive then "alive" else "gone"}, proxies: ${run.strayProxies.mkString(" ")}, session " +
        s"${runnerSession.map(session => if Files.exists(session) then "kept" else "gone").getOrElse("unknown")}")
    if gradleTarget.isEmpty then run.skip(gradleEnd, "needs gradle")
    else
      val forked = run.pids(fixtureSleep)
      run.check(gradleEnd, gradleRunDaemon.nonEmpty && run.launchGradleDaemons.isEmpty && forked.isEmpty,
        s"daemon ${gradleRunDaemon.mkString} ${if gradleRunDaemon.exists(isAlive) then "alive" else "gone"}, " +
          s"daemons: ${run.launchGradleDaemons.mkString(" ")}, forked: ${forked.mkString(" ")}")
      run.command("/usr/bin/pkill", "-f", fixtureSleep)
    removeTree(ch.directory)

    runnerEnd("channel: TERM to the runner ends its command before the runner exits", "TERM", gradleTarget)
    runnerEnd("channel: a killed runner's command ends with it, and its server with the next start", "KILL",
      gradleTarget)

  /**
   * The runner's own end mid-command:
   *
   *   - TERM: the runner's hook ends the supervisor and waits for the supervisor's teardown, then ends the runner's
   *     session, its server and its proxy. So the moment the runner is gone, the command's directory, the server and
   *     every proxy are gone too.
   *   - KILL: nothing waits, but the supervisor's stdin is the runner's pipe, and the pipe's EOF ends the command by
   *     the same teardown. The runner's server and proxy stay, recorded in its session, until the next start scavenges
   *     them by their records; here the next start is the supervisor's recovery run.
   *   - With gradle, TERM arrives during the launch's first gradle build. The build's daemon is unobserved and still
   *     cancelling when the teardown looks, so the teardown must find the daemon then. On KILL nothing observes, so the
   *     daemon is one that a completed command recorded, and the next start's scavenge ends it by that record.
   *   - The shim is left blocked on its exit read (no timeout(1) here), and the row kills it after.
   */
  private def runnerEnd(label: String, signal: String, gradleTarget: Option[Emitted]): Unit =
    val before = ch.count("ended by signal")
    if !ch.start() then
      run.fail(label, "the runner made no FIFOs")
      return
    val blocked = gradleTarget match
      case Some(target) if signal == "TERM" =>
        val started = ch.startShim(s"runner-$signal", target.target.workspace,
          Seq("gradle", "run", s"--args=sleep $tag"))
        within(300, intervalMillis = 500)(ch.outputOf(s"runner-$signal").out.contains("fixture-main"))
        started
      case _ =>
        gradleTarget.foreach: target =>
          ch.run(s"runner-$signal-gradle", target.target.workspace, Seq("gradle", "help"), 600)
          ch.settled()
        val started = ch.startShim(s"runner-$signal", root, Seq("sbt", "compile"))
        within(300, intervalMillis = 500)(run.commandsNow > 0)
        started
    ch.stop(signal)
    val proxiesEnded =
      if signal == "KILL" then
        ch.settled()
        val orphan = run.strayProxies
        val orphanServer = run.sbtServers(root)
        val recovered = run.supervisor("recover-runner", Program.Sbt, root, Seq("--version"))
        orphan.nonEmpty && orphanServer.nonEmpty &&
          recovered.text.matches("(?s).*scavenged r[0-9].*GroupEnded.*GroupEnded.*") && run.strayProxies.isEmpty
      else run.strayProxies.isEmpty
    run.check(label,
      run.commandsNow == 0 && run.sbtServers(root).isEmpty && millWorkspaces.forall(run.millDaemons(_).isEmpty) &&
        run.launchGradleDaemons.isEmpty && run.pids(fixtureSleep).isEmpty && proxiesEnded && !ch.alive &&
        ch.count("ended by signal") > before,
      s"commands: ${run.commandsNow}, servers: ${run.sbtServers(root).mkString(" ")}, gradle daemons: " +
        s"${run.launchGradleDaemons.mkString(" ")}, runner ${if ch.alive then "alive" else "gone"}, proxies " +
        s"ended: $proxiesEnded, logs kept: ${ch.count("ended by signal")} (before: $before)")
    ch.killShim(blocked)
    ch.killExecs()
    removeTree(ch.directory)

  // --- Planted rendezvous -----------------------------------------------------------------------------------------

  /**
   * A new launch adopts nothing that a portfile or a mill rendezvous file nominates.
   *
   *   - fixtures/deny's portfile names a live socket that is not sbt's derivation for the directory, so the runner
   *     refuses the request. The listener hears the liveness probe's connect and no byte: nothing speaks the shutdown
   *     protocol to it.
   *   - The mill rendezvous files name this check's TCP listener's port and its sleep's pid. The new runner connects
   *     to nothing that they name and signals nothing, and the client reaches the runner's own daemon.
   *   - The listeners are the check's and record what reaches them.
   */
  def plantedRows(): Unit =
    transcript.step("planted rendezvous")
    val plantedRow = "channel: a planted portfile nominates nothing: refused, no shutdown spoken"
    val plantedMillRow = "channel: a new launch adopts nothing planted in out/mill-daemon"
    // A socket path must fit macOS's 104 bytes, so it lies under /tmp rather than the run's directory.
    val socketDir = Files.createTempDirectory(Path.of("/tmp"), "run-on-host-planted")
    val socket = socketDir / "s"
    val listener = CountingListener(socket)
    // The control: bytes that the check sends itself must be counted, or "no bytes" below would prove nothing.
    val control = "control".getBytes
    scala.util.Using.resource(java.nio.channels.SocketChannel.open(UnixDomainSocketAddress.of(socket)))(
      _.write(ByteBuffer.wrap(control)))
    val controlCounted = listener.observed(1) && listener.bytes == control.length && listener.failure.isEmpty
    listener.reset()
    val tcp = ServerSocket()
    tcp.bind(InetSocketAddress(InetAddress.getLoopbackAddress, 0))
    val tcpConnects = AtomicInteger()
    val tcpAcceptor = Thread(() =>
      try while true do { tcp.accept().close(); tcpConnects.incrementAndGet() }
      catch case _: java.io.IOException => ())
    tcpAcceptor.setDaemon(true)
    tcpAcceptor.start()
    val sleeper = ProcessBuilder("/bin/sleep", "3600").start()
    val activeJson = checkout.denyFixture / "project" / "target" / "active.json"
    run.cleanup.add("remove the planted rendezvous"):
      Files.deleteIfExists(activeJson)
      listener.close()
      tcp.close()
      sleeper.destroy()
      removeTree(socketDir)
    Files.createDirectories(activeJson.getParent)
    Files.writeString(activeJson, s"""{"uri":"local://$socket"}""")
    daemonMill.foreach: target =>
      val rendezvous = Files.createDirectories(target.target.workspace / "out" / "mill-daemon")
      val savedPort = readTrimmed(rendezvous / "socketPort")
      run.cleanup.add(s"restore ${rendezvous / "socketPort"}")(Files.writeString(rendezvous / "socketPort", savedPort))
      Files.writeString(rendezvous / "socketPort", tcp.getLocalPort.toString)
      Files.writeString(rendezvous / "processId", sleeper.pid.toString)
    if !ch.start() then run.fail(plantedRow, "the runner made no FIFOs")
    else
      val refused = ch.run("planted", checkout.denyFixture, Seq("sbt", "about"), 300)
      ch.settled()
      val complete = listener.observed(1)
      run.check(plantedRow, controlCounted && complete && listener.failure.isEmpty && refused.status == 2 &&
          refused.err.contains("a live sbt server holds") && listener.bytes == 0,
        s"exit ${refused.status}: ${refused.lastErr}; ${listener.connects} connects, ${listener.bytes} bytes; " +
          s"control counted: $controlCounted, reads complete: $complete" +
          listener.failure.fold("")(ex => s", listener failed: $ex"))
      daemonMill.foreach: target =>
        val workspace = target.target.workspace
        val adopted = ch.run("planted-mill", workspace, Seq("mill", "version"), 600)
        ch.settled()
        val ours = daemonInGroup(ch.record("daemon-mill", workspace), workspace)
        run.check(plantedMillRow, adopted.ok && ours.nonEmpty && tcpConnects.get == 0 && sleeper.isAlive,
          s"daemon ${ours.mkString(" ")}; the planted port heard ${tcpConnects.get} connects, the pid " +
            s"${if sleeper.isAlive then "lives" else "is gone"}")
      ch.stop("TERM")
      ch.killExecs()
      removeTree(ch.directory)
    Files.deleteIfExists(activeJson)
