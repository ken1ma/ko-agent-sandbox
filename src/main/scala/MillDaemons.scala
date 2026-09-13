// The launch's mill daemon (run-on-host.md "mill"): started by the project's stock bootstrap under
// the daemon profile — whose denied connect leaves the daemon behind in the starter's group —
// identified there by its command line, proved by pid and start time, and granted the one
// port `lsof` shows it listening on, which `out/mill-daemon/socketPort` may name but
// never authorizes. The stock bootstrap, not a helper over `ServerLauncher(openSocket = false)`:
// the launcher writes the daemon's fingerprint (`DaemonConfig`) with the code every client
// compares it with, where a helper would reproduce `MillLauncherMain.main0`'s preamble against
// `mill.launcher` internals pinned to one version, and a fingerprint that differs is the mismatch
// on which the next client ends the daemon. The cost is the denied connect's ten-second retry
// (TODO.md, "ending the mill starter once the daemon listens"); the helper would return for a Mill
// version whose daemon does not survive the starter's exit. Before the broker's starts, a daemon
// of the user's own for the build directory is ended by proof once idle, as the user's sbt server
// is shut down by protocol.
// macOS only, like the wrapper: the observations are ps, pgrep and lsof, so BrokerRuntimes takes
// `start` as a seam and the profile gate measures it.

package agentsandbox.launcher

import java.io.IOException
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, LinkOption, Path}

import scala.jdk.CollectionConverters.*

import RunOnHostSandbox.{DaemonStart, ServerStartSilenceMillis}
import RunOnHostSession.{Processes, Session}
import RunOnHostSession.HostProcesses.lines

object MillDaemons:

  /** A daemon on the host: its pid with the `ps -o lstart=` start time every later reuse or
    * signal proves first, and the port it listens on. */
  case class Daemon(pid: Long, start: String, port: Int)

  /** The daemon's main class, on its command line and nowhere on the launcher's. */
  val DaemonMain = "mill.daemon.MillDaemonMain"

  /** Where the starter's stdout and stderr go: its "Mill launcher failed" trace after the denied
    * connect is the noise of a start that worked, and the finding of one that did not. In the
    * session directory, beside the sbt servers' logs, for the same reason (serverLog). */
  def starterLog(session: Session, hash: String): Path = session.directory.resolve(s"daemon-mill-$hash.log")

  /** How long a foreign daemon may stay busy before the start is refused: the bound the user's
    * sbt server gets for its shutdown (shutdownForeignServer), for the same reason. */
  val ForeignIdleDeadlineMillis = 120_000L

  /** The starter's connect retry (`MillServerLauncher.serverInitWaitMillis`, 10 s): the daemon
    * is up and listening within it, and `socketPort` written, so a port not verifiable within
    * this bound after the starter's exit is a daemon that is not listening. */
  val PortDeadlineMillis = 10_000L

  /**
   * The daemon of `start`'s runtime: no foreign daemon holds the build directory — the user's
   * own is ended here — then the starter runs, registered at `start.record`, and the daemon it
   * left in that group is proved and its port verified. A daemon that appeared between the
   * foreign check and the starter's lock is attached to by the starter, whose group then holds
   * no daemon: it is ended like the first and the starter runs once more. A start that fails
   * leaves no group behind its record (the caller discards it).
   */
  def start(
    session: Session,
    authority: SeatbeltProfile.RuntimeAuthority,
    forwards: Vector[(String, String)],
    processes: Processes,
    log: String => Unit,
    start: DaemonStart,
  ): Either[String, Daemon] =
    val assembled = start.assembled
    val prereqs = assembled.prereqs
    val output = starterLog(session, start.hash)
    def said =
      s"the starter's output:\n${RunOnHostSandbox.sessionLogTail(output, 4096).getOrElse("(nothing was written)\n")}"
    def attempt(retriesLeft: Int, profileFile: Path): Either[String, Daemon] =
      for
        spawn <- spawnStarter(session, forwards, start, profileFile, output)
        _ <- awaitStarter(spawn, start, output)
        daemon <- memberDaemon(start.record, processes) match
          case Some((pid, daemonStart)) =>
            verifiedPort(start.buildDirectory, pid).map(port => Daemon(pid, daemonStart, port))
          case None if retriesLeft > 0 && foreignDaemons(start.buildDirectory, processes).nonEmpty =>
            retire(start.record, processes)
            endForeign(start.buildDirectory, processes, log).flatMap(_ => attempt(retriesLeft - 1, profileFile))
          case None => Left(s"the mill starter left no daemon in its group; $said")
      yield daemon
    for
      _ <- endForeign(start.buildDirectory, processes, log)
      profile <- SeatbeltProfile.render(
        SeatbeltProfile.ProfileInputs(
          prereqs = prereqs,
          sessionTmp = session.tmp,
          distribution = assembled.distribution,
          sbtGlobal = assembled.sbtGlobalGranted,
          ivyHome = assembled.ivyHomeGranted,
          gradleUserHome = assembled.gradleUserHomeGranted,
          m2Repository = assembled.m2RepositoryGranted,
          proxyPort = start.runtime.proxyPort,
          runtime = authority,
          network = SeatbeltProfile.Network.MillDaemon,
        ),
      )
      profileFile <-
        try Right(Files.writeString(session.directory.resolve(s"daemon-mill-${start.hash}.sb"), profile, UTF_8))
        catch case ex: IOException => Left(s"writing the daemon profile: ${ex.getMessage}")
      _ = discardForeignMemo(start.buildDirectory, prereqs.coursierV1, confined(profileFile)).foreach(log)
      daemon <- attempt(retriesLeft = 1, profileFile)
    yield daemon

  /** `./mill version` from the build directory — the stock bootstrap, `MILL_VERSION` naming the
    * JVM launcher — as a registered spawn under the daemon profile, stdin `/dev/null`, its output
    * to the starter log, the closed environment with the broker's `tmp/` as its temporary and
    * socket directory, which the daemon inherits. */
  private def spawnStarter(
    session: Session, forwards: Vector[(String, String)], start: DaemonStart, profileFile: Path, output: Path,
  ): Either[String, Process] =
    val assembled = start.assembled
    try
      val builder = ProcessBuilder(
        RunOnHostSession.registeredSpawn(
          start.record,
          Seq("/usr/bin/sandbox-exec", "-f", profileFile.toString)
            ++ Seq(start.buildDirectory.resolve("mill").toString, "version"),
        )*,
      )
      builder.directory(start.buildDirectory.toFile)
      builder.redirectInput(ProcessBuilder.Redirect.from(java.io.File("/dev/null")))
      builder.redirectOutput(ProcessBuilder.Redirect.appendTo(output.toFile))
      builder.redirectError(ProcessBuilder.Redirect.appendTo(output.toFile))
      builder.environment.clear()
      builder.environment.putAll(
        RunOnHostSandbox.commandEnvironment(
          name => Option(System.getenv(name)), forwards, assembled.prereqs, assembled.sbtGlobal, assembled.ivyHome,
          assembled.gradleUserHome, assembled.m2Repository, assembled.millDownloads, assembled.millLauncherVersion,
          session.tmp, session.tmp, start.runtime.proxyPort, System.getProperty("user.name"),
        ).asJava,
      )
      Right(builder.start())
    catch case ex: IOException => Left(s"starting the mill starter: ${ex.getMessage}")

  /** The starter's end, whatever its status: the denied connect exits it nonzero by design. A
    * starter making no progress — neither its output nor the proxy log growing — for the bound
    * sbt's server start gets is a failed start; a first start resolves Mill's own daemon
    * classpath through the proxy, so the bound is on progress, not time. */
  private def awaitStarter(spawn: Process, start: DaemonStart, output: Path): Either[String, Unit] =
    val exit = RunOnHostSession.exitRecord(start.record)
    def sizes = (RunOnHostSandbox.logLength(output), RunOnHostSandbox.logLength(start.runtime.proxyLog))
    var last = sizes
    var since = System.nanoTime
    var result: Option[Either[String, Unit]] = None
    while result.isEmpty do
      val spawnEnded = !spawn.isAlive
      if Files.exists(exit) then result = Some(Right(()))
      else if spawnEnded then
        result = Some(Left(s"the mill starter's spawn ended (exit ${spawn.exitValue}) without registering it"))
      else
        val now = sizes
        if now != last then
          last = now
          since = System.nanoTime
        else if System.nanoTime - since > ServerStartSilenceMillis * 1_000_000 then
          result = Some(Left(
            s"the mill starter neither ended nor wrote anything, and the proxy log did not grow, for " +
              s"${ServerStartSilenceMillis / 1000}s",
          ))
        else Thread.sleep(100)
    result.get

  /** The daemon in the record's group: the member whose command line names DaemonMain, with the
    * start time that proves it from now on. */
  private def memberDaemon(record: Path, processes: Processes): Option[(Long, String)] =
    val parsed =
      try RunOnHostSession.parseRecord(Files.readString(record, UTF_8))
      catch case _: IOException => None
    parsed.flatMap: leader =>
      lines("ps", "-ww", "-o", "pid=,command=", "-g", leader.pgid.toString)
        .collectFirst { case Member(pid, command) if command.contains(DaemonMain) => pid.toLong }
        .flatMap(pid => processes.startOf(pid).map(pid -> _))

  private val Member = raw"\s*(\d+)\s+(.*)".r

  /** The port a client is confined to: `out/mill-daemon/socketPort`'s candidate — an integer in
    * port range, nothing more — verified as a port the proved daemon listens on. The
    * file is the build's to write, so a candidate the daemon does not listen on is a refusal,
    * and so is no candidate at all: the client reads the same file and would fail anyway. */
  private def verifiedPort(buildDirectory: Path, pid: Long): Either[String, Int] =
    val file = buildDirectory.resolve("out").resolve("mill-daemon").resolve("socketPort")
    def candidate = (try Some(Files.readString(file, UTF_8).trim) catch case _: IOException => None)
      .flatMap(_.toIntOption).filter(port => port >= 1 && port <= 65535)
    val deadline = System.nanoTime + PortDeadlineMillis * 1_000_000
    var found: Option[Int] = None
    var listening = Vector.empty[Int]
    while found.isEmpty && System.nanoTime < deadline do
      listening = listeningPorts(pid)
      found = candidate.filter(listening.contains)
      if found.isEmpty then Thread.sleep(200)
    val ports = if listening.isEmpty then "no port" else listening.mkString(", ")
    found.toRight(s"the daemon (pid $pid) listens on $ports, and $file names ${candidate.getOrElse("no port")}")

  /** The TCP ports `lsof` shows the pid listening on. */
  private def listeningPorts(pid: Long): Vector[Int] =
    lines("lsof", "-a", "-p", pid.toString, "-iTCP", "-sTCP:LISTEN", "-nP", "-Fn")
      .collect { case Listener(port) => port.toInt }

  private val Listener = raw"n(?:127\.0\.0\.1|localhost|\[::1\]):(\d+)".r

  /**
   * Whether the pid has no established TCP connection: Some(false) while a client runs a
   * command on it, None when the observation is incomplete — lsof exiting nonzero, writing to
   * stderr, or listing no socket, though a live daemon always holds its listener — which is
   * never taken for idle.
   */
  private def idle(pid: Long): Option[Boolean] =
    try
      val process = ProcessBuilder("lsof", "-a", "-p", pid.toString, "-iTCP", "-nP", "-FT").start()
      val output = String(process.getInputStream.readAllBytes(), UTF_8)
      val errors = String(process.getErrorStream.readAllBytes(), UTF_8)
      val states = output.linesIterator.filter(_.startsWith("TST=")).map(_.drop(4)).toVector
      if process.waitFor() != 0 || errors.nonEmpty || states.isEmpty then None
      else Some(!states.contains("ESTABLISHED"))
    catch case _: IOException => None

  /** The launcher's classpath memo (`CoursierClient.cached`): JSON, the key then the paths. */
  private def memoFile(buildDirectory: Path): Path =
    buildDirectory.resolve("out").resolve("mill-daemon").resolve("cache").resolve("mill-daemon-classpath")

  private val MemoPath = """"(/(?:[^"\\]|\\.)*)"""".r

  /** A file read and a file deletion under the profile: what a build could do to the file, and no
    * more, so a link planted under `out/` after rendezvousIsOwn — by the bootstrap script, or by
    * build code in a daemon of yours the start waited on — sends neither past the build's own
    * writable roots. The read is the file's text when the file is one, else None. */
  case class Confined(read: Path => Option[String], delete: Path => Boolean)

  private def confined(profileFile: Path): Confined =
    def run(command: String*): Option[String] =
      try
        val process = ProcessBuilder(("/usr/bin/sandbox-exec" +: "-f" +: profileFile.toString +: command)*)
          .redirectError(ProcessBuilder.Redirect.DISCARD).start()
        val output = String(process.getInputStream.readAllBytes(), UTF_8)
        Option.when(process.waitFor() == 0)(output)
      catch case _: IOException => None
    Confined(
      read = file => run("/bin/cat", "--", file.toString),
      delete = file => run("/bin/rm", "-f", "--", file.toString).isDefined,
    )

  /**
   * Delete the memo when it names a path outside the cache the profile grants, so the launcher
   * resolves afresh into that cache. Mill keeps a memo while every path it names exists
   * (`CoursierClient.resolveMillDaemon`, `os.exists`), and Seatbelt answers an existence test
   * for a path it denies reading — measured: `Files.exists` true, the open `EPERM` — so a memo
   * from an unconfined run, or from this directory served as another project's build directory,
   * would start a daemon on jars its JVM cannot open, which dies before it listens. Read and
   * deleted through `confined`, and only as a regular file. What was done, for the log.
   */
  def discardForeignMemo(buildDirectory: Path, coursierV1: Path, confined: Confined): Option[String] =
    val memo = memoFile(buildDirectory)
    val named = buildDirectory.relativize(memo)
    if !Files.isRegularFile(memo, LinkOption.NOFOLLOW_LINKS) then None
    else
      confined.read(memo).flatMap: text =>
        val paths = MemoPath.findAllMatchIn(text).map(_.group(1)).toVector
        paths.find(path => !Path.of(path).startsWith(coursierV1)).map: foreign =>
          if confined.delete(memo) then s"discarded $named: it names $foreign, outside $coursierV1"
          else s"could not discard $named, which names $foreign, outside $coursierV1"

  /**
   * The command's rendezvous directory is its own build directory's: `out`, `out/mill-daemon`
   * and every entry directly in it are neither links nor files with a second name. Mill's
   * launcher acts on that directory as it finds it — removes a `processId` whose fingerprint
   * differs, ending the daemon it names, and probes `daemonLock` — so a link there would have it
   * act on another build directory's daemon, past the ownership and idleness checks, which are
   * keyed by this directory; a second name for another directory's `processId` would do the same
   * through one inode. Checked before every mill command, under the build lock.
   */
  def rendezvousIsOwn(buildDirectory: Path): Either[String, Unit] =
    val out = buildDirectory.resolve("out")
    val daemonDir = out.resolve("mill-daemon")
    val entries =
      if !Files.isDirectory(daemonDir, LinkOption.NOFOLLOW_LINKS) then Vector.empty
      else
        try HostCommands.directoryEntries(daemonDir)
        catch case _: IOException => Vector.empty
    def refused(path: Path, what: String) =
      Left(
        s"$path is $what; a redirected mill daemon directory is refused, since Mill's launcher would act on " +
          "another build directory's daemon through it",
      )
    (Seq(out, daemonDir) ++ entries).find(Files.isSymbolicLink) match
      case Some(link) => refused(link, "a symlink")
      case None =>
        entries.find(hasSecondName) match
          case Some(file) => refused(file, "a file with more than one name")
          case None       => Right(())

  private def hasSecondName(file: Path): Boolean =
    try
      Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) &&
        (Files.getAttribute(file, "unix:nlink", LinkOption.NOFOLLOW_LINKS) match
          case links: Integer => links > 1
          case _              => false)
    catch case _: (IOException | UnsupportedOperationException | IllegalArgumentException) => false

  /** The mill daemons on the host working in the build directory's `out/mill-daemon` — the
    * daemon's cwd is its `sandbox` beneath it (MillProcessLauncher.configureRunMillProcess) —
    * with their start times. The pid is the process table's, never a file's. */
  def foreignDaemons(buildDirectory: Path, processes: Processes): Vector[(Long, String)] =
    val daemonDir = buildDirectory.resolve("out").resolve("mill-daemon")
    lines("pgrep", "-f", "--", DaemonMain).flatMap(_.toLongOption).flatMap: pid =>
      val cwd = lines("lsof", "-a", "-p", pid.toString, "-d", "cwd", "-Fn").collectFirst {
        case line if line.startsWith("n") => Path.of(line.drop(1))
      }
      Option.when(cwd.exists(_.startsWith(daemonDir)))(pid).flatMap(pid => processes.startOf(pid).map(pid -> _))

  /**
   * End every foreign daemon of the build directory, each once idle and proved again — pid and
   * start time — immediately before its TERM, then KILL behind the same proof: a daemon holding
   * `out/mill-daemon` runs the build outside this launch's ownership, and the stock launcher
   * would attach to one whose fingerprint matches. One that stays busy past the bound, or whose
   * idleness cannot be observed, is a refusal naming it. Between the observation and the TERM a
   * terminal `./mill` can still connect; its build then dies with the daemon (run-on-host.md
   * "mill" states the window).
   */
  def endForeign(buildDirectory: Path, processes: Processes, log: String => Unit): Either[String, Unit] =
    val deadline = System.nanoTime + ForeignIdleDeadlineMillis * 1_000_000
    var result: Option[Either[String, Unit]] = None
    while result.isEmpty do
      foreignDaemons(buildDirectory, processes) match
        case Vector() => result = Some(Right(()))
        case found =>
          val ended = found.filter: (pid, start) =>
            idle(pid).contains(true) && processes.startOf(pid).contains(start) && {
              end(pid, start, processes)
              log(s"ended the mill daemon $pid of $buildDirectory: not this launch's, and idle")
              true
            }
          if ended.isEmpty then
            if System.nanoTime > deadline then
              val (pid, _) = found.head
              result = Some(Left(
                s"a mill daemon not this launch's (pid $pid) holds $buildDirectory and has been running a " +
                  s"command for ${ForeignIdleDeadlineMillis / 1000}s; retry when it is done, or run " +
                  "`./mill shutdown` there",
              ))
            else Thread.sleep(500)
    result.get

  /** TERM, then KILL after a grace, each behind the start-time proof; waits for the pid to go. */
  private def end(pid: Long, start: String, processes: Processes): Unit =
    def alive = processes.startOf(pid).contains(start)
    def signal(name: String): Unit =
      if alive then ProcessBuilder("/bin/kill", s"-$name", "--", pid.toString).start().waitFor()
    signal("TERM")
    val settled = (1 to 100).exists(_ => if !alive then true else { Thread.sleep(100); false })
    if !settled then
      signal("KILL")
      (1 to 50).exists(_ => if !alive then true else { Thread.sleep(100); false })

  /** A starter's group ended behind its leader, and its record and exit file removed, before the
    * same record name is spawned again: the failed starter's spawn is that group's live leader. */
  private def retire(record: Path, processes: Processes): Unit =
    RunOnHostSession.endRecordedGroup(record, processes)
    try
      Files.deleteIfExists(record)
      Files.deleteIfExists(RunOnHostSession.exitRecord(record))
    catch case _: IOException => ()
