// The launch's mill daemon (run-on-host.md "mill"): started by the project's stock bootstrap under
// the daemon profile — whose denied connect leaves the daemon behind in the starter's group —
// identified there by its command line, checked by pid and start time, and granted the one
// port `lsof` shows it listening on, which `out/mill-daemon/socketPort` may name but
// never authorizes. The stock bootstrap, not a helper over `ServerLauncher(openSocket = false)`:
// the launcher writes the daemon's fingerprint (`DaemonConfig`) with the code every client
// compares it with, where a helper would reproduce `MillLauncherMain.main0`'s preamble against
// `mill.launcher` internals pinned to one version, and a fingerprint that differs is the mismatch
// on which the next client ends the daemon. The connect is denied because the daemon inherits the
// starter's profile (SeatbeltProfile.Network.MillDaemon has why no outbound is granted); the
// starter is ended once its daemon is observed listening, so the denied connect's ten-second retry
// is not waited out. The helper would return for a Mill version whose daemon does not survive the
// starter's end. Before the broker's starts, a daemon of the user's own for the build directory
// is ended once idle, after its start-time check, as the user's sbt server is shut down by protocol.
// macOS only, like the wrapper: the observations are ps, pgrep and lsof, so BrokerRuntimes takes
// `start` as a parameter tests replace and the acceptance test measures it.

package agentsandbox.launcher

import java.io.IOException
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, LinkOption, Path}

import scala.jdk.CollectionConverters.*

import RunOnHostSandbox.{DaemonStart, ServerStartSilenceMillis}
import RunOnHostSession.{Processes, Record, Session}
import RunOnHostSession.HostProcesses.lines

object RunOnHostMillDaemons:

  /** A daemon on the host: its pid with the `ps -o lstart=` start time every later reuse or
    * signal checks first, and the port it listens on. */
  case class Daemon(pid: Long, start: String, port: Int)

  /** The daemon's main class, on its command line and nowhere on the launcher's. */
  val DaemonMain = "mill.daemon.MillDaemonMain"

  /** Where the starter's stdout and stderr go: a "Mill launcher failed" trace there marks a
    * starter the broker did not end — its daemon never listened, or the launcher reached its own
    * retry bound first — and is the finding when the start failed. In the session directory,
    * beside the sbt servers' logs, for the same reason (serverLog). */
  def starterLog(session: Session, hash: String): Path = session.directory.resolve(s"daemon-mill-$hash.log")

  /** How long a foreign daemon may stay busy before the start is refused: the bound the user's
    * sbt server gets for its shutdown (shutdownForeignServer), for the same reason. */
  val ForeignIdleDeadlineMillis = 120_000L

  /** The bound on observing the daemon listen on the port after the starter's exit: the launcher's connect retry
    * (`MillServerLauncher.serverInitWaitMillis`, 10 s), within which a daemon listens and
    * `socketPort` is written, so a port not verifiable this long after is a daemon that is not
    * listening. It matters for a starter that exited on its own; one the broker ended was ended
    * after that very observation. */
  val PortDeadlineMillis = 10_000L

  /**
   * The daemon of `start`'s runtime: no foreign daemon holds the build directory — the user's
   * own is ended here — then the starter runs, registered at `start.record`, is ended once the
   * daemon it spawned is observed listening (awaitStarter), and the daemon it left in that group
   * is identified by pid and start time and its port verified. A daemon that appeared between the
   * foreign check and the starter's lock is attached to by the starter, whose group then holds
   * no daemon: it is ended like the first and the starter runs once more. A start that fails
   * leaves no group behind its record (the caller discards it).
   */
  def start(
    session: Session,
    systemPaths: SeatbeltProfile.SystemPaths,
    forwards: Vector[(String, String)],
    processes: Processes,
    log: String => Unit,
    start: DaemonStart,
  ): Either[String, Daemon] =
    val assembled = start.assembled
    val prereqs = assembled.prereqs
    val output = starterLog(session, start.hash)
    val inputs = RunOnHostSandbox.runtimeInputs(
      assembled, session.tmp, start.runtime.proxyPort, systemPaths, forwards, SeatbeltProfile.Network.MillDaemon,
    )
    def said =
      s"the starter's output:\n${RunOnHostSandbox.sessionLogTail(output, 4096).getOrElse("(nothing was written)\n")}"
    def attempt(retriesLeft: Int, profileFile: Path): Either[String, Daemon] =
      for
        spawn <- spawnStarter(start, profileFile, inputs.environment, output)
        _ <- awaitStarter(spawn, start, output, processes, log)
        daemon <- memberDaemon(start.record) match
          case Some((pid, daemonStart)) =>
            verifiedPort(start.buildDirectory, pid).map(port => Daemon(pid, daemonStart, port))
          case None if retriesLeft > 0 && foreignDaemons(start.buildDirectory, processes).nonEmpty =>
            retire(session.directory.getParent, start.record, processes)
              .flatMap(_ => endForeign(start.buildDirectory, processes, log))
              .flatMap(_ => attempt(retriesLeft - 1, profileFile))
          case None => Left(s"the mill starter left no daemon in its group; $said")
      yield daemon
    for
      _ <- endForeign(start.buildDirectory, processes, log)
      profile <- SeatbeltProfile.render(inputs.profile)
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
    start: DaemonStart, profileFile: Path, environment: Map[String, String], output: Path,
  ): Either[String, Process] =
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
      builder.environment.putAll(environment.asJava)
      Right(builder.start())
    catch case ex: IOException => Left(s"starting the mill starter: ${ex.getMessage}")

  /**
   * The starter's end, in the exit file the leader writes: ended by the broker once its daemon is
   * observed listening on the port `socketPort` names (endStarter), or, without that, exited
   * on its own, nonzero, at the end of the launcher's denied-connect retry. The TERM is sent once:
   * a launcher it does not end reaches that retry bound anyway. The group is looked at every half
   * second until then, `lsof` only once a daemon row exists. A starter making no progress —
   * neither its output nor the proxy log growing — for the bound sbt's server start gets is a
   * failed start; a first start resolves Mill's own daemon classpath through the proxy, so the
   * bound is on progress, not time.
   */
  private def awaitStarter(
    spawn: Process, start: DaemonStart, output: Path, processes: Processes, log: String => Unit,
  ): Either[String, Unit] =
    val exit = RunOnHostSession.exitRecord(start.record)
    def sizes = (RunOnHostSandbox.logLength(output), RunOnHostSandbox.logLength(start.runtime.proxyLog))
    var last = sizes
    var since = System.nanoTime
    var starterEnded = false
    var polls = 0
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
        else
          if !starterEnded && polls % 5 == 0 then starterEnded = endStarter(start, processes, log)
          polls += 1
          Thread.sleep(100)
    result.get

  /**
   * TERM to the launcher, alone, once the daemon it spawned is observed listening on the candidate
   * port; whether it was sent. The launcher is the daemon's parent in the group (starterOf), its
   * start time taken from the same `ps` listing — a second `ps` would leave a window between the
   * two for the pid to be recycled in — and checked again immediately before the signal. Never
   * the group: the daemon is a member, and the leader's start time is checked before the
   * group is ended. The daemon, spawned with
   * `destroyOnExit = false` (MillProcessLauncher.scala), survives its launcher's TERM as it
   * survives the launcher's exit (measured, run-on-host-broker-session.sh M8). The observations
   * are parameters so that the tests can interleave them.
   */
  private def endStarter(start: DaemonStart, processes: Processes, log: String => Unit): Boolean =
    endStarter(start.record, start.buildDirectory, processes, log, groupMembers, listeningCandidate)

  def endStarter(
    record: Path,
    buildDirectory: Path,
    processes: Processes,
    log: String => Unit,
    members: Record => Vector[Member],
    listening: (Path, Long) => Option[Int],
  ): Boolean =
    val listeningDaemon =
      for
        leader <- recordedLeader(record)
        (daemon, launcher) <- starterOf(members(leader), leader.pgid)
        port <- listening(buildDirectory, daemon.pid)
      yield (daemon, launcher, port)
    listeningDaemon.exists: (daemon, launcher, port) =>
      signal(launcher.pid, launcher.start, "TERM", processes) && {
        log(s"TERM to the mill starter (pid ${launcher.pid}): its daemon (pid ${daemon.pid}) listens on port $port")
        true
      }

  /** A row of the group's `ps` listing: the pid, its parent's pid, the start time as
    * `ps -o lstart=` spells it, and the command line. */
  case class Member(pid: Long, ppid: Long, start: String, command: String)

  private val MemberLine = raw"\s*(\d+)\s+(\d+)\s+(.*)".r

  /**
   * `ps -ww -o pid=,ppid=,lstart=,command=` lines as members. The start time is not parsed as a
   * date, whose spelling is `ps`'s own: it is split off at the width of the leader's, which the
   * record spells, and only from a listing whose leader row carries that very start — which
   * shows that the width applies; any other listing is empty. A line that is no row is skipped.
   */
  def parseMembers(lines: Vector[String], leader: Record): Vector[Member] =
    val rows = lines.collect { case MemberLine(pid, ppid, rest) => (pid.toLong, ppid.toLong, rest) }
    val width = leader.leaderStart.length
    val leaderRow = rows.exists((pid, _, rest) => pid == leader.pgid && rest.startsWith(leader.leaderStart + " "))
    if !leaderRow then Vector.empty
    else
      rows.collect:
        case (pid, ppid, rest) if rest.length > width && rest(width) == ' ' =>
          Member(pid, ppid, rest.take(width), rest.drop(width + 1))

  private def groupMembers(leader: Record): Vector[Member] =
    parseMembers(lines("ps", "-ww", "-o", "pid=,ppid=,lstart=,command=", "-g", leader.pgid.toString), leader)

  private def recordedLeader(record: Path): Option[Record] =
    try RunOnHostSession.parseRecord(Files.readString(record, UTF_8))
    catch case _: IOException => None

  /**
   * The daemon and the launcher that spawned it, from the group's listing: the member whose
   * command line names DaemonMain, and its parent — a member of the same group other than the
   * leader, whose own command line does not name DaemonMain. None for any other topology, so
   * nothing is signalled then: a daemon the launcher attached to instead of spawning has its
   * parent outside the group, and a `java` that does not exec would put two rows naming
   * DaemonMain in the group, the daemon's parent among them.
   */
  def starterOf(members: Vector[Member], leaderPgid: Long): Option[(Member, Member)] =
    for
      daemon <- members.find(_.command.contains(DaemonMain))
      launcher <- members.find(_.pid == daemon.ppid)
      if launcher.pid != leaderPgid && !launcher.command.contains(DaemonMain)
    yield (daemon, launcher)

  /** The daemon in the record's group: the member whose command line names DaemonMain, with the
    * start time later checks compare with, from the same listing. */
  private def memberDaemon(record: Path): Option[(Long, String)] =
    recordedLeader(record).flatMap: leader =>
      groupMembers(leader).find(_.command.contains(DaemonMain)).map(member => member.pid -> member.start)

  private def portFile(buildDirectory: Path): Path =
    buildDirectory.resolve("out").resolve("mill-daemon").resolve("socketPort")

  /** `out/mill-daemon/socketPort`'s candidate: an integer in port range, nothing more. */
  private def portCandidate(buildDirectory: Path): Option[Int] =
    (try Some(Files.readString(portFile(buildDirectory), UTF_8).trim) catch case _: IOException => None)
      .flatMap(_.toIntOption).filter(port => port >= 1 && port <= 65535)

  /** The candidate, once the pid listens on it: the predicate a client's one-port grant rests on,
    * and the one behind the starter's end. Not any listening port: the daemon listens before it
    * writes the file, and a killed daemon leaves a stale one. */
  private def listeningCandidate(buildDirectory: Path, pid: Long): Option[Int] =
    portCandidate(buildDirectory).filter(listeningPorts(pid).contains)

  /** The port a client is confined to: the one the daemon was observed listening on within the
    * bound. The file is the build's to
    * write, so a candidate the daemon does not listen on is a refusal, and so is no candidate at
    * all: the client reads the same file and would fail anyway. */
  private def verifiedPort(buildDirectory: Path, pid: Long): Either[String, Int] =
    val deadline = System.nanoTime + PortDeadlineMillis * 1_000_000
    var found: Option[Int] = None
    while found.isEmpty && System.nanoTime < deadline do
      found = listeningCandidate(buildDirectory, pid)
      if found.isEmpty then Thread.sleep(200)
    found.toRight:
      val listening = listeningPorts(pid)
      val ports = if listening.isEmpty then "no port" else listening.mkString(", ")
      s"the daemon (pid $pid) listens on $ports, and ${portFile(buildDirectory)} names " +
        portCandidate(buildDirectory).getOrElse("no port")

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
        try FileHelper.directoryEntries(daemonDir)
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
   * End every foreign daemon of the build directory, each once idle and checked again — pid and
   * start time — immediately before its TERM, then KILL after the same check: a daemon holding
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
              val gone = end(pid, start, processes)
              log(
                if gone then s"ended the mill daemon $pid of $buildDirectory: not this launch's, and idle"
                else s"the mill daemon $pid of $buildDirectory, not this launch's and idle, is listed after its KILL",
              )
              gone
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

  /** TERM, then KILL after a grace, each after the start-time check: whether the pid went. */
  private def end(pid: Long, start: String, processes: Processes): Boolean =
    def alive = processes.startOf(pid).contains(start)
    signal(pid, start, "TERM", processes)
    val settled = (1 to 100).exists(_ => !alive || { Thread.sleep(100); false })
    settled || {
      signal(pid, start, "KILL", processes)
      (1 to 50).exists(_ => !alive || { Thread.sleep(100); false })
    }

  /** One signal to the pid, sent only while the pid bears the start time observed: the check
    * immediately before the signal, against a pid recycled since. Whether it was sent. */
  private def signal(pid: Long, start: String, name: String, processes: Processes): Boolean =
    val startMatches = processes.startOf(pid).contains(start)
    if startMatches then processes.signal(pid, name)
    startMatches

  /** A starter's group ended behind its leader, under the record's retirement lock, and its
    * record and exit file removed, before the same record name is spawned again: the failed
    * starter's spawn is that group's live leader. A group listed after its KILL, or a lock not
    * free within the bound, keeps its record, and Left refuses the spawn that would rename over
    * it. */
  private def retire(root: Path, record: Path, processes: Processes): Either[String, Unit] =
    RunOnHostSession.endRecordedGroup(root, record, processes) match
      case Some(kept) if kept.keeps =>
        Left(s"the mill starter's record ${record.getFileName} is kept for the next start to retry: $kept")
      case _ =>
        try
          Files.deleteIfExists(record)
          Files.deleteIfExists(RunOnHostSession.exitRecord(record))
        catch case _: IOException => ()
        Right(())
