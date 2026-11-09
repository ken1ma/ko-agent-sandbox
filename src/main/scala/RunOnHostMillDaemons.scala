// The launch's mill daemon (run-on-host-internals.md, "mill").
//
// - The workspace's stock bootstrap starts the daemon under the daemon profile. The profile denies the starter's
//   connect, which leaves the daemon behind in the starter's group.
// - The runner identifies the daemon in that group by its command line, and checks it by pid and start time.
// - A client is granted the one port that `lsof` shows the daemon listening on. `out/mill-daemon/socketPort` may
//   name that port but never authorizes it.
// - The runner uses the stock bootstrap, not a helper over `ServerLauncher(openSocket = false)`:
//   - The launcher writes the daemon's fingerprint (`DaemonConfig`) with the same code that every client compares
//     the fingerprint with. A helper would reproduce `MillLauncherMain.main0`'s preamble against `mill.launcher`
//     internals pinned to one version.
//   - A fingerprint that differs is the mismatch on which the next client ends the daemon.
//   - A Mill version whose daemon does not survive the starter's end would bring the helper back.
// - The connect is denied because the daemon inherits the starter's profile. SeatbeltProfile.Network.MillDaemon
//   explains why no outbound connection is granted. The runner ends the starter once its daemon is observed listening,
//   so the denied connect's ten-second retry is not waited out.
// - Before the runner's daemon starts, the runner ends the user's own daemon for the build directory, once that
//   daemon is idle and after its start-time check. The user's sbt server is likewise shut down by protocol.
// - The daemon is observed on macOS only, like the supervisor, because the observations are ps, pgrep and lsof.
//   RunnerRuntimes therefore takes `start` as a parameter that tests replace, and ChannelCheck measures it.

package agentsandbox.launcher

import java.io.IOException
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, LinkOption, Path}

import RunOnHostSandbox.{RuntimeStart, ServerStartSilenceMillis}
import RunOnHostSession.{daemonRecordName, Processes, Record, Session}
import RunOnHostSession.HostProcesses.{lines, Lsof, Pgrep, ps}

object RunOnHostMillDaemons:

  /** A daemon on the host: its pid, its `ps -o lstart=` start time and the port it listens on. Every later reuse or
    * signal checks the start time first. */
  case class Daemon(pid: Long, start: String, port: Int)

  /** The daemon's main class. The class appears on the daemon's command line and nowhere on the launcher's. */
  val DaemonMain = "mill.daemon.MillDaemonMain"

  /** Where the starter's stdout and stderr go.
    *
    *   - A "Mill launcher failed" trace there marks a starter that the runner did not end: its daemon never
    *     listened, or the launcher reached its own retry bound first. The trace is the finding when the start failed.
    *   - The file lies in the session directory, beside the sbt servers' logs, for the same reason
    *     (RunOnHostSbtServer.serverLog). */
  def starterLog(session: Session, hash: String): Path = session.directory.resolve(s"${daemonRecordName(hash)}.log")

  /** How long a foreign daemon may stay busy before the start is refused. The user's sbt server gets the same bound
    * for its shutdown, for the same reason (RunOnHostSbtServer.shutdownForeignServer). */
  val ForeignIdleDeadlineMillis = 120_000L

  /** The bound on observing the daemon listen on the port after the starter's exit.
    *
    *   - The bound equals the launcher's connect retry (`MillServerLauncher.serverInitWaitMillis`, 10 s). Within that
    *     time, a daemon listens and `socketPort` is written. A port still unverifiable after this long therefore
    *     means that the daemon is not listening.
    *   - The bound matters for a starter that exited on its own. The runner ends a starter only after that very
    *     observation. */
  val PortDeadlineMillis = 10_000L

  /**
   * Starts the daemon of `start`'s runtime:
   *
   *   - This method ends the user's own daemon, so that no foreign daemon holds the build directory.
   *   - The starter runs, registered at `start.record`. The runner ends the starter once the daemon it spawned is
   *     observed listening (awaitStarter).
   *   - This method identifies the daemon that the starter left in its group by pid and start time, and verifies
   *     the daemon's port.
   *
   * A daemon may appear between the foreign check and the starter's lock. The starter then attaches to that daemon,
   * and the starter's group holds no daemon. This method ends that daemon like the first one, and runs the starter
   * once more.
   *
   * A start that fails leaves no group behind its record. The caller discards the record.
   */
  def start(
    session: Session, processes: Processes, log: String => Unit, start: RuntimeStart,
  ): Either[String, Daemon] =
    val output = starterLog(session, start.hash)
    def said = s"the starter's output:\n${RunOnHostSandbox.starterOutputTail(output)}"
    def attempt(retriesLeft: Int, profileFile: Path): Either[String, Daemon] =
      for
        leader <- spawnStarter(start, profileFile, output)
        _ <- awaitStarter(leader, start, output, processes, log)
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
      profileFile <- RunOnHostSandbox.writeRuntimeProfile(session, daemonRecordName(start.hash), start.inputs)
      _ = discardForeignClasspath(start.buildDirectory, start.assembled.prereqs.coursierV1, confined(profileFile))
        .foreach(log)
      daemon <- attempt(retriesLeft = 1, profileFile)
    yield daemon

  /** Runs `./mill version` from the build directory under the daemon profile (RunOnHostSandbox.startRuntimeStarter).
    *
    *   - `./mill` is the stock bootstrap, and `MILL_VERSION` names the JVM launcher.
    *   - The output goes to the starter log.
    *   - The runner's `tmp/` is the temporary and socket directory, which the daemon inherits. */
  private def spawnStarter(start: RuntimeStart, profileFile: Path, output: Path): Either[String, Process] =
    try
      Right(RunOnHostSandbox.startRuntimeStarter(
        start.record, profileFile, Seq(start.buildDirectory.resolve("mill").toString, "version"),
        start.buildDirectory, start.inputs.environment, output,
      ))
    catch case ex: IOException => Left(s"starting the mill starter: ${ex.getMessage}")

  /**
   * Waits for the starter's end, which the leader writes to the exit file. The starter ends in one of two ways:
   *
   *   - The runner ends the starter once its daemon is observed listening on the port that `socketPort` names
   *     (endStarter).
   *   - Otherwise, the starter exits on its own, nonzero, at the end of the launcher's denied-connect retry.
   *
   * The wait works as follows:
   *
   *   - The TERM is sent once. A launcher that the TERM does not end reaches that retry bound anyway.
   *   - This method looks at the group every half second until then, and runs `lsof` only once a daemon row exists.
   *   - A starter that makes no progress for the bound that sbt's server start gets is a failed start. No progress
   *     means that neither the starter's output nor the proxy log grows.
   *   - A first start resolves Mill's own daemon classpath through the proxy, so the bound is on progress, not on
   *     time.
   */
  private def awaitStarter(
    leader: Process, start: RuntimeStart, output: Path, processes: Processes, log: String => Unit,
  ): Either[String, Unit] =
    val exit = RunOnHostSession.exitRecord(start.record)
    val watch = RunOnHostSandbox.StartWatch(output, start.runtime.proxyLog)
    var starterEnded = false
    var polls = 0
    var result: Option[Either[String, Unit]] = None
    while result.isEmpty do
      val leaderEnded = !leader.isAlive
      if Files.exists(exit) then result = Some(Right(()))
      else if leaderEnded then
        result = Some(Left(s"the mill starter's leader ended (exit ${leader.exitValue}) without registering it"))
      else
        watch.poll() match
          case RunOnHostSandbox.StartProgress.Grew => ()
          case RunOnHostSandbox.StartProgress.Silent =>
            result = Some(Left(
              s"the mill starter neither ended nor wrote anything, and the proxy log did not grow, for " +
                s"${ServerStartSilenceMillis / 1000}s",
            ))
          case RunOnHostSandbox.StartProgress.Waiting =>
            if !starterEnded && polls % 5 == 0 then starterEnded = endStarter(start, processes, log)
            polls += 1
            Thread.sleep(100)
    result.get

  /**
   * Sends TERM to the launcher alone, once the daemon that the launcher spawned is observed listening on the
   * candidate port. Returns whether the TERM was sent.
   *
   *   - The launcher is the daemon's parent in the group (starterOf).
   *   - The launcher's start time comes from the same `ps` listing, and is checked again immediately before the
   *     signal. A second `ps` would leave a window between the two listings in which the pid could be recycled.
   *   - The TERM never goes to the group, because the daemon is a member. The leader's start time is checked before
   *     the group is ended.
   *   - The daemon, spawned with `destroyOnExit = false` (MillProcessLauncher.scala), survives its launcher's TERM as
   *     it survives the launcher's exit (measured, run-on-host-runner-session.sh M8).
   *   - The observations are parameters so that the tests can interleave them.
   */
  private def endStarter(start: RuntimeStart, processes: Processes, log: String => Unit): Boolean =
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
        leader <- RunOnHostSession.readRecord(record)
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
   * `ps -ww -o pid=,ppid=,lstart=,command=` lines as members.
   *
   *   - The start time is not parsed as a date, because `ps` spells dates its own way. The start time is split off at
   *     the width of the leader's start time, which the record spells.
   *   - Only a listing whose leader row carries that very start time gives members, since that row shows that the
   *     width applies. Any other listing gives none.
   *   - A line that is no row is skipped.
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
    parseMembers(ps("-ww", "-o", "pid=,ppid=,lstart=,command=", "-g", leader.pgid.toString), leader)

  /**
   * The daemon and the launcher that spawned it, from the group's listing.
   *
   *   - The daemon is the member whose command line names DaemonMain.
   *   - The launcher is the daemon's parent: a member of the same group other than the leader, whose own command line
   *     does not name DaemonMain.
   *   - The result is None for any other topology, so nothing is signalled then. A daemon that the launcher attached
   *     to instead of spawning has its parent outside the group. A `java` that does not exec would put two rows
   *     naming DaemonMain in the group, the daemon's parent among them.
   */
  def starterOf(members: Vector[Member], leaderPgid: Long): Option[(Member, Member)] =
    for
      daemon <- members.find(_.command.contains(DaemonMain))
      launcher <- members.find(_.pid == daemon.ppid)
      if launcher.pid != leaderPgid && !launcher.command.contains(DaemonMain)
    yield (daemon, launcher)

  /** The daemon in the record's group: the member whose command line names DaemonMain. The daemon's start time comes
    * from the same listing, and later checks compare against it. */
  private def memberDaemon(record: Path): Option[(Long, String)] =
    RunOnHostSession.readRecord(record).flatMap: leader =>
      groupMembers(leader).find(_.command.contains(DaemonMain)).map(member => member.pid -> member.start)

  private def portFile(buildDirectory: Path): Path =
    buildDirectory.resolve("out").resolve("mill-daemon").resolve("socketPort")

  /** The port candidate in `out/mill-daemon/socketPort`: an integer in port range, nothing more. */
  private def portCandidate(buildDirectory: Path): Option[Int] =
    FileHelper.readIfReadable(portFile(buildDirectory)).map(_.trim)
      .flatMap(agentsandbox.egress.HTTPHelper.parseDecimal).filter(port => port >= 1 && port <= 65535).map(_.toInt)

  /** The candidate, once the pid listens on it. A client's one-port grant rests on this predicate, and so does the
    * starter's end. Any listening port would not do: the daemon listens before it writes the file, and a killed
    * daemon leaves a stale file. */
  private def listeningCandidate(buildDirectory: Path, pid: Long): Option[Int] =
    portCandidate(buildDirectory).filter(listeningPorts(pid).contains)

  /** The port a client is confined to: the port the daemon was observed listening on within the bound. The build may
    * write the file, so a candidate that the daemon does not listen on is a refusal. No candidate at all is a
    * refusal too, because the client reads the same file and would fail anyway. */
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
    lines(Lsof, "-a", "-p", pid.toString, "-iTCP", "-sTCP:LISTEN", "-nP", "-Fn")
      .collect { case Listener(port) => port.toInt }

  private val Listener = raw"n(?:127\.0\.0\.1|localhost|\[::1\]):(\d+)".r

  /**
   * Whether the pid has no established TCP connection.
   *
   *   - The result is Some(false) while a client runs a command on the daemon.
   *   - The result is None when the observation is incomplete, and None is never taken for idle. The observation is
   *     incomplete when lsof exits nonzero, writes to stderr, or lists no socket; a live daemon always holds its
   *     listener.
   */
  private def idle(pid: Long): Option[Boolean] =
    try
      val lsof = HostCommands.run(Lsof, "-a", "-p", pid.toString, "-iTCP", "-nP", "-FT")
      val states = lsof.text.linesIterator.filter(_.startsWith("TST=")).map(_.drop(4)).toVector
      if !lsof.ok || lsof.err.nonEmpty || states.isEmpty then None
      else Some(!states.contains("ESTABLISHED"))
    catch case _: IOException => None

  /** The file to which Mill's launcher writes the daemon's classpath (`CoursierClient.cached`). The file holds JSON:
    * the key, then the paths. */
  private def classpathFile(buildDirectory: Path): Path =
    buildDirectory.resolve("out").resolve("mill-daemon").resolve("cache").resolve("mill-daemon-classpath")

  private val ClasspathEntry = """"(/(?:[^"\\]|\\.)*)"""".r

  /** A file read and a file deletion under the profile: what a build could do to the file, and no more.
    *
    *   - A link may be planted under `out/` after rendezvousIsOwn, by the bootstrap script or by build code in one of
    *     the user's daemons that the start waited on. Neither operation then reaches past the build's own writable
    *     roots.
    *   - The read gives the file's text when the path names a file, and None otherwise. */
  case class Confined(read: Path => Option[String], delete: Path => Boolean)

  def confined(profileFile: Path): Confined =
    def run(command: String*): Option[String] =
      try
        val confined = HostCommands.run(RunOnHostSandbox.sandboxExec(profileFile, command)*)
        Option.when(confined.ok)(String(confined.out, UTF_8))
      catch case _: IOException => None
    Confined(
      read = file => run("/bin/cat", "--", file.toString),
      delete = file => run("/bin/rm", "-f", "--", file.toString).isDefined,
    )

  /**
   * Deletes Mill's `mill-daemon-classpath` file when the file names a path outside the cache that the profile grants,
   * so that the launcher resolves afresh into that cache. Returns what was done, for the log.
   *
   *   - Mill reuses the file while every path it names exists (`CoursierClient.resolveMillDaemon`, `os.exists`).
   *   - Seatbelt answers an existence test for a path it denies reading. Measured: `Files.exists` gives true, and the
   *     open gives `EPERM`.
   *   - A file from an unconfined run, or from this directory served as another workspace's build directory, would
   *     therefore start a daemon on jars its JVM cannot open. That daemon dies before it listens.
   *   - This method reads and deletes the file through `confined`, and only when the file is a regular file.
   */
  def discardForeignClasspath(buildDirectory: Path, coursierV1: Path, confined: Confined): Option[String] =
    val file = classpathFile(buildDirectory)
    val named = buildDirectory.relativize(file)
    if !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) then None
    else
      confined.read(file).flatMap: text =>
        val paths = ClasspathEntry.findAllMatchIn(text).map(_.group(1)).toVector
        paths.find(path => !Path.of(path).startsWith(coursierV1)).map: foreign =>
          if confined.delete(file) then s"discarded $named: it names $foreign, outside $coursierV1"
          else s"could not discard $named, which names $foreign, outside $coursierV1"

  /**
   * Checks that the command's rendezvous directory belongs to the command's own build directory: `out`,
   * `out/mill-daemon` and every entry directly in it are neither links nor files with a second name.
   *
   *   - Mill's launcher acts on that directory as it finds it. The launcher removes a `processId` whose fingerprint
   *     differs, which ends the daemon that the file names, and it probes `daemonLock`.
   *   - A link there would make the launcher act on another build directory's daemon, past the ownership and
   *     idleness checks, which are keyed by this directory.
   *   - A second name for another directory's `processId` would do the same through one inode.
   *   - The check runs before every mill command, under the build lock.
   */
  def rendezvousIsOwn(buildDirectory: Path): Either[String, Unit] =
    val out = buildDirectory.resolve("out")
    val daemonDir = out.resolve("mill-daemon")
    val entries =
      if !Files.isDirectory(daemonDir, LinkOption.NOFOLLOW_LINKS) then Vector.empty
      else FileHelper.directoryEntriesIfAny(daemonDir)
    def refused(path: Path, what: String) =
      Left(
        s"$path is $what; a redirected mill daemon directory is refused, since Mill's launcher would act on " +
          "another build directory's daemon through it",
      )
    (Seq(out, daemonDir) ++ entries).find(Files.isSymbolicLink) match
      case Some(link) => refused(link, "a symlink")
      case None =>
        entries.find(FileHelper.hasSecondName(_).contains(true)) match
          case Some(file) => refused(file, "a file with more than one name")
          case None       => Right(())

  /** The mill daemons on the host that work in the build directory's `out/mill-daemon`, with their start times.
    *
    *   - A daemon's cwd is its `sandbox` directory beneath `out/mill-daemon`
    *     (MillProcessLauncher.configureRunMillProcess).
    *   - The pid comes from the process table, never from a file. */
  def foreignDaemons(buildDirectory: Path, processes: Processes): Vector[(Long, String)] =
    val daemonDir = buildDirectory.resolve("out").resolve("mill-daemon")
    lines(Pgrep, "-f", "--", DaemonMain).flatMap(_.toLongOption).flatMap: pid =>
      val cwd = lines(Lsof, "-a", "-p", pid.toString, "-d", "cwd", "-Fn").collectFirst {
        case line if line.startsWith("n") => Path.of(line.drop(1))
      }
      Option.when(cwd.exists(_.startsWith(daemonDir)))(pid).flatMap(pid => processes.startOf(pid).map(pid -> _))

  /**
   * Ends every foreign daemon of the build directory. A daemon holding `out/mill-daemon` runs the build outside this
   * launch's ownership, and the stock launcher would attach to a daemon whose fingerprint matches.
   *
   *   - Each daemon is ended once idle. The daemon's pid and start time are checked again immediately before its TERM,
   *     and the same check precedes its KILL.
   *   - A daemon that stays busy past the bound, or whose idleness cannot be observed, gives a refusal that names the
   *     daemon.
   *   - A terminal `./mill` can still connect between the observation and the TERM. That command's build then dies with
   *     the daemon (run-on-host-internals.md, "mill", states the window).
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

  /** Sends TERM, then KILL after a grace period, each after the start-time check. Returns whether the pid went away. */
  private def end(pid: Long, start: String, processes: Processes): Boolean =
    RunOnHostSession.termThenKill(!processes.startOf(pid).contains(start), signal(pid, start, _, processes))

  /** Sends one signal to the pid, only while the pid bears the observed start time. The check runs immediately before
    * the signal, against a pid recycled since. Returns whether the signal was sent. */
  private def signal(pid: Long, start: String, name: String, processes: Processes): Boolean =
    val startMatches = processes.startOf(pid).contains(start)
    if startMatches then processes.signal(pid, name)
    startMatches

  /** Ends a starter's group behind its leader, under the record's retirement lock, and removes the group's record and
    * exit file before the same record name is spawned again. The failed starter's leader is still alive.
    *
    *   - A group still listed after its KILL keeps its record, and so does a lock that is not free within the bound.
    *   - Left then refuses the leader that would rename over the record. */
  private def retire(root: Path, record: Path, processes: Processes): Either[String, Unit] =
    RunOnHostSession.forgetUnlessKept(record, RunOnHostSession.endRecordedGroup(root, record, processes), _ => ()).left
      .map(kept => s"the mill starter's record ${record.getFileName} is kept for the next start to retry: $kept")
      .map(_ => ())
