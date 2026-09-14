// The host command's lifecycle. A command session is one wrapper invocation; the broker's session
// is one launch, published and locked the same way by the broker, holding the runtimes its
// commands share (RunOnHostSandbox.BrokerRuntimes). A session's directory is published by rename
// so it is never seen half-made, its lock marks its owner as live, and its records identify the
// child processes. The filesystem and process operations are injected,
// so unit tests check the kill interleavings without requiring macOS or a real SIGKILL.
//
// The rule the records keep: no process may outlive its record. A spawn becomes its
// own group's leader and publishes `<pgid> <leader start time>` by rename before it runs the
// command, aborting when the rename fails — so a kill at any instant leaves a complete record or
// a child that ends itself. The spawn stays after the command ends, publishing its exit status
// beside the record, so the group stays provable through teardown. The scavenger condemns a
// directory (rename out of the scanned root) before it reads records, ends what they name, and
// only then deletes. Every ending of a runtime's recorded group, by whichever process, runs
// under that group's retirement lock (retirementLockFile).

package agentsandbox.launcher

import java.io.IOException
import java.nio.channels.FileChannel
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path, StandardCopyOption, StandardOpenOption}

import scala.jdk.CollectionConverters.*
import scala.util.control.NonFatal

object RunOnHostSession:

  val LockFile = "lock"
  val TmpDir = "tmp"
  val RecordsDir = "records"
  val ProjectFile = "project"
  /** The broker's: the launch's sandbox container, by which `--stats` joins the broker to its session. */
  val RunFile = "run"
  val StagingDir = "staging"
  val CondemnedDir = "condemned"
  val RootLockFile = "root-lock"
  val BuildLockDir = "build-lock"
  val RetireLockDir = "retire-lock"
  val BuildFilePrefix = "build-"

  /** Whose lock a session's is, and the prefix its directory is named by: the broker's lives the
    * launch's lifetime; a command's, its wrapper's. */
  enum Kind(val prefix: String):
    case Broker extends Kind("b")
    case Command extends Kind("s")

  /** One registered process group: the leader's pgid (== its pid) and the leader's start time,
    * spelled exactly as `ps -o lstart=` prints it — compared as a string, never parsed, because
    * only equality with a later observation matters. */
  case class Record(pgid: Long, leaderStart: String)

  def renderRecord(record: Record): String = s"${record.pgid} ${record.leaderStart}\n"

  def parseRecord(text: String): Option[Record] =
    text.trim.split(" ", 2) match
      case Array(pid, start) if start.nonEmpty => pid.toLongOption.map(Record(_, start))
      case _                                   => None

  /** What the scavenger observes and does about processes. Injected: the tests exercise the
    * decision protocol, and a real implementation runs only on macOS. */
  trait Processes:
    /** `ps -o lstart= -p pid`, None when no such process exists. An observation that could not
      * be made throws IOException — never None, which the callers read as absence. */
    def startOf(pid: Long): Option[String]

    /** End the whole group, TERM then KILL after a grace: whether `ps` then listed no member. A
      * listing that could not be made proves nothing, and neither does a signal sent — a member
      * can exit before the signal arrives, so the listing decides. */
    def endGroup(pgid: Long): Boolean

    /** Whether `ps` lists no member of the group; IOException when it could not say. */
    def groupEmpty(pgid: Long): Boolean

    /** `kill -<name> <pid>`, one process; the caller proves the pid by its start time first. */
    def signal(pid: Long, name: String): Unit

  /** How one collected session ended up, for the wrapper's report. */
  enum Collected:
    case GroupEnded(pgid: Long)
    /** A member still listed — after the KILL, or with the leader gone — or no listing to be
      * had: its record is kept, and the next collection retries. */
    case GroupAlive(pgid: Long, reason: String)
    case GroupSkipped(pgid: Long, reason: String)
    case ServerShutDown(socket: Path)
    case ServerSkipped(reason: String)
    /** Alive but not answering: its condemned directory is kept, and the next start retries. */
    case ServerUnanswered(socket: Path, reason: String)
    /** Another process held the record's retirement lock past the bound, or the lock could not
      * be opened: nothing was read or signalled, the record is kept, and the next collection
      * retries. */
    case RetirementBusy(record: String, reason: String)

    /** Whether this outcome keeps the directory, records and all, for the next collection. */
    def keeps: Boolean = this match
      case GroupAlive(_, _) | ServerUnanswered(_, _) | RetirementBusy(_, _) => true
      case _                                                                => false

  /** What a shutdown sent to a socket established (RunOnHostSbtServerShutdown is the real sender). */
  enum ServerAnswer:
    case ShutDown
    /** The connect itself failed before reaching a server, so there is no server to stop. */
    case Unreachable(reason: String)
    /** A server accepted the connect but did not finish shutting down before the bound. */
    case Unanswered(reason: String)

  // ---------------------------------------------------------------------------
  // The wrapper root
  // ---------------------------------------------------------------------------

  /** Within RunOnHostPrereqs.SessionTmpMaxLength's budget: every session's `tmp/` is beneath it. */
  def root(uid: Int): Path = Path.of(s"/private/tmp/ko-agent-$uid")

  /**
   * `/private/tmp` is shared and sticky, so the root is trusted the way an XDG runtime directory
   * is — this user's, mode 0700, no symlink — and refused otherwise. Created when absent; created
   * 0700 so there is no window at the default mode. Created first and found to exist second,
   * rather than looked for first: two launches making the root at once both find it absent, and
   * the one whose creation loses goes on to the checks, which are what make the root trusted.
   */
  def ensureRoot(root: Path, uid: Int): Either[String, Path] =
    try
      try Files.createDirectory(root, ownerOnly)
      catch case _: java.nio.file.FileAlreadyExistsException => ()
      if Files.isSymbolicLink(root) then Left(s"$root is a symlink; refusing a redirected root")
      else if !Files.isDirectory(root) then Left(s"$root is not a directory")
      else
        val attributes =
          Files.readAttributes(root, classOf[java.nio.file.attribute.PosixFileAttributes])
        val permissions = attributes.permissions.asScala
        import java.nio.file.attribute.PosixFilePermission.*
        val othersReach = Set(GROUP_READ, GROUP_WRITE, GROUP_EXECUTE, OTHERS_READ, OTHERS_WRITE,
          OTHERS_EXECUTE)
        if (Files.getAttribute(root, "unix:uid") match
            case owner: Integer => owner.intValue != uid
            case _              => true)
        then Left(s"$root is not this user's; refusing a shared root")
        else if permissions.exists(othersReach) then
          Left(s"$root is reachable past its owner; refusing (chmod 700 it, or remove it)")
        else Right(root)
    catch case ex: (IOException | UnsupportedOperationException) => Left(s"$root: ${ex.getMessage}")

  private def ownerOnly =
    java.nio.file.attribute.PosixFilePermissions
      .asFileAttribute(java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"))

  /**
   * The build lock of one build directory and program, `build-lock/<program>-<hash>`: held by
   * the command's own process for its whole life, teardown included, so no two launches run or
   * clean up a command on one build at once, and a broker's death frees nothing the wrapper
   * holds. The spawn below takes it through flock(2), whose lock belongs to the open file
   * description: it survives the exec into the wrapper, reaches none of the wrapper's own
   * children — a JVM's children get only their three standard descriptors — and is released
   * when the wrapper exits; a killed wrapper's at once, the next start's scavenge behind it. A
   * spawn blocked on the lock is a child like any other, ended when its requester leaves. Under
   * the broker it also watches the broker's pipe on its stdin, as the wrapper does, and ends at
   * its EOF, so a dead broker dispatches nothing, and it execs only on the broker's word
   * (lockedSpawn), so the broker's own work on the build before the command — its runtime
   * observed, retired or created — happens under the lock too. The file is never deleted:
   * deleted and recreated, one name would let two holders lock different inodes.
   */
  def buildLockFile(root: Path, program: String, buildDirectory: Path): Either[String, Path] =
    try
      Right(Files.createDirectories(root.resolve(BuildLockDir), ownerOnly)
        .resolve(s"$program-${buildHash(buildDirectory)}"))
    catch case ex: IOException => Left(s"the build locks under $root: ${ex.getMessage}")

  /** The command under the build lock: perl (registeredSpawn has why) takes the lock and execs
    * the command holding it, so the lock ends exactly when the command does, however it dies.
    * When it has to wait it says so on stderr, the requester's. `underBroker`, its stdin is the
    * broker's pipe (RunOnHostChannel.dispatch): EOF while it waits ends it, and once it holds
    * the lock it writes `LockedLine` on its stdout and reads the broker's word from the pipe —
    * `runWord`, whose arguments it inserts before the command's `--`, or `refusedWord`, whose
    * message it prints on stderr before exiting 2, the wrapper's own refusal code. Exit 71 is
    * the spawn ending itself, as in registeredSpawn. */
  def lockedSpawn(lockFile: Path, command: Seq[String], underBroker: Boolean): Seq[String] =
    Seq("/usr/bin/perl", "-e", LockScript, lockFile.toString, if underBroker then "1" else "0") ++ command

  val LockedLine = "locked"

  private val Nul = 0.toChar.toString

  /** The broker's word to a locked spawn: one line of NUL-separated fields, the verdict first,
    * each field escaped so that a refusal of several lines — a server's output quoted — and an
    * argument holding a newline or a NUL arrive whole. */
  def runWord(arguments: Seq[String]): String = ("run" +: arguments.map(escapeField)).mkString(Nul) + "\n"

  def refusedWord(message: String): String = s"refused$Nul${escapeField(message)}\n"

  private val Escape = 1.toChar

  private def escapeField(field: String): String =
    field.flatMap:
      case Escape => s"${Escape}e"
      case '\n'   => s"${Escape}n"
      case '\u0000' => s"${Escape}0"
      case other  => other.toString

  val LockScript: String =
    """use Fcntl qw(:flock F_SETFD);
      |my ($lock, $broker, @command) = @ARGV;
      |open(my $fh, '>>', $lock) or exit 71;
      |unless (flock($fh, LOCK_EX | LOCK_NB)) {
      |    print STDERR "waiting for the build lock: another launch's command runs in this build directory\n";
      |    if ($broker) {
      |        my $stdin = '';
      |        vec($stdin, fileno(STDIN), 1) = 1;
      |        until (flock($fh, LOCK_EX | LOCK_NB)) {
      |            my $readable = $stdin;
      |            if (select($readable, undef, undef, 0.2)) {
      |                exit 71 unless sysread(STDIN, my $byte, 1);
      |            }
      |        }
      |    } else {
      |        flock($fh, LOCK_EX) or exit 71;
      |    }
      |}
      |if ($broker) {
      |    syswrite(STDOUT, "locked\n") or exit 71;
      |    my $word = <STDIN>;
      |    exit 71 unless defined $word;
      |    chomp $word;
      |    my ($verdict, @fields) = split /\0/, $word, -1;
      |    s/\x01([en0])/$1 eq 'n' ? "\n" : $1 eq '0' ? "\0" : "\x01"/ge for @fields;
      |    if ($verdict ne 'run') { print STDERR "$fields[0]\n"; exit 2; }
      |    my $at = 0;
      |    $at++ while $at < @command && $command[$at] ne '--';
      |    splice(@command, $at, 0, @fields);
      |}
      |fcntl($fh, F_SETFD, 0) or exit 71;
      |exec { $command[0] } @command or exit 71;""".stripMargin

  /**
   * The retirement lock of one build directory and program, `retire-lock/<program>-<hash>`: what
   * every process ending a runtime's recorded group — the broker replacing or retiring its own
   * (RunOnHostSandbox.BrokerRuntimes.discard, RunOnHostMillDaemons.retire), its teardown, the scavenger,
   * and another launch taking the runtime over (RunOnHostSandbox.BrokerRuntimes.takeOver) —
   * holds across the leader's proof and the group's signal,
   * and across nothing else. Two processes running that proof-then-signal on one group would
   * correlate the pid recycling window: the first's kill frees the pids at the moment the
   * second's already proved kill is on its way. Not the build lock, which a command holds for its
   * whole life: a teardown would wait on another launch's build before ending its own server.
   * The record is read only under the lock, so a holder acts on what the previous holder left.
   *
   * The order is one-way and the retirement lock is always last: preparation holds the build
   * lock, then the runtimes' monitor; teardown the monitor and the session's own lock; scavenging
   * the condemned entry's lock. Nothing takes a build lock, a session lock or the monitor while
   * holding one, and no process holds two at once, so no wait can cycle. Death releases the lock
   * and not the group, so the next holder validates as every holder does. A lock not free within
   * RetirementDeadlineMillis is Collected.RetirementBusy, which keeps the record for the next
   * collection. The lock files are
   * never deleted, as the build locks are not (buildLockFile has why), and the directory is
   * skipped by the scavenge's root scan, which would otherwise read it as a dead session.
   *
   * Within one process, one thread at a time opens, locks, releases and closes a lock file's
   * channel (retirementPermits): OpenJDK's lock is a POSIX fcntl lock, which the kernel drops for
   * the whole process when any descriptor to the file is closed (scavenge has the same caveat for
   * the session lock), so a waiter's channel closed on its timeout, or a holder's channel still
   * open when the next thread has locked a fresh one, would end another thread's exclusion
   * against other processes. Two threads do contend: the gate's entry prepares its runtime on the
   * main thread and tears the session down from the shutdown hook (RunOnHostSandbox.ownRuntime),
   * and the broker's monitor covers neither the wrapper nor the tests.
   *
   * Only the records that name a runtime another launch could end map to a lock
   * (retirementLockName): a command session's own records and the Gradle daemons' are ended by
   * their session's owner or, once it is dead, by the collector holding that session's lock,
   * which excludes every other ender already.
   */
  def retirementLockFile(root: Path, name: String): Path =
    Files.createDirectories(root.resolve(RetireLockDir), ownerOnly).resolve(name)

  /** `<program>-<hash>` for a runtime's record — `proxy-<program>-<hash>`, `server-sbt-<hash>`,
    * `daemon-mill-<hash>`, a `.pending` one included — and None for every other record. */
  def retirementLockName(recordName: String): Option[String] =
    recordName.stripSuffix(".pending") match
      case RuntimeRecordName(program, hash) => Some(s"$program-$hash")
      case _                               => None

  private val RuntimeRecordName = raw"(?:proxy|server|daemon)-([a-z]+)-([0-9a-f]{16})".r

  /** Past the fifteen seconds a holder's TERM, grace and KILL take at most (HostProcesses.endGroup). */
  val RetirementDeadlineMillis = 20_000L

  /** This process's one permit per lock file, held from the channel's open to its close. A
    * thread taking a lock it already holds waits for the permit until the deadline and gets
    * RetirementBusy, never a second descriptor. */
  private val retirementPermits = java.util.concurrent.ConcurrentHashMap[Path, java.util.concurrent.Semaphore]()

  /**
   * `body` under the record's retirement lock, taken within `deadlineMillis`; None when it was
   * not. A record whose name maps to no lock runs `body` at once. The permit first, then the
   * channel: no other thread of this process touches the file while this one holds it.
   */
  private def underRetirementLock[A](root: Path, record: Path, deadlineMillis: Long)(body: => A): Option[A] =
    retirementLockName(record.getFileName.toString) match
      case None => Some(body)
      case Some(name) =>
        val file = retirementLockFile(root, name).toAbsolutePath.normalize
        val permit = retirementPermits.computeIfAbsent(file, _ => java.util.concurrent.Semaphore(1))
        val deadline = System.nanoTime + deadlineMillis * 1_000_000
        if !permit.tryAcquire(deadlineMillis, java.util.concurrent.TimeUnit.MILLISECONDS) then None
        else
          try
            val channel = FileChannel.open(file, StandardOpenOption.CREATE, StandardOpenOption.WRITE)
            try
              var lock = channel.tryLock()
              while lock == null && System.nanoTime < deadline do
                Thread.sleep(50)
                lock = channel.tryLock()
              if lock == null then None
              else
                try Some(body)
                finally lock.release()
            finally channel.close()
          finally permit.release()

  /** What names one build directory's lock and records: its canonical spelling's SHA-256, 16
    * hex digits. */
  def buildHash(buildDirectory: Path): String =
    java.security.MessageDigest.getInstance("SHA-256")
      .digest(buildDirectory.toString.getBytes(UTF_8))
      .take(8).map(byte => f"$byte%02x").mkString

  /** `build-<hash>`, the canonical build directory the records of that hash serve: published by
    * rename before the first record of the hash and removed after the last is retired, so a
    * reader of another session takes one runtime's directory and its processes together, never
    * a directory of one runtime and a process of its successor; a record without its file is
    * unproven and skipped. */
  def buildFile(sessionDirectory: Path, hash: String): Path =
    sessionDirectory.resolve(s"$BuildFilePrefix$hash")

  def publishBuildFile(sessionDirectory: Path, hash: String, buildDirectory: Path): Either[String, Path] =
    val file = buildFile(sessionDirectory, hash)
    try
      val pending = file.resolveSibling(s"${file.getFileName}.pending")
      Files.writeString(pending, buildDirectory.toString + "\n", UTF_8)
      Files.move(pending, file, StandardCopyOption.ATOMIC_MOVE)
      Right(file)
    catch case ex: IOException => Left(s"publishing $file: ${ex.getMessage}")

  /** The build directories a session's build files name, by hash. */
  def buildDirectories(sessionDirectory: Path): Vector[(String, Path)] =
    listDirectory(sessionDirectory).flatMap: file =>
      val name = file.getFileName.toString
      if !name.startsWith(BuildFilePrefix) || name.endsWith(".pending") || !Files.isRegularFile(file) then None
      else
        try Some(name.stripPrefix(BuildFilePrefix) -> Path.of(Files.readString(file, UTF_8).trim))
        catch case _: IOException => None

  /** The other live brokers' sessions under the root: published under the broker prefix and
    * locked. A broker attaches to another launch's runtime only from one of these
    * (RunOnHostSandbox.BrokerRuntimes.attached). */
  def liveBrokerSessions(root: Path, except: Path): Vector[Path] =
    allBrokerSessions(root, except).filter(entry => !lockIsFree(entry.resolve(LockFile)))

  /** Every broker session directory under the root, locked or not — a just-crashed owner's is
    * unlocked but not yet condemned, and its server group can still be running, so runtimeOwner
    * must weigh it too (its finding is taken over, never attached to, and the next start's
    * scavenge collects it). */
  def allBrokerSessions(root: Path, except: Path): Vector[Path] =
    listDirectory(root).filter: entry =>
      entry != except && entry.getFileName.toString.startsWith(Kind.Broker.prefix)
        && Files.isDirectory(entry)

  /** The sessions under `condemned/`: an owner tearing itself down, or a scavenger, has renamed
    * its directory here and holds its lock while it ends the recorded groups. Their ownership
    * records still name the build directories they own, so a start consults them alongside the
    * live sessions until collection deletes them (runtimeOwner): a server whose socket path has
    * moved with the rename must not read as free. The scavenger's own pass (run first) collects
    * any that no live owner still holds. */
  def collectingSessions(root: Path): Vector[Path] =
    listDirectory(root.resolve(CondemnedDir)).filter(Files.isDirectory(_))

  /**
   * Another launch's session that holds the ownership record `record` — `server-sbt-<hash>` or
   * `daemon-mill-<hash>` — or None. Any broker session under the root — live, or just-crashed
   * and not yet collected — or a session under `condemned/` whose teardown or scavenge has not
   * finished, owns it; the record is read here, and its group ended only by its owner, or by
   * the launch taking the runtime over, under the retirement lock
   * (RunOnHostSandbox.BrokerRuntimes.takeOver). A dead owner's runtime is taken over this time
   * and the next start's scavenge collects its session, so its server or daemon is never left
   * running beside a fresh one.
   *
   * The live sessions are enumerated, then looked up; `condemned/` is enumerated only if that
   * lookup finds nothing (`orElse` is by-name), so its enumeration is strictly later. Teardown
   * renames a session from the root into `condemned/` in one atomic move, one direction only,
   * carrying its records with it, and deletes the record last. So a session enumerated live but
   * renamed away before its record is looked up is already in `condemned/` when that later,
   * fresh enumeration runs, and one gone from both is a teardown that finished — its server
   * ended before the record was deleted. `betweenScan` is the tests' seam for the instant
   * between the live enumeration and its lookup, where that rename races; the caller holding
   * this hash's build lock keeps a new owner from appearing during the check.
   *
   * A record whose group is dead (groupIsDead) owns nothing: its owner has not yet deleted a
   * record another process's retirement, or the group's own end, left behind, and it would
   * otherwise block admission until it did. A record whose group lives, or whose leader is gone
   * while a member is listed, owns as the record says.
   */
  def runtimeOwner(
    root: Path, except: Path, record: String, processes: Processes, betweenScan: () => Unit = () => (),
  ): Option[Path] =
    def owns(session: Path): Boolean =
      val file = session.resolve(RecordsDir).resolve(record)
      Files.exists(file) && !groupIsDead(file, processes)
    val inRoot = allBrokerSessions(root, except)
    betweenScan()
    inRoot.find(owns).orElse(collectingSessions(root).find(owns))

  /** Whether the record's group is proved gone: the leader gone and no member listed, or the
    * leader's pid recycled — which proves the group empty at some instant, its number a
    * stranger's since (endRecordedGroup). A record that does not parse, and an observation ps
    * could not make, prove nothing: false. */
  def groupIsDead(record: Path, processes: Processes): Boolean =
    val parsed =
      try parseRecord(Files.readString(record, UTF_8))
      catch case _: IOException => None
    parsed.exists: known =>
      try
        processes.startOf(known.pgid) match
          case Some(start) => start != known.leaderStart
          case None        => processes.groupEmpty(known.pgid)
      catch case _: IOException => false

  /** Whether the spawn a record names still runs its command: the leader alive with the recorded
    * start time, and no exit published beside the record. Neither alone answers: the leader
    * outlives its command by design, and a group killed whole publishes no exit. */
  def spawnLives(record: Path, processes: Processes): Boolean =
    val parsed =
      try parseRecord(Files.readString(record, UTF_8))
      catch case _: IOException => None
    parsed.exists(known => processes.startOf(known.pgid).contains(known.leaderStart))
      && !Files.exists(exitRecord(record))

  // ---------------------------------------------------------------------------
  // Publication
  // ---------------------------------------------------------------------------

  /** A published, locked session. The lock channel lives as long as its owner; closing it is
    * what frees the session for a scavenger. */
  final class Session(val directory: Path, lockChannel: FileChannel):
    def tmp: Path = directory.resolve(TmpDir)
    def records: Path = directory.resolve(RecordsDir)
    def close(): Unit = lockChannel.close()

  /**
   * Create in staging, lock there, rename into the root: a scanned entry is locked by
   * construction, so a free lock always means a dead session. The root lock covers creating the
   * staging entry through the rename — the scavenger's staging cleanup takes the same lock, so it
   * can never delete a directory whose creator has not locked it yet.
   */
  def publish(root: Path, project: Path, kind: Kind = Kind.Command): Either[String, Session] =
    try
      withRootLock(root):
        val staging = Files.createDirectories(root.resolve(StagingDir), ownerOnly)
        val entry = Files.createTempDirectory(staging, kind.prefix, ownerOnly)
        Files.createDirectory(entry.resolve(TmpDir), ownerOnly)
        Files.createDirectory(entry.resolve(RecordsDir), ownerOnly)
        Files.writeString(entry.resolve(ProjectFile), project.toString + "\n", UTF_8)
        val channel = FileChannel.open(
          entry.resolve(LockFile),
          StandardOpenOption.CREATE_NEW,
          StandardOpenOption.WRITE,
        )
        if channel.tryLock() == null then
          channel.close()
          Left(s"could not take the new session's lock in $entry")
        else
          val published = root.resolve(entry.getFileName)
          Files.move(entry, published, StandardCopyOption.ATOMIC_MOVE)
          Right(Session(published, channel))
    catch case ex: IOException => Left(s"publishing a session under $root: ${ex.getMessage}")

  /** Remove this session's directory. The lock is released by deletion's end; nothing here needs
    * the root lock. */
  def remove(session: Session): Unit =
    deleteSessionTree(session.directory)
    session.close()

  /**
   * A session's teardown: run once, by its owner at the end of its work or by the JVM's shutdown
   * hook on a signal — SIGINT and SIGTERM end a JVM through its hooks, never by unwinding to
   * `finally`. Synchronized, not merely once: the JVM halts when its hooks return, so the losing
   * caller must block until the whole cleanup is done, never return early into a halting JVM.
   */
  final class Teardown(body: Boolean => Unit):
    private var done = false
    def apply(bySignal: Boolean): Unit = synchronized:
      if !done then
        done = true
        body(bySignal)

  /**
   * The wrapper's own step 11, through the scavenger's own steps: condemn the session first — the
   * command's grants are path-based and name the original pathname, so after the rename no process
   * it started can redirect what `collect`'s canonicalization proves — then collect it: recorded
   * groups ended behind their live spawn leaders, the server with them, the directory deleted.
   * Asking the server by protocol is how the scavenger reaches the leaderless orphan; here the
   * group is provable and the TERM is the proof-clean end (the server flushes its portfile on
   * TERM). The session's own lock is held through the collection — the exclusivity every other
   * collector respects (scavenge) — and released only after. `beforeRemoval` sees the condemned
   * directory once its groups are ended, the wrapper's moment to read the session's logs
   * (RunOnHostSandbox.appendSessionLogs). A failed rename falls back to ending the recorded groups
   * and removing in place, with no shutdown sent to any socket and no logs read: at the original
   * pathname a process the command started could still redirect a read. A group alive after that
   * keeps the directory where it is, its lock released: the next scavenge condemns it and retries.
   */
  def endSession(root: Path, session: Session, processes: Processes,
    shutdown: Path => ServerAnswer, beforeRemoval: Path => Unit = _ => (),
    retirementDeadlineMillis: Long = RetirementDeadlineMillis): Vector[Collected] =
    val condemned =
      try
        val condemnedRoot = Files.createDirectories(root.resolve(CondemnedDir), ownerOnly)
        val entry = condemnedRoot.resolve(session.directory.getFileName)
        Files.move(session.directory, entry, StandardCopyOption.ATOMIC_MOVE)
        Some(entry)
      catch case _: IOException => None
    condemned match
      case Some(entry) =>
        val actions = collect(root, entry, processes, shutdown, beforeRemoval, retirementDeadlineMillis)
        session.close()
        actions
      case None =>
        val ended = endRecordedGroups(root, session.records, processes, retirementDeadlineMillis)
        if ended.exists(_.keeps) then session.close() else remove(session)
        ended

  // ---------------------------------------------------------------------------
  // Scavenging
  // ---------------------------------------------------------------------------

  /**
   * Every start runs this before publishing its own session. Condemned entries first — they are
   * work an earlier, killed scavenger left — then every unlocked published entry is condemned and
   * collected, then staging litter is cleared under the root lock. A condemned entry is collected
   * only under its own lock — the same lock its session held — so two starts, or a start and the
   * wrapper's own step 11, never signal or delete the same entry concurrently. The build locks
   * and the retirement locks are skipped by name: a directory without a `lock` file reads as a
   * dead session here.
   *
   * `ownSession` is the caller's own live session, which it must pass when it scavenges after
   * publishing — the broker between commands (RunOnHostSandbox.BrokerRuntimes). That session is
   * skipped entirely: `lockIsFree` opens a second descriptor to the lock file and closes it, and
   * OpenJDK's `FileChannel.lock` is a POSIX `fcntl` lock, which the kernel drops for the whole
   * process when *any* descriptor to that file is closed. Probing the caller's own lock would
   * release it, and another launch could then condemn a live session. A start that scavenges
   * before publishing (the wrapper, and the broker at startup) holds no session yet and passes
   * None.
   */
  def scavenge(
    root: Path, processes: Processes, shutdown: Path => ServerAnswer, ownSession: Option[Path] = None,
    retirementDeadlineMillis: Long = RetirementDeadlineMillis,
  ): Vector[(Path, Vector[Collected])] =
    val results = Vector.newBuilder[(Path, Vector[Collected])]
    val condemnedRoot = root.resolve(CondemnedDir)
    val skipNames = Set(StagingDir, CondemnedDir, RootLockFile, BuildLockDir, RetireLockDir)

    def collectLocked(entry: Path): Unit =
      lockForCollection(entry) match
        case Claim.Taken(lock) =>
          try
            results += entry ->
              collect(root, entry, processes, shutdown, retirementDeadlineMillis = retirementDeadlineMillis)
          finally lock.close()
        case Claim.Held    => ()
        case Claim.HalfDeleted => deleteTree(entry)

    if Files.isDirectory(condemnedRoot) then
      listDirectory(condemnedRoot).foreach(collectLocked)

    listDirectory(root)
      .filterNot(p => skipNames.contains(p.getFileName.toString) || ownSession.contains(p))
      .filter(Files.isDirectory(_))
      .foreach: entry =>
        if lockIsFree(entry.resolve(LockFile)) then
          Files.createDirectories(condemnedRoot, ownerOnly)
          val condemned = condemnedRoot.resolve(entry.getFileName)
          try
            Files.move(entry, condemned, StandardCopyOption.ATOMIC_MOVE)
            collectLocked(condemned)
          catch case _: IOException => () // a concurrent scavenger won the rename; its work now

    try
      withRootLock(root):
        listDirectory(root.resolve(StagingDir)).foreach(deleteTree)
        Right(())
    catch case _: IOException => ()

    results.result()

  /**
   * End what one condemned directory's records name, then delete it — unless a server was asked
   * and did not answer, or a group is still listed after its KILL: then the directory, records and
   * socket stay for the next start to retry, because deleting them would strand a live server
   * nothing can reach, or a group nothing else names. A group is signalled only
   * while its recorded leader is alive with the recorded start time: a dead or mismatched leader
   * frees the pgid for strangers, so those groups are skipped and only the portfile-attributed
   * server is ended, by asking it.
   */
  def collect(root: Path, condemned: Path, processes: Processes,
    shutdown: Path => ServerAnswer, beforeRemoval: Path => Unit = _ => (),
    retirementDeadlineMillis: Long = RetirementDeadlineMillis): Vector[Collected] =
    val actions = endRecordedGroups(root, condemned.resolve(RecordsDir), processes, retirementDeadlineMillis) ++
      collectServers(root, condemned, shutdown)
    // Whatever the reader does, the deletion follows it.
    try beforeRemoval(condemned)
    finally
      if !actions.exists(_.keeps) then deleteSessionTree(condemned)
    actions

  /** End every group the records name and prove — the scavenger's core. */
  def endRecordedGroups(
    root: Path, recordsDir: Path, processes: Processes, retirementDeadlineMillis: Long = RetirementDeadlineMillis,
  ): Vector[Collected] =
    listDirectory(recordsDir).flatMap(endRecordedGroup(root, _, processes, retirementDeadlineMillis))

  /** End the group one record names, if it proves one; None for a file that is no record. Under
    * the record's retirement lock (retirementLockFile), the record read only once it is held.
    * The record outlives anything but a proven end or a proven absence: a group with a member
    * listed — after its KILL, or behind a leader that is gone, when the members may still be the
    * record's, since a pgid is not reused while its group has one — or an observation that
    * failed, is GroupAlive, which every deleter of records keeps. A recycled leader proves the
    * group empty at some point, and what its pgid lists now is another group's. The listed
    * members are never ended by their own pid and start time: a group empty at any unobserved
    * instant frees its number, a stranger's group can hold it, that leader can exit leaving
    * children, and a start-time recheck binds the signal to the process observed, never to the
    * record; a leaderless group with members is reached by its owner's teardown, or the
    * scavenger, asking the server by protocol at the socket proved inside the condemned session
    * (collectServers), and blocks admission until then. */
  def endRecordedGroup(
    root: Path, file: Path, processes: Processes, retirementDeadlineMillis: Long = RetirementDeadlineMillis,
  ): Option[Collected] =
    def busy(reason: String) = Some(Collected.RetirementBusy(file.getFileName.toString, reason))
    try
      underRetirementLock(root, file, retirementDeadlineMillis)(endProvedGroup(file, processes))
        .getOrElse(busy(s"the retirement lock was not free within ${retirementDeadlineMillis / 1000}s"))
    catch case ex: IOException => busy(s"the retirement lock: ${ex.getMessage}")

  private def endProvedGroup(file: Path, processes: Processes): Option[Collected] =
    val parsed =
      try parseRecord(Files.readString(file, UTF_8))
      catch case _: IOException => None
    parsed.map: record =>
      try
        processes.startOf(record.pgid) match
          case Some(start) if start == record.leaderStart =>
            if processes.endGroup(record.pgid) then Collected.GroupEnded(record.pgid)
            else Collected.GroupAlive(record.pgid, "a member is listed after the KILL")
          case Some(_) =>
            Collected.GroupSkipped(record.pgid, "pid recycled: start time differs")
          case None if processes.groupEmpty(record.pgid) =>
            Collected.GroupSkipped(record.pgid, "leader gone: pgid no longer provable")
          case None =>
            Collected.GroupAlive(record.pgid, "leader gone, a member still listed")
      catch case ex: IOException => Collected.GroupAlive(record.pgid, s"ps could not answer: ${ex.getMessage}")

  /**
   * The portfile attribution, for each build directory the session's build files name — the
   * directories its servers ran in — or, for a session without one, its recorded project: the
   * directory's `project/target/active.json` names a `local://` socket, and one under the
   * session's *original* path is our server and no other. The socket moved with the
   * condemnation rename, so the portfile's spelling is remapped before the shutdown is sent to
   * it — and sent only to a pathname proven inside the condemned directory: the portfile is the
   * command's to write, so its spelling is a claim, and canonicalization is the proof.
   */
  def collectServers(root: Path, condemned: Path, shutdown: Path => ServerAnswer): Vector[Collected] =
    val builds = buildDirectories(condemned).map(_(1))
    val projectFile = condemned.resolve(ProjectFile)
    val directories =
      if builds.nonEmpty then builds
      else if !Files.isRegularFile(projectFile) then Vector.empty
      else
        try Vector(Path.of(Files.readString(projectFile, UTF_8).trim))
        catch case _: IOException => Vector.empty
    if directories.isEmpty then Vector(Collected.ServerSkipped("no recorded project"))
    else directories.map(collectServer(root.resolve(condemned.getFileName), condemned, _, shutdown))

  private def collectServer(
    original: Path, condemned: Path, buildDirectory: Path, shutdown: Path => ServerAnswer,
  ): Collected =
    val portfile = buildDirectory.resolve("project").resolve("target").resolve("active.json")
    if !Files.isRegularFile(portfile) then Collected.ServerSkipped(s"no portfile in $buildDirectory")
    else
      try
        portfileSocket(Files.readString(portfile, UTF_8)) match
          case Some(socket) if socket.startsWith(original) =>
            containedSocket(condemned.resolve(original.relativize(socket)), condemned) match
              case None =>
                Collected.ServerSkipped("the portfile socket does not resolve inside the command directory")
              case Some(moved) =>
                shutdown(moved) match
                  case ServerAnswer.ShutDown       => Collected.ServerShutDown(moved)
                  case ServerAnswer.Unreachable(_) =>
                    Collected.ServerSkipped("nothing behind the socket; the server is gone")
                  case ServerAnswer.Unanswered(reason) =>
                    Collected.ServerUnanswered(moved, reason)
          case Some(_) => Collected.ServerSkipped("portfile socket is not this command's")
          case None    => Collected.ServerSkipped("portfile is not a local-socket one")
      catch case ex: IOException => Collected.ServerSkipped(ex.getMessage)

  /**
   * The socket at its canonical pathname, or None when that leaves `container`: `..` in a
   * portfile's spelling and a symlink beneath the session both point outside, and the unconfined
   * wrapper must never send a shutdown past the session's own boundary.
   */
  def containedSocket(socket: Path, container: Path): Option[Path] =
    try
      val real = socket.toRealPath()
      Option.when(real.startsWith(container.toRealPath()))(real)
    catch case _: IOException => None

  /** The portfile's `{"uri":"local://<path>"}`; anything else — TCP mode, or a format a newer sbt
    * writes — is nobody's to shut down here. */
  def portfileSocket(json: String): Option[Path] =
    val Uri = raw""".*"uri"\s*:\s*"local://([^"]+)".*""".r
    json.linesIterator.mkString match
      case Uri(path) => Some(Path.of(path))
      case _         => None

  // ---------------------------------------------------------------------------
  // Spawning with registration
  // ---------------------------------------------------------------------------

  /**
   * The registration, as the command the wrapper spawns. perl makes itself its own group's
   * leader, publishes `<pgid> <leader start>` beside the record path
   * and renames it into place, then runs the command as its child; any failed step is exit 71
   * instead, which is the spawn ending itself after a condemnation won the race. When the command
   * ends, its exit status (128+signal for a signal death, the shell's convention) is published
   * the same way as `<record>.exit`, and the spawn stays until its group is ended: a group is
   * signalled only behind a live leader, and a command can fork a helper and return, so
   * ownership must not expire with the command. A `.pending` file a kill leaves behind still
   * parses, and still names a group whose leader either matches (ours, ended) or is gone
   * (skipped), so the scavenger reads the records directory without special cases.
   *
   * perl, and not a shell or Python: the leader must be the process the broker started, so that
   * its `Process` handle and the record name one pid, and a shell cannot move itself into a new
   * group — it has no builtin for `setpgid` on its own pid, and `set -m` moves a child job
   * instead, one process below the handle. The lock script needs `flock` held across `exec`
   * (lockedSpawn), which no macOS command offers. Python is not part of macOS: 2.7 was removed
   * in 12.3, and `/usr/bin/python3` is a stub that installs the Command Line Tools. perl is in
   * macOS through 26, deprecated with Python and Ruby since Catalina but not removed; the JVM
   * cannot set a child's group through `ProcessBuilder`, and a compiled helper would need a
   * toolchain on the host. Should perl go, a bundled helper replaces these two scripts.
   */
  def registeredSpawn(record: Path, command: Seq[String]): Seq[String] =
    Seq("/usr/bin/perl", "-e", RegistrationScript, record.toString) ++ command

  val RegistrationScript: String =
    """setpgrp(0, 0) or exit 71;
      |my ($record, @command) = @ARGV;
      |my $start = `ps -o lstart= -p $$`;
      |chomp $start;
      |exit 71 unless $start;
      |open(my $fh, '>', "$record.pending") or exit 71;
      |print $fh "$$ $start\n";
      |close($fh) or exit 71;
      |rename("$record.pending", $record) or exit 71;
      |my $pid = fork;
      |exit 71 unless defined $pid;
      |if ($pid == 0) { exec { $command[0] } @command or exit 71; }
      |waitpid($pid, 0);
      |my $status = ($? & 127) ? 128 + ($? & 127) : $? >> 8;
      |open($fh, '>', "$record.exit.pending") or exit 71;
      |print $fh "$status\n";
      |close($fh) or exit 71;
      |rename("$record.exit.pending", "$record.exit") or exit 71;
      |sleep 3600 while 1;""".stripMargin

  /** Where the spawn publishes the command's exit status, beside its record. */
  def exitRecord(record: Path): Path = record.resolveSibling(s"${record.getFileName}.exit")

  /**
   * The command's exit status. The spawn stays alive after publishing it, so the file, not the
   * process, holds the answer; a spawn gone without one was killed, or ended itself (exit 71)
   * after losing a condemnation race.
   */
  def awaitExit(exitFile: Path, spawn: Process): Either[String, Int] =
    var result: Option[Either[String, Int]] = None
    while result.isEmpty do
      val spawnEnded = !spawn.isAlive // read before the file: a spawn dying after its rename still answers
      if Files.exists(exitFile) then
        result = Some(
          try Files.readString(exitFile, UTF_8).trim.toIntOption.toRight(s"$exitFile holds no status")
          catch case ex: IOException => Left(s"$exitFile: ${ex.getMessage}"),
        )
      else if spawnEnded then
        result =
          Some(Left(s"the spawn ended (exit ${spawn.exitValue}) without publishing an exit status"))
      else Thread.sleep(20)
    result.get

  /**
   * The observations on the real host: `ps` spellings that exist on macOS, where alone this
   * runs. TERM first and KILL after a grace — the server flushes its portfile away on TERM.
   *
   * A listing proves itself by listing this process, selected alongside what is asked (ps ORs
   * its selection criteria): nothing else tells an answer from a failure, since Apple's ps exits
   * 0 with nothing printed when its process-table sysctl fails, and 1 both for nothing selected
   * and for a failed allocation. A listing without this process is no observation.
   */
  object HostProcesses extends Processes:
    private def self: Long = ProcessHandle.current.pid

    def startOf(pid: Long): Option[String] =
      startFrom(lines("ps", "-o", "pid=,lstart=", "-p", s"$self,$pid"), self, pid)

    def endGroup(pgid: Long): Boolean =
      def signal(name: String): Unit =
        java.lang.ProcessBuilder("/bin/kill", s"-$name", "--", s"-$pgid").start().waitFor()
      signal("TERM")
      val settled = (1 to 100).exists { _ => groupEmpty(pgid) || { Thread.sleep(100); false } }
      settled || {
        signal("KILL")
        (1 to 50).exists(_ => groupEmpty(pgid) || { Thread.sleep(100); false })
      }

    def groupEmpty(pgid: Long): Boolean =
      groupEmptyFrom(lines("ps", "-o", "pid=", "-p", self.toString, "-g", pgid.toString), self)

    /** `pid lstart` rows: the pid's start, None when the pid is not listed; IOException when
      * `self` is not either, which is a listing that did not happen. */
    private[launcher] def startFrom(rows: Vector[String], self: Long, pid: Long): Option[String] =
      val parsed = rows.map(_.split("\\s+", 2)).collect { case Array(listed, rest) => listed -> rest.trim }
      if !parsed.exists(_(0) == self.toString) then throw IOException(s"ps did not list $self alongside $pid")
      parsed.collectFirst { case (listed, start) if listed == pid.toString && start.nonEmpty => start }

    /** `pid` rows: whether none but `self` is listed; IOException when `self` is not. */
    private[launcher] def groupEmptyFrom(rows: Vector[String], self: Long): Boolean =
      if !rows.contains(self.toString) then throw IOException(s"ps did not list $self alongside the group")
      rows.forall(_ == self.toString)

    def signal(pid: Long, name: String): Unit =
      java.lang.ProcessBuilder("/bin/kill", s"-$name", "--", pid.toString).start().waitFor()

    /** The trimmed, non-empty lines a host command prints; nothing when it cannot run. */
    private[launcher] def lines(command: String*): Vector[String] =
      try
        val process =
          java.lang.ProcessBuilder(command*).redirectError(java.lang.ProcessBuilder.Redirect.DISCARD).start()
        val output = String(process.getInputStream.readAllBytes(), UTF_8)
        process.waitFor()
        output.linesIterator.map(_.trim).filter(_.nonEmpty).toVector
      catch case _: IOException => Vector.empty

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  private def withRootLock[A](root: Path)(body: => A): A =
    val channel = FileChannel.open(
      root.resolve(RootLockFile),
      StandardOpenOption.CREATE,
      StandardOpenOption.WRITE,
    )
    try
      val lock = channel.lock()
      try body
      finally lock.release()
    finally channel.close()

  /** What a collector's claim on a condemned entry came to. */
  private enum Claim:
    case Taken(lock: FileChannel)
    /** Another collector — a concurrent start, or the wrapper ending its own session — holds it. */
    case Held
    /** No lock file: deleteSessionTree unlinks the lock last, so this is a dead collector's
      * leftover — removed without signalling, since only the lock chain proves ownership. */
    case HalfDeleted

  /** The entry's lock taken for the whole collection. Never created when missing: a fresh inode
    * at the pathname could be taken while the unlinked one still guards a half-deleted tree. */
  private def lockForCollection(entry: Path): Claim =
    try
      val channel = FileChannel.open(entry.resolve(LockFile), StandardOpenOption.WRITE)
      try
        if channel.tryLock() != null then Claim.Taken(channel)
        else
          channel.close()
          Claim.Held
      catch
        case _: (IOException | java.nio.channels.OverlappingFileLockException) =>
          channel.close()
          Claim.Held
    catch
      case _: java.nio.file.NoSuchFileException => Claim.HalfDeleted
      case _: IOException => Claim.Held

  /** Free means dead: a published directory was locked before it became visible, so an untaken
    * lock has no live owner. The probe lock is released at once — condemnation under
    * lockForCollection, not this test, is what makes the collection safe against races. An
    * overlapping lock is this very JVM holding it, which is a live session too. */
  private def lockIsFree(lockFile: Path): Boolean =
    if !Files.exists(lockFile) then true
    else
      try
        val channel = FileChannel.open(lockFile, StandardOpenOption.WRITE)
        try
          val lock = channel.tryLock()
          if lock == null then false
          else
            lock.release()
            true
        finally channel.close()
      catch case _: (IOException | java.nio.channels.OverlappingFileLockException) => false

  private def listDirectory(path: Path): Vector[Path] =
    if !Files.isDirectory(path) then Vector.empty
    else FileHelper.directoryEntries(path)

  /** Deletion for a session directory: every child but the lock, then — only if nothing else
    * survived — the lock and the directory. The lock pathname outlives every other child so that
    * no collector can create and take a fresh inode there while the held one still guards a
    * half-deleted tree; a missing lock therefore always means a tree this deletion left half-deleted
    * (Claim.HalfDeleted). A child that would not delete — an unreadable subtree, say — keeps the
    * entry locked and collectable instead of leaving a lockless directory that still holds
    * records. */
  private def deleteSessionTree(entry: Path): Unit =
    listDirectory(entry).filterNot(_.getFileName.toString == LockFile).foreach(deleteTree)
    if listDirectory(entry).forall(_.getFileName.toString == LockFile) then deleteTree(entry)

  private def deleteTree(path: Path): Unit =
    try
      if Files.isDirectory(path, java.nio.file.LinkOption.NOFOLLOW_LINKS) then
        listDirectory(path).foreach(deleteTree)
      Files.deleteIfExists(path)
    catch case NonFatal(_) => ()
