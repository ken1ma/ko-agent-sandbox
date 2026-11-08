// The host command's lifecycle.
//
// - A command session is one supervisor invocation.
// - The runner's session is one launch. The runner publishes and locks it the same way, and the session holds the
//   runtimes that the runner's commands share (RunnerRuntimes).
// - A session's directory is published by rename, so it is never seen half-made.
// - A session's lock marks its owner as live, and its records identify the child processes.
// - The filesystem and process operations are injected, so unit tests check the kill interleavings without
//   requiring macOS or a real SIGKILL.
//
// The records keep one rule: no process may outlive its record.
//
// - The leader is the process that registeredSpawn starts. The leader makes itself its own group's leader and
//   publishes `<pgid> <leader start time>` by rename before it runs the command. The leader aborts when the rename
//   fails. A kill at any instant therefore leaves a complete record or a child that ends itself.
// - The leader stays after the command ends and publishes its exit status beside the record. Teardown can therefore
//   still check the leader's start time before it signals the group.
// - The scavenger condemns a directory by renaming it out of the scanned root. The scavenger then reads the records,
//   ends what they name, and only then deletes the directory.
// - Every ending of a runtime's recorded group, by whichever process, runs under that group's retirement lock
//   (retirementLockFile).

package agentsandbox.launcher

import java.io.IOException
import java.nio.channels.FileChannel
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path, StandardCopyOption, StandardOpenOption}

import scala.jdk.CollectionConverters.*
import scala.util.control.NonFatal

import agentsandbox.egress.LogHelper.sha256Hex

import RunOnHostPrereqs.Program

object RunOnHostSession:

  val LockFile = "lock"
  val TmpDir = "tmp"
  val RecordsDir = "records"
  val WorkspaceFile = "workspace"
  /** The runner's file naming the launch's sandbox container. `--stats` joins the runner to its session by that
    * file. */
  val RunFile = "run"
  val StagingDir = "staging"
  val CondemnedDir = "condemned"
  val RootLockFile = "root-lock"
  val BuildLockDir = "build-lock"
  val RetireLockDir = "retire-lock"
  val BuildFilePrefix = "build-"

  /** Whose lock a session's lock is, and the prefix that names the session's directory. The runner's session lives
    * for the launch's lifetime, and a command's session lives for its supervisor's. */
  enum Kind(val prefix: String):
    case Runner extends Kind("r")
    case Command extends Kind("s")

    /** Whether `name` is a session directory of this kind: the prefix, then the digits that
      * `Files.createTempDirectory` appends. A fixed root entry that shares the letter, such as `retire-lock` or
      * `root-lock`, is therefore no session directory. */
    def names(name: String): Boolean =
      name.length > prefix.length && name.startsWith(prefix) && name.drop(prefix.length).forall(_.isDigit)

  /** One registered process group: the leader's pgid (== its pid) and the leader's start time.
    *
    *   - The start time is spelled exactly as `ps -o lstart=` prints it.
    *   - The start time is compared as a string, never parsed, because only equality with a later observation
    *     matters. */
  case class Record(pgid: Long, leaderStart: String)

  def renderRecord(record: Record): String = s"${record.pgid} ${record.leaderStart}\n"

  def parseRecord(text: String): Option[Record] =
    text.trim.split(" ", 2) match
      case Array(pid, start) if start.nonEmpty => pid.toLongOption.map(Record(_, start))
      case _                                   => None

  /** The suffix of a file being written. The file's rename publishes it (publishByRename). */
  val PendingSuffix = ".pending"

  /** `text` at `file`, published by rename from its PendingSuffix sibling. */
  def publishByRename(file: Path, text: String): Unit =
    val pending = file.resolveSibling(s"${file.getFileName}$PendingSuffix")
    Files.writeString(pending, text, UTF_8)
    Files.move(pending, file, StandardCopyOption.ATOMIC_MOVE)

  /** The record in `file`, or None when it is absent, unreadable or not a record. */
  def readRecord(file: Path): Option[Record] =
    FileHelper.readIfReadable(file).flatMap(parseRecord)

  /** What the scavenger observes and does about processes, injected because the tests exercise the decision
    * protocol and a real implementation runs only on macOS. */
  trait Processes:
    /** `ps -o lstart= -p pid`, or None when no such process exists. An observation that could not be made throws
      * IOException, and never gives None, which the callers read as absence. */
    def startOf(pid: Long): Option[String]

    /** Ends the whole group, TERM then KILL after a grace period. Returns whether `ps` then listed no member.
      *
      *   - A listing that could not be made proves nothing.
      *   - A sent signal proves nothing either. A member can exit before the signal arrives, so the listing
      *     decides. */
    def endGroup(pgid: Long): Boolean

    /** Whether `ps` lists no member of the group. Throws IOException when `ps` could not say. */
    def groupEmpty(pgid: Long): Boolean

    /** `kill -<name> <pid>`, to one process. The caller checks first that the pid still has the start time it
      * observed. */
    def signal(pid: Long, name: String): Unit

  /** How one collected session ended up, for the supervisor's report. */
  enum Collected:
    case GroupEnded(pgid: Long)
    /** A member is still listed, after the KILL or with the leader gone, or no listing could be made. The record is
      * kept, and the next collection retries. */
    case GroupAlive(pgid: Long, reason: String)
    case GroupSkipped(pgid: Long, reason: String)
    case ServerShutDown(socket: Path)
    case ServerSkipped(reason: String)
    /** The server is alive but does not answer. The server's condemned directory is kept, and the next start
      * retries. */
    case ServerUnanswered(socket: Path, reason: String)
    /** Another process held the record's retirement lock past the bound, or the lock could not be opened. Nothing
      * was read or signalled, the record is kept, and the next collection retries. */
    case RetirementBusy(record: String, reason: String)

    /** Whether this outcome keeps the directory, records and all, for the next collection. */
    def keeps: Boolean = this match
      case GroupAlive(_, _) | ServerUnanswered(_, _) | RetirementBusy(_, _) => true
      case _                                                                => false

  /** What a shutdown sent to a socket established. RunOnHostSbtServerShutdown is the real sender. */
  enum ServerAnswer:
    case ShutDown
    /** The connect itself failed before reaching a server, so there is no server to stop. */
    case Unreachable(reason: String)
    /** A server accepted the connect but did not finish shutting down before the bound. */
    case Unanswered(reason: String)

  // ---------------------------------------------------------------------------
  // The supervisor root
  // ---------------------------------------------------------------------------

  /** The supervisor root, within RunOnHostPrereqs.SessionTmpMaxLength's budget, because every session's `tmp/` lies
    * beneath it. */
  def root(uid: Int): Path = Path.of(s"/private/tmp/ko-agent-$uid")

  /**
   * Creates the root when absent, and checks that it can be trusted.
   *
   *   - `/private/tmp` is shared and sticky. The root is therefore trusted the way an XDG runtime directory is: it
   *     must be this user's, have mode 0700 and be no symlink. Any other root is refused.
   *   - The root is created with mode 0700, so there is no window at the default mode.
   *   - This method creates the root first and checks that it exists second, rather than looking first. Two launches
   *     that make the root at once would both find it absent. The launch whose creation loses goes on to the checks,
   *     and the checks are what make the root trusted.
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
   * The build lock of one build directory and program, `build-lock/<program>-<hash>`.
   *
   *   - The command's own process holds the lock for its whole life, teardown included. No two launches therefore run
   *     or clean up a command on one build at once, and a runner's death frees nothing the supervisor holds.
   *   - The lock holder (lockedSpawn) takes the lock through flock(2), whose lock belongs to the open file
   *     description:
   *     - The lock survives the exec into the supervisor.
   *     - The lock reaches none of the supervisor's own children, because a JVM's children get only their three
   *       standard descriptors.
   *     - The lock is released when the supervisor exits. A killed supervisor's lock is released at once, and the
   *       next start's scavenge cleans up behind it.
   *   - A lock holder still waiting for the lock is a child like any other, ended when its requester leaves.
   *   - Under the runner, the lock holder also watches the runner's pipe on its stdin, as the supervisor does, and
   *     ends at the pipe's EOF. A dead runner therefore dispatches nothing.
   *   - Under the runner, the lock holder execs only on the runner's word (lockedSpawn). The runner's own work on the
   *     build before the command therefore also happens under the lock: observing, retiring or creating its runtime.
   *   - The file is never deleted. If one name were deleted and recreated, two holders could lock different inodes.
   */
  def buildLockFile(root: Path, program: String, buildDirectory: Path): Either[String, Path] =
    try
      Right(Files.createDirectories(root.resolve(BuildLockDir), ownerOnly)
        .resolve(s"$program-${buildHash(buildDirectory)}"))
    catch case ex: IOException => Left(s"the build locks under $root: ${ex.getMessage}")

  /** The command under the build lock.
    *
    *   - The lock holder is perl (registeredSpawn explains why). The holder takes the lock and execs the command while
    *     holding it, so the lock ends exactly when the command does, however the command dies.
    *   - When the holder has to wait, it says so on stderr, which is the requester's.
    *   - With `underRunner`, the holder's stdin is the runner's pipe (RunOnHostChannel.dispatch):
    *     - EOF while the holder waits ends the holder.
    *     - Once the holder has the lock, it writes `LockedLine` on its stdout and reads the runner's word from the
    *       pipe. The word is `runWord`, whose arguments the holder inserts before the command's `--`, or
    *       `refusedWord`, whose message the holder prints on stderr before exiting 2, the supervisor's own refusal
    *       code.
    *     - The holder reads the word one byte at a time, so what the runner writes after the word stays in the pipe
    *       for the command (RunOnHostSandbox.CredentialsOption).
    *   - Exit 71 means that the holder ended itself, as the leader does in registeredSpawn. */
  def lockedSpawn(lockFile: Path, command: Seq[String], underRunner: Boolean): Seq[String] =
    Seq("/usr/bin/perl", "-e", LockScript, lockFile.toString, if underRunner then "1" else "0") ++ command

  val LockedLine = "locked"

  private val Nul = 0.toChar.toString

  /** The runner's word to a lock holder: one line of NUL-separated fields, the verdict first. Each field is escaped,
    * so that a refusal of several lines, such as quoted server output, and an argument holding a newline or a NUL
    * arrive whole. */
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
      |my ($lock, $runner, @command) = @ARGV;
      |open(my $fh, '>>', $lock) or exit 71;
      |unless (flock($fh, LOCK_EX | LOCK_NB)) {
      |    print STDERR "waiting for the build lock: another launch's command runs in this build directory\n";
      |    if ($runner) {
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
      |if ($runner) {
      |    syswrite(STDOUT, "locked\n") or exit 71;
      |    my $word = '';
      |    while (1) {
      |        exit 71 unless sysread(STDIN, my $byte, 1);
      |        last if $byte eq "\n";
      |        $word .= $byte;
      |    }
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
   * The retirement lock of one build directory and program, `retire-lock/<program>-<hash>`.
   *
   * Every process that ends a runtime's recorded group holds this lock across the leader's start-time check and the
   * group's signal, and across nothing else. Those processes are:
   *
   *   - the runner replacing or retiring its own runtime (RunnerRuntimes.discard, RunOnHostMillDaemons.retire);
   *   - the runner's teardown;
   *   - the scavenger;
   *   - another launch taking the runtime over (RunnerRuntimes.takeOver).
   *
   * Why a lock of its own:
   *
   *   - Two processes running that check-then-signal on one group would correlate the pid recycling window. The first
   *     process's kill frees the pids at the moment the second process's kill is on its way, its check already passed.
   *   - The build lock would not do, because a command holds it for its whole life. A teardown would then wait on
   *     another launch's build before ending its own server.
   *   - The record is read only under the lock, so a holder acts on what the previous holder left.
   *
   * The lock order is one-way, and the retirement lock is always last:
   *
   *   - Preparation holds the build lock, then the runtimes' monitor.
   *   - Teardown holds the monitor and the session's own lock.
   *   - Scavenging holds the condemned entry's lock.
   *   - Nothing takes a build lock, a session lock or the monitor while holding a retirement lock, and no process holds
   *     two retirement locks at once. No wait can therefore cycle.
   *   - Death releases the lock and not the group, so the next holder validates as every holder does.
   *   - A lock that is not free within RetirementDeadlineMillis gives Collected.RetirementBusy, which keeps the record
   *     for the next collection.
   *   - The lock files are never deleted, like the build locks (buildLockFile explains why). The scavenge's root scan
   *     skips the directory, which it would otherwise read as a dead session.
   *
   * Within one process, one thread at a time opens, locks, releases and closes a lock file's channel
   * (retirementPermits).
   *
   *   - OpenJDK's lock is a POSIX fcntl lock. The kernel drops such a lock for the whole process when any descriptor to
   *     the file is closed. scavenge has the same caveat for the session lock.
   *   - A waiter's channel closed on its timeout would therefore end another thread's exclusion against other
   *     processes. So would a holder's channel still open when the next thread has locked a fresh one.
   *   - Two threads do contend. The acceptance test's entry prepares its runtime on the main thread and tears the
   *     session down from the shutdown hook (RunOnHostSandbox.ownRuntime). The runner's monitor covers neither the
   *     supervisor nor the tests.
   *
   * Only the records that name a runtime another launch could end map to a lock (retirementLockName). A command
   * session's own records and the Gradle daemons' records are ended by their session's owner. Once the owner is dead,
   * the collector that holds the session's lock ends them, and that lock already excludes every other ender.
   */
  def retirementLockFile(root: Path, name: String): Path =
    Files.createDirectories(root.resolve(RetireLockDir), ownerOnly).resolve(name)

  /** A runtime's record names, by its build directory's hash (buildHash): the proxy's record, and the ownership
    * records of the directory's sbt server and mill daemon. Another launch's runner reads the ownership records to
    * attach or take over (runtimeOwner). */
  def proxyRecordName(program: Program, hash: String): String = s"proxy-${program.name}-$hash"
  def serverRecordName(hash: String): String = s"server-sbt-$hash"
  def daemonRecordName(hash: String): String = s"daemon-mill-$hash"

  /** The program and hash a proxy's record name holds (proxyRecordName), or None. */
  def proxyRecordOf(recordName: String): Option[(Program, String)] =
    recordName match
      case RuntimeRecordName("proxy", program, hash) => Program.named(program).map(_ -> hash)
      case _                                         => None

  /** `<program>-<hash>` for a runtime's record, a `.pending` record included, and None for every other record. */
  def retirementLockName(recordName: String): Option[String] =
    recordName.stripSuffix(PendingSuffix) match
      case RuntimeRecordName(_, program, hash) => Some(s"$program-$hash")
      case _                                  => None

  private val RuntimeRecordName = raw"(proxy|server|daemon)-([a-z]+)-([0-9a-f]{16})".r

  /** Longer than the fifteen seconds that a holder's TERM, grace period and KILL take at most (termThenKill). */
  val RetirementDeadlineMillis = 20_000L

  /** This process's one permit per lock file, held from the channel's open to its close. A thread that takes a lock
    * it already holds waits for the permit until the deadline and gets RetirementBusy, never a second descriptor. */
  private val retirementPermits = java.util.concurrent.ConcurrentHashMap[Path, java.util.concurrent.Semaphore]()

  /**
   * Runs `body` under the record's retirement lock, taken within `deadlineMillis`. Returns None when the lock was not
   * taken in time.
   *
   *   - A record whose name maps to no lock runs `body` at once.
   *   - This method takes the permit first, then the channel. No other thread of this process touches the file while
   *     this thread holds it.
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

  /** The hash that names one build directory's lock and records: 16 hex digits of the SHA-256 of the directory's
    * canonical spelling. */
  def buildHash(buildDirectory: Path): String = sha256Hex(buildDirectory.toString).take(16)

  /** `build-<hash>`, which holds the canonical build directory that the records of that hash serve.
    *
    *   - The file is published by rename before the first record of the hash, and removed after the last record is
    *     retired.
    *   - A reader from another session therefore takes one runtime's directory and its processes together. The reader
    *     never takes a directory of one runtime and a process of its successor.
    *   - A record without its file is attributed to no build directory, and is skipped. */
  def buildFile(sessionDirectory: Path, hash: String): Path =
    sessionDirectory.resolve(s"$BuildFilePrefix$hash")

  def publishBuildFile(sessionDirectory: Path, hash: String, buildDirectory: Path): Either[String, Path] =
    val file = buildFile(sessionDirectory, hash)
    try
      publishByRename(file, buildDirectory.toString + "\n")
      Right(file)
    catch case ex: IOException => Left(s"publishing $file: ${ex.getMessage}")

  /** The build directories a session's build files name, by hash. */
  def buildDirectories(sessionDirectory: Path): Vector[(String, Path)] =
    listDirectory(sessionDirectory).flatMap: file =>
      val name = file.getFileName.toString
      if !name.startsWith(BuildFilePrefix) || name.endsWith(PendingSuffix) then None
      else FileHelper.readIfReadable(file).map(text => name.stripPrefix(BuildFilePrefix) -> Path.of(text.trim))

  /** The other live runners' sessions under the root: those published under the runner prefix and locked. A runner
    * attaches to another launch's runtime only from one of these sessions (RunnerRuntimes.attached). */
  def liveRunnerSessions(root: Path, except: Path): Vector[Path] =
    allRunnerSessions(root, except).filter(entry => !lockIsFree(entry.resolve(LockFile)))

  /** Every runner session directory under the root, locked or not.
    *
    *   - A just-crashed owner's session is unlocked but not yet condemned, and its server group can still be running.
    *     runtimeOwner must therefore weigh that session too.
    *   - A runtime found in such a session is taken over, never attached to, and the next start's scavenge collects
    *     the session. */
  def allRunnerSessions(root: Path, except: Path): Vector[Path] =
    listDirectory(root).filter: entry =>
      entry != except && Kind.Runner.names(entry.getFileName.toString) && Files.isDirectory(entry)

  /** The sessions under `condemned/`.
    *
    *   - An owner tearing itself down, or a scavenger, has renamed the session's directory here, and holds the
    *     session's lock while it ends the recorded groups.
    *   - The sessions' ownership records still name the build directories they own. A start therefore consults them
    *     alongside the live sessions until collection deletes them (runtimeOwner). A server whose socket path has
    *     moved with the rename must not read as free.
    *   - The scavenger's own pass runs first, and collects any such session that no live owner still holds. */
  def collectingSessions(root: Path): Vector[Path] =
    listDirectory(root.resolve(CondemnedDir)).filter(Files.isDirectory(_))

  /**
   * Another launch's session that holds the ownership record `record`, `server-sbt-<hash>` or `daemon-mill-<hash>`,
   * or None.
   *
   *   - The owner can be any runner session under the root, live or just crashed and not yet collected. The owner can
   *     also be a session under `condemned/` whose teardown or scavenge has not finished.
   *   - This method only reads the record. Only the record's owner, or the launch taking the runtime over, ends the
   *     record's group, under the retirement lock (RunnerRuntimes.takeOver).
   *   - A dead owner's runtime is taken over this time, and the next start's scavenge collects the owner's session.
   *     The owner's server or daemon is therefore never left running beside a fresh one.
   *
   * The live sessions are enumerated first, then looked up. `condemned/` is enumerated only if that lookup finds
   * nothing (`orElse` is by-name), so its enumeration is strictly later.
   *
   *   - Teardown renames a session from the root into `condemned/` in one atomic move, in one direction only. The move
   *     carries the session's records with it, and teardown deletes the record last.
   *   - A session enumerated live but renamed away before its record is looked up is therefore already in
   *     `condemned/` when the later, fresh enumeration runs.
   *   - A session gone from both places is a teardown that finished. The session's server ended before the record was
   *     deleted.
   *   - Tests use `betweenScan` to act in the instant between the live enumeration and its lookup, where that rename
   *     races.
   *   - The caller holds this hash's build lock, which keeps a new owner from appearing during the check.
   *
   * A record whose group is dead (groupIsDead) owns nothing. Another process's retirement, or the group's own end,
   * left the record behind, and the owner has not yet deleted it. Such a record would otherwise block admission until
   * the owner did. A record whose group lives, or whose leader is gone while a member is listed, owns as the record
   * says.
   */
  def runtimeOwner(
    root: Path, except: Path, record: String, processes: Processes, betweenScan: () => Unit = () => (),
  ): Option[Path] =
    def owns(session: Path): Boolean =
      val file = session.resolve(RecordsDir).resolve(record)
      Files.exists(file) && !groupIsDead(file, processes)
    val inRoot = allRunnerSessions(root, except)
    betweenScan()
    inRoot.find(owns).orElse(collectingSessions(root).find(owns))

  /** Whether the record's group is known to be gone.
    *
    *   - The group is gone when the leader is gone and no member is listed.
    *   - The group is also gone when the leader's pid was recycled. The recycling proves that the group was empty at
    *     some instant, and that its number has belonged to a stranger since (endRecordedGroup).
    *   - A record that does not parse, and an observation that ps could not make, prove nothing, and give false. */
  def groupIsDead(record: Path, processes: Processes): Boolean =
    readRecord(record).exists: known =>
      try
        processes.startOf(known.pgid) match
          case Some(start) => start != known.leaderStart
          case None        => processes.groupEmpty(known.pgid)
      catch case _: IOException => false

  /** Whether the leader that a record names still runs its command: the leader is alive with the recorded start time,
    * and no exit is published beside the record. Neither condition alone answers. The leader outlives its command by
    * design, and a group killed whole publishes no exit. */
  def leaderLives(record: Path, processes: Processes): Boolean =
    readRecord(record).exists(known => processes.startOf(known.pgid).contains(known.leaderStart))
      && !Files.exists(exitRecord(record))

  // ---------------------------------------------------------------------------
  // Publication
  // ---------------------------------------------------------------------------

  /** A published, locked session. The lock channel lives as long as its owner, and closing the channel frees the
    * session for a scavenger. */
  final class Session(val directory: Path, lockChannel: FileChannel):
    def tmp: Path = directory.resolve(TmpDir)
    def records: Path = directory.resolve(RecordsDir)
    def close(): Unit = lockChannel.close()

  /**
   * Creates the session in staging, locks it there, and renames it into the root.
   *
   *   - A scanned entry is locked by construction, so a free lock always means a dead session.
   *   - The root lock covers the steps from creating the staging entry through the rename. The scavenger's staging
   *     cleanup takes the same lock, so it can never delete a directory whose creator has not locked it yet.
   */
  def publish(root: Path, workspaceRoot: Path, kind: Kind = Kind.Command): Either[String, Session] =
    try
      withRootLock(root):
        val staging = Files.createDirectories(root.resolve(StagingDir), ownerOnly)
        val entry = Files.createTempDirectory(staging, kind.prefix, ownerOnly)
        Files.createDirectory(entry.resolve(TmpDir), ownerOnly)
        Files.createDirectory(entry.resolve(RecordsDir), ownerOnly)
        Files.writeString(entry.resolve(WorkspaceFile), workspaceRoot.toString + "\n", UTF_8)
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

  /** Removes this session's directory. The lock is released when the deletion ends. Nothing here needs the root
    * lock. */
  def remove(session: Session): Unit =
    deleteSessionTree(session.directory)
    session.close()

  /**
   * A session's teardown, run once.
   *
   *   - Either the owner runs it at the end of its work, or the JVM's shutdown hook runs it on a signal. SIGINT and
   *     SIGTERM end a JVM through its hooks, never by unwinding to `finally`.
   *   - The teardown is synchronized, not merely run once. The JVM halts when its hooks return, so the losing caller
   *     must block until the whole cleanup is done, and never return early into a halting JVM.
   */
  final class Teardown(body: Boolean => Unit):
    private var done = false
    def apply(bySignal: Boolean): Unit = synchronized:
      if !done then
        done = true
        body(bySignal)

  /**
   * The supervisor's own teardown (RunOnHostSandbox.run), through the scavenger's own steps.
   *
   *   - The teardown condemns the session first. The command's grants are path-based and name the original
   *     pathname, so after the rename no process the command started can change what `collect`'s canonicalization
   *     resolves to.
   *   - The teardown then collects the session: it ends the recorded groups behind their live leaders, the server
   *     with them, and deletes the directory.
   *
   * The teardown's server, lock, logs and fallback:
   *
   *   - The scavenger reaches the leaderless orphan by asking the server by protocol. Here the leader is alive with
   *     its recorded start time, so the group is signalled. TERM is the clean end, since the server flushes its
   *     portfile on TERM.
   *   - The session's own lock is held through the collection and released only after it. Every other collector
   *     respects that exclusivity (scavenge).
   *   - `beforeRemoval` sees the condemned directory once its groups are ended. That is the supervisor's moment to
   *     read the session's logs (RunOnHostSandbox.appendSessionLogs).
   *   - A failed rename falls back to ending the recorded groups and removing the directory in place. No shutdown is
   *     then sent to any socket, and no logs are read: at the original pathname, a process the command started could
   *     still redirect a read.
   *   - A group still alive after that keeps the directory where it is, with its lock released. The next scavenge
   *     condemns the directory and retries.
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
   * Every start runs this before publishing its own session.
   *
   *   - The scavenge collects the condemned entries first, the work that an earlier, killed scavenger left.
   *   - The scavenge then condemns and collects every unlocked published entry.
   *   - The scavenge then clears the staging litter under the root lock.
   *
   * Two rules keep concurrent collectors apart:
   *
   *   - A condemned entry is collected only under its own lock, the same lock its session held. Two starts, or a start
   *     and the supervisor's own teardown, therefore never signal or delete the same entry concurrently.
   *   - The build locks and the retirement locks are skipped by name, because a directory without a `lock` file reads
   *     as a dead session here.
   *
   * `ownSession` is the caller's own live session. The caller must pass it when it scavenges after publishing, as the
   * runner does between commands (RunnerRuntimes).
   *
   *   - The scavenge skips that session entirely. `lockIsFree` opens a second descriptor to the lock file and closes
   *     it. OpenJDK's `FileChannel.lock` is a POSIX `fcntl` lock, which the kernel drops for the whole process when
   *     *any* descriptor to that file is closed.
   *   - Probing the caller's own lock would therefore release it, and another launch could then condemn a live
   *     session.
   *   - A start that scavenges before publishing holds no session yet and passes None. The supervisor does so, and so
   *     does the runner at startup.
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
          catch case _: IOException => () // a concurrent scavenger won the rename, so the entry is its work now

    try
      withRootLock(root):
        listDirectory(root.resolve(StagingDir)).foreach(deleteTree)
        Right(())
    catch case _: IOException => ()

    results.result()

  /**
   * Ends what one condemned directory's records name, then deletes the directory.
   *
   *   - The directory is kept when a server was asked and did not answer, or when a group is still listed after its
   *     KILL. The directory, records and socket then stay for the next start to retry. Deleting them would strand a
   *     live server that nothing can reach, or a group that nothing else names.
   *   - A group is signalled only while its recorded leader is alive with the recorded start time. A dead or
   *     mismatched leader frees the pgid for strangers. Such groups are skipped, and only the portfile-attributed
   *     server is ended, by asking it.
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

  /** Sends TERM and waits up to ten seconds for `gone`, then sends KILL and waits up to five more. Returns whether
    * `gone` held. */
  def termThenKill(gone: => Boolean, signal: String => Unit): Boolean =
    def waited(polls: Int) = (1 to polls).exists(_ => gone || { Thread.sleep(100); false })
    signal("TERM")
    waited(100) || {
      signal("KILL")
      waited(50)
    }

  /** Removes the record and its exit file, and answers Right(ended).
    *
    *   - `ended` is the group's ending (endRecordedGroup). When `ended` keeps the record for the next start to retry,
    *     this method removes nothing and answers Left(kept).
    *   - A failed removal goes to `removalFailed`. */
  def forgetUnlessKept(
    record: Path, ended: Option[Collected], removalFailed: IOException => Unit,
  ): Either[Collected, Option[Collected]] =
    ended match
      case Some(kept) if kept.keeps => Left(kept)
      case _ =>
        try
          Files.deleteIfExists(record)
          Files.deleteIfExists(exitRecord(record))
        catch case ex: IOException => removalFailed(ex)
        Right(ended)

  /** Ends every group the records name, each after checking that its leader has the recorded start time. The method is
    * the scavenger's core. */
  def endRecordedGroups(
    root: Path, recordsDir: Path, processes: Processes, retirementDeadlineMillis: Long = RetirementDeadlineMillis,
  ): Vector[Collected] =
    listDirectory(recordsDir).flatMap(endRecordedGroup(root, _, processes, retirementDeadlineMillis))

  /** Ends the group that one record names, if its leader is alive with the recorded start time. Returns None for a
    * file that is no record.
    *
    *   - The method runs under the record's retirement lock (retirementLockFile), and reads the record only once the
    *     lock is held.
    *   - The record outlives everything but an observed end or an observed absence. These outcomes are GroupAlive,
    *     which every deleter of records keeps:
    *     - a group with a member listed after its KILL;
    *     - a group with a member listed behind a leader that is gone. The members may still be the record's, since a
    *       pgid is not reused while its group has a member;
    *     - an observation that failed.
    *   - A recycled leader proves that the group was empty at some point. What its pgid lists now belongs to another
    *     group.
    *   - The listed members are never ended by their own pid and start time:
    *     - A group that is empty at any unobserved instant frees its number, and a stranger's group can then hold it.
    *     - That stranger's leader can exit and leave children.
    *     - A start-time recheck binds the signal to the process observed, never to the record.
    *   - A leaderless group with members is reached when its owner's teardown, or the scavenger, asks the server by
    *     protocol at the socket resolved inside the condemned session (collectServers). Until then, the group blocks
    *     admission. */
  def endRecordedGroup(
    root: Path, file: Path, processes: Processes, retirementDeadlineMillis: Long = RetirementDeadlineMillis,
  ): Option[Collected] =
    def busy(reason: String) = Some(Collected.RetirementBusy(file.getFileName.toString, reason))
    try
      underRetirementLock(root, file, retirementDeadlineMillis)(endGroupIfLeaderMatches(file, processes))
        .getOrElse(busy(s"the retirement lock was not free within ${retirementDeadlineMillis / 1000}s"))
    catch case ex: IOException => busy(s"the retirement lock: ${ex.getMessage}")

  private def endGroupIfLeaderMatches(file: Path, processes: Processes): Option[Collected] =
    readRecord(file).map: record =>
      try
        processes.startOf(record.pgid) match
          case Some(start) if start == record.leaderStart =>
            if processes.endGroup(record.pgid) then Collected.GroupEnded(record.pgid)
            else Collected.GroupAlive(record.pgid, "a member is listed after the KILL")
          case Some(_) =>
            Collected.GroupSkipped(record.pgid, "pid recycled: start time differs")
          case None if processes.groupEmpty(record.pgid) =>
            Collected.GroupSkipped(record.pgid, "leader gone: no member listed")
          case None =>
            Collected.GroupAlive(record.pgid, "leader gone, a member still listed")
      catch case ex: IOException => Collected.GroupAlive(record.pgid, s"ps could not answer: ${ex.getMessage}")

  /**
   * The portfile attribution, for each build directory that the session's build files name. Those are the
   * directories its servers ran in. For a session without build files, the attribution covers its recorded workspace
   * root.
   *
   *   - The directory's `project/target/active.json` names a `local://` socket. A socket under the session's
   *     *original* path is our server and no other.
   *   - The socket moved with the condemnation rename, so the portfile's spelling is remapped before the shutdown is
   *     sent.
   *   - The shutdown goes only to a pathname that resolves inside the condemned directory. The command may write the
   *     portfile, so the path it names is resolved and compared with the condemned directory (containedSocket).
   */
  def collectServers(root: Path, condemned: Path, shutdown: Path => ServerAnswer): Vector[Collected] =
    val builds = buildDirectories(condemned).map(_(1))
    val workspaceFile = condemned.resolve(WorkspaceFile)
    val directories =
      if builds.nonEmpty then builds
      else FileHelper.readIfReadable(workspaceFile).map(text => Path.of(text.trim)).toVector
    if directories.isEmpty then Vector(Collected.ServerSkipped("no recorded workspace root"))
    else directories.map(collectServer(root.resolve(condemned.getFileName), condemned, _, shutdown))

  private def collectServer(
    original: Path, condemned: Path, buildDirectory: Path, shutdown: Path => ServerAnswer,
  ): Collected =
    val portfile = sbtPortfile(buildDirectory)
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
   * The socket at its canonical pathname, or None when that pathname leaves `container`. `..` in a portfile's
   * spelling and a symlink beneath the session can both point outside. The unconfined supervisor must never send a
   * shutdown past the session's own boundary.
   */
  def containedSocket(socket: Path, container: Path): Option[Path] =
    try
      val real = socket.toRealPath()
      Option.when(real.startsWith(container.toRealPath()))(real)
    catch case _: IOException => None

  /** The file where a running sbt server names its socket. */
  def sbtPortfile(buildDirectory: Path): Path =
    buildDirectory.resolve("project").resolve("target").resolve("active.json")

  /** The portfile's `{"uri":"local://<path>"}`. Nothing else is for this code to shut down, such as TCP mode or a
    * format that a newer sbt writes. */
  def portfileSocket(json: String): Option[Path] =
    val Uri = raw""".*"uri"\s*:\s*"local://([^"]+)".*""".r
    json.linesIterator.mkString match
      case Uri(path) => Some(Path.of(path))
      case _         => None

  // ---------------------------------------------------------------------------
  // Spawning with registration
  // ---------------------------------------------------------------------------

  /**
   * The registration, as the command that the supervisor spawns.
   *
   *   - perl makes itself its own group's leader. perl publishes `<pgid> <leader start>` beside the record path and
   *     renames the file into place, then runs the command as its child.
   *   - Any failed step gives exit 71 instead. Exit 71 means that the leader ended itself after a condemnation won the
   *     race.
   *   - When the command ends, the leader publishes its exit status the same way, as `<record>.exit`. A signal death
   *     gives 128+signal, the shell's convention.
   *   - The leader stays until its group is ended. A group is signalled only behind a live leader, and a command can
   *     fork a helper and return, so ownership must not expire with the command.
   *   - The leader closes its standard input after forking. When the command exits without reading its input, the
   *     writer then gets EPIPE instead of blocking. A host proxy's bindings are such input
   *     (RunOnHostProxy.startProxyUnder).
   *   - A `.pending` file that a kill leaves behind still parses. The file names a group whose leader either matches,
   *     and is ours and ended, or is gone, and is skipped. The scavenger therefore reads the records directory without
   *     special cases.
   *
   * Why perl, and not a shell or Python:
   *
   *   - The leader must be the process that the runner started, so that its `Process` handle and the record name one
   *     pid. A shell cannot move itself into a new group: it has no builtin for `setpgid` on its own pid, and `set -m`
   *     moves a child job instead, one process below the handle.
   *   - The lock script needs `flock` held across `exec` (lockedSpawn), which no macOS command offers.
   *   - Python is not part of macOS. Python 2.7 was removed in 12.3, and `/usr/bin/python3` is a stub that installs
   *     the Command Line Tools.
   *   - perl is in macOS through 26. perl has been deprecated with Python and Ruby since Catalina, but not removed.
   *   - The JVM cannot set a child's group through `ProcessBuilder`, and a compiled helper would need a toolchain on
   *     the host.
   *   - Should perl go, a bundled helper replaces these two scripts.
   */
  def registeredSpawn(record: Path, command: Seq[String]): Seq[String] =
    Seq("/usr/bin/perl", "-e", RegistrationScript, record.toString) ++ command

  val RegistrationScript: String =
    """setpgrp(0, 0) or exit 71;
      |my ($record, @command) = @ARGV;
      |my $start = `/bin/ps -o lstart= -p $$`;
      |chomp $start;
      |exit 71 unless $start;
      |open(my $fh, '>', "$record.pending") or exit 71;
      |print $fh "$$ $start\n";
      |close($fh) or exit 71;
      |rename("$record.pending", $record) or exit 71;
      |my $pid = fork;
      |exit 71 unless defined $pid;
      |if ($pid == 0) { exec { $command[0] } @command or exit 71; }
      |open(STDIN, '<', '/dev/null') or exit 71;
      |waitpid($pid, 0);
      |my $status = ($? & 127) ? 128 + ($? & 127) : $? >> 8;
      |open($fh, '>', "$record.exit.pending") or exit 71;
      |print $fh "$status\n";
      |close($fh) or exit 71;
      |rename("$record.exit.pending", "$record.exit") or exit 71;
      |sleep 3600 while 1;""".stripMargin

  /** Where the leader publishes the command's exit status, beside its record. */
  def exitRecord(record: Path): Path = record.resolveSibling(s"${record.getFileName}.exit")

  /**
   * The command's exit status. The leader stays alive after publishing it, so the file, not the process, holds the
   * answer. A leader gone without a published status was killed, or ended itself (exit 71) after losing a
   * condemnation race.
   */
  def awaitExit(exitFile: Path, leader: Process): Either[String, Int] =
    var result = exitSoFar(exitFile, leader)
    while result.isEmpty do
      Thread.sleep(20)
      result = exitSoFar(exitFile, leader)
    result.get

  /** awaitExit's answer if the command has ended, without waiting. None while the command runs. */
  def exitSoFar(exitFile: Path, leader: Process): Option[Either[String, Int]] =
    val leaderEnded = !leader.isAlive // read before the file, so a leader that dies after its rename still answers
    if Files.exists(exitFile) then
      Some(
        try Files.readString(exitFile, UTF_8).trim.toIntOption.toRight(s"$exitFile holds no status")
        catch case ex: IOException => Left(s"$exitFile: ${ex.getMessage}"),
      )
    else if leaderEnded then
      Some(Left(s"the leader ended (exit ${leader.exitValue}) without publishing an exit status"))
    else None

  /**
   * The observations on the real host, with `ps` spellings that exist on macOS. This object runs on macOS alone.
   *
   *   - The group gets TERM first and KILL after a grace period, because the server flushes its portfile away on TERM.
   *   - Every listing also selects this process, since ps ORs its selection criteria, and this object looks for that
   *     row. Nothing else tells an answer from a failure. Apple's ps exits 0 with nothing printed when its
   *     process-table sysctl fails, and exits 1 both for nothing selected and for a failed allocation.
   *   - A listing without this process is no observation.
   */
  object HostProcesses extends Processes:
    /** macOS's own programs, by absolute path like `/bin/kill`. A bare name would be found through the runner's
      * inherited `PATH` (design.md, "No repository-controlled host executable resolution"). */
    val Ps = "/bin/ps"
    val Pgrep = "/usr/bin/pgrep"
    val Lsof = "/usr/sbin/lsof"

    private def self: Long = ProcessHandle.current.pid

    def startOf(pid: Long): Option[String] =
      startFrom(lines(Ps, "-o", "pid=,lstart=", "-p", s"$self,$pid"), self, pid)

    def endGroup(pgid: Long): Boolean = termThenKill(groupEmpty(pgid), kill(_, s"-$pgid"))

    def groupEmpty(pgid: Long): Boolean =
      groupEmptyFrom(lines(Ps, "-o", "pid=", "-p", self.toString, "-g", pgid.toString), self)

    /** The pid's start from `pid lstart` rows, or None when the pid is not listed. Throws IOException when `self` is
      * not listed either, because then the listing did not happen. */
    private[launcher] def startFrom(rows: Vector[String], self: Long, pid: Long): Option[String] =
      val parsed = rows.map(_.split("\\s+", 2)).collect { case Array(listed, rest) => listed -> rest.trim }
      if !parsed.exists(_(0) == self.toString) then throw IOException(s"ps did not list $self alongside $pid")
      parsed.collectFirst { case (listed, start) if listed == pid.toString && start.nonEmpty => start }

    /** Whether `pid` rows list none but `self`. Throws IOException when `self` is not listed. */
    private[launcher] def groupEmptyFrom(rows: Vector[String], self: Long): Boolean =
      if !rows.contains(self.toString) then throw IOException(s"ps did not list $self alongside the group")
      rows.forall(_ == self.toString)

    def signal(pid: Long, name: String): Unit = kill(name, pid.toString)

    private def kill(name: String, target: String): Unit =
      java.lang.ProcessBuilder("/bin/kill", s"-$name", "--", target).start().waitFor()

    /** The trimmed, non-empty lines a host command prints; nothing when it cannot run. */
    private[launcher] def lines(command: String*): Vector[String] =
      try HostCommands.run(command*).text.linesIterator.map(_.trim).filter(_.nonEmpty).toVector
      catch case _: IOException => Vector.empty

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  private def withRootLock[A](root: Path)(body: => A): A = FileHelper.withFileLock(root.resolve(RootLockFile))(body)

  /** What a collector's claim on a condemned entry came to. */
  private enum Claim:
    case Taken(lock: FileChannel)
    /** Another collector holds the entry: a concurrent start, or the supervisor ending its own session. */
    case Held
    /** The entry has no lock file. deleteSessionTree unlinks the lock last, so the entry is a dead collector's
      * leftover, removed without signalling, since only the lock chain proves ownership. */
    case HalfDeleted

  /** Takes the entry's lock for the whole collection. The lock file is never created when missing: a fresh inode at
    * the pathname could be taken while the unlinked inode still guards a half-deleted tree. */
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

  /** Free means dead: a published directory was locked before it became visible, so an untaken lock has no live owner.
    *
    *   - The probe lock is released at once. Condemnation under lockForCollection, not this test, makes the collection
    *     safe against races.
    *   - An overlapping lock means that this very JVM holds the lock, which is a live session too. */
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

  /** Deletes a session directory: every child but the lock first, then the lock and the directory, only if nothing
    * else survived.
    *
    *   - The lock pathname outlives every other child, so that no collector can create and take a fresh inode there
    *     while the held inode still guards a half-deleted tree. A missing lock therefore always means a tree that this
    *     deletion left half-deleted (Claim.HalfDeleted).
    *   - A child that would not delete, such as an unreadable subtree, keeps the entry locked and collectable. The
    *     deletion then leaves no lockless directory that still holds records. */
  private def deleteSessionTree(entry: Path): Unit =
    listDirectory(entry).filterNot(_.getFileName.toString == LockFile).foreach(deleteTree)
    if listDirectory(entry).forall(_.getFileName.toString == LockFile) then deleteTree(entry)

  private def deleteTree(path: Path): Unit =
    try
      if Files.isDirectory(path, java.nio.file.LinkOption.NOFOLLOW_LINKS) then
        listDirectory(path).foreach(deleteTree)
      Files.deleteIfExists(path)
    catch case NonFatal(_) => ()
