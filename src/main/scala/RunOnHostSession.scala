// The host command's lifecycle. A command session is one wrapper invocation; the broker's session
// is one launch, published and locked the same way by the broker. A session's directory is
// published by rename so it is never seen half-made, its lock marks its owner as live, and its
// records identify the child processes. The filesystem and process operations are injected,
// so unit tests check the kill interleavings without requiring macOS or a real SIGKILL.
//
// The rule the records keep: no process may outlive its record. A spawn becomes its
// own group's leader and publishes `<pgid> <leader start time>` by rename before it runs the
// command, aborting when the rename fails — so a kill at any instant leaves a complete record or
// a child that ends itself. The spawn stays after the command ends, publishing its exit status
// beside the record, so the group stays provable through teardown. The scavenger condemns a
// directory (rename out of the scanned root) before it reads records, ends what they name, and
// only then deletes.

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
  val StagingDir = "staging"
  val CondemnedDir = "condemned"
  val RootLockFile = "root-lock"
  val BuildLockDir = "build-lock"

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
    /** `ps -o lstart= -p pid`, None when no such process exists. */
    def startOf(pid: Long): Option[String]

    /** End the whole group, TERM then KILL after a grace, and wait for it to empty. */
    def endGroup(pgid: Long): Unit

  /** How one collected session ended up, for the wrapper's report. */
  enum Collected:
    case GroupEnded(pgid: Long)
    case GroupSkipped(pgid: Long, reason: String)
    case ServerShutDown(socket: Path)
    case ServerSkipped(reason: String)
    /** Alive but not answering: its condemned directory is kept, and the next start retries. */
    case ServerUnanswered(socket: Path, reason: String)

  /** What a shutdown sent to a socket established (SbtServerShutdown is the real sender). */
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
   * 0700 so there is no window at the default mode.
   */
  def ensureRoot(root: Path, uid: Int): Either[String, Path] =
    try
      if !Files.exists(root, java.nio.file.LinkOption.NOFOLLOW_LINKS) then
        Files.createDirectory(root, ownerOnly)
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

  /** The command under the build lock: perl takes the lock and execs the command holding it.
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

  /** The broker's word to a locked spawn: one line of NUL-separated fields, the verdict first. */
  def runWord(arguments: Seq[String]): String = ("run" +: arguments).mkString(Nul) + "\n"

  def refusedWord(message: String): String = s"refused$Nul$message\n"

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
      |    if ($verdict ne 'run') { print STDERR "$fields[0]\n"; exit 2; }
      |    my $at = 0;
      |    $at++ while $at < @command && $command[$at] ne '--';
      |    splice(@command, $at, 0, @fields);
      |}
      |fcntl($fh, F_SETFD, 0) or exit 71;
      |exec { $command[0] } @command or exit 71;""".stripMargin

  /** What names one build directory's lock and records: its canonical spelling's SHA-256, 16
    * hex digits. */
  def buildHash(buildDirectory: Path): String =
    java.security.MessageDigest.getInstance("SHA-256")
      .digest(buildDirectory.toString.getBytes(UTF_8))
      .take(8).map(byte => f"$byte%02x").mkString

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
   * pathname a process the command started could still redirect a read.
   */
  def endSession(root: Path, session: Session, processes: Processes,
    shutdown: Path => ServerAnswer, beforeRemoval: Path => Unit = _ => ()): Vector[Collected] =
    val condemned =
      try
        val condemnedRoot = Files.createDirectories(root.resolve(CondemnedDir), ownerOnly)
        val entry = condemnedRoot.resolve(session.directory.getFileName)
        Files.move(session.directory, entry, StandardCopyOption.ATOMIC_MOVE)
        Some(entry)
      catch case _: IOException => None
    condemned match
      case Some(entry) =>
        val actions = collect(root, entry, processes, shutdown, beforeRemoval)
        session.close()
        actions
      case None =>
        val ended = endRecordedGroups(session.records, processes)
        remove(session)
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
   * are skipped by name: a directory without a `lock` file reads as a dead session here.
   */
  def scavenge(root: Path, processes: Processes, shutdown: Path => ServerAnswer)
    : Vector[(Path, Vector[Collected])] =
    val results = Vector.newBuilder[(Path, Vector[Collected])]
    val condemnedRoot = root.resolve(CondemnedDir)

    def collectLocked(entry: Path): Unit =
      lockForCollection(entry) match
        case Claim.Taken(lock) =>
          try results += entry -> collect(root, entry, processes, shutdown)
          finally lock.close()
        case Claim.Held    => ()
        case Claim.HalfDeleted => deleteTree(entry)

    if Files.isDirectory(condemnedRoot) then
      listDirectory(condemnedRoot).foreach(collectLocked)

    listDirectory(root)
      .filterNot(p =>
        Set(StagingDir, CondemnedDir, RootLockFile, BuildLockDir).contains(p.getFileName.toString))
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
   * and did not answer: then the directory, records and socket stay for the next start to retry,
   * because deleting them would strand a live server nothing can reach. A group is signalled only
   * while its recorded leader is alive with the recorded start time: a dead or mismatched leader
   * frees the pgid for strangers, so those groups are skipped and only the portfile-attributed
   * server is ended, by asking it.
   */
  def collect(root: Path, condemned: Path, processes: Processes,
    shutdown: Path => ServerAnswer, beforeRemoval: Path => Unit = _ => ()): Vector[Collected] =
    val actions = endRecordedGroups(condemned.resolve(RecordsDir), processes) :+
      collectServer(root, condemned, shutdown)
    // Whatever the reader does, the deletion follows it.
    try beforeRemoval(condemned)
    finally
      if !actions.exists(_.isInstanceOf[Collected.ServerUnanswered]) then deleteSessionTree(condemned)
    actions

  /** End every group the records name and prove — the scavenger's core. */
  def endRecordedGroups(recordsDir: Path, processes: Processes): Vector[Collected] =
    listDirectory(recordsDir).flatMap(endRecordedGroup(_, processes))

  /** End the group one record names, if it proves one; None for a file that is no record. */
  def endRecordedGroup(file: Path, processes: Processes): Option[Collected] =
    val parsed =
      try parseRecord(Files.readString(file, UTF_8))
      catch case _: IOException => None
    parsed.map: record =>
      processes.startOf(record.pgid) match
        case Some(start) if start == record.leaderStart =>
          processes.endGroup(record.pgid)
          Collected.GroupEnded(record.pgid)
        case Some(_) =>
          Collected.GroupSkipped(record.pgid, "pid recycled: start time differs")
        case None =>
          Collected.GroupSkipped(record.pgid, "leader gone: pgid no longer provable")

  /**
   * The portfile attribution: the session's recorded project names
   * `project/target/active.json`; a `local://` socket under the session's *original* path is our
   * server and no other. The socket moved with the condemnation rename, so the portfile's
   * spelling is remapped before the shutdown is sent to it — and sent only to a pathname
   * proven inside the condemned directory: the portfile is the command's to write, so its spelling
   * is a claim, and canonicalization is the proof.
   */
  def collectServer(root: Path, condemned: Path, shutdown: Path => ServerAnswer): Collected =
    val original = root.resolve(condemned.getFileName)
    val projectFile = condemned.resolve(ProjectFile)
    if !Files.isRegularFile(projectFile) then Collected.ServerSkipped("no recorded project")
    else
      try
        val project = Path.of(Files.readString(projectFile, UTF_8).trim)
        val portfile = project.resolve("project").resolve("target").resolve("active.json")
        if !Files.isRegularFile(portfile) then Collected.ServerSkipped("no portfile")
        else
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
   * The registration, as the command the wrapper spawns. perl — present on every macOS —
   * makes itself its own group's leader, publishes `<pgid> <leader start>` beside the record path
   * and renames it into place, then runs the command as its child; any failed step is exit 71
   * instead, which is the spawn ending itself after a condemnation won the race. When the command
   * ends, its exit status (128+signal for a signal death, the shell's convention) is published
   * the same way as `<record>.exit`, and the spawn stays until its group is ended: a group is
   * signalled only behind a live leader, and a command can fork a helper and return, so
   * ownership must not expire with the command. A `.pending` file a kill leaves behind still
   * parses, and still names a group whose leader either matches (ours, ended) or is gone
   * (skipped), so the scavenger reads the records directory without special cases.
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

  /** The observations on the real host: `ps` spellings that exist on macOS, where alone this
    * runs. TERM first and KILL after a grace — the server flushes its portfile away on TERM. */
  object HostProcesses extends Processes:
    def startOf(pid: Long): Option[String] =
      lines("ps", "-o", "lstart=", "-p", pid.toString).headOption.map(_.trim).filter(_.nonEmpty)

    def endGroup(pgid: Long): Unit =
      def members: Vector[String] = lines("ps", "-o", "pid=", "-g", pgid.toString)
      def signal(name: String): Unit =
        java.lang.ProcessBuilder("/bin/kill", s"-$name", "--", s"-$pgid").start().waitFor()
      signal("TERM")
      val settled = (1 to 100).exists { _ => if members.isEmpty then true else { Thread.sleep(100); false } }
      if !settled then
        signal("KILL")
        (1 to 50).exists(_ => if members.isEmpty then true else { Thread.sleep(100); false })

    private def lines(command: String*): Vector[String] =
      try
        val process = java.lang.ProcessBuilder(command*).start()
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
    else
      val stream = Files.list(path)
      try stream.iterator.asScala.toVector
      finally stream.close()

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
