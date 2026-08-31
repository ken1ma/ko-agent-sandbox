// The host build's session lifecycle: PLAN-SBT-ON-HOST.md §4 as code. A session is one wrapper
// command; its directory is published by rename so it is never seen half-made, its lock states the
// wrapper's liveness, and its records own the children's. Everything here is choreography over an
// injected filesystem-and-processes surface, so the kill interleavings are unit tests rather than
// something only a Mac under kill -9 can check.
//
// The invariant the records carry: no process may outlive its record. A spawned process becomes
// its own group's leader and publishes `<pgid> <leader start time>` by rename before it execs,
// aborting when the rename fails — so a kill at any instant leaves a complete record or a child
// that ends itself. The scavenger condemns a directory (rename out of the scanned root) before it
// reads records, ends what they name, and only then deletes.

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

  /** One registered process group: the leader's pgid (== its pid) and the leader's start time,
    * spelled exactly as `ps -o lstart=` prints it — compared as a string, never parsed, because
    * only equality with a later observation matters. */
  case class Record(pgid: Long, leaderStart: String)

  def renderRecord(record: Record): String = s"${record.pgid} ${record.leaderStart}\n"

  def parseRecord(text: String): Option[Record] =
    text.trim.split(" ", 2) match
      case Array(pid, start) if start.nonEmpty => pid.toLongOption.map(Record(_, start))
      case _                                   => None

  /** What the scavenger observes and does about processes. Injected: the decision protocol is the
    * tested thing, and a real implementation only on macOS. */
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

  // ---------------------------------------------------------------------------
  // The wrapper root
  // ---------------------------------------------------------------------------

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

  // ---------------------------------------------------------------------------
  // Publication
  // ---------------------------------------------------------------------------

  /** A published, locked session. The lock channel lives as long as the wrapper; closing it is
    * what frees the session for a scavenger. */
  final class Session(val directory: Path, lockChannel: FileChannel):
    def tmp: Path = directory.resolve(TmpDir)
    def records: Path = directory.resolve(RecordsDir)
    def close(): Unit = lockChannel.close()

  /**
   * Create in staging, lock there, rename into the root: a scanned entry is locked by
   * construction, so a free lock always means a dead session. The root lock covers creating the
   * staging entry through the rename — the scavenger's staging cleanup takes the same lock, so it
   * can never eat a directory whose creator has not locked it yet.
   */
  def publish(root: Path, project: Path): Either[String, Session] =
    try
      withRootLock(root):
        val staging = Files.createDirectories(root.resolve(StagingDir), ownerOnly)
        val entry = Files.createTempDirectory(staging, "s", ownerOnly)
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
          Left(s"could not take the fresh session lock in $entry")
        else
          val published = root.resolve(entry.getFileName)
          Files.move(entry, published, StandardCopyOption.ATOMIC_MOVE)
          Right(Session(published, channel))
    catch case ex: IOException => Left(s"publishing a session under $root: ${ex.getMessage}")

  /** Remove this session's directory; the wrapper's own step 11, after it ended what it started.
    * The lock is released by deletion's end; nothing here needs the root lock (§4). */
  def remove(session: Session): Unit =
    deleteTree(session.directory)
    session.close()

  // ---------------------------------------------------------------------------
  // Scavenging
  // ---------------------------------------------------------------------------

  /**
   * Every start runs this before publishing its own session. Condemned entries first — they are
   * work an earlier, killed scavenger left — then every unlocked published entry is condemned and
   * collected, then staging litter is cleared under the root lock.
   */
  def scavenge(root: Path, processes: Processes, shutdown: Path => Either[String, Unit])
    : Vector[(Path, Vector[Collected])] =
    val results = Vector.newBuilder[(Path, Vector[Collected])]
    val condemnedRoot = root.resolve(CondemnedDir)

    if Files.isDirectory(condemnedRoot) then
      listDirectory(condemnedRoot).foreach: entry =>
        results += entry -> collect(root, entry, processes, shutdown)

    listDirectory(root)
      .filterNot(p => Set(StagingDir, CondemnedDir, RootLockFile).contains(p.getFileName.toString))
      .filter(Files.isDirectory(_))
      .foreach: entry =>
        if lockIsFree(entry.resolve(LockFile)) then
          Files.createDirectories(condemnedRoot, ownerOnly)
          val condemned = condemnedRoot.resolve(entry.getFileName)
          try
            Files.move(entry, condemned, StandardCopyOption.ATOMIC_MOVE)
            results += condemned -> collect(root, condemned, processes, shutdown)
          catch case _: IOException => () // a concurrent scavenger won the rename; its work now

    try
      withRootLock(root):
        listDirectory(root.resolve(StagingDir)).foreach(deleteTree)
        Right(())
    catch case _: IOException => ()

    results.result()

  /**
   * End what one condemned directory's records name, then delete it. A group is signalled only
   * while its recorded leader is alive with the recorded start time: a dead or mismatched leader
   * frees the pgid for strangers (§4), so those groups are skipped and only the portfile-attributed
   * server — the one process of ours built to outlive its leader — is ended, by asking it.
   */
  def collect(root: Path, condemned: Path, processes: Processes,
    shutdown: Path => Either[String, Unit]): Vector[Collected] =
    val actions = endRecordedGroups(condemned.resolve(RecordsDir), processes) :+
      collectServer(root, condemned, shutdown)
    deleteTree(condemned)
    actions

  /** End every group the records name and prove — the scavenger's core, and the wrapper's own
    * step 11 after it shut its server down. */
  def endRecordedGroups(recordsDir: Path, processes: Processes): Vector[Collected] =
    val records = listDirectory(recordsDir).flatMap: file =>
      try parseRecord(Files.readString(file, UTF_8))
      catch case _: IOException => None

    records.map: record =>
      processes.startOf(record.pgid) match
        case Some(start) if start == record.leaderStart =>
          processes.endGroup(record.pgid)
          Collected.GroupEnded(record.pgid)
        case Some(_) =>
          Collected.GroupSkipped(record.pgid, "pid recycled: start time differs")
        case None =>
          Collected.GroupSkipped(record.pgid, "leader gone: pgid no longer provable")

  /**
   * The portfile attribution of §4: the session's recorded project names
   * `project/target/active.json`; a `local://` socket under the session's *original* path is our
   * server and no other. The socket moved with the condemnation rename, so the portfile's
   * spelling is remapped before the shutdown is spoken at it.
   */
  def collectServer(root: Path, condemned: Path, shutdown: Path => Either[String, Unit]): Collected =
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
              val moved = condemned.resolve(original.relativize(socket))
              shutdown(moved) match
                case Right(())     => Collected.ServerShutDown(moved)
                case Left(reason)  => Collected.ServerSkipped(s"server did not answer: $reason")
            case Some(_) => Collected.ServerSkipped("portfile socket is not this session's")
            case None    => Collected.ServerSkipped("portfile is not a local-socket one")
      catch case ex: IOException => Collected.ServerSkipped(ex.getMessage)

  /** The portfile's `{"uri":"local://<path>"}`; anything else — TCP mode, or a shape a newer sbt
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
   * The pre-exec registration of §4, as the command the wrapper spawns. perl — present on every
   * macOS — makes the child its own group's leader, publishes `<pgid> <leader start>` beside the
   * record path and renames it into place, then execs; any failed step is exit 71 instead, which
   * is the child ending itself after a condemnation won the race. A `.pending` file a kill leaves
   * behind still parses, and still names a group whose leader either matches (ours, ended) or is
   * gone (skipped), so the scavenger reads the records directory without special cases.
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
      |exec { $command[0] } @command;
      |exit 71;""".stripMargin

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
  // Plumbing
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

  /** Free means dead: a published directory was locked before it became visible, so an untaken
    * lock has no live owner. The probe lock is released at once — condemnation, not this test, is
    * what makes the collection safe against races. An overlapping lock is this very JVM holding
    * it, which is a live session too. */
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

  private def deleteTree(path: Path): Unit =
    try
      if Files.isDirectory(path, java.nio.file.LinkOption.NOFOLLOW_LINKS) then
        listDirectory(path).foreach(deleteTree)
      Files.deleteIfExists(path)
    catch case NonFatal(_) => ()
