package agentsandbox.launcher

import java.net.{StandardProtocolFamily, UnixDomainSocketAddress}
import java.nio.ByteBuffer
import java.nio.channels.{FileChannel, ServerSocketChannel}
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path, StandardCopyOption}

import scala.collection.mutable.ListBuffer

import RunOnHostSession.*

object RunOnHostSessionTest:
  /** True exactly where the suites run as a confined run-on-host command, as `ko-sandbox-run-on-host sbt` runs
    * them. The leader is the supervisor's own process and runs outside the profile by construction. Under the
    * profile, perl dies before registering, so the tests that spawn a leader skip. */
  val underRunOnHostProfile: Boolean =
    sys.env.get("SBT_GLOBAL_SERVER_DIR").exists(_.startsWith("/private/tmp/ko-agent-"))

  /**
   * A session root for a test that binds the sbt server's socket under a session's `tmp/`. The test deletes the root
   * it got.
   *
   * The socket path runs up to 52 characters past the root, `/b<up to 20 digits>/tmp/<20 hex digits>/sock`, and macOS
   * allows a socket path of 103 characters. A root under macOS's `java.io.tmpdir`, `/var/folders/<2>/<30>/T`, is
   * therefore too long. The supervisor's own root is `/private/tmp/ko-agent-<uid>` for the same reason
   * (RunOnHostPrereqs.SessionTmpMaxLength).
   */
  def socketSessionRoot(prefix: String): Path =
    try Files.createTempDirectory(Path.of("/tmp").toRealPath(), prefix)
    catch
      case ex: java.nio.file.FileSystemException =>
        munit.Assertions.assume(false, s"needs a directory under /tmp, short enough for the server's socket: $ex")
        throw ex

class RunOnHostSessionTest extends munit.FunSuite:

  // --------------------------------------------------------------------------
  // Records
  // --------------------------------------------------------------------------

  test("a record round-trips through its file form"):
    val record = Record(4242, "Mon Aug 31 10:08:27 2026")
    assertEquals(parseRecord(renderRecord(record)), Some(record))

  test("a partial or foreign record parses to nothing rather than a group to signal"):
    for text <- Seq("", "\n", "4242", "4242 ", "notapid Mon Aug 31", "  ") do
      assertEquals(parseRecord(text), None, clue = s"'$text'")

  // --------------------------------------------------------------------------
  // The supervisor root
  // --------------------------------------------------------------------------

  def uid: Int =
    val probe = Files.createTempFile("uid", "")
    try Files.getAttribute(probe, "unix:uid").asInstanceOf[Integer].intValue
    finally Files.delete(probe)

  test("ensureRoot creates an absent root owner-only, and takes one another launch just made"):
    val parent = Files.createTempDirectory("command-session")
    val root = parent.resolve("ko-agent-0")
    assertEquals(ensureRoot(root, uid), Right(root))
    assertEquals(
      java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(root)),
      "rwx------",
    )
    assertEquals(ensureRoot(root, uid), Right(root), "found by the launch whose creation lost")

  test("ensureRoot refuses a symlinked, shared, or foreign root"):
    val parent = Files.createTempDirectory("command-session")
    val real = Files.createDirectory(parent.resolve("real"))
    val link = Files.createSymbolicLink(parent.resolve("link"), real)
    assert(ensureRoot(link, uid).isLeft, "a symlink is a redirected root")

    val shared = Files.createDirectory(parent.resolve("shared"))
    Files.setPosixFilePermissions(
      shared,
      java.nio.file.attribute.PosixFilePermissions.fromString("rwxr-x---"),
    )
    assert(ensureRoot(shared, uid).isLeft, "group access is a shared root")

    val owned = Files.createDirectory(
      parent.resolve("owned"),
      java.nio.file.attribute.PosixFilePermissions
        .asFileAttribute(java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")),
    )
    assert(ensureRoot(owned, uid + 1).isLeft, "another uid's directory is not this user's root")

  // --------------------------------------------------------------------------
  // Publication and removal
  // --------------------------------------------------------------------------

  def freshRoot(): Path =
    // The root is canonical, so the moved-socket pathnames that the tests predict match what containedSocket resolves.
    val root = Files.createTempDirectory("command-session").toRealPath().resolve("root")
    ensureRoot(root, uid).toOption.get

  test("publish yields a locked session with tmp, records and the workspace root on file"):
    val root = freshRoot()
    val session = publish(root, Path.of("/Users/u/proj")).toOption.get
    assert(Files.isDirectory(session.tmp))
    assert(Files.isDirectory(session.records))
    assertEquals(Files.readString(session.directory.resolve(WorkspaceFile), UTF_8).trim, "/Users/u/proj")
    assertEquals(session.directory.getParent, root)
    assertEquals(listNames(root.resolve(StagingDir)), Vector.empty, "staging holds nothing published")
    remove(session)
    assert(!Files.exists(session.directory))

  test("a live session is left alone by the scavenger"):
    val root = freshRoot()
    val session = publish(root, Path.of("/p")).toOption.get
    val results = scavenge(root, processes(), _ => ServerAnswer.ShutDown)
    assertEquals(results, Vector.empty)
    assert(Files.isDirectory(session.directory))
    remove(session)

  test("scavenge skips the caller's own session rather than probe its lock"):
    // ownSession names the runner's own live session, which scavenge must not reach. lockIsFree would open and close a
    // second descriptor to the session's lock file. Closing any descriptor releases the process's POSIX fcntl lock, so
    // probing would unlock a live session.
    // - In one JVM the release is invisible, because the lock reads as held either way. This test therefore asserts
    //   only that scavenge leaves the own session out of the scan and its results.
    // - The run-on-host checks cover the release across processes.
    val root = freshRoot()
    val own = publish(root, Path.of("/p"), Kind.Runner).toOption.get
    val other = die(publish(root, Path.of("/p")).toOption.get)
    val results = scavenge(root, processes(), _ => ServerAnswer.ShutDown, ownSession = Some(own.directory))
    assert(Files.isDirectory(own.directory), clue = own.directory)
    assert(!results.exists(_._1 == own.directory), clue = results)
    assert(!Files.exists(other), clue = "a dead peer is still collected while the own session is skipped")
    remove(own)

  test("the two session kinds are told apart by their directory's prefix"):
    val root = freshRoot()
    val runner = publish(root, Path.of("/p"), Kind.Runner).toOption.get
    val command = publish(root, Path.of("/p")).toOption.get
    assert(Kind.Runner.names(runner.directory.getFileName.toString), clue = runner.directory)
    assert(Kind.Command.names(command.directory.getFileName.toString), clue = command.directory)
    remove(runner)
    remove(command)

  test("a build lock file, and a retirement lock file, is neither a session nor scavenged"):
    val root = freshRoot()
    val build = Path.of("/Users/u/proj/sub")
    val file = buildLockFile(root, "sbt", build).toOption.get
    assertEquals(file, root.resolve(BuildLockDir).resolve(s"sbt-${buildHash(build)}"))
    assertEquals(buildHash(build).length, 16)
    Files.createFile(file)
    val retirement = retirementLockFile(root, s"sbt-${buildHash(build)}")
    assertEquals(retirement, root.resolve(RetireLockDir).resolve(s"sbt-${buildHash(build)}"))
    Files.createFile(retirement)
    assertEquals(scavenge(root, processes(), _ => ServerAnswer.ShutDown), Vector.empty)
    assert(Files.isRegularFile(file), "the lock file outlives every scavenge")
    assert(Files.isRegularFile(retirement), "so does the retirement lock file")
    assert(!Files.exists(root.resolve(CondemnedDir).resolve(BuildLockDir)))
    assert(!Files.exists(root.resolve(CondemnedDir).resolve(RetireLockDir)))

  // --------------------------------------------------------------------------
  // Scavenging the dead
  // --------------------------------------------------------------------------

  class FakeProcesses(alive: Map[Long, String]) extends Processes:
    val ended = ListBuffer[Long]()
    def startOf(pid: Long): Option[String] = alive.get(pid)
    def endGroup(pgid: Long): Boolean = { ended += pgid; true }
    def groupEmpty(pgid: Long): Boolean = !alive.contains(pgid)
    def signal(pid: Long, name: String): Unit = fail(s"signalled $pid with $name")

  def processes(alive: (Long, String)*): FakeProcesses = FakeProcesses(alive.toMap)

  def die(session: Session): Path =
    // A SIGKILLed supervisor frees the lock, and the directory and records stay.
    session.close()
    session.directory

  test("runtimeOwner finds an owner in the root or condemned, and across the rename between the two"):
    val root = freshRoot()
    val mine = publish(root, Path.of("/p"), Kind.Runner).toOption.get
    val owner = publish(root, Path.of("/p"), Kind.Runner).toOption.get
    val hash = "abcdef0123456789"
    Files.writeString(owner.records.resolve(s"server-sbt-$hash"), renderRecord(Record(1, "S")), UTF_8)
    Files.writeString(owner.records.resolve(s"daemon-mill-$hash"), renderRecord(Record(2, "S")), UTF_8)
    val live = processes(1L -> "S", 2L -> "S")
    // runtimeOwner finds a live owner that holds the record and finds no owner for a hash that nobody owns. Each
    // program's record is its own.
    assertEquals(runtimeOwner(root, mine.directory, s"server-sbt-$hash", live), Some(owner.directory))
    assertEquals(runtimeOwner(root, mine.directory, s"daemon-mill-$hash", live), Some(owner.directory))
    assertEquals(runtimeOwner(root, mine.directory, "server-sbt-0000000000000000", live), None)
    assertEquals(runtimeOwner(root, mine.directory, "daemon-mill-0000000000000000", live), None)
    // An owner that just crashed still owns the record: it is unlocked, still in the root and not yet condemned. The
    // owner's server group can be running, so admission stays blocked until the next start collects the owner.
    owner.close()
    assertEquals(
      runtimeOwner(root, mine.directory, s"server-sbt-$hash", live), Some(owner.directory),
      "a dead owner in the root still owns",
    )
    // The owner renames itself into condemned/ in the instant between the root enumeration and its lookup. The lookup
    // then misses the owner in the root, but the later enumeration of condemned/ finds it, so admission stays blocked
    // across the teardown rename.
    val condemned = Files.createDirectories(root.resolve(CondemnedDir))
    val moved = condemned.resolve(owner.directory.getFileName)
    var scans = 0
    val found = runtimeOwner(root, mine.directory, s"server-sbt-$hash", live, betweenScan = () =>
      scans += 1
      if scans == 1 then Files.move(owner.directory, moved, StandardCopyOption.ATOMIC_MOVE))
    assertEquals(found, Some(moved), "the owner renamed away between the scans is found in condemned")
    remove(mine)

  test("a record whose group is dead owns nothing; a live or leaderless one owns"):
    val root = freshRoot()
    val mine = publish(root, Path.of("/p"), Kind.Runner).toOption.get
    val owner = publish(root, Path.of("/p"), Kind.Runner).toOption.get
    val record = "server-sbt-abcdef0123456789"
    Files.writeString(owner.records.resolve(record), renderRecord(Record(7, "START-A")), UTF_8)
    // The leader is gone and no member is listed, so the group ended, through another process's retirement or on its
    // own. The owner has not yet deleted the record, and that record must not block admission.
    assertEquals(runtimeOwner(root, mine.directory, record, processes()), None, "a dead group owns nothing")
    // The leader's pid was recycled. The group was empty at some instant, and the process that the number lists now
    // is a stranger's, so the record owns nothing either.
    assertEquals(runtimeOwner(root, mine.directory, record, processes(7L -> "RECYCLED")), None)
    // The leader is gone and a member is still listed. The members may be the record's, so the record owns as before.
    class Orphaned extends FakeProcesses(Map.empty):
      override def groupEmpty(pgid: Long): Boolean = false
    assertEquals(runtimeOwner(root, mine.directory, record, Orphaned()), Some(owner.directory))
    // An observation that ps could not make proves nothing, so the record owns.
    class Unobservable extends FakeProcesses(Map.empty):
      override def startOf(pid: Long): Option[String] = throw java.io.IOException("ps could not list")
    assertEquals(runtimeOwner(root, mine.directory, record, Unobservable()), Some(owner.directory))
    // A record that does not parse still owns: its existence is the claim, and nothing disproves the claim.
    Files.writeString(owner.records.resolve(record), "", UTF_8)
    assertEquals(runtimeOwner(root, mine.directory, record, processes()), Some(owner.directory))
    remove(mine); remove(owner)

  test("a build file is published by rename, read back by hash, and skipped while pending"):
    val root = freshRoot()
    val session = publish(root, Path.of("/p"), Kind.Runner).toOption.get
    val hash = buildHash(Path.of("/p/sub"))
    assertEquals(
      publishBuildFile(session.directory, hash, Path.of("/p/sub")),
      Right(buildFile(session.directory, hash)),
    )
    Files.writeString(session.directory.resolve(s"${BuildFilePrefix}deadbeef.pending"), "/p/half\n", UTF_8)
    assertEquals(buildDirectories(session.directory), Vector(hash -> Path.of("/p/sub")))
    remove(session)

  test("the other live runners' sessions are the locked ones under the runner prefix"):
    val root = freshRoot()
    val mine = publish(root, Path.of("/p"), Kind.Runner).toOption.get
    val other = publish(root, Path.of("/p"), Kind.Runner).toOption.get
    val command = publish(root, Path.of("/p")).toOption.get
    val dead = publish(root, Path.of("/p"), Kind.Runner).toOption.get
    dead.close()
    // A fixed root entry that shares the prefix's letter is not a session, whatever its lock state.
    Files.createDirectories(root.resolve(RetireLockDir))
    assertEquals(liveRunnerSessions(root, mine.directory), Vector(other.directory))
    assertEquals(allRunnerSessions(root, mine.directory).toSet, Set(other.directory, dead.directory))
    remove(mine); remove(other); remove(command); remove(dead)

  test("a leader lives while it matches the record and no exit is published"):
    val root = freshRoot()
    val record = root.resolve("r")
    Files.writeString(record, renderRecord(Record(7, "START-A")), UTF_8)
    assert(leaderLives(record, processes(7L -> "START-A")))
    assert(!leaderLives(record, processes(7L -> "RECYCLED")))
    assert(!leaderLives(record, processes()))
    Files.writeString(exitRecord(record), "0\n", UTF_8)
    assert(!leaderLives(record, processes(7L -> "START-A")))
    assert(!leaderLives(root.resolve("absent"), processes(7L -> "START-A")))

  test("a dead runner session's records are ended like a command's"):
    val root = freshRoot()
    val session = publish(root, Path.of("/p"), Kind.Runner).toOption.get
    for (name, pid) <- Seq("proxy-sbt-abc" -> 21L, "server-sbt-abc" -> 22L, "daemon-mill-def" -> 23L) do
      Files.writeString(session.records.resolve(name), renderRecord(Record(pid, s"START-$pid")), UTF_8)
    val dead = die(session)
    val fakes = processes(21L -> "START-21", 22L -> "START-22", 23L -> "START-23")
    scavenge(root, fakes, _ => ServerAnswer.ShutDown)
    assertEquals(fakes.ended.toList.sorted, List(21L, 22L, 23L))
    assert(!Files.exists(dead))

  test("a dead command session beside a live runner session is collected alone"):
    val root = freshRoot()
    val runner = publish(root, Path.of("/p"), Kind.Runner).toOption.get
    Files.writeString(runner.records.resolve("server-sbt-abc"), renderRecord(Record(31, "START-31")), UTF_8)
    val command = publish(root, Path.of("/p")).toOption.get
    Files.writeString(command.records.resolve("client"), renderRecord(Record(32, "START-32")), UTF_8)
    val dead = die(command)
    val fakes = processes(31L -> "START-31", 32L -> "START-32")
    scavenge(root, fakes, _ => ServerAnswer.ShutDown)
    assertEquals(fakes.ended.toList, List(32L), "the runner's live session keeps its records")
    assert(!Files.exists(dead))
    assert(Files.isDirectory(runner.directory))
    remove(runner)

  test("a dead session's matching group is ended and the directory removed"):
    val root = freshRoot()
    val session = publish(root, Path.of("/p")).toOption.get
    Files.writeString(session.records.resolve("client"), renderRecord(Record(7, "START-A")), UTF_8)
    val dead = die(session)

    val fakes = processes(7L -> "START-A")
    val results = scavenge(root, fakes, _ => ServerAnswer.ShutDown)
    assertEquals(fakes.ended.toList, List(7L))
    assert(!Files.exists(dead))
    assert(!Files.exists(root.resolve(CondemnedDir).resolve(dead.getFileName)))
    assertEquals(
      results.flatMap(_(1)).collect { case Collected.GroupEnded(g) => g },
      Vector(7L),
    )

  test("a group listed after its KILL keeps its directory, until a collection ends it"):
    val root = freshRoot()
    val session = publish(root, Path.of("/p")).toOption.get
    Files.writeString(session.records.resolve("client"), renderRecord(Record(7, "START-A")), UTF_8)
    val dead = die(session)
    val condemned = root.resolve(CondemnedDir).resolve(dead.getFileName)

    class Survivors(alive: Map[Long, String]) extends FakeProcesses(alive):
      override def endGroup(pgid: Long): Boolean = { ended += pgid; false }
    val survivors = Survivors(Map(7L -> "START-A"))
    val first = scavenge(root, survivors, _ => ServerAnswer.ShutDown)
    assertEquals(survivors.ended.toList, List(7L))
    assertEquals(
      first.flatMap(_(1)).collect { case Collected.GroupAlive(g, _) => g },
      Vector(7L),
    )
    assert(Files.exists(condemned.resolve(RecordsDir).resolve("client")), "the record is kept")

    // The leader is still alive with the recorded start time, so the next collection signals again. This time the group
    // empties.
    val fakes = processes(7L -> "START-A")
    val second = scavenge(root, fakes, _ => ServerAnswer.ShutDown)
    assertEquals(fakes.ended.toList, List(7L))
    assertEquals(second.flatMap(_(1)).collect { case Collected.GroupEnded(g) => g }, Vector(7L))
    assert(!Files.exists(condemned))

  test("an observation ps could not make keeps the record, as a live group does"):
    val root = freshRoot()
    val session = publish(root, Path.of("/p")).toOption.get
    Files.writeString(session.records.resolve("client"), renderRecord(Record(7, "START-A")), UTF_8)
    val dead = die(session)

    class Unobservable extends FakeProcesses(Map.empty):
      override def startOf(pid: Long): Option[String] = throw java.io.IOException("ps could not list")
    val results = scavenge(root, Unobservable(), _ => ServerAnswer.ShutDown)
    assertEquals(
      results.flatMap(_(1)).collect { case Collected.GroupAlive(g, reason) => (g, reason) },
      Vector(7L -> "ps could not answer: ps could not list"),
    )
    val condemned = root.resolve(CondemnedDir).resolve(dead.getFileName)
    assert(Files.exists(condemned.resolve(RecordsDir).resolve("client")), "the record is kept")

  test("a member listed behind a leader that is gone keeps the record, unsignalled, until none is"):
    val root = freshRoot()
    val session = publish(root, Path.of("/p")).toOption.get
    Files.writeString(session.records.resolve("client"), renderRecord(Record(7, "START-A")), UTF_8)
    val dead = die(session)
    val condemned = root.resolve(CondemnedDir).resolve(dead.getFileName)

    // The KILL took the leader and left a member.
    // - No start time is left to check the pgid against, so scavenge signals nothing.
    // - The member may still be the record's, so scavenge deletes nothing.
    class Orphaned extends FakeProcesses(Map.empty):
      override def groupEmpty(pgid: Long): Boolean = false
    val orphaned = Orphaned()
    val first = scavenge(root, orphaned, _ => ServerAnswer.ShutDown)
    assertEquals(orphaned.ended.toList, Nil)
    assertEquals(
      first.flatMap(_(1)).collect { case Collected.GroupAlive(g, reason) => (g, reason) },
      Vector(7L -> "leader gone, a member still listed"),
    )
    assert(Files.exists(condemned.resolve(RecordsDir).resolve("client")), "the record is kept")

    val fakes = processes()
    val second = scavenge(root, fakes, _ => ServerAnswer.ShutDown)
    assertEquals(second.flatMap(_(1)).collect { case Collected.GroupSkipped(g, _) => g }, Vector(7L))
    assert(!Files.exists(condemned))

  test("a ps listing must list this process; without it nothing is observed"):
    import HostProcesses.{groupEmptyFrom, startFrom}
    val start = "Mon Sep 14 10:00:00 2026"
    assertEquals(startFrom(Vector(s"41 $start", "40 Sun Sep 13 09:00:00 2026"), 40, 41), Some(start))
    assertEquals(startFrom(Vector("40 Sun Sep 13 09:00:00 2026"), 40, 41), None, "not listed: no such process")
    // These lines are what Apple's ps prints when its process-table sysctl fails, and when it selects nothing.
    intercept[java.io.IOException](startFrom(Vector.empty, 40, 41))
    intercept[java.io.IOException](startFrom(Vector(s"41 $start"), 40, 41))
    assertEquals(groupEmptyFrom(Vector("40"), 40), true)
    assertEquals(groupEmptyFrom(Vector("40", "77", "78"), 40), false)
    intercept[java.io.IOException](groupEmptyFrom(Vector.empty, 40))
    intercept[java.io.IOException](groupEmptyFrom(Vector("77"), 40))

  test("a session whose condemnation fails keeps its directory in place while a group lives"):
    val root = freshRoot()
    val session = publish(root, Path.of("/p")).toOption.get
    Files.writeString(session.records.resolve("client"), renderRecord(Record(7, "START-A")), UTF_8)
    // A file stands where the condemned directory would be. The rename fails, and the fallback ends the recorded groups
    // in place.
    Files.writeString(root.resolve(CondemnedDir), "", UTF_8)

    class Survivors(alive: Map[Long, String]) extends FakeProcesses(alive):
      override def endGroup(pgid: Long): Boolean = { ended += pgid; false }
    val survivors = Survivors(Map(7L -> "START-A"))
    val kept = endSession(root, session, survivors, _ => ServerAnswer.ShutDown)
    assertEquals(kept.collect { case Collected.GroupAlive(g, _) => g }, Vector(7L))
    assert(Files.exists(session.records.resolve("client")), "the record is kept where it was")

    // Once the lock is released, the next scavenge condemns the directory and retries.
    Files.delete(root.resolve(CondemnedDir))
    val fakes = processes(7L -> "START-A")
    val results = scavenge(root, fakes, _ => ServerAnswer.ShutDown)
    assertEquals(fakes.ended.toList, List(7L))
    assertEquals(results.flatMap(_(1)).collect { case Collected.GroupEnded(g) => g }, Vector(7L))
    assert(!Files.exists(session.directory))

  test("a recycled or vanished leader is never signalled"):
    val root = freshRoot()
    val session = publish(root, Path.of("/p")).toOption.get
    Files.writeString(session.records.resolve("a"), renderRecord(Record(7, "START-A")), UTF_8)
    Files.writeString(session.records.resolve("b"), renderRecord(Record(8, "START-B")), UTF_8)
    die(session)

    val fakes = processes(7L -> "SOMEONE-ELSE") // 8 is gone entirely
    val results = scavenge(root, fakes, _ => ServerAnswer.ShutDown)
    assertEquals(fakes.ended.toList, Nil)
    val skipped = results.flatMap(_(1)).collect { case Collected.GroupSkipped(g, _) => g }
    assertEquals(skipped.sorted, Vector(7L, 8L))

  test("a .pending record a kill left behind is read like any other"):
    val root = freshRoot()
    val session = publish(root, Path.of("/p")).toOption.get
    Files.writeString(
      session.records.resolve("client.pending"),
      renderRecord(Record(9, "START-C")),
      UTF_8,
    )
    die(session)
    val fakes = processes(9L -> "START-C")
    scavenge(root, fakes, _ => ServerAnswer.ShutDown)
    assertEquals(fakes.ended.toList, List(9L))

  test("a condemned directory an earlier killed scavenger left is processed first"):
    val root = freshRoot()
    val session = publish(root, Path.of("/p")).toOption.get
    Files.writeString(session.records.resolve("x"), renderRecord(Record(5, "START-E")), UTF_8)
    val dead = die(session)
    val condemned = root.resolve(CondemnedDir)
    Files.createDirectories(condemned)
    Files.move(dead, condemned.resolve(dead.getFileName))

    val fakes = processes(5L -> "START-E")
    scavenge(root, fakes, _ => ServerAnswer.ShutDown)
    assertEquals(fakes.ended.toList, List(5L))
    assertEquals(listNames(condemned), Vector.empty)

  test("a condemned entry another collector holds is left to it"):
    import java.nio.channels.FileChannel
    import java.nio.file.StandardOpenOption
    val root = freshRoot()
    val session = publish(root, Path.of("/p")).toOption.get
    Files.writeString(session.records.resolve("x"), renderRecord(Record(6, "START-F")), UTF_8)
    val dead = die(session)
    val condemnedDir = Files.createDirectories(root.resolve(CondemnedDir))
    val entry = condemnedDir.resolve(dead.getFileName)
    Files.move(dead, entry)
    val holder = FileChannel.open(entry.resolve(LockFile), StandardOpenOption.WRITE)
    val held = holder.tryLock()
    try
      val fakes = processes(6L -> "START-F")
      assertEquals(scavenge(root, fakes, _ => ServerAnswer.ShutDown), Vector.empty)
      assertEquals(fakes.ended.toList, Nil, "nothing is signalled twice")
      assert(Files.isDirectory(entry), "the entry stays for its holder")
    finally
      held.release()
      holder.close()
    val fakes = processes(6L -> "START-F")
    scavenge(root, fakes, _ => ServerAnswer.ShutDown)
    assertEquals(fakes.ended.toList, List(6L), "released, the entry is anyone's to collect")
    assert(!Files.exists(entry))

  test("a condemned entry without its lock is a half-deleted tree: removed, nothing signalled"):
    val root = freshRoot()
    val session = publish(root, Path.of("/p")).toOption.get
    Files.writeString(session.records.resolve("x"), renderRecord(Record(11, "START-G")), UTF_8)
    val dead = die(session)
    val entry = Files.createDirectories(root.resolve(CondemnedDir)).resolve(dead.getFileName)
    Files.move(dead, entry)
    Files.delete(entry.resolve(LockFile))
    val fakes = processes(11L -> "START-G")
    assertEquals(scavenge(root, fakes, _ => ServerAnswer.ShutDown), Vector.empty)
    assertEquals(fakes.ended.toList, Nil, "only the lock chain proves the authority to signal")
    assert(!Files.exists(entry), "the empty leftover entry is removed")

  test("a child that will not delete keeps the entry locked, never lockless with records left"):
    import java.nio.file.attribute.PosixFilePermissions
    val root = freshRoot()
    val session = publish(root, Path.of("/p")).toOption.get
    val stubborn = Files.createDirectory(session.tmp.resolve("stubborn"))
    Files.writeString(stubborn.resolve("x"), "x", UTF_8)
    Files.setPosixFilePermissions(stubborn, PosixFilePermissions.fromString("---------"))
    val dead = die(session)
    val entry = root.resolve(CondemnedDir).resolve(dead.getFileName)
    val moved = entry.resolve(TmpDir).resolve("stubborn")
    try
      scavenge(root, processes(), _ => ServerAnswer.ShutDown)
      assert(Files.exists(entry.resolve(LockFile)), "the lock outlives every surviving child")
    finally
      if Files.exists(moved) then
        Files.setPosixFilePermissions(moved, PosixFilePermissions.fromString("rwx------"))
    scavenge(root, processes(), _ => ServerAnswer.ShutDown)
    assert(!Files.exists(entry), "deletable again, the retry collects the entry whole")

  test("a session being ended by its supervisor is left alone by a concurrent scavenger"):
    val root = freshRoot()
    val workspace = Files.createTempDirectory("proj")
    val session = publish(root, workspace).toOption.get
    val socket = session.tmp.resolve("sock")
    Files.createFile(socket)
    Files.createDirectories(workspace.resolve("project/target"))
    Files.writeString(
      workspace.resolve("project/target/active.json"),
      s"""{"uri":"local://$socket"}""",
      UTF_8,
    )
    val actions = endSession(root, session, processes(), _ =>
      assertEquals(
        scavenge(root, processes(), _ => ServerAnswer.ShutDown),
        Vector.empty,
        "mid-collection, the condemned entry is its owner's",
      )
      ServerAnswer.ShutDown)
    assert(actions.exists(_.isInstanceOf[Collected.ServerShutDown]), clue = actions)
    assert(!Files.exists(session.directory))

  test("staging leftovers are cleared, published live sessions are not"):
    val root = freshRoot()
    val live = publish(root, Path.of("/p")).toOption.get
    val leftover = Files.createDirectories(root.resolve(StagingDir).resolve("s-half-made"))
    Files.writeString(leftover.resolve("junk"), "x", UTF_8)
    scavenge(root, processes(), _ => ServerAnswer.ShutDown)
    assertEquals(listNames(root.resolve(StagingDir)), Vector.empty)
    assert(Files.isDirectory(live.directory))
    remove(live)

  // --------------------------------------------------------------------------
  // Portfile attribution
  // --------------------------------------------------------------------------

  test("portfileSocket reads the local form and nothing else"):
    assertEquals(
      portfileSocket("""{"uri":"local:///private/tmp/x/srv/abc/sock"}"""),
      Some(Path.of("/private/tmp/x/srv/abc/sock")),
    )
    assertEquals(portfileSocket("""{"uri":"tcp://127.0.0.1:5000"}"""), None)
    assertEquals(portfileSocket("""not a portfile"""), None)

  def deadSessionWithServer(root: Path, socketUnder: Path => Path): (Path, Path) =
    val workspace = Files.createTempDirectory("proj")
    val session = publish(root, workspace).toOption.get
    val dead = die(session)
    val socket = socketUnder(dead)
    // The socket exists on disk like a real server's, because containment canonicalizes it. The test creates it only
    // inside the session: a foreign spelling stays a spelling.
    if socket.normalize.startsWith(dead) then
      Files.createDirectories(socket.getParent)
      Files.createFile(socket)
    Files.createDirectories(workspace.resolve("project/target"))
    Files.writeString(
      workspace.resolve("project/target/active.json"),
      s"""{"uri":"local://$socket"}""",
      UTF_8,
    )
    (dead, socket)

  test("a portfile socket under the session is shut down at its moved pathname"):
    val root = freshRoot()
    val (dead, _) = deadSessionWithServer(root, _.resolve(TmpDir).resolve("srv/sock"))
    val spoken = ListBuffer[Path]()
    val results = scavenge(root, processes(), path => { spoken += path; ServerAnswer.ShutDown })
    val moved = root.resolve(CondemnedDir).resolve(dead.getFileName).resolve("tmp/srv/sock")
    assertEquals(spoken.toList, List(moved))
    assertEquals(
      results.flatMap(_(1)).collect { case Collected.ServerShutDown(p) => p },
      Vector(moved),
    )

  test("a dead runner session's servers are collected by the build files, one portfile each"):
    val root = freshRoot()
    val session = publish(root, Path.of("/p"), Kind.Runner).toOption.get
    val builds = Seq("x", "y").map(name => Files.createTempDirectory(s"build-$name"))
    builds.foreach: build =>
      val hash = buildHash(build)
      publishBuildFile(session.directory, hash, build)
      val socket = session.tmp.resolve(hash).resolve("sock")
      Files.createDirectories(socket.getParent)
      Files.createFile(socket)
      Files.createDirectories(build.resolve("project/target"))
      Files.writeString(build.resolve("project/target/active.json"), s"""{"uri":"local://$socket"}""", UTF_8)
    val dead = die(session)
    val spoken = ListBuffer[Path]()
    val results = scavenge(root, processes(), path => { spoken += path; ServerAnswer.ShutDown })
    val condemned = root.resolve(CondemnedDir).resolve(dead.getFileName)
    assertEquals(spoken.toList.sorted, builds.map(build => condemned.resolve(s"tmp/${buildHash(build)}/sock")).sorted)
    assertEquals(results.flatMap(_(1)).collect { case Collected.ServerShutDown(p) => p }.size, 2)
    assert(!Files.exists(condemned))

  test("a portfile naming someone else's socket is not this command's to end"):
    val root = freshRoot()
    val (_, _) = deadSessionWithServer(root, _ => Path.of("/somewhere/else/sock"))
    val spoken = ListBuffer[Path]()
    val results = scavenge(root, processes(), path => { spoken += path; ServerAnswer.ShutDown })
    assertEquals(spoken.toList, Nil)
    val skips = results.flatMap(_(1)).collect { case Collected.ServerSkipped(reason) => reason }
    assert(skips.exists(_.contains("not this command's")), clue = skips)

  test("a socket spelled through the session but resolving outside it is never sent a shutdown"):
    val root = freshRoot()
    val outside = Files.createTempDirectory("outside").toRealPath()
    Files.createFile(outside.resolve("sock"))
    deadSessionWithServer(root, dead =>
      val ups = Iterator.fill(dead.getNameCount + 1)("..").mkString("/")
      Path.of(s"$dead/tmp/$ups$outside/sock"))
    val spoken = ListBuffer[Path]()
    val results = scavenge(root, processes(), path => { spoken += path; ServerAnswer.ShutDown })
    assertEquals(spoken.toList, Nil)
    val skips = results.flatMap(_(1)).collect { case Collected.ServerSkipped(reason) => reason }
    assert(skips.exists(_.contains("does not resolve inside")), clue = skips)

  test("a symlink beneath the session cannot point the shutdown outside it"):
    val root = freshRoot()
    val outside = Files.createTempDirectory("outside").toRealPath()
    Files.createFile(outside.resolve("sock"))
    val (dead, socket) = deadSessionWithServer(root, _.resolve(TmpDir).resolve("srv").resolve("sock"))
    Files.delete(socket)
    Files.delete(socket.getParent)
    Files.createSymbolicLink(dead.resolve(TmpDir).resolve("srv"), outside)
    val spoken = ListBuffer[Path]()
    val results = scavenge(root, processes(), path => { spoken += path; ServerAnswer.ShutDown })
    assertEquals(spoken.toList, Nil)
    val skips = results.flatMap(_(1)).collect { case Collected.ServerSkipped(reason) => reason }
    assert(skips.exists(_.contains("does not resolve inside")), clue = skips)

  test("endSession condemns before it collects, so the shutdown is sent to the condemned pathname"):
    val root = freshRoot()
    val workspace = Files.createTempDirectory("proj")
    val session = publish(root, workspace).toOption.get
    Files.writeString(session.records.resolve("client"), renderRecord(Record(4, "START-D")), UTF_8)
    val socket = session.tmp.resolve("sock")
    Files.createFile(socket)
    Files.createDirectories(workspace.resolve("project/target"))
    Files.writeString(
      workspace.resolve("project/target/active.json"),
      s"""{"uri":"local://$socket"}""",
      UTF_8,
    )
    val fakes = processes(4L -> "START-D")
    val spoken = ListBuffer[Path]()
    val actions = endSession(root, session, fakes, path => { spoken += path; ServerAnswer.ShutDown })
    assertEquals(fakes.ended.toList, List(4L), "the recorded group is ended behind its live leader")
    val condemned = root.resolve(CondemnedDir).resolve(session.directory.getFileName)
    assertEquals(spoken.toList, List(condemned.resolve("tmp/sock")))
    assert(actions.exists(_.isInstanceOf[Collected.ServerShutDown]), clue = actions)
    assert(!Files.exists(session.directory), "the original pathname is gone before any shutdown was sent")
    assert(!Files.exists(condemned), "collection deleted the condemned directory")

  test("endSession hands beforeRemoval the condemned directory, groups ended, and deletes it even if that throws"):
    val root = freshRoot()
    val session = publish(root, Path.of("/p")).toOption.get
    Files.writeString(session.records.resolve("client"), renderRecord(Record(5, "START-E")), UTF_8)
    val fakes = processes(5L -> "START-E")
    val condemned = root.resolve(CondemnedDir).resolve(session.directory.getFileName)
    val seen = ListBuffer[(Path, List[Long], Boolean)]()
    intercept[IllegalStateException]:
      endSession(root, session, fakes, _ => ServerAnswer.Unreachable("no socket"), condemned =>
        seen += ((condemned, fakes.ended.toList, Files.isDirectory(condemned.resolve(TmpDir))))
        throw IllegalStateException("the reader failed"))
    assertEquals(seen.toList, List((condemned, List(5L), true)))
    assert(!Files.exists(condemned), "the deletion followed the failed read")
    assert(!Files.exists(session.directory))

  test("an unanswered server keeps its condemned directory for the next start to retry"):
    val root = freshRoot()
    val (dead, _) = deadSessionWithServer(root, _.resolve(TmpDir).resolve("sock"))
    val kept = root.resolve(CondemnedDir).resolve(dead.getFileName)
    val first = scavenge(root, processes(), _ => ServerAnswer.Unanswered("timed out"))
    val unanswered =
      first.flatMap(_(1)).collect { case Collected.ServerUnanswered(_, reason) => reason }
    assert(unanswered.exists(_.contains("timed out")), clue = first)
    assert(Files.isDirectory(kept), "the directory, records and socket stay for the retry")
    val second = scavenge(root, processes(), _ => ServerAnswer.Unreachable("connect refused"))
    val skips = second.flatMap(_(1)).collect { case Collected.ServerSkipped(reason) => reason }
    assert(skips.exists(_.contains("gone")), clue = second)
    assert(!Files.exists(kept), "a gone server releases the directory")

  // --------------------------------------------------------------------------
  // The retirement lock
  // --------------------------------------------------------------------------

  test("a runtime's records map to one retirement lock per program and build directory; others to none"):
    val hash = "0123456789abcdef"
    assertEquals(retirementLockName(s"proxy-sbt-$hash"), Some(s"sbt-$hash"))
    assertEquals(retirementLockName(s"server-sbt-$hash"), Some(s"sbt-$hash"))
    assertEquals(retirementLockName(s"proxy-mill-$hash"), Some(s"mill-$hash"))
    assertEquals(retirementLockName(s"daemon-mill-$hash"), Some(s"mill-$hash"))
    assertEquals(retirementLockName(s"proxy-gradle-$hash"), Some(s"gradle-$hash"))
    assertEquals(retirementLockName(s"proxy-mvn-$hash"), Some(s"mvn-$hash"))
    assertEquals(retirementLockName(s"server-sbt-$hash.pending"), Some(s"sbt-$hash"), "a kill's leftover")
    // The session ends the Gradle daemons and a command session's own records under its own lock alone, and no other
    // process holds that lock while the session lives.
    assertEquals(retirementLockName(RunOnHostGradleDaemons.recordName(4242)), None)
    assertEquals(retirementLockName("client"), None)
    assertEquals(retirementLockName("proxy"), None)

  /** The process table that two enders share. An ended group leaves the table, as a group that a real kill ends
    * does. */
  class Groups(initial: Map[Long, String]):
    @volatile var alive: Map[Long, String] = initial
    val ended = ListBuffer[Long]()

  /** A view of the table. With `pause`, the end waits between the leader's start-time check and the signal, so that a
    * second ender can start in between: the end counts `reached` down and then awaits `proceed`. */
  class SharedProcesses(
    groups: Groups,
    pause: Option[(java.util.concurrent.CountDownLatch, java.util.concurrent.CountDownLatch)] = None,
  ) extends Processes:
    def startOf(pid: Long): Option[String] = groups.alive.get(pid)
    def endGroup(pgid: Long): Boolean =
      pause.foreach: (reached, proceed) =>
        reached.countDown()
        proceed.await()
      groups.synchronized:
        groups.ended += pgid
        groups.alive -= pgid
      true
    def groupEmpty(pgid: Long): Boolean = !groups.alive.contains(pgid)
    def signal(pid: Long, name: String): Unit = fail(s"signalled $pid with $name")

  def latches() = (java.util.concurrent.CountDownLatch(1), java.util.concurrent.CountDownLatch(1))

  def started[A](body: => A): java.util.concurrent.Future[A] =
    val task = java.util.concurrent.FutureTask[A](() => body)
    val thread = Thread(task)
    thread.setDaemon(true)
    thread.start()
    task

  /** The group outcomes alone, without the servers that a runner session's collection also reports. */
  def groupsOf(actions: Vector[Collected]): Vector[Collected] =
    actions.filterNot(_.isInstanceOf[Collected.ServerSkipped])

  def doneWithin(future: java.util.concurrent.Future[?], millis: Long): Boolean =
    try
      future.get(millis, java.util.concurrent.TimeUnit.MILLISECONDS)
      true
    catch case _: java.util.concurrent.TimeoutException => false

  /** Whether this JVM holds the lock, which a second channel's tryLock then overlaps. The check is a probe, as
    * lockIsFree is. The fcntl release that the probe's close causes is invisible within one process. */
  def heldByThisJvm(lockFile: Path): Boolean =
    val channel = FileChannel.open(lockFile, java.nio.file.StandardOpenOption.WRITE)
    try
      val lock = channel.tryLock()
      if lock == null then false
      else
        lock.release()
        false
    catch case _: java.nio.channels.OverlappingFileLockException => true
    finally channel.close()

  val Hash = "abcdef0123456789"
  def serverRecordName = s"server-sbt-$Hash"

  def proxyRecordName = s"proxy-sbt-$Hash"

  /** Another holder of the sbt retirement lock of Hash. The holder pauses between its start-time check and its signal
    * on `record` until the caller releases the returned latch. `record` is a `proxy-sbt-<Hash>` record, which shares
    * the lock with the server's record. The pgid is the group that the holder ends. */
  def holdingRetirementLock(
    root: Path, record: Path, groups: Groups,
  ): (java.util.concurrent.Future[Option[Collected]], java.util.concurrent.CountDownLatch) =
    val (reached, proceed) = latches()
    val holding = started(endRecordedGroup(root, record, SharedProcesses(groups, Some((reached, proceed)))))
    reached.await()
    (holding, proceed)

  /** What another launch's takeover does under the lock (RunnerRuntimes.takeOver): it ends the owner's recorded group,
    * and it reads the record only once it holds the lock. */
  def taker(root: Path, record: Path, groups: Groups): Option[Collected] =
    endRecordedGroup(root, record, SharedProcesses(groups))

  /** What a waiter finds once the holder that ended the group released the lock:
    * - the record deleted with its session;
    * - or, since the holder releases the lock before the deletion, the record of a group observed gone, skipped.
    * The waiter never finds a signal: the signal is the holder's, and the caller counts it. */
  def foundEnded(outcome: Option[Collected], pgid: Long): Unit =
    outcome match
      case None | Some(Collected.GroupSkipped(`pgid`, _)) => ()
      case other => fail(s"the waiter found $other")

  test("teardown against a taker: the taker waits for the lock, and the group is signalled once"):
    val root = freshRoot()
    val owner = publish(root, Path.of("/p"), Kind.Runner).toOption.get
    Files.writeString(owner.records.resolve(serverRecordName), renderRecord(Record(7, "START-A")), UTF_8)
    val groups = Groups(Map(7L -> "START-A"))
    val (reached, proceed) = latches()
    val teardown =
      started(endSession(root, owner, SharedProcesses(groups, Some((reached, proceed))), _ => ServerAnswer.ShutDown))
    reached.await()
    // The teardown has checked the leader's start time and holds the lock. The taker, on the condemned record, waits
    // rather than checking and signalling the same group.
    val condemned = root.resolve(CondemnedDir).resolve(owner.directory.getFileName)
    val taking = started(taker(root, condemned.resolve(RecordsDir).resolve(serverRecordName), groups))
    assert(!doneWithin(taking, 300), "the taker waits on the lock")
    proceed.countDown()
    assertEquals(teardown.get.collect { case Collected.GroupEnded(g) => g }, Vector(7L))
    foundEnded(taking.get, 7L)
    assertEquals(groups.ended.toList, List(7L), "one signal")
    assert(!Files.exists(condemned) && !Files.exists(owner.directory))

  test("scavenge against a taker, either first: the group is signalled once, one consistent outcome"):
    // The scavenger goes first. The taker waits, then finds the record gone with the session.
    val root = freshRoot()
    val dead = die(publish(root, Path.of("/p"), Kind.Runner).toOption.get)
    Files.writeString(dead.resolve(RecordsDir).resolve(serverRecordName), renderRecord(Record(7, "START-A")), UTF_8)
    val groups = Groups(Map(7L -> "START-A"))
    val (reached, proceed) = latches()
    val scavenging =
      started(scavenge(root, SharedProcesses(groups, Some((reached, proceed))), _ => ServerAnswer.ShutDown))
    reached.await()
    val condemned = root.resolve(CondemnedDir).resolve(dead.getFileName)
    val taking = started(taker(root, condemned.resolve(RecordsDir).resolve(serverRecordName), groups))
    assert(!doneWithin(taking, 300), "the taker waits on the lock")
    proceed.countDown()
    assertEquals(scavenging.get.flatMap(_(1)).collect { case Collected.GroupEnded(g) => g }, Vector(7L))
    foundEnded(taking.get, 7L)
    assertEquals(groups.ended.toList, List(7L))
    assert(!Files.exists(condemned))

    // The taker goes first. The scavenger waits, then finds the leader gone and the group empty. The scavenger skips
    // the group, never signalling it twice, and deletes the session.
    val second = die(publish(root, Path.of("/p"), Kind.Runner).toOption.get)
    val record = second.resolve(RecordsDir).resolve(serverRecordName)
    Files.writeString(record, renderRecord(Record(8, "START-B")), UTF_8)
    val later = Groups(Map(8L -> "START-B"))
    val (takerReached, takerProceed) = latches()
    val takingFirst =
      started(endRecordedGroup(root, record, SharedProcesses(later, Some((takerReached, takerProceed)))))
    takerReached.await()
    val scavengingLater = started(scavenge(root, SharedProcesses(later), _ => ServerAnswer.ShutDown))
    assert(!doneWithin(scavengingLater, 300), "the scavenger waits on the lock the taker holds")
    takerProceed.countDown()
    assertEquals(takingFirst.get, Some(Collected.GroupEnded(8L)))
    assertEquals(
      scavengingLater.get.flatMap(_(1)).collect { case Collected.GroupSkipped(g, _) => g }, Vector(8L),
    )
    assertEquals(later.ended.toList, List(8L))
    assert(!Files.exists(root.resolve(CondemnedDir).resolve(second.getFileName)))

  test("a retirement interrupted before its TERM is resumed by a successor that ends the group"):
    // The holder died while it held the lock and before it signalled anything. The lock is released with the holder,
    // but the group is not, and the successor checks the leader's start time as any holder does.
    val root = freshRoot()
    val dead = die(publish(root, Path.of("/p"), Kind.Runner).toOption.get)
    val record = dead.resolve(RecordsDir).resolve(serverRecordName)
    Files.writeString(record, renderRecord(Record(7, "START-A")), UTF_8)
    val died = FileChannel.open(
      retirementLockFile(root, s"sbt-$Hash"),
      java.nio.file.StandardOpenOption.CREATE,
      java.nio.file.StandardOpenOption.WRITE,
    )
    died.tryLock()
    died.close()
    val fakes = processes(7L -> "START-A")
    val resumed = scavenge(root, fakes, _ => ServerAnswer.ShutDown).flatMap(_(1))
    assertEquals(groupsOf(resumed), Vector(Collected.GroupEnded(7L)))
    assertEquals(fakes.ended.toList, List(7L))

  test("interrupted between TERM and KILL, the successor retains a blocked group or deletes an ended one"):
    val root = freshRoot()
    val mine = publish(root, Path.of("/p"), Kind.Runner).toOption.get
    // The TERM took the leader and left a member.
    // - The successor signals nothing, because no start time is left to check the number against.
    // - The successor keeps the record, and the record still blocks admission.
    // - Whether the member ends is up to the member, and the test requires no termination.
    val blocked = die(publish(root, Path.of("/p"), Kind.Runner).toOption.get)
    val blockedRecord = blocked.resolve(RecordsDir).resolve(serverRecordName)
    Files.writeString(blockedRecord, renderRecord(Record(7, "START-A")), UTF_8)
    // Group 7 keeps a member, and every other number lists none.
    class Orphaned extends FakeProcesses(Map.empty):
      override def groupEmpty(pgid: Long): Boolean = pgid != 7
    val orphaned = Orphaned()
    val kept = scavenge(root, orphaned, _ => ServerAnswer.ShutDown).flatMap(_(1))
    assertEquals(
      kept.collect { case Collected.GroupAlive(g, reason) => (g, reason) },
      Vector(7L -> "leader gone, a member still listed"),
    )
    assertEquals(orphaned.ended.toList, Nil)
    val condemned = root.resolve(CondemnedDir).resolve(blocked.getFileName)
    assert(Files.exists(condemned.resolve(RecordsDir).resolve(serverRecordName)), "the record is kept")
    assertEquals(runtimeOwner(root, mine.directory, serverRecordName, orphaned), Some(condemned), "admission blocked")
    // The TERM ended the whole group. The successor finds the group empty and deletes the record with the session, and
    // the record blocks nothing.
    val ended = die(publish(root, Path.of("/p"), Kind.Runner).toOption.get)
    Files.writeString(ended.resolve(RecordsDir).resolve(serverRecordName), renderRecord(Record(8, "START-B")), UTF_8)
    assertEquals(runtimeOwner(root, mine.directory, serverRecordName, orphaned), Some(condemned), "the blocked owns")
    val skipped = scavenge(root, orphaned, _ => ServerAnswer.ShutDown)
    assertEquals(
      skipped.find(_(0) == root.resolve(CondemnedDir).resolve(ended.getFileName)).map(pair => groupsOf(pair(1))),
      Some(Vector(Collected.GroupSkipped(8L, "leader gone: no member listed"))),
    )
    assertEquals(orphaned.ended.toList, Nil)
    assert(!Files.exists(root.resolve(CondemnedDir).resolve(ended.getFileName)))
    remove(mine)

  test("a retirement lock held past the bound keeps the session, its records and its directory"):
    // A crashed owner's proxy and server records share one lock. A taker holds the lock on the proxy's record, while
    // the scavenger, which waits a bounded time, gives up on both records.
    val root = freshRoot()
    val dead = die(publish(root, Path.of("/p"), Kind.Runner).toOption.get)
    Files.writeString(dead.resolve(RecordsDir).resolve(serverRecordName), renderRecord(Record(7, "START-A")), UTF_8)
    Files.writeString(dead.resolve(RecordsDir).resolve(proxyRecordName), renderRecord(Record(9, "START-Z")), UTF_8)
    val groups = Groups(Map(7L -> "START-A", 9L -> "START-Z"))
    val (holding, proceed) = holdingRetirementLock(root, dead.resolve(RecordsDir).resolve(proxyRecordName), groups)
    val scavenger = SharedProcesses(groups)
    val condemned = root.resolve(CondemnedDir).resolve(dead.getFileName)
    val bounded = scavenge(root, scavenger, _ => ServerAnswer.ShutDown, retirementDeadlineMillis = 200)
    val busy = groupsOf(bounded.flatMap(_(1)))
    assertEquals(
      busy.collect { case Collected.RetirementBusy(name, _) => name }.sorted, Vector(proxyRecordName, serverRecordName),
    )
    assert(busy.forall(_.keeps), clue = busy)
    assertEquals(groups.ended.toList, Nil, "nothing was read or signalled")
    assert(Files.exists(condemned.resolve(RecordsDir).resolve(serverRecordName)), "the records are kept")
    assert(Files.exists(condemned.resolve(RecordsDir).resolve(proxyRecordName)))
    assert(Files.exists(condemned.resolve(LockFile)), "the directory is kept, collectable")
    proceed.countDown()
    assertEquals(holding.get, Some(Collected.GroupEnded(9L)))
    val freed = groupsOf(scavenge(root, scavenger, _ => ServerAnswer.ShutDown).flatMap(_(1)))
    assertEquals(
      freed.toSet, Set(Collected.GroupEnded(7L), Collected.GroupSkipped(9L, "leader gone: no member listed")),
    )
    assertEquals(groups.ended.toList, List(9L, 7L))
    assert(!Files.exists(condemned))

  /** What another process finds at the lock file, `held` or `taken` (RunOnHostLockProbe). Only another process can
    * observe this JVM's fcntl lock; this JVM's own FileChannel cannot. */
  def probedByAnotherProcess(lockFile: Path): String =
    val launcher = Path.of(System.getProperty("java.home")).resolve("bin").resolve("java").toString
    val process = java.lang.ProcessBuilder(
      launcher, "-cp", EmitRunOnHostProfile.classpathForRelaunch, "agentsandbox.launcher.RunOnHostLockProbe",
      lockFile.toString,
    ).redirectError(java.lang.ProcessBuilder.Redirect.DISCARD).start()
    val said = String(process.getInputStream.readAllBytes(), UTF_8).trim
    assertEquals(process.waitFor(), 0, s"the probe exited with $said")
    said

  test("two threads of one process: the waiter's timeout leaves the holder's lock and signal intact"):
    // The run-on-host checks' entry prepares on its main thread and tears down from the shutdown hook, in one JVM. The
    // waiter must open no second descriptor to the lock file, because closing that descriptor would drop the holder's
    // fcntl lock for the whole process. Only another process can observe that drop.
    val root = freshRoot()
    val dead = die(publish(root, Path.of("/p"), Kind.Runner).toOption.get)
    val record = dead.resolve(RecordsDir).resolve(serverRecordName)
    Files.writeString(record, renderRecord(Record(7, "START-A")), UTF_8)
    val groups = Groups(Map(7L -> "START-A"))
    val (reached, proceed) = latches()
    val holding = started(endRecordedGroup(root, record, SharedProcesses(groups, Some((reached, proceed)))))
    reached.await()
    val lockFile = retirementLockFile(root, s"sbt-$Hash")
    assertEquals(probedByAnotherProcess(lockFile), "held", "the holder's lock, before any waiter")
    val waited = endRecordedGroup(root, record, SharedProcesses(groups), retirementDeadlineMillis = 200)
    assertEquals(waited.map(_.getClass.getSimpleName), Some("RetirementBusy"), clue = waited)
    assert(waited.exists(_.keeps))
    assertEquals(groups.ended.toList, Nil, "the waiter signalled nothing")
    assertEquals(probedByAnotherProcess(lockFile), "held", "the holder's lock survives the waiter's timeout")
    proceed.countDown()
    assertEquals(holding.get, Some(Collected.GroupEnded(7L)), "the holder's end is unaffected")
    assertEquals(probedByAnotherProcess(lockFile), "taken", "released with the holder")
    assertEquals(
      endRecordedGroup(root, record, SharedProcesses(groups)),
      Some(Collected.GroupSkipped(7L, "leader gone: no member listed")),
    )
    assertEquals(groups.ended.toList, List(7L))

  test("the retirement lock is taken last: after the condemned entry's lock, and after the session's own"):
    val root = freshRoot()
    // Scavenging condemns the entry and holds its lock before it waits for the retirement lock, so no other collector
    // can take the entry meanwhile. The holder is a taker on the dead session's proxy record, which shares the lock.
    val dead = die(publish(root, Path.of("/p"), Kind.Runner).toOption.get)
    Files.writeString(dead.resolve(RecordsDir).resolve(serverRecordName), renderRecord(Record(7, "START-A")), UTF_8)
    Files.writeString(dead.resolve(RecordsDir).resolve(proxyRecordName), renderRecord(Record(9, "START-Z")), UTF_8)
    val groups = Groups(Map(7L -> "START-A", 8L -> "START-B", 9L -> "START-Z"))
    val (holding, proceed) = holdingRetirementLock(root, dead.resolve(RecordsDir).resolve(proxyRecordName), groups)
    val fakes = SharedProcesses(groups)
    val scavenging = started(scavenge(root, fakes, _ => ServerAnswer.ShutDown))
    val condemned = root.resolve(CondemnedDir).resolve(dead.getFileName)
    var waited = 0
    while !Files.exists(condemned.resolve(LockFile)) && waited < 200 do { Thread.sleep(20); waited += 1 }
    assert(!doneWithin(scavenging, 300), "the scavenger waits on the retirement lock")
    assert(heldByThisJvm(condemned.resolve(LockFile)), "holding the condemned entry's lock")
    // Teardown condemns the session and still holds the session's own lock while it waits for the retirement lock.
    // Teardown releases the session's lock only after the collection.
    val owner = publish(root, Path.of("/p"), Kind.Runner).toOption.get
    Files.writeString(owner.records.resolve(serverRecordName), renderRecord(Record(8, "START-B")), UTF_8)
    val teardown = started(endSession(root, owner, fakes, _ => ServerAnswer.ShutDown))
    val ownerCondemned = root.resolve(CondemnedDir).resolve(owner.directory.getFileName)
    waited = 0
    while !Files.exists(ownerCondemned.resolve(LockFile)) && waited < 200 do { Thread.sleep(20); waited += 1 }
    assert(!doneWithin(teardown, 300), "the teardown waits on the retirement lock")
    assert(heldByThisJvm(ownerCondemned.resolve(LockFile)), "holding the session's own lock")
    proceed.countDown()
    assertEquals(holding.get, Some(Collected.GroupEnded(9L)))
    assertEquals(
      groupsOf(scavenging.get.flatMap(_(1))).toSet,
      Set(Collected.GroupEnded(7L), Collected.GroupSkipped(9L, "leader gone: no member listed")),
    )
    assertEquals(groupsOf(teardown.get), Vector(Collected.GroupEnded(8L)))
    assertEquals(groups.ended.toList.sorted, List(7L, 8L, 9L))
    assert(!Files.exists(condemned) && !Files.exists(ownerCondemned))

  test("a Gradle daemon's record is ended under its session's lock alone; no retirement lock is made for it"):
    val root = freshRoot()
    val dead = die(publish(root, Path.of("/p"), Kind.Runner).toOption.get)
    val record = dead.resolve(RecordsDir).resolve(RunOnHostGradleDaemons.recordName(4242))
    Files.writeString(record, renderRecord(Record(4242, "S")), UTF_8)
    val fakes = processes(4242L -> "S")
    val collected = scavenge(root, fakes, _ => ServerAnswer.ShutDown).flatMap(_(1))
    assertEquals(groupsOf(collected), Vector(Collected.GroupEnded(4242L)))
    assertEquals(fakes.ended.toList, List(4242L))
    assertEquals(listNames(root.resolve(RetireLockDir)), Vector.empty)

  // --------------------------------------------------------------------------
  // The leader, against real processes
  // --------------------------------------------------------------------------

  def notUnderRunOnHostProfile(): Unit =
    assume(!RunOnHostSessionTest.underRunOnHostProfile, "the leader never runs under the profile")

  test("a leader registers pgid and start time by rename before its command runs"):
    notUnderRunOnHostProfile()
    val dir = Files.createTempDirectory("leader")
    val record = dir.resolve("record")
    val command = registeredSpawn(record, Seq("/bin/sleep", "30"))
    val process = java.lang.ProcessBuilder(command*).start()
    try
      val deadline = System.nanoTime + 10_000_000_000L
      while !Files.exists(record) && System.nanoTime < deadline do Thread.sleep(20)
      val parsed = parseRecord(Files.readString(record, UTF_8))
      assert(parsed.isDefined, "the record was published")
      assertEquals(parsed.get.pgid, process.pid, "the leader is the group leader it registers")
      assertEquals(HostProcesses.startOf(process.pid), Some(parsed.get.leaderStart))
    finally process.destroyForcibly().waitFor()

  test("a record's start time is the C locale's, whatever locale the leader inherits"):
    notUnderRunOnHostProfile()
    def lstartIn(locale: String, pid: Long): String =
      val builder = java.lang.ProcessBuilder("/bin/ps", "-o", "lstart=", "-p", pid.toString)
      builder.environment.put("LC_ALL", locale)
      String(builder.start().getInputStream.readAllBytes(), UTF_8).trim
    val self = ProcessHandle.current.pid
    val unlikeC = Seq("fr_FR.UTF-8", "de_DE.UTF-8", "ja_JP.UTF-8").find(lstartIn(_, self) != lstartIn("C", self))
    assume(unlikeC.isDefined, "no installed locale spells ps's lstart unlike the C locale")
    val record = Files.createTempDirectory("leader").resolve("record")
    val builder = java.lang.ProcessBuilder(registeredSpawn(record, Seq("/bin/sleep", "30"))*)
    builder.environment.put("LC_ALL", unlikeC.get)
    val process = builder.start()
    try
      val deadline = System.nanoTime + 10_000_000_000L
      while !Files.exists(record) && System.nanoTime < deadline do Thread.sleep(20)
      val recorded = parseRecord(Files.readString(record, UTF_8)).map(_.leaderStart)
      assertEquals(recorded, Some(lstartIn("C", process.pid)), s"the leader ran under ${unlikeC.get}")
      assertEquals(HostProcesses.startOf(process.pid), recorded)
    finally process.destroyForcibly().waitFor()

  test("the command's exit status is published beside the record, and the leader stays"):
    notUnderRunOnHostProfile()
    val record = Files.createTempDirectory("leader").resolve("record")
    val process =
      java.lang.ProcessBuilder(registeredSpawn(record, Seq("/bin/sh", "-c", "exit 7"))*).start()
    try
      assertEquals(awaitExit(exitRecord(record), process), Right(7))
      assert(process.isAlive, "the leader outlives its command, keeping its start time checkable")
    finally process.destroyForcibly().waitFor()

  test("a command gone before reading its input makes a write larger than a pipe's buffer fail, not block"):
    notUnderRunOnHostProfile()
    val record = Files.createTempDirectory("leader").resolve("record")
    val process = java.lang.ProcessBuilder(registeredSpawn(record, Seq("/bin/sh", "-c", "exit 0"))*).start()
    try
      assertEquals(awaitExit(exitRecord(record), process), Right(0))
      val written = java.util.concurrent.CompletableFuture.supplyAsync: () =>
        try
          process.getOutputStream.write(Array.fill[Byte](4 << 20)('x'))
          process.getOutputStream.flush()
          "written"
        catch case _: java.io.IOException => "failed"
      assertEquals(written.get(10, java.util.concurrent.TimeUnit.SECONDS), "failed")
      assert(process.isAlive, "the leader stays, holding no reader of the pipe")
    finally process.destroyForcibly().waitFor()

  test("a command's signal death is published as the shell's 128+signal"):
    notUnderRunOnHostProfile()
    val record = Files.createTempDirectory("leader").resolve("record")
    val process = java.lang.ProcessBuilder(
      registeredSpawn(record, Seq("/bin/sh", "-c", "kill -KILL $$"))*).start()
    try assertEquals(awaitExit(exitRecord(record), process), Right(137))
    finally process.destroyForcibly().waitFor()

  test("a leader gone without an exit status is a Left, not a hang"):
    notUnderRunOnHostProfile()
    val record = Files.createTempDirectory("leader").resolve("record")
    val process =
      java.lang.ProcessBuilder(registeredSpawn(record, Seq("/bin/sleep", "30"))*).start()
    process.destroyForcibly().waitFor()
    assert(awaitExit(exitRecord(record), process).isLeft)

  test("a leader whose record cannot be published ends itself with 71"):
    notUnderRunOnHostProfile()
    val gone = Files.createTempDirectory("leader").resolve("condemned-away/record")
    val process =
      java.lang.ProcessBuilder(registeredSpawn(gone, Seq("/bin/sleep", "30"))*).start()
    assertEquals(process.waitFor(), 71)

  test("the build lock admits one command at a time: the second reports it only once the first released"):
    // The runner's work on the runtime before a command runs under the command's build lock (lockedSpawn), whether the
    // runner observes, retires or creates the runtime. Two launches' commands on one build directory therefore never
    // overlap. This test runs two under-runner holders of one lock: the second reports the lock only once the first has
    // released it.
    notUnderRunOnHostProfile()
    val lockFile = Files.createTempDirectory("build-lock").resolve("sbt-x")
    def helper(): (Process, java.io.BufferedReader) =
      val process = java.lang.ProcessBuilder(lockedSpawn(lockFile, Seq("/bin/true"), underRunner = true)*).start()
      (process, java.io.BufferedReader(java.io.InputStreamReader(process.getInputStream, UTF_8)))
    def release(process: Process): Unit =
      process.getOutputStream.write(runWord(Seq.empty).getBytes(UTF_8))
      process.getOutputStream.close()
      process.waitFor()
    val (first, firstOut) = helper()
    assertEquals(firstOut.readLine(), LockedLine, "the first retirer holds the lock")
    val (second, secondOut) = helper()
    try
      val secondReached = java.util.concurrent.atomic.AtomicReference[String]()
      val reader = Thread(() => secondReached.set(secondOut.readLine()))
      reader.setDaemon(true)
      reader.start()
      Thread.sleep(500)
      assertEquals(secondReached.get, null, "the second retirer waits; the critical sections do not overlap")
      release(first)
      reader.join(5_000)
      assertEquals(secondReached.get, LockedLine, "the second retirer enters only once the first released")
    finally release(second)

  test("a lock holder holds the build lock for its life, and the next taker runs once it is gone"):
    notUnderRunOnHostProfile()
    val lockFile = Files.createTempDirectory("lock").resolve("sbt-x")
    val holder =
      java.lang.ProcessBuilder(lockedSpawn(lockFile, Seq("/bin/sleep", "30"), underRunner = false)*).start()
    try
      // The holder takes the lock at its own pace, and a taker started too early runs at once. The test therefore
      // starts takers until one reports the wait and is then still alive, blocked. The test reads one line, not the
      // stream, because a blocked taker holds its stderr open until it exits.
      def taker() = java.lang.ProcessBuilder(
        lockedSpawn(lockFile, Seq("/bin/sh", "-c", "exit 7"), underRunner = false)*).start()
      var waiting: Option[Process] = None
      val deadline = System.nanoTime + 10_000_000_000L
      while waiting.isEmpty && System.nanoTime < deadline do
        val candidate = taker()
        val said = java.io.BufferedReader(java.io.InputStreamReader(candidate.getErrorStream, UTF_8)).readLine()
        if said != null && said.contains("waiting for the build lock") then waiting = Some(candidate)
        else
          assertEquals(candidate.waitFor(), 7, "a taker that did not wait ran")
          Thread.sleep(50)
      val blocked = waiting.getOrElse(fail("no taker ever found the lock held"))
      assert(blocked.isAlive, "the taker blocks while the holder lives")
      // A taker that a runner dispatched reads EOF on its stdin when the runner is gone, and it then ends itself.
      val orphan = java.lang.ProcessBuilder(
        lockedSpawn(lockFile, Seq("/bin/sh", "-c", "exit 7"), underRunner = true)*).start()
      java.io.BufferedReader(java.io.InputStreamReader(orphan.getErrorStream, UTF_8)).readLine()
      orphan.getOutputStream.close()
      assert(orphan.waitFor(10, java.util.concurrent.TimeUnit.SECONDS), "the pipe's EOF ends the wait")
      assertEquals(orphan.exitValue, 71)
      assert(holder.isAlive)
      holder.destroyForcibly().waitFor()
      assert(blocked.waitFor(10, java.util.concurrent.TimeUnit.SECONDS), "the holder's death frees the lock")
      assertEquals(blocked.exitValue, 7)
    finally holder.destroyForcibly().waitFor()

  test("bytes the runner writes after the word reach the exec'd command's stdin whole, and none reach its arguments"):
    // The holder reads its word a byte at a time, so a buffered read cannot take the frame of the brokered credentials
    // (RunOnHostSandbox.CredentialsOption) and lose it at the exec.
    notUnderRunOnHostProfile()
    val lockFile = Files.createTempDirectory("lock").resolve("sbt-x")
    val command = Seq("/bin/sh", "-c", "printf '%s\\n' \"$@\"; echo ==; cat", "sh", "--")
    val process = java.lang.ProcessBuilder(lockedSpawn(lockFile, command, underRunner = true)*).start()
    val out = java.io.BufferedReader(java.io.InputStreamReader(process.getInputStream, UTF_8))
    assertEquals(out.readLine(), LockedLine)
    val frame = "2\nA@h.example:Authorization PHa secret-a\nB@h.example?sig PHb secret-b\n"
    process.getOutputStream.write((runWord(Seq("--credentials-on-stdin")) + frame).getBytes(UTF_8))
    process.getOutputStream.close()
    val lines = Iterator.continually(out.readLine()).takeWhile(_ != null).toVector
    assertEquals(process.waitFor(), 0)
    assertEquals(lines, Vector("--credentials-on-stdin", "--", "==") ++ frame.linesIterator)

  test("a lock holder under the runner reports the lock, then execs on the word, refuses on it, or ends at EOF"):
    notUnderRunOnHostProfile()
    val lockFile = Files.createTempDirectory("lock").resolve("sbt-x")
    def holder(command: String*): (Process, java.io.BufferedReader) =
      val process = java.lang.ProcessBuilder(lockedSpawn(lockFile, command, underRunner = true)*).start()
      val out = java.io.BufferedReader(java.io.InputStreamReader(process.getInputStream, UTF_8))
      assertEquals(out.readLine(), LockedLine)
      (process, out)
    def answer(process: Process, word: String): Unit =
      process.getOutputStream.write(word.getBytes(UTF_8))
      process.getOutputStream.flush()
    // The word's arguments go before the command's `--`, whatever follows the `--`.
    val (run, out) = holder("/bin/sh", "-c", "printf '%s\\n' \"$@\"", "sh", "--", "-x")
    answer(run, runWord(Seq("--proxy-port=1", "--proxy-log=/l")))
    assertEquals(out.readLine(), "--proxy-port=1")
    assertEquals(out.readLine(), "--proxy-log=/l")
    assertEquals(out.readLine(), "--")
    assertEquals(out.readLine(), "-x")
    assertEquals(run.waitFor(), 0)
    // An argument that holds a newline, the escape byte or a NUL arrives whole, because the word is one line.
    val (odd, oddOut) = holder("/bin/sh", "-c", "printf '%s|' \"$@\" | od -An -c | tr -s ' \\n' ' '", "sh")
    answer(odd, runWord(Seq("a\nb", "\u0001x", "c")))
    assertEquals(oddOut.readLine().trim, "a \\n b | 001 x | c |")
    assertEquals(odd.waitFor(), 0)
    // The pipe stays the exec'd command's stdin, and its EOF still means that the runner is gone.
    val (held, _) = holder("/bin/sh", "-c", "cat")
    answer(held, runWord(Seq.empty))
    assert(
      !held.waitFor(500, java.util.concurrent.TimeUnit.MILLISECONDS),
      "the command's stdin is the pipe, still open",
    )
    held.getOutputStream.close()
    assertEquals(held.waitFor(), 0)
    // A refusal of several lines, such as one that quotes a server's output, reaches stderr whole.
    val (refused, _) = holder("/bin/sh", "-c", "exit 0")
    answer(refused, refusedWord("refused: no runtime; its output:\n[error] line one\n[error] line two\n"))
    assertEquals(
      String(refused.getErrorStream.readAllBytes(), UTF_8),
      "refused: no runtime; its output:\n[error] line one\n[error] line two\n\n",
    )
    assertEquals(refused.waitFor(), 2)
    val (orphan, _) = holder("/bin/sh", "-c", "exit 0")
    orphan.getOutputStream.close()
    assertEquals(orphan.waitFor(), 71)

  // --------------------------------------------------------------------------
  // The shutdown speaker, against a real local socket
  // --------------------------------------------------------------------------

  test("shutdown initializes, execs, and succeeds when the server closes"):
    val socket = shortSocketPath()
    val server = ServerSocketChannel.open(StandardProtocolFamily.UNIX)
    server.bind(UnixDomainSocketAddress.of(socket))
    val received = ListBuffer[String]()
    val thread = Thread(() =>
      val channel = server.accept()
      val buffer = ByteBuffer.allocate(8192)
      channel.read(buffer)
      received += String(buffer.array, 0, buffer.position, UTF_8)
      channel.write(ByteBuffer.wrap(frame("""{"jsonrpc":"2.0","id":"x","result":{}}""")))
      buffer.clear()
      channel.read(buffer)
      received += String(buffer.array, 0, buffer.position, UTF_8)
      channel.close(),
    )
    thread.start()
    val result = RunOnHostSbtServerShutdown.shutdown(socket, deadlineMillis = 10_000)
    thread.join(10_000)
    assertEquals(result, ServerAnswer.ShutDown)
    assert(received(0).contains("\"method\": \"initialize\""), clue = received)
    assert(received(0).contains("\"skipAnalysis\":true"), clue = received)
    assert(received(1).contains("\"sbt/exec\""), clue = received)
    assert(received(1).contains("\"shutdown\""), clue = received)

  test("a silent server is a bounded Unanswered — kept retryable — not a hang"):
    val socket = shortSocketPath()
    val server = ServerSocketChannel.open(StandardProtocolFamily.UNIX)
    server.bind(UnixDomainSocketAddress.of(socket))
    val thread = Thread(() => { val c = server.accept(); Thread.sleep(3_000); c.close() })
    thread.start()
    val result = RunOnHostSbtServerShutdown.shutdown(socket, deadlineMillis = 500)
    assert(result.isInstanceOf[ServerAnswer.Unanswered], clue = result)
    thread.join(10_000)

  test("an absent socket is Unreachable: there is no server to stop"):
    val result = RunOnHostSbtServerShutdown.shutdown(Path.of("/no/such/sock"), deadlineMillis = 500)
    assert(result.isInstanceOf[ServerAnswer.Unreachable], clue = result)

  test("a socket file whose listener is gone is Unreachable: the connect is refused"):
    val socket = shortSocketPath()
    val server = ServerSocketChannel.open(StandardProtocolFamily.UNIX)
    server.bind(UnixDomainSocketAddress.of(socket))
    server.close() // the file stays; nothing listens
    val result = RunOnHostSbtServerShutdown.shutdown(socket, deadlineMillis = 500)
    assert(result.isInstanceOf[ServerAnswer.Unreachable], clue = result)

  test("a connect failure that is no refusal stays retryable: a live server may hide behind it"):
    import java.nio.file.attribute.PosixFilePermissions
    val dir = Files.createTempDirectory("deny")
    val socket = dir.resolve("s")
    val server = ServerSocketChannel.open(StandardProtocolFamily.UNIX)
    server.bind(UnixDomainSocketAddress.of(socket))
    try
      Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("---------"))
      val result = RunOnHostSbtServerShutdown.shutdown(socket, deadlineMillis = 500)
      assert(result.isInstanceOf[ServerAnswer.Unanswered], clue = result)
    finally
      Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"))
      server.close()

  private def frame(json: String): Array[Byte] = RunOnHostSbtServerShutdown.frame(json)

  private def shortSocketPath(): Path =
    // sun_path is short on Linux too, so the whole path stays well under its limit.
    Files.createTempDirectory("sk").resolve("s")

  private def listNames(path: Path): Vector[String] =
    if !Files.isDirectory(path) then Vector.empty
    else FileHelper.directoryEntries(path).map(_.getFileName.toString).sorted
