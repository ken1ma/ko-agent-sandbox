package agentsandbox.launcher

import java.net.{StandardProtocolFamily, UnixDomainSocketAddress}
import java.nio.ByteBuffer
import java.nio.channels.ServerSocketChannel
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path, StandardCopyOption}

import scala.collection.mutable.ListBuffer

import RunOnHostSession.*

object RunOnHostSessionTest:
  /** The registration spawn is the wrapper's own process and runs outside the profile by
    * construction; under it, perl dies before registering. True exactly where the gate runs the
    * suites as a confined command, whose tests spawning one skip. */
  val underRunOnHostProfile: Boolean =
    sys.env.get("SBT_GLOBAL_SERVER_DIR").exists(_.startsWith("/private/tmp/ko-agent-"))

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
  // The wrapper root
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
    // Canonical, so the moved-socket pathnames the tests predict match what containment proves.
    val root = Files.createTempDirectory("command-session").toRealPath().resolve("root")
    ensureRoot(root, uid).toOption.get

  test("publish yields a locked session with tmp, records and the project on file"):
    val root = freshRoot()
    val session = publish(root, Path.of("/Users/u/proj")).toOption.get
    assert(Files.isDirectory(session.tmp))
    assert(Files.isDirectory(session.records))
    assertEquals(Files.readString(session.directory.resolve(ProjectFile), UTF_8).trim, "/Users/u/proj")
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
    // ownSession names the broker's own live session, which scavenge must not reach: lockIsFree
    // would open and close a second descriptor to its lock file, and closing any descriptor
    // releases the process's POSIX fcntl lock, so probing would unlock a live session. In one JVM
    // the release is invisible (the lock reads as held either way), so this asserts only that the
    // own session is left out of the scan and its results; the cross-process release is the gate's.
    val root = freshRoot()
    val own = publish(root, Path.of("/p"), Kind.Broker).toOption.get
    val other = die(publish(root, Path.of("/p")).toOption.get)
    val results = scavenge(root, processes(), _ => ServerAnswer.ShutDown, ownSession = Some(own.directory))
    assert(Files.isDirectory(own.directory), clue = own.directory)
    assert(!results.exists(_._1 == own.directory), clue = results)
    assert(!Files.exists(other), clue = "a dead peer is still collected while the own session is skipped")
    remove(own)

  test("the two session kinds are told apart by their directory's prefix"):
    val root = freshRoot()
    val broker = publish(root, Path.of("/p"), Kind.Broker).toOption.get
    val command = publish(root, Path.of("/p")).toOption.get
    assert(broker.directory.getFileName.toString.startsWith("b"), clue = broker.directory)
    assert(command.directory.getFileName.toString.startsWith("s"), clue = command.directory)
    remove(broker)
    remove(command)

  test("a build lock file is neither a session nor scavenged"):
    val root = freshRoot()
    val build = Path.of("/Users/u/proj/sub")
    val file = buildLockFile(root, "sbt", build).toOption.get
    assertEquals(file, root.resolve(BuildLockDir).resolve(s"sbt-${buildHash(build)}"))
    assertEquals(buildHash(build).length, 16)
    Files.createFile(file)
    assertEquals(scavenge(root, processes(), _ => ServerAnswer.ShutDown), Vector.empty)
    assert(Files.isRegularFile(file), "the lock file outlives every scavenge")
    assert(!Files.exists(root.resolve(CondemnedDir).resolve(BuildLockDir)))

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
    // A SIGKILLed wrapper: the lock is freed, the directory and records stay.
    session.close()
    session.directory

  test("runtimeOwner finds an owner in the root or condemned, and across the rename between the two"):
    val root = freshRoot()
    val mine = publish(root, Path.of("/p"), Kind.Broker).toOption.get
    val owner = publish(root, Path.of("/p"), Kind.Broker).toOption.get
    val hash = "abcdef0123456789"
    Files.writeString(owner.records.resolve(s"server-sbt-$hash"), renderRecord(Record(1, "S")), UTF_8)
    Files.writeString(owner.records.resolve(s"daemon-mill-$hash"), renderRecord(Record(2, "S")), UTF_8)
    // A live owner holding the record is found; a hash no one owns is not; each program's record is its own.
    assertEquals(runtimeOwner(root, mine.directory, s"server-sbt-$hash"), Some(owner.directory))
    assertEquals(runtimeOwner(root, mine.directory, s"daemon-mill-$hash"), Some(owner.directory))
    assertEquals(runtimeOwner(root, mine.directory, "server-sbt-0000000000000000"), None)
    assertEquals(runtimeOwner(root, mine.directory, "daemon-mill-0000000000000000"), None)
    // A just-crashed owner — unlocked, still in the root, not yet condemned — still owns: its
    // server group can be running, so admission is blocked until the next start collects it.
    owner.close()
    assertEquals(runtimeOwner(root, mine.directory, s"server-sbt-$hash"), Some(owner.directory), "a dead owner in the root still owns")
    // The owner renames into condemned/ in the instant between the root enumeration and its
    // lookup: the lookup then misses it in the root, but the later condemned enumeration finds
    // it, so admission stays blocked across the teardown rename.
    val condemned = Files.createDirectories(root.resolve(CondemnedDir))
    val moved = condemned.resolve(owner.directory.getFileName)
    var scans = 0
    val found = runtimeOwner(root, mine.directory, s"server-sbt-$hash", betweenScan = () =>
      scans += 1
      if scans == 1 then Files.move(owner.directory, moved, StandardCopyOption.ATOMIC_MOVE))
    assertEquals(found, Some(moved), "the owner renamed away between the scans is found in condemned")
    remove(mine)

  test("a build file is published by rename, read back by hash, and skipped while pending"):
    val root = freshRoot()
    val session = publish(root, Path.of("/p"), Kind.Broker).toOption.get
    val hash = buildHash(Path.of("/p/sub"))
    assertEquals(
      publishBuildFile(session.directory, hash, Path.of("/p/sub")),
      Right(buildFile(session.directory, hash)),
    )
    Files.writeString(session.directory.resolve(s"${BuildFilePrefix}deadbeef.pending"), "/p/half\n", UTF_8)
    assertEquals(buildDirectories(session.directory), Vector(hash -> Path.of("/p/sub")))
    remove(session)

  test("the other live brokers' sessions are the locked ones under the broker prefix"):
    val root = freshRoot()
    val mine = publish(root, Path.of("/p"), Kind.Broker).toOption.get
    val other = publish(root, Path.of("/p"), Kind.Broker).toOption.get
    val command = publish(root, Path.of("/p")).toOption.get
    val dead = publish(root, Path.of("/p"), Kind.Broker).toOption.get
    dead.close()
    assertEquals(liveBrokerSessions(root, mine.directory), Vector(other.directory))
    remove(mine); remove(other); remove(command); remove(dead)

  test("a spawn lives while its leader matches the record and no exit is published"):
    val root = freshRoot()
    val record = root.resolve("r")
    Files.writeString(record, renderRecord(Record(7, "START-A")), UTF_8)
    assert(spawnLives(record, processes(7L -> "START-A")))
    assert(!spawnLives(record, processes(7L -> "RECYCLED")))
    assert(!spawnLives(record, processes()))
    Files.writeString(exitRecord(record), "0\n", UTF_8)
    assert(!spawnLives(record, processes(7L -> "START-A")))
    assert(!spawnLives(root.resolve("absent"), processes(7L -> "START-A")))

  test("a dead broker session's records are ended like a command's"):
    val root = freshRoot()
    val session = publish(root, Path.of("/p"), Kind.Broker).toOption.get
    for (name, pid) <- Seq("proxy-sbt-abc" -> 21L, "server-sbt-abc" -> 22L, "daemon-mill-def" -> 23L) do
      Files.writeString(session.records.resolve(name), renderRecord(Record(pid, s"START-$pid")), UTF_8)
    val dead = die(session)
    val fakes = processes(21L -> "START-21", 22L -> "START-22", 23L -> "START-23")
    scavenge(root, fakes, _ => ServerAnswer.ShutDown)
    assertEquals(fakes.ended.toList.sorted, List(21L, 22L, 23L))
    assert(!Files.exists(dead))

  test("a dead command session beside a live broker session is collected alone"):
    val root = freshRoot()
    val broker = publish(root, Path.of("/p"), Kind.Broker).toOption.get
    Files.writeString(broker.records.resolve("server-sbt-abc"), renderRecord(Record(31, "START-31")), UTF_8)
    val command = publish(root, Path.of("/p")).toOption.get
    Files.writeString(command.records.resolve("client"), renderRecord(Record(32, "START-32")), UTF_8)
    val dead = die(command)
    val fakes = processes(31L -> "START-31", 32L -> "START-32")
    scavenge(root, fakes, _ => ServerAnswer.ShutDown)
    assertEquals(fakes.ended.toList, List(32L), "the broker's live session keeps its records")
    assert(!Files.exists(dead))
    assert(Files.isDirectory(broker.directory))
    remove(broker)

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

    // Its leader still proven, the next collection signals again; this time the group empties.
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

    // The KILL took the leader and left a member: the pgid is no longer provable, so nothing is
    // signalled, and the member may still be the record's, so nothing is deleted.
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

  test("a ps listing proves itself by this process; without it nothing is observed"):
    import HostProcesses.{groupEmptyFrom, startFrom}
    val start = "Mon Sep 14 10:00:00 2026"
    assertEquals(startFrom(Vector(s"41 $start", "40 Sun Sep 13 09:00:00 2026"), 40, 41), Some(start))
    assertEquals(startFrom(Vector("40 Sun Sep 13 09:00:00 2026"), 40, 41), None, "not listed: no such process")
    // What Apple's ps prints when its process-table sysctl fails, and when nothing is selected.
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
    // A file where the condemned directory would be: the rename fails, and the fallback ends the
    // recorded groups in place.
    Files.writeString(root.resolve(CondemnedDir), "", UTF_8)

    class Survivors(alive: Map[Long, String]) extends FakeProcesses(alive):
      override def endGroup(pgid: Long): Boolean = { ended += pgid; false }
    val survivors = Survivors(Map(7L -> "START-A"))
    val kept = endSession(root, session, survivors, _ => ServerAnswer.ShutDown)
    assertEquals(kept.collect { case Collected.GroupAlive(g, _) => g }, Vector(7L))
    assert(Files.exists(session.records.resolve("client")), "the record is kept where it was")

    // The lock released, the next scavenge condemns the directory and retries.
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

  test("a session being ended by its wrapper is left alone by a concurrent scavenger"):
    val root = freshRoot()
    val project = Files.createTempDirectory("proj")
    val session = publish(root, project).toOption.get
    val socket = session.tmp.resolve("sock")
    Files.createFile(socket)
    Files.createDirectories(project.resolve("project/target"))
    Files.writeString(
      project.resolve("project/target/active.json"),
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
    val project = Files.createTempDirectory("proj")
    val session = publish(root, project).toOption.get
    val dead = die(session)
    val socket = socketUnder(dead)
    // The socket exists on disk like a real server's; containment canonicalizes it. Only inside
    // the session — a foreign spelling stays a spelling.
    if socket.normalize.startsWith(dead) then
      Files.createDirectories(socket.getParent)
      Files.createFile(socket)
    Files.createDirectories(project.resolve("project/target"))
    Files.writeString(
      project.resolve("project/target/active.json"),
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

  test("a dead broker session's servers are collected by the build files, one portfile each"):
    val root = freshRoot()
    val session = publish(root, Path.of("/p"), Kind.Broker).toOption.get
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
    val project = Files.createTempDirectory("proj")
    val session = publish(root, project).toOption.get
    Files.writeString(session.records.resolve("client"), renderRecord(Record(4, "START-D")), UTF_8)
    val socket = session.tmp.resolve("sock")
    Files.createFile(socket)
    Files.createDirectories(project.resolve("project/target"))
    Files.writeString(
      project.resolve("project/target/active.json"),
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
  // The registered spawn, against real processes
  // --------------------------------------------------------------------------

  def notUnderRunOnHostProfile(): Unit =
    assume(!RunOnHostSessionTest.underRunOnHostProfile, "the registration spawn never runs under the profile")

  test("a spawned process registers pgid and start time by rename before its command runs"):
    notUnderRunOnHostProfile()
    val dir = Files.createTempDirectory("spawn")
    val record = dir.resolve("record")
    val command = registeredSpawn(record, Seq("/bin/sleep", "30"))
    val process = java.lang.ProcessBuilder(command*).start()
    try
      val deadline = System.nanoTime + 10_000_000_000L
      while !Files.exists(record) && System.nanoTime < deadline do Thread.sleep(20)
      val parsed = parseRecord(Files.readString(record, UTF_8))
      assert(parsed.isDefined, "the record was published")
      assertEquals(parsed.get.pgid, process.pid, "the spawn is the leader it registers")
      assertEquals(HostProcesses.startOf(process.pid), Some(parsed.get.leaderStart))
    finally process.destroyForcibly().waitFor()

  test("the command's exit status is published beside the record, and the leader stays"):
    notUnderRunOnHostProfile()
    val record = Files.createTempDirectory("spawn").resolve("record")
    val process =
      java.lang.ProcessBuilder(registeredSpawn(record, Seq("/bin/sh", "-c", "exit 7"))*).start()
    try
      assertEquals(awaitExit(exitRecord(record), process), Right(7))
      assert(process.isAlive, "the leader outlives its command, keeping the group provable")
    finally process.destroyForcibly().waitFor()

  test("a command's signal death is published as the shell's 128+signal"):
    notUnderRunOnHostProfile()
    val record = Files.createTempDirectory("spawn").resolve("record")
    val process = java.lang.ProcessBuilder(
      registeredSpawn(record, Seq("/bin/sh", "-c", "kill -KILL $$"))*).start()
    try assertEquals(awaitExit(exitRecord(record), process), Right(137))
    finally process.destroyForcibly().waitFor()

  test("a spawn gone without an exit status is a Left, not a hang"):
    notUnderRunOnHostProfile()
    val record = Files.createTempDirectory("spawn").resolve("record")
    val process =
      java.lang.ProcessBuilder(registeredSpawn(record, Seq("/bin/sleep", "30"))*).start()
    process.destroyForcibly().waitFor()
    assert(awaitExit(exitRecord(record), process).isLeft)

  test("a spawned process whose record cannot be published ends itself with 71"):
    notUnderRunOnHostProfile()
    val gone = Files.createTempDirectory("spawn").resolve("condemned-away/record")
    val process =
      java.lang.ProcessBuilder(registeredSpawn(gone, Seq("/bin/sleep", "30"))*).start()
    assertEquals(process.waitFor(), 71)

  test("the build lock admits one retirer at a time: a retirement's validate-and-signal never overlaps another"):
    // A cancelled command's server is retired under the directory's build lock (RunOnHostChannel);
    // a peer's takeover ends the same recorded group under the same lock (noForeignServer). The
    // lock is what keeps the two from interleaving endRecordedGroup's identity check and its
    // signal, so the pid cannot be recycled between them. Two under-broker holders of one lock:
    // the second reports the lock only once the first has released, so their critical sections —
    // where the retirement runs — never overlap.
    notUnderRunOnHostProfile()
    val lockFile = Files.createTempDirectory("retire-lock").resolve("sbt-x")
    def helper(): (Process, java.io.BufferedReader) =
      val process = java.lang.ProcessBuilder(lockedSpawn(lockFile, Seq("/bin/true"), underBroker = true)*).start()
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

  test("a locked spawn holds the build lock for its life, and the next taker runs once it is gone"):
    notUnderRunOnHostProfile()
    val lockFile = Files.createTempDirectory("lock").resolve("sbt-x")
    val holder =
      java.lang.ProcessBuilder(lockedSpawn(lockFile, Seq("/bin/sleep", "30"), underBroker = false)*).start()
    try
      // The holder takes the lock at its own pace: a taker started too early runs at once, so
      // takers are started until one reports the wait — and then is still alive, blocked. One
      // line, not the stream: a blocked taker holds its stderr open until it exits.
      def taker() = java.lang.ProcessBuilder(
        lockedSpawn(lockFile, Seq("/bin/sh", "-c", "exit 7"), underBroker = false)*).start()
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
      // A taker dispatched by a broker: its stdin's EOF is the broker gone, and it ends itself.
      val orphan = java.lang.ProcessBuilder(
        lockedSpawn(lockFile, Seq("/bin/sh", "-c", "exit 7"), underBroker = true)*).start()
      java.io.BufferedReader(java.io.InputStreamReader(orphan.getErrorStream, UTF_8)).readLine()
      orphan.getOutputStream.close()
      assert(orphan.waitFor(10, java.util.concurrent.TimeUnit.SECONDS), "the pipe's EOF ends the wait")
      assertEquals(orphan.exitValue, 71)
      assert(holder.isAlive)
      holder.destroyForcibly().waitFor()
      assert(blocked.waitFor(10, java.util.concurrent.TimeUnit.SECONDS), "the holder's death frees the lock")
      assertEquals(blocked.exitValue, 7)
    finally holder.destroyForcibly().waitFor()

  test("a locked spawn under the broker reports the lock, then execs on the word, refuses on it, or ends at EOF"):
    notUnderRunOnHostProfile()
    val lockFile = Files.createTempDirectory("lock").resolve("sbt-x")
    def spawn(command: String*): (Process, java.io.BufferedReader) =
      val process = java.lang.ProcessBuilder(lockedSpawn(lockFile, command, underBroker = true)*).start()
      val out = java.io.BufferedReader(java.io.InputStreamReader(process.getInputStream, UTF_8))
      assertEquals(out.readLine(), LockedLine)
      (process, out)
    def answer(process: Process, word: String): Unit =
      process.getOutputStream.write(word.getBytes(UTF_8))
      process.getOutputStream.flush()
    // The word's arguments go before the command's `--`, whatever follows it.
    val (run, out) = spawn("/bin/sh", "-c", "printf '%s\\n' \"$@\"", "sh", "--", "-x")
    answer(run, runWord(Seq("--proxy-port=1", "--proxy-log=/l")))
    assertEquals(out.readLine(), "--proxy-port=1")
    assertEquals(out.readLine(), "--proxy-log=/l")
    assertEquals(out.readLine(), "--")
    assertEquals(out.readLine(), "-x")
    assertEquals(run.waitFor(), 0)
    // An argument holding a newline, the escape byte or a NUL arrives whole: the word is one line.
    val (odd, oddOut) = spawn("/bin/sh", "-c", "printf '%s|' \"$@\" | od -An -c | tr -s ' \\n' ' '", "sh")
    answer(odd, runWord(Seq("a\nb", "\u0001x", "c")))
    assertEquals(oddOut.readLine().trim, "a \\n b | 001 x | c |")
    assertEquals(odd.waitFor(), 0)
    // The pipe stays the exec'd command's stdin, its EOF still the broker gone.
    val (held, _) = spawn("/bin/sh", "-c", "cat")
    answer(held, runWord(Seq.empty))
    assert(
      !held.waitFor(500, java.util.concurrent.TimeUnit.MILLISECONDS),
      "the command's stdin is the pipe, still open",
    )
    held.getOutputStream.close()
    assertEquals(held.waitFor(), 0)
    // A refusal of several lines — a server's output quoted — reaches stderr whole.
    val (refused, _) = spawn("/bin/sh", "-c", "exit 0")
    answer(refused, refusedWord("refused: no runtime; its output:\n[error] line one\n[error] line two\n"))
    assertEquals(
      String(refused.getErrorStream.readAllBytes(), UTF_8),
      "refused: no runtime; its output:\n[error] line one\n[error] line two\n\n",
    )
    assertEquals(refused.waitFor(), 2)
    val (orphan, _) = spawn("/bin/sh", "-c", "exit 0")
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
    val result = SbtServerShutdown.shutdown(socket, deadlineMillis = 10_000)
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
    val result = SbtServerShutdown.shutdown(socket, deadlineMillis = 500)
    assert(result.isInstanceOf[ServerAnswer.Unanswered], clue = result)
    thread.join(10_000)

  test("an absent socket is Unreachable: there is no server to stop"):
    val result = SbtServerShutdown.shutdown(Path.of("/no/such/sock"), deadlineMillis = 500)
    assert(result.isInstanceOf[ServerAnswer.Unreachable], clue = result)

  test("a socket file whose listener is gone is Unreachable: the connect is refused"):
    val socket = shortSocketPath()
    val server = ServerSocketChannel.open(StandardProtocolFamily.UNIX)
    server.bind(UnixDomainSocketAddress.of(socket))
    server.close() // the file stays; nothing listens
    val result = SbtServerShutdown.shutdown(socket, deadlineMillis = 500)
    assert(result.isInstanceOf[ServerAnswer.Unreachable], clue = result)

  test("a connect failure that is no refusal stays retryable: a live server may hide behind it"):
    import java.nio.file.attribute.PosixFilePermissions
    val dir = Files.createTempDirectory("deny")
    val socket = dir.resolve("s")
    val server = ServerSocketChannel.open(StandardProtocolFamily.UNIX)
    server.bind(UnixDomainSocketAddress.of(socket))
    try
      Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("---------"))
      val result = SbtServerShutdown.shutdown(socket, deadlineMillis = 500)
      assert(result.isInstanceOf[ServerAnswer.Unanswered], clue = result)
    finally
      Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"))
      server.close()

  private def frame(json: String): Array[Byte] = SbtServerShutdown.frame(json)

  private def shortSocketPath(): Path =
    // sun_path is short on Linux too; keep the whole path well under it.
    Files.createTempDirectory("sk").resolve("s")

  private def listNames(path: Path): Vector[String] =
    if !Files.isDirectory(path) then Vector.empty
    else FileHelper.directoryEntries(path).map(_.getFileName.toString).sorted
