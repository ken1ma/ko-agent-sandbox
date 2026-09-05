package agentsandbox.launcher

import java.net.{StandardProtocolFamily, UnixDomainSocketAddress}
import java.nio.ByteBuffer
import java.nio.channels.ServerSocketChannel
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path}

import scala.collection.mutable.ListBuffer
import scala.jdk.CollectionConverters.*

import RunOnHostSession.*

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

  test("ensureRoot creates an absent root owner-only"):
    val parent = Files.createTempDirectory("build-session")
    val root = parent.resolve("ko-agent-0")
    assertEquals(ensureRoot(root, uid), Right(root))
    assertEquals(
      java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(root)),
      "rwx------",
    )

  test("ensureRoot refuses a symlinked, shared, or foreign root"):
    val parent = Files.createTempDirectory("build-session")
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
    val root = Files.createTempDirectory("build-session").toRealPath().resolve("root")
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

  // --------------------------------------------------------------------------
  // Scavenging the dead
  // --------------------------------------------------------------------------

  class FakeProcesses(alive: Map[Long, String]) extends Processes:
    val ended = ListBuffer[Long]()
    def startOf(pid: Long): Option[String] = alive.get(pid)
    def endGroup(pgid: Long): Unit = ended += pgid

  def processes(alive: (Long, String)*): FakeProcesses = FakeProcesses(alive.toMap)

  def die(session: Session): Path =
    // A SIGKILLed wrapper: the lock is freed, the directory and records stay.
    session.close()
    session.directory

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

  test("a condemned entry without its lock is deletion residue: removed, nothing signalled"):
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

  test("staging litter is cleared, published live sessions are not"):
    val root = freshRoot()
    val live = publish(root, Path.of("/p")).toOption.get
    val litter = Files.createDirectories(root.resolve(StagingDir).resolve("s-half-made"))
    Files.writeString(litter.resolve("junk"), "x", UTF_8)
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

  test("a portfile naming someone else's socket is not this session's to end"):
    val root = freshRoot()
    val (_, _) = deadSessionWithServer(root, _ => Path.of("/somewhere/else/sock"))
    val spoken = ListBuffer[Path]()
    val results = scavenge(root, processes(), path => { spoken += path; ServerAnswer.ShutDown })
    assertEquals(spoken.toList, Nil)
    val skips = results.flatMap(_(1)).collect { case Collected.ServerSkipped(reason) => reason }
    assert(skips.exists(_.contains("not this session's")), clue = skips)

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

  // The registration spawn is the wrapper's tool and runs outside the profile by construction;
  // under it, perl dies before registering. Skipped exactly where the gate runs this suite as a
  // confined build.
  def notUnderBuildProfile(): Unit =
    assume(
      !sys.env.get("SBT_GLOBAL_SERVER_DIR").exists(_.startsWith("/private/tmp/ko-agent-")),
      "the registration spawn never runs under the profile",
    )

  test("a spawned process registers pgid and start time by rename before its command runs"):
    notUnderBuildProfile()
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
    notUnderBuildProfile()
    val record = Files.createTempDirectory("spawn").resolve("record")
    val process =
      java.lang.ProcessBuilder(registeredSpawn(record, Seq("/bin/sh", "-c", "exit 7"))*).start()
    try
      assertEquals(awaitExit(exitRecord(record), process), Right(7))
      assert(process.isAlive, "the leader outlives its command, keeping the group provable")
    finally process.destroyForcibly().waitFor()

  test("a command's signal death is published as the shell's 128+signal"):
    notUnderBuildProfile()
    val record = Files.createTempDirectory("spawn").resolve("record")
    val process = java.lang.ProcessBuilder(
      registeredSpawn(record, Seq("/bin/sh", "-c", "kill -KILL $$"))*).start()
    try assertEquals(awaitExit(exitRecord(record), process), Right(137))
    finally process.destroyForcibly().waitFor()

  test("a spawn gone without an exit status is a Left, not a hang"):
    notUnderBuildProfile()
    val record = Files.createTempDirectory("spawn").resolve("record")
    val process =
      java.lang.ProcessBuilder(registeredSpawn(record, Seq("/bin/sleep", "30"))*).start()
    process.destroyForcibly().waitFor()
    assert(awaitExit(exitRecord(record), process).isLeft)

  test("a spawned process whose record cannot be published ends itself with 71"):
    notUnderBuildProfile()
    val gone = Files.createTempDirectory("spawn").resolve("condemned-away/record")
    val process =
      java.lang.ProcessBuilder(registeredSpawn(gone, Seq("/bin/sleep", "30"))*).start()
    assertEquals(process.waitFor(), 71)

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

  test("an absent socket is Unreachable: nothing lives behind it"):
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
    else
      val stream = Files.list(path)
      try stream.iterator.asScala.map(_.getFileName.toString).toVector.sorted
      finally stream.close()
