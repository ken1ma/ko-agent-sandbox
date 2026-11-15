package koreview

import io.circe.JsonObject
import java.nio.file.{Files, Path}
import java.util.concurrent.{CountDownLatch, TimeUnit}
import scala.collection.mutable
import scala.concurrent.duration.Duration

/** The cases of a turn's cleanup that a fake reviewer cannot force: a timer, a reap and a reader that fail or pause at
  * a chosen moment. */
class ReviewerProcessTest extends munit.FunSuite:

  override val munitTimeout: Duration = Duration(2, "min")

  private val temporary = FunFixture[Path](
    _ => Files.createTempDirectory("ko-review-process-"),
    directory => HelperFixture.deleteTree(directory),
  )

  /** A process control that records the groups it signals. */
  private final class Recorded(
      startTimer: (Long, () => Unit) => TurnTimer = ReviewerProcess.sleepingTimer,
      reapProcess: Process => Unit = ReviewerProcess.reapUninterruptibly,
  ):
    val signalled: mutable.Buffer[Long] = mutable.ArrayBuffer.empty[Long]
    val processes = ReviewerProcess(
      HelperFixture.JavaCommand,
      signalGroup = pgid => signalled.synchronized:
        signalled += pgid
        Posix.killGroup(pgid, Posix.SIGKILL): Unit
      ,
      startTimer = startTimer,
      reapProcess = reapProcess,
    )

    def group(command: String*): (Process, Process) =
      val leader = processes.startLeader()
      val reviewer = processes.startReviewer(leader, command, Path.of("").toAbsolutePath, sys.env,
        Files.createTempFile("ko-review-stderr-", ".txt"))
      (leader, reviewer)

  private def noThread(event: JsonObject): Option[String] = None

  temporary.test("a timeout firing as the reviewer exits signals the group once, before the leader is reaped"): dir =>
    // A timer action that started before its cancellation is paused until the reviewer has exited and the cleanup
    // runs. The action must still find the leader unreaped, and the cleanup must not signal the group again.
    val released = CountDownLatch(1)
    val leaderUnreapedAtAction = mutable.ArrayBuffer.empty[Boolean]
    var leader: Process = null
    val recorded = Recorded(startTimer = (_, action) =>
      val thread = Thread.ofPlatform().start: () =>
        released.await(10, TimeUnit.SECONDS)
        leaderUnreapedAtAction += leader.isAlive
        action()
      new TurnTimer:
        def cancel(): Unit = () // too late: the action has started
        def join(): Unit = thread.join()
    )
    val (groupLeader, reviewer) = recorded.group("sleep", "0")
    leader = groupLeader
    Thread.ofVirtual().start: () =>
      Thread.sleep(500) // long after a cleanup that does not wait would have reaped
      released.countDown()
    val streamed = recorded.processes.stream(reviewer, leader, Array.emptyByteArray, 3600, dir.resolve("events"),
      noThread, _ => ())
    assertEquals((streamed.events, streamed.threadId, streamed.badLine, streamed.timedOut),
      (Vector.empty, None, None, true))
    assertEquals(leaderUnreapedAtAction.toVector, Vector(true))
    assertEquals(recorded.signalled.toVector, Vector(leader.pid()))
    assert(!leader.isAlive)

  temporary.test("an interrupt after the leader is reaped does not signal the group again"): dir =>
    // The cleanup that the failure repeats must not signal the group, whose id the reaping freed.
    var leader: Process = null
    var interrupted = false
    val recorded = Recorded(reapProcess = process =>
      ReviewerProcess.reapUninterruptibly(process)
      if process eq leader then
        if !interrupted then
          interrupted = true
          throw InterruptedException()
    )
    val (groupLeader, reviewer) = recorded.group("sleep", "0")
    leader = groupLeader
    // munit's intercept leaves an InterruptedException uncaught, as a fatal one.
    val raised =
      try
        recorded.processes.stream(reviewer, leader, Array.emptyByteArray, 3600, dir.resolve("events"), noThread,
          _ => ())
        false
      catch case _: InterruptedException => true
    assert(raised, "the interrupt propagates")
    assertEquals(recorded.signalled.toVector, Vector(leader.pid()))
    assert(!leader.isAlive)

  temporary.test("a failure in the reader kills the running reviewer and fails the turn"): dir =>
    // The reader's exception, here from recording the thread id, ends the turn at once and propagates, rather than
    // being lost while the turn waits for the reviewer.
    val recorded = Recorded()
    val (leader, reviewer) = recorded.group("sh", "-c", """echo '{"thread_id": "t"}'; sleep 30""")
    val failure = intercept[java.io.IOException]:
      recorded.processes.stream(reviewer, leader, Array.emptyByteArray, 3600, dir.resolve("events"),
        _("thread_id").flatMap(_.asString), _ => throw java.io.IOException("no space left on device"))
    assertEquals(failure.getMessage, "no space left on device")
    assertEquals(recorded.signalled.toVector, Vector(leader.pid()))
    assert(!reviewer.isAlive && reviewer.exitValue() != 0, "the reviewer was killed, not left to its sleep")
    assert(!leader.isAlive)

  temporary.test("a failure of the turn while the reviewer runs kills it before the turn ends"): dir =>
    // The events file cannot be opened once the reviewer has started.
    val recorded = Recorded()
    val done = dir.resolve("ran-to-the-end")
    val (leader, reviewer) = recorded.group("sh", "-c", s"sleep 2; echo done > '$done'")
    val events = Files.createDirectory(dir.resolve("events"))
    intercept[java.io.IOException]:
      recorded.processes.stream(reviewer, leader, Array.emptyByteArray, 3600, events, noThread, _ => ())
    assert(!reviewer.isAlive && !leader.isAlive)
    Thread.sleep(3000) // past the reviewer's sleep: left running, it would have written
    assert(!Files.exists(done), "the reviewer outlived the turn")

  temporary.test("a child whose command name is not UTF-8 is listed"): dir =>
    assume(Posix.isLinux, "reads /proc, on Linux")
    // The kernel names a process after its program's file, here bytes 0xff 0xfe, which are not UTF-8.
    val child = ProcessBuilder("sh", "-c", """p=$(printf '%s/\377\376' "$1"); cp /bin/sleep "$p"; exec "$p" 30""", "sh",
      dir.toString).start()
    try
      val comm = Path.of(s"/proc/${child.pid()}/comm")
      val deadline = System.nanoTime() + 5_000_000_000L
      while !(Files.exists(comm) && Files.readAllBytes(comm).headOption.contains(0xff.toByte)) &&
          System.nanoTime() < deadline do Thread.sleep(50)
      assertEquals(Files.readAllBytes(comm).headOption, Some(0xff.toByte))
      assert(Posix.childrenOf(ProcessHandle.current().pid()).contains(child.pid()))
    finally child.destroyForcibly().waitFor(): Unit
