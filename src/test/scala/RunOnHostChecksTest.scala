package agentsandbox.launcher

import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicBoolean

import RunOnHostChecks.*

class RunOnHostChecksTest extends munit.FunSuite:

  private def checkRun(): CheckRun =
    val out = Files.createTempDirectory("checks")
    val host = HostPaths(out, out, out, out, out, out)
    CheckRun(HostDriver.Transcript(out.resolve("transcript.log")), Checkout(out), out, Program.values.toSet, host)

  test("inParallel returns only once every group has ended, and a failing group reports a FAIL of its own"):
    val run = checkRun()
    val failed = CountDownLatch(1)
    val finished = AtomicBoolean(false)
    run.inParallel(
      Seq(
        "failing" -> (_ =>
          failed.countDown()
          throw IllegalStateException("staged failure")),
        "running" -> (_ =>
          // The other group is still at work after the first one fails.
          failed.await()
          Thread.sleep(300)
          finished.set(true)),
      ),
      jobs = 2,
    )
    assert(finished.get, "inParallel returned before the running group ended")
    assertEquals(run.transcript.failed, 1)
    assert(Files.readString(run.out.resolve("failing.log")).contains("staged failure"))

  test("a timed-out row fails, whether it expects a denial or a grant"):
    val run = checkRun()
    run.reportDenied("denied row", ProfileOutcome(ok = false, timedOut = true, firstError = ""))
    run.reportAllowed("allowed row", ProfileOutcome(ok = false, timedOut = true, firstError = ""))
    run.reportDenied("a real denial", ProfileOutcome(ok = false, timedOut = false, firstError = "denied"))
    assertEquals((run.transcript.passed, run.transcript.failed), (1, 2))

  test("an Error a group throws is a FAIL row too, and the other groups end first"):
    val run = checkRun()
    val finished = AtomicBoolean(false)
    run.inParallel(
      Seq(
        "erring" -> (_ => throw AssertionError("staged error")),
        "running" -> (_ => { Thread.sleep(200); finished.set(true) }),
      ),
      jobs = 2,
    )
    assert(finished.get)
    assertEquals(run.transcript.failed, 1)
    assert(Files.readString(run.out.resolve("erring.log")).contains("staged error"))

  test("observed waits for a connection whose accept is still held back, and counts its bytes"):
    // A short name keeps the socket's path within macOS's 104 bytes, also under the per-user temporary directory.
    val dir = Files.createTempDirectory("l")
    val listener = CountingListener(dir.resolve("s"), acceptDelayMillis = 500)
    try
      scala.util.Using.resource(java.nio.channels.SocketChannel.open(
        java.net.UnixDomainSocketAddress.of(dir.resolve("s"))))(_.write(java.nio.ByteBuffer.wrap("control".getBytes)))
      assert(listener.observed(1), "the held-back connection was never read")
      assertEquals((listener.connects, listener.bytes, listener.failure), (1, 7, None))
    finally
      listener.close()
      Files.deleteIfExists(dir.resolve("s"))
      Files.delete(dir)
