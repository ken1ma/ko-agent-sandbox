// The launcher's Ctrl-C race, staged: a shutdown hook already running while the main thread goes on
// to refuse. HostCommandsTest runs it in a JVM of its own, since a shutdown cannot be started in
// the test's.

package agentsandbox.launcher

import java.util.concurrent.CountDownLatch

object FailDuringShutdown:
  def main(args: Array[String]): Unit =
    val mainThread = Thread.currentThread
    val hookStarted = CountDownLatch(1)
    Runtime.getRuntime.addShutdownHook(Thread(() =>
      hookStarted.countDown()
      // Held until the main thread is blocked in its own exit, on the shutdown's monitor: the
      // ordering is then observed, not timed, and the wait is the contract under test. Bounded, so
      // a regression fails the assertion instead of hanging the JVM.
      val deadline = System.nanoTime() + 10_000_000_000L
      while mainThread.getState != Thread.State.BLOCKED && System.nanoTime() < deadline do Thread.sleep(10)
      System.err.println(
        if mainThread.getState == Thread.State.BLOCKED then "hook: removed" else "hook: the refusal never blocked",
      ),
    ))
    // A method rather than a lambda: a lambda returning Nothing links as no Runnable.
    def initiate(): Unit = sys.exit(130)
    Thread(() => initiate()).start()
    hookStarted.await()
    HostCommands.fail("error: podman failed\nits stderr")
