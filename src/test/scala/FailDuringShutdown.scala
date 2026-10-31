// Stages the launcher's Ctrl-C race: a shutdown hook is already running while the main thread goes on
// to refuse. HostCommandsTest runs this program in a JVM of its own, because the test cannot start a
// shutdown in the test's own JVM.

package agentsandbox.launcher

import java.util.concurrent.CountDownLatch

object FailDuringShutdown:
  def main(args: Array[String]): Unit =
    val mainThread = Thread.currentThread
    val hookStarted = CountDownLatch(1)
    Runtime.getRuntime.addShutdownHook(Thread(() =>
      hookStarted.countDown()
      // The hook waits until the main thread blocks in its own exit, on the shutdown's monitor. The
      // test then observes the ordering instead of timing it, and this wait is the contract under
      // test. The wait is bounded, so a regression fails the assertion instead of hanging the JVM.
      val deadline = System.nanoTime() + 10_000_000_000L
      while mainThread.getState != Thread.State.BLOCKED && System.nanoTime() < deadline do Thread.sleep(10)
      System.err.println(
        if mainThread.getState == Thread.State.BLOCKED then "hook: removed" else "hook: the refusal never blocked",
      ),
    ))
    // `initiate` is a method rather than a lambda, because a lambda that returns Nothing links as no Runnable.
    def initiate(): Unit = sys.exit(130)
    Thread(() => initiate()).start()
    hookStarted.await()
    HostCommands.fail("error: podman failed\nits stderr")
