// Stages a refusal on the main thread while an inBackground step still runs. HostCommandsTest runs
// this program in a JVM of its own, because the refusal exits the JVM.

package agentsandbox.launcher

import java.util.concurrent.CountDownLatch

object RefuseDuringBackgroundStep:
  def main(args: Array[String]): Unit =
    val stepStarted = CountDownLatch(1)
    HostCommands.inBackground("step"):
      stepStarted.countDown()
      // The step sleeps longer than an exit that does not wait for it takes, so a regression loses this line.
      Thread.sleep(500)
      System.err.println("step: finished")
    stepStarted.await()
    HostCommands.fail("error: refused")
