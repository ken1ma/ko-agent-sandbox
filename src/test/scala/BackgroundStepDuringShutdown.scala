// Stages an inBackground step that is asked for after a shutdown has begun, or whose shutdown hook runs
// between the hook's registration and the step's start. HostCommandsTest runs this program in a JVM of
// its own, because the test cannot start a shutdown in the test's own JVM.

package agentsandbox.launcher

import java.util.concurrent.{CountDownLatch, TimeUnit}

object BackgroundStepDuringShutdown:
  def main(args: Array[String]): Unit =
    val mainThread = Thread.currentThread
    val asked = CountDownLatch(1)
    // The hook holds the shutdown open until the main thread blocks on the step. The JVM then ends
    // only after the step has had every chance to start, so a step that the shutdown cuts off loses
    // its last line. The wait is bounded, so a regression fails the assertion instead of hanging the JVM.
    Runtime.getRuntime.addShutdownHook(Thread(() =>
      asked.await(10, TimeUnit.SECONDS)
      val deadline = System.nanoTime() + 10_000_000_000L
      while mainThread.getState == Thread.State.RUNNABLE && System.nanoTime() < deadline do Thread.sleep(10),
    ))
    // `initiate` is a method rather than a lambda, because a lambda that returns Nothing links as no Runnable.
    def initiate(): Unit = sys.exit(3)
    val register: Thread => Unit = args.headOption match
      // The shutdown began before the step was asked for, so the hook is refused.
      case Some("begun") =>
        Thread(() => initiate()).start()
        while !HostCommands.shuttingDown do Thread.sleep(1)
        Runtime.getRuntime.addShutdownHook(_)
      // The hook is registered, and the hook has run to its end by the time the step would start.
      case _ =>
        settle =>
          val settled = CountDownLatch(1)
          Runtime.getRuntime.addShutdownHook(Thread(() =>
            settle.run()
            settled.countDown(),
          ))
          Thread(() => initiate()).start()
          settled.await()
    val step = HostCommands.inBackground("step", register):
      System.err.println("step: started")
      Thread.sleep(500)
      System.err.println("step: finished")
    asked.countDown()
    step()
