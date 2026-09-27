// An inBackground step asked for once a shutdown has begun, or whose shutdown hook runs between its
// registration and the step's start. HostCommandsTest runs it in a JVM of its own, since a shutdown
// cannot be started in the test's.

package agentsandbox.launcher

import java.util.concurrent.{CountDownLatch, TimeUnit}

object BackgroundStepDuringShutdown:
  def main(args: Array[String]): Unit =
    val mainThread = Thread.currentThread
    val asked = CountDownLatch(1)
    // Holds the shutdown open until the main thread is blocked on the step, so the JVM ends only
    // once the step has had every chance to start: a step cut off then loses its last line.
    // Bounded, so a regression fails the assertion instead of hanging the JVM.
    Runtime.getRuntime.addShutdownHook(Thread(() =>
      asked.await(10, TimeUnit.SECONDS)
      val deadline = System.nanoTime() + 10_000_000_000L
      while mainThread.getState == Thread.State.RUNNABLE && System.nanoTime() < deadline do Thread.sleep(10),
    ))
    // A method rather than a lambda: a lambda returning Nothing links as no Runnable.
    def initiate(): Unit = sys.exit(3)
    val register: Thread => Unit = args.headOption match
      // The hook is refused: the shutdown began before the step was asked for.
      case Some("begun") =>
        Thread(() => initiate()).start()
        while !HostCommands.shuttingDown do Thread.sleep(1)
        Runtime.getRuntime.addShutdownHook(_)
      // The hook is taken, and has run to its end by the time the step would start.
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
