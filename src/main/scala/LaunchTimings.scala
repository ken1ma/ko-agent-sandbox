// How long each part of a launch took: the run's `launch.log`, written just before the handover to podman.
// - The terminal shows nothing during a slow podman call or a lock wait, so the log is where a slow launch shows which
//   part it was.
// - The log ends with the handover's wall-clock time. Inside the session, the start times of the container's first
//   processes (/proc/1/stat and /proc/2/stat, in clock ticks since the machine's boot) continue the timeline.
// - A refused launch exits before the handover and writes no log.
// - Steps run in the background beside the main thread's (inBackground, ResourceSteps), so each line says when its part
//   began, and the lines come in the order the parts ended.

package agentsandbox.launcher

import java.nio.file.Path
import java.time.Instant

final class LaunchTimings:
  private val startNanos = System.nanoTime()
  private val lines = Vector.newBuilder[String]

  def since(what: String, partStart: Long): Unit =
    val line = s"$what: ${millis(partStart, System.nanoTime())}ms, from ${millis(startNanos, partStart)}ms"
    synchronized(lines += line)

  private def millis(from: Long, to: Long): Long = (to - from) / 1_000_000

  def timed[A](what: String)(body: => A): A =
    val start = System.nanoTime()
    try body
    finally since(what, start)

  /** The parts as they ended, then the whole launch, the start prompt's wait included, and the handover's time. */
  def text(handover: Instant): String =
    val whole = s"the launch until the handover: ${millis(startNanos, System.nanoTime())}ms"
    val parts = synchronized(lines.result())
    (parts ++ Vector(whole, s"handed over to podman start at $handover")).mkString("", "\n", "\n")

  /** A failed write loses only the log. */
  def write(file: Path, handover: Instant): Unit =
    try FileHelper.writePrivate(file, text(handover))
    catch case _: java.io.IOException => ()
