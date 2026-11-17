// Tests the run's launch.log: the parts as they ended, the whole launch, and the handover's time.

package agentsandbox.launcher

import java.nio.file.Files
import java.time.Instant

class LaunchTimingsTest extends munit.FunSuite:
  test("the log lists each part as it ended, with when it began, then the whole launch and the handover's time"):
    val timings = LaunchTimings()
    timings.since("waited for the launch lock", System.nanoTime())
    assertEquals(timings.timed("created the container")(42), 42, "a timed body's value passes through")
    val lines = timings.text(Instant.parse("2026-11-17T04:46:03.512Z")).linesIterator.toVector
    assertEquals(lines.size, 4, lines)
    assert(lines(0).matches("waited for the launch lock: \\d+ms, from \\d+ms"), lines)
    assert(lines(1).matches("created the container: \\d+ms, from \\d+ms"), lines)
    assert(lines(2).matches("the launch until the handover: \\d+ms"), lines)
    assertEquals(lines(3), "handed over to podman start at 2026-11-17T04:46:03.512Z")

  test("a part that throws is still timed"):
    val timings = LaunchTimings()
    intercept[IllegalStateException](timings.timed("ran the launch script")(throw IllegalStateException("refused")))
    assert(timings.text(Instant.EPOCH).startsWith("ran the launch script: "))

  test("parts that end on other threads each get their line"):
    val timings = LaunchTimings()
    val threads = (1 to 8).map(i => Thread.startVirtualThread(() => timings.timed(s"part $i")(())))
    threads.foreach(_.join())
    assertEquals(timings.text(Instant.EPOCH).linesIterator.count(_.startsWith("part ")), 8)

  test("an unwritable log costs only the log"):
    val dir = Files.createTempDirectory("launch-timings")
    try LaunchTimings().write(dir.resolve("missing").resolve("launch.log"), Instant.EPOCH)
    finally FileHelper.deleteRecursively(dir)
