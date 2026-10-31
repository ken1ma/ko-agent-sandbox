package agentsandbox.launcher

import java.nio.file.{Files, Path}
import java.util.concurrent.TimeUnit

/** Runs the image's ko-sandbox-mic through its Python suite (src/test/python/ko_sandbox_mic_test.py). */
class SandboxMicTest extends munit.FunSuite:

  // The suite takes about 35 seconds where pulseaudio is installed and its DaemonTest runs.
  override val munitTimeout = scala.concurrent.duration.Duration(4, "min")

  test("the microphone controller and writer keep their contract with the daemon and the relay"):
    // The program runs in the Debian image and uses pidfds and /proc, so the suite runs only on Linux.
    assume(System.getProperty("os.name") == "Linux", "runs the image's ko-sandbox-mic with Python 3 on Linux")
    val output = Files.createTempFile("ko-sandbox-mic-test", ".log")
    val process = ProcessBuilder(
      "python3", "-I", Path.of("src/test/python/ko_sandbox_mic_test.py").toAbsolutePath.toString,
    ).redirectErrorStream(true).redirectOutput(output.toFile).start()
    try
      assert(process.waitFor(180, TimeUnit.SECONDS), "the ko-sandbox-mic tests exceeded 180 seconds")
      assertEquals(process.exitValue(), 0, Files.readString(output))
    finally
      // Ending the descendants also ends the suite's daemons and streams, which the suite's own cleanup ends only when
      // the suite finishes.
      process.descendants().forEach(_.destroyForcibly())
      process.destroyForcibly()
