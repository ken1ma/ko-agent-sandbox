package agentsandbox.launcher

import java.nio.file.{Files, Path}
import java.util.concurrent.TimeUnit

class ClaudeManagedHelpersTest extends munit.FunSuite:

  test("managed Claude status line preserves data-only configuration"):
    assume(System.getProperty("os.name") == "Linux", "runs the image's status-line command with Python 3")
    // Into a file, not a pipe read only after the wait (KoReviewTest.runIn has why).
    val output = Files.createTempFile("claude-managed-helpers-test", ".log")
    val process = ProcessBuilder(
      "python3",
      "-I",
      Path.of("src/test/python/claude_managed_helpers_test.py").toAbsolutePath.toString,
    ).redirectErrorStream(true).redirectOutput(output.toFile).start()
    try
      assert(process.waitFor(30, TimeUnit.SECONDS), "managed helper tests exceeded 30 seconds")
      assertEquals(process.exitValue(), 0, Files.readString(output))
    finally
      process.destroyForcibly()
      Files.deleteIfExists(output)
