package agentsandbox.launcher

import java.nio.file.Path
import java.util.concurrent.TimeUnit

class ClaudeManagedHelpersTest extends munit.FunSuite:

  test("managed Claude status line preserves data-only configuration"):
    assume(System.getProperty("os.name") == "Linux", "runs the image's status-line command with Python 3")
    val process = ProcessBuilder(
      "python3",
      "-I",
      Path.of("src/test/python/claude_managed_helpers_test.py").toAbsolutePath.toString,
    ).redirectErrorStream(true).start()
    try
      assert(process.waitFor(30, TimeUnit.SECONDS), "managed helper tests exceeded 30 seconds")
      val output = String(process.getInputStream.readAllBytes())
      assertEquals(process.exitValue(), 0, output)
    finally process.destroyForcibly()
