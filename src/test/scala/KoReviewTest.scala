package agentsandbox.launcher

import java.nio.file.{Files, Path}
import java.util.concurrent.TimeUnit

class KoReviewTest extends munit.FunSuite:

  private val plugin = Path.of("container/ko-agent-sandbox/claude-code/plugins/ko-review").toAbsolutePath

  private def run(timeoutSeconds: Long, command: String*): (Int, String) =
    val process = ProcessBuilder(command*).redirectErrorStream(true).start()
    try
      assert(process.waitFor(timeoutSeconds, TimeUnit.SECONDS), s"${command.head} exceeded $timeoutSeconds seconds")
      (process.exitValue(), String(process.getInputStream.readAllBytes()))
    finally process.destroyForcibly()

  test("ko-review runs a review cycle against a fake codex"):
    assume(System.getProperty("os.name") == "Linux", "runs the plugin's helper with Python 3")
    val (status, output) = run(
      120,
      "python3",
      "-I",
      Path.of("src/test/python/ko_review_test.py").toAbsolutePath.toString,
    )
    assertEquals(status, 0, output)

  // The plugin's bin/ joins only Claude's Bash tool's PATH, so a plain shell in the session, where
  // `sbt testFull` runs, cannot check that; readability and the helper's mode are what the image sets.
  test("the image's copy of the plugin is readable and its helper executable"):
    assume(Files.isRegularFile(Path.of("/etc/claude-code/managed-settings.json")), "runs inside the sandbox image")
    val installed = Path.of("/etc/claude-code/plugins/ko-review")
    assert(Files.isDirectory(installed), "the image has no copy of the plugin")
    val unreadable = Files.walk(installed).filter(path => !Files.isReadable(path) ||
      (Files.isDirectory(path) && !Files.isExecutable(path))).map(_.toString).toList
    assertEquals(unreadable, java.util.List.of[String](), "paths the plugin loader cannot read")
    assert(Files.isExecutable(installed.resolve("bin/ko-review")), "bin/ko-review is not executable")

  test("the ko-review plugin validates"):
    val claude = System.getenv("PATH").split(java.io.File.pathSeparator)
      .map(Path.of(_, "claude")).find(Files.isExecutable)
    assume(claude.isDefined, "needs claude on PATH")
    val (status, output) = run(60, claude.get.toString, "plugin", "validate", plugin.toString)
    assertEquals(status, 0, output)
    assert(output.contains("Validation passed"), output)
