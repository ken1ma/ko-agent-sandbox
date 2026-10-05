package agentsandbox.launcher

import java.nio.file.{Files, Path}
import java.util.concurrent.TimeUnit

class KoReviewTest extends munit.FunSuite:

  // Longer than the longest wait a test here gives its process (`run`): munit's 30 s default would
  // end the test first, without the process's output.
  override val munitTimeout = scala.concurrent.duration.Duration(6, "min")

  private val plugin = Path.of("container/ko-agent-sandbox/claude-code/plugins/ko-review").toAbsolutePath

  private def run(timeoutSeconds: Long, command: String*): (Int, String) = runIn(timeoutSeconds, Map.empty, command*)

  private def runIn(timeoutSeconds: Long, environment: Map[String, String], command: String*): (Int, String) =
    val builder = ProcessBuilder(command*).redirectErrorStream(true)
    environment.foreach((name, value) => builder.environment().put(name, value))
    val process = builder.start()
    try
      assert(process.waitFor(timeoutSeconds, TimeUnit.SECONDS), s"${command.head} exceeded $timeoutSeconds seconds")
      (process.exitValue(), String(process.getInputStream.readAllBytes()))
    finally process.destroyForcibly()

  test("ko-review runs a review cycle against a fake codex and a fake claude"):
    assume(System.getProperty("os.name") == "Linux", "runs the plugin's helper with Python 3")
    val (status, output) = run(
      300,
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
    assertEquals(
      Files.readString(Path.of("/etc/codex/skills/ko-review/SKILL.md")),
      Files.readString(installed.resolve("skills/ko-review/SKILL.md")),
      "Codex's copy of the skill differs from the plugin's",
    )
    assertEquals(Path.of("/usr/local/bin/ko-review").toRealPath(), installed.resolve("bin/ko-review").toRealPath())

  private def onPath(program: String): Option[Path] =
    System.getenv("PATH").split(java.io.File.pathSeparator).map(Path.of(_, program)).find(Files.isExecutable)

  test("the ko-review plugin validates"):
    val claude = onPath("claude")
    assume(claude.isDefined, "needs claude on PATH")
    val (status, output) = run(60, claude.get.toString, "plugin", "validate", plugin.toString)
    assertEquals(status, 0, output)
    assert(output.contains("Validation passed"), output)

  // A copy, as the image installs it; the Containerfile has why.
  test("Codex loads a copy of the skill as ko-review"):
    val codex = onPath("codex")
    assume(codex.isDefined, "needs codex on PATH")
    val home = Files.createTempDirectory("ko-review-codex-home")
    val skill = home.resolve(".agents/skills/ko-review/SKILL.md")
    Files.createDirectories(skill.getParent)
    Files.copy(plugin.resolve("skills/ko-review/SKILL.md"), skill)
    val codexHome = Files.createDirectories(home.resolve(".codex"))
    val environment = Map("HOME" -> home.toString, "CODEX_HOME" -> codexHome.toString)
    val (status, output) = runIn(60, environment, codex.get.toString, "debug", "prompt-input")
    assertEquals(status, 0, output)
    assert(output.contains("- ko-review: "), output)
