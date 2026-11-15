package agentsandbox.launcher

import java.nio.file.{Files, Path}
import java.util.concurrent.TimeUnit
import scala.jdk.CollectionConverters.*

class KoReviewTest extends munit.FunSuite:

  private def run(timeoutSeconds: Long, command: String*): (Int, String) = runIn(timeoutSeconds, Map.empty, command*)

  private def runIn(timeoutSeconds: Long, environment: Map[String, String], command: String*): (Int, String) =
    // The output goes into a file, which nothing has to read while the process runs. A pipe that is read
    // only after the wait stalls a process that writes more than the pipe holds (doc/limitations.md,
    // "Pipes as small as 8 KiB").
    val output = Files.createTempFile("ko-review-test", ".log")
    val builder = ProcessBuilder(command*).redirectErrorStream(true).redirectOutput(output.toFile)
    environment.foreach((name, value) => builder.environment().put(name, value))
    val process = builder.start()
    try
      assert(process.waitFor(timeoutSeconds, TimeUnit.SECONDS), s"${command.head} exceeded $timeoutSeconds seconds")
      (process.exitValue(), Files.readString(output))
    finally
      process.destroyForcibly()
      Files.deleteIfExists(output)

  // The plugin's bin/ joins only the PATH of Claude's Bash tool, so a plain shell in the session, where
  // `sbt testFull` runs, cannot check that PATH entry. This test checks what the image sets instead: the
  // plugin's readability and the helper's mode.
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

  // The image fetches the helper's dependencies at build time (the Containerfile), so a jar missing from lib/ shows
  // only when the helper runs.
  test("the image's helper runs with the jars that the image fetched"):
    assume(Files.isRegularFile(Path.of("/etc/claude-code/managed-settings.json")), "runs inside the sandbox image")
    val (status, output) = run(20, "/usr/local/bin/ko-review", "digest")
    assertEquals(status, 0, output)
    assert(output.contains("\"contentDigest\""), output)
    // The fetch is intransitive, so lib/ holds the helper's jar and one jar per listed module, nothing more.
    val lib = Path.of("/etc/claude-code/plugins/ko-review/lib")
    val listed = Files.readAllLines(lib.resolve("dependencies.txt")).asScala.toVector.filter(_.nonEmpty)
      .map(_.split(':') match { case Array(_, name, version) => s"$name-$version.jar" })
    val jars = Files.list(lib).iterator().asScala.map(_.getFileName.toString).filter(_.endsWith(".jar")).toVector
    assertEquals(jars.sorted, ("ko-review.jar" +: listed).sorted)
