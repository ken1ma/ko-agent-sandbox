// The image's ENTRYPOINT, run as the shell script it is: what it seeds into a persistent volume
// that is fresh, that predates an agent, or that two sessions open at once.

package agentsandbox.launcher

import java.nio.ByteBuffer
import java.nio.file.{Files, Path}
import java.nio.file.attribute.UserDefinedFileAttributeView
import scala.jdk.CollectionConverters.*

class SandboxEntrypointTest extends munit.FunSuite:

  private val script = Path.of("container/ko-agent-sandbox/sandbox-entrypoint").toAbsolutePath
  private val sh = Path.of("/bin/sh")
  private lazy val gnuMv =
    try
      val process = ProcessBuilder("mv", "--version").redirectErrorStream(true).start()
      val output = String(process.getInputStream.readAllBytes())
      process.waitFor() == 0 && output.contains("GNU coreutils")
    catch case _: java.io.IOException => false

  private def fixture(): (Path, Path) =
    // `mv -T` is GNU coreutils': the script runs only in the Debian image, and so does this suite's host.
    assume(Files.isExecutable(sh) && gnuMv, "runs the entrypoint under /bin/sh with GNU mv")
    val root = Files.createTempDirectory("sandbox-entrypoint")
    val seed = Files.createDirectories(root.resolve("seed"))
    Vector("claude", "codex", "antigravity", "copilot").foreach: agent =>
      Files.createDirectory(seed.resolve(agent))
      Files.writeString(seed.resolve(agent).resolve("seeded"), agent)
    Files.createSymbolicLink(seed.resolve("copilot").resolve("copilot-instructions.md"), script)
    val home = Files.createDirectories(root.resolve("home"))
    Files.createDirectory(home.resolve("persistent-volume"))
    (seed, home)

  /** Starts the entrypoint with the fixture's seed and HOME; the command it execs prints its arguments. */
  private def start(seed: Path, home: Path): Process =
    val builder = ProcessBuilder(sh.toString, script.toString, "sh", "-c", "printf '%s ' \"$0\" \"$@\"", "a", "b c")
    builder.environment.put("SANDBOX_VOLUME_SEED", seed.toString)
    builder.environment.put("HOME", home.toString)
    builder.redirectErrorStream(true)
    builder.start()

  private def finish(process: Process): (Int, String) =
    val output = String(process.getInputStream.readAllBytes())
    (process.waitFor(), output)

  private def run(seed: Path, home: Path): (Int, String) = finish(start(seed, home))

  private def entries(volume: Path): Set[String] =
    Files.list(volume).iterator.asScala.map(_.getFileName.toString).toSet

  private def setUserAttribute(path: Path, name: String): Unit =
    val attributes = Files.getFileAttributeView(path, classOf[UserDefinedFileAttributeView])
    assume(attributes != null, "the test filesystem supports user-defined attributes")
    try attributes.write(name, ByteBuffer.wrap(Array[Byte](1)))
    catch
      case _: UnsupportedOperationException | _: java.io.IOException =>
        assume(false, "the test filesystem supports user-defined attributes")

  private def userAttributes(path: Path): Set[String] =
    val attributes = Files.getFileAttributeView(path, classOf[UserDefinedFileAttributeView])
    Option(attributes).fold(Set.empty[String])(_.list().asScala.toSet)

  test("a fresh volume receives every seed directory, and the command runs with its arguments intact"):
    val (seed, home) = fixture()
    val (status, output) = run(seed, home)
    assertEquals(status, 0, output)
    assertEquals(output, "a b c ")
    val volume = home.resolve("persistent-volume")
    assertEquals(entries(volume), Set("claude", "codex", "antigravity", "copilot"))
    assertEquals(Files.readString(volume.resolve("codex").resolve("seeded")), "codex")
    assert(Files.isSymbolicLink(volume.resolve("copilot").resolve("copilot-instructions.md")))

  test("a volume from an older image gets only the directories it lacks; the rest is untouched"):
    val (seed, home) = fixture()
    val volume = home.resolve("persistent-volume")
    Files.createDirectory(volume.resolve("claude"))
    Files.writeString(volume.resolve("claude").resolve("seeded"), "login state")
    Files.createDirectory(volume.resolve("codex"))  // present but empty: still the agent's
    val (status, output) = run(seed, home)
    assertEquals(status, 0, output)
    assertEquals(Files.readString(volume.resolve("claude").resolve("seeded")), "login state")
    assertEquals(entries(volume.resolve("codex")), Set.empty[String])
    assertEquals(Files.readString(volume.resolve("copilot").resolve("seeded")), "copilot")

  test("seed metadata does not escape into the cross-session volume"):
    val (seed, home) = fixture()
    val privateAttribute = "ko-agent-sandbox-private-label"
    setUserAttribute(seed.resolve("copilot"), privateAttribute)
    setUserAttribute(seed.resolve("copilot").resolve("seeded"), privateAttribute)
    val (status, output) = run(seed, home)
    assertEquals(status, 0, output)
    val copied = home.resolve("persistent-volume").resolve("copilot")
    assert(!userAttributes(copied).contains(privateAttribute))
    assert(!userAttributes(copied.resolve("seeded")).contains(privateAttribute))

  test("sessions seeding one volume at once all succeed, and leave one copy and no staging behind"):
    val (seed, home) = fixture()
    val volume = home.resolve("persistent-volume")
    val results = (1 to 20).toVector.map(_ => start(seed, home)).map(finish)
    results.foreach((status, output) => assertEquals(status, 0, output))
    assertEquals(entries(volume), Set("claude", "codex", "antigravity", "copilot"))
    assertEquals(entries(volume.resolve("copilot")), Set("seeded", "copilot-instructions.md"))
