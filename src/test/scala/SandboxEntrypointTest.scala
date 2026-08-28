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

  /**
   * Starts the entrypoint with the fixture's seed and HOME; the command it execs prints its
   * arguments. `/proc` is the healthy fixture unless a test hands over its own, so the machine
   * this suite runs on never decides whether a warning prints.
   */
  private def start(
    seed: Path,
    home: Path,
    proc: Path = healthyProc(),
    path: Option[Path] = None,
  ): Process =
    val builder =
      ProcessBuilder(sh.toString, script.toString, "sh", "-c", "printf '%s ' \"$0\" \"$@\"", "a", "b c")
    builder.environment.put("SANDBOX_VOLUME_SEED", seed.toString)
    builder.environment.put("HOME", home.toString)
    builder.environment.put("SANDBOX_PROC", proc.toString)
    path.foreach(dir => builder.environment.put("PATH", dir.toString + ":" + System.getenv("PATH")))
    builder.redirectErrorStream(true)
    builder.start()

  /** A `/proc` in kB, as the kernel writes it, with the pressure file present or absent. */
  private def proc(
    available: Long,
    total: Long = 16L << 20,
    swapUsed: Long = 0,
    pressure: Option[String] = None,
  ): Path =
    val root = Files.createTempDirectory("sandbox-entrypoint-proc")
    Files.writeString(
      root.resolve("meminfo"),
      s"""MemTotal:       $total kB
         |MemFree:        ${available / 2} kB
         |MemAvailable:   $available kB
         |SwapTotal:      ${4L << 20} kB
         |SwapFree:       ${(4L << 20) - swapUsed} kB
         |""".stripMargin,
    )
    pressure.foreach: line =>
      Files.createDirectory(root.resolve("pressure"))
      Files.writeString(
        root.resolve("pressure").resolve("memory"),
        line + "\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
      )
    root

  private def healthyProc(): Path =
    proc(available = 8L << 20, pressure = Some("some avg10=0.00 avg60=0.00 avg300=0.00 total=0"))

  /** A `df` answering with the given free kB, on a PATH entry to put before the real one. */
  private def fakeDf(availableKb: Long): Path =
    val dir = Files.createTempDirectory("sandbox-entrypoint-bin")
    val df = dir.resolve("df")
    Files.writeString(
      df,
      s"#!/bin/sh\necho 'Filesystem 1024-blocks Used Available Capacity Mounted on'\n" +
        s"echo 'vda 100 1 $availableKb 1% /'\n",
    )
    df.toFile.setExecutable(true)
    dir

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

  test("a healthy machine prints nothing before the command"):
    val (seed, home) = fixture()
    val (status, output) = run(seed, home)
    assertEquals(status, 0, output)
    assertEquals(output, "a b c ")

  test("a machine short of memory, swapping, stalled, or out of disk is said before the command, once"):
    val (seed, home) = fixture()
    val sick = proc(
      available = 512L << 10,
      total = 8L << 20,
      swapUsed = 1L << 20,
      pressure = Some("some avg10=40.00 avg60=25.50 avg300=3.00 total=1"),
    )
    val (status, output) = finish(start(seed, home, sick, Some(fakeDf(1L << 20))))
    assertEquals(status, 0, output)
    assert(output.startsWith("warning: the machine podman runs on is under pressure"), output)
    assert(output.contains("  0.5 GiB of 8.0 GiB memory available\n"), output)
    assert(output.contains("  1.0 GiB of swap in use\n"), output)
    assert(output.contains("  memory pressure: tasks stalled on memory 25.50% of the last minute\n"), output)
    assert(output.contains("  1.0 GiB of disk left on the machine\n"), output)
    assert(output.contains("podman machine set --memory"), output)
    // No terminal on stdin, so no hold: the command still ran.
    assert(!output.contains("[Y/n]"), output)
    assert(output.endsWith("a b c "), output)

  test("swap left over from pressure that has passed is not pressure"):
    val (seed, home) = fixture()
    val lingering = proc(available = 8L << 20, total = 16L << 20, swapUsed = 1L << 20)
    val (status, output) = finish(start(seed, home, lingering))
    assertEquals(status, 0, output)
    assertEquals(output, "a b c ")
    // The same swap with memory tight now — under a quarter available, not yet under 1 GiB — is.
    val tight = proc(available = 3L << 20, total = 16L << 20, swapUsed = 1L << 20)
    val (_, warned) = finish(start(seed, home, tight))
    assert(warned.contains("  1.0 GiB of swap in use\n"), warned)
    assert(!warned.contains("memory available"), warned)

  test("a pressure file the kernel refuses to serve, or lacks, costs only its line"):
    val (seed, home) = fixture()
    val refused = proc(available = 512L << 10, pressure = Some("x"))
    refused.resolve("pressure").resolve("memory").toFile.setReadable(false)
    Vector(refused, proc(available = 512L << 10)).foreach: sick =>
      val (status, output) = finish(start(seed, home, sick))
      assertEquals(status, 0, output)
      assert(output.contains("memory available"), output)
      assert(!output.contains("memory pressure"), output)
