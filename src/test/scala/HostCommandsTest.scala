// Host command tests cover executable resolution, generated script paths and launcher diagnostics.
// FileHelperTest and DirectoryStreamsTest cover the shared file operations.

package agentsandbox.launcher

import java.nio.file.{Files, Paths}

import HostCommands.*
import FileHelper.*
import KoAgentFs.*
import SandboxLifecycle.*

class HostCommandsTest extends munit.FunSuite:

  test("only an explicit yes is consent"):
    assert(consented(Some("y")))
    assert(consented(Some("Y")))
    assert(consented(Some(" YES ")))
    assert(!consented(Some("")))
    assert(!consented(Some("n")))
    assert(!consented(Some("yeah")))
    assert(!consented(None))

  test("colour is for a terminal that will render it, and for no one else"):
    assertEquals(colorAllowed(Os.Linux, None, Some("xterm-256color")), true)
    assertEquals(colorAllowed(Os.Mac, None, None), true)
    assertEquals(colorAllowed(Os.Windows, None, Some("xterm-256color")), false)
    assertEquals(colorAllowed(Os.Linux, Some("1"), Some("xterm-256color")), false)
    assertEquals(colorAllowed(Os.Linux, None, Some("dumb")), false)

  test("emphasis tints the severity label and leaves every other word as it was written"):
    val warning = "warning: podman runs on 3.0G of memory\n  raise it with `podman machine set`"
    assertEquals(emphasized(warning, color = false), warning)
    assertEquals(
      emphasized(warning, color = true),
      "\u001b[38;5;208mwarning:\u001b[0m podman runs on 3.0G of memory\n  raise it with `podman machine set`",
    )
    // A block has a label per line, and a line that has none keeps its own spelling.
    assertEquals(
      emphasized("error: no\nplain\nwarning: yes", color = true),
      "\u001b[38;5;208merror:\u001b[0m no\nplain\n\u001b[38;5;208mwarning:\u001b[0m yes",
    )
    // The label is a prefix, never a word found mid-line: this one is a subprocess's text quoted.
    assertEquals(emphasized("the proxy said warning: x", color = true), "the proxy said warning: x")

  test("a refusal raised while the JVM is shutting down names the interruption first, and waits"):
    assert(!shuttingDown, "a JVM with no shutdown under way reported one")
    // The true case needs a shutdown under way, so it runs in a JVM of its own on this test's
    // classes (FailDuringShutdown). The exit status is the shutdown's, not the refusal's: the
    // refusal's exit blocked indefinitely, and the JVM ended when the hook finished.
    def location(of: Class[?]) = Paths.get(of.getProtectionDomain.getCodeSource.getLocation.toURI).toString
    val classpath = Vector(
      FailDuringShutdown.getClass, HostCommands.getClass, scala.runtime.LazyVals.getClass, classOf[Option[?]],
    ).map(location).distinct.mkString(java.io.File.pathSeparator)
    val jvm = Paths.get(sys.props("java.home"), "bin", "java").toString
    // Native access as the jar's manifest grants it, for the isatty behind colorStderr. What the
    // JVM prints before the first refusal line is its own: _JAVA_OPTIONS echoed back.
    val staged = run(
      jvm, "--enable-native-access=ALL-UNNAMED", "-cp", classpath, "agentsandbox.launcher.FailDuringShutdown",
    )
    assertEquals(
      staged.err.linesIterator.dropWhile(!_.startsWith("error:")).toVector,
      Vector(
        "error: the launch was interrupted; the failure below is its consequence, not a fault of its own",
        "error: podman failed",
        "its stderr",
        "hook: removed",
      ),
    )
    assertEquals(staged.exit, 130)

  test("every warning and refusal the launcher writes goes through the one label"):
    // warn and fail are where the label is spelled and tinted; a println of its own prints it
    // plain on a terminal and drifts the day the rule changes.
    val printedLabel = """System\.err\.println\(\s*s?"(warning|error):""".r
    val offenders =
      for
        file <- directoryEntries(Paths.get("src", "main", "scala"))
        if file.getFileName.toString != "HostCommands.scala"
        hit <- printedLabel.findFirstIn(Files.readString(file))
      yield s"${file.getFileName}: $hit"
    assertEquals(offenders, Vector.empty)

  // The POSIX-branch resolution tests below build ':'-separated PATH strings out of real
  // directories, which on a Windows runner have their own ':' after the drive letter — the
  // string cannot be built there, not merely the branch untested. The Windows branch has its own
  // test, which runs everywhere.
  private val isWindows = scala.util.Properties.isWin

  test("executables resolve only through absolute PATH entries"):
    assume(!isWindows, "POSIX PATH strings cannot hold drive-letter directories")
    val dir = Files.createTempDirectory("path-resolve").toRealPath()
    val program = dir.resolve("myprogram")
    Files.createFile(program)
    program.toFile.setExecutable(true)
    // `.` and a repository-relative directory are skipped, never searched.
    assertEquals(findOnPath("myprogram", s".:relative/dir:$dir", Os.Linux), Some(program))
    assertEquals(findOnPath("myprogram", ".:relative/dir", Os.Linux), None)
    assertEquals(findOnPath("absent", dir.toString, Os.Linux), None)
    assertEquals(findOnPath("myprogram", "", Os.Linux), None)

  test("an absolute PATH entry inside the project is skipped, not preferred"):
    assume(!isWindows, "POSIX PATH strings cannot hold drive-letter directories")
    // The absolute-entry-inside-the-project case (HostCommands.findOnPath's doc, design.md "No
    // repository-controlled host executable resolution").
    val project = Files.createTempDirectory("untrusted-project").toRealPath()
    val shipped = Files.createDirectories(project.resolve("node_modules/.bin"))
    val planted = shipped.resolve("podman")
    Files.createFile(planted)
    planted.toFile.setExecutable(true)

    val system = Files.createTempDirectory("system-bin").toRealPath()
    val real = system.resolve("podman")
    Files.createFile(real)
    real.toFile.setExecutable(true)

    // Ahead of the system directory, which is exactly where it would otherwise win.
    assertEquals(findOnPath("podman", s"$shipped:$system", Os.Linux, project), Some(real))
    // Skipped rather than merely deprioritized: with nothing else on PATH there is no fallback.
    assertEquals(findOnPath("podman", shipped.toString, Os.Linux, project), None)
    // A directory that merely shares a prefix with the project is not inside it.
    val sibling = Files.createDirectories(project.resolveSibling(s"${project.getFileName}x"))
    val neighbour = sibling.resolve("podman")
    Files.createFile(neighbour)
    neighbour.toFile.setExecutable(true)
    assertEquals(findOnPath("podman", sibling.toString, Os.Linux, project), Some(neighbour))

  test("an executable symlinked out of the project is skipped, and the real path is returned"):
    assume(!isWindows, "POSIX PATH strings cannot hold drive-letter directories")
    val project = Files.createTempDirectory("untrusted-project").toRealPath()
    val shipped = Files.createDirectories(project.resolve("bin"))
    val planted = shipped.resolve("podman")
    Files.createFile(planted)
    planted.toFile.setExecutable(true)

    val outside = Files.createTempDirectory("outside-bin").toRealPath()
    Files.createSymbolicLink(outside.resolve("podman"), planted)
    assertEquals(findOnPath("podman", outside.toString, Os.Linux, project), None)

    val elsewhere = Files.createTempDirectory("real-bin").toRealPath()
    val real = elsewhere.resolve("podman")
    Files.createFile(real)
    real.toFile.setExecutable(true)
    val shim = Files.createTempDirectory("shim-bin").toRealPath()
    Files.createSymbolicLink(shim.resolve("podman"), real)
    assertEquals(findOnPath("podman", shim.toString, Os.Linux, project), Some(real))

  test("Windows resolution appends executable extensions and splits on ;"):
    val dir = Files.createTempDirectory("path-resolve-win").toRealPath()
    val program = dir.resolve("myprogram.exe")
    Files.createFile(program)
    program.toFile.setExecutable(true)
    assertEquals(findOnPath("myprogram", s"relative\\dir;$dir", Os.Windows), Some(program))
    // The bare, extensionless name is not a Windows executable and is never a candidate.
    val bare = Files.createFile(dir.resolve("otherprogram"))
    bare.toFile.setExecutable(true)
    assertEquals(findOnPath("otherprogram", dir.toString, Os.Windows), None)

  test("every script the launcher writes names its own PATH before running anything"):
    val scripts = Vector(
      "mount" -> koAgentFsMountScript("/tmp/backing", "app-abc123def456", "d" * 64, "run-1"),
      "reap" -> koAgentFsReapScript("/usr/bin/podman", "app-abc123def456", "run-1"),
      "unmount" -> koAgentFsUnmountScript("app-abc123def456"),
      "unmount-all" -> koAgentFsUnmountAllScript,
      "reaper" -> ReaperScript,
    )
    scripts.foreach: (name, script) =>
      assertEquals(script.linesIterator.next(), s"export PATH=$ScriptPath", name)
      // Syntax only, by the interpreter that runs it; what a valid script does is each script's
      // own behavioral test.
      if !isWindows then
        val parsed = ProcessBuilder("/bin/sh", "-n", "-c", script).redirectErrorStream(true).start()
        val output = String(parsed.getInputStream.readAllBytes())
        assertEquals(parsed.waitFor(), 0, s"$name does not parse:\n$output")
    // Absolute system directories only: a relative entry is exactly what is kept out.
    assert(
      ScriptPath.split(":").forall(entry => entry.startsWith("/") && entry.length > 1),
      ScriptPath,
    )
