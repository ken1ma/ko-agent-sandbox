// How the launcher runs host executables and what its scripts may resolve: trusted-path lookup,
// and the fixed PATH every generated script declares before anything else.

package agentsandbox.launcher

import java.nio.file.Files

import HostCommands.*
import KoAgentFs.*
import SandboxLifecycle.*

class HostCommandsTest extends munit.FunSuite:

  test("trusted executables resolve only through absolute PATH entries"):
    val dir = Files.createTempDirectory("path-resolve")
    val tool = dir.resolve("mytool")
    Files.createFile(tool)
    tool.toFile.setExecutable(true)
    // `.` and a repository-relative directory are skipped, never searched.
    assertEquals(findOnPath("mytool", s".:relative/dir:$dir", Os.Linux), Some(tool))
    assertEquals(findOnPath("mytool", ".:relative/dir", Os.Linux), None)
    assertEquals(findOnPath("absent", dir.toString, Os.Linux), None)
    assertEquals(findOnPath("mytool", "", Os.Linux), None)

  test("Windows resolution appends executable extensions and splits on ;"):
    val dir = Files.createTempDirectory("path-resolve-win")
    val tool = dir.resolve("mytool.exe")
    Files.createFile(tool)
    tool.toFile.setExecutable(true)
    assertEquals(findOnPath("mytool", s"relative\\dir;$dir", Os.Windows), Some(tool))
    // The bare, extensionless name is not a Windows executable and is never a candidate.
    val bare = Files.createFile(dir.resolve("othertool"))
    bare.toFile.setExecutable(true)
    assertEquals(findOnPath("othertool", dir.toString, Os.Windows), None)

  test("every script the launcher writes names its own PATH before running anything"):
    // These are `sh -c` text inheriting the launcher's environment and its working directory — the
    // repository being sandboxed — so a relative PATH entry would let a checkout supply
    // `fusermount3`, `mountpoint`, `stat` or `sleep`. findOnPath covers what the launcher invokes;
    // this covers what its scripts do.
    val scripts = Vector(
      "mount" -> koAgentFsMountScript("/tmp/backing", "app-abc123def456", "d" * 64, "run-1"),
      "reap" -> koAgentFsReapScript("/usr/bin/podman", "app-abc123def456", "run-1"),
      "unmount" -> koAgentFsUnmountScript("app-abc123def456"),
      "unmount-all" -> koAgentFsUnmountAllScript,
      "reaper" -> ReaperScript
    )
    scripts.foreach: (name, script) =>
      assertEquals(script.linesIterator.next(), s"export PATH=$ScriptPath", name)
    // Absolute system directories only: a relative entry is the whole thing being kept out.
    assert(
      ScriptPath.split(":").forall(entry => entry.startsWith("/") && entry.length > 1),
      ScriptPath
    )
