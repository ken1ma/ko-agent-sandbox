// How the launcher runs host executables and what its scripts may resolve: trusted-path lookup,
// and the fixed PATH every generated script declares before anything else.

package agentsandbox.launcher

import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions

import HostCommands.*
import KoAgentFs.*
import SandboxLifecycle.*

class HostCommandsTest extends munit.FunSuite:

  private def modeOf(path: java.nio.file.Path): String =
    PosixFilePermissions.toString(Files.getPosixFilePermissions(path))

  test("executables resolve only through absolute PATH entries"):
    val dir = Files.createTempDirectory("path-resolve").toRealPath()
    val tool = dir.resolve("mytool")
    Files.createFile(tool)
    tool.toFile.setExecutable(true)
    // `.` and a repository-relative directory are skipped, never searched.
    assertEquals(findOnPath("mytool", s".:relative/dir:$dir", Os.Linux), Some(tool))
    assertEquals(findOnPath("mytool", ".:relative/dir", Os.Linux), None)
    assertEquals(findOnPath("absent", dir.toString, Os.Linux), None)
    assertEquals(findOnPath("mytool", "", Os.Linux), None)

  test("an absolute PATH entry inside the checkout is skipped, not preferred"):
    // The shape absoluteness alone does not catch, and the reason this rule is not about relative
    // entries: `npm run` puts `$PWD/node_modules/.bin` on PATH as an *absolute* entry, and a
    // transitive dependency can ship a `bin` named `podman` without running a line of its own code.
    // The launcher would then be the first thing to execute it — on the host, before any
    // confinement exists.
    val checkout = Files.createTempDirectory("untrusted-checkout").toRealPath()
    val shipped = Files.createDirectories(checkout.resolve("node_modules/.bin"))
    val planted = shipped.resolve("podman")
    Files.createFile(planted)
    planted.toFile.setExecutable(true)

    val system = Files.createTempDirectory("system-bin").toRealPath()
    val real = system.resolve("podman")
    Files.createFile(real)
    real.toFile.setExecutable(true)

    // Ahead of the system directory, which is exactly where it would otherwise win.
    assertEquals(findOnPath("podman", s"$shipped:$system", Os.Linux, checkout), Some(real))
    // Skipped rather than merely deprioritized: with nothing else on PATH there is no fallback.
    assertEquals(findOnPath("podman", shipped.toString, Os.Linux, checkout), None)
    // A directory that merely shares a prefix with the checkout is not inside it.
    val sibling = Files.createDirectories(checkout.resolveSibling(s"${checkout.getFileName}x"))
    val neighbour = sibling.resolve("podman")
    Files.createFile(neighbour)
    neighbour.toFile.setExecutable(true)
    assertEquals(findOnPath("podman", sibling.toString, Os.Linux, checkout), Some(neighbour))

  test("an executable symlinked out of the checkout is skipped, and the real path is returned"):
    // The *candidate* is what must be canonicalized, not the directory holding it. An ordinary
    // directory containing `podman -> <checkout>/bin/podman` passes any check made on the directory
    // alone, because `isRegularFile` and `isExecutable` follow the leaf.
    val checkout = Files.createTempDirectory("untrusted-checkout").toRealPath()
    val shipped = Files.createDirectories(checkout.resolve("bin"))
    val planted = shipped.resolve("podman")
    Files.createFile(planted)
    planted.toFile.setExecutable(true)

    val outside = Files.createTempDirectory("outside-bin").toRealPath()
    Files.createSymbolicLink(outside.resolve("podman"), planted)
    assertEquals(findOnPath("podman", outside.toString, Os.Linux, checkout), None)

    // And the resolution is what is returned, so the path handed to podman and the reaper is the
    // real file rather than a link that could be re-pointed after it was vetted.
    val elsewhere = Files.createTempDirectory("real-bin").toRealPath()
    val real = elsewhere.resolve("podman")
    Files.createFile(real)
    real.toFile.setExecutable(true)
    val shim = Files.createTempDirectory("shim-bin").toRealPath()
    Files.createSymbolicLink(shim.resolve("podman"), real)
    assertEquals(findOnPath("podman", shim.toString, Os.Linux, checkout), Some(real))

  test("Windows resolution appends executable extensions and splits on ;"):
    val dir = Files.createTempDirectory("path-resolve-win").toRealPath()
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

  test("a private file is never briefly readable, and never inherits a mode it replaced"):
    assume(posixPermissions(Files.createTempDirectory("perm-probe")), "POSIX permissions only")
    val dir = Files.createTempDirectory("private-write").toRealPath()

    // The end state, and the reason the mode is also requested at creation: `Files.writeString`
    // alone would leave the key at the umask's mode for the length of the write.
    val key = dir.resolve("ca.key")
    writePrivate(key, "PRIVATE KEY")
    assertEquals(modeOf(key), "rw-------")

    val readable = dir.resolve("bundle.crt")
    writeReadable(readable, "CERT")
    assertEquals(modeOf(readable), "rw-r--r--")

    // Replacing a file does not inherit its mode: a world-writable one planted at the path is
    // unlinked, not opened, so nothing carries the old permissions into the new content.
    val planted = dir.resolve("leaf.key")
    Files.createFile(planted)
    Files.setPosixFilePermissions(planted, PosixFilePermissions.fromString("rw-rw-rw-"))
    writePrivate(planted, "PRIVATE KEY")
    assertEquals(modeOf(planted), "rw-------")
    assertEquals(Files.readString(planted), "PRIVATE KEY")
