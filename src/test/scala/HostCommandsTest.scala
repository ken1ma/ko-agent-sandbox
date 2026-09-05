// How the launcher runs host executables and what its scripts may resolve: trusted-path lookup,
// and the fixed PATH every generated script declares before anything else. Then how it writes the
// state files those runs mount: the mode they are never briefly without, and the name they are
// never briefly missing. Then how its own lines show severity: one label, one place it is
// spelled, and colour only where a terminal will render it.

package agentsandbox.launcher

import java.nio.file.{Files, Paths}
import java.nio.file.attribute.PosixFilePermissions
import scala.jdk.CollectionConverters.*

import HostCommands.*
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
    val warning = "warning: podman runs on 3 GiB of memory\n  raise it with `podman machine set`"
    assertEquals(emphasized(warning, color = false), warning)
    assertEquals(
      emphasized(warning, color = true),
      "\u001b[38;5;208mwarning:\u001b[0m podman runs on 3 GiB of memory\n  raise it with `podman machine set`",
    )
    // A block has a label per line, and a line that has none keeps its own spelling.
    assertEquals(
      emphasized("error: no\nplain\nwarning: yes", color = true),
      "\u001b[38;5;208merror:\u001b[0m no\nplain\n\u001b[38;5;208mwarning:\u001b[0m yes",
    )
    // The label is a prefix, never a word found mid-line: this one is a subprocess's text quoted.
    assertEquals(emphasized("the proxy said warning: x", color = true), "the proxy said warning: x")

  test("every warning and refusal the launcher writes goes through the one label"):
    // warn and fail are where the label is spelled and tinted; a println of its own prints it
    // plain on a terminal and drifts the day the rule changes.
    val printedLabel = """System\.err\.println\(\s*s?"(warning|error):""".r
    val offenders =
      for
        file <- Files.list(Paths.get("src", "main", "scala")).toList.asScala.toVector
        if file.getFileName.toString != "HostCommands.scala"
        hit <- printedLabel.findFirstIn(Files.readString(file))
      yield s"${file.getFileName}: $hit"
    assertEquals(offenders, Vector.empty)

  test("a stamped entry is its own validation, so an interleaved pair misses rather than mixes"):
    // Concurrent launches of one project under different authority selections write the ruleset
    // cache without a lock. With the stamp in a file of its own, one launch's content could end up
    // under the other's stamp and stay there; with it inside each file, the pairing a caller
    // requires simply does not match and the cache re-derives.
    val dir = Files.createTempDirectory("stamped")
    val hosts = dir.resolve("resolved.hosts")
    val warnings = dir.resolve("resolved.warnings")

    writeStamped(hosts, "stamp-a", "one\ntwo")
    writeStamped(warnings, "stamp-a", "")
    assertEquals(stampedEntry(hosts, "stamp-a"), Some("one\ntwo"))
    assertEquals(stampedEntry(warnings, "stamp-a"), Some(""))

    // The interleaving: another selection replaced the content of one file and not the other.
    writeStamped(hosts, "stamp-b", "three")
    assertEquals(stampedEntry(hosts, "stamp-a"), None)
    assertEquals(stampedEntry(warnings, "stamp-b"), None)

    assertEquals(stampedEntry(dir.resolve("absent"), "stamp-a"), None)
    // A file holding a stamp and nothing else is an entry with empty content, not a miss.
    writeReadable(hosts, "stamp-c\n")
    assertEquals(stampedEntry(hosts, "stamp-c"), Some(""))

  // The POSIX-branch resolution tests below build ':'-separated PATH strings out of real
  // directories, which on a Windows runner have their own ':' after the drive letter — the
  // string cannot be built there, not merely the branch untested. The Windows branch has its own
  // test, which runs everywhere.
  private val isWindows = scala.util.Properties.isWin

  private def modeOf(path: java.nio.file.Path): String =
    PosixFilePermissions.toString(Files.getPosixFilePermissions(path))

  test("executables resolve only through absolute PATH entries"):
    assume(!isWindows, "POSIX PATH strings cannot hold drive-letter directories")
    val dir = Files.createTempDirectory("path-resolve").toRealPath()
    val tool = dir.resolve("mytool")
    Files.createFile(tool)
    tool.toFile.setExecutable(true)
    // `.` and a repository-relative directory are skipped, never searched.
    assertEquals(findOnPath("mytool", s".:relative/dir:$dir", Os.Linux), Some(tool))
    assertEquals(findOnPath("mytool", ".:relative/dir", Os.Linux), None)
    assertEquals(findOnPath("absent", dir.toString, Os.Linux), None)
    assertEquals(findOnPath("mytool", "", Os.Linux), None)

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
    val tool = dir.resolve("mytool.exe")
    Files.createFile(tool)
    tool.toFile.setExecutable(true)
    assertEquals(findOnPath("mytool", s"relative\\dir;$dir", Os.Windows), Some(tool))
    // The bare, extensionless name is not a Windows executable and is never a candidate.
    val bare = Files.createFile(dir.resolve("othertool"))
    bare.toFile.setExecutable(true)
    assertEquals(findOnPath("othertool", dir.toString, Os.Windows), None)

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
    // Absolute system directories only: a relative entry is the whole thing being kept out.
    assert(
      ScriptPath.split(":").forall(entry => entry.startsWith("/") && entry.length > 1),
      ScriptPath,
    )

  test("a future path canonicalizes through its nearest existing ancestor"):
    val base = Files.createTempDirectory("future-path").toRealPath()
    // Exists already: plain canonicalization.
    assertEquals(canonicalizedFuturePath(base), Right(base))
    // Does not exist yet: the missing tail is appended to the canonicalized ancestor.
    assertEquals(canonicalizedFuturePath(base.resolve("a/b/c")), Right(base.resolve("a/b/c")))
    // A symlinked ancestor resolves, so a comparison against the answer sees the real location.
    val real = Files.createDirectories(base.resolve("real"))
    val linked = Files.createSymbolicLink(base.resolve("linked"), real)
    assertEquals(
      canonicalizedFuturePath(linked.resolve("missing/tail")),
      Right(real.resolve("missing/tail")),
    )
    // `..` in the spelling is normalized before the walk, not left for the filesystem.
    assertEquals(canonicalizedFuturePath(base.resolve("a/../b")), Right(base.resolve("b")))
    // A dangling symlink is presence, not absence: `exists` would follow it, call it missing, and
    // hand it back as an unchecked "future" component for a concurrent writer to materialize
    // after validation. NOFOLLOW discovery finds the link itself, and toRealPath then refuses it.
    val dangling = Files.createSymbolicLink(base.resolve("dangling"), base.resolve("nowhere"))
    assert(canonicalizedFuturePath(dangling).isLeft)
    assert(canonicalizedFuturePath(dangling.resolve("tail")).isLeft)

  test("the file lock serializes bodies across processes and runs its body inline"):
    val dir = Files.createTempDirectory("file-lock").toRealPath()
    val lock = dir.resolve(".lock")
    // The body runs and its value comes back; the lock file is created for the next taker.
    assertEquals(withFileLock(lock)(41 + 1), 42)
    assert(Files.exists(lock))
    // Cross-process exclusion is what FileChannel.lock means; what a unit test can hold is that a
    // second acquisition after release succeeds — a leaked lock would block it forever.
    assertEquals(withFileLock(lock)("again"), "again")

  test("a private file is never briefly readable, and never inherits a mode it replaced"):
    assume(posixPermissions(Files.createTempDirectory("perm-probe")), "POSIX permissions only")
    val dir = Files.createTempDirectory("private-write").toRealPath()

    val key = dir.resolve("ca.key")
    writePrivate(key, "PRIVATE KEY")
    assertEquals(modeOf(key), "rw-------")

    val readable = dir.resolve("bundle.crt")
    writeReadable(readable, "CERT")
    assertEquals(modeOf(readable), "rw-r--r--")

    // Replacing a file does not inherit its mode: a world-writable one planted at the path is
    // replaced, not opened, so nothing carries the old permissions into the new content.
    val planted = dir.resolve("leaf.key")
    Files.createFile(planted)
    Files.setPosixFilePermissions(planted, PosixFilePermissions.fromString("rw-rw-rw-"))
    writePrivate(planted, "PRIVATE KEY")
    assertEquals(modeOf(planted), "rw-------")
    assertEquals(Files.readString(planted), "PRIVATE KEY")

    // What the writes are made of stays inside them: a leftover temporary is a bind source's
    // directory growing a file no launch mounts, and a sign the rename never happened.
    assertEquals(
      Files.list(dir).iterator().asScala.map(_.getFileName.toString).toVector.sorted,
      Vector("bundle.crt", "ca.key", "leaf.key"),
    )

  test("a mount source's name survives every rewrite"):
    val dir = Files.createTempDirectory("replace-write").toRealPath()
    val mounted = dir.resolve("agents.md")
    writeReadable(mounted, "FIRST")

    // The failure this rules out: a rewrite that unlinks first leaves the name missing for as long
    // as it takes to produce the new content, and a launch of the same project assembling its
    // containers in that window dies on `statfs <path>: no such file or directory`.
    val seenMissing = java.util.concurrent.atomic.AtomicBoolean(false)
    val watcher = Thread: () =>
      while !Thread.currentThread().isInterrupted do
        if !Files.exists(mounted) then seenMissing.set(true)
    watcher.start()
    try (1 to 200).foreach(round => writeReadable(mounted, s"ROUND $round"))
    finally
      watcher.interrupt()
      watcher.join()

    assert(!seenMissing.get(), "the mount source vanished mid-rewrite")
    assertEquals(Files.readString(mounted), "ROUND 200")

  test("a rewrite that changes nothing leaves the mount source's inode alone"):
    // POSIX only, like the private-file test: the mode-planting step needs POSIX permissions, and
    // Windows answers no fileKey for the inode assertions to compare.
    assume(posixPermissions(Files.createTempDirectory("perm-probe")), "POSIX permissions only")
    val dir = Files.createTempDirectory("unchanged-write").toRealPath()
    val mounted = dir.resolve("agents.md")

    def inode(): AnyRef =
      Files.readAttributes(mounted, classOf[java.nio.file.attribute.BasicFileAttributes]).fileKey

    writeReadable(mounted, "POLICY")
    val first = inode()

    // What a running session pays for: the replacement is what its bind mount does not survive
    // through a podman machine, so identical content must not reach the rename at all.
    writeReadable(mounted, "POLICY")
    assertEquals(inode(), first, "an unchanged write replaced the file a live session had mounted")

    // A mode planted on it is a change like any other: identical content does not exempt it.
    Files.setPosixFilePermissions(mounted, PosixFilePermissions.fromString("rw-rw-rw-"))
    writeReadable(mounted, "POLICY")
    assertEquals(modeOf(mounted), "rw-r--r--")

    val corrected = inode()
    writeReadable(mounted, "POLICY 2")
    assertNotEquals(inode(), corrected)
    assertEquals(Files.readString(mounted), "POLICY 2")
