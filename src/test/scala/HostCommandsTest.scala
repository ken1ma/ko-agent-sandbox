// How the launcher runs host executables and what its scripts may resolve: trusted-path lookup,
// and the fixed PATH every generated script declares before anything else. Then how it writes the
// state files those runs mount: the mode they are never briefly without, and the name they are
// never briefly missing.

package agentsandbox.launcher

import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import scala.jdk.CollectionConverters.*

import HostCommands.*
import KoAgentFs.*
import SandboxLifecycle.*

class HostCommandsTest extends munit.FunSuite:

  test("a stamped entry is its own validation, so an interleaved pair misses rather than mixes"):
    // Concurrent launches of one project under different authority selections write the policy
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
  // directories, which on a Windows runner carry their own ':' after the drive letter — the
  // string cannot be built there, not merely the branch untested. The Windows branch has its own
  // test, which runs everywhere.
  private val isWindows = scala.util.Properties.isWin

  private def modeOf(path: java.nio.file.Path): String =
    PosixFilePermissions.toString(Files.getPosixFilePermissions(path))

  test("executables resolve only through absolute PATH entries"):
    assume(!isWindows, "POSIX PATH strings cannot carry drive-letter directories")
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
    assume(!isWindows, "POSIX PATH strings cannot carry drive-letter directories")
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
    assume(!isWindows, "POSIX PATH strings cannot carry drive-letter directories")
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

  test("a future path canonicalizes through its nearest existing ancestor"):
    val base = Files.createTempDirectory("future-path").toRealPath()
    // Exists already: plain canonicalization.
    assertEquals(canonicalizedFuturePath(base), Right(base))
    // Does not exist yet: the missing tail rides on the canonicalized ancestor.
    assertEquals(canonicalizedFuturePath(base.resolve("a/b/c")), Right(base.resolve("a/b/c")))
    // A symlinked ancestor resolves, so a comparison against the answer sees the real location.
    val real = Files.createDirectories(base.resolve("real"))
    val linked = Files.createSymbolicLink(base.resolve("linked"), real)
    assertEquals(
      canonicalizedFuturePath(linked.resolve("missing/tail")),
      Right(real.resolve("missing/tail"))
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

    // The end state, and the reason the mode is also requested at creation: `Files.writeString`
    // alone would leave the key at the umask's mode for the length of the write.
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
      Vector("bundle.crt", "ca.key", "leaf.key")
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
