// State-file replacement must preserve permissions and keep mount-source names present.
// Path resolution and lock release are checked here; DirectoryStreamsTest checks descriptor lifetime.

package agentsandbox.launcher

import java.nio.file.{Files, Path}
import java.nio.file.attribute.PosixFilePermissions

import FileHelper.*

class FileHelperTest extends munit.FunSuite:

  private def modeOf(path: Path): String =
    PosixFilePermissions.toString(Files.getPosixFilePermissions(path))

  test("a stamped entry is its own validation, so an interleaved pair misses rather than mixes"):
    // Concurrent launches of one project under different session options write the ruleset
    // cache without a lock. With the stamp in a file of its own, one launch's content could end up
    // under the other's stamp and stay there; with it inside each file, the pairing a caller
    // requires does not match and the cache re-derives.
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

  test("the file lock returns the body's result and can be acquired again after release"):
    val dir = Files.createTempDirectory("file-lock").toRealPath()
    val lock = dir.resolve(".lock")
    assertEquals(withFileLock(lock)(41 + 1), 42)
    assert(Files.exists(lock))
    // Cross-process exclusion is FileChannel's contract; this test checks the wrapper's release
    // by acquiring again, which a leaked lock would prevent.
    assertEquals(withFileLock(lock)("again"), "again")

  test("state-file writes set the required permissions and correct a planted mode"):
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

    // A failed rename can leave a temporary beside the bind source, where no launch mounts it;
    // successful writes must leave no such files behind either.
    assertEquals(
      directoryEntries(dir).map(_.getFileName.toString).sorted,
      Vector("bundle.crt", "ca.key", "leaf.key"),
    )

  test("a tree holding a read-only file is deleted"):
    // FileHelper.deleteEntry has the Windows refusal. POSIX asks the directory alone, so there
    // this tree is deleted with or without the retry.
    val tree = Files.createTempDirectory("delete-read-only")
    val run = Files.createDirectories(tree.resolve("run-0"))
    val file = Files.writeString(run.resolve("cacerts"), "x")
    assert(file.toFile.setReadOnly())
    deleteRecursively(tree)
    assert(!Files.exists(tree))

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
    // POSIX only: planting a mode needs POSIX permissions, and
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
