// Shared file operations have no dependency on launcher policy or command execution, so callers
// can use them without a dependency cycle.

package agentsandbox.launcher

import java.io.{IOException, UncheckedIOException}
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, StandardCopyOption}
import java.nio.file.attribute.{PosixFilePermission, PosixFilePermissions}
import scala.jdk.CollectionConverters.*
import scala.util.Using

object FileHelper:

  def readIfPresent(path: Path): Option[String] =
    if Files.isRegularFile(path) then Some(Files.readString(path)) else None

  /**
   * The real path a possibly-not-yet-created `path` will occupy: the deepest existing ancestor is
   * canonicalized and the missing tail re-appended. A plain `toRealPath` fails on a path that does
   * not exist yet — which the state root is on every first launch — and comparing the symbolic
   * spelling instead would let a symlinked ancestor place it somewhere the comparison never sees.
   * Left when the existing ancestor cannot be resolved: an unverified spelling handed back
   * instead would bypass whatever containment comparison the caller makes with the answer.
   */
  def canonicalizedFuturePath(path: Path): Either[String, Path] =
    val absolute = path.toAbsolutePath.normalize()
    // NOFOLLOW attributes, not Files.exists: exists follows links, so a dangling symlink would
    // read as absent and pass into the "future" tail unchecked — a concurrent writer could
    // materialize its target after validation — and it folds every other I/O failure into false.
    // Only NotFound means missing; anything else refuses.
    def presence(candidate: Path): Either[String, Boolean] =
      try
        Files.readAttributes(
          candidate,
          classOf[java.nio.file.attribute.BasicFileAttributes],
          java.nio.file.LinkOption.NOFOLLOW_LINKS,
        )
        Right(true)
      catch
        case _: java.nio.file.NoSuchFileException => Right(false)
        case ex: IOException                      => Left(s"cannot inspect $candidate: $ex")
    @scala.annotation.tailrec
    def firstPresent(candidate: Path, tail: List[Path]): Either[String, (Path, List[Path])] =
      presence(candidate) match
        case Left(reason) => Left(reason)
        case Right(true)  => Right((candidate, tail))
        case Right(false) =>
          Option(candidate.getParent) match
            case Some(parent) => firstPresent(parent, candidate.getFileName :: tail)
            case None         => Right((candidate, tail))
    firstPresent(absolute, Nil).flatMap: (existing, tail) =>
      // toRealPath follows, so a dangling symlink found present above is rejected right here
      // rather than adopted as a base.
      try Right(tail.foldLeft(existing.toRealPath())(_.resolve(_)))
      catch case ex: IOException => Left(s"cannot resolve $existing to a real path: $ex")

  /**
   * Run `body` holding an exclusive inter-process lock on `lockFile`.
   * What it serializes is check-then-act over shared files: two launches that both find state
   * missing or stale otherwise interleave their writes, and the survivors need not belong
   * together — a CA key from one launch beside the other's certificate.
   */
  def withFileLock[A](lockFile: Path)(body: => A): A =
    Files.createDirectories(lockFile.toAbsolutePath.getParent)
    val channel = java.nio.channels.FileChannel.open(
      lockFile,
      java.nio.file.StandardOpenOption.CREATE,
      java.nio.file.StandardOpenOption.WRITE,
    )
    try
      val lock = channel.lock()
      try body
      finally lock.release()
    finally channel.close()

  def firstLine(path: Path): String =
    readIfPresent(path).map(_.linesIterator.nextOption().getOrElse("")).getOrElse("")

  /**
   * A stamped cache entry: its content when the file's own first line is `stamp`, None otherwise.
   * The stamp travels inside the file rather than in one beside it because separate files are
   * atomic individually and race as a set — a launch interleaved between writing its content and
   * writing its stamp leaves a pairing neither launch computed, and that pairing is sticky, held
   * until a later launch rewrites it. A caller reading several of these requires every one to
   * match, so an interleaving is a miss that re-derives rather than a mixture that persists.
   */
  def stampedEntry(path: Path, stamp: String): Option[String] =
    readIfPresent(path).map(_.stripLineEnd).flatMap: text =>
      val newline = text.indexOf('\n')
      val (first, rest) =
        if newline < 0 then (text, "") else (text.take(newline), text.drop(newline + 1))
      Option.when(first == stamp)(rest)

  def writeStamped(path: Path, stamp: String, content: String): Unit =
    writeReadable(path, s"$stamp\n$content\n")

  // -------------------------------------------------------------------------
  // Private files
  //
  // Written with owner-only permissions where the filesystem has POSIX
  // permissions at all. On Windows nothing is needed: %LOCALAPPDATA% inherits
  // an ACL that already excludes other users.
  // -------------------------------------------------------------------------

  def posixPermissions(path: Path): Boolean =
    Files.getFileStore(path).supportsFileAttributeView("posix")

  def writePrivate(path: Path, content: String): Unit =
    writeWithMode(path, content.getBytes(StandardCharsets.UTF_8), "rw-------")

  def writeReadable(path: Path, content: String): Unit =
    writeWithMode(path, content.getBytes(StandardCharsets.UTF_8), "rw-r--r--")

  /** For the one state file that is not text: the JDK keystore JdkTrust merges. */
  def writeReadable(path: Path, content: Array[Byte]): Unit =
    writeWithMode(path, content, "rw-r--r--")

  /**
   * Written beside the target and renamed onto it, never written at the target itself. Nearly
   * every file written through here feeds a container mount — as the shared source the per-run
   * copies are taken from (AgentSandboxLauncher, the locked TLS derivation), or per-run itself,
   * like the audit log — and a launch of the same project may be copying or assembling at this
   * moment: a name that disappears even briefly fails that launch, and a name that exists holding
   * half a file is worse. Rename is what leaves neither state visible. The temporary has a
   * generated name, so two launches racing here cannot collide on it.
   * A write that would change neither the content nor the mode is skipped: a cache stamp that
   * misses on identical output must not replace the shared source's inode during another launch's
   * copy. A real change replaces the inode and reaches only the runs that copy after it — a mount
   * cannot follow a file out from under it (SECURITY.md, "The read-only `.git` mounts under
   * `WORKSPACE_GUARD=none`", has the measurement), which is why containers mount per-run copies
   * rather than these files.
   *
   * The mode is requested at creation and set again after the write, and both halves earn their
   * place. Creating with it is what leaves no window: a file created under the umask and chmodded
   * afterwards holds its content at 0644 for as long as the write takes, and what `writePrivate`
   * writes is the CA private key. Setting it again is what makes the mode exact: umask can only
   * clear bits, so a strict one would otherwise leave `writeReadable` narrower than the container
   * reading that file needs. On Windows the attribute is refused and the file is created plainly
   * (the section banner has why nothing is needed there).
   */
  private def writeWithMode(path: Path, content: Array[Byte], mode: String): Unit =
    val permissions = PosixFilePermissions.fromString(mode)
    if !alreadyWritten(path, content, permissions) then replaceWithMode(path, content, permissions)

  /**
   * Whether the file at `path` already is what the write would leave — content and mode both, so a
   * mode planted on a bind source is still corrected. An unreadable or vanishing file is not it:
   * another launch may be replacing this very path, and the write is the answer to that.
   */
  private def alreadyWritten(
    path: Path,
    content: Array[Byte],
    permissions: java.util.Set[PosixFilePermission],
  ): Boolean =
    try
      Files.isRegularFile(path)
        && java.util.Arrays.equals(Files.readAllBytes(path), content)
        && (!posixPermissions(path) || Files.getPosixFilePermissions(path) == permissions)
    catch case _: IOException => false

  private def replaceWithMode(
    path: Path,
    content: Array[Byte],
    permissions: java.util.Set[PosixFilePermission],
  ): Unit =
    val directory = path.toAbsolutePath.getParent
    val prefix = path.getFileName.toString + "."
    val temp =
      try
        Files.createTempFile(directory, prefix, ".tmp", PosixFilePermissions.asFileAttribute(permissions))
      catch case _: UnsupportedOperationException => Files.createTempFile(directory, prefix, ".tmp")
    try
      Files.write(temp, content)
      if posixPermissions(temp) then Files.setPosixFilePermissions(temp, permissions)
      moveReplacing(temp, path)
    catch
      case ex: Throwable =>
        Files.deleteIfExists(temp)
        throw ex

  /**
   * ATOMIC_MOVE alone: it replaces an existing target on both POSIX and Windows, and pairing it
   * with REPLACE_EXISTING is what some implementations refuse. Retried briefly on Windows's
   * transient sharing violations — replacing a file a concurrent reader holds open answers
   * AccessDenied there, and every file written through here is read concurrently by design:
   * another launch copying it, a container mounting it. POSIX never takes the retry.
   */
  @scala.annotation.tailrec
  private def moveReplacing(temp: Path, path: Path, attempts: Int = 40): Unit =
    val moved =
      try
        Files.move(temp, path, StandardCopyOption.ATOMIC_MOVE)
        true
      catch
        case _: java.nio.file.AccessDeniedException if attempts > 0 =>
          Thread.sleep(25)
          false
    if !moved then moveReplacing(temp, path, attempts - 1)

  def directoryEntries(path: Path): Vector[Path] =
    Using.resource(Files.list(path)): entries =>
      entries.iterator().asScala.toVector

  /** Every failure is an IOException: `Files.walk` reports a directory it cannot open as an
    * UncheckedIOException during iteration, which a caller's IOException handling — a counted reset
    * step — would otherwise miss. */
  def deleteRecursively(path: Path): Unit =
    if Files.exists(path) then
      try
        Using.resource(Files.walk(path)): entries =>
          entries.sorted(java.util.Comparator.reverseOrder()).iterator().asScala.foreach(Files.delete)
      catch case ex: UncheckedIOException => throw ex.getCause
