// Shared file operations. The operations have no dependency on launcher policy or command
// execution, so callers can use them without a dependency cycle.

package agentsandbox.launcher

import java.io.{IOException, UncheckedIOException}
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, LinkOption, Path, StandardCopyOption}
import java.nio.file.attribute.{PosixFilePermission, PosixFilePermissions}
import scala.jdk.CollectionConverters.*
import scala.util.Using

object FileHelper:

  def readIfPresent(path: Path): Option[String] =
    if Files.isRegularFile(path) then Some(Files.readString(path)) else None

  /** readIfPresent, with an unreadable file answering None, for a file that another process may remove or replace at
    * any moment. */
  def readIfReadable(path: Path): Option[String] =
    try readIfPresent(path) catch case _: IOException => None

  /**
   * The real path that a possibly-not-yet-created `path` will occupy: the deepest existing ancestor is
   * canonicalized, and the missing tail is re-appended.
   * - A plain `toRealPath` fails on a path that does not exist yet, and the state root does not exist
   *   on every first launch.
   * - Comparing the symbolic spelling instead would let a symlinked ancestor place the path somewhere
   *   the comparison never sees.
   * - The result is Left when the existing ancestor cannot be resolved. An unverified spelling handed
   *   back instead would bypass whatever containment comparison the caller makes with the answer.
   */
  def canonicalizedFuturePath(path: Path): Either[String, Path] =
    val absolute = path.toAbsolutePath.normalize()
    // NOFOLLOW attributes, not Files.exists, for two reasons:
    // - exists follows links, so a dangling symlink would read as absent and pass into the "future"
    //   tail unchecked, and a concurrent writer could create its target after validation;
    // - exists folds every other I/O failure into false.
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
      // toRealPath follows links, so it rejects a dangling symlink found present above rather than
      // adopting the symlink as a base.
      try Right(tail.foldLeft(existing.toRealPath())(_.resolve(_)))
      catch case ex: IOException => Left(s"cannot resolve $existing to a real path: $ex")

  /** The path with its deepest existing ancestor resolved, so that a root reached through a symlink,
    * such as macOS's `/var`, compares equal to its real spelling whether or not the leaf exists. Unlike
    * canonicalizedFuturePath, this method leaves the path as spelled when an ancestor cannot be
    * resolved: it serves a comparison of two paths, not a containment check that grants. */
  def realized(path: Path): Path =
    val absolute = path.toAbsolutePath.normalize
    Iterator.iterate(absolute)(_.getParent).takeWhile(_ != null).find(Files.exists(_)) match
      case Some(existing) =>
        try existing.toRealPath().resolve(existing.relativize(absolute))
        catch case _: IOException => absolute
      case None => absolute

  /** The real path, or None when the path does not exist, an absence the caller classifies. */
  def realPath(path: Path): Option[Path] =
    try Some(path.toRealPath())
    catch case _: IOException => None

  def isExecutableFile(path: Path): Boolean = Files.isExecutable(path) && Files.isRegularFile(path)

  /**
   * Runs `body` holding an exclusive inter-process lock on `lockFile`. The lock serializes
   * check-then-act over shared files. Without the lock, two launches that both find state missing or
   * stale interleave their writes, and the surviving files need not belong together, such as a CA key
   * from one launch beside the other launch's certificate.
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
   * - The stamp travels inside the file rather than in a file beside it. Separate files are atomic
   *   individually but race as a set: a launch interleaved between writing its content and writing
   *   its stamp leaves a pairing neither launch computed. That pairing is sticky, held until a later
   *   launch rewrites it.
   * - A caller reading several of these entries requires every one to match, so an interleaving is a
   *   miss that re-derives rather than a mixture that persists.
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
  // These files are written with owner-only permissions where the filesystem has POSIX permissions at
  // all. On Windows nothing is needed: %LOCALAPPDATA% inherits an ACL that already excludes other users.
  // -------------------------------------------------------------------------

  def posixPermissions(path: Path): Boolean =
    Files.getFileStore(path).supportsFileAttributeView("posix")

  /** Creates the directory and its missing parents, and makes the directory itself owner-only where the
    * volume has POSIX permissions. */
  def createPrivateDirectories(path: Path): Unit =
    Files.createDirectories(path)
    if posixPermissions(path) then Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"))

  def writePrivate(path: Path, content: String): Unit =
    writeWithMode(path, content.getBytes(StandardCharsets.UTF_8), "rw-------")

  def writeReadable(path: Path, content: String): Unit =
    writeWithMode(path, content.getBytes(StandardCharsets.UTF_8), "rw-r--r--")

  /** For the one state file that is not text: the trust store RunOnHostInspection writes. */
  def writeReadable(path: Path, content: Array[Byte]): Unit =
    writeWithMode(path, content, "rw-r--r--")

  /**
   * Writes beside the target and renames onto it, never writing at the target itself.
   * - Nearly every file written through here feeds a container mount: as the shared source that the
   *   per-run copies are taken from (AgentSandboxLauncher, the locked TLS derivation), or per run
   *   itself, like the audit log.
   * - A launch of the same workspace may be copying or assembling at this moment. A name that
   *   disappears even briefly fails that launch, and a name that holds half a file is worse. Rename
   *   leaves neither state visible.
   * - The temporary file has a generated name, so two launches racing here cannot collide on it.
   *
   * A write that would change neither the content nor the mode is skipped: a cache stamp that misses
   * on identical output must not replace the shared source's inode during another launch's copy.
   * - A real change replaces the inode and reaches only the runs that copy after it, because a mount
   *   cannot follow a file out from under it.
   * - Measured on a macOS podman machine: a replaced source is stale in the container for about two
   *   seconds, then served without the mount's read-only option. Containers therefore mount per-run
   *   copies rather than these files.
   *
   * The mode is requested at creation and set again after the write, and both steps are needed.
   * - Creating the file with the mode leaves no window. A file created under the umask and chmodded
   *   afterwards holds its content at 0644 for as long as the write takes, and `writePrivate` writes
   *   the CA private key.
   * - Setting the mode again makes it exact. umask can only clear bits, so a strict umask would
   *   otherwise leave `writeReadable` narrower than the container that reads the file needs.
   * - On Windows, the attribute is refused and the file is created plainly (the section banner
   *   explains why nothing is needed there).
   */
  private def writeWithMode(path: Path, content: Array[Byte], mode: String): Unit =
    val permissions = PosixFilePermissions.fromString(mode)
    if !alreadyWritten(path, content, permissions) then replaceWithMode(path, content, permissions)

  /**
   * Whether the file at `path` already is what the write would leave, in content and mode both, so
   * that a mode planted on a bind source is still corrected. An unreadable or vanishing file does not
   * count: another launch may be replacing this very path, and the write is the answer to that.
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
   * Uses ATOMIC_MOVE alone: it replaces an existing target on both POSIX and Windows, and some
   * implementations refuse it paired with REPLACE_EXISTING.
   * - On Windows, the move is retried briefly on transient sharing violations. Replacing a file that a
   *   concurrent reader holds open answers AccessDenied there, and every file written through here is
   *   read concurrently by design: another launch copies it, or a container mounts it.
   * - POSIX never takes the retry.
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

  /**
   * Whether the regular file has another name (a hard link), or None where the host cannot say: the
   * file cannot be read, or kernel32 cannot open it. A write through the other name changes this file
   * in place. Windows has no `unix` attribute view, so kernel32 counts the names there.
   */
  def hasSecondName(file: Path): Option[Boolean] =
    try
      if !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) then Some(false)
      else if scala.util.Properties.isWin then FFMHelper.kernel32.numberOfLinks(file).map(_ > 1)
      else
        Files.getAttribute(file, "unix:nlink", LinkOption.NOFOLLOW_LINKS) match
          case links: Integer => Some(links > 1)
          case _              => Some(false)
    catch case _: (IOException | UnsupportedOperationException | IllegalArgumentException) => None

  def directoryEntries(path: Path): Vector[Path] =
    Using.resource(Files.list(path)): entries =>
      entries.iterator().asScala.toVector

  /** The entries of a directory, or none when the directory is absent, is something else, or is
    * unreadable. */
  def directoryEntriesIfAny(path: Path): Vector[Path] =
    try directoryEntries(path)
    catch case _: IOException => Vector.empty

  /** Reports every failure as an IOException. `Files.walk` reports a directory it cannot open as an
    * UncheckedIOException during iteration, which a caller's IOException handling, such as a counted
    * reset step, would otherwise miss. */
  def deleteRecursively(path: Path): Unit =
    if Files.exists(path) then
      try
        Using.resource(Files.walk(path)): entries =>
          entries.sorted(java.util.Comparator.reverseOrder()).iterator().asScala.foreach(deleteEntry)
      catch case ex: UncheckedIOException => throw ex.getCause

  /** Windows refuses to delete an entry with the read-only attribute, where POSIX checks only the
    * directory. A run's copy of `cacerts` met that refusal: the prepared store has no write bit
    * (JdkTrust), and attributes travel with the copy (AgentSandboxLauncher, `carried`). */
  private def deleteEntry(path: Path): Unit =
    try Files.delete(path)
    catch
      case ex: java.nio.file.AccessDeniedException =>
        val dos = Files.getFileAttributeView(
          path, classOf[java.nio.file.attribute.DosFileAttributeView], java.nio.file.LinkOption.NOFOLLOW_LINKS,
        )
        if dos == null || !dos.readAttributes().isReadOnly then throw ex
        dos.setReadOnly(false)
        Files.delete(path)
