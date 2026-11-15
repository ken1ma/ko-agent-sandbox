package koreview

import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, LinkOption, NoSuchFileException, Path}
import java.security.MessageDigest
import scala.collection.immutable.TreeMap
import scala.collection.mutable

/** One scan of a worktree: HEAD's commit id, the hash of every reviewable file's entry, and the content digest.
  *
  * - An entry is a file's raw content with its executable bit, or a symlink's target. A nested repository, which Git
  *   lists as one path, is an entry too: the digest of its own files. Its HEAD is not content, so a commit inside it
  *   changes nothing here.
  * - The scan reads raw content because `git status` calls a file clean when its content after the clean filter
  *   matches the index, and so misses a change that a filter strips.
  * - An absent path has no entry, so staging a deletion or a rename changes nothing here.
  */
final case class Observation(head: Option[String], entries: TreeMap[String, String], repositories: Vector[String]):
  def contentDigest: String = Observation.digestOf(entries)

object Observation:

  def observe(git: Git, root: Path): Observation =
    val entries = TreeMap.newBuilder[String, String]
    val repositories = Vector.newBuilder[String]
    for path <- git.reviewablePaths(root) do
      entry(git, root.resolve(path)).foreach: (kind, text) =>
        entries += path -> sha256Hex(text)
        if kind == Kind.Repository then repositories += path
    Observation(git.head(root), entries.result(), repositories.result())

  /** The digest of a manifest's entries, sorted by path: the turn's content digest. */
  def digestOf(entries: collection.Map[String, String]): String =
    val digest = MessageDigest.getInstance("SHA-256")
    for (path, hash) <- entries.toSeq.sortBy(_._1) do digest.update(s"$path\u0000$hash\u0000".getBytes(UTF_8))
    "sha256:" + hex(digest.digest())

  /** The paths whose entry differs between two manifests, sorted. */
  def changes(before: collection.Map[String, String], after: collection.Map[String, String]): Vector[String] =
    (before.keySet ++ after.keySet).filter(path => before.get(path) != after.get(path)).toVector.sorted

  enum Kind:
    case File, Link, Repository, Directory, Other

  /** The entry of `path` as bytes to hash, or None when the path is absent. */
  def entry(git: Git, path: Path): Option[(Kind, Array[Byte])] =
    try
      val attributes = Files.readAttributes(path, classOf[java.nio.file.attribute.BasicFileAttributes],
        LinkOption.NOFOLLOW_LINKS)
      if attributes.isSymbolicLink then
        Some(Kind.Link -> ("link\u0000".getBytes(UTF_8) ++ Posix.readlink(path)))
      else if attributes.isDirectory then
        if Files.exists(path.resolve(".git"), LinkOption.NOFOLLOW_LINKS) then
          Some(Kind.Repository -> ("repository\u0000" + observe(git, path).contentDigest).getBytes(UTF_8))
        else Some(Kind.Directory -> "dir".getBytes(UTF_8))
      else if attributes.isRegularFile then
        // Git keeps no mode for an untracked file, so the executable bit comes from the file system.
        val executable = if Posix.ownerExecutable(path) then "x" else "-"
        Some(Kind.File -> s"file\u0000$executable\u0000${fileSha256Hex(path)}".getBytes(UTF_8))
      else Some(Kind.Other -> "other".getBytes(UTF_8))
    catch case _: NoSuchFileException => None

  def sha256Hex(bytes: Array[Byte]): String = hex(MessageDigest.getInstance("SHA-256").digest(bytes))

  private def fileSha256Hex(path: Path): String =
    val digest = MessageDigest.getInstance("SHA-256")
    val buffer = new Array[Byte](1 << 20)
    scala.util.Using.resource(Files.newInputStream(path)): stream =>
      var read = stream.read(buffer)
      while read >= 0 do
        digest.update(buffer, 0, read)
        read = stream.read(buffer)
    hex(digest.digest())

  def hex(bytes: Array[Byte]): String = bytes.map(byte => f"${byte & 0xff}%02x").mkString

/** The paths that the reviewer is told to look at: those that differ from a commit, plus the untracked ones; every
  * listed file before the first commit. One instance computes each commit's scope once, so that a command that judges
  * many reviews scans the worktree once.
  */
final class Scopes(git: Git, root: Path):
  private val computed = mutable.Map.empty[Option[String], Vector[String]]

  def against(commit: Option[String]): Vector[String] =
    computed.getOrElseUpdate(commit, {
      val listed = commit match
        case Some(id) => git.pathsChangedSince(root, id)
        case None => git.indexPaths(root)
      (git.untrackedPaths(root) ++ listed).distinct.sorted.toVector
    })
