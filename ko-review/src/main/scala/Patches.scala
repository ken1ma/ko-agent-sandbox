package koreview

import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, LinkOption, Path, StandardCopyOption}
import java.security.MessageDigest
import scala.collection.mutable

/** A turn's start as its patches record it: a commit, or an empty tree without one, then each turn's `start.patch` in
  * order. ko-review/doc/design.md, "The patches", gives the reasons for the rules here. */
final case class Chain(commit: Option[String], patches: Vector[Path])

object Patches:

  /** The leading components of a patch's names: `a/old/` and `b/new/`. */
  private val Strip = 2

  /** Writes the patch from `from` to the worktree's current files to `target`. `fromEntries` is the manifest of the
    * turn that `from` ends with, or None when `from` is a commit alone. */
  def write(
      git: Git,
      root: Path,
      from: Chain,
      fromEntries: Option[Map[String, String]],
      observation: Observation,
      target: Path,
  ): Unit =
    // Neither side holds a nested repository or the files in it: a rebuild has no content for them, and the copy of
    // the current files skips them. So the patch records a file that becomes, or becomes part of, a nested
    // repository as deleted, and one that stops being one as added.
    val changed = fromEntries match
      case Some(entries) => Observation.changes(entries, observation.entries)
      case None => changedSinceCommit(git, root, from.commit, observation)
    val scratch = Files.createTempDirectory("ko-review-patch-")
    try
      val old = Files.createDirectory(scratch.resolve("old"))
      val current = Files.createDirectory(scratch.resolve("new"))
      rebuild(git, root, from, changed.toSet, old)
      for path <- changed do copyCurrent(git, root, path, observation, current)
      ReviewFiles.writeBytes(target, git.diffDirectories(scratch, "old", "new"))
    finally delete(scratch)

  /** Rebuilds the files of `paths` at the end of `chain` under `into`, and returns the paths left out: a binary file
    * that a patch changed, whose content no patch holds. */
  def rebuild(git: Git, root: Path, chain: Chain, paths: Set[String], into: Path): Set[String] =
    chain.commit.foreach(commit => writeCommit(git, root, commit, paths, into))
    val leftOut = mutable.Set.empty[String]
    for patch <- chain.patches do
      val applicable = git.sections(into, Files.readAllBytes(patch), Strip).filter(section => paths(section.path))
        .filter: section =>
          if section.binary then
            leftOut += section.path
            Files.deleteIfExists(into.resolve(section.path)) // its content here is stale
            false
          else if leftOut(section.path) then
            // A later patch can hold the file whole again, as after a binary file becomes text.
            if section.createsFile then leftOut -= section.path
            section.createsFile
          else true
      git.apply(into, applicable.flatMap(_.bytes).toArray, Strip)
    leftOut.toSet

  /** Every path that `chain` holds: the commit's files and each path a patch names. */
  def paths(git: Git, root: Path, chain: Chain): Set[String] =
    val committed = chain.commit.toSeq.flatMap(git.tree(root, _)).filter(_.kind == "blob").map(_.path)
    val scratch = Path.of(System.getProperty("java.io.tmpdir"))
    val patched = chain.patches.flatMap(patch => git.sections(scratch, Files.readAllBytes(patch), Strip).map(_.path))
    (committed ++ patched).toSet

  /** Copies the current file at `path` under `into`, checking it against the observation, so that a file edited after
    * the scan cannot enter the patch. A path without an entry, such as a committed file that is now ignored and
    * untracked, and a nested repository are absent from the turn's start. */
  def copyCurrent(git: Git, root: Path, path: String, observation: Observation, into: Path): Unit =
    val source = root.resolve(path)
    if observation.entries.contains(path) && !observation.repositories.contains(path) then
      val target = into.resolve(path)
      Files.createDirectories(target.getParent)
      if Files.isSymbolicLink(source) then Posix.symlink(Posix.readlink(source), target)
      else if Files.exists(source, LinkOption.NOFOLLOW_LINKS) then
        Files.copy(source, target, LinkOption.NOFOLLOW_LINKS, StandardCopyOption.COPY_ATTRIBUTES)
      val copied = Observation.entry(git, target).map((_, bytes) => Observation.sha256Hex(bytes))
      if copied != observation.entries.get(path) then
        throw ReviewError(
          "WORKTREE_CHANGED_DURING_REVIEW",
          s"$path changed while the helper recorded the turn's start; review again",
          io.circe.JsonObject("paths" -> io.circe.Json.arr(io.circe.Json.fromString(path))),
        )

  /** The paths whose bytes on disk differ from their blob in `commit`, or that exist on one side only. A blob is
    * stored as it was committed, which no later attribute or filter setting changes. */
  private def changedSinceCommit(git: Git, root: Path, commit: Option[String], observation: Observation)
      : Vector[String] =
    val committed = commit.toSeq.flatMap(git.tree(root, _)).filter(_.kind == "blob").map(entry => entry.path -> entry)
      .toMap
    val format = git.objectFormat(root)
    (committed.keySet ++ observation.entries.keySet).toVector.sorted.filter: path =>
      (committed.get(path), observation.entries.get(path)) match
        case (Some(entry), Some(_)) => !blobOf(root.resolve(path), format).contains((entry.mode, entry.oid))
        case _ => true

  /** The mode and blob id that `git hash-object --no-filters` would give the file, or None for a path that is not a
    * file or a symlink. */
  private def blobOf(path: Path, format: String): Option[(String, String)] =
    val file =
      if Files.isSymbolicLink(path) then Some("120000" -> Posix.readlink(path))
      else if Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) then
        Some((if Posix.ownerExecutable(path) then "100755" else "100644") -> Files.readAllBytes(path))
      else None
    file.map: (mode, content) =>
      val digest = MessageDigest.getInstance(if format == "sha256" then "SHA-256" else "SHA-1")
      digest.update(s"blob ${content.length}\u0000".getBytes(UTF_8))
      mode -> Observation.hex(digest.digest(content))

  private def writeCommit(git: Git, root: Path, commit: String, paths: Set[String], into: Path): Unit =
    val entries = git.tree(root, commit).filter(entry => entry.kind == "blob" && paths(entry.path))
    val contents = git.blobs(root, entries.map(_.oid))
    for entry <- entries do
      val target = into.resolve(entry.path)
      Files.createDirectories(target.getParent)
      if entry.mode == "120000" then Posix.symlink(contents(entry.oid), target)
      else
        Files.write(target, contents(entry.oid))
        if entry.mode == "100755" then target.toFile.setExecutable(true, false): Unit

  def delete(directory: Path): Unit =
    if Files.exists(directory, LinkOption.NOFOLLOW_LINKS) then
      scala.util.Using.resource(Files.walk(directory)): paths =>
        paths.sorted(java.util.Comparator.reverseOrder()).forEach(path => Files.deleteIfExists(path): Unit)
