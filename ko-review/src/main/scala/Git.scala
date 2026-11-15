package koreview

import java.io.{ByteArrayOutputStream, InputStream}
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path}

/** Runs git for the helper. The object uses no ko-review type, so that it can move into a library of its own.
  *
  * Every call takes `Git.Settings` through `GIT_CONFIG_COUNT`, which ranks above every configuration file as `git -c`
  * does. A call inside a repository still reads the user's configuration for what the settings leave alone, such as
  * `core.excludesFile`, which decides the untracked files that `ls-files` lists. An isolated call reads no system or
  * global file and finds no repository, so nothing of the user's changes what a patch stores or a rebuild writes.
  */
final class Git(program: Path, environment: Map[String, String]):
  import Git.*

  /** Runs `git args` in `directory`. A status other than 0, or than those in `accepted`, throws `Git.Failure`. An
    * interrupt kills git and propagates. */
  def run(
      directory: Path,
      args: Seq[String],
      stdin: Array[Byte] = Array.emptyByteArray,
      isolated: Boolean = false,
      accepted: Set[Int] = Set(0),
      extraEnvironment: Map[String, String] = Map.empty,
  ): Completed =
    val command = program.toString +: args
    val builder = ProcessBuilder(command*).directory(directory.toFile)
    val variables = builder.environment()
    variables.clear()
    environment.foreach((name, value) => variables.put(name, value))
    if isolated then
      environment.keys.filter(_.startsWith("GIT_")).foreach(variables.remove)
      variables.put("GIT_CONFIG_NOSYSTEM", "1")
      variables.put("GIT_CONFIG_GLOBAL", "/dev/null")
      // git looks for no repository above the directory, which holds none.
      variables.put("GIT_CEILING_DIRECTORIES", directory.toAbsolutePath.getParent.toString)
    extraEnvironment.foreach((name, value) => variables.put(name, value))
    variables.put("GIT_CONFIG_COUNT", Settings.size.toString)
    Settings.zipWithIndex.foreach:
      case ((key, value), i) =>
        variables.put(s"GIT_CONFIG_KEY_$i", key)
        variables.put(s"GIT_CONFIG_VALUE_$i", value)
    val process = builder.start()
    val stdout = collect(process.getInputStream)
    val stderr = collect(process.getErrorStream)
    val writer = Thread.ofVirtual().start: () =>
      try
        process.getOutputStream.write(stdin)
        process.getOutputStream.close()
      catch case _: java.io.IOException => () // git stopped reading
    val status =
      try process.waitFor()
      catch
        case ex: InterruptedException =>
          process.destroyForcibly()
          throw ex
    writer.join()
    val completed = Completed(status, stdout.result(), stderr.result())
    if !accepted.contains(status) then throw Failure(args, status, completed.stderrText)
    completed

  def toplevel(directory: Path): Option[Path] =
    val completed = run(directory, Seq("rev-parse", "--show-toplevel"), accepted = Set(0, 128))
    Option.when(completed.status == 0)(Path.of(completed.stdoutText.stripSuffix("\n")).toRealPath())

  /** HEAD's commit id, or None while HEAD is unborn. */
  def head(root: Path): Option[String] = resolveCommit(root, "HEAD")

  def resolveCommit(root: Path, ref: String): Option[String] =
    val completed = run(root, Seq("rev-parse", "--verify", "--quiet", ref + "^{commit}"), accepted = Set(0, 1, 128))
    Option.when(completed.status == 0)(completed.stdoutText.trim)

  /** The repository's object format: `sha1` or `sha256`. */
  def objectFormat(root: Path): String = run(root, Seq("rev-parse", "--show-object-format")).stdoutText.trim

  /** Every file Git would review: tracked, or untracked and not ignored. A nested repository is one path. */
  def reviewablePaths(root: Path): Seq[String] =
    paths(run(root, Seq("ls-files", "-z", "--cached", "--others", "--exclude-standard")))

  def untrackedPaths(root: Path): Seq[String] =
    paths(run(root, Seq("ls-files", "-z", "--others", "--exclude-standard")))

  def indexPaths(root: Path): Seq[String] = paths(run(root, Seq("ls-files", "-z")))

  /** The paths whose working-tree content differs from `commit`. Renames are off: git detects a rename only once it is
    * staged, so staging or unstaging a rename would change the answer without changing a file. */
  def pathsChangedSince(root: Path, commit: String): Seq[String] =
    paths(run(root, Seq("diff", "--name-only", "-z", "--no-renames") ++ ComparisonOptions :+ commit))

  /** Whether the working tree differs from `commit`. */
  def differsFrom(root: Path, commit: String): Boolean =
    run(root, Seq("diff", "--quiet") ++ ComparisonOptions :+ commit, accepted = Set(0, 1)).status == 1

  /** Every entry of `commit`'s tree. */
  def tree(root: Path, commit: String): Seq[TreeEntry] =
    split(run(root, Seq("ls-tree", "-r", "-z", "--full-tree", commit)).stdout).map: record =>
      val text = String(record, UTF_8)
      val tab = text.indexOf('\t')
      val Array(mode, kind, oid) = text.substring(0, tab).split(' ')
      TreeEntry(mode, kind, oid, text.substring(tab + 1))

  /** The stored bytes of each blob, with no filter applied. */
  def blobs(root: Path, oids: Seq[String]): Map[String, Array[Byte]] =
    if oids.isEmpty then Map.empty
    else
      val distinct = oids.distinct
      val request = distinct.mkString("", "\n", "\n").getBytes(UTF_8)
      val output = run(root, Seq("cat-file", "--batch"), stdin = request).stdout
      var offset = 0
      distinct.map: oid =>
        val headerEnd = output.indexOf('\n'.toByte, offset)
        val header = String(output, offset, headerEnd - offset, UTF_8).split(' ')
        if header.length != 3 then
          throw Failure(Seq("cat-file", "--batch"), 0, s"no blob $oid: ${header.mkString(" ")}")
        val size = header(2).toInt
        val content = java.util.Arrays.copyOfRange(output, headerEnd + 1, headerEnd + 1 + size)
        offset = headerEnd + 1 + size + 1
        oid -> content
      .toMap

  /** The patch from directory `from` to directory `to`, both relative to `directory`, with `a/` and `b/` before their
    * names. */
  def diffDirectories(directory: Path, from: String, to: String, options: Seq[String] = Nil): Array[Byte] =
    run(
      directory,
      Seq("diff", "--no-index", "--no-color", "--no-renames", "--no-ext-diff", "--no-textconv", "--src-prefix=a/",
        "--dst-prefix=b/") ++ options ++ Seq("--", from, to),
      isolated = true,
      accepted = Set(0, 1),
    ).stdout

  /** `git diff` from the files under `from` to those under `to`, as between two commits: each directory becomes a
    * tree in a repository of its own under `scratch`, so the output names the files as a diff of the worktree would. */
  def diffTrees(scratch: Path, from: Path, to: Path, options: Seq[String]): Array[Byte] =
    val repository = scratch.resolve("repository")
    run(scratch, Seq("init", "-q", "--bare", repository.toString), isolated = true)
    // Even an isolated add reads rebuilt .gitattributes; info/attributes overrides its content conversions.
    Files.writeString(repository.resolve("info/attributes"), "* -text -ident -filter !working-tree-encoding\n")
    def tree(files: Path, name: String): String =
      val variables = Map("GIT_DIR" -> repository.toString, "GIT_WORK_TREE" -> files.toString,
        "GIT_INDEX_FILE" -> scratch.resolve(s"$name.index").toString)
      // -f: a rebuilt .gitignore must not leave out the files it names
      run(files, Seq("add", "-A", "-f", "."), isolated = true, extraEnvironment = variables)
      run(files, Seq("write-tree"), isolated = true, extraEnvironment = variables).stdoutText.trim
    val (fromTree, toTree) = (tree(from, "from"), tree(to, "to"))
    run(scratch, Seq("--git-dir", repository.toString, "diff", "--no-color", "--no-ext-diff", "--no-textconv") ++
      options ++ Seq(fromTree, toTree, "--"), isolated = true, accepted = Set(0, 1)).stdout

  /** Each file's section of `patch`, in order, with its path after `strip` leading components. */
  def sections(directory: Path, patch: Array[Byte], strip: Int): Seq[PatchSection] =
    if patch.isEmpty then Nil
    else
      val numstat = split(run(directory, Seq("apply", "--numstat", "-z", s"-p$strip"), stdin = patch, isolated = true)
        .stdout)
      val starts = sectionStarts(patch)
      if starts.size != numstat.size then
        throw Failure(Seq("apply", "--numstat"), 0, s"${starts.size} sections and ${numstat.size} numstat records")
      numstat.zipWithIndex.map: (record, i) =>
        val Array(added, _, path) = String(record, UTF_8).split("\t", 3)
        val end = if i + 1 < starts.size then starts(i + 1) else patch.length
        PatchSection(path, added == "-", java.util.Arrays.copyOfRange(patch, starts(i), end))

  /** Applies `patch` to the files under `directory`, with `strip` leading components removed from its names. */
  def apply(directory: Path, patch: Array[Byte], strip: Int): Unit =
    if patch.nonEmpty then
      run(directory, Seq("apply", "--whitespace=nowarn", "--allow-empty", s"-p$strip"), stdin = patch, isolated = true)

object Git:

  /** The settings that shape the output the callers parse. */
  val Settings: Seq[(String, String)] = Seq(
    "core.quotePath" -> "false",
    "color.ui" -> "false",
    "diff.noprefix" -> "false",
    "diff.mnemonicPrefix" -> "false",
    "diff.relative" -> "false",
    "diff.suppressBlankEmpty" -> "false",
  )

  /** An external diff driver, textconv or submodule setting could hide a change from a comparison. */
  private val ComparisonOptions = Seq("--no-ext-diff", "--no-textconv", "--ignore-submodules=none")

  final case class Completed(status: Int, stdout: Array[Byte], stderr: Array[Byte]):
    def stdoutText: String = String(stdout, UTF_8)
    def stderrText: String = String(stderr, UTF_8)

  final class Failure(val args: Seq[String], val status: Int, val stderr: String)
      extends Exception(s"git ${args.mkString(" ")} failed with status $status")

  final case class TreeEntry(mode: String, kind: String, oid: String, path: String)

  final case class PatchSection(path: String, binary: Boolean, bytes: Array[Byte]):
    def createsFile: Boolean =
      String(bytes, UTF_8).linesIterator.takeWhile(line => !line.startsWith("@@")).exists(_.startsWith("new file mode"))

  private def collect(stream: InputStream): Collected =
    val collected = Collected()
    collected.thread = Thread.ofVirtual().start(() => stream.transferTo(collected.buffer): Unit)
    collected

  private final class Collected:
    val buffer = ByteArrayOutputStream()
    var thread: Thread = null
    def result(): Array[Byte] =
      thread.join()
      buffer.toByteArray

  private def split(output: Array[Byte]): Seq[Array[Byte]] =
    val records = Vector.newBuilder[Array[Byte]]
    var start = 0
    for i <- output.indices if output(i) == 0 do
      records += java.util.Arrays.copyOfRange(output, start, i)
      start = i + 1
    records.result()

  /** NUL-separated paths, without the slash that names an untracked nested repository, sorted and distinct. */
  private def paths(completed: Completed): Seq[String] =
    split(completed.stdout).map(utf8Path).map(_.stripSuffix("/")).filter(_.nonEmpty).distinct.sorted

  /** A path as the JVM names files, or `UndecodablePath` for one that is not UTF-8, which the JVM cannot open. */
  private def utf8Path(record: Array[Byte]): String =
    try UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(record)).toString
    catch case _: java.nio.charset.CharacterCodingException => throw UndecodablePath(record)

  final class UndecodablePath(val bytes: Array[Byte])
      extends Exception(s"a file name that is not UTF-8: ${String(bytes, UTF_8)}")

  /** The offsets of the lines that start with `diff --git `. No other line of a patch starts with `d`: hunk lines
    * start with a space, `+`, `-` or a backslash. */
  private def sectionStarts(patch: Array[Byte]): Seq[Int] =
    val marker = "diff --git ".getBytes(UTF_8)
    def startsAt(offset: Int) =
      offset + marker.length <= patch.length && marker.indices.forall(i => patch(offset + i) == marker(i))
    (0 until patch.length).filter(offset => (offset == 0 || patch(offset - 1) == '\n'.toByte) && startsAt(offset))
