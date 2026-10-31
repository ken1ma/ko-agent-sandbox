// The file rules as the launcher handles them (doc/file-rules.md):
// - the defaults and the workspace's .ko-agent-sandbox/file/rule;
// - their grammar and resolution;
// - the text that the filter daemon and the run-on-host profile receive.
//
// The launcher owns the grammar. The filter reads only the resolved form
// (ko-agent-fs/policy/src/rulefile.rs), and the Seatbelt profile renders that form
// (SeatbeltProfile.fileRuleFilters).

package agentsandbox.launcher

import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.Path

import HostCommands.Os

object FileRules:

  enum Word(val keyword: String):
    case ReadOnly extends Word("read-only")
    case Writable extends Word("writable")

  /** One rule line: a word and a name matching at any depth, `*` within one component. */
  case class Line(word: Word, name: String):
    def text: String = s"${word.keyword} $name"

  /**
   * What the resolved set holds beyond the rule lines: the paths that the filter's guard found,
   * relative to the workspace root and spelled as the host spells them.
   * - `readOnlyPaths` are directories and files served read-only as a whole.
   * - `pinnedPaths` are components pinned against rename, replacement and removal.
   * - `readOnlyUnder` holds `(directory, rest)` pairs. The directory is one that a symlink makes an
   *   interior component of a `read-only` line, and the line's rest is the pattern below it.
   */
  case class Resolved(
      lines: Vector[Line],
      readOnlyPaths: Vector[String],
      pinnedPaths: Vector[String],
      readOnlyUnder: Vector[(String, String)] = Vector.empty,
  ):
    /** The resolved text: the form the filter writes back and `--resolve` prints. */
    def text: String =
      (lines.map(_.text) ++ readOnlyPaths.map(path => s"read-only-path $path") ++
        pinnedPaths.map(path => s"pinned-path $path") ++
        readOnlyUnder.map((path, rest) => s"read-only-under $path $rest")).map(_ + "\n").mkString

  object Resolved:
    val Empty: Resolved = Resolved(Vector.empty, Vector.empty, Vector.empty)

  /** The resolved set the launcher wrote for the run-on-host runner and its commands. */
  def readResolved(file: Path): Either[String, Resolved] =
    try parseResolved(java.nio.file.Files.readString(file, UTF_8))
    catch case ex: java.io.IOException => Left(s"error: cannot read the file rules $file: ${ex.getMessage}")

  /**
   * The lines for `workspaceRoot` without the filter's guard. A host command gets these lines when no
   * launch handed it a resolved set, as in the acceptance test's own entry. The guard's paths, a
   * relocated hook directory among them, come only from a launch's mount or `--resolve`.
   */
  def ofWorkspace(workspaceRoot: Path): Either[String, Resolved] =
    readRuleFile(SandboxWorkspace.boundaryDirOf(workspaceRoot).resolve("file")).map: file =>
      Resolved(resolve(file.fold(Vector.empty[Line])(_(1))), Vector.empty, Vector.empty)

  /** The names that the filter's own rules govern, which a rule line cannot reach. The host command's
    * profile guards the same names (SeatbeltProfile), and the launcher's walks of the workspace enter
    * neither. */
  val GuardedComponents: Seq[String] = Seq(".git", ".ko-agent-sandbox")

  /**
   * The lines of `text`, with `origin` naming the text in a refusal. Comments and whitespace follow
   * egress/rule (EgressRules.normalizeRuleText). Every ambiguity refuses:
   * - a line that is not one word and one name;
   * - a `#` inside a token;
   * - an empty, `.` or `..` component;
   * - a character outside `a`–`z`, `0`–`9`, `.`, `_`, `-` and `*`;
   * - a `.git` or `.ko-agent-sandbox` component.
   */
  def parse(text: String, origin: String): Either[String, Vector[Line]] =
    val lines = EgressRules.normalizeRuleText(text).linesIterator.toVector
    val parsed = lines.map: line =>
      line.split(" ").toVector match
        case Vector(word, name) =>
          Word.values.find(_.keyword == word) match
            case None => Left(s"'$word' is not a word; a line is `read-only NAME` or `writable NAME`")
            case Some(known) => nameRefusal(name).toLeft(Line(known, name))
        case _ => Left("a line is one word and one name: `read-only NAME` or `writable NAME`")
    parsed.zip(lines).collectFirst { case (Left(why), line) => s"error: $origin: $line: $why" }
      .toLeft(parsed.collect { case Right(line) => line })

  private def nameRefusal(name: String): Option[String] =
    val components = name.split("/", -1).toVector
    if components.exists(_.isEmpty) then
      Some("a name has no leading, trailing or doubled `/`")
    else if components.exists(component => component == "." || component == "..") then
      Some("a name has no `.` or `..` component")
    else if !name.forall(ch => (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || "._-*/".contains(ch)) then
      Some(
        "a name holds only a-z, 0-9, `.`, `_`, `-` and the wildcard `*`; the filter folds case, so " +
          "write it lowercase",
      )
    else
      components.find(GuardedComponents.contains).map: guarded =>
        s"`$guarded` is the filter's own to protect, and no file rule reaches it"

  /** The launcher's defaults (`agentsandbox/file-rule-defaults`), before the workspace's lines. */
  lazy val Defaults: Vector[Line] =
    val stream = getClass.getResourceAsStream("/agentsandbox/file-rule-defaults")
    if stream == null then throw IllegalStateException("the launcher has no file-rule-defaults resource")
    val text =
      try String(stream.readAllBytes(), UTF_8)
      finally stream.close()
    parse(text, "the launcher's file-rule-defaults").fold(why => throw IllegalStateException(why), identity)

  /**
   * The workspace's `.ko-agent-sandbox/file/rule`, as (normalized text, lines), or None when the file
   * is absent. `fileDir` is the file's `file/` directory (SandboxWorkspace.readBoundaryRuleFiles has
   * the refusals).
   */
  def readRuleFile(fileDir: Path): Either[String, Option[(String, Vector[Line])]] =
    SandboxWorkspace.readBoundaryRuleFiles(fileDir, Vector("rule"), "doc/file-rules.md", EgressRules.normalizeRuleText)
      .flatMap: files =>
        files.headOption match
          case None => Right(None)
          case Some((name, text)) =>
            parse(text, s".ko-agent-sandbox/file/$name").map(lines => Some((text, lines)))

  /** The lines a session gets: the defaults, then the workspace's. */
  def resolve(workspaceLines: Vector[Line]): Vector[Line] = Defaults ++ workspaceLines

  /**
   * The directories whose objects the filter's daemon sees as the host does, for the daemon's guard
   * (`guard.rs`, `resolve`).
   * - On native Linux, the daemon sees the whole filesystem as the host does.
   * - Elsewhere, the daemon sees the podman machine's shares as the host does (SECURITY.md,
   *   "Container, runtime and kernel escape", has the observed mounts).
   * - On Windows, that share is the workspace's own drive, which WSL mounts where the workspace's
   *   mount path says.
   */
  def hostView(os: Os, mountPath: String): Vector[String] =
    os match
      case Os.Linux   => Vector("/")
      case Os.Mac     => Vector("/Users", "/private", "/var/folders")
      case Os.Windows => Vector(mountPath.split("/").take(3).mkString("/"))

  /** What the daemon reads: the host-view line, then the lines. */
  def daemonText(lines: Vector[Line], hostView: Vector[String]): String =
    (s"host-view ${hostView.mkString(" ")}" +: lines.map(_.text)).map(_ + "\n").mkString

  /**
   * The resolved set out of the filter's output: `--resolve`'s output, or the mount script's output
   * after ResolvedMarker. A line of any other form comes from another filter version, and so does a
   * rule name or rest that the grammar refuses, because the Seatbelt profile writes names and rests
   * into its regexes.
   */
  def parseResolved(text: String): Either[String, Resolved] =
    val lines = text.linesIterator.filter(_.nonEmpty).toVector
    def named(name: String, entry: => ResolvedEntry, line: String) =
      if nameRefusal(name).isEmpty then Right(entry) else Left(line)
    val parsed = lines.map: line =>
      line.split(" ").toVector match
        case Vector("read-only", name)             => named(name, ResolvedEntry.Rule(Line(Word.ReadOnly, name)), line)
        case Vector("writable", name)              => named(name, ResolvedEntry.Rule(Line(Word.Writable, name)), line)
        case Vector("read-only-path", path)        => Right(ResolvedEntry.ReadOnlyPath(path))
        case Vector("pinned-path", path)           => Right(ResolvedEntry.PinnedPath(path))
        case Vector("read-only-under", path, rest) => named(rest, ResolvedEntry.ReadOnlyUnder(path, rest), line)
        case _                                     => Left(line)
    parsed.collectFirst { case Left(line) => line } match
      case Some(line) =>
        Left(
          s"error: the filter answered a file rule line this launcher cannot read: $line\n" +
            "An installed ko-agent-fs of another version prints another format; rebuild with --build.",
        )
      case None =>
        val entries = parsed.collect { case Right(entry) => entry }
        Right(
          Resolved(
            entries.collect { case ResolvedEntry.Rule(line) => line },
            entries.collect { case ResolvedEntry.ReadOnlyPath(path) => path },
            entries.collect { case ResolvedEntry.PinnedPath(path) => path },
            entries.collect { case ResolvedEntry.ReadOnlyUnder(path, rest) => (path, rest) },
          ),
        )

  private enum ResolvedEntry:
    case Rule(line: Line)
    case ReadOnlyPath(path: String)
    case PinnedPath(path: String)
    case ReadOnlyUnder(path: String, rest: String)

  /** The line the mount script prints before the resolved set. */
  val ResolvedMarker = "file rules resolved:"

  /** The launch lines about the workspace's rule file (HostCommands.ruleFileReport). A workspace
    * without the file gets no lines, because the defaults are every launch's. The file's `writable`
    * lines, the only kind that can widen, are reported as the widening. What the guard added is printed
    * once the filter has answered (guardLines). */
  def launchLines(
    workspaceFile: Option[(String, Vector[Line])],
    color: Boolean = HostCommands.colorStderr,
  ): Vector[String] =
    workspaceFile.toVector.flatMap((_, lines) => report(".ko-agent-sandbox/file/rule", lines, color))

  /** The launch lines about the rules of a running mount that a launch joins: the mount's lines beyond
    * the defaults, or all of them when the mount runs under other defaults, with the `writable` lines
    * reported as the widening. */
  def runningLaunchLines(running: Vector[Line], color: Boolean = HostCommands.colorStderr): Vector[String] =
    val beyond = if running.startsWith(Defaults) then running.drop(Defaults.size) else running
    if beyond.isEmpty then Vector("the running mount's file rules: the launcher-owned defaults")
    else report("the running mount's file rules", beyond, color)

  private def report(source: String, lines: Vector[Line], color: Boolean): Vector[String] =
    val writable = lines.filter(_.word == Word.Writable)
    HostCommands.ruleFileReport(source, lines.map(_.text), writable.map(_.text), color, joinedWritable)

  /** Joins two or more `writable` lines into one, `writable: <name>, <name>`, as egress joins its hosts
    * (EgressRules.groupedByHost). A single line stays as written. A name holds no `,` (parse). */
  private def joinedWritable(rules: Seq[String]): Seq[String] =
    val names = rules.map(_.stripPrefix(s"${Word.Writable.keyword} ")).distinct
    if names.size < 2 then rules.distinct else Vector(s"${Word.Writable.keyword}: ${names.mkString(", ")}")

  /** The rule lines of a text daemonText wrote, as a running mount serves them. */
  def parseDaemonText(text: String): Either[String, Vector[Line]] =
    parseResolved(text.linesIterator.filterNot(_.startsWith("host-view ")).mkString("\n")).map(_.lines)

  /** What the filter's guard added, once it has answered. */
  def guardLines(resolved: Resolved): Vector[String] =
    val paths = resolved.readOnlyPaths ++ resolved.readOnlyUnder.map((path, rest) => s"$path/$rest")
    Option.when(paths.nonEmpty)(s"file rules: read-only by the filter's guard: ${paths.mkString(", ")}").toVector
