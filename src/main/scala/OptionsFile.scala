// The options file holds launcher options that the user writes once. Each launch reads the file, and so does each
// action that uses the options (doc/design.md, "Host resources are granted by launch options, not variables").
// This file holds the options file's location, its syntax, and its lines as the arguments that
// CommandLine.parseArguments takes. CommandLine.merge puts the command line's options over the file's options.

package agentsandbox.launcher

import java.io.IOException
import java.nio.ByteBuffer
import java.nio.charset.{CharacterCodingException, CodingErrorAction, StandardCharsets}
import java.nio.file.{Files, NoSuchFileException, Path}

import CommandLine.*
import FileHelper.canonicalizedFuturePath
import HostCommands.{colorStderr, displayPath, fromOptionsFile, Os}
import SandboxWorkspace.overlapsInAnySpelling

object OptionsFile:

  /**
   * `$XDG_CONFIG_HOME/ko-agent-sandbox/options`, by default `~/.config/ko-agent-sandbox/options`, and
   * `%APPDATA%\ko-agent-sandbox\options` on Windows.
   * - The file lies under the configuration roots rather than under the state root, because the user writes the
   *   file.
   * - The path is resolved and canonicalized as LauncherState.stateRootOf resolves the state root. A symlink into the
   *   workspace therefore counts as inside the workspace, and `refusal` refuses the file.
   */
  def pathOf(os: Os, env: String => Option[String]): Either[String, Path] =
    LauncherState.userRootOf(
      os, env, "APPDATA", "XDG_CONFIG_HOME", ".config", "The launcher's options file chooses each launch's grants",
    ).flatMap: (variable, root) =>
      canonicalizedFuturePath(root.resolve("ko-agent-sandbox").resolve("options"))
        .left.map(reason => s"error: $variable: $reason")

  /** Why the file at `file` may not configure a launch from `workspaceRoot`. A repository must not choose its own
    * launch's grants, so a file inside the workspace is refused, as LauncherState.requireStateRootOutside refuses a
    * state root there. */
  def refusal(os: Os, file: Path, workspaceRoot: Path): Option[String] =
    Option.when(LauncherState.couldBeAWorkspace(os, workspaceRoot) && overlapsInAnySpelling(os, file, workspaceRoot))(
      s"error: the launcher's options file $file is inside the workspace root $workspaceRoot\n" +
        "A repository must not choose its own launch's grants; point XDG_CONFIG_HOME (or APPDATA) at a\n" +
        s"directory outside the workspace, or pass $NoOptionsFileOption.",
    )

  /** The options a file supplies to a launch or an action, and where it is. */
  case class Loaded(path: Path, options: ParsedCommandLine)

  /** The file's options for a launch or action from `workspaceRoot`, or None when there is no file. A missing file is
    * refused nowhere, because only a file that the launch would read can choose the launch's grants. */
  def load(os: Os, workspaceRoot: Path, env: String => Option[String]): Either[String, Option[Loaded]] =
    for
      path <- pathOf(os, env)
      bytes <-
        try Right(Some(Files.readAllBytes(path)))
        catch
          case _: NoSuchFileException => Right(None)
          case ex: IOException        => Left(s"error: cannot read the options file ${shown(path, os)}: $ex")
      _ <- bytes.flatMap(_ => refusal(os, path, workspaceRoot)).toLeft(())
      loaded <- bytes match
        case None => Right(None)
        case Some(content) => options(content, shown(path, os), env).map(parsed => Some(Loaded(path, parsed)))
    yield loaded

  /**
   * The options in force for a launch or an action: the command line's options over the file's options named in
   * `used`, once `load` has read the file, unless the command line skips the file.
   */
  def inForce(commandLine: ParsedCommandLine, used: Set[String])(
    load: => Either[String, Option[Loaded]],
  ): Either[String, OptionsInForce] =
    val loaded = if commandLine.noOptionsFile then Right(None) else load
    loaded.flatMap: found =>
      val file = found.fold(NoOptions)(read => restrictedTo(read.options, used))
      merge(file, commandLine).map((parsed, supplied) => OptionsInForce(parsed, supplied, found.map(_.path)))

  def shown(path: Path, os: Os): String = displayPath(path, os)

  /** What a startup line adds after an option that the file supplied, in the file's shade
    * (HostCommands.fromOptionsFile). */
  def fromFile(path: Path, os: Os, color: Boolean = colorStderr): String =
    s" ${fromOptionsFile(s"(from ${shown(path, os)})", color)}"

  /** fromFile with the values that the file supplied, for a line that also states values from elsewhere. */
  def valuesFromFile(values: Vector[String], path: Path, os: Os, color: Boolean = colorStderr): String =
    s" ${fromOptionsFile(s"(${values.mkString(", ")} from ${shown(path, os)})", color)}"

  /**
   * The file's options as one source of arguments, or the reason the file fails the launch. The reason names the file
   * as `shown`, and names the line.
   * - Each line holds one launcher option and nothing else. A line that the parser would read as the command, as its
   *   `--`, as a management action or as `--no-options-file` is refused.
   * - Each parser refusal names the line that completes the refused input: a second `--memory` names the second line.
   */
  def options(content: Array[Byte], shown: String, env: String => Option[String]): Either[String, ParsedCommandLine] =
    def at(line: Int, reason: String): String = s"error: $shown:$line: ${reason.stripPrefix("error: ")}"
    val arguments = lines(content).foldLeft[Either[String, Vector[(Int, String)]]](Right(Vector.empty)):
      case (Right(done), (number, Right(text))) =>
        argumentOf(text, env).left.map(at(number, _)).map(argument => done ++ argument.map(number -> _))
      case (Right(_), (number, Left(reason))) => Left(at(number, reason))
      case (refused, _)                       => refused
    arguments.flatMap: numbered =>
      numbered.indices.foldLeft[Either[String, ParsedCommandLine]](Right(NoOptions)): (parsed, index) =>
        parsed.flatMap: _ =>
          val (number, argument) = numbered(index)
          lineKindRefusal(argument).map(at(number, _)).toLeft(()).flatMap: _ =>
            parseArguments(numbered.take(index + 1).map(_._2).toList).left.map(at(number, _))

  private def lineKindRefusal(argument: String): Option[String] =
    if argument == "--" then Some("-- ends the options on the command line; this file holds options alone")
    else if argument == NoOptionsFileOption || argument.startsWith(NoOptionsFileOption + "=") then
      Some(s"$NoOptionsFileOption belongs on the command line, where it skips this file")
    else
      parseArguments(List(argument)).toOption.flatMap: parsed =>
        if parsed.action.isDefined then Some(s"$argument is a management action; give it on the command line")
        else Option.when(parsed.command.nonEmpty)(s"$argument is not an option; give a command on the command line")

  /** The file's lines with their numbers, each decoded as UTF-8 or the reason it is not. */
  private def lines(content: Array[Byte]): Vector[(Int, Either[String, String])] =
    val ends = content.indices.filter(content(_) == '\n'.toByte).toVector
    val starts = 0 +: ends.map(_ + 1)
    val bounds = starts.zip(ends :+ content.length).filter((start, end) => start < end || end < content.length)
    bounds.zipWithIndex.map:
      case ((start, end), index) =>
        val decoder = StandardCharsets.UTF_8.newDecoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
        val decoded =
          try Right(decoder.decode(ByteBuffer.wrap(content, start, end - start)).toString)
          catch case _: CharacterCodingException => Left("not UTF-8")
        (index + 1, decoded)

  private def isBlank(ch: Char): Boolean = ch == ' ' || ch == '\t' || ch == '\r' || ch == '\f' || ch == '\u000b'

  /**
   * One line as the argument it holds, or None for a blank line or a comment. The argument is `--name` or
   * `--name=value`:
   * - the whitespace around the line, the name and the value is removed;
   * - `#` outside double quotes starts a comment;
   * - each `${NAME}` in the value, unquoted or quoted, is expanded from `env`.
   */
  def argumentOf(line: String, env: String => Option[String]): Either[String, Option[String]] =
    val text = line.dropWhile(isBlank)
    if text.isEmpty || text.startsWith("#") then Right(None)
    else
      val name = text.takeWhile(ch => !isBlank(ch) && ch != '=' && ch != '#')
      val afterName = text.drop(name.length).dropWhile(isBlank)
      if name.contains('"') then Left(s"$name: quotes enclose a value, never an option's name")
      else
        afterName.headOption match
          case None | Some('#') => Right(Some(name))
          case Some('=') =>
            val spelled = afterName.drop(1).dropWhile(isBlank)
            val value = if spelled.startsWith("\"") then quoted(spelled.drop(1), env) else unquoted(spelled, env)
            value.map(expanded => Some(s"$name=$expanded"))
          case Some(_) => Left(s"$name is followed by text with no =; spell the option $name=<value>")

  private def unquoted(spelled: String, env: String => Option[String]): Either[String, String] =
    val raw = spelled.takeWhile(_ != '#').reverse.dropWhile(isBlank).reverse
    if raw.contains('"') then
      Left("a \" inside an unquoted value; enclose the whole value in quotes: --name=\"NAME=a b\"")
    else expanded(raw, env)

  /** Expands each `${NAME}` in `raw`. `raw` holds no escape, because `raw` is an unquoted value, where every
    * backslash is literal. */
  private def expanded(raw: String, env: String => Option[String]): Either[String, String] =
    val out = StringBuilder()
    @scala.annotation.tailrec
    def from(index: Int): Either[String, String] =
      if index >= raw.length then Right(out.toString)
      else if raw(index) == '$' then
        variableAt(raw, index, env) match
          case Left(reason) => Left(reason)
          case Right((value, next)) =>
            out ++= value
            from(next)
      else
        out += raw(index)
        from(index + 1)
    from(0)

  /** The value of the `${NAME}` at `index` of `text`, where `text(index)` is `$`, and the index after that `}`. */
  private def variableAt(text: String, index: Int, env: String => Option[String]): Either[String, (String, Int)] =
    if !text.startsWith("${", index) then
      Left("a $ that starts no ${NAME}; spell a literal $ as \\$ in a quoted value")
    else
      val close = text.indexOf('}', index + 2)
      if close < 0 then Left("a ${ without its }")
      else
        val name = text.substring(index + 2, close)
        if name.isEmpty then Left("${} names no variable")
        else env(name).toRight(s"$${$name} is not set in the launcher's environment").map(_ -> (close + 1))

  /** The value after its opening quote. The value takes the escapes `\"`, `\\` and `\$` and expands `${NAME}`. Only
    * whitespace and a comment may follow the closing quote. */
  private def quoted(text: String, env: String => Option[String]): Either[String, String] =
    val out = StringBuilder()
    @scala.annotation.tailrec
    def from(index: Int): Either[String, String] =
      if index >= text.length then Left("a quoted value without its closing \"")
      else
        text(index) match
          case '"' =>
            val rest = text.drop(index + 1).dropWhile(isBlank)
            if rest.isEmpty || rest.startsWith("#") then Right(out.toString)
            else Left("text after the closing \"; only whitespace and a comment may follow it")
          case '\\' =>
            text.lift(index + 1) match
              case Some(escaped @ ('"' | '\\' | '$')) =>
                out += escaped
                from(index + 2)
              case _ => Left("a backslash in a quoted value escapes \", \\ or $ alone; spell a backslash as \\\\")
          case '$' =>
            variableAt(text, index, env) match
              case Left(reason) => Left(reason)
              case Right((value, next)) =>
                out ++= value
                from(next)
          case ch =>
            out += ch
            from(index + 1)
    from(0)

/**
 * The options in force for a launch or an action (CommandLine.merge), the options that the options file supplied, and
 * the file's path when the launcher read a file.
 */
case class OptionsInForce(
  parsed: CommandLine.ParsedCommandLine,
  supplied: Vector[CommandLine.FileSupplied],
  file: Option[Path],
):
  /** What the line that states `option` adds when the file supplied `option`, else nothing. */
  def from(
    option: String, os: HostCommands.Os = HostCommands.currentOs, color: Boolean = HostCommands.colorStderr,
  ): String =
    file.filter(_ => supplied.exists(_.option == option)).fold("")(OptionsFile.fromFile(_, os, color))

  /** The values that the file supplied for `option`: every value, for a repeatable option. */
  def fileValues(option: String): Vector[String] =
    supplied.filter(_.option == option).map(_.spelled.stripPrefix(option + "="))

  /** The `--workspace` parts that the file supplied and the command line left in force. */
  def workspacePartsFromFile: Set[String] = fileValues("--workspace").flatMap(_.split(",")).toSet

  /** What the egress line adds after the `selected` providers: `from` when the file supplied every selected provider,
    * else the provider names that the file supplied. A provider that the command or the command line added is thus
    * not credited to the file. */
  def providersFrom(
    selected: Vector[String], os: HostCommands.Os = HostCommands.currentOs, color: Boolean = HostCommands.colorStderr,
  ): String =
    val fromFile = fileValues(CommandLine.ModelProviderOption)
    file.filter(_ => fromFile.nonEmpty).fold(""): path =>
      if selected.forall(fromFile.contains) then OptionsFile.fromFile(path, os, color)
      else OptionsFile.valuesFromFile(fromFile, path, os, color)

  /** The startup line of each option that the file supplied, except the options in `covered`, whose own lines name
    * the file (from). Each line tints the option's value as the file's choice (HostCommands.chosen). */
  def fileLines(
    covered: Set[String] = Set.empty,
    os: HostCommands.Os = HostCommands.currentOs,
    color: Boolean = HostCommands.colorStderr,
  ): Vector[String] =
    file.toVector.flatMap: path =>
      supplied.filterNot(entry => covered(entry.option)).map: entry =>
        val (name, value) = entry.spelled.span(_ != '=')
        val tinted =
          if value.isEmpty then name else s"$name=${HostCommands.chosen(value.drop(1), color, fromFile = true)}"
        tinted + OptionsFile.fromFile(path, os, color)
