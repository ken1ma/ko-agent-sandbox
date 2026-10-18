// The options file: launcher options the user writes once, read by each launch and by the actions
// that use them (doc/design.md, "Host resources are granted by launch options, not variables").
// Its location, its syntax, and its lines as the arguments CommandLine.parseArguments takes;
// CommandLine.merge puts the command line's options over them.

package agentsandbox.launcher

import java.io.IOException
import java.nio.ByteBuffer
import java.nio.charset.{CharacterCodingException, CodingErrorAction, StandardCharsets}
import java.nio.file.{Files, NoSuchFileException, Path}

import CommandLine.*
import FileHelper.canonicalizedFuturePath
import HostCommands.{colorStderr, displayPath, lookedUp, Os}
import SandboxWorkspace.overlapsInAnySpelling

object OptionsFile:

  /**
   * `$XDG_CONFIG_HOME/ko-agent-sandbox/options`, by default `~/.config/ko-agent-sandbox/options`, and
   * `%APPDATA%\ko-agent-sandbox\options` on Windows: under the configuration roots rather than the
   * state root's, since the user writes it. Resolved and canonicalized as LauncherState.stateRootOf
   * resolves the state root, so a symlink into the workspace is seen as inside it (refusal).
   */
  def pathOf(os: Os, env: String => Option[String]): Either[String, Path] =
    LauncherState.userRootOf(
      os, env, "APPDATA", "XDG_CONFIG_HOME", ".config", "The launcher's options file chooses each launch's grants",
    ).flatMap: (variable, root) =>
      canonicalizedFuturePath(root.resolve("ko-agent-sandbox").resolve("options"))
        .left.map(reason => s"error: $variable: $reason")

  /** Why the file at `file` may not configure a launch from `workspaceRoot`: a repository must not
    * choose its own launch's grants, so a file inside the workspace is refused as
    * LauncherState.requireStateRootOutside refuses the state root there. */
  def refusal(os: Os, file: Path, workspaceRoot: Path): Option[String] =
    Option.when(LauncherState.couldBeAWorkspace(os, workspaceRoot) && overlapsInAnySpelling(os, file, workspaceRoot))(
      s"error: the launcher's options file $file is inside the workspace root $workspaceRoot\n" +
        "A repository must not choose its own launch's grants; point XDG_CONFIG_HOME (or APPDATA) at a\n" +
        s"directory outside the workspace, or pass $NoOptionsFileOption.",
    )

  /** The options a file supplies to a launch or an action, and where it is. */
  case class Loaded(path: Path, options: ParsedCommandLine)

  /** The file's options for a launch or action from `workspaceRoot`; None when there is no file, which
    * is refused nowhere: only a file the launch would read can choose its grants. */
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
   * The options in force for a launch or an action: the command line's over those of the file
   * named in `used`, once `load` read it, unless the command line skips the file.
   */
  def inForce(commandLine: ParsedCommandLine, used: Set[String])(
    load: => Either[String, Option[Loaded]],
  ): Either[String, OptionsInForce] =
    val loaded = if commandLine.noOptionsFile then Right(None) else load
    loaded.flatMap: found =>
      val file = found.fold(NoOptions)(read => restrictedTo(read.options, used))
      merge(file, commandLine).map((parsed, supplied) => OptionsInForce(parsed, supplied, found.map(_.path)))

  def shown(path: Path, os: Os): String = displayPath(path, os)

  /** What a startup line adds after an option the file supplied: a path to look up, not to read
    * (HostCommands.lookedUp). */
  def fromFile(path: Path, os: Os, color: Boolean = colorStderr): String =
    s" ${lookedUp(s"(from ${shown(path, os)})", color)}"

  /**
   * The file's options as one source of arguments, or why the file fails the launch, naming it as
   * `shown` and the line. Each line holds one launcher option and nothing else, so a line the parser
   * would read as the command, its `--`, a management action or `--no-options-file` is refused, and
   * each parser refusal names the line that completes it: a second `--memory` names the second.
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
   * One line as the argument it holds, None for a blank line or a comment: `--name` or
   * `--name=value`, with the whitespace around the line, the name and the value removed, `#`
   * outside double quotes starting a comment, and the value's `${NAME}` expanded from `env`
   * (unquoted and quoted).
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

  /** Expands each `${NAME}` in `raw`, which holds no escape: an unquoted value, where every backslash
    * is literal. */
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

  /** The value of the `${NAME}` at `index` of `text`, where `text(index)` is `$`, and the index after
    * its `}`. */
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

  /** The value after its opening quote: escapes `\"`, `\\` and `\$`, `${NAME}` expanded, and after the
    * closing quote only whitespace and a comment. */
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
 * The options in force for a launch or an action (CommandLine.merge), those the options file
 * supplied to it, and the file's path when one was read.
 */
case class OptionsInForce(
  parsed: CommandLine.ParsedCommandLine,
  supplied: Vector[CommandLine.FileSupplied],
  file: Option[Path],
):
  /** What the line saying `option` adds when the file supplied it, else nothing. */
  def from(
    option: String, os: HostCommands.Os = HostCommands.currentOs, color: Boolean = HostCommands.colorStderr,
  ): String =
    file.filter(_ => supplied.exists(_.option == option)).fold("")(OptionsFile.fromFile(_, os, color))

  /** The values the file supplied for `option`, a repeatable option's each. */
  def fileValues(option: String): Vector[String] =
    supplied.filter(_.option == option).map(_.spelled.stripPrefix(option + "="))

  /** The startup line of each option the file supplied, but those in `covered`, whose own lines
    * name the file (from), with its value tinted as what the user chose (HostCommands.chosen). */
  def fileLines(
    covered: Set[String] = Set.empty,
    os: HostCommands.Os = HostCommands.currentOs,
    color: Boolean = HostCommands.colorStderr,
  ): Vector[String] =
    file.toVector.flatMap: path =>
      supplied.filterNot(entry => covered(entry.option)).map: entry =>
        val (name, value) = entry.spelled.span(_ != '=')
        val tinted = if value.isEmpty then name else s"$name=${HostCommands.chosen(value.drop(1), color)}"
        tinted + OptionsFile.fromFile(path, os, color)
