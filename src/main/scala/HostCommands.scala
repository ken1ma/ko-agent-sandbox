// Host executable resolution and execution, platform selection, launcher diagnostics, and the sizes the diagnostics
// print.
//
// - This object does not depend on sandbox policy, so launcher components can use it without a dependency cycle.
// - findOnPath enforces trusted executable resolution.

package agentsandbox.launcher

import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.{Path, Paths}

object HostCommands:

  // A parameter rather than Properties.isWin at each use, so that tests exercise the Windows branches from a POSIX
  // runner.
  enum Os:
    case Linux, Mac, Windows

  def currentOs: Os =
    if scala.util.Properties.isWin then Os.Windows
    else if scala.util.Properties.isMac then Os.Mac
    else Os.Linux

  /** Prints the message on stderr and exits. A stack trace would read as a launcher bug, not as operator guidance. The
    * message is ASCII (design.md, "The launcher's text is ASCII"). */
  def fail(message: String, code: Int = 1): Nothing =
    if shuttingDown then
      val interrupted = "the launch was interrupted; the failure below is its consequence, not a fault of its own"
      System.err.println(emphasized(s"$ErrorLabel $interrupted"))
    System.err.println(emphasized(message))
    sys.exit(code)

  /**
   * Whether this JVM's shutdown has begun.
   *
   *   - A child podman shares the terminal's process group and dies of the same Ctrl-C. The refusal that the main
   *     thread raises on the child's exit status is therefore the interruption's, not the child's, and `fail` says so
   *     first.
   *   - The JDK reports the state only by refusing. `addShutdownHook` and `removeShutdownHook` throw
   *     IllegalStateException once the hooks have started, and removing needs no hook of this probe's to exist.
   *   - The exit that `fail` then makes blocks indefinitely, by Runtime.exit's contract: "all other invocations will
   *     perform no action and block indefinitely". The JVM ends when the hooks finish, with the shutdown's own status.
   */
  def shuttingDown: Boolean =
    try
      Runtime.getRuntime.removeShutdownHook(Thread(() => ()))
      false
    catch case _: IllegalStateException => true

  def env(name: String): Option[String] =
    Option(System.getenv(name)).filter(_.nonEmpty)

  def pathLine(
    label: String,
    path: Path,
    os: Os = currentOs,
    environment: String => Option[String] = env,
    separator: String = ": ",
    tint: String => String = identity,
  ): String =
    s"$label${shellLabel(path, os)}$separator${tint(displayPath(path, os, environment))}"

  /** A path inside a sentence. The shell label that pathLine puts on the line's label follows the path here instead,
    * because the sentence names a directory to act in, and cmd.exe cannot take the PowerShell form. */
  def pathInline(path: Path, os: Os = currentOs, environment: String => Option[String] = env): String =
    s"${displayPath(path, os, environment)}${shellLabel(path, os)}"

  private def shellLabel(path: Path, os: Os): String =
    if os == Os.Windows && needsPowerShellLiteral(path.toString) then " (PowerShell)" else ""

  def displayPath(
    path: Path,
    os: Os = currentOs,
    environment: String => Option[String] = env,
  ): String =
    // PowerShell file commands expand ~, but cmd.exe does not, so Windows paths stay absolute. Quoting cannot suppress
    // cmd's %NAME% expansion or delayed !NAME! expansion. Paths that need those literals, or PowerShell's $ and
    // backtick literals, carry a PowerShell label at the call site.
    if os == Os.Windows then
      val text = path.toString
      if needsPowerShellLiteral(text) then powerShellPathArgument(text)
      else if WindowsBarePath.matches(text) then text
      else s"\"$text\""
    else
      val home = environment("HOME").filter(_.nonEmpty).flatMap: value =>
        try Some(Paths.get(value))
        catch case _: java.nio.file.InvalidPathException => None
      home.filter(directory => directory.isAbsolute && path.startsWith(directory)).map: directory =>
        val relative = directory.relativize(path).toString
        // Quoting ~ would suppress home expansion when the path is pasted into a shell.
        if relative.isEmpty then "~" else s"~/${posixPathArgument(relative)}"
      .getOrElse(posixPathArgument(path.toString))

  private def posixPathArgument(path: String): String =
    if BareWord.matches(path) then path else "'" + path.replace("'", "'\\''") + "'"

  private val WindowsBarePath = """[A-Za-z0-9_:\\./-]+""".r

  private def needsPowerShellLiteral(path: String): Boolean =
    path.exists("$`%!\"\u201c\u201d\u201e".contains(_))

  private def powerShellPathArgument(path: String): String =
    // PowerShell treats curly apostrophes as single-quote delimiters too.
    val escaped = path.flatMap: char =>
      if "'\u2018\u2019\u201a\u201b".contains(char) then s"$char$char" else char.toString
    s"'$escaped'"

  // -------------------------------------------------------------------------
  // Emphasis
  // -------------------------------------------------------------------------

  /**
   * Case is not emphasis. A value is printed as it is configured, such as `live` or `deny-unless-allowed`. The
   * banner, `--egress-effective` and the rule file then read and grep alike, and the reader is not shouted at for
   * the mode they selected.
   *
   * Color is the emphasis, and each hue has one meaning:
   *
   *   - red: the launch stopped. Red appears on the `error:` label only (stopped).
   *   - orange: the launch goes on, and there is something to know.
   *     - Orange appears on the `warning:` label (caution).
   *     - On a grant, orange means that a boundary is weaker than the default (weakened). An option of this launch, a
   *       rule file of the workspace, or the unconfined host run that a prompt offers (RunOnHostProvisioning) can
   *       weaken the boundary.
   *     - Orange is a reminder, not an alarm. The line, or the line before it, says what weakened the boundary.
   *     - A grant is the label and what it grants, such as `audio: mic`, with the explanation after it plain. A
   *       widening rule and the prompt are grants whole.
   *   - purple: what the user chose, on a line that states no weakened boundary (chosen). Examples are the workspace
   *     root and mode, the egress profile and model providers, an upstream proxy, the forwarded variables, brokered
   *     credentials and AWS profile. Purple is a hue of its own, so that it is never read as a severity.
   *     - A value that the options file supplied is a darker purple, and so is the file's `(from …)` after it
   *       (fromOptionsFile). The shade tells a choice made once for every launch from one made for this launch.
   *     - A grant's orange stays: only its `(from …)` takes the darker purple.
   *   - gray: what is there to look up, not to read (lookedUp). An example is the long path of the run's log
   *     directory. The reader skips this text on every ordinary launch, and the tint teaches the reader to skip it
   *     without learning to skip the lines around it.
   *   - green, orange and red on a headroom figure: a measurement's scale, outside this ranking (Headroom).
   *
   * A label is tinted alone, as sbt and mill tint `[warn]` and `[error]` and leave the message. A grant is tinted
   * alike. A span inside a tinted span, such as the file's source among a grant's plugins, reopens the outer color
   * after it (tinted).
   *
   * Color adds nothing the words do not say. These lines are read back from a redirected stream and from a pasted
   * transcript. The workspace and egress lines are also read from the instructions the agent is handed, where an
   * escape would be noise. The words have to hold in all three.
   */
  def caution(text: String, color: Boolean = colorStderr): String = tinted(Orange, text, color)

  def stopped(text: String, color: Boolean = colorStderr): String = tinted(Red, text, color)

  def weakened(text: String, color: Boolean = colorStderr): String = tinted(Orange, text, color)

  /** A heading `<source>: <count> widening lines`, then one indented line per rule, or per group of rules that
    * `grouped` joins. Each line is tinted on its own, so that a line filtered out of a saved log still opens and
    * closes its color. */
  def wideningReport(
    source: String,
    rules: Seq[String],
    color: Boolean = colorStderr,
    grouped: Seq[String] => Seq[String] = identity,
  ): Vector[String] =
    val count = if rules.size == 1 then "1 widening line" else s"${rules.size} widening lines"
    (s"$source: $count" +: grouped(rules).map(rule => s"  $rule")).toVector.map(weakened(_, color))

  /** A launch's lines about one rule file, with each of the file's lines once.
    *
    *   - A line printed twice lengthens what is read at every launch, and a longer text is skipped.
    *   - The `widening` lines are a wideningReport joined by `grouped`.
    *   - The file's other lines follow on one line, untinted.
    *
    * @param source names the rule file, such as `.ko-agent-sandbox/egress/rule`. */
  def ruleFileReport(
    source: String,
    lines: Seq[String],
    widening: Seq[String],
    color: Boolean = colorStderr,
    grouped: Seq[String] => Seq[String] = identity,
  ): Vector[String] =
    val others = lines.filterNot(widening.contains)
    val report = if widening.isEmpty then Vector.empty else wideningReport(source, widening, color, grouped)
    val rest =
      if others.isEmpty then Vector.empty
      else if widening.isEmpty then Vector(s"$source: ${others.mkString("; ")}")
      else Vector(s"$source, other lines: ${others.mkString("; ")}")
    report ++ rest

  /** What the user chose, as the line stating it says it, such as `live` or `deny-unless-allowed`. Purple and orange
    * are not among the theme's sixteen colors: the theme's magenta is as often pink, and its yellow as often olive.
    * Both therefore come from the 256-color cube. */
  def chosen(text: String, color: Boolean = colorStderr, fromFile: Boolean = false): String =
    if fromFile then fromOptionsFile(text, color) else tinted("38;5;207", text, color)

  /** What the options file supplied, and the file's `(from …)`: a darker purple from the cube, legible on a light and
    * a dark background alike. */
  def fromOptionsFile(text: String, color: Boolean = colorStderr): String = tinted("38;5;133", text, color)

  /** What is there to look up, not to read. The tint is mid-gray from the cube, legible on a light and a dark
    * background alike. The theme's bright black can be either. */
  def lookedUp(text: String, color: Boolean = colorStderr): String = tinted("38;5;245", text, color)

  /** The scale of a headroom figure: green while what the action is about fits, orange where it is warned, and red
    * where it is short. AgentSandboxLauncher.launchMemoryHeadroom and buildMemoryHeadroom each define their own
    * scale. The tint goes on the figure alone, so that the words hold where the escape does not. */
  enum Headroom(val code: String):
    case Ample extends Headroom("32")
    case Warned extends Headroom(Orange)
    case Short extends Headroom(Red)

  def gauged(text: String, headroom: Headroom, color: Boolean = colorStderr): String =
    tinted(headroom.code, text, color)

  /** Tints each line's leading severity label. The work goes line by line, because a block has a label on some lines
    * and not on others, such as the proxy's rule warnings or a warning's continuation. */
  def emphasized(text: String, color: Boolean = colorStderr): String =
    text.linesIterator
      .map: line =>
        if line.startsWith(ErrorLabel) then stopped(ErrorLabel, color) + line.stripPrefix(ErrorLabel)
        else if line.startsWith(WarningLabel) then caution(WarningLabel, color) + line.stripPrefix(WarningLabel)
        else line
      .mkString("\n")

  /** Writes every warning that the launcher writes itself, so that the label is spelled and tinted in one place. */
  def warn(message: String): Unit = System.err.println(emphasized(s"$WarningLabel $message"))

  /** The `[y/N]` convention, stated once for every prompt. Only an explicit yes is consent. EOF and everything else
    * decline. */
  def consented(answer: Option[String]): Boolean =
    answer.map(_.trim.toLowerCase(java.util.Locale.ROOT)).exists(a => a == "y" || a == "yes")

  private val WarningLabel = "warning:"
  private val ErrorLabel = "error:"
  private val Esc = 27.toChar
  private final val Red = "31"
  private final val Orange = "38;5;208"

  /** A span tinted inside `text`, such as the file's source among a grant's plugins, ends with a reset. The color is
    * reopened after the span, so the rest of `text` keeps its tint. */
  private def tinted(code: String, text: String, color: Boolean): String =
    val reset = s"$Esc[0m"
    if color then s"$Esc[${code}m${text.replace(reset, s"$reset$Esc[${code}m")}$reset" else text

  /**
   * `isatty(2)` and not `System.console()`, which answers for stdin. These lines go to stderr, and stderr is the
   * stream a reader redirects to keep them.
   */
  lazy val colorStderr: Boolean = colorAllowed(env("NO_COLOR"), env("TERM")) && rendersEscapes(2)

  /** For the `--stats` report, the one output the launcher writes to stdout. A reader is as likely to pipe stdout as
    * to watch it, so the launcher asks about stdout separately. */
  lazy val colorStdout: Boolean = colorAllowed(env("NO_COLOR"), env("TERM")) && rendersEscapes(1)

  /** A program is expected to honour `NO_COLOR` and `TERM=dumb`. The launcher adds no variable of its own. */
  def colorAllowed(noColor: Option[String], term: Option[String]): Boolean =
    noColor.isEmpty && !term.contains("dumb")

  /** A Windows console prints an escape as text unless it is asked to interpret escapes. On Windows, the question
    * therefore includes the asking. */
  private def rendersEscapes(fd: Int): Boolean =
    if currentOs == Os.Windows then FFMHelper.kernel32.enableVirtualTerminalProcessing(fd)
    else FFMHelper.libc.isatty(fd)

  // -------------------------------------------------------------------------
  // Sizes
  // -------------------------------------------------------------------------

  private val Units = Vector("", "K", "M", "G", "T", "P", "E")

  /**
   * A size as `df -h`, `du -h` and `ls -lh` print it, so that a reader brings the rule with them.
   *
   *   - Bytes are printed bare. Otherwise the size is printed in the largest unit it reaches.
   *   - The figure has one decimal below 10 of that unit and none from 10 up. The figure is rounded up, so 1023.6M
   *     carries to 1.0G.
   *   - That gives two or three significant figures. The four of `podman stats` are what make `16.67MB / 268.4MB`
   *     hard to read.
   *   - Every figure the launcher prints follows this rule, and the entrypoint's `human` is its awk spelling.
   */
  def humanBytes(bytes: Long): String =
    val index = unitIndex(bytes)
    figure(bytes, index) + Units(index)

  /**
   * `0.3 / 11G` as (`0.3`, `11G`).
   *
   *   - A part beside its whole reads as a ratio when both are in the whole's unit. The part is therefore rendered in
   *     that unit, rounded as any figure is, and the unit is written once, on the whole.
   *   - The part is then known to a tenth of the whole's unit, at worst a tenth of a 1.0G limit. That is the ratio's
   *     precision, on purpose, not the part's, so 30 MiB under 6.7G reads 0.1.
   */
  def humanPair(part: Long, whole: Long): (String, String) =
    val index = unitIndex(whole)
    (figure(part, index), figure(whole, index) + Units(index))

  private def unitIndex(bytes: Long): Int =
    val reached = (1 until Units.size).count(index => bytes >= (1L << (10 * index)))
    if reached == Units.size - 1 || Math.ceilDiv(bytes, 1L << (10 * reached)) < 1024 then reached
    else reached + 1

  private def figure(bytes: Long, index: Int): String =
    if index == 0 then bytes.toString
    else
      val unit = 1L << (10 * index)
      // The remainder's tenths are computed as fifths of half the unit, because bytes * 10 overflows from 0.8 EiB.
      val tenths = (bytes / unit) * 10 + Math.ceilDiv((bytes % unit) * 5, unit / 2)
      if tenths < 100 then s"${tenths / 10}.${tenths % 10}" else Math.ceilDiv(bytes, unit).toString

  /**
   * `memory: 58% (4.2G) available` or `storage: 58% (937G) free`.
   *
   *   - The share comes first, for a reader who knows the machine's size. Beside it comes the figure that the limits
   *     and the `--reset-run-on-host` flag act on. `tint` applies to just those two.
   *   - `whole` is positive. A machine that cannot say its size gets no line.
   */
  def shareLine(label: String, part: Long, whole: Long, state: String, tint: String => String = identity): String =
    val figure = f"${part * 100.0 / whole}%.0f%% (${humanBytes(part)})"
    s"$label: ${tint(figure)} $state"

  // -------------------------------------------------------------------------
  // Subprocesses
  // -------------------------------------------------------------------------

  case class Run(exit: Int, out: Array[Byte], err: String):
    def text: String = String(out, StandardCharsets.UTF_8).stripLineEnd
    def ok: Boolean = exit == 0

  /**
   * Echoes a command before it runs, as `set -x` prints it: `+ ` and then the words.
   *
   *   - Each word is shown unambiguously on the one line. A multi-line script argument thus prints as the one quoted
   *     word it is, not as lines that look like commands of their own.
   *   - The marker distinguishes echoed commands from launcher diagnostics and subprocess output.
   *   - The resolved podman is shown by its bare name, since the `using:` line said the path once when it was
   *     resolved. The bare name appears only after that line: an unannounced path stays spelled out.
   */
  def echoCommand(command: Seq[String]): Unit =
    System.err.println(renderCommand(command, announcedPodman))

  def stepOk(command: String*): Boolean =
    echoCommand(command)
    ProcessBuilder(command*).inheritIO().start().waitFor() == 0

  /** The echoed line. `announcedPodman` is the path that the `using:` line said, or None before that line. */
  def renderCommand(command: Seq[String], announcedPodman: Option[String]): String =
    "+ " + commandWords(command, announcedPodman)

  /** The command as its echo shows it, for an error whose command was echoed far above, or not at all. */
  def shownCommand(command: Seq[String]): String = commandWords(command, announcedPodman)

  def commandWords(command: Seq[String], announcedPodman: Option[String]): String =
    val words = command.toVector
    val named =
      if words.headOption.exists(announcedPodman.contains) then "podman" +: words.tail else words
    named.map(shellWord).mkString(" ")

  private val BareWord = "[A-Za-z0-9_@%+=:,./-]+".r

  /** The word as an unambiguous one-line display.
    *
    *   - The word is bare where sh would read it so, and single-quoted otherwise.
    *   - A character that the terminal would act on is spelled out as `shown` spells it. A backslash is spelled as
    *     `\\`, so that the two stay apart.
    *   - No shell of the supported hosts reads that spelling back. The spelling keeps the command on one physical
    *     line, so a following line is never one of its words. */
  def shellWord(word: String): String =
    if BareWord.matches(word) then word
    else "'" + shown(word.replace("\\", "\\\\")).replace("'", "'\\''") + "'"

  /**
   * One argument as the reader agrees to it.
   *
   *   - The argument is verbatim when it is one plain word, so that the usual command reads as typed.
   *   - Otherwise the argument is quoted, so that `program "a b"` and `program a b` render apart.
   *   - A character that would drive or reorder the terminal's display is spelled out instead. Such characters are a
   *     control, a bidi or other format character, and a line or paragraph separator.
   *   - The spelling is the shell's: single quotes, or `$'...'` around escapes.
   */
  def renderArgument(argument: String): String =
    if BareWord.matches(argument) then argument
    else if !argument.codePoints().anyMatch(invisible(_)) then s"'${argument.replace("'", "'\\''")}'"
    else s"$$'${shown(argument.replace("\\", "\\\\").replace("'", "\\'"))}'"

  /**
   * One line as the terminal shows it whole.
   *
   *   - A code point that the terminal would act on rather than show is spelled out as `\n`, `\xNN`, `\uNNNN` or
   *     `\UNNNNNNNN`. Such code points are a control, a bidi or other format character, and a line or paragraph
   *     separator.
   *   - Nothing the text came from can therefore erase or redraw what the reader answers to.
   *   - A backslash stays as it is. The line may already carry the escapes that renderArgument or shellWord wrote, and
   *     a literal backslash acts on nothing.
   */
  def shown(line: String): String =
    val visible = new StringBuilder
    line.codePoints().forEach: cp =>
      cp match
        case '\n'                                => visible ++= "\\n"
        case '\t'                                => visible ++= "\\t"
        case '\r'                                => visible ++= "\\r"
        case cp if cp < 0x80 && invisible(cp)    => visible ++= f"\\x$cp%02x"
        case cp if invisible(cp) && cp <= 0xffff => visible ++= f"\\u$cp%04x"
        case cp if invisible(cp)                 => visible ++= f"\\U$cp%08x"
        case cp                                  => visible.appendAll(Character.toChars(cp))
    visible.result()

  /** Character.getType values that the terminal would act on rather than show. shown escapes them. */
  val InvisibleTypes: Set[Int] = Set(
    Character.CONTROL,
    Character.FORMAT,
    Character.LINE_SEPARATOR,
    Character.PARAGRAPH_SEPARATOR,
    Character.SURROGATE,
    Character.PRIVATE_USE,
    Character.UNASSIGNED,
  ).map(_.toInt)

  private def invisible(codePoint: Int): Boolean = InvisibleTypes.contains(Character.getType(codePoint))

  /** A shell command that prints `text` byte for byte. The text is base64 in the script and decoded where it runs, so
    * no quote, newline or `$` in it reaches the script's own syntax. */
  def printingCommand(text: String): String =
    s"printf %s ${java.util.Base64.getEncoder.encodeToString(text.getBytes(StandardCharsets.UTF_8))} | base64 -d"

  /**
   * `exec` attaching stdin, for every such exec.
   *
   *   - Podman reads an exec's stdin through its detach keys, Ctrl-P Ctrl-Q by default, whether or not a terminal is
   *     attached.
   *   - Podman detaches when successive reads return those bytes alone (`detach.Copy` in containers/common). Audio, a
   *     clipboard image or a command's output could therefore end the exec.
   *   - An empty sequence turns the keys off.
   */
  val ExecWithInput: Vector[String] = Vector("exec", "-i", "--detach-keys=")

  /**
   * `sh -c <script> sh <arguments>` for a script that the launcher passes to podman, as words that hold no double
   * quote and no newline.
   *
   *   - A Windows launcher cannot pass a double quote or a newline (LauncherImages.BundleLabelTemplate explains why).
   *     KoAgentFs.koAgentFsScriptCommand crosses the machine's ssh the same way.
   *   - The script crosses base64-encoded and is evaluated in the receiving shell itself, never piped to a second
   *     shell, so its stdin stays the caller's.
   *   - An empty IFS and `set -f` keep the unquoted expansion one word, newlines included. The script's own first line
   *     restores both.
   *   - Every platform uses this form, so macOS and Linux runs detect a broken wrapper before Windows does.
   */
  def quoteFreeSh(script: String, arguments: String*): Vector[String] =
    val encoded = java.util.Base64.getEncoder
      .encodeToString(s"unset IFS; set +f\n$script".getBytes(StandardCharsets.UTF_8))
    val wrapper = "IFS=; set -f; script=$(printf %s $1 | base64 -d); shift; eval $script"
    Vector("sh", "-c", wrapper, "sh", encoded) ++ arguments

  /**
   * The `--volume` argument for a file under the launcher's state root.
   *
   *   - On an SELinux-enforcing host, a container reads a bind-mounted file only once the file is relabeled. podman
   *     mounts an unlabeled file without complaint, and the container's own read fails with EACCES.
   *   - `Z` gives the file the one container's private MCS categories. The categories keep a key from every other
   *     container that runs under SELinux separation, but not from a container with `label=disable`.
   *   - No file is mounted into two containers, so `Z` never takes a file from another container. The proxy and the
   *     sandbox mount this run's copies (the launch's `carried`), and the throwaway JDK container mounts the
   *     workspace's CA certificate.
   *   - The workspace never gets `Z` (SECURITY.md, "the workspace's SELinux labels").
   */
  def fileBind(source: Path, containerPath: String, access: String, selinuxEnforcing: Boolean): String =
    val relabel = if selinuxEnforcing then ",Z" else ""
    s"--volume=$source:$containerPath:$access$relabel"

  def run(command: String*): Run = runProcess(ProcessBuilder(command*))

  /** `run`, with `environment` set in the child's own environment. A value-less `--env=NAME` of `podman create` reads
    * from there. */
  def runWithEnvironment(environment: Map[String, String], command: String*): Run =
    // Scrubbed, because an edited environment starts from the JVM's copy, which still holds the withheld names.
    val builder = EgressCredentials.scrub(ProcessBuilder(command*))
    environment.foreach(builder.environment.put(_, _))
    runProcess(builder)

  private def runProcess(builder: ProcessBuilder): Run =
    val process = builder.start()
    // stdin is closed at once, so that a child that unexpectedly prompts reads EOF and fails loudly, rather than
    // hanging forever on a pipe that nobody writes.
    process.getOutputStream.close()
    // stderr is drained on its own thread, since either stream can fill its pipe first and block the child.
    var err: Array[Byte] = Array.emptyByteArray
    val errThread = Thread(() => err = process.getErrorStream.readAllBytes())
    errThread.start()
    val out = process.getInputStream.readAllBytes()
    errThread.join()
    Run(process.waitFor(), out, String(err, StandardCharsets.UTF_8).stripLineEnd)

  /**
   * Runs `body` on its own thread, for a launch step that overlaps the steps after it. The returned function waits
   * for the step and gives its result, or throws what it threw.
   *
   *   - `body` must not call `fail` or print. The caller does both with the result, in the launch's own order.
   *   - An exit waits for a started step, through a shutdown hook. Without the hook, a refusal on the main thread would
   *     leave the step's child with nobody reading its pipes, and the child's next write would kill it with SIGPIPE.
   *     The FUSE backend's self-test could then stop between its mount and its unmount.
   *   - A step that a shutdown overtakes does not start, since the JVM ends once the hooks finish, wherever the step
   *     is. A shutdown under way refuses the hook, and a hook run before the start closes `gate`. The returned
   *     function then blocks until the JVM ends, as `fail` does during shutdown.
   *   - `register` adds the hook. A test passes its own `register` to run the hook between the registration and the
   *     start.
   */
  def inBackground[A](
    name: String,
    register: Thread => Unit = Runtime.getRuntime.addShutdownHook(_),
  )(body: => A): () => A =
    var outcome: Option[scala.util.Try[A]] = None
    val worker = Thread(() => outcome = Some(scala.util.Try(body)), name)
    val gate = Object()
    var closed = false
    val settle = Thread: () =>
      gate.synchronized { closed = true }
      worker.join()
    val started =
      try
        register(settle)
        gate.synchronized:
          if !closed then worker.start()
          !closed
      catch case _: IllegalStateException => false
    () =>
      if !started then untilTheJvmEnds()
      worker.join()
      try Runtime.getRuntime.removeShutdownHook(settle)
      catch case _: IllegalStateException => ()
      outcome.getOrElse(throw IllegalStateException(s"$name ended without a result")).get

  private def untilTheJvmEnds(): Nothing =
    while true do Thread.sleep(Long.MaxValue)
    throw IllegalStateException("the JVM outlived its shutdown")

  def runOk(command: String*): Boolean =
    try run(command*).ok
    catch case _: IOException => false

  /**
   * The launcher's working directory, canonical where possible. It is the workspace root being sandboxed, untrusted
   * by definition, and so the one directory out of which a host executable must never be resolved.
   */
  def workingDirectory(): Path =
    val here = Paths.get("").toAbsolutePath
    try here.toRealPath()
    catch case _: IOException => here.normalize()

  /**
   * Host executables resolve through PATH entries that are absolute *and* outside the workspace. The rule keeps out
   * two different path classes, and neither subsumes the other:
   *
   *   - A relative entry (`.`, `bin`, `../programs`) resolves against the working directory. The workspace would thus
   *     supply the host's podman without anybody choosing it. Invoking the returned absolute path forecloses
   *     CreateProcess's implicit current-directory search on Windows, for the same reason (prior art: Docker
   *     Sandboxes #392).
   *   - An *absolute* entry that names a directory inside the workspace also lets the workspace select the host
   *     executable, while looking deliberate. `npm run` puts an absolute `$PWD/node_modules/.bin` on PATH, and a
   *     transitive dependency can ship a `bin` entry named `podman` without running a line of its own code. Nothing
   *     about absoluteness makes the workspace's copy the user's choice, so both classes are skipped.
   *
   * The *candidate* is canonicalized, not the directory holding it, and that distinction is the rule rather than a
   * detail.
   *
   *   - `isRegularFile` and `isExecutable` follow a symlink. An innocent directory holding
   *     `podman -> <workspace>/bin/podman` would pass a check made on the directory alone, and run the workspace's
   *     binary anyway.
   *   - Resolving here also fixes *what* runs. The absolute path handed to podman and to the reaper is the real file,
   *     so a link swapped afterwards cannot redirect it.
   */
  def findOnPath(name: String, pathValue: String, os: Os): Option[Path] =
    findOnPath(name, pathValue, os, workingDirectory())

  /** On the host's own PATH. */
  def findOnPath(name: String, os: Os): Option[Path] = findOnPath(name, env("PATH").getOrElse(""), os)

  /** @param ignoreUnder a candidate under this path is treated as unresolved. */
  def findOnPath(name: String, pathValue: String, os: Os, ignoreUnder: Path): Option[Path] =
    val separator = if os == Os.Windows then ';' else ':'
    val extensions =
      if os == Os.Windows then Vector(".exe", ".com", ".bat", ".cmd")
      else Vector("")
    pathValue
      .split(separator)
      .iterator
      .map(_.trim)
      .filter(_.nonEmpty)
      .flatMap: entry =>
        try Some(Paths.get(entry))
        catch case _: java.nio.file.InvalidPathException => None
      .filter(_.isAbsolute)
      .flatMap(dir => extensions.iterator.map(ext => dir.resolve(name + ext)))
      .flatMap(FileHelper.realPath)
      .filterNot(_.startsWith(ignoreUnder))
      .find(FileHelper.isExecutableFile)

  /**
   * The PATH that every script this launcher writes runs with, named rather than inherited.
   *
   *   - Those scripts are `sh -c` text. On native Linux, they inherit the launcher's environment and its working
   *     directory, which is the workspace root. A relative entry in the inherited PATH (`.`, `bin`, `../programs`)
   *     would therefore let the workspace supply what the scripts run.
   *   - findOnPath covers the executables that the launcher itself invokes. This value covers the ones its scripts
   *     invoke.
   *   - The system directories are the whole list, and the cost is reported rather than silent. A host that keeps
   *     fusermount3 somewhere unusual, such as a Nix profile, gets a "not found" it can read, never a binary out of
   *     the workspace.
   *   - Inside a podman machine, the value is what the VM already had.
   *   - podman never leans on this value (koAgentFsReapPodman has the argument).
   *   - The value is declared here, above every script that uses it. An object's vals initialize in declaration
   *     order, so a later declaration would read as null.
   */
  val ScriptPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

  // Concatenated, not an interpolated stripMargin. stripMargin runs after interpolation, so a script line that began
  // with `|` would be silently dropped.
  def withScriptPath(script: String): String = s"export PATH=$ScriptPath\n$script"

  /**
   * The podman that every command below runs, resolved once, absolutely, through findOnPath.
   *
   *   - The reaper receives this same path as an argument, so its invocations are the launcher's decision too.
   *   - The value is lazy, so `--help` needs no podman at all.
   */
  lazy val podman: String = podmanResolution._1

  def podmanRuns: Boolean = podmanResolution._2.exists(_.ok)

  /** The client build recorded by --self-test, from the same probe as the startup announcement. */
  def podmanVersion(): String =
    podmanResolution._2.filter(_.ok).map(_.text.trim).getOrElse("podman version unknown")

  /** Whether the container runs. A podman that cannot be asked answers no. */
  def containerRunning(podman: String, container: String): Boolean =
    try run(podman, "container", "inspect", "--format", "{{.State.Running}}", container).text.trim == "true"
    catch case _: IOException => false

  private lazy val podmanResolution: (String, Option[Run]) =
    val found = findOnPath("podman", currentOs)
      .map(_.toString)
      .getOrElse(
        fail(
          """error: podman is not installed or not on PATH
            |
            |PATH entries inside the current directory are not searched: it is the
            |workspace root being sandboxed (design.md, "No repository-controlled host executable resolution").
            |
            |Install it first: https://podman.io/docs/installation""".stripMargin,
          127,
        ),
      )
    val version =
      try Some(run(found, "--version"))
      catch case _: IOException => None
    // Said once, here, so that every echoed command can then say just `podman` (echoCommand).
    System.err.println(podmanUsingLine(found, version))
    announcedPodman = Some(found)
    (found, version)

  def podmanUsingLine(path: String, result: Option[Run]): String =
    val version = result.filter(_.ok).map(_.text.trim).collect:
      case PodmanVersion(value) => s" (v$value)"
    s"using: $path${version.getOrElse("")}"

  private val PodmanVersion = "podman version ([0-9][A-Za-z0-9.+-]*)".r

  @volatile private var announcedPodman: Option[String] = None
