// Host executable resolution and execution, platform selection, launcher diagnostics and the sizes they print.
// This object does not depend on sandbox policy, so launcher components can use it without a
// dependency cycle. findOnPath enforces trusted executable resolution.

package agentsandbox.launcher

import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.{Path, Paths}

object HostCommands:

  // A parameter rather than Properties.isWin at each use, so tests exercise the Windows branches from a POSIX runner.
  enum Os:
    case Linux, Mac, Windows

  def currentOs: Os =
    if scala.util.Properties.isWin then Os.Windows
    else if scala.util.Properties.isMac then Os.Mac
    else Os.Linux

  /** Stderr and exit; a stack trace would read as a launcher bug, not
    * operator guidance. Console text stays ASCII: a Windows console decodes
    * in its legacy codepage and renders anything else as `?`, and some of
    * these lines are consent or refusal text a reader must be able to trust
    * verbatim. */
  def fail(message: String, code: Int = 1): Nothing =
    if shuttingDown then
      val interrupted = "the launch was interrupted; the failure below is its consequence, not a fault of its own"
      System.err.println(emphasized(s"$ErrorLabel $interrupted"))
    System.err.println(emphasized(message))
    sys.exit(code)

  /**
   * Whether this JVM's shutdown has begun. A child podman shares the terminal's process group and
   * dies of the same Ctrl-C, so the refusal the main thread raises on its exit status is the
   * interruption's, not the child's, and `fail` says so first. The JDK reports the state only by
   * refusing: `addShutdownHook` and `removeShutdownHook` throw IllegalStateException once the hooks
   * have started, and removing needs no hook of this probe's to exist. The exit that `fail` then
   * makes blocks indefinitely — Runtime.exit's contract: "all other invocations will perform no
   * action and block indefinitely" — and the JVM ends when the hooks finish, with the shutdown's
   * own status.
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

  /** A path inside a sentence, with the shell label pathLine puts on the line's label following it
    * instead: the sentence names a directory to act in, and cmd.exe cannot take the PowerShell form. */
  def pathInline(path: Path, os: Os = currentOs, environment: String => Option[String] = env): String =
    s"${displayPath(path, os, environment)}${shellLabel(path, os)}"

  private def shellLabel(path: Path, os: Os): String =
    if os == Os.Windows && needsPowerShellLiteral(path.toString) then " (PowerShell)" else ""

  def displayPath(
    path: Path,
    os: Os = currentOs,
    environment: String => Option[String] = env,
  ): String =
    // PowerShell file commands expand ~, but cmd.exe does not, so Windows paths stay absolute.
    // Quoting cannot suppress cmd's %NAME% expansion or delayed !NAME! expansion. Paths needing
    // those literals, or PowerShell's $ and backtick literals, carry a PowerShell label at the call site.
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
   * Case is not emphasis: a value is printed as it is configured — `live`, `deny-unless-allowed` —
   * so the banner, `--egress-effective` and the rule file read and grep
   * alike, and the reader is not shouted at for the mode they selected. Colour is the emphasis, and
   * each hue has one meaning:
   *
   *   - red: the launch stopped. On the `error:` label only (stopped).
   *   - orange: the launch goes on, and there is something to know. On the `warning:` label
   *     (caution); on a whole line, a boundary is weaker than the default (weakened), by an option
   *     or environment variable of this launch, by a rule file of the project directory, or by
   *     the unconfined host run a prompt offers (RunOnHostProvisioning) — a reminder and not an
   *     alarm, and the line or the one before it says what weakened it.
   *   - purple: what the user chose where it weakens nothing — the project directory, the
   *     workspace mode, the egress profile, an upstream proxy (chosen) — a hue of its own so it
   *     is never read as a severity.
   *   - gray: what is there to look up, not to read — the egress log's long path (lookedUp).
   *     Text that is skipped on every ordinary launch, tinted so the reader learns to skip it
   *     without learning to skip the lines around it.
   *   - green, orange and red on a headroom figure: a measurement's scale, outside this ranking
   *     (Headroom).
   *
   * A label is tinted alone, as sbt and mill tint `[warn]` and `[error]` and leave the message; a
   * weakened boundary is tinted as a whole line and holds no tinted word, since a word's reset
   * would end the line's colour. So no line has two colours.
   *
   * Colour adds nothing the words do not say. These lines are read back from a redirected stream, from a
   * pasted transcript, and — for the workspace and egress lines — from the instructions the agent is
   * handed, where an escape would be noise: the words have to hold in all three.
   */
  def caution(text: String, color: Boolean = colorStderr): String = tinted(Orange, text, color)

  def stopped(text: String, color: Boolean = colorStderr): String = tinted(Red, text, color)

  def weakened(text: String, color: Boolean = colorStderr): String = tinted(Orange, text, color)

  /** A heading ending in `widen (<count of rules>):`, then one indented line per rule, each tinted
    * on its own so a line filtered out of a saved log still opens and closes its colour. */
  def wideningReport(heading: String, rules: Seq[String], color: Boolean = colorStderr): Vector[String] =
    (s"$heading widen (${rules.size}):" +: rules.map(rule => s"  $rule")).toVector.map(weakened(_, color))

  /** A launch's lines about one rule file, each of the file's lines once: a line printed twice
    * lengthens what is read at every launch, and a longer text is skipped. The `widening` lines
    * are a wideningReport; the file's other lines follow on one line, untinted.
    *
    * @param source names the rules and their file, such as `egress rules (.ko-agent-sandbox/egress/rule)`. */
  def ruleFileReport(
    source: String,
    lines: Seq[String],
    widening: Seq[String],
    color: Boolean = colorStderr,
  ): Vector[String] =
    val others = lines.filterNot(widening.contains)
    val report = if widening.isEmpty then Vector.empty else wideningReport(source, widening, color)
    val rest =
      if others.isEmpty then Vector.empty
      else if widening.isEmpty then Vector(s"$source: ${others.mkString("; ")}")
      else Vector(s"$source, other lines: ${others.mkString("; ")}")
    report ++ rest

  /** What the user chose, as the line stating it says it — `live`, `deny-unless-allowed`.
    * Purple and orange are not among the theme's sixteen — its magenta is as often pink, its
    * yellow as often olive — so both are the 256-colour cube's. */
  def chosen(text: String, color: Boolean = colorStderr): String = tinted("38;5;207", text, color)

  /** What is there to look up, not to read. Mid-gray from the cube, legible on a light and a dark
    * background alike, where the theme's bright black is either. */
  def lookedUp(text: String, color: Boolean = colorStderr): String = tinted("38;5;245", text, color)

  /** The scale of a headroom figure: green while what the action is about fits, orange where it is
    * warned, red where it is short (AgentSandboxLauncher.launchMemoryHeadroom and
    * buildMemoryHeadroom each define their own scale). On the figure alone, so the
    * words hold where the escape does not. */
  enum Headroom(val code: String):
    case Ample extends Headroom("32")
    case Warned extends Headroom(Orange)
    case Short extends Headroom(Red)

  def gauged(text: String, headroom: Headroom, color: Boolean = colorStderr): String =
    tinted(headroom.code, text, color)

  /** Each line's leading severity label tinted. Line by line, because a block has a label on
    * some lines and not others — the proxy's rule warnings, a warning's continuation. */
  def emphasized(text: String, color: Boolean = colorStderr): String =
    text.linesIterator
      .map: line =>
        if line.startsWith(ErrorLabel) then stopped(ErrorLabel, color) + line.stripPrefix(ErrorLabel)
        else if line.startsWith(WarningLabel) then caution(WarningLabel, color) + line.stripPrefix(WarningLabel)
        else line
      .mkString("\n")

  /** Every warning the launcher writes itself, so the label is spelled and tinted in one place. */
  def warn(message: String): Unit = System.err.println(emphasized(s"$WarningLabel $message"))

  /** The `[y/N]` convention, stated once for every prompt: only an explicit yes is consent —
    * EOF and everything else decline. */
  def consented(answer: Option[String]): Boolean =
    answer.map(_.trim.toLowerCase(java.util.Locale.ROOT)).exists(a => a == "y" || a == "yes")

  private val WarningLabel = "warning:"
  private val ErrorLabel = "error:"
  private val Esc = 27.toChar
  private final val Red = "31"
  private final val Orange = "38;5;208"

  private def tinted(code: String, text: String, color: Boolean): String =
    if color then s"$Esc[${code}m$text$Esc[0m" else text

  /**
   * `isatty(2)` and not `System.console()`, which answers for stdin: stderr is where these lines
   * go, and the stream a reader redirects to keep them.
   */
  lazy val colorStderr: Boolean = colorAllowed(env("NO_COLOR"), env("TERM")) && rendersEscapes(2)

  /** For the `--stats` report, the one output the launcher writes to stdout: the stream a reader
    * pipes as readily as watches, so it is asked for itself. */
  lazy val colorStdout: Boolean = colorAllowed(env("NO_COLOR"), env("TERM")) && rendersEscapes(1)

  /** `NO_COLOR` and `TERM=dumb` are what a program is expected to honour; the launcher adds no
    * variable of its own. */
  def colorAllowed(noColor: Option[String], term: Option[String]): Boolean =
    noColor.isEmpty && !term.contains("dumb")

  /** A Windows console prints an escape as text unless it is asked to interpret it, so there the
    * question includes the asking. */
  private def rendersEscapes(fd: Int): Boolean =
    if currentOs == Os.Windows then FFMHelper.kernel32.enableVirtualTerminalProcessing(fd)
    else FFMHelper.libc.isatty(fd)

  // -------------------------------------------------------------------------
  // Sizes
  // -------------------------------------------------------------------------

  private val Units = Vector("", "K", "M", "G", "T", "P", "E")

  /**
   * A size as `df -h`, `du -h` and `ls -lh` print it, so a reader brings the rule with them:
   * bytes bare, otherwise the largest unit the size reaches, one decimal below 10 of it and none
   * from 10 up, rounded up, with 1023.6M carrying to 1.0G. That is two or three significant
   * figures; the four of `podman stats` are what make `16.67MB / 268.4MB` hard to read. Every
   * figure the launcher prints is this rule, and the entrypoint's `human` is its awk spelling.
   */
  def humanBytes(bytes: Long): String =
    val index = unitIndex(bytes)
    figure(bytes, index) + Units(index)

  /**
   * `0.3 / 11G` as (`0.3`, `11G`): a part beside its whole reads as a ratio when both are in
   * the whole's unit, so the part is rendered there — rounded as any figure, and the unit
   * written once, on the whole. The part is then known to a tenth of the whole's unit, a tenth
   * of a 1.0G limit at worst: the ratio's precision, on purpose, not the part's, so 30 MiB
   * under 6.7G reads 0.1.
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
      // The remainder's tenths as fifths of half the unit: bytes * 10 overflows from 0.8 EiB.
      val tenths = (bytes / unit) * 10 + Math.ceilDiv((bytes % unit) * 5, unit / 2)
      if tenths < 100 then s"${tenths / 10}.${tenths % 10}" else Math.ceilDiv(bytes, unit).toString

  /**
   * `memory: 58% (4.2G) available`, `storage: 58% (937G) free`: the share first, for a
   * reader who knows the machine's size, and beside it the figure the limits and the
   * `--reset-run-on-host` flag act on, `tint` applied to just those. `whole` is positive; a
   * machine that cannot say its size gets no line.
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
   * A command echoed before it runs, as `set -x` prints it: `+ ` and then the words, each shown
   * unambiguously on the one line — so a multi-line script argument prints as the one quoted
   * word it is, not as lines that look like commands of their own. The marker distinguishes
   * echoed commands from launcher diagnostics and subprocess output.
   *
   * The resolved podman is shown by its bare name, since the `using:` line said the path once
   * when it was resolved — and only then: an unannounced path stays spelled out.
   */
  def echoCommand(command: Seq[String]): Unit =
    System.err.println(renderCommand(command, announcedPodman))

  def stepOk(command: String*): Boolean =
    echoCommand(command)
    ProcessBuilder(command*).inheritIO().start().waitFor() == 0

  /** The echoed line; `announcedPodman` is the path the `using:` line said, or None before it has. */
  def renderCommand(command: Seq[String], announcedPodman: Option[String]): String =
    val words = command.toVector
    val named =
      if words.headOption.exists(announcedPodman.contains) then "podman" +: words.tail else words
    "+ " + named.map(shellWord).mkString(" ")

  private val BareWord = "[A-Za-z0-9_@%+=:,./-]+".r

  /** The word as an unambiguous one-line display: bare where sh would read it so, single-quoted
    * otherwise, with a character the terminal would act on spelled out as `shown` spells it and a
    * backslash as `\\` so the two stay apart. No shell of the supported hosts reads that back; it
    * keeps the command on one physical line, so a following line is never one of its words. */
  def shellWord(word: String): String =
    if BareWord.matches(word) then word
    else "'" + shown(word.replace("\\", "\\\\")).replace("'", "'\\''") + "'"

  /**
   * One argument as the reader agrees to it: verbatim when it is one plain word, so that the
   * usual command reads as typed, and otherwise quoted so that `program "a b"` and `program a b` render
   * apart and a character that would drive or reorder the terminal's display — a control,
   * a bidi or other format character, a line or paragraph separator — is spelled out instead.
   * The spelling is the shell's: single quotes, or `$'...'` around escapes.
   */
  def renderArgument(argument: String): String =
    if BareWord.matches(argument) then argument
    else if !argument.codePoints().anyMatch(invisible(_)) then s"'${argument.replace("'", "'\\''")}'"
    else s"$$'${shown(argument.replace("\\", "\\\\").replace("'", "\\'"))}'"

  /**
   * One line as the terminal shows it whole: a code point the terminal would act on rather than
   * show — a control, a bidi or other format character, a line or paragraph separator — spelled
   * out as `\n`, `\xNN`, `\uNNNN` or `\UNNNNNNNN`, so nothing the text came from can erase or
   * redraw what the reader answers to. A backslash stays as it is: the line may already carry
   * the escapes renderArgument or shellWord wrote, and a literal one acts on nothing.
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

  /** Character.getType values the terminal would act on rather than show: escaped by shown. */
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

  /** A shell command printing `text` byte for byte: base64 in the script, decoded where it runs,
    * so no quote, newline or `$` in it reaches the script's own syntax. */
  def printingCommand(text: String): String =
    s"printf %s ${java.util.Base64.getEncoder.encodeToString(text.getBytes(StandardCharsets.UTF_8))} | base64 -d"

  /**
   * `sh -c <script> sh <arguments>` for a script the launcher passes to podman, as words holding
   * no double quote and no newline, which a Windows launcher cannot pass
   * (LauncherImages.BundleLabelTemplate has why; KoAgentFs.koAgentFsScriptCommand crosses the
   * machine's ssh the same way). The script crosses base64-encoded and is evaluated in the
   * receiving shell itself, never piped to a second one, so its stdin stays the caller's. An
   * empty IFS and `set -f` keep the unquoted expansion one word, newlines included, and the
   * script's own first line restores both. Every platform uses it, so macOS and Linux runs
   * detect a broken wrapper before Windows does.
   */
  def quoteFreeSh(script: String, arguments: String*): Vector[String] =
    val encoded = java.util.Base64.getEncoder
      .encodeToString(s"unset IFS; set +f\n$script".getBytes(StandardCharsets.UTF_8))
    val wrapper = "IFS=; set -f; script=$(printf %s $1 | base64 -d); shift; eval $script"
    Vector("sh", "-c", wrapper, "sh", encoded) ++ arguments

  /**
   * The `--volume` argument for a file under the launcher's state root. On an SELinux-enforcing
   * host a container reads a bind-mounted file only once it is relabeled: podman mounts an
   * unlabeled one without complaint, and the container's own read fails with EACCES. `Z` gives
   * the file the one container's private MCS categories, which keep a key from every other
   * container that runs under SELinux separation — not from one with `label=disable`. No file is
   * mounted into two containers — the proxy and the sandbox mount this run's copies (the launch's
   * `carried`), the throwaway JDK container the project's CA certificate — so `Z` never takes a
   * file from another container. Never for the project tree: SECURITY.md ("the project tree's
   * SELinux labels").
   */
  def fileBind(source: Path, containerPath: String, access: String, selinuxEnforcing: Boolean): String =
    val relabel = if selinuxEnforcing then ",Z" else ""
    s"--volume=$source:$containerPath:$access$relabel"

  def run(command: String*): Run =
    val process = ProcessBuilder(command*).start()
    // stdin is closed at once, so a child that unexpectedly prompts reads EOF and fails loudly
    // rather than hanging forever on a pipe nobody writes.
    process.getOutputStream.close()
    // stderr is drained on its own thread, since either stream can fill its pipe first and block the child.
    var err: Array[Byte] = Array.emptyByteArray
    val errThread = Thread(() => err = process.getErrorStream.readAllBytes())
    errThread.start()
    val out = process.getInputStream.readAllBytes()
    errThread.join()
    Run(process.waitFor(), out, String(err, StandardCharsets.UTF_8).stripLineEnd)

  /**
   * `body` on its own thread, for a launch step that overlaps the steps after it; the function
   * returned waits for it and gives its result, or throws what it threw.
   *
   *   - `body` must not call `fail` or print: the caller does both with the result, in the launch's
   *     own order.
   *   - An exit waits for a started step, through a shutdown hook. Without it, a refusal on the main
   *     thread would leave the step's child with nobody reading its pipes, and its next write would
   *     kill it with SIGPIPE: the filter's self-test could stop between its mount and its unmount.
   *   - A step a shutdown overtakes does not start, since the JVM ends once the hooks finish,
   *     wherever the step is. A shutdown under way refuses the hook; a hook run before the start
   *     closes `gate`. The function returned then blocks until the JVM ends, as `fail` does during
   *     shutdown.
   *   - `register` adds the hook; a test passes its own to run the hook between the registration
   *     and the start.
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
   * The launcher's working directory, canonical where it can be. It is the
   * project directory being sandboxed — untrusted by definition — and so the one
   * directory a host executable must never be resolved out of.
   */
  def workingDirectory(): Path =
    val here = Paths.get("").toAbsolutePath
    try here.toRealPath()
    catch case _: IOException => here.normalize()

  /**
   * Host executables resolve through PATH entries that are absolute *and*
   * outside the project directory. Two different path classes are being
   * kept out, and neither subsumes the other:
   *
   *   - a relative entry (`.`, `bin`, `../programs`) resolves against the working
   *     directory, so the project supplies the host's podman with nobody having
   *     chosen it — and invoking the returned absolute path forecloses
   *     CreateProcess's implicit current-directory search on Windows for the
   *     same reason (prior art: Docker Sandboxes #392);
   *   - an *absolute* entry that names a directory inside the project also lets the project select
   *     the host executable while looking deliberate. `npm run` puts an absolute
   *     `$PWD/node_modules/.bin` on PATH, and a transitive dependency can ship
   *     a `bin` entry named `podman` without running a line of its own code.
   *     Nothing about absoluteness makes the project's copy the user's
   *     choice, so both are skipped.
   *
   * The *candidate* is what gets canonicalized, not the directory holding it,
   * and that distinction is the rule rather than a detail: `isRegularFile` and
   * `isExecutable` follow a symlink, so an innocent directory holding
   * `podman -> <project>/bin/podman` would pass a check made on the directory
   * alone and run the project's binary anyway. Resolving here also fixes
   * *what* runs — the absolute path handed to podman and to the reaper is the
   * real file, so a link swapped afterwards cannot redirect it.
   */
  def findOnPath(name: String, pathValue: String, os: Os): Option[Path] =
    findOnPath(name, pathValue, os, workingDirectory())

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
   * The PATH every script this launcher writes runs with, named rather than
   * inherited. Those scripts are `sh -c` text, and on native Linux they
   * inherit the launcher's environment and its working directory — the
   * project directory — so a relative entry in the inherited PATH (`.`,
   * `bin`, `../programs`) would let the project supply what they run. findOnPath
   * covers the executables the launcher itself invokes; this covers the ones
   * its scripts do.
   *
   * The system directories are the whole list, and what that costs is reported
   * rather than silent: a host keeping fusermount3 somewhere unusual — a Nix
   * profile, say — gets a "not found" it can read, never a binary out of the
   * project. Inside a podman machine the value is what the VM already had.
   *
   * podman never leans on this (koAgentFsReapPodman has the argument).
   *
   * Declared here, above every script that uses it: an object's vals
   * initialize in declaration order, so a later one would read as null.
   */
  val ScriptPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

  // Concatenated, not an interpolated stripMargin: stripMargin runs after interpolation, so a
  // script line that began with `|` would be silently dropped.
  def withScriptPath(script: String): String = s"export PATH=$ScriptPath\n$script"

  /**
   * The podman every command below runs: resolved once, absolutely, through
   * findOnPath. The reaper receives this same path as an argument, so its
   * invocations are the launcher's decision too. Lazy, so `--help` needs no
   * podman at all.
   */
  lazy val podman: String = podmanResolution._1

  def podmanRuns: Boolean = podmanResolution._2.exists(_.ok)

  /** The client build recorded by --self-test, from the same probe as the startup announcement. */
  def podmanVersion(): String =
    podmanResolution._2.filter(_.ok).map(_.text.trim).getOrElse("podman version unknown")

  private lazy val podmanResolution: (String, Option[Run]) =
    val found = findOnPath("podman", env("PATH").getOrElse(""), currentOs)
      .map(_.toString)
      .getOrElse(
        fail(
          """error: podman is not installed or not on PATH
            |
            |PATH entries inside the current directory are not searched: it is the
            |project directory being sandboxed (design.md, "No repository-controlled host executable resolution").
            |
            |Install it first: https://podman.io/docs/installation""".stripMargin,
          127,
        ),
      )
    val version =
      try Some(run(found, "--version"))
      catch case _: IOException => None
    // Said once, here, so every echoed command can then say just `podman` (echoCommand).
    System.err.println(podmanUsingLine(found, version))
    announcedPodman = Some(found)
    (found, version)

  def podmanUsingLine(path: String, result: Option[Run]): String =
    val version = result.filter(_.ok).map(_.text.trim).collect:
      case PodmanVersion(value) => s" (v$value)"
    s"using: $path${version.getOrElse("")}"

  private val PodmanVersion = "podman version ([0-9][A-Za-z0-9.+-]*)".r

  @volatile private var announcedPodman: Option[String] = None

  /**
   * A variable governing the boundary — or whether its reader sees it — takes exactly one of a
   * closed value set, case-sensitive: never a bare presence test, and no alternate spellings
   * (`1`, `true`, `yes`, …). An unclear value must refuse the launch rather than be read as
   * either side of the choice (design.md, "Security configuration must fail closed"), and each
   * accepted spelling must be handled consistently everywhere it is parsed. Unset and
   * empty mean the default, which is always the choice that weakens nothing.
   */
  def closedChoice(
      variable: String,
      value: Option[String],
      choices: Vector[String],
      default: String,
      advice: String,
  ): Either[String, String] =
    value match
      case None | Some("")                      => Right(default)
      case Some(text) if choices.contains(text) => Right(text)
      case Some(text) =>
        Left(
          s"""error: $variable is set to '$text'; the only values are ${choices.mkString(" and ")}, exactly
             |
             |This variable governs the boundary, so an unrecognized value is refused rather
             |than guessed at. $advice""".stripMargin,
        )
