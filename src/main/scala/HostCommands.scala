// Host executable resolution and execution, platform selection, and launcher diagnostics.
// This object does not depend on sandbox policy, so launcher components can use it without a
// dependency cycle. findOnPath enforces trusted executable resolution.

package agentsandbox.launcher

import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, Paths}

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
  ): String =
    val shell = if os == Os.Windows && needsPowerShellLiteral(path.toString) then " (PowerShell)" else ""
    s"$label$shell$separator${displayPath(path, os, environment)}"

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
   *   - red: what the user did not ask for. On the `error:` label, the launch stopped (stopped);
   *     on a whole line, a file of the project directory widens a boundary (weakenedByProject) —
   *     a file that arrives with the repository, written by whoever can write there.
   *   - orange: the launch goes on, and there is something to know. On the `warning:` label
   *     (caution); on a whole line, an option or environment variable of this launch weakens a
   *     boundary (weakenedByUser) — the user's own, so a reminder and not an alarm.
   *   - purple: what the user chose where it weakens nothing — the workspace mode, the egress
   *     profile, an upstream proxy (chosen) — a hue of its own so it is never read as a severity.
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

  def weakenedByUser(text: String, color: Boolean = colorStderr): String = tinted(Orange, text, color)

  def weakenedByProject(text: String, color: Boolean = colorStderr): String = tinted(Red, text, color)

  /** What the user chose, as the line stating it says it — `live`, `deny-unless-allowed`.
    * Purple and orange are not among the theme's sixteen — its magenta is as often pink, its
    * yellow as often olive — so both are the 256-colour cube's. */
  def chosen(text: String, color: Boolean = colorStderr): String = tinted("38;5;207", text, color)

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

  /** The echoed line; `announcedPodman` is the path the `using:` line said, or None before it has. */
  def renderCommand(command: Seq[String], announcedPodman: Option[String]): String =
    val words = command.toVector
    val shown =
      if words.headOption.exists(announcedPodman.contains) then "podman" +: words.tail else words
    "+ " + shown.map(shellWord).mkString(" ")

  private val BareWord = "[A-Za-z0-9_@%+=:,./-]+".r

  /** The word as an unambiguous one-line display: bare where sh would read it so, single-quoted
    * otherwise, with a line break or another control character shown as `\n`, `\t` or `\xNN`
    * and a backslash as `\\` so the two stay apart. No shell of the supported hosts reads that
    * back; it keeps the command on one physical line, so a following line is never one of its
    * words. */
  def shellWord(word: String): String =
    if BareWord.matches(word) then word
    else "'" + word.replace("\\", "\\\\").flatMap(visible).replace("'", "'\\''") + "'"

  /** Text a project file supplied, safe on a terminal: a control character is shown, never sent. */
  def printable(text: String): String = text.flatMap(visible)

  private def visible(char: Char): String =
    char match
      case '\n' => "\\n"
      case '\t' => "\\t"
      case other if other.isControl => f"\\x${other.toInt}%02x"
      case other => other.toString

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

  /** How many containers read one bind-mounted file, which decides its SELinux relabel option. */
  enum FileBindReaders:
    case OneContainer, SeveralContainers

  /**
   * The `--volume` argument for a file under the launcher's state root. On an SELinux-enforcing
   * host a container reads a bind-mounted file only once it is relabeled: podman mounts an
   * unlabeled one without complaint, and the container's own read fails with EACCES. `Z` gives
   * the file the one container's private MCS categories, which keep a key from every other
   * container that runs under SELinux separation — not from one with `label=disable`. `z` gives
   * it none, for a file a second container mounts, whose `Z` would take it from the first. Never
   * for the project tree: SECURITY.md ("the project tree's SELinux labels").
   */
  def fileBind(
    source: Path,
    containerPath: String,
    access: String,
    selinuxEnforcing: Boolean,
    readers: FileBindReaders = FileBindReaders.OneContainer,
  ): String =
    val relabel =
      if !selinuxEnforcing then ""
      else if readers == FileBindReaders.OneContainer then ",Z"
      else ",z"
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
      .flatMap(candidate => try Some(candidate.toRealPath()) catch case _: IOException => None)
      .filterNot(_.startsWith(ignoreUnder))
      .find(p => Files.isRegularFile(p) && Files.isExecutable(p))

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
             |than guessed at. $advice""".stripMargin
        )
