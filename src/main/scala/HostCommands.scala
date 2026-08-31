// The launcher's host-side primitives: the platform tag, how it runs an executable, and how it
// reads and writes the small state files everything else keeps. Nothing here knows what a sandbox
// is, which is what lets every other file in this package sit on top of it without a cycle.
//
// The security-relevant member is findOnPath — see its comment. Everything else is plumbing.

package agentsandbox.launcher

import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, Paths, StandardCopyOption}
import java.nio.file.attribute.{PosixFilePermission, PosixFilePermissions}
import scala.jdk.CollectionConverters.*

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
    System.err.println(emphasized(message))
    sys.exit(code)

  def env(name: String): Option[String] =
    Option(System.getenv(name)).filter(_.nonEmpty)

  // -------------------------------------------------------------------------
  // Emphasis
  // -------------------------------------------------------------------------

  /**
   * Case is not emphasis: a value is printed as it is configured — `live`, `guard none`,
   * `deny-unless-allowed` — so the banner, `--egress-effective` and the policy file read and grep
   * alike, and the reader is not shouted at for the mode they selected. What earns their eye is a
   * severity label, a boundary weaker than the default, or the mode an authority line states, and
   * colour is what marks those; sbt and mill tint their `[warn]` label and leave the message
   * alone, and this follows them. A mode takes a hue of its own so it is never read as a severity:
   * yellow and red stay warning and error.
   *
   * Colour carries nothing of its own. These lines are read back from a redirected stream, from a
   * pasted transcript, and — for the two authority lines — from the instructions the agent is
   * handed, where an escape would be noise: the words have to hold in all three.
   */
  def caution(text: String, color: Boolean = colorStderr): String = tinted("33", text, color)

  /** A refusal, which in this launcher is only ever the `error:` label. */
  def alarm(text: String, color: Boolean = colorStderr): String = tinted("31", text, color)

  /** The mode an authority line states — `live`, `deny-unless-allowed`. Orange is not among
    * ANSI's eight, so this is the 256-colour cube's. */
  def statedMode(text: String, color: Boolean = colorStderr): String = tinted("38;5;208", text, color)

  /** Each line's leading severity label tinted. Line by line, because a block carries a label on
    * some lines and not others — the proxy's policy warnings, a warning's continuation. */
  def emphasized(text: String, color: Boolean = colorStderr): String =
    text.linesIterator
      .map: line =>
        if line.startsWith(ErrorLabel) then alarm(ErrorLabel, color) + line.stripPrefix(ErrorLabel)
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

  private def tinted(code: String, text: String, color: Boolean): String =
    if color then s"$Esc[${code}m$text$Esc[0m" else text

  /**
   * `isatty(2)` and not `System.console()`, which answers for stdin: stderr is where these lines
   * go, and the stream a reader redirects to keep them. Windows stays plain — `fail` has why its
   * console text is ASCII, and a console without virtual-terminal processing prints the escape
   * itself.
   */
  lazy val colorStderr: Boolean =
    colorAllowed(currentOs, env("NO_COLOR"), env("TERM")) && FFMHelper.libc.isatty(2)

  /** `NO_COLOR` and `TERM=dumb` are what a tool is expected to honour; the launcher adds no
    * variable of its own. */
  def colorAllowed(os: Os, noColor: Option[String], term: Option[String]): Boolean =
    os != Os.Windows && noColor.isEmpty && !term.contains("dumb")

  // -------------------------------------------------------------------------
  // Subprocess plumbing
  // -------------------------------------------------------------------------

  case class Run(exit: Int, out: Array[Byte], err: String):
    def text: String = String(out, StandardCharsets.UTF_8).stripLineEnd
    def ok: Boolean = exit == 0

  /**
   * A command echoed before it runs, as `set -x` prints it: `+ ` and then the words, each shown
   * unambiguously on the one line — so a multi-line script argument prints as the one quoted
   * word it is, not as lines that look like commands of their own. The marker is what tells a
   * command from the output that follows it; the launcher's own lines carry a `label:` instead,
   * and a subprocess's carry neither.
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

  private def visible(char: Char): String =
    char match
      case '\n' => "\\n"
      case '\t' => "\\t"
      case other if other.isControl => f"\\x${other.toInt}%02x"
      case other => other.toString

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
   * outside the project directory. Two different things are being
   * kept out, and neither subsumes the other:
   *
   *   - a relative entry (`.`, `bin`, `../tools`) resolves against the working
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
   * `bin`, `../tools`) would let the project supply what they run. findOnPath
   * covers the executables the launcher itself invokes; this covers the ones
   * its scripts do.
   *
   * The system directories are the whole list, and what that costs is legible
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
  // script line that began with `|` would be silently eaten.
  def withScriptPath(script: String): String = s"export PATH=$ScriptPath\n$script"

  /**
   * The podman every command below runs: resolved once, absolutely, through
   * findOnPath. The reaper receives this same path as an argument, so its
   * invocations are the launcher's decision too. Lazy, so `--help` needs no
   * podman at all.
   */
  lazy val podman: String =
    val found = findOnPath("podman", env("PATH").getOrElse(""), currentOs)
      .map(_.toString)
      .getOrElse(
        fail(
          """error: podman is not installed or not on PATH
            |
            |PATH entries inside the current directory are not searched: it is the
            |project directory being sandboxed (DESIGN.md, "No PATH-resolved host executables").
            |
            |Install it first: https://podman.io/docs/installation""".stripMargin,
          127,
        ),
      )
    // Said once, here, so every echoed command can then say just `podman` (echoCommand).
    System.err.println(s"using: $found")
    announcedPodman = Some(found)
    found

  @volatile private var announcedPodman: Option[String] = None

  def readIfPresent(path: Path): Option[String] =
    if Files.isRegularFile(path) then Some(Files.readString(path)) else None

  /**
   * The real path a possibly-not-yet-created `path` will occupy: the deepest existing ancestor is
   * canonicalized and the missing tail re-appended. A plain `toRealPath` fails on a path that does
   * not exist yet — which the state root is on every first launch — and comparing the symbolic
   * spelling instead would let a symlinked ancestor place it somewhere the comparison never sees.
   * Left when the existing ancestor cannot be resolved: an unverified spelling handed back
   * instead would bypass whatever containment comparison the caller makes with the answer.
   */
  def canonicalizedFuturePath(path: Path): Either[String, Path] =
    val absolute = path.toAbsolutePath.normalize()
    // NOFOLLOW attributes, not Files.exists: exists follows links, so a dangling symlink would
    // read as absent and ride into the "future" tail unchecked — a concurrent writer could
    // materialize its target after validation — and it folds every other I/O failure into false.
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
      // toRealPath follows, so a dangling symlink found present above is rejected right here
      // rather than adopted as a base.
      try Right(tail.foldLeft(existing.toRealPath())(_.resolve(_)))
      catch case ex: IOException => Left(s"cannot resolve $existing to a real path: $ex")

  /**
   * Run `body` holding an exclusive inter-process lock on `lockFile`.
   * What it serializes is check-then-act over shared files: two launches that both find state
   * missing or stale otherwise interleave their writes, and the survivors need not belong
   * together — a CA key from one launch beside the other's certificate.
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
   * The stamp travels inside the file rather than in one beside it because separate files are
   * atomic individually and race as a set — a launch interleaved between writing its content and
   * writing its stamp leaves a pairing neither launch computed, and that pairing is sticky, held
   * until something happens to rewrite it. A caller reading several of these requires every one to
   * match, so an interleaving is a miss that re-derives rather than a mixture that persists.
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
  // Written with owner-only permissions where the filesystem has POSIX
  // permissions at all. On Windows nothing is needed: %LOCALAPPDATA% inherits
  // an ACL that already excludes other users.
  // -------------------------------------------------------------------------

  def posixPermissions(path: Path): Boolean =
    Files.getFileStore(path).supportsFileAttributeView("posix")

  def writePrivate(path: Path, content: String): Unit =
    writeWithMode(path, content.getBytes(StandardCharsets.UTF_8), "rw-------")

  def writeReadable(path: Path, content: String): Unit =
    writeWithMode(path, content.getBytes(StandardCharsets.UTF_8), "rw-r--r--")

  /** For the one state file that is not text: the JDK keystore JdkTrust merges. */
  def writeReadable(path: Path, content: Array[Byte]): Unit =
    writeWithMode(path, content, "rw-r--r--")

  /**
   * Written beside the target and renamed onto it, never written at the target itself. Nearly
   * every file written through here feeds a container mount — as the shared source the per-run
   * copies are taken from (AgentSandboxLauncher, the locked TLS derivation), or per-run itself,
   * like the audit log — and a launch of the same project may be copying or assembling at this
   * moment: a name that disappears even briefly fails that launch, and a name that exists holding
   * half a file is worse. Rename is what leaves neither state visible. The temporary carries a
   * generated name, so two launches racing here cannot collide on it.
   *
   * A write that would change neither the content nor the mode is skipped: a cache stamp that
   * misses on identical output must not churn the shared source's inode under a concurrent
   * launch's copy. A real change replaces the inode and reaches only the runs that copy after it —
   * a mount cannot follow a file out from under it (SECURITY.md, "The `.git` pins of
   * `WORKSPACE_GUARD=none`", has the measurement), which is why containers mount per-run copies rather than these
   * files.
   *
   * The mode is requested at creation and set again after the write, and both halves earn their
   * place. Creating with it is what leaves no window: a file created under the umask and chmodded
   * afterwards holds its content at 0644 for as long as the write takes, and what `writePrivate`
   * writes is the CA private key. Setting it again is what makes the mode exact: umask can only
   * clear bits, so a strict one would otherwise leave `writeReadable` narrower than the container
   * reading that file needs. On Windows the attribute is refused and the file is created plainly
   * (the section banner has why nothing is needed there).
   */
  private def writeWithMode(path: Path, content: Array[Byte], mode: String): Unit =
    val permissions = PosixFilePermissions.fromString(mode)
    if !alreadyWritten(path, content, permissions) then replaceWithMode(path, content, permissions)

  /**
   * Whether the file at `path` already is what the write would leave — content and mode both, so a
   * mode planted on a bind source is still corrected. An unreadable or vanishing file is not it:
   * another launch may be replacing this very path, and the write is the answer to that.
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
   * ATOMIC_MOVE alone: it replaces an existing target on both POSIX and Windows, and pairing it
   * with REPLACE_EXISTING is what some implementations refuse. Retried briefly on Windows's
   * transient sharing violations — replacing a file a concurrent reader holds open answers
   * AccessDenied there, and every file written through here is read concurrently by design:
   * another launch copying it, a container mounting it. POSIX never takes the retry.
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

  def deleteRecursively(path: Path): Unit =
    if Files.exists(path) then
      Files
        .walk(path)
        .sorted(java.util.Comparator.reverseOrder())
        .iterator()
        .asScala
        .foreach(Files.delete)

  /**
   * A variable governing the boundary — or whether its reader sees it — takes exactly one of a
   * closed value set, case-sensitive: never a bare presence test, and no alternate spellings
   * (`1`, `true`, `yes`, …). An unclear value must refuse the launch rather than be read as
   * either side of the choice (DESIGN.md, "Security configuration must fail closed"), and each
   * accepted spelling is surface that has to stay correct everywhere it is parsed. Unset and
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
