// The launcher's host-side primitives: the platform tag, how it runs an executable, and how it
// reads and writes the small state files everything else keeps. Nothing here knows what a sandbox
// is, which is what lets every other file in this package sit on top of it without a cycle.
//
// The security-relevant member is findOnPath — see its comment. Everything else is plumbing.

package agentsandbox.launcher

import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, Paths}
import java.nio.file.attribute.PosixFilePermissions
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
    * operator guidance. */
  def fail(message: String, code: Int = 1): Nothing =
    System.err.println(message)
    sys.exit(code)

  def env(name: String): Option[String] =
    Option(System.getenv(name)).filter(_.nonEmpty)

  // -------------------------------------------------------------------------
  // Subprocess plumbing
  // -------------------------------------------------------------------------

  case class Run(exit: Int, out: Array[Byte], err: String):
    def text: String = String(out, StandardCharsets.UTF_8).stripLineEnd
    def ok: Boolean = exit == 0

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
   * Trusted host executables resolve through absolute PATH entries only;
   * relative entries are skipped, and invoking the returned absolute path
   * forecloses CreateProcess's implicit current-directory search on Windows.
   * The launcher's working directory is the repository being sandboxed —
   * untrusted by definition. (Prior art: Docker Sandboxes #392.)
   */
  def findOnPath(name: String, pathValue: String, os: Os): Option[Path] =
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
      .find(p => Files.isRegularFile(p) && Files.isExecutable(p))

  /**
   * The PATH every script this launcher writes runs with, named rather than
   * inherited. Those scripts are `sh -c` text, and on native Linux they
   * inherit the launcher's environment and its working directory — the
   * repository being sandboxed — so a relative entry in the inherited PATH
   * (`.`, `bin`, `../tools`) would let a checkout supply the `fusermount3`,
   * `mountpoint`, `stat` or `sleep` they call. findOnPath covers the
   * executables the launcher itself invokes; this covers the ones its scripts
   * do.
   *
   * The system directories are the whole list, and what that costs is legible
   * rather than silent: a host keeping fusermount3 somewhere unusual — a Nix
   * profile, say — gets a "not found" it can read, never a binary out of the
   * checkout. Inside a podman machine the value is what the VM already had.
   *
   * podman never leans on this. The reaper receives the path findOnPath
   * resolved, and inside the machine it is the machine's own
   * (koAgentFsReapPodman).
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
    findOnPath("podman", env("PATH").getOrElse(""), currentOs)
      .map(_.toString)
      .getOrElse(
        fail(
          """error: podman is not installed or not on PATH
            |
            |Install it first: https://podman.io/docs/installation""".stripMargin,
          127
        )
      )

  def readIfPresent(path: Path): Option[String] =
    if Files.isRegularFile(path) then Some(Files.readString(path)) else None

  def firstLine(path: Path): String =
    readIfPresent(path).map(_.linesIterator.nextOption().getOrElse("")).getOrElse("")

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
    Files.deleteIfExists(path)
    Files.writeString(path, content)
    if posixPermissions(path) then
      Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"))

  def writeReadable(path: Path, content: String): Unit =
    Files.deleteIfExists(path)
    Files.writeString(path, content)
    if posixPermissions(path) then
      Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-r--r--"))

  def deleteRecursively(path: Path): Unit =
    if Files.exists(path) then
      Files
        .walk(path)
        .sorted(java.util.Comparator.reverseOrder())
        .iterator()
        .asScala
        .foreach(Files.delete)

  /**
   * A boundary-weakening variable takes exactly one of a closed value set, case-sensitive —
   * never a bare presence test, and no alternate spellings (`1`, `true`, `yes`, …): such a
   * variable can weaken the boundary, so an unclear value must refuse the launch rather than be
   * read as either side of it (DESIGN.md, "Security configuration must fail closed"), and each
   * accepted spelling is surface that has to stay correct everywhere it is parsed. Unset and
   * empty mean the default, which is always the choice that weakens nothing.
   */
  def closedChoice(
      variable: String,
      value: Option[String],
      choices: Vector[String],
      default: String,
      advice: String
  ): Either[String, String] =
    value match
      case None | Some("")                      => Right(default)
      case Some(text) if choices.contains(text) => Right(text)
      case Some(text) =>
        Left(
          s"""error: $variable is set to '$text'; the only values are ${choices.mkString(" and ")}, exactly
             |
             |This variable can weaken the boundary, so an unrecognized value is refused rather
             |than guessed at. $advice""".stripMargin
        )
