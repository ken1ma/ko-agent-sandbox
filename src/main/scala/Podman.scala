// Finds, announces and drives the host's podman, and builds the arguments that the launcher passes to it. The file
// depends on the launcher only for running and resolving host commands and for the terminal's output (HostCommands),
// so that it can move into a library.

package agentsandbox.launcher

import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.{Path, Paths}

import HostCommands.*

object Podman:

  /**
   * The podman that every launcher command runs, resolved once, absolutely, through findOnPath.
   *
   *   - The reaper receives this same path as an argument, so its invocations are the launcher's decision too.
   *   - The value is lazy, so `--help` needs no podman at all.
   *   - The first use prints the `using:` line (announcePodman), unless requirePodman printed it first.
   */
  lazy val podman: String =
    announcePodman(None)
    podmanResolution._1

  /** The path of `podman`, without printing the `using:` line: requirePodman prints that line itself, once `podman
    * info` has said the kernel. */
  def unannouncedPodman: String = podmanResolution._1

  def podmanRuns: Boolean = podmanResolution._2.exists(_.ok)

  /** The client build recorded by --self-test, from the same probe as the startup announcement. */
  def podmanVersion(): String =
    podmanResolution._2.filter(_.ok).map(_.text.trim).getOrElse("podman version unknown")

  /** Whether the container runs. A podman that cannot be asked answers no. */
  def containerRunning(podman: String, container: String): Boolean =
    try run(podman, "container", "inspect", "--format", "{{.State.Running}}", container).text.trim == "true"
    catch case _: IOException => false

  /**
   * A Windows relay's loop, which is the POSIX relay's `while` in Java: waits for the sandbox to run, then calls
   * `serveOnce` while the sandbox runs, and pauses a second after a call that served nothing or failed. The first
   * wait is bounded like the reaper's, for a launcher that never reaches the start.
   */
  def serveWhileRunning(podman: String, sandboxContainer: String)(serveOnce: () => Boolean): Unit =
    def running(): Boolean = containerRunning(podman, sandboxContainer)
    var waited = 0
    while !running() && waited < 600 do
      Thread.sleep(1000)
      waited += 1
    while running() do
      val served =
        try serveOnce()
        catch case _: IOException => false
      if !served then Thread.sleep(1000)

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
    (found, version)

  /** Prints the `using:` line once, so that every echoed command can then say just `podman` (echoCommand). `kernel`
    * is the line's tail that AgentSandboxLauncher.machineKernel gives. */
  def announcePodman(kernel: Option[String]): Unit = synchronized:
    if !announced then
      val (found, version) = podmanResolution
      System.err.println(podmanUsingLine(found, version, kernel))
      podmanUpgradeWarning(version).foreach(warn)
      echoAs(found, "podman")
      announced = true

  /** The line grays the path's directory and, on Windows, the file's extension (lookedUp), which a reader consults only
    * when the launcher found an unexpected podman. The version and kernel stay plain, since a reader upgrades podman
    * and the machine by them. */
  def podmanUsingLine(
    path: String,
    result: Option[Run],
    kernel: Option[String] = None,
    os: Os = currentOs,
    environment: String => Option[String] = env,
    color: Boolean = colorStderr,
  ): String =
    val version = result.filter(_.ok).map(_.text.trim).collect:
      case PodmanVersion(value) => s" ($value)"
    val separators = if os == Os.Windows then "/\\" else "/"
    def grayAllButName(shown: String): String =
      val nameStart = shown.lastIndexWhere(separators.contains(_)) + 1
      val extensionStart = if os == Os.Windows then shown.lastIndexOf('.') else -1
      val nameEnd = if extensionStart > nameStart then extensionStart else shown.length
      def grayed(text: String) = if text.isEmpty then text else lookedUp(text, color)
      grayed(shown.take(nameStart)) + shown.slice(nameStart, nameEnd) + grayed(shown.drop(nameEnd))
    val using = pathLine("using", Paths.get(path), os, environment, tint = grayAllButName)
    s"$using${version.getOrElse("")}${kernel.fold("")(", " + _)}"

  private val PodmanVersion = "podman version ([0-9][A-Za-z0-9.+-]*)".r

  /** README.md's prerequisite. */
  val MinimumPodman = "6.2.0"

  /** The warning for a podman older than MinimumPodman, or None. An answer that fails or does not parse gets no
    * warning. */
  def podmanUpgradeWarning(result: Option[Run]): Option[String] =
    result.filter(_.ok).map(_.text.trim).collect { case PodmanVersion(value) => value }
      .filter(olderVersion(_, MinimumPodman))
      .map: value =>
        s"podman $value is older than $MinimumPodman; upgrade it"

  @volatile private var announced = false

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
