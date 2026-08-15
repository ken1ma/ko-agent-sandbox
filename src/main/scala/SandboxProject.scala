// The project directory — the thing that becomes /workspace, and everything the launcher decides
// about it before any resource exists: the real path it resolves to, the directories refused as
// projects outright, the identity its path hashes to (which names every per-project resource), and
// the mount guards that pin or refuse its .git and .ko-agent-sandbox shapes. All pure given their
// arguments, and the most SECURITY.md-cited functions in the launcher; the session's configuration
// variables are deliberately NOT here — they describe a launch, not the project, and live beside
// the --help text they must stay in step with.

package agentsandbox.launcher

import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, Paths}
import java.security.MessageDigest
import scala.jdk.CollectionConverters.*

import HostCommands.*

object SandboxProject:

  /**
   * The current directory, symlinks resolved (like `pwd -P`) — what becomes
   * /workspace, and the thing every per-project resource is named after. A
   * directory that cannot be canonicalized fails the command: falling back
   * to the symbolic spelling would hash to a different project id than the
   * launches that resolved it, and the symlink guards assume a real path.
   */
  def resolveProjectDir(): Path =
    try Paths.get("").toAbsolutePath.toRealPath()
    catch
      case ex: IOException =>
        fail(s"error: cannot resolve the current directory to a real path\n$ex")

  /**
   * Launching from $HOME or a filesystem root would mount ~/.ssh, ~/.aws
   * and ~/.config into the sandbox. Catches the accident, not an attacker:
   * `cd` one directory down and it no longer applies. The environment is a
   * parameter for the same reason the Os is.
   */
  def isForbiddenProjectDir(dir: Path, os: Os, env: String => Option[String]): Boolean =
    def trimmed(p: String) = p.replaceAll("[/\\\\]+$", "")
    val dirText = trimmed(dir.toString)
    os match
      case Os.Windows =>
        val forbidden = Seq("HOME", "USERPROFILE", "PUBLIC").flatMap(env(_)).map(trimmed)
        // A drive root is compared through the path API rather than by trimming, since trimming "C:\" would leave the
        // ambiguous drive-relative "C:".
        forbidden.contains(dirText) || dir.getRoot == dir
      case _ =>
        val forbidden = env("HOME").map(trimmed).toSeq ++ Seq("/", "/home", "/Users", "/root")
        forbidden.contains(dirText) || dirText.isEmpty

  /**
   * Podman accepts [a-zA-Z0-9][a-zA-Z0-9_.-]* only, so fold anything else out.
   */
  def slugOf(directoryName: String): String =
    val folded = directoryName.map: c =>
      if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
        || c == '.' || c == '_' || c == '-'
      then c
      else '-'
    folded.take(32)

  def sha256Hex(text: String): String =
    MessageDigest
      .getInstance("SHA-256")
      .digest(text.getBytes(StandardCharsets.UTF_8))
      .map(b => f"$b%02x")
      .mkString

  /**
   * Lowercased before hashing on Windows, because its paths are
   * case-insensitive: C:\Src\App and C:\src\app are one project and must
   * produce one set of resources. POSIX paths are hashed as spelled.
   * Locale.ROOT, because the machine's locale must not decide identity: the
   * Turkish fold of I to dotless ı would hash the same path differently, and
   * a locale change would orphan every project's volume and sign it out.
   */
  def projectHash(absolutePath: String, os: Os): String =
    val canonical =
      if os == Os.Windows then absolutePath.toLowerCase(java.util.Locale.ROOT) else absolutePath
    sha256Hex(canonical).take(12)

  def projectIdOf(dir: Path, os: Os): String =
    s"${slugOf(dir.getFileName.toString)}-${projectHash(dir.toString, os)}"

  /**
   * The opt-out fallback's enforcement: default sessions get the workspace
   * FUSE filter instead, whose policy is a strict superset of these pins
   * (AgentSandboxLauncher's header map has the split).
   *
   * Host git executes what .git configures — hooks, and commands named in
   * .git/config (core.hooksPath, core.fsmonitor, filters, pagers) — so
   * writing either from inside would turn the user's next `git status` into
   * execution outside the boundary. A mount point cannot be written,
   * deleted or replaced from inside; pinning these two pins the execution
   * surface while the rest of .git stays writable data (SECURITY.md, "The
   * project checkout").
   *
   * Shapes:
   *   - directory: pin config and hooks; an absent one is pinned from the
   *     launcher's own empty source (below) — never created in the project,
   *     and never left to podman, which would manufacture a *directory*
   *     named config on Linux and refuse the missing source on podman
   *     machine;
   *   - pointer file (linked worktree): pin the file itself, so a rewritten
   *     relative gitdir cannot redirect host git into the writable tree;
   *   - absent: pin the name over the launcher's empty directory, so a
   *     sandbox cannot fabricate a repository for host git to discover;
   *   - a symlink anywhere refuses the launch: podman resolves mount
   *     sources on the host.
   *
   * The empty sources are the launcher's, under its state root: the project
   * tree is never written (SECURITY.md, "Silent changes to what you own").
   *
   * The shape is read once, at launch; a bind mount binds the inode, so a
   * repository created on the host mid-session appears inside behind the
   * whole-directory pin, read-only until the next launch. Mid-session
   * changes only ever sit behind a mount coarser than their shape warrants.
   */
  def gitGuardVolumes(gitDir: Path, emptyFile: Path, emptyDir: Path): Either[String, Vector[String]] =
    def refuse(path: Path): Either[String, Vector[String]] =
      Left(
        s"error: $path must not be a symlink\nRefusing to mount the sandbox through one."
      )

    if Files.isSymbolicLink(gitDir) then refuse(gitDir)
    else if Files.isDirectory(gitDir) then
      val config = gitDir.resolve("config")
      val hooks = gitDir.resolve("hooks")
      if Files.isSymbolicLink(config) then refuse(config)
      else if Files.isSymbolicLink(hooks) then refuse(hooks)
      else
        val configSource = if Files.exists(config) then config else emptyFile
        val hooksSource = if Files.exists(hooks) then hooks else emptyDir
        Right(
          Vector(
            s"--volume=$configSource:/workspace/.git/config:ro",
            s"--volume=$hooksSource:/workspace/.git/hooks:ro"
          )
        )
    else if Files.exists(gitDir) then Right(Vector(s"--volume=$gitDir:/workspace/.git:ro"))
    else Right(Vector(s"--volume=$emptyDir:/workspace/.git:ro"))

  /**
   * The launcher-owned empty bind sources gitGuardVolumes pins from. Kept
   * outside the project and re-emptied at every launch *in place* —
   * truncate and clear, never delete-and-recreate — so a concurrent
   * session's running bind keeps its inode and its emptiness.
   */
  def emptyMountSources(launcherStateRoot: Path): (Path, Path) =
    val root = launcherStateRoot.resolve("empty")
    val dir = root.resolve("dir")
    Files.createDirectories(dir)
    Files.list(dir).iterator().asScala.foreach(deleteRecursively)
    val file = root.resolve("file")
    Files.write(file, Array.emptyByteArray)
    (file, dir)

  /**
   * The mount at /workspace/.ko-agent-sandbox must exist on every launch —
   * even with no policy shipped — so a session cannot fabricate the policy
   * governing the next one (SECURITY.md). Created here, not by podman,
   * whose machine path refuses a missing bind source. This creation is the
   * one enumerated exception to "the project tree is never written by the
   * launcher" (SECURITY.md, "Silent changes to what you own"). Refused
   * shapes: a symlink of the directory or of egress-hosts (podman resolves
   * mount sources on the host, and the policy read follows this check),
   * anything that is not a directory, or an entry that is no configuration
   * of this launcher's — the directory is a closed namespace, decided
   * before it has a second tenant, so a typo'd `egres-hosts/` is a refused
   * launch and not ignored config, the same rule egress-hosts/ applies
   * inside itself. The tier files inside egress-hosts/ are vetted where
   * they are read (EgressProxyPolicy.readPolicyFiles).
   */
  def policyGuardVolume(policyDir: Path): Either[String, String] =
    def refuse(path: Path): Either[String, String] =
      Left(
        s"error: $path must not be a symlink\nRefusing to read this project's egress policy through one."
      )

    val hostsDir = policyDir.resolve("egress-hosts")
    if Files.isSymbolicLink(policyDir) then refuse(policyDir)
    else if Files.isSymbolicLink(hostsDir) then refuse(hostsDir)
    else if Files.exists(policyDir) && !Files.isDirectory(policyDir) then
      Left(
        s"error: $policyDir must be a directory\n" +
          "Remove what is in its place; the launcher recreates the policy directory itself."
      )
    else if !Files.exists(policyDir) then
      Files.createDirectory(policyDir)
      Right(s"--volume=$policyDir:/workspace/.ko-agent-sandbox:ro")
    else
      strayPolicyEntries(policyDir) match
        case Vector() => Right(s"--volume=$policyDir:/workspace/.ko-agent-sandbox:ro")
        case stray =>
          Left(
            s"""error: $policyDir contains ${stray.mkString(", ")}, which this launcher does not read
               |The directory is boundary configuration and holds only:
               |${PolicyDirEntries.toVector.sorted.mkString(", ")}. A stray name — a typo'd
               |egress-hosts, notes, a backup — must fail the launch, never sit as ignored config.""".stripMargin
          )

  /**
   * The entries .ko-agent-sandbox may contain. Names beginning with `.` are
   * exempt as editor and OS metadata (.DS_Store, .gitkeep) — no
   * configuration will ever be named that way, so the typo protection loses
   * nothing to the exemption.
   */
  val PolicyDirEntries: Set[String] = Set("egress-hosts")

  private def strayPolicyEntries(policyDir: Path): Vector[String] =
    Files
      .list(policyDir)
      .iterator()
      .asScala
      .map(_.getFileName.toString)
      .filterNot(_.startsWith("."))
      .filterNot(PolicyDirEntries)
      .toVector
      .sorted

  // -------------------------------------------------------------------------
  // Launcher verbs: --build, --update and --reset
  // -------------------------------------------------------------------------
