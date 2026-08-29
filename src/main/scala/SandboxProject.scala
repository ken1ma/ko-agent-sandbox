// The project directory — the thing that becomes /workspace, and everything the launcher decides
// about it before any resource exists: the real path it resolves to, the directories refused as
// projects outright, the identity its path hashes to (which names every per-project resource), and
// the mount guards that pin or refuse its .git and .ko-agent-sandbox shapes. The session's
// configuration variables are deliberately not here — they describe a launch, not the project,
// and live beside the --help text they must stay in step with.

package agentsandbox.launcher

import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, InvalidPathException, Path, Paths}
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

  private def normalizedAndCanonical(path: Path): Seq[Path] =
    val normalized = path.normalize()
    try Seq(normalized, normalized.toRealPath()).distinct
    catch case _: IOException => Seq(normalized)

  /**
   * The outcome of home discovery: the directories refused as projects,
   * which of them are *containers* of homes rather than homes — their direct
   * children are refused too, because a child of /home is somebody's home and
   * exposes that account's credentials exactly as this one's would — and
   * anything the user should hear about how the set was derived: a home
   * variable that was dropped, could not be canonicalized, or was never set.
   * Warnings rather than errors: this guard catches accidents, and a degraded
   * guard that says so beats a refused launch in a HOME-less environment.
   */
  final case class HomeProtection(paths: Seq[Path], containers: Seq[Path], warnings: Seq[String])

  /**
   * One home variable: Left when the value cannot name a directory at all,
   * Right with the normalized and (best-effort) canonical spellings. A value
   * that fails toRealPath is still protected by its exact spelling, but with
   * a warning — silently keeping only the symbolic form while the candidate
   * project dir is always canonical would disable the comparison unnoticed.
   */
  private def parseHomeVariable(name: String, value: String): Either[String, (Seq[Path], Seq[String])] =
    try
      val candidate = Paths.get(value)
      if !candidate.isAbsolute then Left(s"$name must name an absolute directory")
      else
        val normalized = candidate.normalize()
        try Right((Seq(normalized, normalized.toRealPath()).distinct, Seq.empty))
        catch
          case _: IOException =>
            Right(
              (
                Seq(normalized),
                Seq(s"$name ($value) does not resolve to a real path; only this exact spelling is refused as a project"),
              ),
            )
    catch case _: InvalidPathException => Left(s"$name is not a valid path")

  /**
   * Refused whether or not a configured home sits beneath them: the
   * directories operating systems keep user homes in, so a relocated or
   * unset HOME never leaves /home or /Users mountable. Returned as
   * (containers, homes) — `/home` and `/Users` hold homes, `/root` and
   * `/var/root` are homes — because only a container's direct children are
   * refused. The Windows profiles root is derived from SystemDrive rather
   * than from USERPROFILE's parent, so it stays protected when the current
   * profile lives on another drive, and falls back to `C:` so an environment
   * without even SystemDrive keeps the boundary SECURITY.md states.
   * Best-effort canonicalized; a root absent on this machine is kept as
   * spelled and protects nothing that exists.
   */
  private def wellKnownHomeRoots(os: Os, env: String => Option[String]): (Seq[Path], Seq[Path]) =
    os match
      case Os.Linux | Os.Mac =>
        (
          Seq("/home", "/Users").map(Paths.get(_)).flatMap(normalizedAndCanonical),
          Seq("/root", "/var/root").map(Paths.get(_)).flatMap(normalizedAndCanonical),
        )
      case Os.Windows =>
        val drive = env("SystemDrive").filter(_.nonEmpty).getOrElse("C:")
        val profiles =
          try normalizedAndCanonical(Paths.get(drive + java.io.File.separator + "Users"))
          catch case _: InvalidPathException => Seq.empty
        (profiles, Seq.empty)

  /**
   * macOS exposes the writable data volume both at / and at
   * /System/Volumes/Data — a firmlink, which toRealPath does not collapse
   * (it is not a symlink). Every protected path therefore also gets its
   * other spelling, so `cd /System/Volumes/Data/Users/me` cannot mount the
   * home the guard refuses as /Users/me.
   */
  private val MacDataVolumePrefix = "/System/Volumes/Data"
  /** Not private: the state-root containment check compares the same firmlink spellings
    * (AgentSandboxLauncher.forbiddenStateRootReason). */
  def withMacDataVolumeAliases(paths: Seq[Path]): Seq[Path] =
    paths.flatMap: path =>
      val text = path.toString
      val alias =
        if text.startsWith(MacDataVolumePrefix + "/") then Some(Paths.get(text.stripPrefix(MacDataVolumePrefix)))
        else if text.startsWith("/") && text != MacDataVolumePrefix then Some(Paths.get(MacDataVolumePrefix + text))
        else None
      path +: alias.toSeq

  /**
   * The directories whose contents must never become a project mount, and
   * the warnings describing any degradation in deriving them. PUBLIC is the
   * shared Windows profile. A home variable that is set but invalid refuses
   * the launch on POSIX; on Windows it is dropped with a warning as long as
   * another home variable resolved,
   * because Git Bash and MSYS2 export a POSIX-style HOME (/c/Users/me) beside
   * a perfectly good USERPROFILE. No home variable at all degrades to the
   * well-known roots, with a warning — HOME-less environments (cron, CI,
   * env -i) stay launchable under the static guard.
   */
  def protectedHomeDirectories(
    os: Os,
    env: String => Option[String],
  ): Either[String, HomeProtection] =
    val homeVariables = os match
      case Os.Linux | Os.Mac => Seq("HOME")
      case Os.Windows        => Seq("USERPROFILE", "HOME")

    val configured = homeVariables.flatMap: name =>
      env(name).filter(_.nonEmpty).map(name -> _)
    val parsed = configured.map((name, value) => (name, value, parseHomeVariable(name, value)))
    val resolved = parsed.collect { case (_, _, Right(result)) => result }

    if configured.nonEmpty && resolved.isEmpty then
      val problem = parsed.collectFirst { case (_, _, Left(problem)) => problem }.get
      Left(
        s"""error: $problem
           |Cannot determine which project directories are safe to mount.""".stripMargin
      )
    else
      val unsetWarnings =
        if configured.isEmpty then
          val missing = os match
            case Os.Linux | Os.Mac => "HOME is not set"
            case Os.Windows        => "neither USERPROFILE nor HOME is set"
          Seq(s"$missing; only the well-known home directories are refused as projects")
        else Seq.empty
      val droppedWarnings = parsed.collect { case (_, _, Left(problem)) =>
        s"$problem; dropped, since the remaining home variables cover the boundary"
      }

      val public = os match
        case Os.Windows =>
          env("PUBLIC").filter(_.nonEmpty).toSeq.map(value => (value, parseHomeVariable("PUBLIC", value)))
        case Os.Linux | Os.Mac => Seq.empty
      val publicPaths = public.collect { case (_, Right((paths, _))) => paths }.flatten
      val publicWarnings = public.flatMap {
        case (_, Right((_, warnings))) => warnings
        case (_, Left(problem))        => Seq(s"$problem; dropped")
      }

      val (containers, wellKnownHomes) = wellKnownHomeRoots(os, env)
      val paths = resolved.flatMap(_._1) ++ publicPaths ++ containers ++ wellKnownHomes
      val alias = (values: Seq[Path]) =>
        if os == Os.Mac then withMacDataVolumeAliases(values) else values
      Right(
        HomeProtection(
          alias(paths).distinct,
          alias(containers).distinct,
          unsetWarnings ++ droppedWarnings ++ resolved.flatMap(_._2) ++ publicWarnings,
        ),
      )

  /**
   * Why dir must not become /workspace, or None if it may. The reason is
   * user-facing and names the rule that fired: telling someone inside
   * ~/.config to "change into a project directory" would send them deeper
   * into a tree the dot rule refuses everywhere. A project at <home>/project
   * remains valid (HomeProtection has what is refused).
   */
  def forbiddenProjectDirReason(dir: Path, homes: HomeProtection): Option[String] =
    val candidate = dir.normalize()
    val dotDirectory = candidate.iterator().asScala.map(_.toString).find(_.startsWith("."))

    if candidate.getRoot == candidate || candidate.toString.isEmpty then
      Some(
        "It is a filesystem root: the whole system would be exposed to the agent.\n" +
          "Change into a project directory and run this again.",
      )
    else
      dotDirectory match
        case Some(name) =>
          Some(
            s"The resolved path contains the dot-prefixed directory '$name'. Dot directories hold\n" +
              "configuration and credentials (~/.ssh, ~/.aws, ~/.config), so nothing beneath one is\n" +
              "mounted; symlinks are resolved first, so the dot directory may come from where a link\n" +
              "leads rather than from the path as typed. Move the project outside dot-prefixed\n" +
              "directories and run this again.",
          )
        case None =>
          val insideAContainer = Option(candidate.getParent).exists(homes.containers.contains)
          if homes.paths.exists(_.startsWith(candidate)) || insideAContainer then
            Some(
              "It is a home directory, or a directory containing one: anything like .aws, .ssh or\n" +
                ".config beneath it would be exposed to the agent.\n" +
                "Change into a project directory and run this again.",
            )
          else None

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
   * Enforcement under guard=none: default sessions get the workspace
   * FUSE filter instead, whose policy is a strict superset of these pins
   * (AgentSandboxLauncher's header map has the split).
   *
   * Host git executes what .git configures — hooks, and commands named in
   * .git/config (core.hooksPath, core.fsmonitor, filters, pagers) — so
   * writing either from inside would turn the user's next `git status` into
   * execution outside the boundary. A mount point cannot be written,
   * deleted or replaced from inside; pinning these two pins the execution
   * surface while the rest of .git stays writable data (SECURITY.md, "The
   * project directory").
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
        s"error: $path must not be a symlink\nRefusing to mount the sandbox through one.",
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
            s"--volume=$hooksSource:/workspace/.git/hooks:ro",
          ),
        )
    else if Files.exists(gitDir) then Right(Vector(s"--volume=$gitDir:/workspace/.git:ro"))
    else Right(Vector(s"--volume=$emptyDir:/workspace/.git:ro"))

  /**
   * The launcher-owned empty bind sources gitGuardVolumes pins from. Kept
   * outside the project and re-emptied at every launch *in place*: never
   * delete-and-recreate, for the reason in HostCommands.writeWithMode, and
   * not rename-and-replace either — a concurrent session's running bind
   * keeps this very inode, and its emptiness with it.
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
   * Why .ko-agent-sandbox cannot serve as this project's policy directory, or None. Checked in
   * every write mode before the policy is read — the read is a host-side read either way.
   * Refused shapes: a symlink of the directory or of an entry (podman resolves mount sources on
   * the host, and the policy read must see the bytes a mounted-back directory would show);
   * anything that is not a directory; or an entry that is no configuration of this launcher's —
   * the directory is a closed namespace, so a typo'd `egres/` is a refused launch and not
   * ignored config, the same rule each entry applies inside itself. The files inside egress/ and
   * agent/ are vetted where they are read (EgressProxyPolicy.readPolicyFiles,
   * readAgentInstructions). An absent directory is empty policy input, never a directory to
   * materialize.
   */
  def policyDirError(policyDir: Path): Option[String] =
    def symlinkRefusal(path: Path): String =
      s"error: $path must not be a symlink\nRefusing to read this project's egress policy through one."

    val linkedEntry = PolicyDirEntries.toVector.sorted.map(policyDir.resolve).find(Files.isSymbolicLink)
    if Files.isSymbolicLink(policyDir) then Some(symlinkRefusal(policyDir))
    else if linkedEntry.isDefined then linkedEntry.map(symlinkRefusal)
    else if Files.exists(policyDir) && !Files.isDirectory(policyDir) then
      Some(
        s"error: $policyDir must be a directory\n" +
          "Remove what is in its place; the directory holds this project's boundary configuration.",
      )
    else if !Files.exists(policyDir) then None
    else
      strayPolicyEntries(policyDir) match
        case Vector() => None
        case stray =>
          Some(
            s"""error: $policyDir contains ${stray.mkString(", ")}, which this launcher does not read
               |The directory is boundary configuration and holds only:
               |${PolicyDirEntries.toVector.sorted.mkString(", ")}. A stray name (a typo'd
               |egress, notes, a backup) must fail the launch, never sit as ignored config.""".stripMargin
          )

  /**
   * guard=none's mount at /workspace/.ko-agent-sandbox, which must exist even with no
   * policy shipped so that session cannot fabricate the policy governing the next one
   * (SECURITY.md): with the raw tree bound writable, the read-only mount-back is the only thing
   * standing between the session and the policy files. Created here when absent, not by podman,
   * whose machine path refuses a missing bind source — a residue of guard=none alone: the
   * FUSE filter enforces the same rule by name (protected-sandbox-config) with no mount and no
   * created path, and reject mode's read-only tree needs neither. Call after policyDirError.
   */
  def policyGuardVolume(policyDir: Path): String =
    if !Files.exists(policyDir) then Files.createDirectory(policyDir)
    s"--volume=$policyDir:/workspace/.ko-agent-sandbox:ro"

  val PolicyDirEntries: Set[String] = Set("egress", "agent")

  /** The one file agent/ holds: the project's replacement for the image's AGENTS-CUSTOM.md. */
  val AgentInstructionsFile: String = "AGENTS-CUSTOM.md"

  /**
   * The project's agent instructions under .ko-agent-sandbox/agent, or None when it ships none.
   * Read on the host, so the same shapes egress/ refuses (EgressProxyPolicy.readPolicyFiles) are
   * refused here for the same reasons: agent as a file, a stray name, a symlink, a non-regular
   * file, an empty file. Not normalized — it is prose, mounted as written.
   */
  def readAgentInstructions(agentDir: Path): Either[String, Option[String]] =
    def symlinkRefusal(path: Path): String =
      s"error: $path must not be a symlink\nRefusing to read this project's agent instructions through one."

    val file = agentDir.resolve(AgentInstructionsFile)
    if Files.isSymbolicLink(agentDir) then Left(symlinkRefusal(agentDir))
    else if !Files.exists(agentDir) then Right(None)
    else if !Files.isDirectory(agentDir) then
      Left(
        s"""error: $agentDir is a file
           |agent is a directory holding $AgentInstructionsFile; move the file there.""".stripMargin
      )
    else
      val entries = Files
        .list(agentDir)
        .iterator()
        .asScala
        .filterNot(entry => isMetadataEntry(entry.getFileName.toString))
        .toVector
        .sortBy(_.getFileName.toString)

      val refusal = entries
        .collectFirst:
          case entry if entry.getFileName.toString != AgentInstructionsFile =>
            s"error: $entry is not agent instructions\nagent/ holds only $AgentInstructionsFile; " +
              "a stray name would be ignored config."
          case entry if Files.isSymbolicLink(entry) => symlinkRefusal(entry)
          case entry if !Files.isRegularFile(entry) =>
            s"error: $entry is not a regular file\nagent/$AgentInstructionsFile is a text file; " +
              "anything else would leave it silently unread."
        .orElse:
          Option.when(readIfPresent(file).exists(_.isBlank))(
            s"error: $file is empty\nDelete the file; the image's own instructions then apply."
          )

      refusal.toLeft(readIfPresent(file))

  /**
   * Whether an entry of a closed policy namespace is exempt from its unknown-name refusal:
   * dot-named editor and OS metadata (.DS_Store, .gitkeep). No configuration will ever be named
   * that way, so the typo protection loses nothing. One predicate for .ko-agent-sandbox and for
   * egress/ inside it (EgressProxyPolicy.readPolicyFiles), so browsing the tree on macOS cannot
   * fail the next launch at either level.
   */
  def isMetadataEntry(name: String): Boolean = name.startsWith(".")

  private def strayPolicyEntries(policyDir: Path): Vector[String] =
    Files
      .list(policyDir)
      .iterator()
      .asScala
      .map(_.getFileName.toString)
      .filterNot(isMetadataEntry)
      .filterNot(PolicyDirEntries)
      .toVector
      .sorted
