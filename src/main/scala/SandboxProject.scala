// The project directory — the thing that becomes /workspace, and everything the launcher decides
// about it before any resource exists: the real path it resolves to, the directories refused as
// projects outright, the identity its path hashes to (which names every per-project resource), and
// the mount guards that pin or refuse its .git and .ko-agent-sandbox layouts. The session's
// configuration variables are deliberately not here — they describe a launch, not the project,
// and live beside the --help text they must stay in step with.

package agentsandbox.launcher

import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, InvalidPathException, Path, Paths}
import java.security.MessageDigest
import scala.jdk.CollectionConverters.*
import scala.util.Using

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
                Seq(
                  s"$name ($value) does not resolve to a real path; " +
                    "only this exact spelling is refused as a project",
                ),
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
   * another home variable resolved, because Git Bash and MSYS2 export a
   * POSIX-style HOME (/c/Users/me) beside a perfectly good USERPROFILE. No
   * home variable at all degrades to the
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
   * podman accepts [a-zA-Z0-9][a-zA-Z0-9_.-]* only, so fold anything else out.
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
   * The layout is read once, at launch; a bind mount binds the inode, so a
   * repository created on the host mid-session appears inside behind the
   * whole-directory pin, read-only until the next launch. Mid-session
   * changes only ever sit behind a mount coarser than their layout warrants.
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
   * Why git does not work in a session on this project directory, while the host directory the
   * user launched from is part of a repository. The container has the project directory at
   * `/workspace` and nothing above or beside it, so git works there only when the repository's
   * control directory is inside the project: a `.git` directory, or a pointer file whose relative
   * target stays within it. Every other shape leaves `/workspace/.git` naming a path the container
   * does not have — a submodule checkout (`gitdir: ../.git/modules/<name>`), a linked worktree, a
   * `--separate-git-dir` repository, an absolute pointer or symlink wherever it leads, a launch
   * from a subdirectory of the repository — and every git command fails with `not a git repository`,
   * which an agent reads as breakage. No workspace path holds control bytes in any of them, so
   * every guard rightly admits the mount.
   *
   * Said at launch and in the agent's instructions — a warning, never a refusal: the host's git is
   * untouched, and a session that only edits files is a legitimate one.
   *
   * Two questions of one resolution (repositoryAt): whether the host has a repository rooted at a
   * directory — a nested worktree or submodule is one, its control directory elsewhere — and
   * whether the container can follow `.git` to that control directory from a given base. A
   * `launchFrom` is the nearest directory holding the project from which the repository git uses
   * there is reachable, so `that whole tree is then the project` is true of it: the superproject
   * over a submodule, the repository root over a subdirectory. A separate git dir has none — nor
   * has any parent of one, under which the pointer stays as absolute — and neither has a linked
   * worktree, whose main worktree is a different checkout, not this one's tree.
   *
   * Nothing is said where host git fails too: a `.git` naming a gitdir git rejects ends its search
   * where it ends this one, and a `.git` that cannot be read or parsed is another check's to refuse
   * (gitGuardVolumes, the filter's own guard). This one never fails a launch.
   */
  enum NoGit:
    case Gitdir(named: String, resolved: Path, launchFrom: Option[Path])
    case Above(repository: Path, launchFrom: Option[Path])

  def noGit(projectDir: Path, homes: HomeProtection): Option[NoGit] =
    repositoryAt(projectDir) match
      case Some(gitdir) if gitdir.reachable => None
      case Some(gitdir) => Some(NoGit.Gitdir(gitdir.named, gitdir.resolved, launchWithGit(projectDir, homes)))
      // A `.git` directory git rejects, or none at all, leaves it searching above, where the
      // container cannot follow. A pointer file it rejects ends the search instead — here as at
      // any ancestor the search would otherwise pass (searched).
      case None if Files.isRegularFile(projectDir.resolve(".git")) => None
      case None =>
        searched(projectDir)
          .find(dir => repositoryAt(dir).isDefined)
          .map(repository => NoGit.Above(repository, launchWithGit(repository, homes)))

  /**
   * The repository rooted at a directory, as the host has it, and whether the container would
   * reach its control directory with `base` as `/workspace`.
   *
   * A shape test, and deliberately not git's own discovery (`is_git_directory` in setup.c reads
   * `HEAD`, `objects` and `refs`, the last two through a linked worktree's `commondir`): the
   * gitdir must exist and hold a `HEAD`, the one entry every gitdir shape has. Reproducing the
   * rest buys an exactness this cannot spend — what it decides is a warning and a suggested
   * launch, never a refusal, and host git states the authoritative failure in its own words. The
   * cost, in full: a `.git` git would reject and search past counts here, so a session under one
   * hears nothing, and such a directory can be the launch named.
   */
  private def repositoryAt(dir: Path): Option[Gitdir] = repositoryAt(dir, base = dir)

  private def repositoryAt(dir: Path, base: Path): Option[Gitdir] =
    gitdirOf(dir, base).filter(gitdir => Files.exists(gitdir.resolved.resolve("HEAD")))

  /** `named` is what `.git` names, as it is written, which is what the warning shows; `reachable`
    * says the container can take every step there, which is what decides whether it has git. */
  private case class Gitdir(named: String, resolved: Path, reachable: Boolean)

  /**
   * Where `.git` leads: the OS follows a symlink when git opens the path, but a pointer file's
   * relative `gitdir:` resolves against the directory holding the `.git` pathname — never the
   * symlink's own — and what it names is a gitdir, never a second pointer file
   * (`read_gitfile_gently`). So there are two steps at most, and one base for both.
   *
   * `reachable` is the container's side of those steps, and deliberately approximate: each must be
   * relative, never climb above `base` — the directory that would be `/workspace` — and land
   * inside it. The container resolves the same two steps under a `/workspace` of its own, so a
   * step that is absolute, or that leaves the base and re-enters the host's path by name
   * (`../foo/x` under `/root/foo`), leads nowhere there; one through a symlinked component is
   * judged where the host's link really lands.
   */
  private def gitdirOf(dir: Path, base: Path): Option[Gitdir] =
    val dotGit = dir.resolve(".git")
    val link =
      if !Files.isSymbolicLink(dotGit) then None
      else
        try gitdirNamed(dir, base, Files.readSymbolicLink(dotGit).toString)
        catch case _: IOException => None
    if Files.isSymbolicLink(dotGit) && link.isEmpty then None
    else if Files.isDirectory(dotGit) then Some(link.getOrElse(Gitdir(".git", dotGit, reachable = true)))
    else if !Files.isRegularFile(dotGit) then None
    else
      gitfileTarget(dotGit)
        .flatMap(gitdirNamed(dir, base, _))
        .map(gitdir => gitdir.copy(reachable = gitdir.reachable && link.forall(_.reachable)))

  /** The gitdir one step names, resolved against the directory holding `.git`, and whether the
    * container can take that step under `base` (gitdirOf). */
  private def gitdirNamed(dir: Path, base: Path, target: String): Option[Gitdir] =
    try
      val path = dir.getFileSystem.getPath(target)
      val resolved = dir.resolve(path).toAbsolutePath.normalize
      val under = base.toAbsolutePath.normalize.relativize(dir.toAbsolutePath.normalize)
      val stays = !path.isAbsolute
        && !under.resolve(path).normalize.startsWith("..")
        && realized(resolved).startsWith(realized(base))
      Some(Gitdir(target, resolved, stays))
    catch case _: InvalidPathException => None

  /** git's `read_gitfile_gently` (setup.c): a file of at most 1 MiB that begins `gitdir: ` — that
    * spelling, at its start — and the rest of it, less trailing CR and LF, is the path. A file of
    * another shape is no pointer to git, and a later line naming a gitdir is not one either. The
    * bound is the read itself, one byte past it and no more, so a `.git` of any size — or one
    * growing while it is read — costs the launcher nothing. */
  private def gitfileTarget(gitfile: Path): Option[String] =
    val bound = 1 << 20
    try
      val bytes = Using.resource(Files.newInputStream(gitfile))(_.readNBytes(bound + 1))
      if bytes.length > bound then None
      else
        val text = String(bytes, StandardCharsets.UTF_8)
        Option
          .when(text.startsWith("gitdir: ")):
            val body = text.substring("gitdir: ".length)
            body.substring(0, body.lastIndexWhere(char => char != '\n' && char != '\r') + 1)
          .filter(_.nonEmpty)
    catch case _: IOException => None

  /** The nearest directory holding the project from which the repository git uses there is
    * reachable — judged on that repository's own `.git` chain, never on the candidate's: a parent
    * whose own `.git` is fine holds a nested absolute pointer exactly as absolute as before, and a
    * parent with no repository of its own still serves a pointer into a sibling. A directory the
    * launcher would refuse as the project (forbiddenProjectDirReason) is passed over, not stopped
    * at: it is no launch at all, and what lies above it may still be one. */
  private def launchWithGit(repository: Path, homes: HomeProtection): Option[Path] =
    (Iterator(repository.toAbsolutePath.normalize) ++ ancestors(repository))
      .filter(base => forbiddenProjectDirReason(base, homes).isEmpty)
      .find(base => repositoryAt(repository, base).exists(_.reachable))

  /** The ancestors host git's search from this directory reaches: a `.git` file it rejects is a
    * failure there, not a step passed over, so the search — and every answer drawn from it — ends
    * at that directory (`setup_git_directory_gently_1`). A repository whose control directory the
    * container cannot reach is not such a stop: git works there, and a launch above it still
    * holds the project. */
  private def searched(projectDir: Path): Iterator[Path] =
    ancestors(projectDir).takeWhile: dir =>
      repositoryAt(dir).isDefined || !Files.isRegularFile(dir.resolve(".git"))

  private def ancestors(dir: Path): Iterator[Path] =
    Iterator.iterate(dir.toAbsolutePath.normalize.getParent)(_.getParent).takeWhile(_ != null)

  /** The path with its deepest existing ancestor resolved, so a root reached through a symlink —
    * macOS's `/var` — compares equal to its real spelling whether or not the leaf exists. */
  private def realized(path: Path): Path =
    val absolute = path.toAbsolutePath.normalize
    Iterator.iterate(absolute)(_.getParent).takeWhile(_ != null).find(Files.exists(_)) match
      case Some(existing) =>
        try existing.toRealPath().resolve(existing.relativize(absolute))
        catch case _: IOException => absolute
      case None => absolute

  /** The launch's warning: what is wrong, and the launch that would have git. */
  def noGitWarning(noGit: NoGit): String =
    val (cause, launchFrom) = noGit match
      case NoGit.Gitdir(named, resolved, launchFrom) =>
        (s".git names $named ($resolved), a gitdir the container does not have", launchFrom)
      case NoGit.Above(repository, launchFrom) =>
        (s"the repository at $repository is above the project directory, which is all the " +
          "container has", launchFrom)
    s"git will not work in this session: $cause." +
      launchFrom.fold(" Git operations stay on the host.")(path =>
        s" To have git, launch from $path, which holds this directory; that whole tree is then the project.",
      )

  /** The same fact in the container's words, for the agent's instructions. */
  def noGitInstruction(noGit: NoGit): String = noGit match
    case NoGit.Gitdir(named, _, _) =>
      s"`/workspace/.git` names `$named`, a gitdir the sandbox does not have"
    case NoGit.Above(_, _) =>
      "the repository's `.git` lies above the project directory, which is all the sandbox has"

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
   * Why .ko-agent-sandbox cannot serve as this project's boundary directory, or None. Checked in
   * every write mode before the rules are read — the read is a host-side read either way.
   * Refused forms: a symlink of the directory or of an entry (podman resolves mount sources on
   * the host, and the rule read must see the bytes a mounted-back directory would show);
   * anything that is not a directory; or an entry that is no configuration of this launcher's —
   * the directory is a closed namespace, so a typo'd `egres/` is a refused launch and not
   * ignored config, the same rule each entry applies inside itself. The files inside egress/ and
   * agent/ are vetted where they are read (EgressRules.readRuleFiles,
   * readAgentInstructions), and host-command/ where the host build wrapper reads it
   * (RunOnHostPolicy.buildRuleHosts). An absent directory is empty configuration, never a
   * directory to materialize.
   */
  def boundaryDirError(boundaryDir: Path): Option[String] =
    def symlinkRefusal(path: Path): String =
      s"error: $path must not be a symlink\nRefusing to read this project's egress rules through one."

    val linkedEntry = BoundaryDirEntries.toVector.sorted.map(boundaryDir.resolve).find(Files.isSymbolicLink)
    if Files.isSymbolicLink(boundaryDir) then Some(symlinkRefusal(boundaryDir))
    else if linkedEntry.isDefined then linkedEntry.map(symlinkRefusal)
    else if Files.exists(boundaryDir) && !Files.isDirectory(boundaryDir) then
      Some(
        s"error: $boundaryDir must be a directory\n" +
          "Remove what is in its place; the directory holds this project's boundary configuration.",
      )
    else if !Files.exists(boundaryDir) then None
    else
      strayBoundaryEntries(boundaryDir) match
        case Vector() => None
        case stray =>
          Some(
            s"""error: $boundaryDir contains ${stray.mkString(", ")}, which this launcher does not read
               |The directory is boundary configuration and holds only:
               |${BoundaryDirEntries.toVector.sorted.mkString(", ")}. A stray name must fail the
               |launch, never sit as ignored config — and it is either a typo or a boundary file a
               |newer launcher reads, so check the spelling or update the launcher and image.""".stripMargin
          )

  /**
   * guard=none's mount at /workspace/.ko-agent-sandbox, which must exist even with no
   * configuration shipped so that session cannot fabricate the configuration governing the next
   * one (SECURITY.md): with the raw tree bound writable, the read-only mount-back is the only thing
   * standing between the session and the boundary files. Created here when absent, not by podman,
   * whose machine path refuses a missing bind source — a residue of guard=none alone: the
   * FUSE filter enforces the same rule by name (protected-sandbox-config) with no mount and no
   * created path, and reject mode's read-only tree needs neither. Call after boundaryDirError.
   */
  def boundaryGuardVolume(boundaryDir: Path): String =
    if !Files.exists(boundaryDir) then Files.createDirectory(boundaryDir)
    s"--volume=$boundaryDir:/workspace/.ko-agent-sandbox:ro"

  val BoundaryDirEntries: Set[String] = Set("egress", "agent", "host-command")

  /** The one file agent/ holds: the project's replacement for the image's AGENTS-CUSTOM.md. */
  val AgentInstructionsFile: String = "AGENTS-CUSTOM.md"

  /**
   * The project's agent instructions under .ko-agent-sandbox/agent, or None when it ships none.
   * Read on the host, so the same forms egress/ refuses (EgressRules.readRuleFiles) are
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
   * Whether an entry of the closed boundary namespace is exempt from its unknown-name refusal:
   * dot-named editor and OS metadata (.DS_Store, .gitkeep). No configuration will ever be named
   * that way, so the typo protection loses nothing. One predicate for .ko-agent-sandbox and for
   * egress/ inside it (EgressRules.readRuleFiles), so browsing the tree on macOS cannot
   * fail the next launch at either level.
   */
  def isMetadataEntry(name: String): Boolean = name.startsWith(".")

  private def strayBoundaryEntries(boundaryDir: Path): Vector[String] =
    Files
      .list(boundaryDir)
      .iterator()
      .asScala
      .map(_.getFileName.toString)
      .filterNot(isMetadataEntry)
      .filterNot(BoundaryDirEntries)
      .toVector
      .sorted
