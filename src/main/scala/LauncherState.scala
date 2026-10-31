// The launcher's per-user state root, with the inspection CAs, audit logs, ruleset stamps and workspace records under
// it. This file also holds the resets that remove what launches leave (--reset, --reset-run-on-host, --reset-all), and
// the name patterns by which the resets find podman's objects.

package agentsandbox.launcher

import java.io.IOException
import java.nio.file.{Files, Path, Paths}

import AgentSandboxLauncher.*
import HostCommands.*
import FileHelper.*
import ImageBuilds.*
import KoAgentFs.*
import LauncherImages.*
import SandboxWorkspace.*

object LauncherState:

  // Every launcher-made name ends with a generated tail: the folded directory slug, the twelve-hex path hash
  // (SandboxWorkspace.workspaceIdOf), and, for per-run resources, the eight-hex run suffix.
  // - `--reset-all` matches whole names against these patterns rather than bare prefixes. The reset force-removes what
  //   it matches, and a prefix alone would also take a user's own `ko-agent-sandbox-persistent-backup`.
  // - A pattern is not provenance, so the patterns are a reserved namespace, and SECURITY.md states them as such
  //   ("Silent changes to what you own"). The reset removes an object hand-named inside a pattern like the launcher's
  //   own objects.
  // - The launcher adopts one user-supplied name, the shared volume, and refuses that name when it strays into a
  //   pattern (sharedVolumeNameRefusal).

  /** Whether `name` is `builder(<any workspace id>, <run suffix>)`, matched whole. */
  private def isAnyWorkspaceRunNamed(builder: (String, String) => String)(name: String): Boolean =
    name.matches(builder(WorkspaceIdPattern, RunSuffixPattern))

  /**
   * Why `name` may not serve as the shared agent-state volume, or None.
   * - `--reset-all` removes the generated volume pattern by name. Adopting a user-supplied name inside the pattern
   *   would hand that sweep a volume that the sweep must not own. Such a name could even be another workspace's real
   *   volume, spelled out to alias its sign-ins.
   * - The launch refuses the name, where the volume would be created and used, rather than the reset that deletes the
   *   volume discovering it.
   * - The one name inside the pattern that a launch adopts is the main worktree's (mainWorktreeVolume). The
   *   worktree's own Git metadata names that volume rather than the user, and the user agrees to it at the prompt.
   */
  def sharedVolumeNameRefusal(name: String): Option[String] =
    Option.when(name.matches(persistentVolumeName(WorkspaceIdPattern)))(
      s"--persistent-volume=$name has the launcher's generated " +
        "volume-name pattern, and --reset-all removes every volume matching it\n\n" +
        s"Choose a name outside ${persistentVolumeName("<slug>-<12 hex>")}.",
    )

  /** The volume that a launch from `main` itself mounts (SandboxWorkspace.mainWorktreeOf has the spelling). */
  def mainWorktreeVolume(main: Path, os: Os): String =
    persistentVolumeName(workspaceIdOf(main, os))

  /** What a linked worktree's `--reset` says about the main worktree's volume, which the reset leaves in place. */
  def mainWorktreeVolumeNote(main: Path, os: Os): String =
    s"note: leaving the main worktree's volume ${mainWorktreeVolume(main, os)} in place; " +
      s"run --reset in ${pathInline(main, os)} to remove it"

  def proxyContainers(names: Seq[String]): Seq[String] =
    names.filter(isAnyWorkspaceRunNamed(proxyRunContainer))

  /**
   * Run containers are --rm and normally remove themselves. A run container survives only when its launcher died
   * between create and start, and its reaper failed too. This filter is the resets' fallback sweep, not the primary
   * cleanup.
   */
  def sandboxRunContainers(names: Seq[String]): Seq[String] =
    names.filter(isAnyWorkspaceRunNamed(sandboxRunContainer))

  private val RunContainerName = s"ko-agent-(sandbox-run|egress-proxy)-($WorkspaceIdPattern)-($RunSuffixPattern)".r

  /** The kind, workspace id and run suffix of a container in the namespace that the two filters above sweep, or None.
    * `--stats` reads the names back one at a time. */
  def runContainerParts(name: String): Option[(String, String, String)] =
    name match
      case RunContainerName(kind, workspaceId, suffix) => Some((kind, workspaceId, suffix))
      case _                                         => None

  /**
   * The resets deliberately leave volumes named through --persistent-volume alone. Such a volume cannot match this
   * pattern, because a matching value refuses the launch (sharedVolumeNameRefusal).
   */
  def persistentVolumes(names: Seq[String]): Seq[String] =
    names.filter(_.matches(persistentVolumeName(WorkspaceIdPattern)))

  def launcherNetworks(names: Seq[String]): Seq[String] =
    names.filter: name =>
      isAnyWorkspaceRunNamed(sandboxRunNetwork)(name) || isAnyWorkspaceRunNamed(egressRunNetwork)(name)

  def workspaceNetworks(names: Seq[String], workspaceId: String): Seq[String] =
    names.filter: name =>
      isRunNamed(sandboxRunNetwork, workspaceId)(name)
        || isRunNamed(egressRunNetwork, workspaceId)(name)

  /**
   * `--reset`'s operands: none, for the current directory's workspace, or ids as `--stats` prints them. An id is the
   * one name left once a workspace root is gone, because the hash in the id is one-way.
   */
  def workspaceIdOperands(action: String, rest: List[String]): Either[String, Vector[String]] =
    rest.find(id => !isWorkspaceId(id)) match
      case Some(odd) => Left(s"error: $action $odd; a workspace id is as --stats prints it, <slug>-<12 hex digits>")
      case None =>
        rest.diff(rest.distinct).headOption match
          case Some(twice) => Left(s"error: $action names $twice twice")
          case None        => Right(rest.toVector)

  /**
   * `--reset` (README.md has what the reset removes). The reset leaves every other workspace's state and the built
   * images alone.
   * - The reset checks the roots against the current directory whichever workspaces are named, as `--reset-all` checks
   *   them, because the deletions happen under the roots either way.
   * - The reset resets every id before reporting any failure, so one workspace's failed step does not leave the next
   *   workspace untouched.
   */
  def resetWorkspace(os: Os, givenIds: Vector[String], sharedVolume: Option[String], sharedFrom: String): Nothing =
    val workspaceRoot = resolveWorkspaceRoot(os)
    // This check runs before the deletions below: a state root that overlaps the workspace root must refuse here, not
    // aim `rm -rf` at the workspace.
    requireStateRootOutside(os, workspaceRoot)
    val ids = if givenIds.isEmpty then Vector(workspaceIdOf(workspaceRoot, os)) else givenIds
    // Only the directory's own reset reads the main worktree, because a named id's directory is gone, with its
    // metadata.
    val mainWorktree =
      if givenIds.nonEmpty then None
      else SandboxWorkspace.mainWorktreeOf(workspaceRoot, protectedHomeDirectories(os, env).fold(fail(_), identity), os)
    val outcomes = ids.map: id =>
      // A podman that stops answering mid-way counts as one failed step of this id, not as the end of the run.
      id -> (
        try resetOne(os, workspaceRoot, id, named = givenIds.nonEmpty, mainWorktree, sharedVolume, sharedFrom)
        catch
          case ex: IOException =>
            System.err.println(s"$id: $ex")
            Reset(failures = 1, found = true)
      )
    val failures = outcomes.map(_._2.failures).sum
    if failures > 0 then fail(s"error: $failures reset steps failed")
    // A typed id that names nothing is refused after its no-op sweep. A directory's own id needs no such check.
    val unknown = if givenIds.isEmpty then Vector.empty else outcomes.collect { case (id, Reset(_, false)) => id }
    if unknown.nonEmpty then fail(s"error: no workspace ${unknown.mkString(", ")}; --stats lists them")
    sys.exit(0)

  /** One workspace's reset: how many steps failed, and whether anything named the id at all. */
  private case class Reset(failures: Int, found: Boolean)

  /** `named` says that the id came from the command line rather than from `workspaceRoot`, the directory that the
    * reset runs in. Every failure is a counted step, never an exception, so the reset still resets the ids after this
    * one. */
  private def resetOne(
    os: Os,
    workspaceRoot: Path,
    id: String,
    named: Boolean,
    mainWorktree: Option[Path],
    sharedVolume: Option[String],
    sharedFrom: String,
  ): Reset =
    var failures = 0
    var found = false
    def remove(kind: String, name: String): Unit = if !resetRemoved(podman, kind, name) then failures += 1
    def deleteTree(dir: Path): Unit =
      found |= Files.exists(dir)
      try removeTree(dir)
      catch
        case ex: IOException =>
          failures += 1
          System.err.println(s"rm -rf $dir: $ex")

    // The reset removes everything that this workspace's launches created, stray or live. Removing a running session's
    // containers ends that session, which is what "reset" means.
    val containers = run(podman, "ps", "--all", "--format", "{{.Names}}")
    if !containers.ok then
      failures += 1
      System.err.println(containers.err)
    containers.text.linesIterator
      .map(_.trim)
      .filter: name =>
        isRunNamed(proxyRunContainer, id)(name) || isRunNamed(sandboxRunContainer, id)(name)
      .foreach: name =>
        found = true
        remove("container", name)

    // The reset removes only the computed per-workspace volume, because a volume shared through --persistent-volume
    // belongs to other workspaces too.
    // A failed probe is a failed step, not an absent volume, so a failed probe does not drop the record below.
    val volume = persistentVolumeName(id)
    val volumeExists: Option[Boolean] =
      val probe = run(podman, "volume", "exists", volume)
      val answer = existsAnswer(probe.exit)
      if answer.isEmpty then
        failures += 1
        System.err.println(s"podman volume exists $volume: exit ${probe.exit} ${probe.err}".stripTrailing)
      answer
    val volumeKept = sharedVolume match
      case Some(shared) =>
        System.err.println(s"note: leaving shared volume $shared in place$sharedFrom")
        volumeExists.contains(true)
      case None =>
        if volumeExists.contains(true) then
          found = true
          remove("volume", volume)
        false
    // The main worktree's volume, which this directory's launches may have shared, is named for that workspace. The
    // reset leaves the volume in place like a configured shared volume, because removing it would sign the main
    // worktree and every other linked worktree out. The reset names the volume where the volume exists, so the reader
    // knows what this reset did not remove, and where the reset that removes the volume runs.
    mainWorktree.foreach: main =>
      val mainVolume = mainWorktreeVolume(main, os)
      if existsAnswer(run(podman, "volume", "exists", mainVolume).exit).contains(true) then
        System.err.println(mainWorktreeVolumeNote(main, os))

    // This workspace's per-run networks. The containers went first above, so nothing still holds the networks.
    val networks = run(podman, "network", "ls", "--format", "{{.Name}}")
    if !networks.ok then
      failures += 1
      System.err.println(networks.err)
    workspaceNetworks(networks.text.linesIterator.map(_.trim).toSeq, id)
      .foreach: network =>
        found = true
        remove("network", network)

    // The audit trail goes with the rest of the workspace's state, because "reset" means "as if this workspace had
    // never been opened". Copy the files out first if a session's refusals still matter.
    perWorkspaceStateRoots(os).foreach(root => deleteTree(root.resolve(id)))
    // The BPF backend's proof fixture for the workspace. The fixture's pins and cgroups go with the reconcile at the
    // next launch, once the containers above are gone (KoAgentBpf.reconcileScript).
    deleteTree(KoAgentBpf.fixtureRoot(stateRoot(os), id))
    // The run-on-host cache goes too. The cache is the one store that a command can poison (SECURITY.md, "Cache
    // poisoning stops at the workspace"), and a reset that kept the cache would not mean "never opened".
    // - The reset checks the root against the directory that the reset runs in, as for every deletion under the root.
    // - A root inside that directory is a root that the directory's own workspace builds refused, so nothing of those
    //   builds is under the root. From its own directory, the reset therefore prints a note where --reset-run-on-host
    //   refuses.
    // - Every other refusal says nothing about what a usable root once held: an unset or relative override, or a root
    //   that cannot be resolved. A named workspace's builds may well have used a root that this directory happens to
    //   contain. Both cases are failed steps, and the user runs the reset again from elsewhere or with the root
    //   repaired.
    runOnHostCacheRoot(os, workspaceRoot)
      .flatMap(root => runOnHostRemoval(os, workspaceRoot, RunOnHostPrereqs.runOnHostCacheDir(root, id)))
    match
      case Right(caches) => deleteTree(caches)
      case Left(refusal @ RunOnHostPrereqs.Refusal.CacheRootInsideWorkspace(_, _)) if !named =>
        System.err.println(s"note: run-on-host cache not removed; ${cacheRootRefusalLine(refusal, os)}")
      case Left(refusal) =>
        failures += 1
        System.err.println(cacheRootRefusalLine(refusal, os))
        if named then System.err.println(s"Run --reset $id from a directory the cache root is not inside.")

    // The workspace's filter daemon and mountpoint, where the feature has been used. The step is best effort by design,
    // because with no machine running, nothing is mounted to tear down.
    found |= unmountKoAgentFs(os, koAgentFsUnmountScript(id))

    // The record goes last, as in --reset-all, and only after every step succeeded. The record outlives these:
    // - the generated volume that a shared volume left in place;
    // - a cache under a root that the step above could not use;
    // - whatever a failed step left.
    // The reset reads the cache root as --stats reads it: where --stats can show no cache, no cache keeps the record.
    val cache = RunOnHostPrereqs.cacheRootOf(os, env).toOption.map(RunOnHostPrereqs.runOnHostCacheDir(_, id))
    found |= cache.exists(Files.exists(_)) || Files.exists(workspacesStateRoot(os).resolve(id))
    if failures == 0 then
      try dropRecordUnless(workspacesStateRoot(os), id, cache.toSeq, volumeKept)
      catch
        case ex: IOException =>
          failures += 1
          System.err.println(s"record of $id: $ex")
    Reset(failures, found)

  /** `rm -rf`, echoed only where there is something to remove, so a reset lists what the reset removed. */
  private def removeTree(dir: Path): Unit =
    if Files.exists(dir) then
      echoCommand(Vector("rm", "-rf", dir.toString))
      deleteRecursively(dir)

  /** `podman container exists`, `volume exists` and `network exists` answer present with exit 0, absent with exit 1,
    * and any failure with another code, which means neither. */
  def existsAnswer(exit: Int): Option[Boolean] = exit match
    case 0 => Some(true)
    case 1 => Some(false)
    case _ => None

  /**
   * A reset's removal of the podman `kind` (`container`, `volume` or `network`) `name`. The removal is done when the
   * removal succeeds, or when the removal failed and podman says that `name` does not exist.
   * - The reaper of a run that has just ended removes the same containers and networks. Podman tells whichever of the
   *   two loses the race that the objects are not found.
   * - An existence that podman cannot answer counts as a failure.
   */
  def resetRemoved(podman: String, kind: String, name: String): Boolean =
    val rm =
      if kind == "container" then Vector(podman, "rm", "--force", name) else Vector(podman, kind, "rm", name)
    stepOk(rm*) || {
      val gone = existsAnswer(run(podman, kind, "exists", name).exit).contains(false)
      if gone then System.err.println(s"note: the $kind $name was already gone")
      gone
    }

  /**
   * `--reset-all`, which performs every workspace's `--reset`.
   * - The reset deliberately does not remove built images or the images' valid pending-cleanup journal. The
   *   image-producing actions own both, and the images are costly to rebuild (`podman image rm` removes them by hand).
   * - The reset repairs a malformed journal, because a malformed journal names no image that the launcher can safely
   *   remove.
   */
  def resetAll(os: Os): Nothing =
    // The workstation-wide deletions below run wherever the state and cache roots point. The reset resolves both roots
    // and checks them against the current directory before the first deletion.
    val workspaceRoot = resolveWorkspaceRoot(os)
    requireStateRootOutside(os, workspaceRoot)
    // Every workspace's run-on-host caches as one tree. RunOnHostPrereqs.runOnHostCachesOf says why the tree is not the
    // cache root itself. The reset removes the tree after the podman resources and the per-workspace state, and only
    // the directory records follow the tree.
    val caches = runOnHostCacheRoot(os, workspaceRoot)
      .flatMap(root => runOnHostRemoval(os, workspaceRoot, RunOnHostPrereqs.runOnHostCachesOf(root)))
      .fold(refusal => fail(cacheRootRefusalLine(refusal, os)), identity)
    val cleanupJournal = imageCleanupJournal(os)
    if Files.exists(cleanupJournal) then
      withFileLock(imageBuildLockFile(os)):
        repairImageCleanupJournal(cleanupJournal)
    var failures = 0

    def listed(command: String*): Vector[String] =
      echoCommand(command)
      val result = run(command*)
      if !result.ok then
        failures += 1
        System.err.println(result.err)
      result.text.linesIterator.map(_.trim).filter(_.nonEmpty).toVector

    def remove(kind: String, name: String): Unit = if !resetRemoved(podman, kind, name) then failures += 1

    val containers = listed(podman, "ps", "-a", "--format", "{{.Names}}")
    (proxyContainers(containers) ++ sandboxRunContainers(containers) ++
      SelfTestShare.probeContainers(containers))
      .foreach(name => remove("container", name))

    persistentVolumes(listed(podman, "volume", "ls", "--format", "{{.Name}}"))
      .foreach(name => remove("volume", name))

    launcherNetworks(listed(podman, "network", "ls", "--format", "{{.Name}}"))
      .foreach(name => remove("network", name))

    perWorkspaceStateRoots(os).foreach(removeTree)

    // Every workspace's filter mount. The step is best effort, as in the per-workspace reset.
    unmountKoAgentFs(os, koAgentFsUnmountAllScript)

    removeTree(caches)

    if failures > 0 then fail(s"error: $failures reset steps failed")
    // The records go last, and only after everything they locate is gone, so a volume or cache left by a failed step
    // keeps its directory in the next --stats.
    removeTree(workspacesStateRoot(os))
    removeTree(formerWorkspacesStateRoot(os))
    sys.exit(0)

  /**
   * The run-on-host cache root, refused when the root would be inside the workspace.
   * - Every action that deletes under the root makes this check, as [[requireStateRootOutside]] does for the state
   *   root, and with the same [[couldBeAWorkspace]] exemption. From an exempt directory, only the root's own
   *   resolution can refuse.
   * - The answer is canonical either way, since deletion follows the answer. [[runOnHostRemoval]] checks what the
   *   deletion's own path may resolve to.
   */
  private def runOnHostCacheRoot(os: Os, workspaceRoot: Path): Either[RunOnHostPrereqs.Refusal, Path] =
    RunOnHostPrereqs
      .cacheRootOf(os, env)
      .flatMap: root =>
        if couldBeAWorkspace(os, workspaceRoot) then
          RunOnHostPrereqs.cacheRootOutsideWorkspace(root, workspaceRoot, os, canonicalizedFuturePath)
        else
          canonicalizedFuturePath(root).left.map(RunOnHostPrereqs.Refusal.CacheRootUnusable(_))

  /**
   * A directory under the run-on-host tree that an action is about to remove, refused when the directory's canonical
   * form overlaps the workspace or the state root.
   * - A symlinked `run-on-host` or per-workspace directory places the directory wherever the link points.
   * - The workspace check has [[couldBeAWorkspace]]'s exemption. No directory is exempt from the state root check
   *   (RunOnHostPrereqs.cachePathClearOfStateRoot).
   * - The answer is the spelling, and removal follows the spelling. A link that stands for the directory itself goes
   *   as a link, as `rm -rf` removes a link. A link among the directory's ancestors is followed, and that case is what
   *   the check is for.
   */
  private def runOnHostRemoval(os: Os, workspaceRoot: Path, target: Path): Either[RunOnHostPrereqs.Refusal, Path] =
    for
      canonical <- canonicalizedFuturePath(target).left.map(RunOnHostPrereqs.Refusal.CacheRootUnusable(_))
      _ <-
        if couldBeAWorkspace(os, workspaceRoot) then
          RunOnHostPrereqs.cacheRootOutsideWorkspace(canonical, workspaceRoot, os, Right(_))
        else Right(canonical)
      _ <- RunOnHostPrereqs.cachePathClearOfStateRoot(canonical, stateRoot(os), os)
    yield target

  private def cacheRootRefusalLine(refusal: RunOnHostPrereqs.Refusal, os: Os): String =
    s"error: ${RunOnHostPrereqs.wording(refusal, HostCommands.displayPath(_, os))}"

  /**
   * `--reset-run-on-host` removes this workspace's run-on-host caches, which hold what the workspace's
   * `--run-on-host` commands resolved. The action removes the caches as one directory and alone, so the space comes
   * back beside a live session. `--reset` removes the caches with the rest.
   */
  def resetRunOnHost(os: Os): Nothing =
    val workspaceRoot = resolveWorkspaceRoot(os)
    requireStateRootOutside(os, workspaceRoot)
    val id = workspaceIdOf(workspaceRoot, os)
    val caches = runOnHostCacheRoot(os, workspaceRoot)
      .flatMap(root => runOnHostRemoval(os, workspaceRoot, RunOnHostPrereqs.runOnHostCacheDir(root, id)))
      .fold(refusal => fail(cacheRootRefusalLine(refusal, os)), identity)
    removeTree(caches)
    // The action asks for the generated volume as well, because a shared volume or a failed step leaves the generated
    // volume behind a --reset that removed these directories. This action needs no podman, so the record stays where
    // no podman answers.
    val state = perWorkspaceStateRoots(os).map(_.resolve(id))
    val volumeKept = findOnPath("podman", os).fold(true): found =>
      existsAnswer(run(found.toString, "volume", "exists", persistentVolumeName(id)).exit)
        .getOrElse(true)
    dropRecordUnless(workspacesStateRoot(os), id, state, volumeKept)
    sys.exit(0)

  /**
   * Per-user state, outside any workspace, because the agent must not read or rewrite anything in it.
   * %LOCALAPPDATA% is per user and not roamed.
   *
   * The launcher validates the configured value rather than adopting it:
   * - The value must be absolute. A relative value resolves against the current directory, which is the workspace
   *   root. The state root would then hand the CA signing key to the sandbox, and aim `--reset-all`'s recursive
   *   deletions into the workspace.
   * - The launcher canonicalizes the value through its nearest existing ancestor, so a symlinked spelling cannot place
   *   the state root somewhere that the outside-the-workspace comparison (forbiddenStateRootReason) never sees. On a
   *   first launch the directory does not exist yet, which is why a plain toRealPath is not enough.
   * - An empty variable counts as unset, as RunOnHostPrereqs.cacheRootOf reads its own variables. An empty HOME would
   *   otherwise place the state root at `/.local/state`.
   */
  def stateRoot(os: Os): Path = stateRootOf(os, env).fold(fail(_), identity)

  def stateRootOf(os: Os, env: String => Option[String]): Either[String, Path] =
    userRootOf(
      os, env, "LOCALAPPDATA", "XDG_STATE_HOME", ".local/state",
      "The launcher's state root holds the CA signing key and audit logs",
    ).flatMap: (variable, root) =>
      canonicalizedFuturePath(root.resolve("ko-agent-sandbox")).left.map(reason => s"error: $variable: $reason")

  /**
   * A per-user root as the XDG Base Directory specification and Windows place it, and the variable that the root came
   * from: `windowsVariable` on Windows, else `xdgVariable`, else `homeRelative` under HOME.
   * - An empty variable counts as unset.
   * - A relative value is refused, since a relative value would resolve against the current directory, the workspace
   *   root. `holds` says what the root holds, and the refusal names that content.
   * - The callers canonicalize what they resolve under the root.
   */
  def userRootOf(
    os: Os,
    env: String => Option[String],
    windowsVariable: String,
    xdgVariable: String,
    homeRelative: String,
    holds: String,
  ): Either[String, (String, Path)] =
    val (variable, configured) = os match
      case Os.Windows => (windowsVariable, env(windowsVariable))
      case _ =>
        env(xdgVariable).filter(_.nonEmpty) match
          case Some(value) => (xdgVariable, Some(value))
          case None        => ("HOME", env("HOME").filter(_.nonEmpty).map(_ + "/" + homeRelative))
    configured.filter(_.nonEmpty) match
      case None => Left(s"error: $variable is not set")
      case Some(value) =>
        val base =
          try Some(Paths.get(value))
          catch case _: java.nio.file.InvalidPathException => None
        base match
          case None => Left(s"error: $variable is not a valid path: '$value'")
          case Some(path) if !path.isAbsolute =>
            Left(
              s"""error: $variable is '$value', which is not an absolute path
                 |$holds; a relative
                 |value would resolve against the current directory, the repository being
                 |sandboxed, so it is refused rather than resolved.""".stripMargin,
            )
          case Some(path) => Right((variable, path))

  /**
   * Why the resolved state root may not serve this workspace, or None. The answer is a reason when the state root and
   * the workspace overlap in either direction.
   * - A state root inside the workspace hands the sandbox the CA signing key.
   * - A workspace inside the state root puts the workspace under a reset's recursive deletions, as
   *   RunOnHostPrereqs.cacheRootOutsideWorkspace refuses for the cache root.
   * - Both paths are canonical, as overlapsInAnySpelling requires: the workspace root is toRealPath-resolved, and
   *   stateRootOf canonicalized its answer.
   */
  def forbiddenStateRootReason(os: Os, stateRoot: Path, workspaceRoot: Path): Option[String] =
    Option.when(overlapsInAnySpelling(os, stateRoot, workspaceRoot))(
      s"error: the launcher's state root $stateRoot overlaps the workspace root $workspaceRoot\n" +
        "It holds the CA signing key, proxy audit logs and launch state, which the sandbox must\n" +
        "not reach and a reset removes; point XDG_STATE_HOME (or LOCALAPPDATA) at a directory\n" +
        "outside the workspace.",
    )

  /**
   * Whether a launch could accept `dir` as this workspace's root. The containment checks ([[requireStateRootOutside]],
   * [[runOnHostCacheRoot]], OptionsFile.refusal) share this exemption:
   * - A directory that a launch itself refuses, a home or a filesystem root, cannot be a workspace root.
   * - The default state, cache and configuration layouts (`~/.local/state`, `~/.cache`, `~/.config`) are inside a home
   *   as the normal case, not a breach.
   * - An unanswerable home discovery keeps the checks, which is the fail-closed side.
   */
  def couldBeAWorkspace(os: Os, dir: Path): Boolean =
    protectedHomeDirectories(os, env) match
      case Right(protection) => forbiddenWorkspaceRootReason(dir, protection).isEmpty
      case Left(_)           => true

  /**
   * The containment check for the actions run *from* a directory. The check refuses when the state root overlaps what
   * a launch would accept as this workspace's root. Every caller that deletes or reads under the state root calls
   * this check before touching the state root.
   */
  def requireStateRootOutside(os: Os, workspaceRoot: Path): Unit =
    if couldBeAWorkspace(os, workspaceRoot) then
      forbiddenStateRootReason(os, stateRoot(os), workspaceRoot).foreach(fail(_))

  /**
   * Every workspace's inspection CA, under the state root, so the agent can neither read the signing key nor replace
   * the key for the next session.
   */
  def tlsStateRoot(os: Os): Path = stateRoot(os).resolve("tls")

  /**
   * Proxy audit logs, one file per run. The directory is a sibling of tls/, never inside it, because the proxy writes
   * here, and what the proxy writes must not be stored beside the CA key.
   */
  def logStateRoot(os: Os): Path = stateRoot(os).resolve("log")

  /**
   * Per workspace, stamped copies of --print-ruleset dry runs. The copies are a cache and never an authority, because
   * the proxy re-resolves the ruleset at every startup. The assembled agent instructions and the image's `absent`
   * answers about mount paths lie beside the copies (AgentSandboxLauncher.mountPathProbeStamp).
   */
  def rulesetStateRoot(os: Os): Path = stateRoot(os).resolve("ruleset")

  /**
   * The directory that each workspace id was made from, one file per id. The hash in the id is one-way, and `--stats`
   * names a workspace by the directory that its `--reset-run-on-host` runs in.
   */
  def workspacesStateRoot(os: Os): Path = stateRoot(os).resolve("workspaces")

  /** Where launchers that called the workspace a project kept those records. Nothing reads these records, and
    * `--reset-all` removes them with the rest (TODO.md says when this directory goes). */
  def formerWorkspacesStateRoot(os: Os): Path = stateRoot(os).resolve("projects")

  /** The roots that hold a directory per workspace id, which a reset removes. The reset removes the workspaces record
    * separately (dropRecordUnless). */
  def perWorkspaceStateRoots(os: Os): Vector[Path] = Vector(tlsStateRoot(os), rulesetStateRoot(os), logStateRoot(os))

  /** Records the workspace root for its id.
    * - A launch writes the record with the first state that the launch creates, so a launch refused before that state
    *   leaves no record.
    * - Every launch rewrites the record. The id changes with the path, so a stale record cannot exist under a live id.
    * - The record remains while `--stats` finds a resource for that id. `--reset` retains the record when a shared
    *   volume or an unusable cache root prevents complete cleanup. `--reset-run-on-host` retains the record while other
    *   workspace state remains.
    * - [[dropRecordUnless]] deletes the record when no resource remains, and `--reset-all` deletes every record. */
  def recordWorkspaceRoot(workspacesRoot: Path, workspaceId: String, workspaceRoot: Path): Unit =
    Files.createDirectories(workspacesRoot)
    writePrivate(workspacesRoot.resolve(workspaceId), workspaceRoot.toString)

  /**
   * Deletes the record when none of `remaining` exists. A record that names nothing would keep a workspace in the
   * `--stats` list after the workspace's directory is deleted, with the path string as its size. `remaining` and
   * `volumeKept` are what the calling action leaves in place.
   */
  def dropRecordUnless(workspacesRoot: Path, workspaceId: String, remaining: Seq[Path], volumeKept: Boolean): Unit =
    val record = workspacesRoot.resolve(workspaceId)
    if !volumeKept && !remaining.exists(Files.exists(_)) && Files.exists(record) then
      echoCommand(Vector("rm", "-f", record.toString))
      Files.delete(record)
