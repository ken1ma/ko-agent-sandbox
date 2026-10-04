// The launcher's per-user state root — the inspection CAs, audit logs, ruleset stamps and project
// records under it — and the resets that remove what launches leave (--reset, --reset-run-on-host,
// --reset-all), with the name patterns by which they find podman's objects.

package agentsandbox.launcher

import java.io.IOException
import java.nio.file.{Files, Path, Paths}

import AgentSandboxLauncher.*
import HostCommands.*
import FileHelper.*
import ImageBuilds.*
import KoAgentFs.*
import LauncherImages.*
import SandboxProject.*

object LauncherState:

  // The generated tail every launcher-made name ends with: the folded directory slug, the
  // twelve-hex path hash (SandboxProject.projectIdOf), and — for per-run resources — the
  // eight-hex run suffix. `--reset-all` matches whole names against these patterns rather than
  // bare prefixes: it force-removes what it matches, and a prefix alone would also take a
  // user's own `ko-agent-sandbox-persistent-backup`. A pattern is not provenance, so the patterns
  // are a reserved namespace, stated as such in SECURITY.md ("Silent changes to what you own"):
  // an object hand-named inside one is removed like the launcher's own, and the one
  // launcher-adopted name — the shared volume — is refused when it strays into it
  // (sharedVolumeNameRefusal).

  /** Whether `name` is `builder(<any project id>, <run suffix>)`, matched whole. */
  private def isAnyProjectRunNamed(builder: (String, String) => String)(name: String): Boolean =
    name.matches(builder(ProjectIdPattern, RunSuffixPattern))

  /**
   * Why `name` may not serve as the shared agent-state volume, or None. The generated volume
   * pattern is `--reset-all`'s to remove by name, so adopting a user-supplied name inside it
   * would hand that sweep a volume it must not own — including another project's real volume,
   * spelled out to alias its sign-ins. Refused at launch, where the volume would be created and
   * used, rather than discovered at the reset that deletes it. The one name inside the pattern a
   * launch adopts is its main worktree's (mainWorktreeVolume): named by the worktree's own Git
   * metadata rather than by the user, and agreed to at the prompt.
   */
  def sharedVolumeNameRefusal(name: String): Option[String] =
    Option.when(name.matches(persistentVolumeName(ProjectIdPattern)))(
      s"KO_AGENT_SANDBOX_PERSISTENT_VOLUME is '$name', which has the launcher's generated " +
        "volume-name pattern, and --reset-all removes every volume matching it\n\n" +
        s"Choose a name outside ${persistentVolumeName("<slug>-<12 hex>")}.",
    )

  /** The volume a launch from `main` itself mounts (SandboxProject.mainWorktreeOf has the spelling). */
  def mainWorktreeVolume(main: Path, os: Os): String =
    persistentVolumeName(projectIdOf(main, os))

  /** What a linked worktree's `--reset` says of the volume it leaves in place. */
  def mainWorktreeVolumeNote(main: Path, os: Os): String =
    s"note: leaving the main worktree's volume ${mainWorktreeVolume(main, os)} in place; " +
      s"run --reset in ${pathInline(main, os)} to remove it"

  def proxyContainers(names: Seq[String]): Seq[String] =
    names.filter(isAnyProjectRunNamed(proxyRunContainer))

  /**
   * Run containers are --rm and normally remove themselves; one survives
   * only when its launcher died between create and start and its reaper
   * failed too. This filter is the resets' fallback sweep, not the
   * primary cleanup.
   */
  def sandboxRunContainers(names: Seq[String]): Seq[String] =
    names.filter(isAnyProjectRunNamed(sandboxRunContainer))

  private val RunContainerName = s"ko-agent-(sandbox-run|egress-proxy)-($ProjectIdPattern)-($RunSuffixPattern)".r

  /** The kind, project id and run suffix of a container in the namespace the two filters above
    * sweep, or None: `--stats` reads the names back one at a time. */
  def runContainerParts(name: String): Option[(String, String, String)] =
    name match
      case RunContainerName(kind, projectId, suffix) => Some((kind, projectId, suffix))
      case _                                         => None

  /**
   * Volumes named through KO_AGENT_SANDBOX_PERSISTENT_VOLUME are deliberately left alone — and
   * cannot match this pattern, because such a value refuses the launch (sharedVolumeNameRefusal).
   */
  def persistentVolumes(names: Seq[String]): Seq[String] =
    names.filter(_.matches(persistentVolumeName(ProjectIdPattern)))

  def launcherNetworks(names: Seq[String]): Seq[String] =
    names.filter: name =>
      isAnyProjectRunNamed(sandboxRunNetwork)(name) || isAnyProjectRunNamed(egressRunNetwork)(name)

  def projectNetworks(names: Seq[String], projectId: String): Seq[String] =
    names.filter: name =>
      isRunNamed(sandboxRunNetwork, projectId)(name)
        || isRunNamed(egressRunNetwork, projectId)(name)

  /**
   * `--reset`'s operands: none, the current directory's project, or ids as `--stats` prints them —
   * the one name left once a project's directory is gone, the hash in the id being one-way.
   */
  def projectIdOperands(action: String, rest: List[String]): Either[String, Vector[String]] =
    rest.find(id => !isProjectId(id)) match
      case Some(odd) => Left(s"error: $action $odd; a project id is as --stats prints it, <slug>-<12 hex digits>")
      case None =>
        rest.diff(rest.distinct).headOption match
          case Some(twice) => Left(s"error: $action names $twice twice")
          case None        => Right(rest.toVector)

  /**
   * `--reset` (README.md has what it removes). Every other project's state and the built images are
   * left alone. The roots are checked against the current directory whichever projects are named,
   * as `--reset-all` checks them: the deletions happen under them either way. Every id is reset
   * before any failure is reported, so one project's failed step does not leave the next untouched.
   */
  def resetProject(os: Os, givenIds: Vector[String]): Nothing =
    val projectDir = resolveProjectDir(os)
    // Before the deletions below: a state root overlapping the project directory must refuse here,
    // not aim `rm -rf` at it.
    requireStateRootOutside(os, projectDir)
    val ids = if givenIds.isEmpty then Vector(projectIdOf(projectDir, os)) else givenIds
    // Read only for the directory's own reset: a named id's directory is gone, with its metadata.
    val mainWorktree =
      if givenIds.nonEmpty then None
      else SandboxProject.mainWorktreeOf(projectDir, protectedHomeDirectories(os, env).fold(fail(_), identity), os)
    val outcomes = ids.map: id =>
      // A podman that stopped answering mid-way is one failed step of this id, not the run's end.
      id -> (
        try resetOne(os, projectDir, id, named = givenIds.nonEmpty, mainWorktree)
        catch
          case ex: IOException =>
            System.err.println(s"$id: $ex")
            Reset(failures = 1, found = true)
      )
    val failures = outcomes.map(_._2.failures).sum
    if failures > 0 then fail(s"error: $failures reset steps failed")
    // A typed id that names nothing is refused, after its no-op sweep — a directory's own id
    // needs no such check.
    val unknown = if givenIds.isEmpty then Vector.empty else outcomes.collect { case (id, Reset(_, false)) => id }
    if unknown.nonEmpty then fail(s"error: no project ${unknown.mkString(", ")}; --stats lists them")
    sys.exit(0)

  /** One project's reset: how many steps failed, and whether anything named the id at all. */
  private case class Reset(failures: Int, found: Boolean)

  /** `named`: the id came from the command line rather than from `projectDir`, the directory the
    * reset runs in. Every failure is a counted step, never an exception, so the ids after this one
    * are still reset. */
  private def resetOne(os: Os, projectDir: Path, id: String, named: Boolean, mainWorktree: Option[Path]): Reset =
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

    // Everything this project's launches created, stray or live — removing a running session's containers ends that
    // session, which is what "reset" means.
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

    // Only the computed per-project volume; a volume shared through KO_AGENT_SANDBOX_PERSISTENT_VOLUME belongs to other
    // projects too.
    // A failed probe is a failed step, not an absent volume, so the record below is not dropped over one.
    val volume = persistentVolumeName(id)
    val volumeExists: Option[Boolean] =
      val probe = run(podman, "volume", "exists", volume)
      val answer = existsAnswer(probe.exit)
      if answer.isEmpty then
        failures += 1
        System.err.println(s"podman volume exists $volume: exit ${probe.exit} ${probe.err}".stripTrailing)
      answer
    val volumeKept = env("KO_AGENT_SANDBOX_PERSISTENT_VOLUME") match
      case Some(shared) =>
        System.err.println(s"note: leaving shared volume $shared in place")
        volumeExists.contains(true)
      case None =>
        if volumeExists.contains(true) then
          found = true
          remove("volume", volume)
        false
    // The main worktree's volume, which this directory's launches may have shared, is named for
    // that project and left in place like a configured shared one: removing it would sign the
    // main worktree and every other linked worktree out. Said where it exists, so the reader knows
    // what this reset did not remove and where the reset that does runs.
    mainWorktree.foreach: main =>
      val mainVolume = mainWorktreeVolume(main, os)
      if existsAnswer(run(podman, "volume", "exists", mainVolume).exit).contains(true) then
        System.err.println(mainWorktreeVolumeNote(main, os))

    // This project's per-run networks. Containers went first above, so nothing still holds them.
    val networks = run(podman, "network", "ls", "--format", "{{.Name}}")
    if !networks.ok then
      failures += 1
      System.err.println(networks.err)
    projectNetworks(networks.text.linesIterator.map(_.trim).toSeq, id)
      .foreach: network =>
        found = true
        remove("network", network)

    // The audit trail goes with the rest of the project's state: "reset" means "as if this project had never been
    // opened". Copy the files out first if a session's refusals still matter.
    perProjectStateRoots(os).foreach(root => deleteTree(root.resolve(id)))
    // The run-on-host cache too: it is the one store a command can poison (SECURITY.md, "Cache
    // poisoning stops at the project"), and a reset that kept it would not mean "never opened".
    // The root is checked against the directory the reset runs in, as every deletion under it is.
    // A root inside that directory is one its own project's builds refused, so nothing of theirs
    // is under it and from its own directory the reset notes it where --reset-run-on-host refuses.
    // Every other refusal — an unset or relative override, a root that cannot be resolved — says
    // nothing about what a usable root once held, and a named project's builds may well have used
    // a root this directory happens to contain; both are failed steps, and the reset is run again
    // from elsewhere or with the root repaired.
    runOnHostCacheRoot(os, projectDir)
      .flatMap(root => runOnHostRemoval(os, projectDir, RunOnHostPrereqs.runOnHostCacheDir(root, id)))
    match
      case Right(caches) => deleteTree(caches)
      case Left(refusal @ RunOnHostPrereqs.Refusal.CacheRootInsideProject(_, _)) if !named =>
        System.err.println(s"note: run-on-host cache not removed; ${cacheRootRefusalLine(refusal)}")
      case Left(refusal) =>
        failures += 1
        System.err.println(cacheRootRefusalLine(refusal))
        if named then System.err.println(s"Run --reset $id from a directory the cache root is not inside.")

    // The project's filter daemon and mountpoint, where the feature has been used. Best effort by
    // design: with no machine running there is nothing mounted to tear down.
    found |= unmountKoAgentFs(os, koAgentFsUnmountScript(id))

    // Last, as in --reset-all, and only after every step succeeded: the record outlives the
    // generated volume a shared one left in place, a cache under a root the step above could not
    // use, and whatever a failed step left. The cache root is read as --stats reads it: where
    // --stats can show no cache, none keeps the record.
    val cache = RunOnHostPrereqs.cacheRootOf(os, env).toOption.map(RunOnHostPrereqs.runOnHostCacheDir(_, id))
    found |= cache.exists(Files.exists(_)) || Files.exists(projectsStateRoot(os).resolve(id))
    if failures == 0 then
      try dropRecordUnless(projectsStateRoot(os), id, cache.toSeq, volumeKept)
      catch
        case ex: IOException =>
          failures += 1
          System.err.println(s"record of $id: $ex")
    Reset(failures, found)

  /** `rm -rf`, echoed only where there is something to remove, so a reset lists what it removed. */
  private def removeTree(dir: Path): Unit =
    if Files.exists(dir) then
      echoCommand(Vector("rm", "-rf", dir.toString))
      deleteRecursively(dir)

  /** `podman container exists`, `volume exists` and `network exists` answer present with exit 0,
    * absent with 1, and any failure with another code, which is neither. */
  def existsAnswer(exit: Int): Option[Boolean] = exit match
    case 0 => Some(true)
    case 1 => Some(false)
    case _ => None

  /**
   * A reset's removal of the podman `kind` (`container`, `volume` or `network`) `name`: done when
   * the removal succeeds, or when it failed and podman says `name` no longer exists. The reaper of
   * a run that has just ended removes the same containers and networks, and whichever of the two
   * loses the race is told they are not found. An existence podman cannot answer is a failure.
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
   * `--reset-all`, every project's `--reset`. It deliberately does not remove built images or
   * their valid pending-cleanup journal: image-producing actions own both, and the images are costly
   * to rebuild (`podman image rm` removes them by hand). A malformed journal is repaired because
   * it names no image the launcher can safely remove.
   */
  def resetAll(os: Os): Nothing =
    // The workstation-wide deletions below run wherever the state and cache roots point; both
    // roots are resolved and checked against the current directory before the first of them.
    val project = resolveProjectDir(os)
    requireStateRootOutside(os, project)
    // Every project's run-on-host caches as one tree (RunOnHostPrereqs.runOnHostCachesOf has why
    // not the cache root itself), removed after the podman resources and the per-project state;
    // only the directory records follow them.
    val caches = runOnHostCacheRoot(os, project)
      .flatMap(root => runOnHostRemoval(os, project, RunOnHostPrereqs.runOnHostCachesOf(root)))
      .fold(refusal => fail(cacheRootRefusalLine(refusal)), identity)
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

    perProjectStateRoots(os).foreach(removeTree)

    // Every project's filter mount. Best effort, as in the per-project reset.
    unmountKoAgentFs(os, koAgentFsUnmountAllScript)

    removeTree(caches)

    if failures > 0 then fail(s"error: $failures reset steps failed")
    // Last, and only after everything it locates is gone: a volume or cache left by a failed
    // step keeps its directory in the next --stats.
    removeTree(projectsStateRoot(os))
    sys.exit(0)

  /**
   * The run-on-host cache root, refused when it would be inside the project — the check every action
   * that deletes under it makes, as [[requireStateRootOutside]] does for the state root and with
   * the same [[couldBeAProject]] exemption; from an exempt directory only the root's own
   * resolution can refuse. The canonical answer either way, since deletion follows it: what the
   * deletion's own path may resolve to is [[runOnHostRemoval]].
   */
  private def runOnHostCacheRoot(os: Os, project: Path): Either[RunOnHostPrereqs.Refusal, Path] =
    RunOnHostPrereqs
      .cacheRootOf(os, env)
      .flatMap: root =>
        if couldBeAProject(os, project) then
          RunOnHostPrereqs.cacheRootOutsideProject(root, project, os, canonicalizedFuturePath)
        else
          canonicalizedFuturePath(root).left.map(RunOnHostPrereqs.Refusal.CacheRootUnusable(_))

  /**
   * A directory under the run-on-host tree an action is about to remove, refused when its canonical
   * form — a symlinked `run-on-host` or project directory places it wherever the link points —
   * overlaps the project, with [[couldBeAProject]]'s exemption, or the state root
   * (RunOnHostPrereqs.cachePathClearOfStateRoot), from which no directory is exempt. The spelling is
   * the answer: removal follows it, so a link standing for the directory itself goes as a link, as
   * `rm -rf` removes one, while a link among its ancestors is followed, which is what the check is for.
   */
  private def runOnHostRemoval(os: Os, project: Path, target: Path): Either[RunOnHostPrereqs.Refusal, Path] =
    for
      canonical <- canonicalizedFuturePath(target).left.map(RunOnHostPrereqs.Refusal.CacheRootUnusable(_))
      _ <-
        if couldBeAProject(os, project) then
          RunOnHostPrereqs.cacheRootOutsideProject(canonical, project, os, Right(_))
        else Right(canonical)
      _ <- RunOnHostPrereqs.cachePathClearOfStateRoot(canonical, stateRoot(os), os)
    yield target

  private def cacheRootRefusalLine(refusal: RunOnHostPrereqs.Refusal): String =
    s"error: ${RunOnHostPrereqs.wording(refusal)}"

  /**
   * `--reset-run-on-host`: this project's run-on-host caches — what its `--run-on-host` commands
   * resolved — removed as one directory and alone, so the space comes back beside a live
   * session. `--reset` removes them with the rest.
   */
  def resetRunOnHost(os: Os): Nothing =
    val project = resolveProjectDir(os)
    requireStateRootOutside(os, project)
    val id = projectIdOf(project, os)
    val caches = runOnHostCacheRoot(os, project)
      .flatMap(root => runOnHostRemoval(os, project, RunOnHostPrereqs.runOnHostCacheDir(root, id)))
      .fold(refusal => fail(cacheRootRefusalLine(refusal)), identity)
    removeTree(caches)
    // The generated volume is asked for as well: a shared volume or a failed step leaves it behind
    // a --reset that removed these directories. This action needs no podman, so where none answers
    // the record stays.
    val state = perProjectStateRoots(os).map(_.resolve(id))
    val volumeKept = findOnPath("podman", env("PATH").getOrElse(""), os).fold(true): found =>
      existsAnswer(run(found.toString, "volume", "exists", persistentVolumeName(id)).exit)
        .getOrElse(true)
    dropRecordUnless(projectsStateRoot(os), id, state, volumeKept)
    sys.exit(0)

  /**
   * Per-user state, outside any project directory: nothing in it is the
   * agent's to read or rewrite. %LOCALAPPDATA% is per user and not roamed.
   *
   * Validated, not adopted: the value must be absolute — a relative one resolves against the
   * current directory, which is the project directory, and would hand the CA signing key
   * to the sandbox (and aim `--reset-all`'s recursive deletions into the project directory). It is
   * canonicalized through its nearest existing ancestor, so a symlinked spelling cannot place it
   * somewhere the outside-the-project comparison (forbiddenStateRootReason) never sees; on a first
   * launch the directory does not exist yet, which is why a plain toRealPath is not enough. An
   * empty variable is an unset one, as RunOnHostPrereqs.cacheRootOf reads its own: an empty HOME
   * would otherwise place the state root at `/.local/state`.
   */
  def stateRoot(os: Os): Path = stateRootOf(os, env).fold(fail(_), identity)

  def stateRootOf(os: Os, env: String => Option[String]): Either[String, Path] =
    val (variable, configured) = os match
      case Os.Windows => ("LOCALAPPDATA", env("LOCALAPPDATA"))
      case _ =>
        env("XDG_STATE_HOME").filter(_.nonEmpty) match
          case Some(value) => ("XDG_STATE_HOME", Some(value))
          case None        => ("HOME", env("HOME").filter(_.nonEmpty).map(_ + "/.local/state"))
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
                 |The launcher's state root holds the CA signing key and audit logs; a relative
                 |value would resolve against the current directory, the repository being
                 |sandboxed, so it is refused rather than resolved.""".stripMargin
            )
          case Some(path) =>
            canonicalizedFuturePath(path.resolve("ko-agent-sandbox"))
              .left.map(reason => s"error: $variable: $reason")

  /**
   * Why the resolved state root may not serve this project, or None: the two overlap in either
   * direction. A state root inside the project hands the sandbox the CA signing key; a project
   * inside the state root puts the project under a reset's recursive deletions, as
   * RunOnHostPrereqs.cacheRootOutsideProject refuses for the cache root. Both paths are
   * canonical, as overlapsInAnySpelling requires: the project directory is toRealPath-resolved,
   * and stateRootOf canonicalized its answer.
   */
  def forbiddenStateRootReason(os: Os, stateRoot: Path, projectDir: Path): Option[String] =
    Option.when(overlapsInAnySpelling(os, stateRoot, projectDir))(
      s"error: the launcher's state root $stateRoot overlaps the project directory $projectDir\n" +
        "It holds the CA signing key, proxy audit logs and launch state, which the sandbox must\n" +
        "not reach and a reset removes; point XDG_STATE_HOME (or LOCALAPPDATA) at a directory\n" +
        "outside the project.",
    )

  /**
   * Whether a launch could accept `dir` as this project — the exemption the containment checks
   * ([[requireStateRootOutside]], [[runOnHostCacheRoot]]) share: a directory a launch itself refuses,
   * a home or a filesystem root, cannot be a project, and the default state and cache layouts
   * (`~/.local/state`, `~/.cache`) are inside a home as the normal case, not a breach. An
   * unanswerable home discovery keeps the checks, the fail-closed side.
   */
  private def couldBeAProject(os: Os, dir: Path): Boolean =
    protectedHomeDirectories(os, env) match
      case Right(protection) => forbiddenProjectDirReason(dir, protection).isEmpty
      case Left(_)           => true

  /**
   * The containment check for the actions run *from* a directory: refuse when the state root
   * overlaps what a launch would accept as this project. Every caller that deletes or reads under
   * the state root calls this before touching it.
   */
  def requireStateRootOutside(os: Os, projectDir: Path): Unit =
    if couldBeAProject(os, projectDir) then
      forbiddenStateRootReason(os, stateRoot(os), projectDir).foreach(fail(_))

  /**
   * Every project's inspection CA: the agent can neither read the signing key nor replace it for the next session.
   */
  def tlsStateRoot(os: Os): Path = stateRoot(os).resolve("tls")

  /**
   * Proxy audit logs, one file per run. A sibling of tls/, never inside it:
   * the proxy writes here and must not be stored beside the CA key.
   */
  def logStateRoot(os: Os): Path = stateRoot(os).resolve("log")

  /**
   * Per project, stamped copies of --print-ruleset dry runs, which are a cache and never an
   * authority: the proxy re-resolves the ruleset at every startup. Beside them, the assembled
   * agent instructions and the image's `absent` answers about mount paths (AgentSandboxLauncher.mountPathProbeStamp).
   */
  def rulesetStateRoot(os: Os): Path = stateRoot(os).resolve("ruleset")

  /**
   * The directory each project id was made from, one file per id. The hash in the id is one-way,
   * and `--stats` names a project by the directory its `--reset-run-on-host` runs in.
   */
  def projectsStateRoot(os: Os): Path = stateRoot(os).resolve("projects")

  /** The roots holding a directory per project id, which a reset removes; the projects record is
    * removed separately (dropRecordUnless). */
  def perProjectStateRoots(os: Os): Vector[Path] = Vector(tlsStateRoot(os), rulesetStateRoot(os), logStateRoot(os))

  /** Written with the first state a launch creates, so a launch refused before that leaves no
    * record, and rewritten at every launch: the id changes with the path, so a stale record
    * cannot exist under a live id. The record remains while `--stats` finds a resource for that
    * id. `--reset` retains it when a shared volume or an unusable cache root prevents complete
    * cleanup; `--reset-run-on-host` retains it while other project state remains.
    * [[dropRecordUnless]] deletes it when no resource remains, and `--reset-all` deletes every
    * record. */
  def recordProjectDirectory(projectsRoot: Path, projectId: String, projectDir: Path): Unit =
    Files.createDirectories(projectsRoot)
    writePrivate(projectsRoot.resolve(projectId), projectDir.toString)

  /**
   * The record goes when none of `remaining` exists: a record naming nothing keeps a project
   * `--stats` lists after its directory is deleted, its size the path string. `remaining` and
   * `volumeKept` are what the calling action leaves in place.
   */
  def dropRecordUnless(projectsRoot: Path, projectId: String, remaining: Seq[Path], volumeKept: Boolean): Unit =
    val record = projectsRoot.resolve(projectId)
    if !volumeKept && !remaining.exists(Files.exists(_)) && Files.exists(record) then
      echoCommand(Vector("rm", "-f", record.toString))
      Files.delete(record)
