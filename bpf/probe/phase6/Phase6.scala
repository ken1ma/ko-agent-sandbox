#!/usr/bin/env -S scala shebang
//> using scala 3.10.0
//> using file ../ProbeHelper.scala

// Phase 6 of doc/plan-bpf-lsm-cgroup.md ("Phases", 6) on the podman machine of either host, in one
// run: the rows that need the launcher itself. Run it on the HOST, from the repository root, from a
// plain terminal with no sandbox session on the machine, after `sbt dist`, the jar's `--build`, and
// Phase 4's run, whose other.bpf.o stands for another build:
//
//     bpf/probe/phase6/Phase6.scala [--out DIR] [--platform mac|windows] [--jar PATH]
//
// On Windows the same is `scala shebang bpf\probe\phase6\Phase6.scala [options]`. The jar defaults
// to target/dist/ko-agent-sandbox.jar. The driver refuses while a sandbox container, session pins or
// a session record it did not make exist, since the refusal rows and the memory row would measure
// them too, and looks again before those rows and at the end; it refuses a jar whose bundled sources
// differ from the checkout's. Every line is printed and appended to OUTDIR/transcript.log (default:
// out-macos/ or out-wsl/ beside this script, ignored by git), each launch's output beside it.
//
// The rows, in order: `io_uring_setup` from a session's first process and from `podman exec`; the
// preloaded set taken by a launch, its records frozen, the next one prepared, a live session's
// records unchanged across another launch's take and the two sessions' programs disjoint, two
// launches racing, a set of an earlier build discarded, an orphan of a launch that died after the
// take removed by the reconcile, and a launch finding no set; `podman exec` and `podman restart` of
// a `unix-socket` session; a linked worktree's socket symlink under the main checkout's
// `.git/objects`; on macOS, a FIFO the host made; the refusals beside a live session of the other
// backend or socket setting, in each pairing and both orders; the kernel's memory for one, four and
// eight program sets and after their removal; and the `codex exec` row, which needs a signed-in
// Codex and is the user's to run by hand.
//
// It writes scratch repositories under ~/ko-agent-bpf-phase6.<pid>/, launches sessions of them with
// their volumes and run logs, one container of its own labelled ko-agent-bpf6.session, and, in the
// machine, pins under /sys/fs/bpf/ko-agent-bpf6-mem and a transient cgroup ko-agent-bpf6-mem; it
// swaps the installed policy object for Phase 4's other build for one row and restores it. All of it
// is removed on exit, the sessions' state with `--reset`.

import scala.annotation.tailrec
import scala.jdk.CollectionConverters.*
import scala.util.Using
import scala.util.matching.Regex

import java.nio.file.{Files, Path}
import java.util.concurrent.TimeUnit

import ProbeHelper.*

@main def probe(args: String*): Unit = Phase6.run(args)

object Phase6:

  case class ProbeOptions(
      out: Option[Path] = None,
      platform: Option[Platform] = None,
      jar: Option[Path] = None,
  )

  def parseOptions(args: Seq[String]): Either[String, ProbeOptions] =
    def loop(rest: Seq[String], options: ProbeOptions): Either[String, ProbeOptions] = rest match
      case Seq() => Right(options)
      case Seq("--out", value, tail*) => loop(tail, options.copy(out = Some(Path.of(value).toAbsolutePath)))
      case Seq("--jar", value, tail*) => loop(tail, options.copy(jar = Some(Path.of(value).toAbsolutePath)))
      case Seq("--platform", value, tail*) =>
        Platform.named(value).flatMap(platform => loop(tail, options.copy(platform = Some(platform))))
      case Seq(other, _*) => Left(s"unknown option $other; see the header of Phase6.scala")
    loop(args, ProbeOptions())

  // --- The launcher's names, as KoAgentBpf.scala and AgentSandboxLauncher.scala spell them ----------------

  val InstallDir = ".local/share/ko-agent-sandbox/bpf"
  val PinRoot = "/sys/fs/bpf/ko-agent-bpf"
  val Preloaded = s"$PinRoot/preloaded"
  val ContainerPrefix = "ko-agent-sandbox-run-"
  val VolumeLabel = "ko-agent-sandbox.volume"
  /** A run suffix: eight hex digits after the workspace id (AgentSandboxLauncher.newRunSuffix). */
  val RunSuffix: Regex = raw"run-\S*?-([0-9a-f]{8})(?:[/\\\s']|$$)".r
  /** The steps log's line (KoAgentBpf.stepsLogLine): the preloaded set taken, or the programs loaded. */
  val TakenPhrase = "the program set verified ahead"

  // --- The driver's own names ----------------------------------------------------------------------------

  val Prefix = "ko-agent-bpf6"
  val Label = s"$Prefix.session"
  val MemRoot = s"/sys/fs/bpf/$Prefix-mem"
  /** Phase 4's other build, which its run leaves in the machine. */
  val OtherBuild = ".local/share/ko-agent-sandbox/bpf-probe4/other.bpf.o"
  /** Long enough that every session outlives its row; each row ends its sessions. */
  val Linger = "900"
  /** A launch's self-test, mount, certificates and proxy come before its container runs. */
  val Patience = 240

  // --- Programs the sessions run, copied into a container or laid in a workspace --------------------------

  val IoUringPy: String =
    """import ctypes, errno
      |libc = ctypes.CDLL(None, use_errno=True)
      |result = libc.syscall(425, 1, ctypes.create_string_buffer(120))
      |print('io_uring_setup result=%d errno=%s' % (result, errno.errorcode.get(ctypes.get_errno(), 'none')),
      |      flush=True)
      |""".stripMargin

  val BindPy: String =
    """import socket, sys, time
      |server = socket.socket(socket.AF_UNIX)
      |server.bind(sys.argv[1])
      |server.listen(4)
      |print('bound', flush=True)
      |time.sleep(600)
      |""".stripMargin

  val ConnectPy: String =
    """import errno, socket, sys
      |client = socket.socket(socket.AF_UNIX)
      |try:
      |    client.connect(sys.argv[1])
      |    print('connect result=ok')
      |except OSError as ex:
      |    print('connect result=%s' % errno.errorcode.get(ex.errno, str(ex.errno)))
      |""".stripMargin

  val FifoPy: String =
    """import errno, os, stat, sys
      |path = sys.argv[1]
      |def answer(action):
      |    try:
      |        action()
      |        return 'ok'
      |    except OSError as ex:
      |        return errno.errorcode.get(ex.errno, str(ex.errno))
      |try:
      |    print('fifo lstat=ok is_fifo=%d' % stat.S_ISFIFO(os.lstat(path).st_mode))
      |except OSError as ex:
      |    print('fifo lstat=%s' % errno.errorcode.get(ex.errno, str(ex.errno)))
      |    sys.exit(0)
      |print('fifo open=%s' % answer(lambda: os.close(os.open(path, os.O_RDONLY | os.O_NONBLOCK))))
      |print('fifo utime=%s' % answer(lambda: os.utime(path)))
      |""".stripMargin

  // --- The pure parts ------------------------------------------------------------------------------------

  /** The run suffix the launch's `log dir` line names, once it printed one. */
  def runSuffixOf(output: String): Option[String] = RunSuffix.findFirstMatchIn(output).map(_.group(1))

  /** The workspace id the same line names (SandboxWorkspace.WorkspaceIdPattern), which `--reset` takes. */
  def workspaceIdOf(output: String): Option[String] =
    raw"[/\\]log[/\\]([A-Za-z0-9._-]{1,32}-[0-9a-f]{12})[/\\]run-".r.findFirstMatchIn(output).map(_.group(1))

  /** The launcher's state root (LauncherState.stateRootOf), under which the run logs and the proof fixture
    * lie. */
  def stateRoot(platform: Platform): Path =
    val root = platform match
      case Platform.Windows => Path.of(sys.env("LOCALAPPDATA"))
      case Platform.Mac =>
        sys.env.get("XDG_STATE_HOME").filter(_.nonEmpty).map(Path.of(_))
          .getOrElse(Path.of(sys.props("user.home"), ".local", "state"))
    val path = root / "ko-agent-sandbox"
    if Files.exists(path) then path.toRealPath() else path


  /** The installed object put back from the copy the earlier-build row kept, its tags recorded again by
    * root, which owns tags.txt (`readback tags` under sudo), then a preloaded set of it. */
  def restoreScript(dir: String): String =
    s"cp $dir/policy.bpf.o.phase6 $dir/policy.bpf.o && sudo -n $dir/readback tags policy.bpf.o $dir/tags.txt && " +
      s"{ sudo -n $dir/controller unpin $Preloaded 2>/dev/null; sudo -n $dir/controller preload $Preloaded; }"

  // --- The run -------------------------------------------------------------------------------------------

  /** A session the launcher started: its container, workspace, `--workspace` value, launcher process and
    * output. */
  case class Session(container: String, workspace: Path, settings: String, process: Process, log: Path):
    def id: String = container.stripPrefix(ContainerPrefix).dropRight(9)
    def suffix: String = container.takeRight(8)
    def pinDir: String = s"$PinRoot/${container.replace('.', '_')}"
    def bpf: Boolean = settings.contains("bpf")
    def unixSocket: Boolean = settings.contains("unix-socket")

  /** A launch on its way: its process and output, until `await` tells what it became. */
  case class Pending(workspace: Path, settings: String, process: Process, log: Path)

  /** What a launch became: a running session, or the launcher's exit before any container ran. */
  enum Outcome:
    case Started(session: Session)
    case Ended(status: Int, output: String)
    def started: Option[Session] = this match
      case Started(session) => Some(session)
      case Ended(_, _) => None
    def describe: String = this match
      case Started(session) => s"started ${session.container}"
      case Ended(status, output) =>
        val lines = output.linesIterator.toSeq
        val reason = lines.find(_.startsWith("error:")).orElse(lines.lastOption).getOrElse("")
        s"ended with status $status: ${reason.take(160)}"

  /** What the run made and its cleanup removes: the launchers, the containers, the workspaces' ids for
    * `--reset`, the volumes, the swapped build and the memory row's pins and cgroup. */
  class Registry:
    var processes = Vector.empty[Process]
    var containers = Set.empty[String]
    var ids = Set.empty[String]
    var volumes = Set.empty[String]
    var swapped = false
    var memoryCgroup = false
    /** The emulated launch the reconcile row leaves for the reconcile: its pins, record and cgroup. */
    var orphans = Set.empty[String]
    var home = ""
    var manager = ""
    var uid = ""

  def removeLeftovers(platform: Platform, jar: Path, scratchRoot: Path, transcript: Transcript, vm: Vm,
      registry: Registry): Unit =
    if registry.containers.nonEmpty then podman(transcript, Seq("rm", "-f", "-v", "-t", "2") ++ registry.containers)
    registry.processes.foreach: process =>
      if !process.waitFor(30, TimeUnit.SECONDS) then process.destroyForcibly()
    val dir = s"${registry.home}/$InstallDir"
    if registry.swapped then vm(restoreScript(dir))
    vm(sh(s"[ -x $dir/controller ] && ${unpinEvery(s"$dir/controller", MemRoot)}", s"sudo -n rmdir $MemRoot", "true"))
    registry.orphans.foreach: orphan =>
      vm(sh(s"sudo -n $dir/controller unpin $PinRoot/$orphan 2>/dev/null", s"rm -rf $dir/sessions/$orphan", "true"))
      removeCgroup(vm, registry.manager, registry.uid, "ko-agent-bpf", orphan)
    if registry.memoryCgroup then removeCgroup(vm, registry.manager, registry.uid, Prefix, "mem")
    if registry.ids.nonEmpty && Files.isDirectory(scratchRoot) then
      host(transcript, Seq("java", "-jar", jar.toString, "--no-options-file", "--reset") ++ registry.ids.toSeq.sorted,
        cwd = scratchRoot, timeoutSeconds = Some(Patience))
    if registry.volumes.nonEmpty then podman(transcript, Seq("volume", "rm", "-f") ++ registry.volumes)
    removeTree(platform, scratchRoot)

  def run(args: Seq[String]): Unit =
    val options = orExit(parseOptions(args))
    val platform = orExit(Platform.resolve(options.platform))
    val repoDir = orExit(repositoryRoot("bpf/probe/phase6/Phase6.scala", "bpf/probe/phase6/sources.txt"))
    val probeDir = repoDir / "bpf" / "probe" / "phase6"
    val jar = options.jar.getOrElse(repoDir / "target" / "dist" / "ko-agent-sandbox.jar")
    val out = options.out.getOrElse(probeDir / platform.outDir)
    Files.createDirectories(out)
    val transcript = Transcript(out / "transcript.log")
    // Every machine command of this driver is short, so each is bounded.
    val vm = Vm(transcript, Some(PodmanSeconds))
    val registry = Registry()
    val scratchRoot = Path.of(sys.props("user.home"), s"ko-agent-bpf-phase6.${ProcessHandle.current().pid()}")
    val cleanup =
      Cleanup(transcript, Label, () => removeLeftovers(platform, jar, scratchRoot, transcript, vm, registry))
    runMeasured(transcript, cleanup):
      Measurement(platform, repoDir, probeDir, jar, out, transcript, vm, scratchRoot, registry).measure()

  /** The phase as steps, each `Right` with what the next needs or `Left` with the exit status after it
    * said why: 2 for a refusal before any row is measured. The rows after the preparation run to the end
    * whatever they record. */
  class Measurement(
      platform: Platform,
      repoDir: Path,
      probeDir: Path,
      jar: Path,
      out: Path,
      transcript: Transcript,
      vm: Vm,
      scratchRoot: Path,
      registry: Registry,
  ):
    import transcript.{check, info, step}
    private val scratchRootVm = vmPath(platform, scratchRoot.toString)
    private var launches = 0

    def measure(): Int =
      val outcome =
        for
          _ <- prerequisites()
          facts <- readVmFacts(transcript, vm, out, scratchRoot, scratchRootVm, PinRoot)
          _ <- installed(facts)
          found = foreign()
          _ <- transcript.refuse(found == Right(Seq()),
            s"not alone on the machine: ${found.fold(identity, _.mkString(", "))}; end them first")
        yield
          Rows(facts).run()
          if transcript.failed == 0 then 0 else 1
      outcome.merge

    def prerequisites(): Either[Int, Unit] =
      step("the jar and the procedure")
      for
        _ <- transcript.refuse(Files.isRegularFile(jar), s"no jar at $jar; run `sbt dist` and the jar's --build first")
        stale = staleEntry(jar, repoDir)
        _ <- transcript.refuse(stale.isEmpty,
          s"$jar bundles ${stale.getOrElse("")}, which differs from the checkout's; run `sbt dist`")
        // The hashed launcher source is compiled into the jar, not bundled as a file the check above
        // compares: a jar older than any listed source may not hold it.
        sources = Files.readString(probeDir / "sources.txt").linesIterator.filter(_.nonEmpty).toSeq
        built = Files.getLastModifiedTime(jar)
        newer = sources.filter(source => Files.getLastModifiedTime(probeDir.resolve(source)).compareTo(built) > 0)
        _ <- transcript.refuse(newer.isEmpty,
          s"${newer.mkString(", ")} changed after $jar was built; run `sbt dist` and the jar's --build")
      yield
        procedureSha(transcript, Seq(probeDir / "Phase6.scala", repoDir / "bpf" / "probe" / "ProbeHelper.scala"))
        // The backend and the launcher's side of it, which the plan's sections name and
        // bpf/probe/CheckEvidence.scala recomputes; the rest of the launcher is the jar's.
        info(s"sources sha256=${sha256(sources.map(source => Files.readAllBytes(probeDir.resolve(source))))} " +
          s"over ${sources.mkString(" ")}")
        info(s"jar $jar")

    def installed(facts: VmFacts): Either[Int, Unit] =
      registry.home = vm.line("echo $HOME")
      registry.manager = facts.manager
      registry.uid = facts.uid
      val dir = s"${registry.home}/$InstallDir"
      transcript.refuse(vm(s"test -x $dir/controller && test -r $dir/source-id").ok,
        s"no BPF backend installed in the machine; run java -jar $jar --build")

    /** What the machine holds that this run did not make: sandbox containers, session pins and session
      * records, each named; Left when a listing failed, which tells nothing. A record whose session has
      * neither a container nor pins is a stale one, which no row measures and the reconcile at the next
      * launch removes: it is reported, not counted. */
    def foreign(): Either[String, Seq[String]] =
      def names(listed: Output): Seq[String] = listed.text.linesIterator.map(_.trim).filter(_.nonEmpty).toSeq
      val containers = podman(transcript, Seq("ps", "-a", "--filter", s"name=$ContainerPrefix", "--format",
        "{{.Names}}"), record = false)
      val pins = vm(s"sudo -n sh -c '[ -d $PinRoot ] || exit 0; ls $PinRoot'")
      val records = vm(s"[ -d $InstallDir/sessions ] || exit 0; ls $InstallDir/sessions")
      val ours = (registry.containers ++ registry.orphans).map(_.replace('.', '_'))
      val failed = Seq("podman ps" -> containers, "the pin root" -> pins, "the session records" -> records)
        .collect { case (what, listed) if !listed.ok => what }
      val foreignContainers = names(containers).filterNot(registry.containers.contains)
      val foreignPins =
        names(pins).filterNot(name => name == "preloaded" || name.startsWith("preloaded-") || ours.contains(name))
      val (live, stale) = names(records)
        .filterNot(name => registry.containers.contains(name) || registry.orphans.contains(name))
        .partition(name => foreignContainers.contains(name) || foreignPins.contains(name.replace('.', '_')))
      if failed.isEmpty && stale.nonEmpty then
        info(s"stale session records, which the next launch's reconcile removes: ${stale.mkString(", ")}")
      Either.cond(failed.isEmpty,
        foreignContainers.map("container " + _) ++ foreignPins.map("pins " + _) ++ live.map("session record " + _),
        s"the listing of ${failed.mkString(" and ")} failed",
      )

    /** Whether the machine holds nothing foreign, a FAIL naming what it holds otherwise. */
    def alone(when: String): Boolean = foreign() match
      case Right(Seq()) => true
      case Right(found) => check(s"alone on the machine $when: ${found.mkString(", ")}", false)
      case Left(reason) => check(s"alone on the machine $when: $reason", false)

    /** The rows, over the machine's facts. */
    class Rows(facts: VmFacts):
      private val dir = s"${registry.home}/$InstallDir"
      private val controller = s"$dir/controller"
      private val readback = s"$dir/readback"
      private val stateDir = stateRoot(platform)

      def run(): Unit =
        firstLaunch().foreach(recordsAcrossTake)
        race()
        if alone("before swapping the installed build") then replacedBuild()
        orphanOfKilledLaunch()
        noPreloadedSet()
        unixSocketExecAndRestart()
        worktreeSocketSymlink()
        hostFifo()
        if alone("before the refusals") then refusals()
        if alone("before the memory row") then memory()
        codexExec()
        step("alone on the machine at the end")
        if alone("at the end") then transcript.pass("nothing foreign appeared during the run")

      // --- Workspaces and launches -----------------------------------------------------------------------

      /** A git repository with one commit under the scratch root. */
      private def repository(name: String): Path =
        val path = scratchRoot / name
        Files.createDirectories(path)
        git(path, "init", "-q")
        git(path, "-c", "user.name=probe", "-c", "user.email=probe@invalid", "commit", "-q", "--allow-empty",
          "-m", "init")
        path.toRealPath()

      private def git(path: Path, arguments: String*): Output =
        host(transcript, Seq("git", "-C", path.toString) ++ arguments)

      /** A linked worktree of `main` under the scratch root. */
      private def worktree(main: Path, name: String): Path =
        git(main, "worktree", "add", "-q", (scratchRoot / name).toString)
        (scratchRoot / name).toRealPath()

      /** A launch from WORKSPACE under `--workspace=SETTINGS`, the session's first process COMMAND. */
      private def begin(workspace: Path, settings: String, extra: Seq[String] = Seq.empty,
          command: Seq[String] = Seq("sleep", Linger)): Pending =
        // Running out of space ends the run, cleanup included, before the machine's storage fails.
        val free = freeSpace(vm)
        if !free.enough then throw IllegalStateException(s"before launch ${launches + 1}: ${free.shortfall}")
        launches += 1
        val log = out / f"launch-$launches%02d.log"
        val builder = ProcessBuilder((Seq("java", "-jar", jar.toString, "--no-options-file",
          "--session-start=immediate", "--egress=deny-unless-allowed", s"--workspace=$settings") ++ extra ++
          command)*).directory(workspace.toFile).redirectErrorStream(true).redirectOutput(log.toFile)
        // Its stdin stays an open pipe, as the container suites leave it (WithPodman.launchWith).
        val process = builder.start()
        registry.processes :+= process
        transcript.log(s"  launch ${log.getFileName}: --workspace=$settings ${extra.mkString(" ")} from $workspace")
        Pending(workspace, settings, process, log)

      /** The launch's container once it runs, or the launcher's exit; a launcher still running after the
        * wait is ended with whatever container it made. Every launch that named its workspace leaves state
        * there, which the cleanup's `--reset` takes. */
      private def await(pending: Pending): Outcome =
        val deadline = System.nanoTime() + Patience * 1_000_000_000L
        def remaining: Int = ((deadline - System.nanoTime()) / 1_000_000_000L).toInt
        @tailrec def poll(): Outcome =
          val output = Files.readString(pending.log)
          workspaceIdOf(output).foreach(id => registry.ids += id)
          val container = runSuffixOf(output).flatMap: suffix =>
            podman(transcript, Seq("ps", "--filter", s"name=-$suffix$$", "--filter", "status=running",
              "--format", "{{.Names}}"), record = false, seconds = remaining.min(PodmanSeconds)).text.linesIterator
              .map(_.trim)
              .find(name => name.startsWith(ContainerPrefix) && name.endsWith(s"-$suffix"))
          container match
            case Some(name) =>
              registry.containers += name
              val session = Session(name, pending.workspace, pending.settings, pending.process, pending.log)
              registry.ids += session.id
              Outcome.Started(session)
            case None if !pending.process.isAlive => Outcome.Ended(pending.process.exitValue, output)
            case None if remaining <= 0 =>
              pending.process.destroy()
              if !pending.process.waitFor(30, TimeUnit.SECONDS) then pending.process.destroyForcibly()
              runSuffixOf(output).foreach: suffix =>
                val made = podman(transcript, Seq("ps", "-a", "--filter", s"name=-$suffix$$", "--format",
                  "{{.Names}}")).text.linesIterator.map(_.trim).filter(_.nonEmpty).toSeq
                if made.nonEmpty then podman(transcript, Seq("rm", "-f", "-v", "-t", "0") ++ made)
              Outcome.Ended(-1, output + "\n(no container within the wait; the launcher was ended)")
            case None =>
              Thread.sleep(1000)
              poll()
        val outcome = poll()
        transcript.log(s"  ${pending.log.getFileName}: ${outcome.describe}")
        outcome

      private def launch(workspace: Path, settings: String, extra: Seq[String] = Seq.empty,
          command: Seq[String] = Seq("sleep", Linger)): Outcome =
        await(begin(workspace, settings, extra, command))

      /** The session's container removed, its launcher's teardown waited for, and, under the backend, its
        * pins gone. */
      private def end(session: Session): Unit =
        // With its anonymous volumes: the session's home is one, a copy of the image's, which `--rm` removes
        // on the container's own exit and `podman rm` keeps without `--volumes`.
        podman(transcript, Seq("rm", "-f", "-v", "-t", "2", session.container))
        session.process.waitFor(Patience, TimeUnit.SECONDS)
        if session.bpf then
          @tailrec def gone(tries: Int): Boolean =
            vm.rootSees(session.pinDir).contains(false) ||
              tries < 30 && { Thread.sleep(1000); gone(tries + 1) }
          if !gone(0) then info(s"${session.container}'s pins outlived its teardown")

      private def exec(session: Session, command: String*): Output =
        podman(transcript, Seq("exec", session.container) ++ command)

      /** A program of the driver's, copied into the session's /tmp. */
      private def copyIn(session: Session, name: String, text: String): String =
        val file = scratchRoot / name
        Files.writeString(file, text)
        podman(transcript, Seq("cp", file.toString, s"${session.container}:/tmp/$name"))
        s"/tmp/$name"

      /** Where the session sees a host path: the workspace's own path, as the machine serves it. */
      private def seen(path: Path): String = vmPath(platform, path.toString)

      // --- The machine's view of a session ---------------------------------------------------------------

      /** The launch's steps line (KoAgentBpf.stepsLogLine) in its run's ko-agent-bpf.log. */
      private def stepsLog(session: Session): String =
        val logs = stateDir / "log" / session.id
        if !Files.isDirectory(logs) then ""
        else
          Using.resource(Files.list(logs))(_.iterator().asScala.toSeq)
            .find(run => run.getFileName.toString.matches(s"run-.*-${session.suffix}"))
            .map(_ / "ko-agent-bpf.log").filter(Files.isRegularFile(_)).map(Files.readString).getOrElse("")

      private def took(session: Session): Boolean = stepsLog(session).contains(TakenPhrase)

      /** The read-back of a live session's attached set against its own records, as its launch ran it. */
      private def reverify(session: Session): String =
        val volume = podman(transcript, Seq("inspect", "--format",
          s"{{with .Config.Labels}}{{index . `$VolumeLabel`}}{{end}}", session.container)).text.trim
        val flags = Seq(Option.when(platform == Platform.Windows)("short-names"),
          Option.when(session.unixSocket)("unix-socket")).flatten
        val flagOption = if flags.isEmpty then "" else s"--flags ${flags.mkString(",")}"
        val hooks = (if session.unixSocket then Hooks9 else Hooks8).mkString(" ")
        val sess = s"$dir/sessions/${session.container}"
        val fixture = quoted(seen(stateDir / "bpf" / "proof" / session.id))
        vm(sh(
          s"cg=$$(sed -n 's/^cgroup=\\([^ ]*\\).*/\\1/p' $sess/cgroup)",
          s"volmp=$$(podman volume inspect --format '{{.Mountpoint}}' $volume)",
          s"sudo -n $readback verify $$cg --tags $dir/tags.txt --records $sess/records.bin --workspace " +
            s"${quoted(seen(session.workspace))} --fixture $fixture --volume $$volmp $flagOption $hooks",
        )).text.trim

      /** The programs the session's pinned links hold, one per hook. */
      private def programIds(session: Session): Set[String] =
        val hooks = (if session.unixSocket then Hooks9 else Hooks8).mkString(" ")
        vm(s"sudo -n sh -c 'for h in $hooks; do $controller link-info ${session.pinDir}/links/$$h; done'").text
          .linesIterator.map(line => field("prog_id", line)).filter(_.nonEmpty).toSet

      private def preloadedCheck(): String =
        vm(s"sudo -n $readback check-preloaded $Preloaded --tags $dir/tags.txt ${Hooks9.mkString(" ")}").text.trim

      /** Whether a preloaded set passing its check appears within 30 s. */
      private def awaitPreloaded(): Boolean =
        @tailrec def poll(tries: Int): Boolean =
          preloadedCheck().contains("check-preloaded ok=1") || tries < 30 && { Thread.sleep(1000); poll(tries + 1) }
        poll(0)

      /** A preloaded set ready, prepared now as `--build` prepares one where none passes. */
      private def ensurePreloaded(): Unit =
        if !preloadedCheck().contains(" ok=1") then
          vm(sh(s"sudo -n $controller unpin $Preloaded 2>/dev/null", s"sudo -n $controller preload $Preloaded"))

      // --- The rows --------------------------------------------------------------------------------------

      def firstLaunch(): Option[Session] =
        step("a launch: io_uring_setup refused, the preloaded set taken and frozen, the next one prepared")
        val workspace = repository("first")
        Files.writeString(workspace / "io_uring.py", IoUringPy)
        val script = quoted(s"${seen(workspace)}/io_uring.py")
        ensurePreloaded()
        val launched = launch(workspace, "live,bpf", command = Seq("sh", "-c", s"python3 $script; exec sleep $Linger"))
        check(s"the launch ran: ${launched.describe}", launched.started.nonEmpty)
        launched.started.map: session =>
          @tailrec def firstAnswer(tries: Int): String =
            val line = Files.readString(session.log).linesIterator.find(_.startsWith("io_uring_setup ")).getOrElse("")
            if line.nonEmpty || tries >= 30 then line else { Thread.sleep(1000); firstAnswer(tries + 1) }
          val first = firstAnswer(0)
          check(s"the first process's io_uring_setup answers ENOSYS: $first", first.contains("errno=ENOSYS"))
          val execed = exec(session, "python3", s"${seen(workspace)}/io_uring.py").text.trim
          check(s"a podman exec process's io_uring_setup answers ENOSYS: $execed", execed.contains("errno=ENOSYS"))
          val steps = stepsLog(session).trim
          check(s"the launch took the preloaded set: $steps", steps.contains(TakenPhrase))
          val verified = reverify(session)
          check(s"the taken set's records are the launch's and frozen: $verified",
            verified.contains("verify ok=1") && field("records_frozen", verified) == "1")
          val ready = awaitPreloaded()
          val next = preloadedCheck()
          check(s"the next set was prepared and passes its check, not frozen: $next",
            ready && field("records_frozen", next) == "0")
          info(s"cgroup manager ${facts.manager}; the proof ran through ${
            if facts.manager == "systemd" then "a scope under the attach slice" else "a user scope joining the leaf"
          }")
          if platform == Platform.Windows then
            check("on WSL the launcher's own proof ran below the attach cgroup and passed: the launch started",
              steps.contains("tested in"))
          session

      def recordsAcrossTake(first: Session): Unit =
        step("a live session's records across another launch's take, and the two sessions' programs")
        val before = reverify(first)
        val second = launch(repository("second"), "live,bpf")
        check(s"a second launch ran beside it: ${second.describe}", second.started.nonEmpty)
        second.started.foreach: other =>
          val taken = if took(other) then "took a" else "found no"
          info(s"the second launch $taken preloaded set: ${stepsLog(other).trim}")
          awaitPreloaded()
          val after = reverify(first)
          check(s"the live session's records read back the same before and after: ${field("roots", before)} roots, " +
            s"${field("rule_count", after)} rules", before.contains("verify ok=1") && after.contains("verify ok=1"))
          val (mine, theirs) = (programIds(first), programIds(other))
          check(s"the two sessions' programs are disjoint: ${mine.size} and ${theirs.size} ids",
            mine.size == 8 && theirs.size == 8 && mine.intersect(theirs).isEmpty)
          end(other)
        end(first)

      def race(): Unit =
        step("two launches racing for one preloaded set")
        ensurePreloaded()
        val pending = Seq(begin(repository("race-a"), "live,bpf"), begin(repository("race-b"), "live,bpf"))
        val sessions = pending.map(await).flatMap(_.started)
        check(s"both launches ran: ${sessions.map(_.container).mkString(" ")}", sessions.size == 2)
        if sessions.size == 2 then
          val taken = sessions.map(session => s"${session.container}=${took(session)}")
          info(s"took the preloaded set: ${taken.mkString(" ")}")
          val ids = sessions.map(programIds)
          check(s"their programs are disjoint: ${ids.map(_.size).mkString(" and ")} ids",
            ids.forall(_.size == 8) && ids(0).intersect(ids(1)).isEmpty)
        sessions.foreach(end)

      def replacedBuild(): Unit =
        step("a preloaded set of an earlier build, discarded by its tags")
        if !vm(s"test -r $OtherBuild").ok then
          info(s"skipped: no $OtherBuild in the machine; run Phase 4 first, whose build leaves it")
        else
          ensurePreloaded()
          def sha(file: String): String = vm.line(s"sha256sum $file | cut -d' ' -f1")
          val installedSha = sha(s"$dir/policy.bpf.o")
          // The copy the restore puts back, made and compared before anything is replaced: a failed or
          // stale copy must never overwrite the installed object.
          val kept = vm(s"rm -f $dir/policy.bpf.o.phase6 && cp $dir/policy.bpf.o $dir/policy.bpf.o.phase6").ok &&
            installedSha.nonEmpty && sha(s"$dir/policy.bpf.o.phase6") == installedSha
          if check("the installed object is kept aside, the copy's SHA-256 its own", kept) then
            registry.swapped = true
            val swapped = vm(s"cp $OtherBuild $dir/policy.bpf.o && sudo -n $readback tags policy.bpf.o $dir/tags.txt")
            if check("the other build is installed in the installed one's place, its tags recorded", swapped.ok) then
              val launched = launch(repository("replaced"), "live,bpf")
              check(
                "a launch after another build's install ran, its read-back passing against the new tags, so the " +
                  s"set of the earlier build was not attached: ${launched.describe}",
                launched.started.nonEmpty,
              )
              launched.started.foreach: session =>
                val how = if took(session) then "took a set of the new build" else "loaded"
                info(s"the launch $how: ${stepsLog(session).trim}")
                end(session)
            val restoredRun = vm(restoreScript(dir))
            val restored = preloadedCheck()
            val back =
              restoredRun.ok && sha(s"$dir/policy.bpf.o") == installedSha && restored.contains("check-preloaded ok=1")
            if back then registry.swapped = false
            check(s"the installed build is restored, its tags recorded and its set passing: $restored", back)

      def orphanOfKilledLaunch(): Unit =
        step("the pins of a launch that died after taking the preloaded set, removed by the next reconcile")
        ensurePreloaded()
        // What a launch killed after its attach and before its container leaves (KoAgentBpf.launchScript):
        // the session's record and attach cgroup, and the taken set pinned at the session's pin directory,
        // its programs attached to that cgroup. The launcher's own names, so its reconcile takes it.
        val orphan = s"${ContainerPrefix}$Prefix-dead-${ProcessHandle.current().pid()}"
        registry.orphans += orphan
        val cgroup = attachCgroup(vm, facts.manager, facts.uid, "ko-agent-bpf", orphan)
        val record = s"$dir/sessions/$orphan"
        val made = vm(s"mkdir -p $record && echo cgroup=${cgroup.path} cgroup_id=$$(stat -c %i ${cgroup.path}) " +
          s"> $record/cgroup && sudo -n mv $Preloaded $PinRoot/$orphan && sudo -n $controller attach-pinned " +
          s"${cgroup.path} $PinRoot/$orphan ${Hooks8.mkString(" ")}")
        if check(s"the dead launch's record, cgroup and attached pins are in place: ${cgroup.path}", made.ok) then
          val launched = launch(repository("after-death"), "live,bpf")
          check(s"the next launch ran: ${launched.describe}", launched.started.nonEmpty)
          val left = vm.line(s"sudo -n sh -c 'for p in $PinRoot/$orphan $record ${cgroup.path}; do " +
            s"[ -e $$p ] && echo $$p; done; true'")
          val leftover = if left.isEmpty then "none" else left
          check(s"its reconcile removed the dead launch's pins, record and cgroup: $leftover left", left.isEmpty)
          launched.started.foreach(end)

      def noPreloadedSet(): Unit =
        step("a launch finding no preloaded set, as the first after a machine boot")
        vm(s"sudo -n $controller unpin $Preloaded")
        val launched = launch(repository("no-set"), "live,bpf")
        check(s"the launch ran: ${launched.describe}", launched.started.nonEmpty)
        launched.started.foreach: session =>
          val how = if took(session) then "took the set its own reconcile prepared" else "loaded its own"
          info(s"the launch $how: ${stepsLog(session).trim}")
          val ready = awaitPreloaded()
          check(s"a set was prepared for the next launch: ${preloadedCheck()}", ready)
          end(session)

      def unixSocketExecAndRestart(): Unit =
        step("podman exec and podman restart of a unix-socket session")
        val workspace = repository("unix-socket")
        val launched = launch(workspace, "live,bpf,unix-socket")
        check(s"the launch under unix-socket ran: ${launched.describe}", launched.started.nonEmpty)
        launched.started.foreach: session =>
          val config = quoted(s"${seen(workspace)}/.git/config")
          def protectedWrite(): String = exec(session, "sh", "-c", s"echo x >> $config; echo status=$$?").text.trim
          check("a podman exec process starts under file_receive", exec(session, "true").ok)
          // dash answers a refused redirection with status 2.
          def refused(answer: String) = answer.contains("not permitted") && !answer.contains("status=0")
          val before = protectedWrite()
          check(s"its protected write is refused: $before", refused(before))
          val restarted = podman(transcript, Seq("restart", "-t", "2", session.container))
          val state =
            podman(transcript, Seq("inspect", "--format", "{{.State.Status}}", session.container)).text
          check(s"podman restart ran and the container ran again under file_receive: status ${restarted.status}, " +
            state.trim, restarted.ok && state.trim == "running")
          // The launcher's `podman wait` returns at the restart's stop, and its run's cleanup removes the
          // container (SandboxLifecycle.ReaperScript): a launcher session does not outlive a restart.
          Thread.sleep(5000)
          val remains = podman(transcript, Seq("container", "exists", session.container)).ok
          if remains then
            check("after the restart a podman exec process starts", exec(session, "true").ok)
            val after = protectedWrite()
            check(s"and its protected write is refused: $after", refused(after))
          end(session)
          if !remains then
            val pins = vm.rootSees(session.pinDir)
            val state = pins.fold("unreadable")(present => if present then "present" else "gone")
            check(s"the launcher ended the restarted session, and its pins went with it: $state",
              pins.contains(false))

      def worktreeSocketSymlink(): Unit =
        step("a linked worktree's main gitdir: a symlink under .git/objects to a socket outside")
        if platform == Platform.Windows then
          info("skipped: the WSL share answers a socket bind ENOTSUP, so no socket lies in the main checkout's tree")
        else worktreeRow()

      private def worktreeRow(): Unit =
        val main = repository("main")
        val linked = worktree(main, "main-linked")
        val socket = s"${seen(main)}/sock"
        val link = main / ".git" / "objects" / "s"
        val linkSeen = s"${seen(main)}/.git/objects/s"
        val made =
          try { Files.createSymbolicLink(link, Path.of("../../sock")); true }
          catch case ex: java.io.IOException => { info(s"skipped: the host made no symlink: ${ex.getMessage}"); false }
        if made then
          val mainLaunch = launch(main, "live,bpf,unix-socket")
          check(s"the main checkout's session ran: ${mainLaunch.describe}", mainLaunch.started.nonEmpty)
          mainLaunch.started.foreach: mainSession =>
            val bind = copyIn(mainSession, "bind.py", BindPy)
            val connect = copyIn(mainSession, "connect.py", ConnectPy)
            podman(transcript, Seq("exec", "-d", mainSession.container, "python3", bind, socket))
            Thread.sleep(2000)
            val direct = exec(mainSession, "python3", connect, linkSeen).text.trim
            check(s"in the main session the socket answers through the symlink: $direct", direct == "connect result=ok")
            val linkedLaunch = launch(linked, "live,bpf,unix-socket")
            check(s"the linked worktree's session ran beside it: ${linkedLaunch.describe}",
              linkedLaunch.started.nonEmpty)
            linkedLaunch.started.foreach: linkedSession =>
              val program = copyIn(linkedSession, "connect.py", ConnectPy)
              val through = exec(linkedSession, "python3", program, linkSeen).text.trim
              check(s"the linked worktree's container cannot connect through it: $through",
                through.startsWith("connect result=") && through != "connect result=ok")
              end(linkedSession)
            end(mainSession)

      def hostFifo(): Unit =
        step("a FIFO the host made, in a session")
        if platform == Platform.Windows then
          info("skipped: NTFS makes no FIFO, so the host cannot make one on the share")
        else
          val workspace = repository("fifo")
          val made = host(transcript, Seq("mkfifo", (workspace / "fifo").toString)).ok
          check("the host made a FIFO in the workspace", made)
          if made then
            val launched = launch(workspace, "live,bpf")
            check(s"the launch ran: ${launched.describe}", launched.started.nonEmpty)
            launched.started.foreach: session =>
              val program = copyIn(session, "fifo.py", FifoPy)
              val answered = exec(session, "python3", program, s"${seen(workspace)}/fifo").text
              transcript.indent(answered)
              if field("lstat", answered) != "ok" then
                info(s"the session's lstat of it answers ${field("lstat", answered)}: the share refuses it before " +
                  "any hook, the policy having none on lookup or getattr")
              else if field("is_fifo", answered) != "1" then info("the share does not show the session a FIFO")
              else
                check("its open, non-blocking, is refused: EPERM", field("open", answered) == "EPERM")
                check("a time change on it is refused: EPERM", field("utime", answered) == "EPERM")
              end(session)

      /** The refusal of `second` beside a live `first`, in one case of what the two share. */
      private def refusedBeside(
          description: String,
          first: (Path, String, Seq[String]),
          second: (Path, String, Seq[String]),
          between: () => Option[Path] = () => None,
      ): Unit =
        val (firstDir, firstSettings, firstExtra) = first
        val launched = launch(firstDir, firstSettings, firstExtra)
        launched.started match
          case None => check(s"$description: the first launch ran: ${launched.describe}", false)
          case Some(live) =>
            val (secondDir, secondSettings, secondExtra) = second
            val target = between().getOrElse(secondDir)
            val beside = launch(target, secondSettings, secondExtra)
            beside.started.foreach(end)
            check(s"$description, $firstSettings then $secondSettings: refused: ${beside.describe}",
              beside match
                case Outcome.Ended(status, output) => status != 0 && output.toLowerCase.contains("end it first")
                case Outcome.Started(_) => false)
            end(live)

      def refusals(): Unit =
        step("the refusals beside a live session of the other backend or socket setting")
        // On Windows `git worktree add` writes an absolute `C:/...` pointer, which the guard refuses to
        // serve (doc/TODO.md, "Deferred — a linked worktree's absolute pointer on Windows"), and a
        // directory the share serves to a live session cannot be renamed: the host answers a sharing
        // violation.
        val worktrees = platform == Platform.Mac
        val renames = platform == Platform.Mac
        if !worktrees then
          info("skipped on Windows: the linked worktree's cases, whose launch the guard refuses for the " +
            "worktree's absolute pointer, and the host rename, which a live session's share refuses")
        val pairings = Seq(("live,fuse", "live,bpf"), ("live,bpf", "live,bpf,unix-socket"))
        var round = 0
        def fresh(name: String): Path = { round += 1; repository(s"$name-$round") }
        def volume(name: String): Seq[String] =
          val named = s"$Prefix-$name-$round"
          registry.volumes += named
          Seq(s"--persistent-volume=$named")
        for
          (a, b) <- pairings
          (first, second) <- Seq((a, b), (b, a))
        do
          val one = fresh("volumes")
          refusedBeside("one workspace, two volumes", (one, first, Seq.empty), (one, second, volume("vol")))
          if worktrees then
            val main = fresh("shared")
            val linked = worktree(main, s"shared-linked-$round")
            refusedBeside("a main checkout and its linked worktree sharing its volume", (main, first, Seq.empty),
              (linked, second, Seq.empty))
          val outer = fresh("outer")
          val inner = Files.createDirectories(outer / "inner")
          refusedBeside("a workspace below another's root", (outer, first, Seq.empty), (inner, second, Seq.empty))
          if worktrees then
            val own = fresh("own")
            val ownLinked = worktree(own, s"own-linked-$round")
            refusedBeside("a linked worktree with its own volume beside its main checkout", (own, first, Seq.empty),
              (ownLinked, second, volume("wt")))
          if renames then
            val before = fresh("renamed")
            val after = before.resolveSibling(s"${before.getFileName}-moved")
            refusedBeside("a host rename of the workspace between the two launches", (before, first, Seq.empty),
              (after, second, Seq.empty), between = () => { Files.move(before, after); Some(after) })
        unlabelled()
        racingSettings()
        control()

      /** A container of an earlier launcher, named as the launcher names its own and without the labels. */
      private def unlabelled(): Unit =
        val name = s"${ContainerPrefix}$Prefix-unlabelled-${ProcessHandle.current().pid()}"
        registry.containers += name
        podman(transcript, Seq("run", "-d", "--name", name, "--label", s"$Label=unlabelled",
          "--entrypoint", "sleep", SandboxImage, "600"))
        val workspace = repository("beside-unlabelled")
        val bpf = launch(workspace, "live,bpf")
        bpf.started.foreach(end)
        check(s"a launch under bpf beside an unlabelled container of an earlier launcher is refused: ${bpf.describe}",
          bpf.started.isEmpty && bpf.describe.toLowerCase.contains("earlier launcher"))
        val fuse = launch(workspace, "live,fuse")
        check(s"a filter launch beside it runs: ${fuse.describe}", fuse.started.nonEmpty)
        fuse.started.foreach(end)
        podman(transcript, Seq("rm", "-f", "-v", "-t", "0", name))

      private def racingSettings(): Unit =
        val workspace = repository("racing")
        val outcomes = Seq(begin(workspace, "live,fuse"), begin(workspace, "live,bpf")).map(await)
        // The other must be the sharing refusal, not a timeout or a failure of its own.
        val refused = outcomes.count:
          case Outcome.Ended(status, output) => status > 0 && output.toLowerCase.contains("end it first")
          case Outcome.Started(_) => false
        check(s"of two launches of one workspace under the two backends racing, one runs and one is refused: " +
          outcomes.map(_.describe).mkString("; "), outcomes.count(_.started.nonEmpty) == 1 && refused == 1)
        outcomes.flatMap(_.started).foreach(end)

      /** The comparison's other side: the same backend and setting beside a sharing session is no refusal. */
      private def control(): Unit =
        val workspace = repository("control")
        val first = launch(workspace, "live,bpf")
        val second = launch(workspace, "live,bpf")
        check(s"a second session of one workspace under the same backend and setting runs: ${first.describe}; " +
          second.describe, first.started.nonEmpty && second.started.nonEmpty)
        (second.started ++ first.started).foreach(end)

      def memory(): Unit =
        step("the kernel's memory for one, four and eight program sets, and after their removal")
        // The kernel charges a set's memory to the loader's memory cgroup, after the loader too
        // (kernel/bpf/syscall.c, bpf_map_save_memcg): every load runs in one cgroup kept for the
        // measurement, the loader moved there by root, since an ssh session's cgroup shares no ancestor the
        // user owns with the delegated subtree ("Phase 4 on WSL").
        registry.memoryCgroup = true
        val cgroup = attachCgroup(vm, facts.manager, facts.uid, Prefix, "mem")
        val leaf = if facts.manager == "systemd" then s"${cgroup.path}/$Prefix-hold-mem.service" else cgroup.path
        def current(): Long = vm.line(s"cat ${cgroup.path}/memory.current").toLongOption.getOrElse(-1L)
        def load(index: Int): Output =
          vm(s"sudo -n sh -c 'echo $$$$ > $leaf/cgroup.procs && exec $controller preload $MemRoot/set$index'")
        def programs(): String = vm.line(s"sudo -n find $MemRoot -path '*/progs/*' | wc -l")
        val base = current()
        if base < 0 then info(s"skipped: ${cgroup.path} has no memory.current")
        else
          vm(s"sudo -n mkdir -p $MemRoot")
          val counts = Seq(1, 4, 8)
          // Strict and in order: each reading follows its loads.
          val readings = counts.zip(0 +: counts).map: (sets, loaded) =>
            val loads = (loaded + 1 to sets).map(load)
            loads.foreach(answer => transcript.indent(answer.text))
            val bytes = current()
            // `preload` loads every program of the object, the ninth hook's included.
            val programCount = programs()
            check(s"$sets sets loaded, $programCount programs: memory.current $bytes, " +
              s"${(bytes - base) / sets / 1024} KiB a set above the cgroup's $base before",
              loads.forall(_.ok) && programCount == (sets * Hooks9.size).toString)
            bytes
          vm(unpinEvery(controller, MemRoot))
          // A program's and a map's memory is freed after an RCU grace period, not at the unpin.
          Thread.sleep(5000)
          val removed = current()
          info(s"after their removal: memory.current $removed")
          val bytes = base +: readings
          check("the charge grows with the sets and falls after their removal",
            bytes.zip(bytes.tail).forall(_ < _) && removed < bytes.last)
        removeCgroup(vm, facts.manager, facts.uid, Prefix, "mem")
        registry.memoryCgroup = false

      def codexExec(): Unit =
        step("codex exec with its daemon directory unwritable: the user's row")
        info("run by hand in a live,bpf session with a signed-in Codex: `codex exec 'print hello'` must answer " +
          "while ~/.codex holds no socket the policy refuses (\"The hooks\", file_receive)")
