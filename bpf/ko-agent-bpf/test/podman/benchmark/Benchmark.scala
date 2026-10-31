#!/usr/bin/env -S scala shebang
//> using scala 3.10.0
//> using file ../PodmanTestHelper.scala
//> using file ../../../../../src/main/scala/SourceDigest.scala

// The benchmark suite of bpf/ko-agent-bpf/doc/evidence.md ("Suites", benchmark) on the podman machine of either host,
// in one run. Run it on the HOST, from the repository root, with the default machine running and the sandbox image
// built by the launcher's --build:
//
//     bpf/ko-agent-bpf/test/podman/benchmark/Benchmark.scala [--out DIR] [--launcher JAR] [--tree PATH|URL]
//         [--rounds N] [--files N]
//                                   [--stacks LIST] [--workloads LIST] [--platform mac|windows]
//
// The first line hands the file to the `scala` runner's `shebang` sub-command, which takes everything after the file as
// the program's arguments; on Windows, where no shebang runs, the same is
// `scala shebang bpf\ko-agent-bpf\test\podman\benchmark\Benchmark.scala [options]`. The `using file` line pulls in
// ../PodmanTestHelper.scala, what every driver shares; this file holds the suite's own rows and readers.
//
// It builds the suite image (Containerfile) from a context assembled out of the files sources.txt
// lists, extracts /out into the machine under ~/.local/share/ko-agent-sandbox/bpftest-benchmark, clones the
// tree of fuse/ko-agent-fs/doc/verification-log.md's real-tree rows (sbt/sbt, shallow) into a scratch
// workspace on the share, launches the policy over it as the lifecycle suite's driver does, steps 1 to 3 of
// "Lifecycle", and runs the two benchmarks of fuse/ko-agent-fs/bench/ over that one tree in three stacks:
//
//   bind     the sandbox image over a writable bind of the workspace, unfiltered.sh's command
//   policy   the same command below the attach cgroup, so the eight hooks judge it
//   filter   the launcher's session under --workspace=live,fuse, the workspace through the filter
//
// and, before the launch, one round of entry-cost.py on the bind with no program attached to any hook,
// the `bare` column, so that the shim the first attach installs on each hook for every task in the VM
// ("The mechanism") has its cost measured against the bind beside the policy.
//
// entry-cost.py runs --rounds times per stack (default 3), the stacks interleaved within a round; the
// build, `sbt 'testOnly *SandboxTextWidthTest'` on a clone of this repository made inside the tree with
// its output there, as verification-log.md's "an sbt build, by where its output goes" ran it, once on
// the bind and once under the policy, with network for its downloads and no filter run, whose 604 s
// that log holds; and walk-cost.py once per stack. During each run a sampler in the machine records /proc/stat,
// /proc/meminfo and the pressure files each second, and after each run under the policy the
// program's counters are read and zeroed. Every line is printed and appended to OUTDIR/transcript.log
// (default: out-macos/ or out-wsl/ beside this script, ignored by git), the raw outputs land beside
// it, and results.txt holds the tables. Send OUTDIR back; the transcript and the tables are what
// "Benchmark on macOS" and "Benchmark on WSL" are filled from.
//
// --stacks and --workloads take comma-separated subsets (bind,policy,filter and perf,build,walk) for a
// partial rerun; --tree names a repository to clone instead of GitHub's, such as an earlier clone;
// --platform drives as that platform where the detection must be overridden, as in a dry run against
// fake commands.
// At the figures of verification-log.md, "The cost of a path walk", entry-cost.py's five rows through
// the filter take about 54 s a round on the macOS machine and about 8 minutes on the WSL one, and
// walk-cost.py's `git status` 72 s on macOS; the other stacks are faster by the ratios there.
//
// The platforms differ in data alone: the cgroup manager podman reports (a transient slice under
// systemd, a directory under the user's delegated subtree under cgroupfs), the path the machine serves
// a host directory at (the same path on macOS, /mnt/<drive>/... on Windows) and the output
// directory's name. On Windows, %UserProfile%\.wslconfig must hold `[wsl2]` and
// `isolateDistroCgroup=false` ("Environment evidence"), or the containers land in no cgroup of their
// own. Every command in the machine is one line without double quotes, the form the lifecycle suite's Windows
// driver settled on after double quotes inside an argument did not reach the machine.
//
// It writes the scratch workspace and the proof fixture under ~/ko-agent-bpftest-benchmark.<pid> on the host, which the
// machine mounts, one attach cgroup ko-agent-bpftest-benchmark-policy with its transient unit, a podman volume, pins
// under /sys/fs/bpf/ko-agent-bpftest-benchmark in the machine, containers labelled ko-agent-bpftest-benchmark and,
// through the filter stack's launches, the launcher's own state for the scratch workspace; all are removed on exit,
// that state by the launcher's --reset. A live sandbox session whose workspace holds that directory, under another
// backend or socket setting, makes the launcher refuse the filter stack.

import scala.util.Using
import scala.util.matching.Regex

import java.lang.ProcessBuilder.Redirect
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path, StandardCopyOption}
import java.util.Base64
import java.util.concurrent.TimeUnit

import PodmanTestHelper.*

@main def suite(args: String*): Unit = Benchmark.run(args)

object Benchmark:

  /** `Bare` is the bind before any program is attached, run once before the launch and not selectable. */
  enum Stack(val name: String):
    case Bare   extends Stack("bare")
    case Bind   extends Stack("bind")
    case Policy extends Stack("policy")
    case Filter extends Stack("filter")

  object Stack:
    val selectable: Seq[Stack] = Seq(Bind, Policy, Filter)

  enum Workload(val name: String):
    case Perf  extends Workload("perf")
    case Build extends Workload("build")
    case Walk  extends Workload("walk")

  /** The build's clone inside the tree, made before each build run and removed after it, at a name no run
    * reuses: the machine keeps a removed entry's dentry for seconds (libkrun's `entry_timeout`, "One hook on
    * macOS"), so a clone made again at the same name reads as absent in the next container. */
  def buildDir(stack: Stack): String = s".ko-build-${stack.name}/ko-agent-sandbox"

  case class SuiteOptions(
      out: Option[Path] = None,
      launcher: Option[Path] = None,
      tree: String = "https://github.com/sbt/sbt.git",
      rounds: Int = 3,
      files: Int = 1800,
      stacks: Seq[Stack] = Stack.selectable,
      workloads: Seq[Workload] = Workload.values.toSeq,
      platform: Option[Platform] = None,
  )

  def parseOptions(args: Seq[String]): Either[String, SuiteOptions] =
    def names[A](text: String, all: Seq[A], nameOf: A => String): Either[String, Seq[A]] =
      val wanted = text.split(',').toSeq.map(_.trim).filter(_.nonEmpty)
      val unknown = wanted.filterNot(name => all.exists(item => nameOf(item) == name))
      if unknown.nonEmpty then Left(s"unknown: ${unknown.mkString(", ")}")
      else Right(all.filter(item => wanted.contains(nameOf(item))))
    def loop(rest: Seq[String], options: SuiteOptions): Either[String, SuiteOptions] = rest match
      case Seq() => Right(options)
      case Seq("--out", value, tail*) => loop(tail, options.copy(out = Some(Path.of(value).toAbsolutePath)))
      case Seq("--launcher", value, tail*) => loop(tail, options.copy(launcher = Some(Path.of(value).toAbsolutePath)))
      case Seq("--tree", value, tail*) => loop(tail, options.copy(tree = value))
      case Seq("--rounds", value, tail*) =>
        value.toIntOption.filter(_ > 0).toRight(s"--rounds takes a positive number: $value")
          .flatMap(rounds => loop(tail, options.copy(rounds = rounds)))
      case Seq("--files", value, tail*) =>
        value.toIntOption.filter(_ > 0).toRight(s"--files takes a positive number: $value")
          .flatMap(files => loop(tail, options.copy(files = files)))
      case Seq("--stacks", value, tail*) =>
        names(value, Stack.selectable, _.name).flatMap(stacks => loop(tail, options.copy(stacks = stacks)))
      case Seq("--workloads", value, tail*) =>
        names(value, Workload.values.toSeq, _.name)
          .flatMap(workloads => loop(tail, options.copy(workloads = workloads)))
      case Seq("--platform", value, tail*) =>
        Platform.named(value).flatMap(platform => loop(tail, options.copy(platform = Some(platform))))
      case Seq(other, _*) => Left(s"unknown option $other; see the header of Benchmark.scala")
    loop(args, SuiteOptions())

  // --- The pure parts: what the transcript's figures are read with -----------------------------------------

  case class Figure(row: String, value: Double, unit: String)

  private val perfLine = raw"^\s*(\S.*?)\s+(\d+) us/entry\s*$$".r

  def parsePerf(text: String): Seq[Figure] =
    text.linesIterator
      .collect:
        case perfLine(row, value) => Figure(row, value.toDouble, "µs/entry")
      .toSeq

  private val walkDepth = raw"^depth (\d+)\s+([\d.]+) ms\s+.*$$".r
  private val walkDeep = raw"^\s+(absolute|relative after chdir|through directory fd) ([\d.]+) ms$$".r
  private val walkByPath = raw"^lstat each tracked by path: ([\d.]+) s, ([\d.]+) ms/file$$".r
  private val walkByFd = raw"^same through directory fds: ([\d.]+) s, ([\d.]+) ms/file \(opening the (\d+) .*$$".r
  private val walkCommand = raw"^(find \. -type f|git status|git status --untracked-files=no): ([\d.]+) s$$".r

  def parseWalk(text: String): Seq[Figure] =
    text.linesIterator
      .collect:
        case walkDepth(depth, ms) => Figure(s"lstat by path at depth $depth", ms.toDouble, "ms")
        case walkDeep(way, ms) => Figure(s"the deepest file, $way", ms.toDouble, "ms")
        case walkByPath(_, perFile) => Figure("lstat of each tracked file, by path", perFile.toDouble, "ms/file")
        case walkByFd(_, perFile, _) => Figure("the same files through a directory fd", perFile.toDouble, "ms/file")
        case walkCommand(command, seconds) => Figure(s"`$command`", seconds.toDouble, "s")
      .toSeq

  private val sbtElapsed = raw"(?:elapsed time|Total time): (\d+) s".r

  /** sbt's own elapsed time over its commands, `elapsed time` in sbt 2 and `Total time` in sbt 1. */
  def parseBuild(text: String): Seq[Figure] =
    val totals = sbtElapsed.findAllMatchIn(text).map(_.group(1).toDouble).toSeq
    Seq(Figure("`sbt testOnly`, sbt's elapsed time", totals.sum, "s")).filter(_ => totals.nonEmpty)

  /** The sampler's lines over one run: CPU busy and iowait from /proc/stat's deltas, memory used
    * from MemTotal - MemAvailable, and the highest `some avg10` of each pressure file. */
  case class SampleSummary(
      samples: Int,
      busyMeanPct: Double,
      busyMaxPct: Double,
      iowaitMaxPct: Double,
      usedMinMiB: Long,
      usedMaxMiB: Long,
      psiMax: Seq[Double],
  ):
    def text: String =
      f"$samples samples; CPU busy $busyMeanPct%.0f %% mean, $busyMaxPct%.0f %% max, iowait $iowaitMaxPct%.0f %% " +
        f"max; memory used $usedMinMiB to $usedMaxMiB MiB; pressure some avg10 max cpu/memory/io " +
        psiMax.map(value => f"$value%.2f").mkString("/")

  def summarizeSamples(text: String): Option[SampleSummary] =
    case class Sample(cpu: Seq[Long], used: Long, psi: Seq[Double])
    val samples = text.linesIterator
      .flatMap: line =>
        line.split(" \\| ") match
          case Array(cpuPart, memPart, psiPart) =>
            val cpu = cpuPart.split("\\s+").drop(1).dropWhile(_ == "cpu").flatMap(_.toLongOption).toSeq
            val total = field("MemTotal", memPart).toLongOption
            val available = field("MemAvailable", memPart).toLongOption
            val psi = psiPart.split("\\s+").drop(1).flatMap(_.toDoubleOption).toSeq
            for t <- total; a <- available if cpu.length >= 5 yield Sample(cpu, (t - a) / 1024, psi)
          case _ => None
      .toSeq
    Option.when(samples.length >= 2):
      val pairs = samples.zip(samples.tail)
      val (busy, iowait) = pairs
        .map: (before, after) =>
          val delta = before.cpu.zip(after.cpu).map((earlier, later) => later - earlier)
          val total = delta.take(8).sum.toDouble.max(1)
          (100 * (1 - (delta(3) + delta(4)) / total), 100 * delta(4) / total)
        .unzip
      val psiLength = samples.map(_.psi.length).min
      SampleSummary(
        samples.length,
        busy.sum / busy.length,
        busy.max,
        iowait.max,
        samples.map(_.used).min,
        samples.map(_.used).max,
        (0 until psiLength).map(i => samples.map(_.psi(i)).max),
      )

  /** A Markdown table with aligned columns. */
  def table(header: Seq[String], rows: Seq[Seq[String]]): String =
    val widths = (header +: rows).transpose.map(_.map(_.length).max)
    def line(cells: Seq[String]) =
      cells.zip(widths).map((text, width) => text.padTo(width, ' ')).mkString("| ", " | ", " |")
    (line(header) +: widths.map("-" * _).mkString("| ", " | ", " |") +: rows.map(line)).mkString("\n")

  def mean(values: Seq[Double]): Double = values.sum / values.length

  /** One figure over the rounds of a stack: the mean, with the range when there are several. */
  def cell(values: Seq[Double], unit: String): String =
    if values.isEmpty then "—"
    else
      val format = if unit == "µs/entry" then "%.0f" else "%.2f"
      val meanText = format.format(mean(values))
      if values.length == 1 then meanText
      else s"$meanText (${format.format(values.min)} to ${format.format(values.max)})"

  // --- The run ---------------------------------------------------------------------------------------------

  val VmDir = ".local/share/ko-agent-sandbox/bpftest-benchmark"
  val Controller = s"./$VmDir/controller"
  val Readback = s"./$VmDir/readback"
  val Fixture = s"./$VmDir/fixture"
  val Stats = s"./$VmDir/stats"
  val Tags = s"./$VmDir/tags.txt"
  val PinRoot = "/sys/fs/bpf/ko-agent-bpftest-benchmark"
  val Session = "policy"
  val Pins = s"$PinRoot/$Session"
  val SuiteImage = "ko-agent-bpftest:benchmark"
  val Volume = "ko-agent-bpftest-benchmark-vol"
  val Label = "ko-agent-bpftest-benchmark"
  val PerfDefaultFiles = 1800

  /** One line a second while OUT.run exists; the driver makes that file before starting the sampler
    * and removes it to stop it, so a run shorter than ssh's start still ends the loop. */
  val SamplerScript =
    """#!/bin/sh
      |out=$1
      |: > "$out"
      |while [ -e "$out.run" ]; do
      |    cpu=$(head -1 /proc/stat)
      |    mem=$(awk '/^MemTotal:|^MemAvailable:/ { printf "%s=%s ", substr($1, 1, length($1) - 1), $2 }' /proc/meminfo)
      |    psi=$(awk '/^some/ { printf "%s ", substr($2, 7) }' /proc/pressure/cpu /proc/pressure/memory \
      |        /proc/pressure/io 2>/dev/null)
      |    echo "t=$(date +%s.%N) $cpu | $mem| psi $psi" >> "$out"
      |    sleep 1
      |done
      |""".stripMargin

  def samplesFile(name: String): String = s"$VmDir/samples-$name.txt"

  /** The sampler over one run, held in a `Using` block: made, it marks the file and starts the loop in
    * the machine; closed, it removes the mark and waits for the loop, so a run that throws still ends it. */
  class Sampling(vm: Vm, name: String) extends AutoCloseable:
    private val file = samplesFile(name)
    private val marked = vm(s"touch ${file}.run").ok
    private val process = ProcessBuilder("podman", "machine", "ssh", s"sh $VmDir/sample.sh $file")
      .redirectOutput(Redirect.DISCARD).redirectErrorStream(true).start()
    process.getOutputStream.close()
    private var ended = false
    def close(): Unit =
      vm(s"rm -f ${file}.run")
      ended = process.waitFor(20, TimeUnit.SECONDS) && process.exitValue() == 0
      if !ended then process.destroyForcibly()
    /** The marker was made and the loop ended on its removal with status 0. */
    def ran: Boolean = marked && ended

  /** What the run leaves beside its containers: the pins, the attach cgroup, the sampler's files, the
    * volume and the scratch directory. */
  def removeLeftovers(platform: Platform, scratchDir: Path, filterLauncher: Option[Path], transcript: Transcript,
      vm: Vm): Unit =
    // What the filter stack's launches made for the scratch workspace, its volume, networks, inspection CA,
    // ruleset cache and logs, is the launcher's to name: its --reset removes it, run from that directory.
    val tree = scratchDir / "sbt"
    filterLauncher.filter(_ => Files.isDirectory(tree)).foreach: launcher =>
      host(transcript, Seq("java", "-jar", launcher.toString, "--reset"), cwd = tree)
    vm(sh(
      s"[ -x $Controller ] && sudo -n $Controller unpin $Pins >/dev/null 2>&1",
      s"sudo -n rmdir $PinRoot 2>/dev/null",
      s"systemctl --user stop $Label-hold-$Session $Label-$Session.slice 2>/dev/null",
      "systemctl --user reset-failed 2>/dev/null",
      s"rmdir $AppSliceGlob/$Label-$Session/proof $AppSliceGlob/$Label-$Session 2>/dev/null",
      s"rm -f $VmDir/sample.sh $VmDir/samples-* $VmDir/programs.txt",
      "true",
    ))
    host(transcript, Seq("podman", "volume", "rm", "-f", Volume))
    removeTree(platform, scratchDir)

  def launcherOf(options: SuiteOptions, repoDir: Path): Path =
    options.launcher.getOrElse(repoDir / "target" / "dist" / "ko-agent-sandbox.jar")

  /** The scratch workspace on the share: the host path and the machine path of the tree, what the tree
    * is, and the machine paths of the rule file, the records, the proof fixture and the volume. */
  case class Workspace(
      tree: Path,
      treeVm: String,
      head: String,
      tracked: Int,
      rulesVm: String,
      recordsVm: String,
      proofVm: String,
      volumeMountpoint: String,
  )

  /** What a container of a stack runs; `network` for the build's downloads, the rest run without one. */
  case class Command(argv: Seq[String], network: Boolean = false)

  /** A command run in a container of the stack. */
  type Runner = (Stack, Command) => Output

  case class Run(
      workload: Workload,
      stack: Stack,
      round: Int,
      wallSeconds: Double,
      figures: Seq[Figure],
      samples: Option[SampleSummary],
      stats: Seq[String],
  ):
    def name: String = s"${workload.name}-${stack.name}-$round"

  def run(args: Seq[String]): Unit =
    val options = orExit(parseOptions(args))
    val platform = orExit(Platform.resolve(options.platform))
    val repoDir = orExit(repositoryRoot(s"$SuitesPath/benchmark/sources.txt", "fuse/ko-agent-fs/bench/entry-cost.py"))
    val suiteDir = repoDir / SuitesPath / "benchmark"
    val out = options.out.getOrElse(suiteDir / platform.outDir)
    Files.createDirectories(out)
    val transcript = Transcript(out / "transcript.log")
    val vm = Vm(transcript)
    // In the home directory, on the share the machine mounts: not under the repository, which a sandbox
    // session over it holds, and beside which the launcher refuses the filter stack's session under another
    // backend ("The mechanism"); not under ~/.cache, since the launcher refuses a workspace below a dot-prefixed
    // directory.
    val scratchDir =
      Path.of(System.getProperty("user.home")) / s"ko-agent-bpftest-benchmark.${ProcessHandle.current().pid()}"
    val filterLauncher = Option.when(options.stacks.contains(Stack.Filter))(launcherOf(options, repoDir))
    val cleanup =
      Cleanup(transcript, Label, () => removeLeftovers(platform, scratchDir, filterLauncher, transcript, vm))
    runMeasured(transcript, cleanup):
      Measurement(options, platform, suiteDir, repoDir, out, transcript, vm, scratchDir).measure()

  /** The suite as steps, each `Right` with what the next needs or `Left` with the exit status after it
    * said why: 2 for a refusal before any figure is taken, 1 for a gate the transcript records as FAIL. */
  class Measurement(
      options: SuiteOptions,
      platform: Platform,
      suiteDir: Path,
      repoDir: Path,
      out: Path,
      transcript: Transcript,
      vm: Vm,
      scratchDir: Path,
  ):
    import transcript.{check, gate, info, log, refuse, step}
    private val scratchDirVm = vmPath(platform, scratchDir.toString)
    private val launcher = launcherOf(options, repoDir)

    def measure(): Int =
      val outcome =
        for
          facts <- readVmFacts()
          _ <- buildAndInstall(facts)
          workspace <- prepareWorkspace()
          bare = baseline(workspace)
          cgroup <- launchPolicy(facts, workspace)
        yield
          val runOn = containerOf(workspace, cgroup)
          stacksAreWhatTheyClaim(runOn)
          val planned = plannedRuns
          step("the workloads")
          val runs = bare ++ planned.map((workload, stack, round) => runWorkload(runOn, workload, stack, round))
          tables(facts, workspace, runs, bare.length + planned.length)
          if transcript.failed == 0 then 0 else 1
      outcome.merge

    def readVmFacts(): Either[Int, VmFacts] =
      for
        facts <- PodmanTestHelper.readVmFacts(transcript, vm, out, scratchDir, scratchDirVm, PinRoot)
        _ <- refuse(host(transcript, Seq("podman", "image", "exists", SandboxImage)).ok,
          s"no $SandboxImage image; run the launcher's --build first")
        _ <- refuse(!options.stacks.contains(Stack.Filter) || Files.exists(launcher),
          s"no launcher at $launcher; pass --launcher JAR or build it with sbt dist")
      yield facts

    def buildAndInstall(facts: VmFacts): Either[Int, Unit] =
      step("build, with the hash of its sources, and install")
      // The procedure: the driver, the rule defaults and the two benchmarks.
      val procedure = procedureSha(transcript, Seq(
        suiteDir / "Benchmark.scala",
        repoDir / SuitesPath / "PodmanTestHelper.scala",
        repoDir / RuleDefaults,
        repoDir / "fuse" / "ko-agent-fs" / "bench" / "entry-cost.py",
        repoDir / "fuse" / "ko-agent-fs" / "bench" / "walk-cost.py",
      ))
      for builtDigest <- buildSuiteImage(transcript, suiteDir, scratchDir, SuiteImage, facts.kernel)
      yield
        val installed = installSuite(vm, SuiteImage, VmDir, Label, Seq("controller", "readback", "fixture", "stats"))
        check("suite installed in the machine", installed.ok)
        vm(sh(s"sudo -n $Controller unpin $Pins >/dev/null 2>&1", "true"))
        recordBuild(transcript, vm, out, VmDir, Seq(s"sources digest=$builtDigest", s"procedure sha256=$procedure"))
        val sampler = Base64.getEncoder.encodeToString(SamplerScript.getBytes(UTF_8))
        vm(s"echo $sampler | base64 -d > $VmDir/sample.sh")
        recordTags(transcript, vm, Readback, Tags)

    def prepareWorkspace(): Either[Int, Workspace] =
      step("the workspace: the tree of the real-tree rows, the benchmarks, the rules, the proof fixture")
      val tree = scratchDir / "sbt"
      val treeVm = s"$scratchDirVm/sbt"
      val clone = host(transcript, Seq("git", "clone", "--depth", "1", options.tree, tree.toString))
      for _ <- refuse(clone.ok, s"the clone of ${options.tree} failed; pass --tree with a repository that clones")
      yield
        val head = host(transcript, Seq("git", "rev-parse", "HEAD"), cwd = tree).text.trim
        val tracked = host(transcript, Seq("git", "ls-files"), cwd = tree).text.linesIterator.length
        info(s"the tree: ${options.tree} at $head, $tracked tracked files, at $tree ($treeVm in the machine)")
        // The guarded directory the policy records as a root, read by statx, the hooks directory the stack
        // check writes into, which a clone has only when git installed its samples, and the two benchmarks at
        // the root, where entry-cost.py builds its corpus and walk-cost.py reads the tracked files.
        Files.createDirectories(tree / ".ko-agent-sandbox")
        Files.createDirectories(tree / ".git" / "hooks")
        Seq("entry-cost.py", "walk-cost.py").foreach(bench =>
          Files.copy(repoDir / "fuse" / "ko-agent-fs" / "bench" / bench, tree / bench,
            StandardCopyOption.REPLACE_EXISTING),
        )
        // The rules: the launcher's defaults, exactly what a session's policy holds.
        Files.writeString(scratchDir / "rules.txt",
          stripRules(Files.readString(repoDir / RuleDefaults)).mkString("", "\n", "\n"))
        val rulesVm = s"$scratchDirVm/rules.txt"
        val recordsVm = s"$scratchDirVm/records.bin"
        val proofVm = s"$scratchDirVm/state/proof"
        val made = vm(
          s"mkdir -p ${quoted(s"$scratchDirVm/state")} && $Fixture make ${quoted(proofVm)} ${quoted(rulesVm)} && " +
            s"$Fixture records ${quoted(rulesVm)} ${quoted(recordsVm)} $GuardedOptions",
        )
        transcript.indent(made.text)
        check(
          "the proof fixture and the records of the defaults exist",
          made.ok && field("rule_count", made.text).nonEmpty,
        )
        host(transcript, Seq("podman", "volume", "create", Volume))
        val volumeMountpoint = vm.line(s"podman volume inspect --format '{{.Mountpoint}}' $Volume")
        val volumeFsType = vm.line(s"findmnt -T ${quoted(volumeMountpoint)} -n -o FSTYPE")
        info(s"the volume's mountpoint in the machine: $volumeMountpoint, on $volumeFsType")
        Workspace(tree, treeVm, head, tracked, rulesVm, recordsVm, proofVm, volumeMountpoint)

    /** Steps 1 to 3 of "Lifecycle" over the scratch workspace; `None` when no stack needs the policy. */
    def launchPolicy(facts: VmFacts, workspace: Workspace): Either[Int, Option[Cgroup]] =
      step("the launch: the attach cgroup, the controller, the read-back, the proof")
      if !options.stacks.contains(Stack.Policy) then Right(None)
      else
        val cgroup = attachCgroup(vm, facts.manager, facts.uid, Label, Session)
        val roots = s"--records ${quoted(workspace.recordsVm)} --workspace ${quoted(workspace.treeVm)} " +
          s"--fixture ${quoted(workspace.proofVm)} --volume ${quoted(workspace.volumeMountpoint)}"
        for
          _ <- gate(s"the attach cgroup exists: ${cgroup.path}", cgroup.path.nonEmpty)
          // Step 2: load, fill, attach by link, pin.
          attach = vm(s"sudo -n $Controller attach ${cgroup.path} $Pins $roots ${Hooks8.mkString(" ")}")
          _ = transcript.indent(
            attach.text.linesIterator.filter(line => line.startsWith("attach ") || line.startsWith("refused "))
              .mkString("\n"),
          )
          _ <- gate(
            s"the controller attached eight hooks with ${field("rule_count", attach.text)} rules and five roots, " +
              "and pinned",
            field("hooks", attach.text) == Hooks8.length.toString && field("roots", attach.text) == "5",
          )
          // Step 3, the read-back.
          verify = vm(s"sudo -n $Readback verify ${cgroup.path} --tags $Tags $roots ${Hooks8.mkString(" ")}")
          _ = transcript.indent(verify.text)
          _ <- gate(
            "the read-back finds eight programs of the installed tags over one map set holding the records",
            field("ok", verify.text) == "1" && field("programs", verify.text) == Hooks8.length.toString,
          )
          proof = runProof(vm, facts.manager, cgroup, Fixture, workspace.proofVm, workspace.rulesVm)
          _ = transcript.indent(
            proof.text.linesIterator.filter(line => line.contains("mismatch") || line.startsWith("fixture ops"))
              .mkString("\n"),
          )
          _ <- gate(
            s"the proof: ${proof.text.linesIterator.find(_.startsWith("fixture ops")).getOrElse("no fixture line")}",
            field("mismatches", proof.text) == "0",
          )
        yield
          info(
            s"step 2: load ${field("load_ms", attach.text)} ms, fill ${field("fill_ms", attach.text)} ms, attach " +
              s"${field("attach_ms", attach.text)} ms; step 3: read-back ${field("ms", verify.text)} ms, proof " +
              s"${field("ms", proof.text)} ms (${field("ops", proof.text)} operations)",
          )
          Some(cgroup)

    /** A command in a container of the stack: unfiltered.sh's command for the bind, the same below the attach
      * cgroup for the policy, the launcher's own session over the same workspace for the filter. */
    def containerOf(workspace: Workspace, cgroup: Option[Cgroup]): Runner =
      val filesEnv =
        if options.files == PerfDefaultFiles then Seq.empty[String] else Seq("--env", s"FILES=${options.files}")
      val launcherFilesEnv =
        if options.files == PerfDefaultFiles then Seq.empty[String] else Seq(s"--env=FILES=${options.files}")
      (stack, command) =>
        stack match
          case Stack.Filter =>
            host(
              transcript,
              Seq("java", "-jar", launcher.toString, "--workspace=live,fuse") ++ launcherFilesEnv ++ command.argv,
              cwd = workspace.tree,
              inheritStdin = true,
            )
          case _ =>
            val parent =
              if stack == Stack.Policy then cgroup.map(attach => s"--cgroup-parent=${attach.parent}").toSeq
              else Seq.empty
            val network = if command.network then Seq.empty else Seq("--network=none")
            host(
              transcript,
              Seq("podman", "run", "--rm", "-i", "--entrypoint=", s"--label=$Label=1",
                "--userns=keep-id:uid=65532,gid=65532", "--user=65532:65532",
                s"--volume=${workspace.tree}:${workspace.treeVm}:rw", s"--workdir=${workspace.treeVm}") ++ network ++
                parent ++ filesEnv ++ Seq(SandboxImage) ++ command.argv,
            )

    /** A hook file is refused under the policy and through the filter, and made over the bare bind. */
    def stacksAreWhatTheyClaim(runOn: Runner): Unit =
      step("the three stacks over one tree: each is what it claims")
      val hookWrite = Command(Seq(
        "sh", "-c", s"echo x > .git/hooks/$Label && rm .git/hooks/$Label && echo WROTE || echo REFUSED",
      ))
      options.stacks.foreach: stack =>
        val answer = runOn(stack, hookWrite).text
        val (expected, other) = if stack == Stack.Bind then ("WROTE", "REFUSED") else ("REFUSED", "WROTE")
        check(
          s"a hook file in .git/hooks on the ${stack.name} stack: $expected",
          answer.contains(expected) && !answer.contains(other),
        )

    /** One `entry-cost.py` round on the bind before any program is attached: the shim's control. */
    def baseline(workspace: Workspace): Seq[Run] =
      if !options.stacks.contains(Stack.Bind) || !options.workloads.contains(Workload.Perf) then Seq.empty
      else
        step("the bind before any program is attached")
        // What this establishes: no pin anywhere in bpffs, and no program of type `lsm`, the policy's type,
        // where bpftool can list programs (its listing names the program type, not the attach type); a link
        // held open by a live process elsewhere in the machine is not excluded.
        val pins = vm.line("sudo -n find /sys/fs/bpf -mindepth 1 2>/dev/null").linesIterator.toSeq
        info(s"pins in bpffs before the launch: ${if pins.isEmpty then "none" else pins.mkString(" ")}")
        // A launcher session of the backend pins its links, and its attach installed the shim already.
        val links = pins.count(pin => pin.contains("/links/") && !pin.startsWith(PinRoot))
        if links > 0 then
          info(
            s"$links links of live sessions are attached, so the shim is installed and this round is no control " +
              "for it; end every session of the bpf backend on this machine for one",
          )
        // A failed listing reads `unknown`, a machine without bpftool `unavailable`; grep's own status on a
        // count of zero does not decide, since the count is printed either way.
        val programs = vm.line(sh(
          s"if ! command -v bpftool >/dev/null 2>&1; then echo unavailable",
          s"elif sudo -n bpftool prog show > $VmDir/programs.txt 2>/dev/null; then " +
            s"grep -cE '^[0-9]+: lsm ' $VmDir/programs.txt",
          "else echo unknown; fi",
        ))
        info(s"LSM programs bpftool lists before the launch: $programs")
        Seq(runWorkload(containerOf(workspace, None), Workload.Perf, Stack.Bare, 1))

    /** The runs after the launch, in order: the `entry-cost.py` rounds with the stacks interleaved, the build
      * on the bind and under the policy, then `walk-cost.py` once a stack. */
    def plannedRuns: Seq[(Workload, Stack, Int)] =
      val perf =
        if !options.workloads.contains(Workload.Perf) then Seq.empty
        else for round <- 1 to options.rounds; stack <- options.stacks yield (Workload.Perf, stack, round)
      val build =
        if !options.workloads.contains(Workload.Build) then Seq.empty
        else options.stacks.filter(stack => stack == Stack.Bind || stack == Stack.Policy).map((Workload.Build, _, 1))
      val walk =
        if !options.workloads.contains(Workload.Walk) then Seq.empty
        else options.stacks.map((Workload.Walk, _, 1))
      perf ++ build ++ walk

    def commandOf(workload: Workload, stack: Stack): Command = workload match
      case Workload.Perf => Command(Seq("python3", "entry-cost.py"))
      case Workload.Walk => Command(Seq("python3", "walk-cost.py"))
      case Workload.Build =>
        // The image's global sbt settings send the output outside the mount; another global base keeps it in
        // the workspace, as the 604 s row of the verification log had it.
        val build = s"cd ${buildDir(stack)} && sbt -Dsbt.global.base=/tmp/sbt-global 'testOnly *SandboxTextWidthTest'"
        Command(Seq("sh", "-c", build), network = true)

    def runWorkload(runOn: Runner, workload: Workload, stack: Stack, round: Int): Run =
      val name = s"${workload.name}-${stack.name}-$round"
      val tree = scratchDir / "sbt"
      val clone = tree / buildDir(stack)
      if workload == Workload.Build then
        host(transcript, Seq("git", "clone", "--quiet", repoDir.toString, clone.toString))
      val sampling = Sampling(vm, name)
      val (output, counters, wall) = Using.resource(sampling): _ =>
        val reset = if stack == Stack.Policy then vm(s"sudo -n $Stats reset $Pins/links/file_open").text else ""
        val started = System.nanoTime()
        val output = runOn(stack, commandOf(workload, stack))
        val wall = (System.nanoTime() - started) / 1e9
        val read = if stack == Stack.Policy then vm(s"sudo -n $Stats read $Pins/links/file_open").text else ""
        (output, (reset, read), wall)
      if workload == Workload.Build then removeTree(platform, clone.getParent)
      val (reset, stats) = counters
      val samplesRead = vm(s"cat ${samplesFile(name)}")
      val samples = samplesRead.text
      Files.writeString(out / s"$name.txt", output.text)
      Files.writeString(out / s"samples-$name.txt", samples)
      if stats.nonEmpty then Files.writeString(out / s"stats-$name.txt", stats)
      val summary = summarizeSamples(samples)
      // The run's evidence beside its figures: the sampler ran and left two samples or more, and under
      // the policy the counters were zeroed before the run and read after it, one line per hook.
      val missing = Seq(
        Option.when(!sampling.ran)("the sampler did not run to its end"),
        Option.when(!samplesRead.ok || summary.isEmpty)("fewer than two samples"),
        Option.when(stack == Stack.Policy && field("ok", reset) != "1")("the counters were not zeroed"),
        Option.when(stack == Stack.Policy && stats.linesIterator.count(_.startsWith("stats hook=")) != 9)(
          "the counters were not read",
        ),
      ).flatten
      val figures = workload match
        case Workload.Perf => parsePerf(output.text)
        case Workload.Walk => parseWalk(output.text)
        case Workload.Build => Figure(s"`sbt testOnly`, wall", wall, "s") +: parseBuild(output.text)
      val complete = workload match
        case Workload.Perf => figures.length == 5
        case Workload.Walk =>
          figures.exists(_.row.startsWith("lstat of each")) && figures.exists(_.row == "`git status`")
        case Workload.Build => output.text.contains("[success]") && !output.text.contains("[error]")
      check(
        f"$name: ${workload.name} completed in $wall%.0f s with ${figures.length} rows" +
          (if missing.isEmpty then "" else missing.mkString(" (", "; ", ")")),
        output.ok && complete && missing.isEmpty,
      )
      if !output.ok then transcript.indent(output.text.linesIterator.toSeq.takeRight(5).mkString("\n"))
      output.text.linesIterator.filter(_.startsWith("tracked ")).foreach(line => info(s"$name: $line"))
      output.text.linesIterator.filter(_.startsWith("stack under test")).foreach(line => info(s"$name: $line"))
      figures.foreach(figure => info(f"$name: ${figure.row} ${figure.value}%.2f ${figure.unit}"))
      val judged =
        stats.linesIterator.filter(line => line.startsWith("stats hook=") && field("calls", line) != "0").toSeq
      judged.foreach(line => info(s"$name: $line"))
      info(s"$name: machine ${summary.fold("no samples")(_.text)}")
      Run(workload, stack, round, wall, figures, summary, judged)

    def tables(facts: VmFacts, workspace: Workspace, runs: Seq[Run], expectedRuns: Int): Unit =
      step("the tables")
      val results = StringBuilder()
      def emit(text: String): Unit =
        results.append(text).append("\n")
        text.linesIterator.foreach(info)
      emit(
        s"Benchmark on ${platform.label}: kernel ${facts.kernel}, ${facts.podmanVersion}, " +
          s"${facts.runtime}, share ${facts.fsType}, machine ${facts.cpus} cpus " +
          s"${facts.memory} MiB; tree " +
          s"${workspace.head}, ${workspace.tracked} tracked files; entry-cost.py FILES=${options.files}, " +
          s"${options.rounds} rounds",
      )
      emit("")
      def ratio(values: Seq[Double], base: Seq[Double]): String =
        if values.isEmpty || base.isEmpty || mean(base) == 0 then "—" else f"${mean(values) / mean(base)}%.2f×"
      options.workloads.foreach: workload =>
        val ofWorkload = runs.filter(_.workload == workload)
        val rows = ofWorkload.flatMap(_.figures.map(figure => (figure.row, figure.unit))).distinct
        def values(row: String, stack: Stack): Seq[Double] =
          ofWorkload.filter(_.stack == stack).flatMap(_.figures.filter(_.row == row).map(_.value))
        val stacks = Stack.values.toSeq.filter(stack => ofWorkload.exists(_.stack == stack))
        val ratios = Seq((Stack.Bind, Stack.Bare), (Stack.Policy, Stack.Bind), (Stack.Filter, Stack.Bind))
          .filter((over, base) => stacks.contains(over) && stacks.contains(base))
        val header = Seq(s"${workload.name}, row", "unit") ++ stacks.map(_.name) ++
          ratios.map((over, base) => s"${over.name} / ${base.name}")
        val lines = rows.map: (row, unit) =>
          Seq(row, unit) ++ stacks.map(stack => cell(values(row, stack), unit)) ++
            ratios.map((over, base) => ratio(values(row, over), values(row, base)))
        emit(table(header, lines))
        emit("")
      emit(table(
        Seq("run", "wall s", "samples", "CPU busy mean %", "CPU busy max %", "iowait max %", "memory used MiB",
          "pressure max cpu/mem/io"),
        runs.map: run =>
          val none = Seq("—", "—", "—", "—", "—", "—")
          Seq(run.name, f"${run.wallSeconds}%.0f") ++ run.samples.fold(none): summary =>
            Seq(summary.samples.toString, f"${summary.busyMeanPct}%.0f", f"${summary.busyMaxPct}%.0f",
              f"${summary.iowaitMaxPct}%.0f", s"${summary.usedMinMiB} to ${summary.usedMaxMiB}",
              summary.psiMax.map(value => f"$value%.2f").mkString("/")),
      ))
      emit("")
      val statsRows = runs.flatMap: run =>
        run.stats.map: line =>
          Seq(run.name, field("hook", line), field("calls", line), field("outside", line), field("denied", line),
            field("walks", line), field("retries", line), field("max_depth", line), field("ns_mean", line),
            field("ns_max", line))
      if statsRows.nonEmpty then
        emit(table(
          Seq("run under the policy", "hook", "calls", "outside", "denied", "walks", "retries", "max depth", "ns mean",
            "ns max"),
          statsRows,
        ))
      Files.writeString(out / "results.txt", results.toString)
      check(
        s"every run completed and its figures are recorded: ${runs.length} runs, results in ${out / "results.txt"}",
        runs.length == expectedRuns && transcript.failed == 0,
      )
