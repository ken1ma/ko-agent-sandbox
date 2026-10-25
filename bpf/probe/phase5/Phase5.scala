#!/usr/bin/env -S scala shebang
//> using scala 3.10.0

// Phase 5 of doc/plan-bpf-lsm-cgroup.md ("Phases", 5) on the podman machine of either host, in one
// run. Run it on the HOST, from the repository root, with the default machine running and the
// sandbox image built by the launcher's --build:
//
//     bpf/probe/phase5/Phase5.scala [--out DIR] [--launcher JAR] [--tree PATH|URL] [--rounds N] [--files N]
//                                   [--stacks LIST] [--workloads LIST] [--platform mac|windows]
//
// The first line hands the file to the `scala` runner's `shebang` sub-command, which takes everything
// after the file as the program's arguments; on Windows, where no shebang runs, the same is
// `scala shebang bpf\probe\phase5\Phase5.scala [options]`.
//
// It builds the probe image (Containerfile) from a context assembled out of the files sources.txt
// lists, extracts /out into the machine under ~/.local/share/ko-agent-sandbox/bpf-probe5, clones the
// tree of fuse/ko-agent-fs/doc/verification-log.md's real-tree rows (sbt/sbt, shallow) into a scratch
// workspace on the share, launches the policy over it as Phase 4's driver does, steps 1 to 3 of
// "Lifecycle", and runs the two probes of fuse/ko-agent-fs/probe/ over that one tree in three stacks:
//
//   bind     the sandbox image over a writable bind of the workspace, unfiltered.sh's command
//   policy   the same command below the attach cgroup, so the eight hooks judge it
//   filter   the launcher's session, the workspace through the filter
//
// and, before the launch, one round of perf-probe.py on the bind with no program attached to any hook,
// the `bare` column, so that the shim the first attach installs on each hook for every task in the VM
// ("The mechanism") has its cost measured against the bind beside the policy.
//
// perf-probe.py runs --rounds times per stack (default 3), the stacks interleaved within a round; the
// build, `sbt 'testOnly *SandboxTextWidthTest'` on a clone of this repository made inside the tree with
// its output there, as verification-log.md's "an sbt build, by where its output goes" ran it, once on
// the bind and once under the policy, with network for its downloads and no filter run, whose 604 s
// that log holds; and walk-probe.py once per stack. During each run a sampler in the machine records /proc/stat,
// /proc/meminfo and the pressure files each second, and after each run under the policy the
// program's counters are read and zeroed. Every line is printed and appended to OUTDIR/transcript.log
// (default: out-macos/ or out-wsl/ beside this script, ignored by git), the raw outputs land beside
// it, and results.txt holds the tables. Send OUTDIR back; the transcript and the tables are what
// "Phase 5 on macOS" and "Phase 5 on WSL" are filled from.
//
// --stacks and --workloads take comma-separated subsets (bind,policy,filter and perf,build,walk) for a
// partial rerun; --tree names a repository to clone instead of GitHub's, such as an earlier clone;
// --platform drives as that platform where the detection must be overridden, as in a dry run against
// fake commands.
// At the figures of verification-log.md, "The cost of a path walk", perf-probe.py's five rows through
// the filter take about 54 s a round on the macOS machine and about 8 minutes on the WSL one, and
// walk-probe.py's `git status` 72 s on macOS; the other stacks are faster by the ratios there.
//
// The platforms differ in data alone: the cgroup manager podman reports (a transient slice under
// systemd, a directory under the user's delegated subtree under cgroupfs), the path the machine serves
// a host directory at (the same path on macOS, /mnt/<drive>/... on Windows) and the output
// directory's name. On Windows, %UserProfile%\.wslconfig must hold `[wsl2]` and
// `isolateDistroCgroup=false` ("VmFacts evidence"), or the containers land in no cgroup of their
// own. Every command in the machine is one line without double quotes, the form Phase 4's Windows
// driver settled on after double quotes inside an argument did not reach the machine.
//
// It writes the scratch workspace and the proof fixture under the repository's tmp/, which git ignores
// and the machine mounts, one attach cgroup ko-agent-bpf5-policy with its transient unit, a podman volume, pins under
// /sys/fs/bpf/ko-agent-bpf-phase5 in the machine, and containers labelled ko-agent-bpf5; all are
// removed on exit.

import scala.util.Properties
import scala.util.Using
import scala.util.matching.Regex

import java.lang.ProcessBuilder.Redirect
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path, StandardCopyOption, StandardOpenOption}
import java.security.MessageDigest
import java.util.Base64
import java.util.Comparator
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

@main def probe(args: String*): Unit = Phase5.run(args)

object Phase5:

  extension (path: Path)
    def /(child: String): Path = path.resolve(child)
    def /(child: Path): Path = path.resolve(child)

  def workingDir: Path = Path.of("").toAbsolutePath

  /** The hosts whose podman machine the phase measures, each with the name the output calls it by, which
    * names its output directory too. A native Linux host has no machine and keeps the filter until a later
    * version of the backend runs on its own kernel ("Later versions", "Native Linux"); it joins here when
    * that version's phase measures it, with the controller run under the host's `sudo -n` in place of the
    * machine's. */
  enum Platform(val label: String):
    case Mac     extends Platform("macOS")
    case Windows extends Platform("WSL")
    def outDir: String = s"out-${label.toLowerCase}"

  object Platform:
    def detect: Either[String, Platform] =
      if Properties.isWin then Right(Windows)
      else if Properties.isMac then Right(Mac)
      else
        Left(
          s"this probe measures the podman machines of macOS and Windows; a ${Properties.osName} host keeps the " +
            "filter until \"Later versions\" of doc/plan-bpf-lsm-cgroup.md admits it (\"Native Linux\")",
        )

  /** The path the machine serves a host path at (SandboxWorkspace.mountPathOf). */
  def vmPath(platform: Platform, path: String): String = platform match
    case Platform.Mac => path
    case Platform.Windows => s"/mnt/${path.head.toLower}/${path.drop(3).replace('\\', '/')}"

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
    * reuses: the machine keeps a removed entry's dentry for seconds (libkrun's `entry_timeout`, "Phase 1 on
    * macOS"), so a clone made again at the same name reads as absent in the next container. */
  def buildDir(stack: Stack): String = s".ko-build-${stack.name}/ko-agent-sandbox"

  case class ProbeOptions(
      out: Option[Path] = None,
      launcher: Option[Path] = None,
      tree: String = "https://github.com/sbt/sbt.git",
      rounds: Int = 3,
      files: Int = 1800,
      stacks: Seq[Stack] = Stack.selectable,
      workloads: Seq[Workload] = Workload.values.toSeq,
      platform: Option[Platform] = None,
  )

  def parseOptions(args: Seq[String]): Either[String, ProbeOptions] =
    def names[A](text: String, all: Seq[A], nameOf: A => String): Either[String, Seq[A]] =
      val wanted = text.split(',').toSeq.map(_.trim).filter(_.nonEmpty)
      val unknown = wanted.filterNot(name => all.exists(item => nameOf(item) == name))
      if unknown.nonEmpty then Left(s"unknown: ${unknown.mkString(", ")}")
      else Right(all.filter(item => wanted.contains(nameOf(item))))
    def loop(rest: Seq[String], options: ProbeOptions): Either[String, ProbeOptions] = rest match
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
      case Seq("--platform", "mac", tail*) => loop(tail, options.copy(platform = Some(Platform.Mac)))
      case Seq("--platform", "windows", tail*) => loop(tail, options.copy(platform = Some(Platform.Windows)))
      case Seq(other, _*) => Left(s"unknown option $other; see the header of Phase5.scala")
    loop(args, ProbeOptions())

  // --- The pure parts: what the transcript's figures are read with -----------------------------------------

  /** The value of KEY in the first line holding `KEY=`, as the binaries print `key=value`. */
  def field(key: String, text: String): String =
    raw"(?m)(?:^|(?<=\s))${Regex.quote(key)}=(\S*)".r.findFirstMatchIn(text).map(_.group(1)).getOrElse("")

  /** The rule file's lines without comments: `kind path`, as the Phase 3 probe reads them. */
  def stripRules(text: String): Seq[String] =
    text.linesIterator
      .map(_.replaceAll("#.*", "").trim.split("\\s+").toSeq)
      .collect:
        case Seq(kind, path) => s"$kind $path"
      .toSeq

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

  def sha256(contents: Seq[Array[Byte]]): String =
    val digest = MessageDigest.getInstance("SHA-256")
    contents.foreach(digest.update)
    digest.digest().map(byte => f"$byte%02x").mkString

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

  class Transcript(val path: Path):
    var passed = 0
    var failed = 0
    Files.writeString(path, "")
    def record(text: String): Unit =
      Files.writeString(path, text.stripLineEnd + "\n", StandardOpenOption.CREATE, StandardOpenOption.APPEND)
    def log(text: String): Unit =
      println(text)
      record(text)
    def info(text: String): Unit = log("INFO " + text)
    def pass(text: String): Unit =
      passed += 1
      log("PASS " + text)
    def fail(text: String): Unit =
      failed += 1
      log("FAIL " + text)
    def check(description: String, ok: Boolean): Boolean =
      if ok then pass(description) else fail(description)
      ok
    def step(text: String): Unit =
      log("")
      log("== " + text)
    def indent(text: String): Unit = text.linesIterator.filter(_.nonEmpty).foreach(line => log("  " + line))

  /** What a command printed, both streams merged, and its exit status. */
  case class Output(status: Int, text: String):
    def ok: Boolean = status == 0

  /** A command on the host, its output recorded; a merged stream, a closed stdin unless inherited. */
  def host(transcript: Transcript, command: Seq[String], cwd: Path = workingDir, inheritStdin: Boolean = false)
      : Output =
    val builder = ProcessBuilder(command*).directory(cwd.toFile).redirectErrorStream(true)
    if inheritStdin then builder.redirectInput(Redirect.INHERIT)
    val process = builder.start()
    if !inheritStdin then process.getOutputStream.close()
    val text = String(process.getInputStream.readAllBytes(), UTF_8)
    val status = process.waitFor()
    transcript.record(text)
    Output(status, text)

  /** One shell command of several statements, for `Vm`. */
  def sh(statements: String*): String = statements.mkString("; ")

  /** A path as one word of a machine command, whatever it holds; the checkout's path is the user's. */
  def quoted(path: String): String = "'" + path.replace("'", "'\\''") + "'"

  /** A command in the podman machine, as the machine's user, over `podman machine ssh`. */
  class Vm(transcript: Transcript):
    def apply(command: String): Output = host(transcript, Seq("podman", "machine", "ssh", command))
    def line(command: String): String = apply(command).text.trim

  val VmDir = ".local/share/ko-agent-sandbox/bpf-probe5"
  val Controller = s"./$VmDir/controller"
  val Readback = s"./$VmDir/readback"
  val Fixture = s"./$VmDir/fixture"
  val Stats = s"./$VmDir/stats"
  val Tags = s"./$VmDir/tags.txt"
  val PinRoot = "/sys/fs/bpf/ko-agent-bpf-phase5"
  val AppSliceGlob = "/sys/fs/cgroup/user.slice/user-*.slice/user@*.service/app.slice"
  val Session = "policy"
  val Pins = s"$PinRoot/$Session"
  val ProbeImage = "ko-agent-bpf-probe:phase5"
  val SandboxImage = "ko-agent-sandbox:latest"
  val Volume = "ko-agent-bpf5-vol"
  val Label = "ko-agent-bpf5"
  val Hooks8 = Seq("file_open", "inode_create", "inode_mknod", "inode_symlink", "inode_link", "inode_rename",
    "inode_unlink", "inode_setattr")
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

  /** What the run leaves on the host and in the machine, held in a `Using` block and by the shutdown hook:
    * closed once, it removes the containers, the pins, the attach cgroup, the volume and the scratch
    * directory, and prints the tally. */
  class Cleanup(platform: Platform, scratchDir: Path, transcript: Transcript, vm: Vm) extends AutoCloseable:
    private val closed = AtomicBoolean(false)
    def close(): Unit = if closed.compareAndSet(false, true) then
      transcript.step("cleanup")
      val containers = host(transcript, Seq("podman", "ps", "-aq", "--filter", s"label=$Label")).text.trim
      if containers.nonEmpty then host(transcript, Seq("podman", "rm", "-f") ++ containers.linesIterator.toSeq)
      vm(sh(
        s"[ -x $Controller ] && sudo -n $Controller unpin $Pins >/dev/null 2>&1",
        s"sudo -n rmdir $PinRoot 2>/dev/null",
        s"systemctl --user stop ko-agent-bpf5-hold-$Session ko-agent-bpf5-$Session.slice 2>/dev/null",
        "systemctl --user reset-failed 2>/dev/null",
        s"rmdir $AppSliceGlob/ko-agent-bpf5-$Session/proof $AppSliceGlob/ko-agent-bpf5-$Session 2>/dev/null",
        s"rm -f $VmDir/sample.sh $VmDir/samples-* $VmDir/programs.txt",
        "true",
      ))
      host(transcript, Seq("podman", "volume", "rm", "-f", Volume))
      removeTree(platform, scratchDir)
      transcript.log("")
      transcript.log(s"passed=${transcript.passed} failed=${transcript.failed} transcript=${transcript.path}")

  case class VmFacts(
      uid: String,
      kernel: String,
      manager: String,
      runtime: String,
      podmanVersion: String,
      fsType: String,
      cpus: String,
      memory: String,
  ):
    def appSlice: String = s"/user.slice/user-$uid.slice/user@$uid.service/app.slice"

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

  case class Cgroup(path: String, parent: String)

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
    val options = parseOptions(args) match
      case Right(options) => options
      case Left(message) =>
        System.err.println(message)
        sys.exit(2)
    val platform = options.platform.toRight(()).left.flatMap(_ => Platform.detect) match
      case Right(platform) => platform
      case Left(message) =>
        System.err.println(message)
        sys.exit(2)
    val repoDir = workingDir
    val probeDir = repoDir / "bpf" / "probe" / "phase5"
    val probes = repoDir / "fuse" / "ko-agent-fs" / "probe"
    if !Files.exists(probeDir / "sources.txt") || !Files.exists(probes / "perf-probe.py") then
      System.err.println(s"$repoDir is not the repository root; run this from it")
      sys.exit(2)
    val out = options.out.getOrElse(probeDir / platform.outDir)
    Files.createDirectories(out)
    val transcript = Transcript(out / "transcript.log")
    val vm = Vm(transcript)
    // Under the repository's ignored tmp/, on the share the machine mounts; not under ~/.cache, where Phase 4
    // kept its fixtures, since the launcher refuses a workspace below a dot-prefixed directory.
    val scratchDir = repoDir / "tmp" / s"ko-agent-bpf-phase5.${ProcessHandle.current().pid()}"
    val cleanup = Cleanup(platform, scratchDir, transcript, vm)
    Runtime.getRuntime.addShutdownHook(Thread(() => cleanup.close()))
    val status = Using.resource(cleanup): _ =>
      try Measurement(options, platform, probeDir, repoDir, out, transcript, vm, scratchDir).measure()
      catch
        case ex: Exception =>
          transcript.fail(s"the driver failed: ${ex.getMessage}")
          2
    sys.exit(status)

  def removeTree(platform: Platform, path: Path): Unit =
    if Files.exists(path) then
      platform match
        // Git's pack files are read-only, which Java's delete refuses on Windows and rmdir does not.
        case Platform.Windows =>
          val process = ProcessBuilder("cmd", "/c", "rmdir", "/s", "/q", path.toString)
            .redirectOutput(Redirect.DISCARD).redirectErrorStream(true).start()
          process.getOutputStream.close()
          process.waitFor()
        case Platform.Mac =>
          Using.resource(Files.walk(path))(_.sorted(Comparator.reverseOrder()).forEach(Files.delete(_)))

  /** The phase as steps, each `Right` with what the next needs or `Left` with the exit status after it
    * said why: 2 for a refusal before any figure is taken, 1 for a gate the transcript records as FAIL. */
  class Measurement(
      options: ProbeOptions,
      platform: Platform,
      probeDir: Path,
      repoDir: Path,
      out: Path,
      transcript: Transcript,
      vm: Vm,
      scratchDir: Path,
  ):
    import transcript.{check, info, log, step}
    private val scratchDirVm = vmPath(platform, scratchDir.toString)
    private val launcher = options.launcher.getOrElse(repoDir / "target" / "dist" / "ko-agent-sandbox.jar")

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

    /** A refusal before any figure is taken: the message, then exit status 2. */
    private def refuse(ok: Boolean, message: String): Either[Int, Unit] =
      if ok then Right(())
      else
        log(message)
        Left(2)

    /** A gate the transcript records: FAIL ends the phase with exit status 1. */
    private def gate(description: String, ok: Boolean): Either[Int, Unit] = Either.cond(check(description, ok), (), 1)

    def readVmFacts(): Either[Int, VmFacts] =
      step("environment")
      for
        _ <- refuse(host(transcript, Seq("podman", "machine", "inspect", "--format", "{{.State}}")).ok,
          "no default podman machine")
        _ <- refuse(vm("sudo -n true").ok, "sudo -n fails in the machine")
        _ <- refuse(host(transcript, Seq("podman", "image", "exists", SandboxImage)).ok,
          s"no $SandboxImage image; run the launcher's --build first")
        _ <- refuse(!options.stacks.contains(Stack.Filter) || Files.exists(launcher),
          s"no launcher at $launcher; pass --launcher JAR or build it with sbt dist")
      yield
        val uid = vm.line("id -u")
        val kernel = vm.line("uname -r")
        val manager = vm.line("podman info --format '{{.Host.CgroupManager}}'")
        val runtime = vm.line("podman info --format '{{.Host.OCIRuntime.Name}} {{.Host.OCIRuntime.Version}}'")
          .linesIterator.next()
        val podmanVersion = host(transcript, Seq("podman", "--version")).text.trim
        info(s"machine user uid=$uid kernel=$kernel podman=$podmanVersion cgroup manager=$manager runtime=$runtime")
        // The pseudo filesystems the controller and the read-back need, mounted where the machine does not.
        vm(sh(
          "sudo -n sh -c 'findmnt -n /sys/kernel/security >/dev/null || " +
            "mount -t securityfs securityfs /sys/kernel/security'",
          "sudo -n sh -c 'findmnt -n /sys/fs/bpf >/dev/null || mount -t bpf bpf /sys/fs/bpf'",
        ))
        info(s"lsm=${vm.line("sudo -n cat /sys/kernel/security/lsm")}")
        Files.createDirectories(scratchDir)
        val findmnt = vm(s"findmnt -T ${quoted(scratchDirVm)} -o TARGET,SOURCE,FSTYPE,OPTIONS").text
        Files.writeString(out / "findmnt.txt", findmnt)
        val fsType = vm.line(s"findmnt -T ${quoted(scratchDirVm)} -n -o FSTYPE")
        info(s"share: ${findmnt.linesIterator.drop(1).nextOption().getOrElse("?")}, type $fsType")
        vm(s"sudo -n mkdir -p $PinRoot")
        val cpus = vm.line("nproc")
        val memory = vm.line("awk '/^MemTotal:/ { print int($2 / 1024) }' /proc/meminfo")
        info(s"machine cpus=$cpus memory=$memory MiB")
        VmFacts(uid, kernel, manager, runtime, podmanVersion, fsType, cpus, memory)

    def buildAndInstall(facts: VmFacts): Either[Int, Unit] =
      step("build, with the hash of its sources, and install")
      // The context holds the files sources.txt lists, the policy program of Phase 3, the guard's records
      // header and Phase 4's binaries among them; their hash in that order is what the plan's section
      // names and check-evidence.sh recomputes.
      val sources =
        Files.readString(probeDir / "sources.txt").linesIterator.filter(_.nonEmpty).map(Path.of(_)).toSeq
      val context = scratchDir / "build-context"
      Files.createDirectories(context)
      sources.foreach: source =>
        Files.copy(probeDir / source, context / source.getFileName.toString, StandardCopyOption.REPLACE_EXISTING)
      val sourcesSha = sha256(sources.map(source => Files.readAllBytes(probeDir / source)))
      info(s"sources sha256=$sourcesSha over ${sources.mkString(" ")}")
      // The procedure's digest, the driver, the rule defaults and the two probes, says which measurement
      // ran; it binds nothing, since the plan's sections name the compiled sources' hash alone.
      val procedureFiles = Seq(
        probeDir / "Phase5.scala",
        repoDir / "src" / "main" / "resources" / "agentsandbox" / "file-rule-defaults",
        repoDir / "fuse" / "ko-agent-fs" / "probe" / "perf-probe.py",
        repoDir / "fuse" / "ko-agent-fs" / "probe" / "walk-probe.py",
      )
      val procedureSha = sha256(procedureFiles.map(Files.readAllBytes))
      info(s"procedure sha256=$procedureSha over Phase5.scala file-rule-defaults perf-probe.py walk-probe.py")
      val build = host(
        transcript,
        Seq("podman", "build", "--build-arg", s"BUILD_KERNEL=${facts.kernel}", "-t", ProbeImage, "-f",
          (context / "Containerfile").toString, context.toString),
      )
      for _ <- refuse(build.ok, s"the probe image failed to build; the build log is in ${transcript.path}")
      yield
        val installed = vm(sh(
          "set -eu",
          s"mkdir -p $VmDir",
          s"podman create --replace --name ko-agent-bpf5-extract $ProbeImage >/dev/null",
          s"podman cp ko-agent-bpf5-extract:/out/. $VmDir/",
          "podman rm ko-agent-bpf5-extract >/dev/null",
          s"test -x $Controller && test -x $Readback && test -x $Fixture && test -x $Stats",
        ))
        check("probe installed in the machine", installed.ok)
        vm(sh(s"sudo -n $Controller unpin $Pins >/dev/null 2>&1", "true"))
        val buildText = s"sources sha256=$sourcesSha\nprocedure sha256=$procedureSha\n" +
          vm(s"cat $VmDir/clang-version.txt $VmDir/build-kernel.txt $VmDir/objects.sha256").text
        Files.writeString(out / "build.txt", buildText)
        info(buildText.linesIterator.mkString(" "))
        val sampler = Base64.getEncoder.encodeToString(SamplerScript.getBytes(UTF_8))
        vm(s"echo $sampler | base64 -d > $VmDir/sample.sh")
        // The installation records the object's tags once, under the running kernel ("Lifecycle", 3).
        val tags = vm(s"sudo -n $Readback tags policy.bpf.o $Tags").text
        tags.linesIterator.filter(_.startsWith("tags ")).foreach(info)
        check("the installed object's nine tags are recorded", field("programs", tags) == "9")

    def prepareWorkspace(): Either[Int, Workspace] =
      step("the workspace: the tree of the real-tree rows, the probes, the rules, the proof fixture")
      val tree = scratchDir / "sbt"
      val treeVm = s"$scratchDirVm/sbt"
      val clone = host(transcript, Seq("git", "clone", "--depth", "1", options.tree, tree.toString))
      for _ <- refuse(clone.ok, s"the clone of ${options.tree} failed; pass --tree with a repository that clones")
      yield
        val head = host(transcript, Seq("git", "rev-parse", "HEAD"), cwd = tree).text.trim
        val tracked = host(transcript, Seq("git", "ls-files"), cwd = tree).text.linesIterator.length
        info(s"the tree: ${options.tree} at $head, $tracked tracked files, at $tree ($treeVm in the machine)")
        // The guarded directory the policy records as a root, read by statx, the hooks directory the stack
        // check writes into, which a clone has only when git installed its samples, and the two probes at
        // the root, where perf-probe.py builds its corpus and walk-probe.py reads the tracked files.
        Files.createDirectories(tree / ".ko-agent-sandbox")
        Files.createDirectories(tree / ".git" / "hooks")
        Seq("perf-probe.py", "walk-probe.py").foreach(probe =>
          Files.copy(repoDir / "fuse" / "ko-agent-fs" / "probe" / probe, tree / probe,
            StandardCopyOption.REPLACE_EXISTING),
        )
        // The rules: the launcher's defaults, exactly what a session's policy holds.
        val defaults = repoDir / "src" / "main" / "resources" / "agentsandbox" / "file-rule-defaults"
        Files.writeString(scratchDir / "rules.txt", stripRules(Files.readString(defaults)).mkString("", "\n", "\n"))
        val rulesVm = s"$scratchDirVm/rules.txt"
        val recordsVm = s"$scratchDirVm/records.bin"
        val proofVm = s"$scratchDirVm/state/proof"
        val guarded = "--guarded workspace= --guarded guarded-git=.git --guarded guarded-sandbox=.ko-agent-sandbox"
        val made = vm(
          s"mkdir -p ${quoted(s"$scratchDirVm/state")} && $Fixture make ${quoted(proofVm)} ${quoted(rulesVm)} && " +
            s"$Fixture records ${quoted(rulesVm)} ${quoted(recordsVm)} $guarded",
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

    /** Step 1 of "Lifecycle": a transient slice held by a unit under systemd, a directory under the user's
      * delegated subtree under cgroupfs. */
    private def attachCgroup(facts: VmFacts): Cgroup =
      if facts.manager == "systemd" then
        vm(sh(
          s"systemctl --user stop ko-agent-bpf5-hold-$Session 2>/dev/null",
          "systemctl --user reset-failed 2>/dev/null",
          s"systemd-run --user --unit=ko-agent-bpf5-hold-$Session --slice=ko-agent-bpf5-$Session.slice " +
            "/usr/bin/sleep infinity",
        ))
        val path =
          vm.line(s"find /sys/fs/cgroup/user.slice -type d -name ko-agent-bpf5-$Session.slice 2>/dev/null | head -1")
        Cgroup(path, s"ko-agent-bpf5-$Session.slice")
      else
        val parent = s"${facts.appSlice}/ko-agent-bpf5-$Session"
        vm(s"mkdir -p /sys/fs/cgroup$parent")
        Cgroup(s"/sys/fs/cgroup$parent", parent)

    /** Step 3's proof, by a process of the launcher's own below the attach cgroup: a scope under the slice,
      * or a leaf directory joined from a transient scope of the user manager ("Phase 4 on WSL"). */
    private def runProof(facts: VmFacts, cgroup: Cgroup, workspace: Workspace): Output =
      val run = s"$Fixture run ${quoted(workspace.proofVm)} ${quoted(workspace.rulesVm)}"
      if facts.manager == "systemd" then vm(s"systemd-run --user --scope --slice=${cgroup.parent} -q $run")
      else
        vm(sh(
          s"mkdir -p ${cgroup.path}/proof && systemd-run --user --scope -q $Fixture join ${cgroup.path}/proof $run",
          s"rmdir ${cgroup.path}/proof",
        ))

    /** Steps 1 to 3 of "Lifecycle" over the scratch workspace; `None` when no stack needs the policy. */
    def launchPolicy(facts: VmFacts, workspace: Workspace): Either[Int, Option[Cgroup]] =
      step("the launch: the attach cgroup, the controller, the read-back, the proof")
      if !options.stacks.contains(Stack.Policy) then Right(None)
      else
        val cgroup = attachCgroup(facts)
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
          proof = runProof(facts, cgroup, workspace)
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
              Seq("java", "-jar", launcher.toString) ++ launcherFilesEnv ++ command.argv,
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
        "sh", "-c", "echo x > .git/hooks/ko-agent-bpf5 && rm .git/hooks/ko-agent-bpf5 && echo WROTE || echo REFUSED",
      ))
      options.stacks.foreach: stack =>
        val answer = runOn(stack, hookWrite).text
        val (expected, other) = if stack == Stack.Bind then ("WROTE", "REFUSED") else ("REFUSED", "WROTE")
        check(
          s"a hook file in .git/hooks on the ${stack.name} stack: $expected",
          answer.contains(expected) && !answer.contains(other),
        )

    /** One `perf-probe.py` round on the bind before any program is attached: the shim's control. */
    def baseline(workspace: Workspace): Seq[Run] =
      if !options.stacks.contains(Stack.Bind) || !options.workloads.contains(Workload.Perf) then Seq.empty
      else
        step("the bind before any program is attached")
        // What this establishes: no pin anywhere in bpffs, and no program of type `lsm`, the policy's type,
        // where bpftool can list programs (its listing names the program type, not the attach type); a link
        // held open by a live process elsewhere in the machine is not excluded.
        val pins = vm.line("sudo -n find /sys/fs/bpf -mindepth 1 2>/dev/null").linesIterator.mkString(" ")
        info(s"pins in bpffs before the launch: ${if pins.isEmpty then "none" else pins}")
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

    /** The runs after the launch, in order: the `perf-probe.py` rounds with the stacks interleaved, the build
      * on the bind and under the policy, then `walk-probe.py` once a stack. */
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
      case Workload.Perf => Command(Seq("python3", "perf-probe.py"))
      case Workload.Walk => Command(Seq("python3", "walk-probe.py"))
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
        s"Phase 5 on ${platform.label}: kernel ${facts.kernel}, ${facts.podmanVersion}, " +
          s"${facts.runtime}, share ${facts.fsType}, machine ${facts.cpus} cpus " +
          s"${facts.memory} MiB; tree " +
          s"${workspace.head}, ${workspace.tracked} tracked files; perf-probe.py FILES=${options.files}, " +
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
