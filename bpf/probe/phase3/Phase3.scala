#!/usr/bin/env -S scala shebang
//> using scala 3.10.0
//> using file ../ProbeHelper.scala

// Phase 3 of doc/plan-bpf-lsm-cgroup.md ("Phases", 3) on the podman machine of either host, in one
// run. Run it on the HOST, from the repository root, with the default machine running:
//
//     bpf/probe/phase3/Phase3.scala [--out DIR] [--platform mac|windows]
//
// The first line hands the file to the `scala` runner's `shebang` sub-command, which takes everything
// after the file as the program's arguments; on Windows, where no shebang runs, the same is
// `scala shebang bpf\probe\phase3\Phase3.scala [options]`. The `using file` line pulls in ../ProbeHelper.scala,
// what every driver shares; this file holds the phase's own rows and readers.
//
// It builds the probe image (Containerfile) from a context assembled out of the files sources.txt
// lists, the policy program of bpf/ko-agent-bpf/ among them, extracts /out into the machine under
// ~/.local/share/ko-agent-sandbox/bpf-probe3, and runs the phase's rows through `podman machine ssh`
// and the machine's sudo, each printed as PASS, FAIL or INFO. Every line is printed and appended to
// OUTDIR/transcript.log (default: out-macos/ or out-wsl/ beside this script, ignored by git), and the
// files the rows produce land beside it. Send OUTDIR back; the transcript is what "Phase 3 on macOS"
// and "Phase 3 on WSL" are filled from.
//
// The rows, in order: the environment and the kernel's preemption mode; the verifier's answer to
// the policy program's nine hooks, with the full log of the two largest; the corpus (exercise.c)
// on a fixture laid out as a workspace, with the defaults' rules, a freed file, a relocated hook
// directory and a symlinked `.claude` (the alias), and on a workspace whose `.git` is a pointer
// file with host-made hard links; ordinary git in a clone of this repository; the torn-name race;
// the concurrency storm; the socket rules by default; a second host share; host git in a
// session-made `.git` without HEAD; the walk's cost in pairs beside a bare container, and the jited
// barrier; the NTFS short-name form under its flag, and on Windows the short name NTFS serves;
// under `--unix-sockets`, the socket corpus and descriptors passed between four sandboxes, a live
// session, a second session of the workspace under a later rule file, a session of another
// workspace and a read-only session; and the namespaces and mounts a generated seccomp profile
// refuses.
//
// The platforms differ in data alone: the cgroup manager podman reports (a transient slice under
// systemd, a directory under the user's delegated subtree under cgroupfs), the path the machine serves
// a host directory at (the same path on macOS, /mnt/<drive>/... on Windows), where a second share of
// the share's type is found (/private/tmp on macOS, the D: drive on Windows), the short name NTFS
// serves, and the output directory's name. Every command in the machine is one line without double
// quotes, the form Phase 4's Windows driver settled on after double quotes inside an argument did not
// reach the machine. --platform drives as that platform where the detection must be overridden, as in
// a dry run against fake commands.
//
// It writes the fixture under the repository's tmp/, which git ignores and the machine mounts, a
// directory on the second share, four attach cgroups ko-agent-bpf3-* with their transient units, two
// podman volumes, the second standing for `~`, pins under /sys/fs/bpf/ko-agent-bpf-phase3 in the
// machine, and containers labelled ko-agent-bpf3; all are removed on exit.

import scala.util.matching.Regex

import java.nio.file.{Files, Path}
import java.util.Base64

import ProbeHelper.*

@main def probe(args: String*): Unit = Phase3.run(args)

object Phase3:

  /** Where a second host share of the share's type is found, when the host has one: another mount of
    * the macOS machine, the D: drive on Windows. */
  def secondShareRoot(platform: Platform): Option[Path] =
    val root = platform match
      case Platform.Mac => Path.of("/private/tmp")
      case Platform.Windows => Path.of("D:\\")
    Option.when(Files.isDirectory(root))(root)

  case class ProbeOptions(
      out: Option[Path] = None,
      platform: Option[Platform] = None,
  )

  def parseOptions(args: Seq[String]): Either[String, ProbeOptions] =
    def loop(rest: Seq[String], options: ProbeOptions): Either[String, ProbeOptions] = rest match
      case Seq() => Right(options)
      case Seq("--out", value, tail*) => loop(tail, options.copy(out = Some(Path.of(value).toAbsolutePath)))
      case Seq("--platform", value, tail*) =>
        Platform.named(value).flatMap(platform => loop(tail, options.copy(platform = Some(platform))))
      case Seq(other, _*) => Left(s"unknown option $other; see the header of Phase3.scala")
    loop(args, ProbeOptions())

  // --- The pure parts: what the transcript's figures are read with -----------------------------------------

  /** KEY's value in every line holding it, as the controller prints one `stats` line per CPU. */
  def numbers(key: String, text: String): Seq[Long] =
    raw"(?m)(?:^|(?<=\s))${Regex.quote(key)}=(-?\d+)".r.findAllMatchIn(text).map(_.group(1).toLong).toSeq

  /** The lower middle value of an even count, 0 of none. */
  def median(values: Seq[Long]): Long =
    if values.isEmpty then 0 else values.sorted.apply((values.length + 1) / 2 - 1)

  /** A text's last line, as a binary's summary line is read. */
  def lastLine(text: String): String = text.linesIterator.toSeq.lastOption.getOrElse("")

  /** The two rule files: the launcher's defaults, a workspace line freeing one file, filler lines up to
    * the map's capacity, then the guard's anchored lines: a relocated hook directory first, ahead of every
    * floating line, so that an alias context computed by the wrong indices names the wrong lines, which
    * the alias cases catch; the traversed component and the end of the `.claude` symlink with its alias
    * context last. B has a workspace line in place of the last filler, as a later rule file would, at the
    * same 128 lines. */
  def ruleFiles(defaults: String): (Seq[String], Seq[String]) =
    val freed = stripRules(defaults) :+ "writable .vscode/settings.json"
    val filled = freed ++ (freed.length until 124).map(i => s"read-only zz-filler-$i")
    val first = Seq("read-only githooks anchored")
    val anchored = Seq("pinned-path shared anchored", "pinned-path shared/claude anchored alias=.claude")
    (
      first ++ filled ++ Seq("read-only zz-filler-last") ++ anchored,
      first ++ filled ++ Seq("read-only README.md") ++ anchored,
    )

  /** The deepest tracked path of `git ls-files`' output, by its count of components. */
  def deepestOf(lsFiles: String): Option[String] =
    lsFiles.linesIterator.map(_.trim).filter(_.nonEmpty).toSeq.maxByOption(_.count(_ == '/'))

  /** The short name `dir /x` lists for `.vscode`, when NTFS generates one. */
  def shortNameOf(dirX: String): Option[String] =
    val shortLine = raw"\s(\S+~\d\S*)\s+\.vscode\s*$$".r
    dirX.linesIterator.flatMap(line => shortLine.findFirstMatchIn(line).map(_.group(1))).nextOption()

  /** The differences of one walk-cost pair, policy minus bare, in ns, and the line the transcript holds. */
  case class WalkPair(n: Int, first: String, policy: String, bare: String):
    def difference(key: String): Long = number(key, policy) - number(key, bare)
    def rdwr: Long = difference("open_rdwr_ns")
    def rdonly: Long = difference("open_rdonly_ns")
    def lstat: Long = difference("lstat_ns")
    def policyRdwr: Long = number("open_rdwr_ns", policy)
    def bareRdwr: Long = number("open_rdwr_ns", bare)
    def failed: Long = number("failed", policy) + number("failed", bare)
    def line: String =
      s"walk-pair n=$n first=$first rdwr=$rdwr rdonly=$rdonly lstat=$lstat policy_rdwr=$policyRdwr " +
        s"bare_rdwr=$bareRdwr failed=$failed"

  /** The profile "Mounts" relies on, derived from the machine's default as the TODO item plans it: a user
    * namespace refused with EPERM by the flag of clone and unshare, clone3 answered ENOSYS, and the mount
    * family answered EPERM by rules of its own, since the machine's default action is ENOSYS. Run by the
    * machine's python3 over the machine's own file, which its podman serves. */
  val SeccompGenerator: String =
    """import json, sys
      |profile = json.load(open(sys.argv[1]))
      |mounts = ["mount", "fsopen", "fsconfig", "fsmount", "fspick", "move_mount", "open_tree", "open_tree_attr",
      |          "mount_setattr", "umount2", "umount", "pivot_root"]
      |family = set(mounts) | {"clone", "clone3", "unshare"}
      |for entry in profile["syscalls"]:
      |    entry["names"] = [name for name in entry["names"] if name not in family]
      |profile["syscalls"] = [entry for entry in profile["syscalls"] if entry["names"]]
      |CLONE_NEWUSER = 0x10000000
      |rules = [{"names": ["clone3"], "action": "SCMP_ACT_ERRNO", "errnoRet": 38},
      |         {"names": mounts, "action": "SCMP_ACT_ERRNO", "errnoRet": 1}]
      |for name in ("clone", "unshare"):
      |    rules.append({"names": [name], "action": "SCMP_ACT_ERRNO", "errnoRet": 1,
      |        "args": [{"index": 0, "value": CLONE_NEWUSER, "valueTwo": CLONE_NEWUSER, "op": "SCMP_CMP_MASKED_EQ"}]})
      |    rules.append({"names": [name], "action": "SCMP_ACT_ALLOW",
      |        "args": [{"index": 0, "value": CLONE_NEWUSER, "valueTwo": 0, "op": "SCMP_CMP_MASKED_EQ"}]})
      |profile["syscalls"] = rules + profile["syscalls"]
      |json.dump(profile, open(sys.argv[2], "w"))
      |""".stripMargin

  val RefusedByProfile = Seq("unshare_newuser", "unshare_newns", "mount", "fsopen", "open_tree", "move_mount",
    "fsmount", "fspick", "mount_setattr", "umount2", "pivot_root")

  // --- The run ---------------------------------------------------------------------------------------------

  val VmDir = ".local/share/ko-agent-sandbox/bpf-probe3"
  val Controller = s"./$VmDir/controller"
  val Exercise = "/out/exercise"
  val PinRoot = "/sys/fs/bpf/ko-agent-bpf-phase3"
  val ProbeImage = "ko-agent-bpf-probe:phase3"
  val Volume = "ko-agent-bpf3-vol"
  val HomeVolume = "ko-agent-bpf3-home"
  val Label = "ko-agent-bpf3"
  val Sessions = 1 to 4
  val WalkCount = 2000
  val WalkPairs = 5
  val RaceSeconds = 5
  val StormProcesses = 16
  val StormSeconds = 5
  /** The named containers the descriptor and slot rows start detached. */
  val Server = "ko-agent-bpf3-srv"
  val Receiver = "ko-agent-bpf3-rcv"
  val Slot = "ko-agent-bpf3-slot"

  /** What the run leaves beside its containers: the pins, the attach cgroups, the volumes, the second
    * share's directory and the scratch directory. */
  def removeLeftovers(platform: Platform, scratchDir: Path, secondShare: Option[Path], transcript: Transcript,
      vm: Vm): Unit =
    vm(sh(
      s"[ -x $Controller ] && ${unpinEvery(Controller, PinRoot)}",
      s"sudo -n rmdir $PinRoot 2>/dev/null",
      "systemctl --user stop " + Sessions.map(n => s"$Label-hold-$n").mkString(" ") + " " +
        Sessions.map(n => s"ko-agent-bpf3-$n.slice").mkString(" ") + " 2>/dev/null",
      "systemctl --user reset-failed 2>/dev/null",
      s"rmdir $AppSliceGlob/ko-agent-bpf3-? 2>/dev/null",
      s"rm -rf ${quoted(vmPath(platform, scratchDir.toString))}",
      "true",
    ))
    host(transcript, Seq("podman", "volume", "rm", "-f", Volume, HomeVolume))
    secondShare.foreach(removeTree(platform, _))
    removeTree(platform, scratchDir)

  /** The fixture on the share: the machine paths of the tree laid out as a workspace, of the tree whose
    * `.git` is a pointer file, of the clone of this repository and of the two rule files; the clone's
    * deepest tracked file; the four attach cgroups, one a session; the volume the policy records as a
    * root, on its superblock's type; and whether the share let the host make the FIFO the fifo rows use. */
  case class Fixture(
      fsType: String,
      tree: String,
      pointerTree: String,
      repoClone: String,
      rulesA: String,
      rulesB: String,
      deepest: String,
      deepestDepth: Int,
      cgroups: Map[Int, Cgroup],
      volumeMountpoint: String,
      volumeFsType: String,
      hostFifo: Boolean,
  ):
    /** The guarded objects: the pointer files and the `.git` directories of the fixture and the clone, so
      * that the gitdir cases run under a recorded `.git` directory, with the workspace's rules and depth
      * kept above it. */
    def rootsA: String =
      s"--root workspace=$tree --root workspace=$pointerTree --root workspace=$repoClone " +
        s"--root gitdir=$tree/.git/modules/sub --root guarded-git=$pointerTree/.git " +
        s"--root guarded-git=$tree/submod/.git --root guarded-git=$tree/.git --root guarded-git=$repoClone/.git " +
        s"--root guarded-sandbox=$pointerTree/.ko-agent-sandbox --root guarded-sandbox=$tree/.ko-agent-sandbox " +
        s"--root volume=$volumeMountpoint --vol-fs-type $volumeFsType"
    def hostFifoPath: String = s"$tree/apps/host-fifo"

  def run(args: Seq[String]): Unit =
    val options = orExit(parseOptions(args))
    val platform = orExit(Platform.resolve(options.platform))
    val repoDir = orExit(repositoryRoot("bpf/probe/phase3/sources.txt", "bpf/probe/phase3/exercise.c"))
    val probeDir = repoDir / "bpf" / "probe" / "phase3"
    val out = options.out.getOrElse(probeDir / platform.outDir)
    Files.createDirectories(out)
    val transcript = Transcript(out / "transcript.log")
    val vm = Vm(transcript)
    // Under the repository's ignored tmp/, on the share the machine mounts, as Phase 5 keeps its fixtures.
    val name = s"ko-agent-bpf-phase3.${ProcessHandle.current().pid()}"
    val scratchDir = repoDir / "tmp" / name
    val secondShare = secondShareRoot(platform).map(_ / name)
    val cleanup = Cleanup(transcript, Label, () => removeLeftovers(platform, scratchDir, secondShare, transcript, vm))
    runMeasured(transcript, cleanup):
      Measurement(platform, probeDir, repoDir, out, transcript, vm, scratchDir, secondShare).measure()

  /** The phase as steps, each `Right` with what the next needs or `Left` with the exit status after it
    * said why: 2 for a refusal before any row is measured, 1 for a gate the transcript records as FAIL. */
  class Measurement(
      platform: Platform,
      probeDir: Path,
      repoDir: Path,
      out: Path,
      transcript: Transcript,
      vm: Vm,
      scratchDir: Path,
      secondShare: Option[Path],
  ):
    import transcript.{check, gate, info, log, refuse, step}
    private val scratchDirVm = vmPath(platform, scratchDir.toString)
    private val repoDirVm = vmPath(platform, repoDir.toString)
    private val treeDir = scratchDir / "tree"
    private val pointerTreeDir = scratchDir / "tree-ptr"
    private val pinA = s"$PinRoot/a/file_open"

    def measure(): Int =
      val outcome =
        for
          facts <- readVmFacts()
          _ <- buildAndInstall(facts)
          _ <- verifier()
          fixture <- prepareFixture(facts)
          _ <- attachLiveSession(fixture)
        yield
          corpusGitRaceStormSocketsWalk(fixture)
          shortNames(fixture)
          unixSockets(fixture)
          seccompProfile(fixture)
          if transcript.failed == 0 then 0 else 1
      outcome.merge

    // --- The containers: the probe image holds the exerciser at /out/exercise and git -----------------------

    /** `--userns=keep-id` so files on the share are the user's; the volume at /vol, the stand-in for `~` at
      * /home2, this repository read-only for the clone. The exerciser runs without podman's seccomp profile,
      * so that what a row sees is the hooks' answer; one row runs under a generated profile. */
    private def exerciserOptions: Seq[String] = Seq(
      "--userns=keep-id", "--security-opt", "seccomp=unconfined", s"--label=$Label=1",
      s"--volume=$scratchDir:$scratchDirVm", s"--volume=$Volume:/vol", s"--volume=$HomeVolume:/home2",
      s"--volume=$repoDir:$repoDirVm:ro",
    )

    private def cgroupOption(fixture: Fixture, session: Int): Seq[String] =
      if session == 0 then Seq.empty else Seq(s"--cgroup-parent=${fixture.cgroups(session).parent}")

    /** A shell script in a container under attach cgroup `session`, or outside any policy for 0. */
    private def inSession(fixture: Fixture, session: Int, script: String): Output =
      host(transcript, Seq("podman", "run", "--rm") ++ cgroupOption(fixture, session) ++ exerciserOptions ++
        Seq(ProbeImage, "sh", "-c", script))

    private def outside(script: String): Output =
      host(transcript, Seq("podman", "run", "--rm") ++ exerciserOptions ++ Seq(ProbeImage, "sh", "-c", script))

    /** A container started detached under `session`, by name; `collect` waits for it and returns its log. */
    private def detached(fixture: Fixture, name: String, session: Int, argv: Seq[String]): Unit =
      host(transcript, Seq("podman", "rm", "-f", name))
      host(transcript, Seq("podman", "run", "-d", "--name", name) ++ cgroupOption(fixture, session) ++
        exerciserOptions ++ Seq(ProbeImage) ++ argv)

    private def logsOf(name: String): String = host(transcript, Seq("podman", "logs", name)).text

    private def collect(name: String): String =
      host(transcript, Seq("podman", "wait", name))
      val logs = logsOf(name)
      host(transcript, Seq("podman", "rm", "-f", name))
      logs

    /** The server's `serve listening` line, polled for up to ten seconds. */
    private def awaitListening(name: String): Unit =
      var tries = 0
      while tries < 50 && !logsOf(name).contains("serve listening") do
        Thread.sleep(200)
        tries += 1

    // --- The steps ------------------------------------------------------------------------------------------

    def readVmFacts(): Either[Int, VmFacts] =
      ProbeHelper.readVmFacts(transcript, vm, out, scratchDir, scratchDirVm, PinRoot).map: facts =>
        // The preemption mode decides whether a task can be preempted inside the program ("Phases", 3); debugfs
        // shows it.
        vm("sudo -n sh -c 'findmnt -n /sys/kernel/debug >/dev/null || mount -t debugfs debugfs /sys/kernel/debug'")
        val preemption = vm.line("sudo -n cat /sys/kernel/debug/sched/preempt 2>/dev/null || echo unavailable")
        info(s"preemption mode: $preemption")
        facts

    def buildAndInstall(facts: VmFacts): Either[Int, Unit] =
      step("build and install the probe")
      for sourcesSha <- buildProbeImage(transcript, probeDir, scratchDir, ProbeImage, facts.kernel)
      yield
        check("probe installed in the machine", installProbe(vm, ProbeImage, VmDir, Label, Seq("controller")).ok)
        recordBuild(transcript, vm, out, VmDir, Seq(s"sources sha256=$sourcesSha"))
        Files.writeString(out / "policy.bpf.asm", vm(s"cat $VmDir/policy.bpf.asm").text)

    def verifier(): Either[Int, Unit] =
      step("verifier: the policy program's nine hooks")
      val load = vm(s"sudo -n $Controller load policy.bpf.o")
      Files.writeString(out / "verifier-policy.txt", load.text)
      transcript.indent(lines(load.text, "^(load|verifier|prog) ".r).mkString("\n"))
      check(
        "the policy program's nine hooks load, alone and together",
        load.text.linesIterator.count(_.contains(" ok=1")) == 10 && load.ok,
      )
      val mostInsns = numbers("verified_insns", load.text).maxOption
      info(
        s"the most instructions the verifier processed for one program: ${mostInsns.getOrElse("none")}, of the " +
          "limit 1,000,000",
      )
      // The gate's budget ("Phases", 3): a program near the limit fails to load at the next change of the walk.
      val within = check(
        "every program verifies within 500,000 instructions, half the limit",
        mostInsns.exists(_ <= 500000),
      )
      Seq("inode_rename", "inode_symlink").foreach: program =>
        val logged = vm(s"sudo -n $Controller verifier-log policy.bpf.o $program /tmp/$program.log")
        lines(logged.text, "^verifier ".r).foreach(log)
        val encoded = vm(s"gzip -c /tmp/$program.log | base64 -w0")
        scala.util.Try(Base64.getDecoder.decode(encoded.text.trim)) match
          case scala.util.Success(bytes) if encoded.ok => Files.write(out / s"policy-$program.log.gz", bytes)
          case _ => info(s"the verifier log of $program could not be read: ${encoded.text.trim}")
      info(s"the logs are in ${out / "policy-inode_rename.log.gz"} and policy-inode_symlink.log.gz")
      Either.cond(within, (), 1)

    /** The tree, and the host-made hard links to the guarded files, made on the host as the filter's test
      * makes them, and to the submodule worktree's pointer file, in another directory. NTFS serves `GIT~1`
      * itself as the pointer file's short name, so the link at that name may be refused there and the name
      * NTFS serves stands in. */
    private def makeFixture(tree: String): Output =
      val made = outside(s"$Exercise make-tree $tree")
      Seq((".git", "GIT~1"), (".ko-agent-sandbox", "KO-AGE~1")).foreach: (target, link) =>
        try Files.createLink(pointerTreeDir / link, pointerTreeDir / target)
        catch case ex: Exception => info(s"hard link $link: ${ex.getMessage}; the name NTFS serves stands in")
      Files.createLink(treeDir / "apps" / "submod-pointer", treeDir / "submod" / ".git")
      made

    def prepareFixture(facts: VmFacts): Either[Int, Fixture] =
      step("fixtures, clone, volume and the attach cgroups")
      val cgroups =
        Sessions.map(session => session -> attachCgroup(vm, facts.manager, facts.uid, Label, session.toString)).toMap
      for _ <- gate(
          s"four attach cgroups exist under the user's manager: ${cgroups(1).path}",
          Sessions.forall(session => cgroups(session).path.nonEmpty),
        )
      yield
        // The persistent volume, whose root the policy records, and a second volume standing for `~`, which
        // shares its superblock ("Environment evidence").
        host(transcript, Seq("podman", "volume", "create", Volume))
        host(transcript, Seq("podman", "volume", "create", HomeVolume))
        val volumeMountpoint = vm.line(s"podman volume inspect --format '{{.Mountpoint}}' $Volume")
        val volumeFsType = vm.line(s"findmnt -T ${quoted(volumeMountpoint)} -n -o FSTYPE")
        info(s"the volume's mountpoint in the machine: $volumeMountpoint, on $volumeFsType")
        val tree = s"$scratchDirVm/tree"
        val pointerTree = s"$scratchDirVm/tree-ptr"
        val repoClone = s"$scratchDirVm/repo"
        makeFixture(tree)
        val inodes = vm(s"stat -c %i ${quoted(s"$pointerTree/.git")} ${quoted(s"$pointerTree/GIT~1")}").text
          .linesIterator.filter(_.matches("\\d+")).toSeq
        check(
          s"GIT~1 names the pointer file's inode in the machine: ${inodes.mkString(" ")}",
          inodes.length == 2 && inodes(0) == inodes(1),
        )
        // The clone is made in a container, where git is the probe image's, over the repository mounted
        // read-only: the same path on both hosts.
        val cloned = outside(s"git -c safe.directory='*' clone --quiet $repoDirVm $repoClone")
        if cloned.text.trim.nonEmpty then info(s"clone: ${cloned.text.linesIterator.mkString(" ")}")
        check(
          "the fixtures and a clone of this repository exist on the share",
          Files.isRegularFile(treeDir / ".git" / "config") && Files.isRegularFile(pointerTreeDir / ".git") &&
            Files.isDirectory(scratchDir / "repo" / ".git"),
        )
        val fixtureCheck = outside(s"$Exercise check $tree")
        check(
          s"the fixture holds every operand the corpus needs: ${lastLine(fixtureCheck.text)}",
          field("gaps", fixtureCheck.text) == "0",
        )
        // The fixture is laid out again after the check, which ran the allowed cases on it.
        removeTree(platform, treeDir)
        removeTree(platform, pointerTreeDir)
        val made = makeFixture(tree)
        // The FIFO the host made for the `fifo` group and the descriptor row below: a share may refuse to
        // make one, and the cases on it are then skipped and said so.
        val fifoLine = lines(made.text, "^made fifo".r).mkString(" ")
        val hostFifo = vm(s"test -p ${quoted(s"$tree/apps/host-fifo")}").ok
        if hostFifo then info(s"the host FIFO $tree/apps/host-fifo exists: $fifoLine")
        else info(s"the share refused the host FIFO: $fifoLine; its rows are skipped")
        val deepest = deepestOf(outside(s"cd $repoClone && git ls-files").text).getOrElse("")
        val deepestDepth = deepest.count(_ == '/') + 1
        val (rulesA, rulesB) = ruleFiles(Files.readString(repoDir / RuleDefaults))
        Files.writeString(scratchDir / "rules-a.txt", rulesA.mkString("", "\n", "\n"))
        Files.writeString(scratchDir / "rules-b.txt", rulesB.mkString("", "\n", "\n"))
        info(s"rule lines: ${rulesA.length} in A, ${rulesB.length} in B")
        Fixture(facts.fsType, tree, pointerTree, repoClone, s"$scratchDirVm/rules-a.txt", s"$scratchDirVm/rules-b.txt",
          deepest, deepestDepth, cgroups, volumeMountpoint, volumeFsType, hostFifo)

    /** The live session's policy on cgroup 1, under FLAGS when given, pinned at `a`. */
    private def attachA(fixture: Fixture, flags: Option[String], hooks: Seq[String]): Output =
      vm(s"sudo -n $Controller unpin $PinRoot/a")
      val flagOption = flags.fold("")(value => s"--flags $value")
      val attach = vm(
        s"sudo -n $Controller attach policy.bpf.o ${fixture.cgroups(1).path} $PinRoot/a --fs-type ${fixture.fsType} " +
          s"--rules ${fixture.rulesA} $flagOption ${fixture.rootsA} ${hooks.mkString(" ")}",
      )
      transcript.indent(lines(attach.text, "^(root|alias|policy|attached) ".r).mkString("\n"))
      attach

    def attachLiveSession(fixture: Fixture): Either[Int, Unit] =
      val attach = attachA(fixture, None, Hooks8)
      for _ <- gate(
          "the live session's policy attached with 128 rules, one alias and eleven roots",
          field("count", attach.text) == "8" && field("rule_count", attach.text) == "128",
        )
      yield
        val partialLines = lines(attach.text, "^alias ".r).mkString.split("partial_lines=").lift(1).getOrElse("")
        check(
          "the alias context of .claude holds the five .claude lines as partial matches",
          partialLines.count(_ == ',') >= 5,
        )

    private def statsOf(pin: String): Output = vm(s"sudo -n $Controller stats $pin")
    private def resetStats(pin: String): Unit = vm(s"sudo -n $Controller reset-stats $pin")
    private def corpusMismatches(corpus: Output): Unit =
      transcript.indent(lines(corpus.text, "MISMATCH|UNSUPPORTED".r).mkString("\n"))
    private def corpusLine(corpus: Output): String = lines(corpus.text, "^corpus ".r).mkString(" ")

    def corpusGitRaceStormSocketsWalk(fixture: Fixture): Unit =
      step("the corpus, git in the clone, the race, the storm, sockets, a second share")
      val tree = fixture.tree
      val repoClone = fixture.repoClone
      val corpus = inSession(fixture, 1, s"$Exercise corpus $tree")
      corpusMismatches(corpus)
      check(s"the corpus: ${corpusLine(corpus)}", field("mismatches", corpus.text) == "0")
      info(vm.line(s"sudo -n $Controller last-decision $pinA"))
      val gitOk = inSession(fixture, 1,
        s"cd $repoClone && git status --short > /dev/null && git add -A && " +
          "git -c user.name=probe -c user.email=probe@example.invalid commit -q --allow-empty -m probe && " +
          "git checkout -q -b probe && git log -1 --oneline > /dev/null && git gc -q && echo GIT_OK")
      check("ordinary git in the clone: status, add, commit, branch, log, gc", gitOk.has("GIT_OK"))
      val gitConfig = inSession(fixture, 1,
        s"cd $repoClone && (git config probe.key value 2>&1 || echo CONFIG_REFUSED) && " +
          "(git init -q sub2 2>&1 || echo INIT_REFUSED)")
      check(
        "git config and git init in the clone are refused",
        gitConfig.has("CONFIG_REFUSED") && gitConfig.has("INIT_REFUSED"),
      )
      // Host git in a session-made `.git` without HEAD: git walks past it to the workspace's gitdir.
      val hostGit = outside(s"cd $tree/sub && git rev-parse --absolute-git-dir 2>&1").text.trim
      check(
        s"git outside the policy in sub/, whose .git has no HEAD, finds the workspace's gitdir: $hostGit",
        hostGit.contains(s"$tree/.git"),
      )
      // The torn-name race: the walks that overlapped a rename are the retries.
      resetStats(pinA)
      val race = inSession(fixture, 1, s"$Exercise race $tree $RaceSeconds")
      val raceStats = statsOf(pinA)
      transcript.indent(raceStats.text)
      check(
        s"the race: ${lines(race.text, "^race ".r).mkString(" ")}",
        field("succeeded", race.text) == "0" && numbers("gave_up", raceStats.text).sum == 0,
      )
      // The race ran when both renamers moved and the writer met both names, refused under one and absent
      // under the other. The torn reads the walk caught, its retries, are information: each dentry is
      // validated over the read of its own name, a window a run hits 0 to 15 times ("Phase 3 on macOS").
      check(
        "the race ran: both renamers moved, and the writer saw refusals and absences",
        numbers("renames", race.text).forall(_ > 0) && numbers("renames", race.text).nonEmpty &&
          number("refused", race.text) > 0 && number("absent", race.text) > 0,
      )
      info(s"walks that read a torn name and were made again: ${numbers("retries", raceStats.text).sum}")
      // The storm: every decision counted, none wrong, and no call denied for want of a slot.
      resetStats(pinA)
      val storm = inSession(fixture, 1, s"$Exercise storm $tree $StormProcesses $StormSeconds")
      val stormStats = statsOf(pinA)
      transcript.indent(stormStats.text)
      transcript.indent(lines(storm.text, "^storm process".r).mkString("\n"))
      check(s"the storm: ${lines(storm.text, "^storm processes".r).mkString(" ")}", field("failed", storm.text) == "0")
      info(
        s"reentry: ${numbers("reentry", stormStats.text).sum} calls denied for want of a slot; the deepest nesting " +
          s"on one CPU: slot ${numbers("nested_max", stormStats.text).maxOption.getOrElse(0L)}",
      )
      slots(fixture)
      socketsByDefault(fixture)
      secondShareRow(fixture)
      walkCost(fixture)

    /** The slots exhausted by hand: the guard word is set while a container already up sleeps, so no call of
      * the runtime's is in flight, and read back by that container's write once the word is set. With all
      * four slots marked taken on every CPU a write on the share is denied and counted; with three it runs in
      * the fourth; freed, it runs in the first again. */
    private def slots(fixture: Fixture): Unit =
      def slotWrite(mask: String, name: String): Output =
        detached(fixture, Slot, 1, Seq("sh", "-c",
          s"sleep 3; (echo x > ${fixture.tree}/apps/$name) 2>&1 && echo SLOT_OK || echo SLOT_REFUSED"))
        Thread.sleep(1000)
        vm(sh(s"sudo -n $Controller reset-stats $pinA", s"sudo -n $Controller guard $pinA $mask"))
        val logs = collect(Slot)
        vm(s"sudo -n $Controller guard $pinA 0")
        Output(0, logs)
      def createNested(stats: Output): String =
        lines(stats.text, "hook=inode_create".r).headOption.map(field("nested_max", _)).getOrElse("")
      val full = slotWrite("0xf", "slot-full")
      val fullStats = statsOf(pinA)
      check(
        "with every slot taken a write on the share is refused and counted as reentry: " +
          s"${numbers("reentry", fullStats.text).sum}",
        full.has("SLOT_REFUSED") && numbers("reentry", fullStats.text).sum > 0,
      )
      val three = slotWrite("0x7", "slot-three")
      check(
        "with three slots taken a write runs in the fourth: nested_max 3, no reentry",
        three.has("SLOT_OK") && createNested(statsOf(pinA)) == "3",
      )
      val freed = slotWrite("0", "slot-freed")
      check(
        "with the slots freed a write runs in the first again",
        freed.has("SLOT_OK") && createNested(statsOf(pinA)) == "0",
      )

    /** Sockets by default: refused beneath the volume, allowed under /home2, the stand-in for `~` on the
      * volume's superblock, from where a bound socket cannot be renamed or linked beneath the volume; a `mv`
      * into the workspace crosses superblocks and recreates the socket by mknod, which is refused too. */
    private def socketsByDefault(fixture: Fixture): Unit =
      val sockets = inSession(fixture, 1,
        s"$Exercise bind /vol/s; $Exercise bind /home2/s; " +
          "(mv /home2/s /vol/s 2>&1 && echo MV_VOL_OK || echo MV_VOL_REFUSED); " +
          "(ln /home2/s /vol/s 2>&1 && echo LN_VOL_OK || echo LN_VOL_REFUSED); " +
          s"(mv /home2/s ${fixture.tree}/apps/s 2>&1 && echo MV_WS_OK || echo MV_WS_REFUSED)")
      def bindResult(path: String): String =
        lines(sockets.text, s"^bind path=${Regex.quote(path)} ".r).headOption.map(field("result", _)).getOrElse("")
      check(
        "a socket is refused beneath the volume and allowed under /home2",
        bindResult("/vol/s") == "EPERM" && bindResult("/home2/s") == "ok",
      )
      check(
        "a socket bound under /home2 cannot be renamed or linked beneath the volume, nor moved into the workspace",
        sockets.has("MV_VOL_REFUSED") && sockets.has("LN_VOL_REFUSED") && sockets.has("MV_WS_REFUSED"),
      )

    /** A second host share, bound into a container under the policy: on its superblock, of the root's type,
      * no walk meets a root. */
    private def secondShareRow(fixture: Fixture): Unit =
      secondShare match
        case None => info("second share: the host has none; not measured")
        case Some(dir) =>
          Files.createDirectories(dir)
          val dirVm = vmPath(platform, dir.toString)
          val shareType = vm.line(s"findmnt -T ${quoted(dirVm)} -n -o FSTYPE")
          val shareTarget = vm.line(s"findmnt -T ${quoted(dirVm)} -n -o TARGET")
          val fixtureTarget = vm.line(s"findmnt -T ${quoted(scratchDirVm)} -n -o TARGET")
          if shareType == fixture.fsType && shareTarget != fixtureTarget then
            val answer = host(transcript, Seq("podman", "run", "--rm", s"--cgroup-parent=${fixture.cgroups(1).parent}",
              "--userns=keep-id", "--security-opt", "seccomp=unconfined", s"--label=$Label=1",
              s"--volume=$dir:/share2", ProbeImage, "sh", "-c",
              "(echo x > /share2/f) 2>&1 && echo W_OK || echo W_REFUSED; " +
                "(mkdir /share2/d) 2>&1 && echo MKDIR_OK || echo MKDIR_REFUSED"))
            check(
              s"a write on a second share of the same type, bound into the container, is refused: " +
                answer.text.linesIterator.mkString(" "),
              answer.has("W_REFUSED"),
            )
          else
            info(
              s"second share: $dirVm is on $shareType at $shareTarget, the fixture's mount or another type; " +
                "not measured",
            )

    /** The walk's cost: WalkPairs pairs of a container under the policy and one outside it, the policy's
      * first in the odd pairs so that the order is not confounded with the policy, each timing WalkCount
      * opens for writing, opens for reading, which the hook leaves before any walk, and lstats, which no hook
      * sees. The share's speed can drift within a pair by more than the walk costs ("Phase 3 on macOS"), so
      * the figure that resolves the walk is the program's own timer: file_open's mean over the pairs' write
      * opens, read after them. */
    private def walkCost(fixture: Fixture): Unit =
      val command = s"$Exercise walk-cost ${fixture.repoClone}/${fixture.deepest} $WalkCount"
      resetStats(pinA)
      val pairs = (1 to WalkPairs).map: n =>
        val pair =
          if n % 2 == 1 then
            val policy = inSession(fixture, 1, command)
            WalkPair(n, "policy", policy.text, outside(command).text)
          else
            val bare = outside(command)
            WalkPair(n, "bare", inSession(fixture, 1, command).text, bare.text)
        log(pair.line)
        pair
      info(
        s"walk cost at the clone's deepest file, depth ${fixture.deepestDepth}, policy minus bare over $WalkPairs " +
          s"pairs, the medians: open_rdwr=${median(pairs.map(_.rdwr))} open_rdonly=${median(pairs.map(_.rdonly))} " +
          s"lstat=${median(pairs.map(_.lstat))} ns; bare open_rdwr ${pairs.map(_.bareRdwr).min} to " +
          s"${pairs.map(_.bareRdwr).max} ns; failed=${pairs.map(_.failed).sum}",
      )
      info(s"in program over the pairs: ${lines(statsOf(pinA).text, "^stats hook=file_open ".r).mkString(" ")}")
      val jited = vm(s"sudo -n $Controller jited $pinA /tmp/file_open.jited").text.trim
      info(jited)
      val fetchAdd = field("fetch_add_insns", jited)
      check(
        "the xlated program holds the atomic fetch-add and the jited one a barrier instruction",
        fetchAdd.nonEmpty && fetchAdd != "0" &&
          Seq("ldaddal", "dmb_ish", "lock_xadd").exists(key => field(key, jited) != "0"),
      )

    def shortNames(fixture: Fixture): Unit =
      step("the NTFS short-name form, under its flag, and the generated short name of .vscode")
      val attach = attachA(fixture, Some("short-names"), Hooks8)
      check(
        "the policy attached again with the short-names flag",
        field("count", attach.text) == "8" && field("flags", attach.text) == "1",
      )
      val corpus = inSession(fixture, 1, s"$Exercise corpus ${fixture.tree} short")
      corpusMismatches(corpus)
      check(s"the short-name corpus: ${corpusLine(corpus)}", field("mismatches", corpus.text) == "0")
      // The short name NTFS serves for `.vscode`, read by `dir /x` on the Windows host: under the flag a write
      // through it is refused and the host sees no file in `.vscode`.
      if platform == Platform.Windows then
        val dirX = host(transcript, Seq("cmd", "/c", "dir", "/x", treeDir.toString)).text
        shortNameOf(dirX) match
          case Some(shortName) =>
            info(s"NTFS serves .vscode as $shortName")
            val through = inSession(fixture, 1,
              s"(echo x > ${fixture.tree}/$shortName/new.json) 2>&1 && echo SHORT_OK || echo SHORT_REFUSED")
            check(
              s"a write through the generated short name of .vscode is refused under the flag: ${through.text.trim}",
              through.has("SHORT_REFUSED"),
            )
            check(
              "the host saw no file arrive in .vscode through its short name",
              !Files.exists(treeDir / ".vscode" / "new.json"),
            )
          case None =>
            info(
              "NTFS generates no short name for .vscode on this volume (8dot3name disabled); the form row is the " +
                "corpus's",
            )

    /** A, the live session (cgroup 1), and B, a second session of the workspace under a later rule file
      * (cgroup 2), each with file_receive; C, a session of another workspace, the clone (cgroup 3); D, a
      * --workspace=read-only session, a policy with no root (cgroup 4). */
    def unixSockets(fixture: Fixture): Unit =
      step("--unix-sockets: four sandboxes, the socket corpus and descriptors between them")
      val tree = fixture.tree
      val attachedA = attachA(fixture, Some("unix-sockets"), Hooks9)
      check(
        "A attached with nine hooks under unix-sockets",
        field("count", attachedA.text) == "9" && field("flags", attachedA.text) == "2",
      )
      // What the runtime passes into a starting container reaches file_receive first: a container that does
      // nothing, then the hook's last decision and counts.
      val started = inSession(fixture, 1, "echo STARTED")
      check("a container starts under A with file_receive attached", started.has("STARTED"))
      info(vm.line(s"sudo -n $Controller last-decision $PinRoot/a/file_receive"))
      info(lines(statsOf(s"$PinRoot/a/file_receive").text, "hook=file_receive".r).mkString(" "))
      // What the runtime leaves open: the first process and a process of its own hold no descriptor beyond
      // the standard three.
      val fds = inSession(fixture, 1, s"$Exercise fds")
      check(
        s"the container's first process holds no descriptor of the runtime's: ${lastLine(fds.text)}",
        field("beyond_standard", fds.text) == "0",
      )
      val hooks9 = Hooks9.mkString(" ")
      val attachedB = vm(
        s"sudo -n $Controller attach policy.bpf.o ${fixture.cgroups(2).path} $PinRoot/b --fs-type ${fixture.fsType} " +
          s"--rules ${fixture.rulesB} --flags unix-sockets ${fixture.rootsA} $hooks9",
      )
      check(
        "B attached with nine hooks and the later rule file",
        field("count", attachedB.text) == "9" && field("rule_count", attachedB.text) == "128",
      )
      val attachedC = vm(
        s"sudo -n $Controller attach policy.bpf.o ${fixture.cgroups(3).path} $PinRoot/c --fs-type ${fixture.fsType} " +
          s"--rules ${fixture.rulesA} --flags unix-sockets --root workspace=${fixture.repoClone} " +
          s"--root volume=${fixture.volumeMountpoint} --vol-fs-type ${fixture.volumeFsType} $hooks9",
      )
      check("C, another workspace's session, attached", field("count", attachedC.text) == "9")
      val attachedD = vm(
        s"sudo -n $Controller attach policy.bpf.o ${fixture.cgroups(4).path} $PinRoot/d --fs-type ${fixture.fsType} " +
          s"--flags unix-sockets $hooks9",
      )
      check("D, a read-only session's policy with no root, attached", field("count", attachedD.text) == "9")
      val query = vm(s"sudo -n $Controller query ${fixture.cgroups(1).path}")
      info(lines(query.text, "^slots ".r).mkString(" "))
      check("four sandboxes hold nine hooks of the ten slots", field("hooks_in_use", query.text) == "9")
      val corpus = inSession(fixture, 1, s"$Exercise corpus $tree unix")
      corpusMismatches(corpus)
      check(s"the socket corpus under unix-sockets: ${corpusLine(corpus)}", field("mismatches", corpus.text) == "0")
      // A and B differ in policy: README.md is writable to A and not to B.
      val readmeA = inSession(fixture, 1, s"(echo x >> $tree/README.md) 2>&1 && echo A_OK || echo A_REFUSED")
      val readmeB = inSession(fixture, 2, s"(echo x >> $tree/README.md) 2>&1 && echo B_OK || echo B_REFUSED")
      check(
        "A writes README.md and B, under the later rule file, cannot",
        readmeA.has("A_OK") && readmeB.has("B_REFUSED"),
      )
      // D: nothing on the share opens for writing, /tmp does, reading works.
      val readOnly = inSession(fixture, 4,
        s"(echo x > $tree/apps/ro) 2>&1 && echo WS_OK || echo WS_REFUSED; (echo x > /tmp/ro) && echo TMP_OK; " +
          s"cat $tree/README.md > /dev/null && echo READ_OK")
      check(
        "D cannot write on the share, writes /tmp and reads the workspace",
        readOnly.has("WS_REFUSED") && readOnly.has("TMP_OK") && readOnly.has("READ_OK"),
      )
      descriptors(fixture)
      Seq("a", "b", "c", "d").foreach(pin => vm(s"sudo -n $Controller unpin $PinRoot/$pin"))

    /** Descriptors over a socket in the volume: `serve` runs detached in the sender's sandbox, `receive` in
      * the receiver's. Sender 0 is a container outside any policy: no attach cgroup above it. */
    private def descriptors(fixture: Fixture): Unit =
      val tree = fixture.tree
      def passFds(sender: Int, receiver: Int, sock: String, specs: Seq[String], actions: Seq[String] = Seq.empty)
          : Output =
        detached(fixture, Server, sender, Seq(Exercise, "serve", sock) ++ specs)
        awaitListening(Server)
        val received = inSession(fixture, receiver, s"$Exercise receive $sock ${actions.mkString(" ")}")
        collect(Server)
        received
      def received(answer: Output, count: Int, ctrunc: Int): Boolean =
        field("received", answer.text) == count.toString && field("ctrunc", answer.text) == ctrunc.toString
      def actionResult(answer: Output, action: String): String =
        raw"action=${Regex.quote(action)} result=(\S+)".r.findFirstMatchIn(answer.text).map(_.group(1)).getOrElse("")
      val same = inSession(fixture, 1,
        s"$Exercise serve /vol/s0 pipe pair ro:$tree/README.md > /tmp/serve.log & sleep 1; " +
          s"$Exercise receive /vol/s0; wait; cat /tmp/serve.log")
      check(
        "a pipe, a socket pair's end and a workspace file pass between two processes of one container",
        received(same, 3, 0),
      )
      val three = passFds(1, 2, "/vol/s1", Seq(s"ro:$tree/ordinary", s"rw:$tree/README.md", s"ro:$tree/ordinary"))
      check(
        "B gets the first of three descriptors from A and MSG_CTRUNC: the writable README.md is refused by B's rules",
        received(three, 1, 1),
      )
      val writable =
        passFds(1, 2, "/vol/s2", Seq(s"rw:$tree/ordinary", s"ro:$tree/README.md"), Seq("write:0", "reopen:1"))
      check(
        "B gets a writable descriptor of a file its rules allow, and a read-only one, writes the first",
        field("received", writable.text) == "2" && actionResult(writable, "write:0") == "ok",
      )
      check(
        "B cannot reopen the read-only descriptor of README.md for writing",
        actionResult(writable, "reopen:1") == "EPERM",
      )
      check(
        "B gets no directory descriptor from A: its container root, its /tmp, the receiver's own root",
        received(passFds(1, 2, "/vol/s3", Seq("dir:/", "dir:/tmp", s"dir:$tree")), 0, 1),
      )
      check(
        "C, another workspace's session, gets no descriptor of this workspace",
        received(passFds(1, 3, "/vol/s4", Seq(s"ro:$tree/ordinary", s"ro:$tree/ordinary")), 0, 1),
      )
      check(
        "D, the read-only session, gets no descriptor of the share",
        received(passFds(1, 4, "/vol/s5", Seq(s"ro:$tree/ordinary", s"rw:$tree/ordinary")), 0, 1),
      )
      check(
        "A gets no directory descriptor from B, and the pipe after it is dropped with it",
        received(passFds(2, 1, "/vol/s6", Seq("dir:/", "pipe")), 0, 1),
      )
      check(
        "A gets the pipe before a refused directory descriptor from B",
        received(passFds(2, 1, "/vol/s7", Seq("pipe", "dir:/tmp")), 1, 1),
      )
      // A FIFO of the share from a container outside any policy, which can open it ("The policy", the FIFO
      // rules): refused on arrival, whatever its mode.
      if fixture.hostFifo then
        check(
          "A gets no descriptor of the host FIFO from a container outside any policy, and the file after it is dropped",
          received(passFds(0, 1, "/vol/s10", Seq(s"fifo:${fixture.hostFifoPath}", s"ro:$tree/ordinary")), 0, 1),
        )
      else info("the FIFO descriptor row is skipped: the share refused the host FIFO")
      // The sender gone before the receiver reads: the receiver connects and then waits for a marker the
      // driver makes once the sender's container has ended and been removed, so its mount namespace is torn
      // down; the hook's record of the refusal must then show no namespace.
      def passFdsAfterExit(sock: String, specs: Seq[String]): Output =
        host(transcript, Seq("podman", "rm", "-f", Receiver))
        detached(fixture, Server, 1, Seq(Exercise, "serve", sock, "then-exit") ++ specs)
        awaitListening(Server)
        detached(fixture, Receiver, 2, Seq(Exercise, "receive", sock, s"wait-for:$sock.gone"))
        collect(Server)
        vm(s"touch ${fixture.volumeMountpoint}/${sock.split('/').last}.gone")
        Output(0, collect(Receiver))
      val afterExit = passFdsAfterExit("/vol/s8", Seq(s"rw:$tree/README.md", s"dir:$tree", s"ro:$tree/ordinary"))
      val last = vm.line(s"sudo -n $Controller last-decision $PinRoot/b/file_receive")
      info(last)
      check(
        "B, receiving after A's container ended, gets neither the writable README.md nor the directory",
        received(afterExit, 0, 1),
      )
      check(
        "the refused descriptor's mount was in no namespace: the sender's was torn down before the read",
        field("ns_inum", last) == "0" && field("name", last) == "README.md",
      )
      check(
        "B, receiving after A's container ended, gets a read-only share file its policy allows",
        received(passFdsAfterExit("/vol/s9", Seq(s"ro:$tree/ordinary")), 1, 0),
      )
      info(lines(statsOf(s"$PinRoot/b/file_receive").text, "hook=file_receive".r).mkString(" "))

    def seccompProfile(fixture: Fixture): Unit =
      step("the namespaces and mounts a generated seccomp profile refuses")
      Files.writeString(scratchDir / "seccomp-gen.py", SeccompGenerator)
      vm(s"python3 ${quoted(s"$scratchDirVm/seccomp-gen.py")} /usr/share/containers/seccomp.json " +
        quoted(s"$scratchDirVm/seccomp.json"))
      val namespaces = host(transcript, Seq("podman", "run", "--rm", s"--cgroup-parent=${fixture.cgroups(1).parent}",
        "--userns=keep-id", "--security-opt", s"seccomp=${scratchDir / "seccomp.json"}", s"--label=$Label=1",
        s"--volume=$scratchDir:$scratchDirVm", ProbeImage, "sh", "-c", s"$Exercise namespaces; echo CHILD_RAN"))
      // Every syscall the profile refuses answered EPERM, clone3's ENOSYS aside.
      val refused = RefusedByProfile.forall(call => field(call, namespaces.text) == "EPERM")
      check(
        "under the generated profile a user namespace and every mount syscall answer EPERM, and a child still runs",
        refused && namespaces.has("CHILD_RAN"),
      )
