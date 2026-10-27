#!/usr/bin/env -S scala shebang
//> using scala 3.10.0
//> using file ../ProbeHelper.scala

// Phase 4 of doc/plan-bpf-lsm-cgroup.md ("Phases", 4) on the podman machine of either host, in one
// run. Run it on the HOST, from the repository root, with the default machine running:
//
//     bpf/probe/phase4/Phase4.scala [--out DIR] [--platform mac|windows]
//
// The first line hands the file to the `scala` runner's `shebang` sub-command, which takes everything
// after the file as the program's arguments; on Windows, where no shebang runs, the same is
// `scala shebang bpf\probe\phase4\Phase4.scala [options]`. The `using file` line pulls in ../ProbeHelper.scala,
// what every driver shares; this file holds the phase's own rows and readers.
//
// It builds the probe image (Containerfile) from a context assembled out of the files sources.txt
// lists, the policy program and the launcher's binaries of bpf/ko-agent-bpf/ and the guard's records
// header among them, extracts /out into the machine under ~/.local/share/ko-agent-sandbox/bpf-probe4,
// and runs the phase's rows through `podman machine ssh` and the machine's sudo, each printed as PASS,
// FAIL or INFO. Every line is printed and appended to OUTDIR/transcript.log (default: out-macos/ or
// out-wsl/ beside this script, ignored by git), and the files the rows produce land beside it. Send
// OUTDIR back; the transcript is what "Phase 4 on macOS", "Phase 4 on WSL" and the phase's gate are
// filled from.
//
// The rows, in order: the environment, the build with the hash of its sources, the installation
// with the installed object's tags; the launch of a session through the launcher's steps 1 to 4
// ("Lifecycle"): the attach cgroup, the controller's attach with pins, the read-back, the proof
// fixture run by a process of the launcher's own below the cgroup, then the container, whose first
// process is refused a protected write; `podman exec`, `podman restart`, `podman kill`, the
// controller gone, a recreate that attaches the pinned programs and loads nothing, the socket rule's
// dependence on the mounts, the cgroup that cannot be removed while the container is in it and the
// enforcement that ends only when root unpins; the defective controllers, caught before any
// container exists; a launch under --unix-socket with the ninth hook and its proof; the pins reused
// across a rule change and a new build; the controller's refusals; the reconcile over its orphans,
// its kept sessions, its contradictions and its cleanup refusals; the costs of the launch's steps;
// and last, the restart invariant across a machine restart, which stops the podman machine and with
// it every session running on it, so the driver asks first, on stdin, and skips the rows unless
// answered yes.
//
// The platforms differ in data alone: the cgroup manager podman reports (a transient slice under
// systemd; under cgroupfs a directory under the user's delegated subtree, which the proof joins from a
// transient scope of the user manager and the reconcile removes itself), the path the machine serves a
// host directory at (the same path on macOS, /mnt/<drive>/... on Windows) and the output directory's
// name. On Windows, %UserProfile%\.wslconfig must hold `[wsl2]` and `isolateDistroCgroup=false`
// ("Environment evidence"), or the containers land in no cgroup of their own. Every command in the
// machine is one line without double quotes, since double quotes inside an argument do not reach the
// machine from Windows. --platform drives as that platform where the detection must be overridden, as
// in a dry run against fake commands.
//
// It writes a workspace fixture and the proof fixture under the repository's tmp/, which git ignores
// and the machine mounts, attach cgroups ko-agent-bpf4-* with their transient units, a podman volume,
// pins under /sys/fs/bpf/ko-agent-bpf-phase4 in the machine, session records under the machine's probe
// directory, and containers labelled ko-agent-bpf4.session; all are removed on exit.

import scala.annotation.tailrec
import scala.io.StdIn
import scala.util.matching.Regex

import java.nio.file.{Files, Path}
import java.time.LocalTime
import java.time.format.DateTimeFormatter

import ProbeHelper.*

@main def probe(args: String*): Unit = Phase4.run(args)

object Phase4:

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
      case Seq(other, _*) => Left(s"unknown option $other; see the header of Phase4.scala")
    loop(args, ProbeOptions())

  // --- The pure parts: what the transcript's figures are read with -----------------------------------------

  def count(text: String, needle: String): Int = text.linesIterator.count(_.contains(needle))

  def oneLine(text: String): String = text.linesIterator.map(_.trim).filter(_.nonEmpty).mkString(" ")

  /** The proof's summary line, `fixture ops=... mismatches=...`. */
  def fixtureLine(proof: String): String = lines(proof, "^fixture ops".r).mkString(" ")

  /** The read-back's failing line, cut to the width a row quotes. */
  def verdict(text: String): String = lines(text, "ok=0".r).map(_.take(70)).mkString(" ")

  /** A session as the launcher records it for the reconcile, read back as `NAME cgroup=PATH cgroup_id=ID`. */
  case class SessionRecord(name: String, cgroup: String, cgroupId: String)

  def parseRecords(text: String): Seq[SessionRecord] =
    text.linesIterator
      .map(_.trim.split("\\s+").toSeq)
      .collect:
        case Seq(name, rest*) if rest.length >= 2 =>
          SessionRecord(name, field("cgroup", rest.mkString(" ")), field("cgroup_id", rest.mkString(" ")))
      .toSeq

  /** The containers' labels, `SESSION CGROUP` a line, as the session's name to the cgroup it names. */
  def parseLabels(text: String): Map[String, String] =
    text.linesIterator
      .map(_.trim.split("\\s+").toSeq)
      .collect:
        case Seq(name, cgroup, _*) => name -> cgroup
      .toMap

  /** The controller's reconcile arguments for the recorded sessions: a session some container names with
    * the recorded cgroup is kept (`--named`), one whose container's label names another cgroup is held
    * (`--hold`), and each is given with its recorded cgroup and identity ("Lifecycle", 7). */
  def reconcileArguments(records: Seq[SessionRecord], labels: Map[String, String]): Seq[String] =
    records.flatMap: record =>
      val association = labels.get(record.name) match
        case None => Seq.empty
        case Some(cgroup) if cgroup == record.cgroup => Seq("--named", record.name)
        case Some(_) => Seq("--hold", record.name)
      association ++ Seq("--session", record.name, record.cgroup, record.cgroupId)

  /** What the reconcile did with SESSION, and the reason it gives. */
  def actionOf(reconciled: String, session: String): String =
    raw"(?m)^reconcile session=${Regex.quote(session)} action=(\S+)".r.findFirstMatchIn(reconciled)
      .map(_.group(1)).getOrElse("")

  def reasonOf(reconciled: String, session: String): String =
    raw"(?m)^reconcile session=${Regex.quote(session)} .*reason=(\S+)".r.findFirstMatchIn(reconciled)
      .map(_.group(1)).getOrElse("")

  // --- The run ---------------------------------------------------------------------------------------------

  val VmDir = ".local/share/ko-agent-sandbox/bpf-probe4"
  val Controller = s"./$VmDir/controller"
  val Readback = s"./$VmDir/readback"
  val Fixture = s"./$VmDir/fixture"
  /** The fixture binary in the session container, where the probe image holds it. */
  val FixtureInContainer = "/out/fixture"
  val Tags = s"./$VmDir/tags.txt"
  val PinRoot = "/sys/fs/bpf/ko-agent-bpf-phase4"
  val ProbeImage = "ko-agent-bpf-probe:phase4"
  /** What the attach cgroups, their hold units, the volume and the extraction container are named after. */
  val Prefix = "ko-agent-bpf4"
  val Volume = s"$Prefix-vol"
  /** The labels a session's container carries, as the launcher's do: the session's name and its cgroup. */
  val Label = s"$Prefix.session"
  val CgroupLabel = s"$Prefix.cgroup"
  val Hooks7 = Hooks8.filterNot(_ == "inode_setattr")

  /** How a launch treats the session's pins: removed first, or reused when the read-back's check passes. */
  enum Mode:
    case Fresh, Restart

  /** The step a launch reached: where it stopped, or `Started`. */
  enum Reached:
    case Attach, Verify, Proof, Created, Started
    def label: String = toString.toLowerCase

  /** What a launch printed at each step it reached. */
  case class Launched(
      cgroup: Cgroup,
      reached: Reached,
      attach: String,
      check: String,
      verify: String = "",
      proof: String = "",
  )

  /** A rule file and the records `fixture records` compiled from it, as machine paths. */
  case class RuleSet(rules: String, records: String)

  /** The fixtures on the share, as machine paths: the workspace tree, the proof fixture, the two rule sets
    * and the volume's mountpoint. */
  case class Workspace(tree: String, proof: String, a: RuleSet, b: RuleSet, volumeMountpoint: String):
    /** The records and the four roots of a launch under the rule set, as the controller takes them. */
    def roots(ruleSet: RuleSet): String =
      s"--records ${quoted(ruleSet.records)} --workspace ${quoted(tree)} --fixture ${quoted(proof)} " +
        s"--volume ${quoted(volumeMountpoint)}"
    /** What the read-back expects of a launch under the rule set. */
    def expect(ruleSet: RuleSet): String = s"--tags $Tags ${roots(ruleSet)}"

  /** What the run leaves beside its containers: the mounts, the pins, the attach cgroups with their units,
    * the session records, the volume and the scratch directory. */
  def removeLeftovers(platform: Platform, scratchDir: Path, transcript: Transcript, vm: Vm): Unit =
    val scratchDirVm = vmPath(platform, scratchDir.toString)
    vm(sh(
      s"sudo -n umount $PinRoot/r4 2>/dev/null",
      s"sudo -n umount ${quoted(s"$scratchDirVm/tree/vendor")} 2>/dev/null",
      s"[ -x $Controller ] && ${unpinEvery(Controller, PinRoot)}",
      s"sudo -n rmdir $PinRoot 2>/dev/null",
      s"systemctl --user stop '$Prefix-*' 2>/dev/null",
      "systemctl --user reset-failed 2>/dev/null",
      s"rmdir $AppSliceGlob/$Prefix-*/proof 2>/dev/null",
      s"rmdir $AppSliceGlob/$Prefix-* 2>/dev/null",
      s"rm -rf $VmDir/sessions ${quoted(scratchDirVm)}",
      "true",
    ))
    host(transcript, Seq("podman", "volume", "rm", "-f", Volume))
    removeTree(platform, scratchDir)

  def run(args: Seq[String]): Unit =
    val options = orExit(parseOptions(args))
    val platform = orExit(Platform.resolve(options.platform))
    val repoDir = orExit(repositoryRoot("bpf/probe/phase4/sources.txt", "bpf/probe/phase4/Containerfile"))
    val probeDir = repoDir / "bpf" / "probe" / "phase4"
    val out = options.out.getOrElse(probeDir / platform.outDir)
    Files.createDirectories(out)
    val transcript = Transcript(out / "transcript.log")
    val vm = Vm(transcript)
    // Under the repository's ignored tmp/, on the share the machine mounts, as Phases 3 and 5 keep theirs.
    val scratchDir = repoDir / "tmp" / s"ko-agent-bpf-phase4.${ProcessHandle.current().pid()}"
    val cleanup = Cleanup(transcript, Label, () => removeLeftovers(platform, scratchDir, transcript, vm))
    runMeasured(transcript, cleanup):
      Measurement(platform, probeDir, repoDir, out, transcript, vm, scratchDir).measure()

  /** The phase as steps, each `Right` with what the next needs or `Left` with the exit status after it
    * said why: 2 for a refusal before any row is measured. The rows after the preparation run to the end
    * whatever they record. */
  class Measurement(
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

    def measure(): Int =
      val outcome =
        for
          facts <- readVmFacts(transcript, vm, out, scratchDir, scratchDirVm, PinRoot)
          tags <- buildAndInstall(facts)
        yield
          Lifecycle(facts, prepareWorkspace(), tags).rows()
          if transcript.failed == 0 then 0 else 1
      outcome.merge

    def buildAndInstall(facts: VmFacts): Either[Int, Output] =
      step("build, with the hash of its sources, and install")
      val procedure = procedureSha(transcript, Seq(
        probeDir / "Phase4.scala",
        repoDir / "bpf" / "probe" / "ProbeHelper.scala",
        repoDir / RuleDefaults,
      ))
      for sourcesSha <- buildProbeImage(transcript, probeDir, scratchDir, ProbeImage, facts.kernel)
      yield
        val installed = installProbe(vm, ProbeImage, VmDir, Prefix, Seq("controller", "readback", "fixture"))
        // The installed object kept aside: the rows of a new build put another in its place, then restore it.
        val kept = vm(s"cp $VmDir/policy.bpf.o $VmDir/policy-installed.bpf.o")
        check("probe installed in the machine", installed.ok && kept.ok)
        val leftover = vm(sh(s"sudo -n ls $PinRoot", unpinEvery(Controller, PinRoot)))
          .text.linesIterator.filter(line => line.nonEmpty && !line.startsWith("unpinned")).toSeq
        if leftover.nonEmpty then info(s"pins left by an earlier run, removed: ${leftover.mkString(" ")}")
        recordBuild(transcript, vm, out, VmDir, Seq(s"sources sha256=$sourcesSha", s"procedure sha256=$procedure"))
        recordTags(transcript, vm, Readback, Tags)

    def prepareWorkspace(): Workspace =
      step("the workspace fixture, the proof fixture, the records and the volume")
      // The rules: the launcher's defaults and an overlapping pair on purpose, the defaults' `read-only
      // .vscode` and a later `writable .vscode/settings.json`. B lacks the later line: another rule file,
      // whose records differ from A's, and under which A's proof fixture fails one expectation.
      val rulesB = stripRules(Files.readString(repoDir / RuleDefaults))
      val rulesA = rulesB :+ "writable .vscode/settings.json"
      Files.writeString(scratchDir / "rules-a.txt", rulesA.mkString("", "\n", "\n"))
      Files.writeString(scratchDir / "rules-b.txt", rulesB.mkString("", "\n", "\n"))
      val a = RuleSet(s"$scratchDirVm/rules-a.txt", s"$scratchDirVm/records-a.bin")
      val b = RuleSet(s"$scratchDirVm/rules-b.txt", s"$scratchDirVm/records-b.bin")
      val tree = s"$scratchDirVm/tree"
      val proof = s"$scratchDirVm/state/proof"
      val made = vm(
        s"$Fixture make ${quoted(tree)} ${quoted(a.rules)} && mkdir -p ${quoted(s"$scratchDirVm/state")} && " +
          s"$Fixture make ${quoted(proof)} ${quoted(a.rules)} && " +
          s"$Fixture records ${quoted(a.rules)} ${quoted(a.records)} $GuardedOptions && " +
          s"$Fixture records ${quoted(b.rules)} ${quoted(b.records)} $GuardedOptions",
      )
      transcript.indent(made.text)
      check(
        "the workspace fixture, the proof fixture and two records files exist",
        lines(made.text, "^make ".r).length == 2 && lines(made.text, "^records ".r).length == 2,
      )
      host(transcript, Seq("podman", "volume", "create", Volume))
      val volumeMountpoint = vm.line(s"podman volume inspect --format '{{.Mountpoint}}' $Volume")
      info(
        s"the volume's mountpoint in the machine: $volumeMountpoint, on " +
          vm.line(s"findmnt -T ${quoted(volumeMountpoint)} -n -o FSTYPE"),
      )
      Workspace(tree, proof, a, b, volumeMountpoint)

    /** The rows after the preparation: launches through the launcher's steps, the reconcile and the
      * machine restart, with the state they share, the proof fixture's layout. */
    class Lifecycle(facts: VmFacts, workspace: Workspace, tags: Output):
      private val tree = workspace.tree
      private val hooks8 = Hooks8.mkString(" ")
      /** --userns=keep-id so files on the share are the user's; the scratch directory at its machine path and
        * the volume at /vol. */
      private val sessionOptions = Seq("--userns=keep-id", "--security-opt", "seccomp=unconfined",
        s"--volume=$scratchDir:$scratchDirVm", s"--volume=$Volume:/vol")
      /** The session's first process: a protected write, refused, and an ordinary one, then it waits. */
      private val sessionCommand =
        s"echo STARTED; $FixtureInContainer write ${quoted(s"$tree/.git/config")}; " +
          s"$FixtureInContainer write ${quoted(s"$tree/ordinary")}; exec sleep infinity"
      // The proof fixture is laid out once; its entries are laid out again, the root keeping its identity,
      // only after a failed proof or for other rules ("Lifecycle", 3).
      private var proofLaidFor = workspace.a.rules
      private var proofDirty = false

      private def podman(args: String*): Output = host(transcript, "podman" +: args)
      private def state(name: String): String = podman("inspect", "--format", "{{.State.Status}}", name).text.trim
      private def running(name: String): String = podman("inspect", "--format", "{{.State.Running}}", name).text.trim
      private def execWrite(name: String, path: String): Output =
        podman("exec", name, FixtureInContainer, "write", path)

      /** The container's log once it holds LINE_COUNT lines with NEEDLE, or after 20 s. */
      private def waitLogs(name: String, needle: String, lineCount: Int): String =
        def logs(record: Boolean): String = host(transcript, Seq("podman", "logs", name), record = record).text
        @tailrec def poll(tries: Int): Unit =
          if tries < 40 && count(logs(record = false), needle) < lineCount then
            Thread.sleep(500)
            poll(tries + 1)
        poll(0)
        logs(record = true)

      private def attach(name: String): Cgroup =
        val cgroup = attachCgroup(vm, facts.manager, facts.uid, Prefix, name)
        if cgroup.path.nonEmpty then cgroup
        else
          transcript.fail(s"no attach cgroup for $name")
          cgroup.copy(path = "/nonexistent")
      private def remove(name: String): Unit = removeCgroup(vm, facts.manager, facts.uid, Prefix, name)
      private def cgroupId(path: String): String = vm.line(s"stat -c %i $path")
      private def unpin(name: String): Unit = vm(s"sudo -n $Controller unpin $PinRoot/$name")
      /** What the launcher records for the reconcile: the cgroup's path and identity. */
      private def recordSession(name: String, cgroup: Cgroup): Unit =
        vm(s"mkdir -p $VmDir/sessions && echo 'cgroup=${cgroup.path} cgroup_id=${cgroupId(cgroup.path)}' > " +
          s"$VmDir/sessions/$name")
      private def forgetSession(name: String): Unit = vm(s"rm -f $VmDir/sessions/$name")
      /** Step 2 alone, under rule set A, as the reconcile rows make their pins. */
      private def attachController(name: String, cgroup: Cgroup): Unit =
        vm(s"sudo -n $Controller attach ${cgroup.path} $PinRoot/$name ${workspace.roots(workspace.a)} $hooks8")

      private def layOutProof(rules: String): Unit =
        if proofDirty || proofLaidFor != rules then
          vm(s"find ${quoted(workspace.proof)} -mindepth 1 -delete && $Fixture make ${quoted(workspace.proof)} " +
            quoted(rules))
          proofLaidFor = rules
          proofDirty = false

      private def prove(cgroup: Cgroup, rules: String, unixSocket: Boolean): String =
        val flags = if unixSocket then Seq("--unix-socket") else Seq.empty
        val proved = runProof(vm, facts.manager, cgroup, Fixture, workspace.proof, rules, flags).text
        transcript.indent(lines(proved, "mismatch|^fixture ops".r).mkString("\n"))
        proved

      /** Steps 1 to 4 of "Lifecycle" for session NAME under the rule set: the attach cgroup, the
        * controller's attach with pins, which a restart reuses when the read-back's check passes them, the
        * read-back, the proof, then the container created and started. The read-back expects the eight
        * hooks, or the nine under --unix-socket, of the installed tags over the rule set's records; DEFECT
        * and HOOKS make the controller deviate from that. No container is created once a step fails. */
      def launch(name: String, mode: Mode, ruleSet: RuleSet = workspace.a, defect: String = "",
          hooks: Seq[String] = Hooks8, unixSocket: Boolean = false): Launched =
        val cgroup = attach(name)
        val pins = s"$PinRoot/$name"
        val flags = if unixSocket then " --flags unix-socket" else ""
        val expectation =
          s"${workspace.expect(ruleSet)}$flags ${(if unixSocket then Hooks9 else Hooks8).mkString(" ")}"
        layOutProof(ruleSet.rules)
        val checked = if mode == Mode.Restart then vm(s"sudo -n $Readback check-pins $pins $expectation").text else ""
        val reuse = checked.contains(" ok=1")
        if !reuse then unpin(name)
        val attached =
          if reuse then vm(s"sudo -n $Controller attach-pinned ${cgroup.path} $pins ${hooks.mkString(" ")}").text
          else
            vm(s"sudo -n $Controller attach ${cgroup.path} $pins ${workspace.roots(ruleSet)}$flags $defect " +
              hooks.mkString(" ")).text
        transcript.indent(lines(attached, "^(attach|attach-pinned|refused) ".r).mkString("\n"))
        val atAttach = Launched(cgroup, Reached.Attach, attached, checked)
        val outcome =
          for
            _ <- Either.cond(lines(attached, "^attach".r).nonEmpty, (), atAttach)
            verified = vm(s"sudo -n $Readback verify ${cgroup.path} $expectation").text
            _ = transcript.indent(verified)
            atVerify = atAttach.copy(reached = Reached.Verify, verify = verified)
            _ <- Either.cond(verified.contains("verify ok=1"), (), atVerify)
            atProof = atVerify.copy(reached = Reached.Proof, proof = prove(cgroup, ruleSet.rules, unixSocket))
            _ <- Either.cond(field("mismatches", atProof.proof) == "0", (), atProof)
            atCreated = atProof.copy(reached = Reached.Created)
            created = podman(
              Seq("create", "--name", name, "--restart=no", s"--cgroup-parent=${cgroup.parent}", "--label",
                s"$Label=$name", "--label", s"$CgroupLabel=${cgroup.path}") ++ sessionOptions ++
                Seq(ProbeImage, "sh", "-c", sessionCommand)*,
            )
            _ <- Either.cond(created.ok, (), atCreated)
            _ = recordSession(name, cgroup)
            _ <- Either.cond(podman("start", name).ok, (), atCreated)
          yield atCreated.copy(reached = Reached.Started)
        val launched = outcome.merge
        if launched.reached == Reached.Proof then proofDirty = true
        launched

      def rows(): Unit =
        val first = firstLaunch()
        val recreated = recreate()
        defectiveControllers()
        unixSocketLaunch()
        pinsAcrossChanges()
        controllerRefusals()
        reconcileRows()
        costs(first, recreated)
        machineRestart()

      def firstLaunch(): Launched =
        step("the launch: steps 1 to 4, the first process refused, exec, restart, kill, the controller gone")
        val s1 = launch("s1", Mode.Fresh)
        check(
          s"the launch ran every step: attach, read-back, proof, create, start (reached ${s1.reached.label})",
          s1.reached == Reached.Started,
        )
        check(
          s"the controller attached eight hooks with ${field("rule_count", s1.attach)} rules and five roots, " +
            "and pinned",
          field("hooks", s1.attach) == "8" && field("roots", s1.attach) == "5",
        )
        check(
          "the read-back finds eight programs of the installed tags over one map set holding the records",
          field("programs", s1.verify) == "8" && field("maps", s1.verify) == "9",
        )
        check(
          s"the proof: ${fixtureLine(s1.proof)}",
          field("mismatches", s1.proof) == "0" && number("ops", s1.proof) > 60,
        )
        val logs = waitLogs("s1", "result=", 2)
        check(
          "the first process is refused the protected write and makes the ordinary one",
          logs.contains(".git/config result=EPERM") && logs.contains("tree/ordinary result=ok"),
        )
        // The link's cgroup id is the attach cgroup's inode number: the identity the reconcile records.
        val s1Id = cgroupId(s1.cgroup.path)
        check(
          s"the links carry the attach cgroup's identity, its inode number $s1Id",
          field("cgroup_id", s1.attach) == s1Id,
        )
        check(
          "the controller has exited and no process of it remains while the policy holds",
          vm("pgrep -x controller >/dev/null && echo RUNNING || echo NONE").has("NONE"),
        )
        check(
          "podman exec joins the container's cgroup and is refused the protected write",
          execWrite("s1", s"$tree/.git/config").has("result=EPERM"),
        )
        // The socket rule's dependence on the mounts ("The policy"): a directory under the container's own
        // filesystem holding a bound socket cannot be moved into the volume or the workspace.
        val sock = podman("exec", "s1", "sh", "-c",
          s"mkdir -p /tmp/d && $FixtureInContainer bind /tmp/d/s; $FixtureInContainer rename /tmp/d /vol/d; " +
            s"$FixtureInContainer rename /tmp/d ${quoted(s"$tree/d")}").text
        check(
          "a directory holding a bound socket cannot be renamed into the volume or the workspace: EXDEV",
          count(sock, "result=EXDEV") == 2 && sock.contains("bind path=/tmp/d/s result=ok"),
        )
        podman("restart", "s1")
        val restarted = waitLogs("s1", "STARTED", 2)
        check(
          "after podman restart the first process runs again under the policy and is refused again",
          count(restarted, "STARTED") == 2 && count(restarted, ".git/config result=EPERM") == 2,
        )
        podman("kill", "s1")
        Thread.sleep(1000)
        val query = vm(s"sudo -n $Controller query ${s1.cgroup.path}").text
        val link = vm(s"sudo -n $Controller link-info $PinRoot/s1/links/file_open").text
        check(
          s"after podman kill the container is exited and the programs stay attached: ${field("prog_cnt", query)}",
          state("s1") == "exited" && field("prog_cnt", query) == "8",
        )
        check(s"the pinned link still names the cgroup: ${oneLine(link)}", field("cgroup_id", link) == s1Id)
        check(
          "the created container's restart policy reads no",
          podman("inspect", "--format", "{{.HostConfig.RestartPolicy.Name}}", "s1").text.trim == "no",
        )
        // The policy cannot lapse without a trusted hand: the cgroup with the container's scope in it is not
        // removable, and only root's unpin ends the enforcement.
        podman("start", "s1")
        val rmdir = vm(s"sudo -n rmdir ${s1.cgroup.path} 2>&1 || echo RMDIR_FAILED").text
        check(
          s"the attach cgroup cannot be removed while the container is in it: ${oneLine(rmdir)}",
          rmdir.contains("RMDIR_FAILED"),
        )
        unpin("s1")
        val unpinned = vm(s"sudo -n $Controller query ${s1.cgroup.path}").text
        val afterUnpin = execWrite("s1", s"$tree/.git/config")
        check(
          "root unpinning the links ends the enforcement: 0 programs attached, the protected write succeeds",
          field("prog_cnt", unpinned) == "0" && afterUnpin.has("result=ok"),
        )
        podman("rm", "-f", "s1")
        forgetSession("s1")
        remove("s1")
        s1

      def recreate(): Launched =
        step("a recreate attaches the pinned programs and loads nothing")
        val fresh = launch("s2", Mode.Fresh)
        check(s"s2 launched fresh (reached ${fresh.reached.label})", fresh.reached == Reached.Started)
        podman("rm", "-f", "s2")
        remove("s2")
        val link = vm(s"sudo -n $Controller link-info $PinRoot/s2/links/file_open").text
        check(
          "with its cgroup removed the pinned link is detached, cgroup_id 0, and the pinned programs stay",
          field("cgroup_id", link) == "0" &&
            vm.line(s"sudo -n test -e $PinRoot/s2/progs/file_open && echo PRESENT") == "PRESENT",
        )
        val s2 = launch("s2", Mode.Restart)
        check(
          s"the recreate checked the pins, attached them to the new cgroup and started (reached ${s2.reached.label})",
          s2.check.contains("check-pins ok=1") && s2.reached == Reached.Started &&
            lines(s2.attach, "^attach-pinned ".r).nonEmpty,
        )
        val logs = waitLogs("s2", "result=", 2)
        check(
          "the recreated session's first process is refused the protected write",
          logs.contains(".git/config result=EPERM"),
        )
        podman("rm", "-f", "s2")
        forgetSession("s2")
        remove("s2")
        s2

      def defectiveControllers(): Unit =
        step("the defective controllers, each caught before any container exists")
        // No container is created when a step before 4 fails; each launch ends at the read-back.
        def caught(name: String, description: String, launched: Launched, reason: String): Unit =
          check(
            s"$description: ${verdict(launched.verify)}",
            launched.reached == Reached.Verify && field("reason", launched.verify) == reason,
          )
          check(s"no container $name exists", !podman("container", "exists", name).ok)
        val d1 = launch("d1", Mode.Fresh, hooks = Hooks7)
        caught("d1", "a controller attaching seven of the eight hooks is caught by the read-back", d1, "hook-set")
        unpin("d1")
        remove("d1")
        val d2 = launch("d2", Mode.Fresh, defect = "--object other.bpf.o")
        caught("d2", "a controller attaching another build's programs is caught by their tags", d2, "tag")
        unpin("d2")
        remove("d2")
        val d3 = launch("d3", Mode.Fresh, defect = s"--records ${quoted(workspace.b.records)}")
        caught("d3", "a controller loading another rule file's records is caught by the map contents", d3,
          "map-contents")
        // The proof alone would catch the records too: one expectation of A's fixture fails under B.
        val proofB = prove(d3.cgroup, workspace.a.rules, unixSocket = false)
        proofDirty = true
        check(
          s"the proof fixture catches the wrong records as well: ${fixtureLine(proofB)}",
          field("mismatches", proofB) == "1",
        )
        unpin("d3")
        remove("d3")
        val d4 = launch("d4", Mode.Fresh, defect = "--object other-data.bpf.o")
        caught("d4", "a controller attaching a build differing in data alone", d4, "rodata")
        unpin("d4")
        remove("d4")

      def unixSocketLaunch(): Unit =
        step("a launch under --unix-socket: nine hooks, the proof's socket in .git and file_receive")
        val u1 = launch("u1", Mode.Fresh, hooks = Hooks9, unixSocket = true)
        check(
          s"the launch under unix-socket ran every step with nine hooks (reached ${u1.reached.label})",
          u1.reached == Reached.Started && field("programs", u1.verify) == "9",
        )
        check(
          "the proof refused a socket in .git and a directory descriptor from another mount namespace",
          u1.proof.contains("op=bind path=.git/ko+sock expect=EPERM got=EPERM") &&
            u1.proof.contains("op=receive-dir path=. expect=refused got=refused"),
        )
        podman("rm", "-f", "u1")
        forgetSession("u1")
        unpin("u1")
        remove("u1")

      def pinsAcrossChanges(): Unit =
        step("pins across a rule change and a new build")
        def freshStart(launched: Launched): Boolean =
          launched.reached == Reached.Started && lines(launched.attach, "^attach ".r).nonEmpty
        val fresh = launch("s3", Mode.Fresh)
        check(s"s3 launched fresh (reached ${fresh.reached.label})", fresh.reached == Reached.Started)
        podman("rm", "-f", "s3")
        remove("s3")
        // A rule change: the pinned programs hold A's records, this launch wants B's, and its proof fixture
        // and expectations follow B.
        val ruleChange = launch("s3", Mode.Restart, workspace.b)
        check(
          s"after a rule change the pins fail the check and fresh programs are loaded: ${verdict(ruleChange.check)}",
          field("reason", ruleChange.check) == "map-contents" && freshStart(ruleChange),
        )
        check(
          s"the fresh programs are new: prog_id ${field("prog_id", ruleChange.attach)} after " +
            field("prog_id", fresh.attach),
          field("prog_id", ruleChange.attach) != field("prog_id", fresh.attach),
        )
        podman("rm", "-f", "s3")
        remove("s3")
        // A new build installed: the other object takes the installed one's place and its tags are recorded.
        vm(s"cp $VmDir/other.bpf.o $VmDir/policy.bpf.o && sudo -n $Readback tags policy.bpf.o $Tags")
        val newBuild = launch("s3", Mode.Restart, workspace.b)
        check(
          s"after a new build the pins fail the check on their tags and fresh programs are loaded: " +
            verdict(newBuild.check),
          field("reason", newBuild.check) == "tag" && freshStart(newBuild),
        )
        check(
          s"the fresh programs are the new build's, prog_id ${field("prog_id", newBuild.attach)} after " +
            s"${field("prog_id", ruleChange.attach)}, verified",
          field("prog_id", newBuild.attach) != field("prog_id", ruleChange.attach) &&
            field("programs", newBuild.verify) == "8",
        )
        val pinCount = vm.line(s"sudo -n ls $PinRoot/s3/links $PinRoot/s3/progs | grep -c -v -e '^$$' -e ':$$'")
        check(
          "the old pins are gone: the pin directory holds the eight links and eight programs of this launch alone",
          pinCount == "16",
        )
        podman("rm", "-f", "s3")
        forgetSession("s3")
        unpin("s3")
        remove("s3")
        vm(s"cp $VmDir/policy-installed.bpf.o $VmDir/policy.bpf.o && sudo -n $Readback tags policy.bpf.o $Tags")

      def controllerRefusals(): Unit =
        step("the controller's refusals")
        val x1 = attach("x1")
        def refused(description: String, arguments: String, reason: String): Unit =
          val answer =
            lines(vm(s"sudo -n $Controller $arguments; echo STATUS=$$?").text, "^(refused|STATUS)".r).mkString(" ")
          check(s"$description: $answer", field("reason", answer) == reason && field("STATUS", answer) == "3")
        val rootsA = workspace.roots(workspace.a)
        refused("an object given as a path is refused",
          s"attach ${x1.path} $PinRoot/x1 $rootsA --object /tmp/other.bpf.o $hooks8", "object-path")
        refused("a cgroup outside the invoking user's slice is refused",
          s"attach /sys/fs/cgroup/system.slice $PinRoot/x1 $rootsA $hooks8", "cgroup-outside-slice")
        val vendor = quoted(s"$tree/vendor")
        vm(s"mkdir -p $vendor && sudo -n mount -t tmpfs tmpfs $vendor")
        refused("a mount under the bind source refuses the launch and is named",
          s"attach ${x1.path} $PinRoot/x1 $rootsA --bind-source ${quoted(tree)} $hooks8", "mount-under-bind-source")
        vm(s"sudo -n umount $vendor")
        refused("a proof fixture on another filesystem type is refused",
          s"attach ${x1.path} $PinRoot/x1 --records ${quoted(workspace.a.records)} --workspace ${quoted(tree)} " +
            s"--fixture /tmp --volume ${quoted(workspace.volumeMountpoint)} $hooks8", "fixture-fs-type")
        check(
          "none of the refused attaches pinned anything",
          vm.line(s"sudo -n test -e $PinRoot/x1 && echo PRESENT || echo ABSENT") == "ABSENT",
        )
        remove("x1")

      /** The launcher's start: the recorded sessions, the containers by their labels, then the controller. A
        * session without a container has its hold unit stopped first, so that the hold does not count as
        * populated ("Lifecycle", 7). A listing or a label read that fails tells the controller so, which then
        * removes nothing; LISTING_FAILS makes the listing fail. The controller's output, after the slices it
        * names are stopped and the sessions it removed are forgotten. */
      private def reconcile(listingFails: Boolean = false): String =
        val records = parseRecords(
          vm(s"cd $VmDir/sessions 2>/dev/null && for f in *; do [ -f $$f ] && echo $$f $$(cat $$f); done").text,
        )
        // `podman ps` renders .Labels as text, so the labels are read from each container's inspect. The keys
        // are Go raw strings in backquotes, since a double quote does not reach the machine from Windows.
        val format = s"{{index .Config.Labels `$Label`}} {{index .Config.Labels `$CgroupLabel`}}"
        val listCommand = if listingFails then "false" else s"podman ps -aq --filter label=$Label"
        val listing = vm(
          s"ids=$$($listCommand) || exit 9; for id in $$ids; do podman inspect --format '$format' $$id || exit 9; " +
            "done; echo LISTING_OK",
        ).text
        val listed = listing.contains("LISTING_OK")
        val labels = if listed then parseLabels(listing) else Map.empty[String, String]
        if listed then
          records.filterNot(record => labels.contains(record.name))
            .foreach(record => releaseHold(vm, facts.manager, Prefix, record.name))
        // A stopped hold unit leaves its slice; populated follows within the second.
        Thread.sleep(1000)
        val arguments =
          Seq("--manager", facts.manager) ++ Option.when(!listed)("--listing-failed") ++
            reconcileArguments(records, labels)
        val reconciled = vm(s"sudo -n $Controller reconcile $PinRoot ${arguments.mkString(" ")}").text
        transcript.indent(reconciled)
        raw"cgroup=stop-slice slice=(\S+)".r.findAllMatchIn(reconciled)
          .foreach(found => vm(s"systemctl --user stop ${found.group(1)}"))
        raw"(?m)^reconcile session=(\S+) action=removed".r.findAllMatchIn(reconciled)
          .foreach(found => forgetSession(found.group(1)))
        reconciled

      def reconcileRows(): Unit =
        step("the reconcile: orphans, kept sessions, contradictions, cleanup refusals")
        // o1: the launcher killed between the pins and podman create.
        val o1 = attach("o1")
        attachController("o1", o1)
        recordSession("o1", o1)
        // o2: podman create fails after the pins.
        val o2 = attach("o2")
        attachController("o2", o2)
        recordSession("o2", o2)
        val missingImage = podman("create", "--name", "o2", s"--cgroup-parent=${o2.parent}", "--label", s"$Label=o2",
          "--label", s"$CgroupLabel=${o2.path}", s"localhost/$Prefix-no-such-image:none", "true")
        if missingImage.ok then transcript.fail("podman create of a missing image worked")
        // o3: the launcher killed between podman create and podman start.
        val o3 = attach("o3")
        attachController("o3", o3)
        recordSession("o3", o3)
        podman(
          Seq("create", "--name", "o3", "--restart=no", s"--cgroup-parent=${o3.parent}", "--label", s"$Label=o3",
            "--label", s"$CgroupLabel=${o3.path}") ++ sessionOptions ++ Seq(ProbeImage, "sh", "-c", sessionCommand)*,
        )
        // st: a stopped session; lv: a live one.
        launch("st", Mode.Fresh)
        podman("kill", "st")
        launch("lv", Mode.Fresh)
        check(
          "the reconcile's sessions exist: o1, o2, o3, st stopped, lv live",
          state("st") == "exited" && state("lv") == "running",
        )
        val failedListing = reconcile(listingFails = true)
        check(
          s"a listing that fails removes nothing: ${lines(failedListing, "^reconcile listing".r).mkString(" ")}",
          field("removed", failedListing) == "0" && failedListing.contains("listing=failed"),
        )
        val orphans = reconcile()
        check(
          s"the two orphans are removed, pins and cgroups: o1 ${actionOf(orphans, "o1")}, " +
            s"o2 ${actionOf(orphans, "o2")}",
          actionOf(orphans, "o1") == "removed" && actionOf(orphans, "o2") == "removed",
        )
        check(
          s"o3 (a created container), st (stopped) and lv (live) stay: ${actionOf(orphans, "o3")} " +
            s"${actionOf(orphans, "st")} ${actionOf(orphans, "lv")}",
          Seq("o3", "st", "lv").forall(session => actionOf(orphans, session) == "kept"),
        )
        check(
          s"nothing else was removed: ${lines(orphans, "^reconcile sessions".r).mkString(" ")}",
          field("removed", orphans) == "2",
        )
        check(
          "o1's and o2's pins and cgroups are gone, o3's and st's stay",
          vm.line(s"sudo -n ls -d $PinRoot/o1 $PinRoot/o2 2>/dev/null | wc -l | tr -d ' '") == "0" &&
            vm.line(s"sudo -n ls -d $PinRoot/o3 $PinRoot/st 2>/dev/null | wc -l | tr -d ' '") == "2",
        )
        podman("rm", "o3")
        val createdGone = reconcile()
        check(
          s"once its container is removed, o3's pins and cgroup go: ${actionOf(createdGone, "o3")}",
          actionOf(createdGone, "o3") == "removed",
        )
        contradictions()
        refusalsRemoveNothing()
        cleanupRefusals()

      /** c1, a container whose labels name another session's cgroup; c2, a cgroup whose identity changed
        * since the record; c4, a pin directory whose links name another cgroup. */
      private def contradictions(): Unit =
        val c1 = attach("c1")
        attachController("c1", c1)
        recordSession("c1", c1)
        podman("create", "--name", "c1", s"--cgroup-parent=${c1.parent}", "--label", s"$Label=c1", "--label",
          s"$CgroupLabel=/elsewhere", ProbeImage, "true")
        val c2 = attach("c2")
        attachController("c2", c2)
        recordSession("c2", c2)
        val c2Id = cgroupId(c2.path)
        remove("c2")
        val c2Again = attach("c2")
        info(s"c2's cgroup recreated at its path: identity $c2Id before, ${cgroupId(c2Again.path)} after")
        val c3 = attach("c3")
        attachController("c3", c3)
        val c4 = attach("c4")
        vm(s"sudo -n mv $PinRoot/c3 $PinRoot/c4")
        recordSession("c4", c4)
        val reconciled = reconcile()
        check(
          s"a container whose label names another cgroup leaves c1 unassociated and kept: " +
            s"${actionOf(reconciled, "c1")} ${reasonOf(reconciled, "c1")}",
          actionOf(reconciled, "c1") == "kept" && reasonOf(reconciled, "c1") == "identity-contradicted",
        )
        check(
          s"a cgroup whose identity changed is refused: ${actionOf(reconciled, "c2")} ${reasonOf(reconciled, "c2")}",
          actionOf(reconciled, "c2") == "refused" && reasonOf(reconciled, "c2") == "cgroup-identity",
        )
        check(
          s"a pin directory whose links name another cgroup is refused: ${actionOf(reconciled, "c4")} " +
            reasonOf(reconciled, "c4"),
          actionOf(reconciled, "c4") == "refused" && reasonOf(reconciled, "c4") == "pin-names-another-cgroup",
        )
        check("nothing was removed for them", field("removed", reconciled) == "0")
        podman("rm", "-f", "c1")
        vm(sh(
          s"sudo -n $Controller unpin $PinRoot/c1",
          s"sudo -n $Controller unpin $PinRoot/c2",
          s"sudo -n $Controller unpin $PinRoot/c4",
          s"rm -f $VmDir/sessions/c1 $VmDir/sessions/c2 $VmDir/sessions/c4",
        ))
        Seq("c1", "c2", "c3", "c4").foreach(remove)

      /** A refusal removes nothing: c5's links hold one of c6's among their own, and c7's progs directory is a
        * symlink; every pin of both must survive the reconcile. */
      private def refusalsRemoveNothing(): Unit =
        val c5 = attach("c5")
        attachController("c5", c5)
        recordSession("c5", c5)
        val c6 = attach("c6")
        attachController("c6", c6)
        vm(s"sudo -n mv $PinRoot/c6/links/inode_setattr $PinRoot/c5/links/zz-foreign")
        val c7 = attach("c7")
        attachController("c7", c7)
        recordSession("c7", c7)
        vm(s"sudo -n mv $PinRoot/c7/progs $PinRoot/c7/progs-real && sudo -n ln -s progs-real $PinRoot/c7/progs")
        val reconciled = reconcile()
        def pinsOf(session: String, kind: String): String =
          vm.line(s"sudo -n sh -c 'ls $PinRoot/$session/$kind 2>/dev/null | wc -l'").trim
        check(
          s"one foreign link among a session's pins refuses it: ${actionOf(reconciled, "c5")} " +
            reasonOf(reconciled, "c5"),
          actionOf(reconciled, "c5") == "refused" && reasonOf(reconciled, "c5") == "pin-names-another-cgroup",
        )
        check(
          s"and every pin of c5 survives: ${pinsOf("c5", "links")} links, ${pinsOf("c5", "progs")} programs",
          pinsOf("c5", "links") == "9" && pinsOf("c5", "progs") == "8",
        )
        check(
          s"a progs directory that is a symlink refuses the session: ${actionOf(reconciled, "c7")} " +
            reasonOf(reconciled, "c7"),
          actionOf(reconciled, "c7") == "refused" && reasonOf(reconciled, "c7") == "pins-open",
        )
        check(s"and every link of c7 survives: ${pinsOf("c7", "links")} links", pinsOf("c7", "links") == "8")
        vm(sh(
          s"sudo -n rm $PinRoot/c7/progs && sudo -n mv $PinRoot/c7/progs-real $PinRoot/c7/progs",
          s"sudo -n $Controller unpin $PinRoot/c5",
          s"sudo -n $Controller unpin $PinRoot/c6",
          s"sudo -n $Controller unpin $PinRoot/c7",
          s"rm -f $VmDir/sessions/c5 $VmDir/sessions/c7",
        ))
        Seq("c5", "c6", "c7").foreach(remove)

      /** The cleanup's refusals, each with a valid empty cgroup and a defective pin path or record. */
      private def cleanupRefusals(): Unit =
        val r1 = attach("r1")
        releaseHold(vm, facts.manager, Prefix, "r1")
        val r1Id = cgroupId(r1.path)
        def reconcileOne(arguments: String): String =
          val reconciled = vm(s"sudo -n $Controller reconcile $PinRoot --manager ${facts.manager} $arguments").text
          transcript.indent(reconciled)
          reconciled
        def quotedLine(reconciled: String, session: String): String =
          lines(reconciled, s"session=$session".r).map(_.take(90)).mkString(" ")
        val sliceRoot = s"/sys/fs/cgroup/user.slice/user-${facts.uid}.slice"
        val relative = reconcileOne(s"--session ../r1 ${r1.path} $r1Id --session r1 $sliceRoot/../r1 $r1Id")
        check(
          "a session name and a cgroup path with a relative component are refused",
          count(relative, "action=refused reason=name") == 1 &&
            count(relative, "action=refused reason=cgroup-outside-slice") == 1,
        )
        val symlink =
          vm(s"sudo -n mkdir -p $PinRoot/real && sudo -n ln -s $PinRoot/real $PinRoot/r2 2>&1 && echo LINKED").text
        if symlink.contains("LINKED") then
          val reconciled = reconcileOne(s"--session r2 ${r1.path} $r1Id")
          check(
            s"a symlink in place of the pin directory is refused: ${quotedLine(reconciled, "r2")}",
            reconciled.contains("session=r2 action=refused reason=pins-open"),
          )
          vm(sh(s"sudo -n rm $PinRoot/r2", s"sudo -n rmdir $PinRoot/real"))
        else info(s"bpffs refused the symlink: ${oneLine(symlink)}; the row is not constructible here")
        val cgroupSymlink =
          vm(s"ln -s ${r1.path} /sys/fs/cgroup${appSlice(facts.uid)}/$Prefix-r3 2>&1 && echo LINKED || echo REFUSED")
        info(s"a symlink in place of a cgroup directory: cgroup2 answers ${oneLine(cgroupSymlink.text)}")
        vm(s"sudo -n mkdir -p $PinRoot/r4 && sudo -n mount -t tmpfs tmpfs $PinRoot/r4")
        val mounted = reconcileOne(s"--session r4 ${r1.path} $r1Id")
        check(
          s"a mount on the pin directory is refused: ${quotedLine(mounted, "r4")}",
          mounted.contains("session=r4 action=refused reason=pins-open"),
        )
        vm(sh(s"sudo -n umount $PinRoot/r4", s"sudo -n rmdir $PinRoot/r4"))
        val otherId = vm(s"sudo -n $Controller reconcile $PinRoot --manager ${facts.manager} --session r1 ${r1.path} " +
          (r1Id.toLongOption.getOrElse(0L) + 1)).text
        check(
          "a cgroup whose recorded identity differs from the directory's is refused, nothing removed",
          otherId.contains("session=r1 action=refused reason=cgroup-identity") &&
            vm.line(s"test -d ${r1.path} && echo PRESENT") == "PRESENT",
        )
        remove("r1")

      def costs(first: Launched, recreated: Launched): Unit =
        step("the costs of the launch's steps")
        info(s"install, the verifier over nine programs (tags): ${field("ms", tags.text)} ms")
        info(
          s"step 2 at launch, the controller: load, fill, attach = ${field("load_ms", first.attach)} " +
            s"${field("fill_ms", first.attach)} ${field("attach_ms", first.attach)} ms; step 2 at a recreate, " +
            s"attach-pinned: ${field("ms", recreated.attach)} ms after check-pins ${field("ms", recreated.check)} ms",
        )
        info(
          s"step 3 at launch: read-back ${field("ms", first.verify)} ms, proof fixture ${field("ms", first.proof)} " +
            s"ms (${field("ops", first.proof)} operations)",
        )

      /** Whether the user lets the next rows stop the machine, asked on stdin; no answer is no. */
      @tailrec private def restartAllowed(): Boolean =
        log("The next rows stop the podman machine, which ends every session running on it. Stop it now? [Y/n]")
        Option(StdIn.readLine()).map(_.trim) match
          case None => false
          case Some("" | "y" | "Y" | "yes" | "Yes" | "YES") => true
          case Some("n" | "N" | "no" | "No" | "NO") => false
          case Some(_) =>
            log("Answer y or n.")
            restartAllowed()

      /** The machine answering ssh again, polled for up to two minutes. */
      @tailrec private def awaitMachine(tries: Int = 0): Unit =
        if tries < 60 && !host(transcript, Seq("podman", "machine", "ssh", "true"), record = false).ok then
          Thread.sleep(2000)
          awaitMachine(tries + 1)

      private def clock(): String = LocalTime.now.format(DateTimeFormatter.ofPattern("HH:mm:ss"))

      /** lv runs and st is stopped; both have pins. After the restart the pins and the attach cgroups are gone,
        * the containers are not running, and podman-restart.service starts neither. */
      def machineRestart(): Unit =
        step("a machine restart with a stopped session present: pins, cgroups, and nothing starts it")
        if !restartAllowed() then
          info("skipped: the machine restart rows were declined")
          podman("rm", "-f", "st", "lv")
          forgetSession("st")
          forgetSession("lv")
        else
          podman("kill", "lv")
          info(s"pins before the restart: ${oneLine(vm(s"sudo -n ls $PinRoot").text)}")
          info(s"podman machine stop at ${clock()}")
          podman("machine", "stop")
          info(s"podman machine start at ${clock()}")
          podman("machine", "start")
          info(s"machine started at ${clock()}")
          awaitMachine()
          Thread.sleep(15000)
          mountPseudoFilesystems(vm)
          check(
            s"after the machine restart no pin survives: ${oneLine(vm(s"sudo -n ls $PinRoot 2>&1").text)}",
            vm.line(s"sudo -n test -e $PinRoot && echo PRESENT || echo ABSENT") == "ABSENT",
          )
          check(
            "the attach cgroups are gone",
            vm.line(s"find /sys/fs/cgroup/user.slice -type d -name '$Prefix-*' 2>/dev/null | wc -l | tr -d ' '") == "0",
          )
          check(
            s"the stopped containers stay stopped: st ${state("st")}, lv ${state("lv")}",
            running("st") == "false" && running("lv") == "false",
          )
          val reconciled = reconcile()
          check(
            s"the reconcile after the restart keeps the sessions that still have containers: " +
              s"${actionOf(reconciled, "st")} ${actionOf(reconciled, "lv")}",
            actionOf(reconciled, "st") == "kept" && actionOf(reconciled, "lv") == "kept",
          )
          podman("rm", "-f", "st", "lv")
          forgetSession("st")
          forgetSession("lv")
