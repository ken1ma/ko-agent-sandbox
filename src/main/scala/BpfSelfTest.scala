// --self-test's BPF corpus rows: the policy suite's corpus (ko-agent-fs/bpf/test/podman/policy/exercise.c, laid out
// as BpfCorpus says) run under the BPF backend that --build installed, on the machine's own kernel, each answer
// compared with the expected one (ko-agent-fs/doc/testing.md). A launch's proof makes one refused operation per
// hook and one write per rule line; the corpus also catches a defect that the program shares with the proof's
// expectations (ko-agent-fs/bpf/doc/architecture.md, "Lifecycle", 3).
//
// The corpus runs as the policy suite runs it, the setting its answers were measured in:
// - in a container under the attach cgroup, from the self-test image, which compiles the exerciser;
// - without a seccomp filter: a filter answers EPERM too, so a case that the hook should refuse would pass;
// - under keep-id, so that the container's process owns the share's files as a session's does.
//
// What the rows hold to, beside the share rows' standard (SelfTestShare):
// - the scratch lies under the state root on the machine's share, as the proof fixture does, since the policy
//   judges objects on the share's superblock type alone ("The policy");
// - the policy is a session's (Session), recorded as one, so a killed run leaves an orphan that the next run and the
//   reconcile at the next launch remove;
// - the rows hold the launch lock, so that no reconcile takes the session while it runs, and the image-build lock,
//   so that no --build replaces the binaries meanwhile, in the launch's order (AgentSandboxLauncher.startSandbox).

package agentsandbox.launcher

import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path}

import CommandLine.WorkspaceSettings
import FileHelper.*
import HostCommands.*
import KoAgentFs.{bundledKoAgentFsSourceId, koAgentFsScriptCommand}
import LauncherState.stateRoot

object BpfSelfTest:

  /** The session the corpus's policy is attached for. One name serves every run, so a run removes what a killed run
    * left before it starts. */
  val Session = "ko-agent-self-test-bpf"

  /** Where the self-test image has the exerciser (ko-agent-self-test/Containerfile). */
  val Exercise = "/opt/ko-agent-fs-suite/exercise"

  /** The scratch: the corpus's trees and rule file. A failed run's scratch stays until the next run. */
  def scratchDir(stateRoot: Path): Path = stateRoot.resolve("bpf").resolve("self-test")

  /** What `exercise corpus TREE` runs without a GROUP operand: every group but `short` and `unix`. */
  val DefaultGroups = "default"

  /** One policy load and the corpus groups run under it. */
  final case class PolicySet(unixSocket: Boolean, groups: Vector[String]):
    def settings: WorkspaceSettings = WorkspaceSettings("live", "bpf", unixSocket)

  /**
   * The policies that launches on `os` load, each with the groups whose answers it was measured under:
   * - the flags are a launch's (KoAgentBpf.policyFlags): `short-names` on Windows alone, then `unix-socket` off
   *   and on;
   * - the `short` group expects the short-name flag, and `unix` expects `unix-socket`;
   * - the default groups run in the first load only, since their socket cases expect the refusal that `unix-socket`
   *   lifts.
   */
  def policySets(os: Os): Vector[PolicySet] = Vector(
    PolicySet(unixSocket = false, DefaultGroups +: Option.when(os == Os.Windows)("short").toVector),
    PolicySet(unixSocket = true, Vector("unix")),
  )

  def flagsLabel(set: PolicySet, os: Os): String =
    KoAgentBpf.policyFlags(set.settings, os).stripPrefix("--flags ") match
      case "" => "no flags"
      case flags => flags

  /** The exerciser's arguments for one group of the corpus over the tree at `tree`. */
  def corpusArguments(tree: String, group: String): Vector[String] =
    Vector(Exercise, "corpus", tree) ++ Option.when(group != DefaultGroups)(group)

  /**
   * A container of the self-test image that runs the exerciser over the scratch, placed under `parent` when given.
   * The scratch is bound at the path the machine has it at, which the policy's roots name.
   */
  def exerciseCommand(
    podman: String,
    scratch: Path,
    machineScratch: String,
    parent: Option[String],
    arguments: Seq[String],
  ): Vector[String] =
    Vector(
      podman, "run", "--rm", "--pull=never", "--network=none", "--entrypoint=",
      s"--userns=keep-id:uid=${AgentSandboxLauncher.ContainerUid},gid=${AgentSandboxLauncher.ContainerGid}",
      s"--user=${AgentSandboxLauncher.ContainerUid}:${AgentSandboxLauncher.ContainerGid}",
      "--security-opt", "seccomp=unconfined", s"--volume=$scratch:$machineScratch",
    ) ++ parent.map(at => s"--cgroup-parent=$at") ++ (LauncherImages.SelfTestImage +: arguments)

  /**
   * The policy for one PolicySet, attached to the session's cgroup and read back. The first set also writes the
   * records and makes the cgroup; a later set replaces the first's links on the same cgroup, as the policy suite
   * attaches again.
   * - The records come from `fixture records`, the suites' stand-in for the guard, since the corpus's rule file
   *   holds the guard's anchored lines without the tree the guard would resolve them from.
   * - The workspace is the scratch, which holds both trees; every root is a guarded path below it (BpfCorpus.Roots).
   */
  def attachScript(facts: KoAgentBpf.Facts, machineScratch: String, set: PolicySet, os: Os, first: Boolean): String =
    import KoAgentBpf.{InstallDir, StepMarker}
    val roots = BpfCorpus.Roots.map((kind, path) => s"--guarded $kind=$path").mkString(" ")
    val flags = KoAgentBpf.policyFlags(set.settings, os)
    val hookList = KoAgentBpf.hooks(set.unixSocket).mkString(" ")
    val prepare =
      if !first then ""
      else
        s"""echo "${StepMarker}records"
           |"$$dir/fixture" records "$$scratch/rules" "$$sess/records.bin" $roots
           |echo "${StepMarker}cgroup"
           |${KoAgentBpf.attachCgroupStep(facts, Session)}
           |""".stripMargin
    withScriptPath(
      s"""set -eu
         |dir="$$HOME/$InstallDir"
         |sess="$$dir/sessions/$Session"
         |scratch="$$(${printingCommand(machineScratch)})"
         |mkdir -p "$$sess"
         |$prepare
         |cg="$$(sed -n 's/^cgroup=\\([^ ]*\\).*/\\1/p' "$$sess/cgroup")"
         |pins=${KoAgentBpf.pinDir(Session)}
         |echo "${StepMarker}attach"
         |sudo -n "$$dir/controller" unpin "$$pins" >/dev/null 2>&1 || true
         |sudo -n "$$dir/controller" attach "$$cg" "$$pins" --records "$$sess/records.bin" --workspace "$$scratch" \\
         |  $flags $hookList
         |echo "${StepMarker}verify"
         |sudo -n "$$dir/readback" verify "$$cg" --tags "$$dir/tags.txt" --records "$$sess/records.bin" \\
         |  --workspace "$$scratch" $flags $hookList
         |echo "${StepMarker}done"""".stripMargin,
    )

  /** The attach line's hook and rule counts match the set and the rule file: the records reached the policy. */
  def attachedAsAsked(output: String, set: PolicySet, ruleCount: Int): Boolean =
    output.linesIterator.find(_.startsWith("attach ")).exists: line =>
      KoAgentBpf.field("hooks", line).contains(KoAgentBpf.hooks(set.unixSocket).size.toString) &&
        KoAgentBpf.field("rule_count", line).contains(ruleCount.toString)

  /**
   * One group's figures, from the exerciser's `corpus group=...` line, and its mismatching cases' lines. `unsupported`
   * counts the cases the share answered before the hook, or after it where the case expects the operation allowed
   * (exercise.c, `cmd_corpus`).
   */
  final case class CorpusResult(
    cases: Int,
    mismatches: Int,
    skipped: Int,
    unsupported: Int,
    mismatchLines: Vector[String],
  ):
    def figures: String = s"$cases cases, $mismatches mismatches, $skipped skipped, $unsupported unsupported"

  def parseCorpus(output: String): Option[CorpusResult] =
    val lines = output.linesIterator.toVector
    lines.findLast(_.startsWith("corpus group=")).flatMap: line =>
      def count(key: String): Option[Int] = KoAgentBpf.field(key, line).flatMap(_.toIntOption)
      for
        cases <- count("cases")
        mismatches <- count("mismatches")
        skipped <- count("skipped")
        unsupported <- count("unsupported")
      yield CorpusResult(cases, mismatches, skipped, unsupported, lines.filter(line => line.contains(" MISMATCH")))

  /** The note for a short-name link that NTFS refused (BpfCorpus.ShortNameLinks). NTFS refuses it where it serves the
    * name as the target's own short name; any other refusal keeps its exception. */
  def shortNameNote(name: String, refusal: java.io.IOException): String = refusal match
    case _: java.nio.file.FileAlreadyExistsException =>
      s"NTFS serves $name as a short name already, and that name stands in for the hard link"
    case ex => s"hard link $name: $ex; NTFS's name stands in"

  /** The note that the corpus skips the `fifo` group's cases, where the share refused the host FIFO that `make-tree`
    * makes (exercise.c, `cmd_corpus`). */
  def refusedFifoNote(makeTreeOutput: String): Option[String] =
    makeTreeOutput.linesIterator.find(_.startsWith("made fifo=")).flatMap(KoAgentBpf.field("result", _))
      .filter(_ != "ok")
      .map(error => s"the share refused the host FIFO ($error); the corpus skips the fifo group's cases on it")

  /** The probe's facts where the installed backend can serve a launch of this launcher, else what it lacks. */
  private def probe(podman: String, os: Os): Either[Vector[String], KoAgentBpf.Facts] =
    // The share's type is read at the scratch's parent, which exists before the scratch does.
    val parent = stateRoot(os).resolve("bpf")
    Files.createDirectories(parent)
    val backing = SandboxWorkspace.mountPathOf(os, parent).fold(fail(_), identity)
    val probed = run(koAgentFsScriptCommand(podman, os, KoAgentBpf.checksScript(backing))*)
    if !probed.ok then Left(Vector(s"the machine did not answer the BPF backend's checks: ${probed.err.trim}"))
    else
      val facts = KoAgentBpf.parseFacts(probed.text)
      val failures =
        KoAgentBpf.requirementFailures(facts, os, KoAgentBpf.bundledSourceId(), bundledKoAgentFsSourceId())
      Either.cond(failures.isEmpty, facts, failures)

  def missingBackend(failures: Vector[String]): String =
    (("error: the BPF backend, which launches use by default, cannot be tested on this machine:" +:
      failures.map(reason => s"  - $reason")) :+
      s"On a machine whose kernel lacks what the backend needs, --self-test ${KoAgentBpf.NoBpfOption} leaves the " +
      "corpus out.").mkString("\n")

  /** Ends the self-test before its image builds where the corpus could not run. */
  def requireInstalled(podman: String, os: Os): Unit =
    probe(podman, os).left.foreach(failures => fail(missingBackend(failures)))

  private def row(verdict: String, label: String, detail: String): Unit =
    ImageBuilds.selfTestRow(verdict, label, detail)

  /** Runs the rows and returns 0 when every row passed or `noBpf` skipped them. */
  def corpusRows(podman: String, os: Os, noBpf: Boolean): Int =
    if noBpf then
      row("SKIP", "the BPF backend's corpus", s"${KoAgentBpf.NoBpfOption}: bpf launches are not tested")
      0
    else
      System.err.println("BPF corpus rows: the policy suite's corpus under the installed backend")
      withFileLock(KoAgentBpf.launchLockFile(stateRoot(os))):
        withFileLock(ImageBuilds.imageBuildLockFile(os)):
          probe(podman, os) match
            case Left(failures) =>
              row("FAIL", "the installed BPF backend", "")
              System.err.println(missingBackend(failures))
              1
            case Right(facts) => runCorpus(podman, os, facts)

  private def runCorpus(podman: String, os: Os, facts: KoAgentBpf.Facts): Int =
    val scratch = scratchDir(stateRoot(os))
    val machineScratch = SandboxWorkspace.mountPathOf(os, scratch).fold(fail(_), identity)
    val tree = s"$machineScratch/${BpfCorpus.Tree}"
    val teardown = koAgentFsScriptCommand(podman, os, KoAgentBpf.teardownScript(Session, facts.manager))
    def exercise(parent: Option[String], arguments: String*): Run =
      run(exerciseCommand(podman, scratch, machineScratch, parent, arguments)*)
    // The corpus makes names that the host may not spell, such as a newline or bytes that are not UTF-8, so the
    // trees go through the container, in the machine's view of the share.
    def removeScratch(): Unit =
      if Files.exists(scratch) then
        val trees = Seq(BpfCorpus.Tree, BpfCorpus.PointerTree).map(name => s"$machineScratch/$name")
        exercise(None, (Vector("rm", "-rf", "--") ++ trees)*)
        deleteRecursively(scratch)

    System.err.println(
      s"BPF corpus: kernel ${facts("kernel")}, share ${facts.shareType}, cgroup manager ${facts.manager}",
    )
    run(teardown*)
    removeScratch()
    Files.createDirectories(scratch)
    var failed = false
    def check(ok: Boolean, label: String, detail: String, explanation: => Iterable[String]): Boolean =
      row(if ok then "PASS" else "FAIL", label, detail)
      if !ok then
        failed = true
        explanation.foreach(line => System.err.println(s"    $line"))
      ok

    // The trees, then the host's hard links: the exerciser's output, what failed, and a note per short-name link that
    // NTFS refused, which leaves the name NTFS serves. Every layout makes the same notes, and the caller prints the
    // first layout's.
    def layOut(): (Run, Vector[String], Vector[String]) =
      val made = exercise(None, Exercise, "make-tree", tree)
      def link(name: String, target: String): Option[java.io.IOException] =
        try
          Files.createLink(scratch.resolve(name), scratch.resolve(target))
          None
        catch case ex: java.io.IOException => Some(ex)
      if !made.ok then (made, s"exercise make-tree: exit ${made.exit}" +: made.err.linesIterator.toVector, Vector())
      else
        val notes = BpfCorpus.ShortNameLinks.flatMap((name, target) => link(name, target).map(shortNameNote(name, _)))
        val failures =
          BpfCorpus.RequiredLinks.flatMap((name, target) => link(name, target).map(ex => s"hard link $name: $ex"))
        (made, failures.toVector, notes.toVector)

    try
      val (laid, laidFailures, shortNameNotes) = layOut()
      shortNameNotes.foreach(note => System.err.println(s"  note: $note"))
      // `exercise check` runs the allowed cases outside any policy, so the trees are laid out again after it.
      val checked = if laidFailures.isEmpty then exercise(None, Exercise, "check", tree) else laid
      val gaps = checked.text.linesIterator.find(_.startsWith("check cases=")).flatMap(KoAgentBpf.field("gaps", _))
      if check(
          laidFailures.isEmpty && checked.ok && gaps.contains("0"),
          "the corpus's trees hold every operand",
          gaps.fold(s"exit ${checked.exit}")(count => s"$count gaps"),
          // The exerciser's `check case=` lines: an operand missing, or an allowed operation that failed.
          laidFailures ++ checked.text.linesIterator.filter(_.startsWith("check case=")) ++ checked.err.linesIterator,
        )
      then
        exercise(None, "rm", "-rf", "--", tree, s"$machineScratch/${BpfCorpus.PointerTree}")
        val (relaid, relaidFailures, _) = layOut()
        refusedFifoNote(relaid.text).foreach(note => System.err.println(s"  note: $note"))
        val (rules, _) = BpfCorpus.ruleFiles(FileRules.Defaults.map(_.text))
        Files.write(scratch.resolve("rules"), rules.mkString("", "\n", "\n").getBytes(UTF_8))
        if check(relaidFailures.isEmpty, "the corpus's trees laid out again", "", relaidFailures) then
          policySets(os).zipWithIndex.foreach: (set, index) =>
            if !failed then
              val label = flagsLabel(set, os)
              val attached = run(koAgentFsScriptCommand(podman, os, attachScript(
                facts, machineScratch, set, os, first = index == 0,
              ))*)
              val ok = attached.ok && attachedAsAsked(attached.text, set, rules.size)
              if check(
                  ok,
                  s"the policy attached and read back, $label",
                  if ok then "" else s"at the ${KoAgentBpf.stepReached(attached.text)} step",
                  (attached.text.linesIterator ++ attached.err.linesIterator).toVector,
                )
              then
                set.groups.foreach: group =>
                  val ran = exercise(Some(KoAgentBpf.cgroupParent(facts, Session)), corpusArguments(tree, group)*)
                  val result = parseCorpus(ran.text)
                  // A container that podman cannot place under the attach cgroup fails as a launch's `podman
                  // create` does, and gets the same note.
                  check(
                    ran.ok && result.exists(_.mismatches == 0),
                    s"the corpus, $group groups, $label",
                    result.fold(s"exit ${ran.exit} without a corpus line")(_.figures),
                    result.fold(ran.err.linesIterator.toVector)(_.mismatchLines) ++
                      KoAgentBpf.createFailureNote(os, ran.err),
                  )
    finally
      run(teardown*)
      if !failed then removeScratch()
      else System.err.println(s"  the corpus's scratch stays for inspection until the next run: $scratch")
    if failed then 1 else 0
