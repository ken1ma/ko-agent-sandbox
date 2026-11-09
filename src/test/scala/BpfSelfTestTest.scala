// Tests --self-test's BPF corpus rows as far as they run without a podman machine: the policies chosen per platform,
// the corpus's rule file, the containers' options, the attach script against stub binaries, and the parse of what the
// exerciser and the controller print.

package agentsandbox.launcher

import java.nio.file.{Files, Path}

import BpfSelfTest.*
import HostCommands.Os

class BpfSelfTestTest extends munit.FunSuite:

  test("the policies are a launch's: short-names on Windows alone, unix-socket off then on, each with its groups"):
    def described(os: Os): Vector[(String, Vector[String])] =
      policySets(os).map(set => flagsLabel(set, os) -> set.groups)
    assertEquals(described(Os.Mac), Vector("no flags" -> Vector(DefaultGroups), "unix-socket" -> Vector("unix")))
    assertEquals(
      described(Os.Windows),
      Vector("short-names" -> Vector(DefaultGroups, "short"), "short-names,unix-socket" -> Vector("unix")),
    )
    assertEquals(corpusArguments("/t/tree", DefaultGroups), Vector(Exercise, "corpus", "/t/tree"))
    assertEquals(corpusArguments("/t/tree", "unix"), Vector(Exercise, "corpus", "/t/tree", "unix"))

  test("both runners make one rule file of the map's 128 lines from the launcher's defaults"):
    // The policy suite strips the resource's comments itself (PodmanTestHelper.stripRules); this copy checks that the
    // launcher's parse gives the self-test the same lines.
    val stream = getClass.getResourceAsStream("/agentsandbox/file-rule-defaults")
    val text = try String(stream.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8) finally stream.close()
    val stripped = text.linesIterator.map(_.replaceAll("#.*", "").trim.split("\\s+").toSeq)
      .collect { case Seq(kind, path) => s"$kind $path" }.toSeq
    assertEquals(FileRules.Defaults.map(_.text), stripped.toVector)
    val (rulesA, rulesB) = BpfCorpus.ruleFiles(stripped)
    assertEquals((rulesA.size, rulesB.size), (128, 128))
    assertEquals(rulesA.head, "read-only githooks anchored")
    assertEquals(rulesA.last, "pinned-path shared/claude anchored alias=.claude")

  test("the corpus runs as a session's process, without a seccomp filter, under the attach cgroup it is given"):
    val command = exerciseCommand(
      "podman", Path.of("/Users/me/state/bpf/self-test"), "/Users/me/state/bpf/self-test",
      Some("ko-agent-bpf-ko-agent-self-test-bpf.slice"), corpusArguments("/Users/me/state/bpf/self-test/tree", "unix"),
    )
    val shown = command.mkString(" ")
    Vector(
      "--rm", "--pull=never", "--network=none", "--entrypoint=", "--security-opt", "seccomp=unconfined",
      s"--user=${AgentSandboxLauncher.ContainerUid}:${AgentSandboxLauncher.ContainerGid}",
      "--volume=/Users/me/state/bpf/self-test:/Users/me/state/bpf/self-test",
      "--cgroup-parent=ko-agent-bpf-ko-agent-self-test-bpf.slice",
    ).foreach(argument => assert(command.contains(argument), s"$argument: $shown"))
    assert(command.exists(_.startsWith("--userns=keep-id:uid=")), shown)
    assert(command.endsWith(Vector(LauncherImages.SelfTestImage, Exercise, "corpus",
      "/Users/me/state/bpf/self-test/tree", "unix")), shown)
    val outside = exerciseCommand("podman", Path.of("/s"), "/s", None, Vector(Exercise, "check", "/s/tree"))
    assert(!outside.exists(_.startsWith("--cgroup-parent")), outside.mkString(" "))
    assertEquals(scratchDir(Path.of("/state")), Path.of("/state/bpf/self-test"))

  test("the first attach writes the records and makes the cgroup; a later one replaces the links on that cgroup"):
    val facts = KoAgentBpf.parseFacts("manager=systemd\nuid=501")
    val unixSet = policySets(Os.Windows)(1)
    val first = attachScript(facts, "/Users/me/My State/bpf/self-test", policySets(Os.Windows).head, Os.Windows, true)
    val later = attachScript(facts, "/Users/me/My State/bpf/self-test", unixSet, Os.Windows, first = false)
    def steps(script: String): Vector[String] =
      script.linesIterator.filter(_.startsWith("echo \"step=")).map(_.stripPrefix("echo \"step=").stripSuffix("\""))
        .toVector
    assertEquals(steps(first), Vector("records", "cgroup", "attach", "verify", "done"))
    assertEquals(steps(later), Vector("attach", "verify", "done"))
    assert(!first.contains("My State") && first.contains("base64 -d"), "the scratch travels encoded")
    assert(first.linesIterator.filter(_.contains("sudo")).forall(_.contains("sudo -n")), first)
    BpfCorpus.Roots.foreach((kind, path) => assert(first.contains(s"--guarded $kind=$path"), s"$kind=$path"))
    assert(first.contains("--flags short-names ") && !first.contains("unix-socket"), first)
    assert(later.contains("--flags short-names,unix-socket ") && later.contains(KoAgentBpf.hooks(true).mkString(" ")))
    assert(first.contains(s"--slice=${KoAgentBpf.slice(Session)}"), first)

  test("the attach script runs in order against stub binaries, and the later attach reads the first's cgroup"):
    assume(!System.getProperty("os.name").toLowerCase.contains("win"), "the stubs are /bin/sh scripts")
    val dir = Files.createTempDirectory("bpf-self-test").toRealPath()
    try
      val bin = Files.createDirectories(dir.resolve("bin"))
      val home = dir.resolve("home")
      val install = Files.createDirectories(home.resolve(KoAgentBpf.InstallDir))
      val calls = dir.resolve("calls")
      def stub(file: Path, body: String): Unit =
        Files.writeString(file, s"#!/bin/sh\n$body\n")
        file.toFile.setExecutable(true)
      stub(install.resolve("fixture"), s"""echo "fixture $$*" >> $calls; : > "$$3"""")
      stub(install.resolve("controller"),
        s"""echo "controller $$*" >> $calls; [ "$$1" = attach ] && echo 'attach hooks=8 rule_count=128'; true""")
      stub(install.resolve("readback"), s"""echo "readback $$*" >> $calls; echo 'verify ok=1'""")
      stub(bin.resolve("sudo"), "[ \"$1\" = -n ] && shift\nexec \"$@\"")
      stub(bin.resolve("stat"), "echo 7")
      val facts = KoAgentBpf.parseFacts("manager=cgroupfs\nuid=1000")
      val cgroupRoot = dir.resolve("cgroup").toString
      def ran(script: String): (Int, String) =
        val text = script.linesIterator.drop(1).mkString("\n").replace("/sys/fs/cgroup", cgroupRoot)
        val builder = ProcessBuilder("/bin/sh", "-c", text).redirectErrorStream(true)
        builder.environment().put("HOME", home.toString)
        builder.environment().put("PATH", s"$bin:${System.getenv("PATH")}")
        val process = builder.start()
        val output = String(process.getInputStream.readAllBytes())
        (process.waitFor(), output)
      val sets = policySets(Os.Mac)
      val (firstStatus, firstOutput) = ran(attachScript(facts, "/scratch", sets.head, Os.Mac, first = true))
      assertEquals(firstStatus, 0, firstOutput)
      assert(firstOutput.contains("step=done") && attachedAsAsked(firstOutput, sets.head, 128), firstOutput)
      val cg = s"$cgroupRoot${KoAgentBpf.cgroupParent(facts, Session)}"
      assertEquals(
        Files.readString(install.resolve(s"sessions/$Session/cgroup")).trim, s"cgroup=$cg cgroup_id=7",
        "the record the teardown and the reconcile read",
      )
      val (laterStatus, laterOutput) = ran(attachScript(facts, "/scratch", sets(1), Os.Mac, first = false))
      assertEquals(laterStatus, 0, laterOutput)
      val logged = Files.readAllLines(calls).toArray.toVector.map(_.toString)
      assertEquals(logged.count(_.startsWith("fixture records /scratch/rules ")), 1, logged.mkString("\n"))
      val attaches = logged.filter(_.startsWith("controller attach "))
      assertEquals(attaches.size, 2, logged.mkString("\n"))
      attaches.foreach: line =>
        assert(line.startsWith(s"controller attach $cg ${KoAgentBpf.pinDir(Session)} --records "), line)
        assert(line.contains("--workspace /scratch"), line)
      assert(attaches(1).contains("--flags unix-socket") && attaches(1).endsWith("file_receive"), attaches(1))
      assertEquals(logged.count(_.startsWith("readback verify ")), 2, logged.mkString("\n"))
    finally FileHelper.deleteRecursively(dir)

  test("the attach is as asked only with the set's hooks and the rule file's line count"):
    val set = policySets(Os.Mac).head
    assert(attachedAsAsked("step=attach\nattach cgroup=/c hooks=8 rule_count=128 aliases=1\nverify ok=1", set, 128))
    assert(!attachedAsAsked("attach cgroup=/c hooks=7 rule_count=128", set, 128))
    assert(!attachedAsAsked("attach cgroup=/c hooks=8 rule_count=0", set, 128))
    assert(!attachedAsAsked("step=attach", set, 128))

  test("a group's figures come from the corpus line, with its mismatching cases"):
    val output =
      """case=name/creat-dotgit expect=deny got=deny MATCH
        |case=hooks/write-hook expect=deny got=allow MISMATCH
        |case=fifo/open-host-fifo-read SKIPPED without the host FIFO
        |corpus group=default cases=242 mismatches=1 unsupported=2 skipped=4""".stripMargin
    val result = parseCorpus(output)
    assertEquals(
      result,
      Some(CorpusResult(242, 1, 4, 2, Vector("case=hooks/write-hook expect=deny got=allow MISMATCH"))),
    )
    assertEquals(result.map(_.figures), Some("242 cases, 1 mismatches, 4 skipped, 2 unsupported"))
    assertEquals(parseCorpus("exercise: open /t: No such file or directory"), None)

  test("a note names the share's refusal of the host FIFO, and a made FIFO gets none"):
    assertEquals(
      refusedFifoNote("made fifo=apps/host-fifo result=EACCES\n"),
      Some("the share refused the host FIFO (EACCES); the corpus skips the fifo group's cases on it"),
    )
    assertEquals(refusedFifoNote("made fifo=apps/host-fifo result=ok\n"), None)
    assertEquals(refusedFifoNote("exercise: mkdir /t: Permission denied\n"), None)

  test("a short-name link that NTFS already serves gets a note without the exception, any other refusal keeps it"):
    assertEquals(
      shortNameNote("tree-ptr/GIT~1", java.nio.file.FileAlreadyExistsException("C:\\s\\tree-ptr\\GIT~1")),
      "NTFS serves tree-ptr/GIT~1 as a short name already, and that name stands in for the hard link",
    )
    assertEquals(
      shortNameNote("tree-ptr/GIT~1", java.nio.file.AccessDeniedException("C:\\s\\tree-ptr\\GIT~1")),
      "hard link tree-ptr/GIT~1: java.nio.file.AccessDeniedException: C:\\s\\tree-ptr\\GIT~1; NTFS's name stands in",
    )

  test("a machine without a usable backend is told what it lacks and how to leave the corpus out"):
    val message = missingBackend(Vector("the BPF backend is not installed from this launcher's build; run --build"))
    assert(message.startsWith("error: ") && message.contains("  - the BPF backend is not installed"), message)
    assert(message.contains(s"--self-test ${KoAgentBpf.NoBpfOption}"), message)
