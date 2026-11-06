// Tests the reaper's arguments, where a wrong positional argument removes the wrong container, and
// the run's cleanup, whose whole mechanism is one hook that answers to the run's own state.

package agentsandbox.launcher

import SandboxLifecycle.*

class SandboxLifecycleTest extends munit.FunSuite:

  test("the cleanup removes what a refused launch made, once"):
    var removals = 0
    val cleanup = RunCleanup(() => removals += 1)
    cleanup.perform()
    assertEquals(removals, 1, "a refusal before the handover left this run's resources behind")
    cleanup.perform()
    assertEquals(removals, 1, "the cleanup ran twice")
    assertEquals(cleanup.handingOver(), false, "the handover was allowed after the removal won")

  test("a cleanup that throws part-way still refuses the handover"):
    val cleanup = RunCleanup(() => throw RuntimeException("podman rm failed"))
    cleanup.perform()
    assertEquals(cleanup.handingOver(), false, "the handover was allowed after a failed removal")

  test("the cleanup removes nothing while podman is being started"):
    var removals = 0
    val cleanup = RunCleanup(() => removals += 1)
    assertEquals(cleanup.handingOver(), true)
    cleanup.perform()
    assertEquals(removals, 0, "the cleanup removed while the sandbox may have been starting")

    // With a process, the removal follows the process's exit rather than racing it. Any short-lived
    // process serves, and each platform supplies its own shell.
    val process =
      if scala.util.Properties.isWin then ProcessBuilder("cmd", "/c", "exit 0").start()
      else ProcessBuilder("/bin/sh", "-c", "exit 0").start()
    cleanup.watching(process)
    cleanup.perform()
    assertEquals(removals, 1, "the cleanup did not run after the session ended")
    assert(!process.isAlive, "perform returned before the process it was watching had exited")

  test("a failed start hands the run back to the cleanup"):
    var removals = 0
    val cleanup = RunCleanup(() => removals += 1)
    assertEquals(cleanup.handingOver(), true)
    cleanup.startFailed()
    cleanup.perform()
    assertEquals(removals, 1, "a launch whose podman never started leaked what it had made")

  test("arming registers the cleanup as a shutdown hook"):
    // The registration is the entire mechanism, and a launch cannot show whether the registration
    // happened. Removing the hook again also keeps this suite from leaving hooks behind.
    val armed = armRunCleanup(() => ())
    assert(
      Runtime.getRuntime.removeShutdownHook(armed.hook),
      "arming registered no shutdown hook",
    )

  test("the resident cleanup removes the sandbox first, and tolerates one already gone"):
    // The sandbox may be created and never started, after a refusal or a Ctrl-C before the handover.
    // Then only a forced rm frees the sandbox's network. After an ordinary run, --rm has already taken
    // the sandbox, and a failing rm must not stop the rest. The fake podman logs each call and fails
    // the rm of the absent sandbox, as the real podman does.
    assume(java.nio.file.Files.isExecutable(java.nio.file.Paths.get("/bin/sh")), "needs /bin/sh")
    val dir = java.nio.file.Files.createTempDirectory("cleanup")
    val log = dir.resolve("log")
    val podman = dir.resolve("podman")
    java.nio.file.Files.writeString(
      podman,
      s"""#!/bin/sh
         |echo "$$*" >> "$log"
         |case "$$*" in
         |  "rm --force gone-sandbox") exit 125 ;;
         |  "network exists "*) exit 0 ;;
         |esac
         |""".stripMargin
    )
    podman.toFile.setExecutable(true)
    removeRunResources(podman.toString, "gone-sandbox", "proxy-container", Seq("net-sandbox", "net-egress"))
    assertEquals(
      java.nio.file.Files.readAllLines(log).toArray.toVector,
      Vector(
        "rm --force gone-sandbox",
        "rm --force --time 2 proxy-container",
        "network exists net-sandbox", "network rm net-sandbox",
        "network exists net-egress", "network rm net-egress",
      ),
    )

  test("the reaper receives its names and podman path as data, after $0"):
    val command = reaperCommand(
      "/usr/bin/podman", "run-container", "proxy-container", "net-sandbox", "net-egress",
      "machine", "reap-script", "paste",
      ClipboardRelay.HostBackend(xclip = "/usr/bin/xclip", wlPaste = "/usr/bin/wl-paste"),
    )
    assertEquals(command.take(3), Vector("/bin/sh", "-c", ReaperScript))
    assertEquals(command(3), "ko-agent-sandbox-reaper")
    assertEquals(
      command.drop(4),
      Vector(
        "run-container", "proxy-container", "/usr/bin/podman",
        "net-sandbox", "net-egress", "machine", "reap-script", "paste",
        "/usr/bin/xclip", "/usr/bin/wl-paste", "", "", "", "",
      ),
    )
    // Under --audio=mic: the status file, the log, then each candidate as one argument.
    val withMic = reaperCommand(
      "/usr/bin/podman", "run-container", "proxy-container", "net-sandbox", "net-egress",
      "machine", "reap-script", "off", ClipboardRelay.HostBackend(ps = "/bin/ps"),
      Some(
        MicJob(
          java.nio.file.Paths.get("/run/status"), java.nio.file.Paths.get("/log/mic.log"),
          Vector(
            MicRelay.Recorder("arecord", Vector("/usr/bin/aplay", "-C")),
            MicRelay.Recorder("parecord", Vector("/usr/bin/pacat", "--record")),
          ),
        ),
      ),
    )
    assertEquals(
      withMic.drop(4 + 12),
      Vector("/run/status", "/log/mic.log", "/usr/bin/aplay\u001f-C", "/usr/bin/pacat\u001f--record"),
    )
    // The names travel as arguments and are never interpolated into the script.
    assert(!ReaperScript.contains("run-container"))

  test("the reaper ignores terminal signals and removes only this run's resources"):
    // The trap comes before any command that a signal could interrupt; only the PATH assignment precedes it.
    assertEquals(ReaperScript.linesIterator.drop(1).next(), "trap '' INT HUP TERM")
    assert(ReaperScript.contains("\"$3\" rm --force \"$1\""))
    assert(ReaperScript.contains("\"$3\" rm --force --time 2 \"$2\""))
    assert(ReaperScript.contains("for net in \"$4\" \"$5\""))
    assert(ReaperScript.contains("\"$3\" network rm \"$net\""))
    // "none" (a run without the FUSE backend) matches no case.
    assert(ReaperScript.contains("machine) \"$3\" machine ssh \"$7\""))
    assert(ReaperScript.contains("local) /bin/sh -c \"$7\""))
    assert(
      ReaperScript.indexOf("case \"$6\"") > ReaperScript.indexOf("network rm"),
      "the teardown step must come after this run's own cleanup",
    )
    // This test checks the script text. The lifecycle tests below check what the script does: no job
    // under off, a pid held, a signal delivered, a tree ended.
    val wait = ReaperScript.indexOf("\"$3\" wait \"$1\"")
    val relay = ReaperScript.indexOf(
      "if [ \"$8\" != off ]; then\n  ( clipboard_relay \"$3\" \"$1\" \"$8\" \"$9\" \"${10}\" \"${11}\"\n" +
        "    while kill -0 \"$$\" 2>/dev/null; do sleep 1; done ) &\n  relay=$!\nfi",
    )
    assert(relay >= 0 && relay < wait, "the relay must be backgrounded before the wait")
    assert(ReaperScript.indexOf("end_tree \"$relay\"") > wait, "the tree must be ended after the wait")
    assert(!ReaperScript.contains("kill $!"), "an unconditional kill of the last background pid")
    // The job must keep the reaper's ignores, because a reset would let a group TERM free the job's pid.
    assert(!ReaperScript.contains("trap -"), "a trap reset inside the reaper")

  test("after the wait the reaper removes the sandbox before its proxy, so a podman restart ends the session"):
    assume(java.nio.file.Files.isExecutable(java.nio.file.Paths.get("/bin/sh")), "needs /bin/sh")
    // The fake answers as podman does at a `podman restart`: the wait returns at the stop, and the
    // sandbox runs again before --rm removes it, so it still exists after the wait.
    val dir = java.nio.file.Files.createTempDirectory("reaper-restart")
    val calls = dir.resolve("calls.log")
    val podman = dir.resolve("podman")
    java.nio.file.Files.writeString(
      podman,
      s"""#!/bin/sh
         |echo "$$*" >> "$calls"
         |case "$$1 $$2" in
         |  "container inspect") echo true ;;
         |  "network exists") exit 1 ;;
         |esac
         |""".stripMargin,
    )
    podman.toFile.setExecutable(true)
    val command = reaperCommand(
      podman.toString, "sandbox", "proxy", "net-a", "net-b", "none", "", "off", ClipboardRelay.HostBackend(),
    )
    val process = ProcessBuilder(command*).redirectErrorStream(true).redirectOutput(dir.resolve("out").toFile).start()
    assert(process.waitFor(30, java.util.concurrent.TimeUnit.SECONDS), "the reaper did not exit within 30 s")
    val lines = java.nio.file.Files.readAllLines(calls).toArray.toVector.map(_.toString)
    val waited = lines.indexOf("wait sandbox")
    val sandboxRemoved = lines.indexOf("rm --force --time 2 sandbox")
    val proxyRemoved = lines.indexOf("rm --force --time 2 proxy")
    assert(waited >= 0 && sandboxRemoved > waited && proxyRemoved > sandboxRemoved, lines.mkString("\n"))

  /** What one reaper run against the fake podman left to observe. */
  private case class ReaperRun(
    /** The `container inspect` calls that the run made before the reaper exited. One is the reaper's own
      * running check, and the rest are the relay's turns. */
    inspects: Int,
    /** More inspect calls in the two seconds after the reaper exited, which show the relay outliving the
      * reaper. */
    inspectsAfter: Int,
    /** The reaper's live (non-zombie) children at `podman wait`, excluding the waiting podman itself:
      * the relay job, when the reaper holds one. The handles were captured while the processes were the
      * fixture's own. A handle knows its process's start time, so a handle whose pid was since reused
      * answers dead and cannot signal another process. */
    childrenAtWait: Vector[ProcessHandle],
    /** Whether the blocking `exec` child, the stand-in for a hung clipboard program, is still alive. The
      * check uses the handle captured for the pid that the child recorded before blocking. */
    hungChildAlive: Boolean,
  )

  /** This host's `ps` (HostPs.answering), which the lifecycle tests hand the reaper as the launcher would. */
  private def hostPs(): String = HostPs.answering()

  /**
   * Runs the reaper for real under /bin/sh against a fake podman, in the given clipboard mode.
   *
   *  - The sandbox "runs" for the first `runningAnswers` inspect calls and is stopped after them.
   *  - `wait` returns after a second.
   *  - `exec` either returns at once, so the relay loops with one inspect per turn, or blocks for good,
   *    which leaves a hung child under the job.
   *  - With `groupTerm`, `wait` first sends TERM to the reaper's whole process group, from a fake that
   *    ignores the TERM itself. The TERM is an explicit group signal, the form that a terminal's INT or HUP
   *    takes. The reaper then runs under `setsid`, so that group is the reaper's own and not this JVM's.
   *    The caller assumes that `setsid` is present (stock macOS has none).
   *
   * Beyond /bin/sh and its `wc` and `sleep`, the host program that this method executes is the host's
   * `ps` (hostPs), as the launcher would pass it.
   */
  private def reaperRun(
    mode: String,
    runningAnswers: Int,
    hangExec: Boolean,
    groupTerm: Boolean = false,
  ): ReaperRun =
    val ps = hostPs()
    val dir = java.nio.file.Files.createTempDirectory("reaper-run")
    val log = dir.resolve("inspect.log")
    val children = dir.resolve("children")
    val hungPid = dir.resolve("hung.pid")
    val podman = dir.resolve("podman")
    java.nio.file.Files.writeString(
      podman,
      s"""#!/bin/sh
         |case "$$1 $$2" in
         |  "container inspect")
         |    echo x >> "$log"
         |    if [ "$$(wc -l < "$log")" -le $runningAnswers ]; then echo true; else echo false; fi ;;
         |  "container exists") exit 0 ;;
         |  "wait "*)
         |    ${if groupTerm then s"trap '' TERM; kill -TERM -\"$$PPID\" || : > '$children.unsent';" else ":"}
         |    sleep 1
         |    '$ps' -A -o pid=,ppid=,stat= | while read -r pid ppid stat; do
         |      [ "$$ppid" = "$$PPID" ] && [ "$$pid" != "$$$$" ] && case "$$stat" in *Z*) ;; *) echo "$$pid" ;; esac
         |    done > "$children" ;;
         |  "exec -i") ${if hangExec then s"echo $$$$ > '$hungPid'; exec sleep 3029" else "exit 0"} ;;
         |  "network exists") exit 1 ;;
         |esac
         |""".stripMargin,
    )
    podman.toFile.setExecutable(true)
    val backend = if mode == "off" then ClipboardRelay.HostBackend() else ClipboardRelay.HostBackend(ps = ps)
    val command = reaperCommand(podman.toString, "sandbox", "proxy", "net-a", "net-b", "none", "", mode, backend)
    // `-w`: setsid forks when its caller leads a group, and the parent's exit would leave nothing
    // to capture descendants from.
    val launched = if groupTerm then Vector("setsid", "-w") ++ command else command
    // The output goes to a file, with a bounded wait. Reading the pipe to EOF would block for the
    // whole of a `sleep 3029` on any descendant that a regressed cleanup left holding the pipe, which
    // is the very failure this test measures. The test captures the fixture's descendants as handles,
    // continuously while the reaper runs. Both the assertions and the forcible cleanup below therefore
    // act on the processes that were the fixture's, never on a reused pid.
    val output = dir.resolve("reaper.out")
    val process = ProcessBuilder(launched*).redirectErrorStream(true).redirectOutput(output.toFile).start()
    def pidsIn(file: java.nio.file.Path): Vector[Long] =
      if java.nio.file.Files.exists(file) then
        java.nio.file.Files.readAllLines(file).toArray.toVector
          .map(_.toString.trim.split("\\s+").head).flatMap(_.toLongOption)
      else Vector.empty
    val deadline = System.nanoTime() + 30_000_000_000L
    val owned = scala.collection.mutable.Map.empty[Long, ProcessHandle]
    try
      while process.isAlive && System.nanoTime() < deadline do
        process.descendants().forEach(handle => owned.getOrElseUpdate(handle.pid, handle))
        Thread.sleep(20)
      assert(!process.isAlive, "the reaper did not exit within 30 s")
      assertEquals(process.exitValue(), 0, java.nio.file.Files.readString(output))
      // dash's kill takes no `--`; a group kill that failed to send would pass every assertion below.
      assert(!java.nio.file.Files.exists(dir.resolve("children.unsent")), "the group TERM was never sent")
      def calls(): Int = if java.nio.file.Files.exists(log) then java.nio.file.Files.readAllLines(log).size else 0
      val atExit = calls()
      Thread.sleep(2500)
      def handles(file: java.nio.file.Path): Vector[ProcessHandle] = pidsIn(file).flatMap(owned.get)
      ReaperRun(atExit, calls() - atExit, handles(children), handles(hungPid).exists(_.isAlive))
    finally
      process.destroyForcibly()
      owned.values.foreach(_.destroyForcibly())

  test("under off the reaper starts no relay job"):
    // The test measures this rather than reading it off the script text (ReaperScript has the
    // `if`-not-`||` pitfall).
    assume(java.nio.file.Files.isExecutable(java.nio.file.Paths.get("/bin/sh")), "needs /bin/sh")
    val run = reaperRun("off", runningAnswers = 99, hangExec = false)
    assertEquals(run.inspects, 1, "a caller besides the reaper's own check called inspect")
    assertEquals(run.childrenAtWait, Vector.empty, "a job was running at the wait")

  test("the relay and everything under it end with the sandbox, through the reaper's ignored TERM"):
    // Here an exec that never returns stands in for xclip waiting on a selection owner.
    assume(java.nio.file.Files.isExecutable(java.nio.file.Paths.get("/bin/sh")), "needs /bin/sh")
    val run = reaperRun("paste", runningAnswers = 99, hangExec = true)
    assert(run.inspects > 1, "the relay never ran")
    assertEquals(run.inspectsAfter, 0, "the relay outlived the reaper")
    assert(!run.hungChildAlive, "a child blocked under the relay outlived the reaper")
    run.childrenAtWait.foreach(child => assert(!child.isAlive, s"${child.pid} outlived the reaper"))

  test("a relay that exits early keeps its pid until the reaper ends it, and no other is touched"):
    // The unrelated sleeper is the process a stray kill would have hit.
    assume(java.nio.file.Files.isExecutable(java.nio.file.Paths.get("/bin/sh")), "needs /bin/sh")
    val bystander = ProcessBuilder("sleep", "300").start()
    try
      val run = reaperRun("paste", runningAnswers = 1, hangExec = false)
      assertEquals(run.inspects, 2, "the relay did not take exactly one turn")
      assert(run.childrenAtWait.nonEmpty, "the job did not hold its pid until the wait returned")
      run.childrenAtWait.foreach(child => assert(!child.isAlive, s"${child.pid} outlived the reaper"))
      assert(bystander.isAlive, "an unrelated process was killed")
    finally bystander.destroyForcibly()

  test("a TERM to the reaper's process group mid-session leaves the job's pid held until cleanup"):
    // Both job states are covered: blocked in a hung child, and already past clipboard_relay.
    assume(java.nio.file.Files.isExecutable(java.nio.file.Paths.get("/bin/sh")), "needs /bin/sh")
    val setsid = sys.env.getOrElse("PATH", "").split(":")
      .exists(dir => java.nio.file.Files.isExecutable(java.nio.file.Paths.get(dir, "setsid")))
    assume(setsid, "needs setsid on PATH for a process group of the reaper's own")
    for (answers, hang) <- Vector((99, true), (1, false)) do
      val run = reaperRun("paste", runningAnswers = answers, hangExec = hang, groupTerm = true)
      assert(run.childrenAtWait.nonEmpty, s"($answers, $hang): the group TERM ended the job before the wait returned")
      assertEquals(run.inspectsAfter, 0, s"($answers, $hang): the relay outlived the reaper")
      assert(!run.hungChildAlive, s"($answers, $hang): a child under the job outlived the reaper")
      run.childrenAtWait.foreach: child =>
        assert(!child.isAlive, s"($answers, $hang): ${child.pid} outlived the reaper")
    assert(ReaperScript.contains(ClipboardRelay.sandboxRequestReader()))
    assert(ReaperScript.contains(ClipboardRelay.sandboxResponseWriter()))
    assert(ClipboardRelay.sandboxResponseWriter().startsWith("timeout "))
    // Comments may name podman, but no executable line may invoke podman bare.
    assert(
      ReaperScript.linesIterator.forall: line =>
        line.trim.startsWith("#") || !line.contains("podman")
      ,
      "a bare podman invocation crept in",
    )
