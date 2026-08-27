// The reaper's argument plumbing, where a wrong positional argument removes the wrong container,
// and the run's cleanup, whose whole mechanism is one hook answering to the run's own state.

package agentsandbox.launcher

import SandboxLifecycle.*

class SandboxLifecycleTest extends munit.FunSuite:

  test("the cleanup removes what a refused launch made, once"):
    var removals = 0
    val cleanup = RunCleanup(() => removals += 1)
    cleanup.perform()
    assertEquals(removals, 1, "a refusal before the handover left this run's resources behind")
    // Terminal: nothing it already removed can be removed again, and the handover is refused from
    // here on, because starting podman now would leave a sandbox with no proxy and no reaper.
    cleanup.perform()
    assertEquals(removals, 1, "the cleanup ran twice")
    assertEquals(cleanup.handingOver(), false, "the handover was allowed after the removal won")

  test("a cleanup that throws part-way still refuses the handover"):
    // The half-removed state is the one that must not be handed over: `remove` may already have
    // taken the proxy away when it throws, and a launch that went on to start podman would run a
    // sandbox with nothing to reach the network through and no reaper to remove it.
    val cleanup = RunCleanup(() => throw RuntimeException("podman rm failed"))
    cleanup.perform()
    assertEquals(cleanup.handingOver(), false, "the handover was allowed after a failed removal")

  test("the cleanup removes nothing while podman is being started"):
    // The state that exists only because reading it and acting on it are one critical section: a
    // hook that sampled "nothing has started yet" and then removed could take the proxy out from
    // under a sandbox the main thread had meanwhile started.
    var removals = 0
    val cleanup = RunCleanup(() => removals += 1)
    assertEquals(cleanup.handingOver(), true)
    cleanup.perform()
    assertEquals(removals, 0, "the cleanup removed while the sandbox may have been starting")

    // With a process, the removal follows its exit rather than racing it. Any short-lived process
    // serves; each platform lends its own shell.
    val process =
      if scala.util.Properties.isWin then ProcessBuilder("cmd", "/c", "exit 0").start()
      else ProcessBuilder("/bin/sh", "-c", "exit 0").start()
    cleanup.watching(process)
    cleanup.perform()
    assertEquals(removals, 1, "the cleanup did not run after the session ended")
    assert(!process.isAlive, "perform returned before the process it was watching had exited")

  test("a failed start hands the run back to the cleanup"):
    // `ProcessBuilder.start` throwing leaves no child at all, so the handing-over state would
    // otherwise mean nobody removes this run's proxy and networks.
    var removals = 0
    val cleanup = RunCleanup(() => removals += 1)
    assertEquals(cleanup.handingOver(), true)
    cleanup.startFailed()
    cleanup.perform()
    assertEquals(removals, 1, "a launch whose podman never started leaked what it had made")

  test("arming registers the cleanup as a shutdown hook"):
    // The registration is the entire mechanism and a launch cannot show whether it happened.
    // Removing it again is also what keeps this suite from leaving hooks behind.
    val armed = armRunCleanup(() => ())
    assert(
      Runtime.getRuntime.removeShutdownHook(armed.hook),
      "arming registered no shutdown hook",
    )

  test("the resident cleanup removes the sandbox first, and tolerates one already gone"):
    // The sandbox may be created and never started (a refusal, a Ctrl-C before the handover), in
    // which case only a forced rm frees its network; after an ordinary run --rm has already taken
    // it, and a failing rm must not stop the rest. The fake podman logs each call and fails the rm
    // of the absent sandbox, as the real one does.
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
      ClipboardBroker.HostBackend(xclip = "/usr/bin/xclip", wlPaste = "/usr/bin/wl-paste"),
    )
    assertEquals(command.take(3), Vector("/bin/sh", "-c", ReaperScript))
    // sh -c: the argument after the script becomes $0; $1 through ${12} follow.
    assertEquals(command(3), "ko-agent-sandbox-reaper")
    assertEquals(
      command.drop(4),
      Vector(
        "run-container", "proxy-container", "/usr/bin/podman",
        "net-sandbox", "net-egress", "machine", "reap-script", "paste",
        "/usr/bin/xclip", "/usr/bin/wl-paste", "", "",
      ),
    )
    // The names travel as arguments, never interpolated into the script.
    assert(!ReaperScript.contains("run-container"))

  test("the reaper ignores terminal signals and removes only this run's resources"):
    // The trap is the first thing that can matter; only the PATH assignment precedes it.
    assertEquals(ReaperScript.linesIterator.drop(1).next(), "trap '' INT HUP TERM")
    // The stray never-started sandbox is $1; the proxy, stopped with a short grace, is $2; every invocation goes
    // through the resolved path in $3, never through the reaper's own PATH; the run's networks are $4 and $5.
    assert(ReaperScript.contains("\"$3\" rm --force \"$1\""))
    assert(ReaperScript.contains("\"$3\" rm --force --time 2 \"$2\""))
    assert(ReaperScript.contains("for net in \"$4\" \"$5\""))
    assert(ReaperScript.contains("\"$3\" network rm \"$net\""))
    // The filter teardown is the LAST step, so a fault in it cannot cost the removals above; the
    // mode and script travel as $6 and $7, and "none" (an unfiltered run) matches no case.
    assert(ReaperScript.contains("machine) \"$3\" machine ssh \"$7\""))
    assert(ReaperScript.contains("local) /bin/sh -c \"$7\""))
    assert(
      ReaperScript.indexOf("case \"$6\"") > ReaperScript.indexOf("network rm"),
      "the teardown step must come after this run's own cleanup",
    )
    // The clipboard broker is a job, never the wait: `podman wait` decides removal, and the job's
    // tree is ended after it so nothing outlives the sandbox it serves. The shape is pinned here;
    // what it does — no job under off, a pid held, a signal delivered, a tree ended — is the
    // lifecycle tests below.
    val wait = ReaperScript.indexOf("\"$3\" wait \"$1\"")
    val broker = ReaperScript.indexOf(
      "if [ \"$8\" != off ]; then\n  ( clipboard_broker \"$3\" \"$1\" \"$8\" \"$9\" \"${10}\" \"${11}\"\n" +
        "    while kill -0 \"$$\" 2>/dev/null; do sleep 1; done ) &\n  broker=$!\nfi",
    )
    assert(broker >= 0 && broker < wait, "the broker must be backgrounded before the wait")
    assert(ReaperScript.indexOf("end_tree \"$broker\"") > wait, "the tree must be ended after the wait")
    assert(!ReaperScript.contains("kill $!"), "an unconditional kill of the last background pid")
    // The job must keep the reaper's ignores: a reset would let a group TERM free its pid.
    assert(!ReaperScript.contains("trap -"), "a trap reset inside the reaper")

  /** What one reaper run against the fake podman left to observe. */
  private case class ReaperRun(
    /** `container inspect` calls the run made before the reaper exited: one is the reaper's own
      * running check, the rest are the broker's turns. */
    inspects: Int,
    /** More inspect calls in the two seconds after the reaper exited: the broker outliving it. */
    inspectsAfter: Int,
    /** The reaper's live (non-zombie) children at `podman wait`, the waiting podman itself
      * excluded: the broker job, when one is held. Handles captured while they were the fixture's
      * own — a handle knows its process's start time, so one whose pid was since reused answers
      * dead and cannot be signalled into another process. */
    childrenAtWait: Vector[ProcessHandle],
    /** Whether the blocking `exec` child — the shape of a hung clipboard tool — is still alive,
      * by the handle captured for the pid it recorded before blocking. */
    hungChildAlive: Boolean,
  )

  /** This host's `ps`, which the lifecycle tests hand the reaper as the launcher would, probed for
    * the exact shape the harness itself parses — `-A -o pid=,ppid=,stat=`, the launcher's shape
    * plus `stat=` — so an incompatible one (BusyBox) skips the suite rather than failing it. */
  private def hostPs(): String =
    val found = HostCommands.findOnPath("ps", sys.env.getOrElse("PATH", ""), HostCommands.currentOs)
    assume(found.isDefined, "needs ps on PATH")
    val ps = found.get.toString
    val me = ProcessHandle.current.pid.toString
    val answers =
      try HostCommands.run(ps, "-A", "-o", "pid=,ppid=,stat=").text.linesIterator
          .exists(line => line.trim.split("\\s+").toList match
            case pid :: _ :: stat :: Nil => pid == me && stat.nonEmpty
            case _ => false)
      catch case _: java.io.IOException => false
    assume(answers, s"needs a ps answering `ps -A -o pid=,ppid=,stat=`; $ps did not")
    ps

  /**
   * The reaper run for real under /bin/sh against a fake podman, the clipboard mode as given. The
   * sandbox "runs" for the first `runningAnswers` inspect calls and is stopped after; `wait`
   * returns after a second; `exec` either returns at once (the broker then loops, one inspect per
   * turn) or blocks for good (a hung child under the job). With `groupTerm`, `wait` first sends
   * TERM to the reaper's whole process group — an explicit group signal, the shape a terminal's
   * INT or HUP take — from a fake that ignores it itself; the reaper then runs under `setsid`, so
   * that group is its own and not this JVM's, and the caller assumes `setsid` is present (stock
   * macOS has none). Beyond /bin/sh and its `wc` and `sleep`, the host tool this executes is its
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
    val backend = if mode == "off" then ClipboardBroker.HostBackend() else ClipboardBroker.HostBackend(ps = ps)
    val command = reaperCommand(podman.toString, "sandbox", "proxy", "net-a", "net-b", "none", "", mode, backend)
    // `-w`: setsid forks when its caller leads a group, and the parent's exit would leave nothing
    // to capture descendants from.
    val launched = if groupTerm then Vector("setsid", "-w") ++ command else command
    // Output to a file, and a bounded wait: reading the pipe to EOF would block on any descendant
    // a regressed cleanup left holding it — the very failure this measures — for the whole of a
    // `sleep 3029`. The fixture's descendants are captured as handles, continuously while the
    // reaper runs, so both the assertions and the forcible cleanup below act on the processes
    // that were the fixture's, never on a reused pid.
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

  test("under off the reaper starts no broker job"):
    // `[ ... ] || cmd &` would have backgrounded the whole list: a job under off, a pid to kill
    // that nobody meant to start. Measured, not read off the text.
    assume(java.nio.file.Files.isExecutable(java.nio.file.Paths.get("/bin/sh")), "needs /bin/sh")
    val run = reaperRun("off", runningAnswers = 99, hangExec = false)
    assertEquals(run.inspects, 1, "something besides the reaper's own check called inspect")
    assertEquals(run.childrenAtWait, Vector.empty, "a job was running at the wait")

  test("the broker and everything under it end with the sandbox, through the reaper's ignored TERM"):
    // The reaper traps TERM to nothing and a job inherits that, so a TERM at cleanup is a no-op
    // on it: the tree is stopped and KILLed instead. And ending the job alone would leave what
    // it was blocked in — here an exec that never returns, the shape of xclip waiting on a
    // selection owner — so the tree is what is ended.
    assume(java.nio.file.Files.isExecutable(java.nio.file.Paths.get("/bin/sh")), "needs /bin/sh")
    val run = reaperRun("paste", runningAnswers = 99, hangExec = true)
    assert(run.inspects > 1, "the broker never ran")
    assertEquals(run.inspectsAfter, 0, "the broker outlived the reaper")
    assert(!run.hungChildAlive, "a child blocked under the broker outlived the reaper")
    run.childrenAtWait.foreach(child => assert(!child.isAlive, s"${child.pid} outlived the reaper"))

  test("a broker that exits early keeps its pid until the reaper ends it, and no other is touched"):
    // The pid-reuse window: with the broker gone before the wait returns, its pid could be
    // another process's by the time the kill lands. The job holds the pid instead — live at the
    // wait although clipboard_broker returned at once — and is then ended. The unrelated sleeper
    // is the process a stray kill would have hit.
    assume(java.nio.file.Files.isExecutable(java.nio.file.Paths.get("/bin/sh")), "needs /bin/sh")
    val bystander = ProcessBuilder("sleep", "300").start()
    try
      val run = reaperRun("paste", runningAnswers = 1, hangExec = false)
      assertEquals(run.inspects, 2, "the broker did not take exactly one turn")
      assert(run.childrenAtWait.nonEmpty, "the job did not hold its pid until the wait returned")
      run.childrenAtWait.foreach(child => assert(!child.isAlive, s"${child.pid} outlived the reaper"))
      assert(bystander.isAlive, "an unrelated process was killed")
    finally bystander.destroyForcibly()

  test("a TERM to the reaper's process group mid-session leaves the job's pid held until cleanup"):
    // A signal to the whole group — a terminal's INT or HUP, or a TERM someone sends the group —
    // reaches the reaper's job too. A job that honoured it would be gone before the wait
    // returned, its pid free for another process to take and the cleanup to signal; so the job
    // keeps the reaper's ignores, and cleanup uses STOP and KILL, which no disposition refuses.
    // Both job states are covered: blocked in a hung child, and already past clipboard_broker.
    assume(java.nio.file.Files.isExecutable(java.nio.file.Paths.get("/bin/sh")), "needs /bin/sh")
    val setsid = sys.env.getOrElse("PATH", "").split(":")
      .exists(dir => java.nio.file.Files.isExecutable(java.nio.file.Paths.get(dir, "setsid")))
    assume(setsid, "needs setsid on PATH for a process group of the reaper's own")
    for (answers, hang) <- Vector((99, true), (1, false)) do
      val run = reaperRun("paste", runningAnswers = answers, hangExec = hang, groupTerm = true)
      assert(run.childrenAtWait.nonEmpty, s"($answers, $hang): the group TERM ended the job before the wait returned")
      assertEquals(run.inspectsAfter, 0, s"($answers, $hang): the broker outlived the reaper")
      assert(!run.hungChildAlive, s"($answers, $hang): a child under the job outlived the reaper")
      run.childrenAtWait.foreach: child =>
        assert(!child.isAlive, s"($answers, $hang): ${child.pid} outlived the reaper")
    // Both ends bound their own waits: the host may have no `timeout`, so the response writer's
    // bound runs in the sandbox, and a `set` under paste is drained rather than left in the pipe.
    assert(ReaperScript.contains(ClipboardBroker.SandboxRequestReader))
    assert(ReaperScript.contains(ClipboardBroker.SandboxResponseWriter))
    assert(ClipboardBroker.SandboxResponseWriter.startsWith("timeout "))
    assert(ReaperScript.contains("else head -c \"$arg\" >/dev/null; fi"))
    // Comments may name podman; no executable line may invoke it bare.
    assert(
      ReaperScript.linesIterator.forall: line =>
        line.trim.startsWith("#") || !line.contains("podman")
      ,
      "a bare podman invocation crept in",
    )
