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
      "arming registered no shutdown hook"
    )

  test("the reaper receives its names and podman path as data, after $0"):
    val command = reaperCommand(
      "/usr/bin/podman", "run-container", "proxy-container", "net-sandbox", "net-egress",
      "machine", "reap-script", "paste",
      ClipboardBroker.HostBackend(xclip = "/usr/bin/xclip", wlPaste = "/usr/bin/wl-paste")
    )
    assertEquals(command.take(3), Vector("/bin/sh", "-c", ReaperScript))
    // sh -c: the argument after the script becomes $0; $1 through ${11} follow.
    assertEquals(command(3), "ko-agent-sandbox-reaper")
    assertEquals(
      command.drop(4),
      Vector(
        "run-container", "proxy-container", "/usr/bin/podman",
        "net-sandbox", "net-egress", "machine", "reap-script", "paste", "/usr/bin/xclip", "/usr/bin/wl-paste", ""
      )
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
      "the teardown step must come after this run's own cleanup"
    )
    // The clipboard broker is a job, never the wait: `podman wait` decides removal, and the job is
    // killed after it so nothing outlives the sandbox it serves. Off means the job never starts.
    val wait = ReaperScript.indexOf("\"$3\" wait \"$1\"")
    val broker =
      ReaperScript.indexOf("[ \"$8\" = off ] || clipboard_broker \"$3\" \"$1\" \"$8\" \"$9\" \"${10}\" \"${11}\" &")
    assert(broker >= 0 && broker < wait, "the broker must be backgrounded before the wait")
    assert(ReaperScript.indexOf("kill $! 2>/dev/null") > wait, "the broker must be killed after the wait")
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
      "a bare podman invocation crept in"
    )
