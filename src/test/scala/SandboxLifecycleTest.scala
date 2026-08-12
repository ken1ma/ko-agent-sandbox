// The reaper's argument plumbing, where a wrong positional argument removes the wrong container.

package agentsandbox.launcher

import SandboxLifecycle.*

class SandboxLifecycleTest extends munit.FunSuite:

  test("the reaper receives its names and podman path as data, after $0"):
    val command = reaperCommand(
      "/usr/bin/podman", "run-container", "proxy-container", "net-sandbox", "net-egress",
      "machine", "reap-script"
    )
    assertEquals(command.take(3), Vector("/bin/sh", "-c", ReaperScript))
    // sh -c: the argument after the script becomes $0; $1 through $7 follow.
    assertEquals(command(3), "ko-agent-sandbox-reaper")
    assertEquals(
      command.drop(4),
      Vector(
        "run-container", "proxy-container", "/usr/bin/podman",
        "net-sandbox", "net-egress", "machine", "reap-script"
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
    // Comments may name podman; no executable line may invoke it bare.
    assert(
      ReaperScript.linesIterator.forall: line =>
        line.trim.startsWith("#") || !line.contains("podman")
      ,
      "a bare podman invocation crept in"
    )
