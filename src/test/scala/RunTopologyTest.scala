// What a run creates on the host and who can reach it: the per-run networks across a session's
// lifetime, the isolation SECURITY.md claims between concurrent sessions — "the networks and the
// proxy are per sandbox run, created by the launch and removed with it — so concurrent sessions
// cannot reach one another either" — and `--reset` as the recovery when a run outlives its reaper.
//
// Out of reach here: the resident teardown path, which removes the same resources from the launcher
// process instead of the reaper. Native Windows always takes it, and a POSIX launch falls back to
// it only when the reaper's spawn fails — which nothing outside the process can make happen, and
// design.md declines the test hook that would.
//
// Opt-in like the other container-launching suites (IntegrationSession has the gate):
//
//     KO_AGENT_SANDBOX_INTEGRATION=1 sbt "testOnly *RunTopologyTest"

package agentsandbox.launcher

import AgentSandboxLauncher.addressOn
import HostCommands.*
import IntegrationSession.*

class RunTopologyTest extends munit.FunSuite:

  override val munitTimeout = scala.concurrent.duration.Duration(20, "min")

  /** The proxy's address on one named network, read back through the launcher's own parser. */
  private def proxyAddress(session: Session): String =
    val listing = inspect(
      session.proxy,
      "{{range $net, $conf := .NetworkSettings.Networks}}{{$net}} {{$conf.IPAddress}}{{println}}{{end}}",
    )
    addressOn(listing, session.sandboxNetwork)
      .getOrElse(fail(s"${session.proxy} has no address on ${session.sandboxNetwork}"))

  /** Reach a proxy directly from inside a sandbox, bypassing the session's own proxy variables.
    * The status, or the empty string when the connection never became one. */
  private def reachFrom(session: Session, address: String): String =
    run(
      podman, "exec", session.container,
      "curl", "-sS", "--max-time", "8", "-o", "/dev/null", "-w", "%{http_code}",
      "-x", s"http://$address:3128", "https://pypi.org/"
    ).text.trim

  /** Kill this run's detached reaper, leaving nothing to remove what the run created. `pkill -f`
    * because the reaper is a `/bin/sh` like any other: the launcher names it in argv — argv[0]
    * `ko-agent-sandbox-reaper`, then the sandbox container, which is unique to the run.
    *
    * `-KILL` is required, not defensive: the reaper opens with `trap '' INT HUP TERM`, so it
    * outlives every catchable signal on purpose. That makes this the faithful simulation anyway —
    * a reaper is lost by its machine dying under it, never by being asked to stop. */
  private def killReaper(session: Session): Unit =
    val pattern = s"ko-agent-sandbox-reaper ${session.container}"
    assert(run("pkill", "-KILL", "-f", pattern).ok, s"no reaper matched `$pattern`")
    assertEquals(
      eventually(30)(run("pgrep", "-f", pattern).ok)(_ == false), false,
      s"still running after SIGKILL:\n${run("pgrep", "-fl", pattern).text}",
    )

  private def exists(container: String): Boolean = run(podman, "container", "exists", container).ok

  test("a run's networks are created by its launch and removed when its sandbox exits"):
    optIn()

    val project = scratchProject()
    try
      val session = launch(project, project.resolve("session.log"))
      val expected = Vector(session.sandboxNetwork, session.egressNetwork)
      expected.foreach: network =>
        assert(networks().contains(network), s"$network was not created by the launch")

      stop(session)
      // The reaper removes them after `podman wait`, retrying while the --rm sandbox is still
      // mid-removal, so this is a wait rather than a check.
      expected.foreach: network =>
        assertEquals(
          eventually(Patience)(networks().contains(network))(_ == false), false,
          s"$network outlived the session that created it",
        )
    finally discard(project)

  test("a session reaches its own proxy and no other session's"):
    optIn()

    // Two projects rather than two sessions of one, because that also settles the cross-*project*
    // claim. The run suffix is fresh per launch, so two sessions of one project are separated the
    // same way — by their own networks and their own proxy — and would test the narrower half.
    val projectA = scratchProject()
    val projectB = scratchProject()
    var live = Vector.empty[Session]
    try
      val a = launch(projectA, projectA.resolve("a.log"))
      live = live :+ a
      val b = launch(projectB, projectB.resolve("b.log"))
      live = live :+ b

      assertNotEquals(a.sandboxNetwork, b.sandboxNetwork, "the two runs shared a network")

      // The control: without it, a session with no network at all would pass the refusal below.
      assertEquals(reachFrom(a, proxyAddress(a)), "200", "A cannot reach its own proxy")
      assertEquals(reachFrom(b, proxyAddress(b)), "200", "B cannot reach its own proxy")

      // The claim itself, in both directions — one internal network per run, and no route between.
      assertNotEquals(
        reachFrom(a, proxyAddress(b)), "200",
        "A reached B's proxy; concurrent sessions are not isolated",
      )
      assertNotEquals(
        reachFrom(b, proxyAddress(a)), "200",
        "B reached A's proxy; concurrent sessions are not isolated",
      )
    finally
      live.foreach(stop)
      discard(projectA)
      discard(projectB)

  test("a run whose reaper died strands its resources, and --reset sweeps them"):
    optIn()
    // No reaper exists on Windows by construction — the resident launcher is the teardown there,
    // which the first test verifies — and pkill is not a Windows tool either way.
    assume(currentOs != Os.Windows, "no reaper exists on Windows")

    val project = scratchProject()
    try
      val session = launch(project, project.resolve("session.log"))
      val stranded = Vector(session.sandboxNetwork, session.egressNetwork)

      // The crash --reset exists for: the reaper gone first, so the sandbox's exit is observed by
      // nobody. Killing the container is how a crash ends; the order is what makes it one.
      killReaper(session)
      val removed = run(podman, "rm", "--force", "--time", "2", session.container)
      assert(removed.ok, s"could not remove ${session.container}: ${removed.err}")

      // Long enough that a surviving reaper would have finished: it removes its run's resources
      // immediately after `podman wait` returns. Without this the sweep below would pass on a run
      // that had already cleaned itself up, which is the opposite of what this asserts.
      Thread.sleep(5000)
      stranded.foreach: network =>
        assert(networks().contains(network), s"$network was removed by something other than --reset")
      assert(exists(session.proxy), s"${session.proxy} was removed by something other than --reset")

      val (ok, output) = reset(project)
      assert(ok, s"--reset failed:\n$output")

      stranded.foreach: network =>
        assert(!networks().contains(network), s"--reset left $network behind:\n$output")
      assert(!exists(session.proxy), s"--reset left ${session.proxy} behind:\n$output")
    finally discard(project)
