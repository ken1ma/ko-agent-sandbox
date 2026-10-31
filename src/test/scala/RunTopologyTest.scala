// Tests what a run creates on the host and who can reach it:
// - the per-run networks across a session's lifetime;
// - the isolation between concurrent sessions that SECURITY.md claims: "The networks and proxy are per run and removed
//   with it, so concurrent sessions cannot reach one another through those networks";
// - `--reset` as the recovery when a run outlives its reaper.
//
// This suite cannot reach the resident teardown path, in which the launcher process removes the same resources instead
// of the reaper.
// - Native Windows always takes the resident path.
// - A POSIX launch falls back to the resident path only when the reaper's spawn fails. Nothing outside the process can
//   make the spawn fail. A hook that could would be launch-path code that exists only for a test, which design.md
//   declines for the pause hook ("No test hook that pauses a launch mid-flight").
//
// The suite runs only under testWithPodman, like the other suites that launch containers. WithPodman holds the
// condition.
//
//     sbt "testWithPodman *RunTopologyTest"

package agentsandbox.launcher

import AgentSandboxLauncher.addressOn
import HostCommands.*
import WithPodman.{*, given}

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

  /** Reaches a proxy directly from inside a sandbox, bypassing the session's own proxy variables. Returns the HTTP
    * status, or the empty string when the connection never got a response. */
  private def reachFrom(session: Session, address: String): String =
    run(
      podman, "exec", session.container,
      "curl", "-sS", "--max-time", "8", "-o", "/dev/null", "-w", "%{http_code}",
      "-x", s"http://$address:3128", "https://pypi.org/"
    ).text.trim

  /** Kills this run's detached reaper, so that nothing removes what the run created.
    *
    * The kill uses `pkill -f` because the reaper is a `/bin/sh` like any other. The launcher names the reaper in argv:
    * argv[0] is `ko-agent-sandbox-reaper`, and the next argument is the sandbox container, which is unique to the run.
    *
    * `-KILL` is required, not defensive. The reaper starts with `trap '' INT HUP TERM`, so the reaper outlives every
    * catchable signal on purpose. SIGKILL is also the faithful simulation: a reaper is lost when its machine dies under
    * it, never because something asks it to stop. */
  private def killReaper(session: Session): Unit =
    val pattern = s"ko-agent-sandbox-reaper ${session.container}"
    assert(run("pkill", "-KILL", "-f", pattern).ok, s"no reaper matched `$pattern`")
    polling.withMaxRetries(30).eventually:
      assert(!run("pgrep", "-f", pattern).ok, s"still running after SIGKILL:\n${run("pgrep", "-fl", pattern).text}")

  private def exists(container: String): Boolean = run(podman, "container", "exists", container).ok

  test("a run's networks are created by its launch and removed when its sandbox exits"):
    requireTestWithPodman()

    val workspace = scratchWorkspace()
    try
      val session = launch(workspace, workspace.resolve("session.log"))
      val expected = Vector(session.sandboxNetwork, session.egressNetwork)
      expected.foreach: network =>
        assert(networks().contains(network), s"$network was not created by the launch")

      stop(session)
      // The reaper removes the networks after `podman wait`, and it retries while podman is still removing the --rm
      // sandbox. This assertion therefore waits rather than checks once.
      expected.foreach: network =>
        eventually(assert(!networks().contains(network), s"$network outlived the session that created it"))
    finally discard(workspace)

  test("a session reaches its own proxy and no other session's"):
    requireTestWithPodman()

    // The test uses two workspaces rather than two sessions of one workspace, because two workspaces also settle the
    // cross-*workspace* claim. Each launch gets a fresh run suffix, so two sessions of one workspace are separated the
    // same way, by their own networks and their own proxy. Two such sessions would test only the narrower half.
    val workspaceA = scratchWorkspace()
    val workspaceB = scratchWorkspace()
    var live = Vector.empty[Session]
    try
      val a = launch(workspaceA, workspaceA.resolve("a.log"))
      live = live :+ a
      val b = launch(workspaceB, workspaceB.resolve("b.log"))
      live = live :+ b

      assertNotEquals(a.sandboxNetwork, b.sandboxNetwork, "the two runs shared a network")

      // The control: without it, a session with no network at all would pass the refusal check below.
      assertEquals(reachFrom(a, proxyAddress(a)), "200", "A cannot reach its own proxy")
      assertEquals(reachFrom(b, proxyAddress(b)), "200", "B cannot reach its own proxy")

      // The claim itself, in both directions: each run has one internal network, and no route joins two of them.
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
      discard(workspaceA)
      discard(workspaceB)

  test("a run whose reaper died strands its resources, and --reset sweeps them"):
    requireTestWithPodman()
    // No reaper exists on Windows by construction: the resident launcher tears the run down there, and the first test
    // verifies that teardown. pkill is not a Windows program either.
    assume(currentOs != Os.Windows, "no reaper exists on Windows")

    val workspace = scratchWorkspace()
    try
      val session = launch(workspace, workspace.resolve("session.log"))
      val stranded = Vector(session.sandboxNetwork, session.egressNetwork)

      // The test stages the crash that --reset exists for. The reaper goes first, so nobody observes the sandbox's
      // exit. Killing the container is how a crash ends, and the order of the two kills makes the run a crash.
      killReaper(session)
      val removed = run(podman, "rm", "--force", "--time", "2", session.container)
      assert(removed.ok, s"could not remove ${session.container}: ${removed.err}")

      // The sleep lasts long enough for a surviving reaper to finish, since a reaper removes its run's resources
      // immediately after `podman wait` returns. Without the sleep, the sweep below would pass on a run that had
      // already cleaned itself up, which is the opposite of what this test asserts.
      Thread.sleep(5000)
      stranded.foreach: network =>
        assert(networks().contains(network), s"$network was removed before --reset")
      assert(exists(session.proxy), s"${session.proxy} was removed before --reset")

      val (ok, output) = reset(workspace)
      assert(ok, s"--reset failed:\n$output")

      stranded.foreach: network =>
        assert(!networks().contains(network), s"--reset left $network behind:\n$output")
      assert(!exists(session.proxy), s"--reset left ${session.proxy} behind:\n$output")
    finally discard(workspace)
