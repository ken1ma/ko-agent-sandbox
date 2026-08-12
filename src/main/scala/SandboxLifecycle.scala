// How a run ends: the handover to podman, and the removal of the proxy and networks that run
// created. Both removal paths live here together on purpose — the detached reaper (POSIX, after the
// exec) and removeRunResources (Windows, or any launch that stayed resident) are twins, and a change
// to one is nearly always a change to the other. Splitting them by platform would put the twins in
// different files.

package agentsandbox.launcher

import java.io.IOException
import scala.annotation.tailrec

import HostCommands.*

object SandboxLifecycle:

  // -------------------------------------------------------------------------
  // Handing over to podman
  // -------------------------------------------------------------------------

  /**
   * On POSIX the launcher execs podman, so terminal, raw mode and signals
   * are exactly direct podman's — the fullscreen TUIs depend on it, which is
   * why cleanup is a detached reaper rather than code after a wait here.
   * Windows (no execve) and a failed reaper spawn stay resident instead:
   * wait, forward the exit code, run afterWait.
   *
   * Cleanup lives in a shutdown hook because a terminal SIGINT reaches this
   * JVM as well as podman; the hook waits for podman first.
   *
   * Accepted edges: podman never exiting blocks the hook, as it would block
   * podman alone; a Windows console close allows ~5 seconds, which the wait
   * plus rm can exceed — the run's proxy and networks then linger for a
   * reset; execvp failing after the reaper spawned cleans up twice, the
   * second rm failing harmlessly.
   */
  def handOver(command: Vector[String], viaExec: Boolean, afterWait: () => Unit): Nothing =
    System.out.flush()
    System.err.flush()
    if viaExec && currentOs != Os.Windows then
      try FFMHelper.libc.execvp(command)
      catch case _: Throwable => () // fall through to the wait model
    val process = ProcessBuilder(command*).inheritIO().start()
    // Reached by normal exit too (sys.exit below), so the cleanup is stated once and runs exactly once per process
    // either way.
    Runtime.getRuntime.addShutdownHook(
      Thread(() =>
        try
          process.waitFor()
          afterWait()
        catch
          // Give up rather than block the JVM's exit any further; the proxy and the run's networks linger until --reset
          // removes them.
          case _: Exception => ()
      )
    )
    sys.exit(process.waitFor())

  // -------------------------------------------------------------------------
  // Removing what the run created
  // -------------------------------------------------------------------------
  //
  // One proxy and two networks per run: nothing shared, so removal needs no coordination; each run's policy and
  // certificate are current; nothing worth keeping dies with any of it (the audit log is a host file).
  //
  // Removal: exec path (POSIX) — a detached sh reaper spawned just before the exec; resident path (Windows, or
  // exec/spawn failure) — the shutdown hook in handOver.
  //
  // Every open edge fails toward a LINGERING proxy or network — visible, never reused, swept by --reset — never toward
  // a removed proxy under a live sandbox:
  //
  //   - a reaper that dies after a successful spawn removes nothing;
  //   - a launcher killed between proxy start and sandbox create leaves a
  //     running proxy with no reaper. Not swept at the next launch: that is
  //     also what a concurrent launcher mid-start looks like. If it ever
  //     matters, age-gate the sweep on container creation time;
  //   - a failed `podman rm` is not retried.

  /**
   * sh, because it must outlive the launcher's exec and /bin/sh is the one
   * interpreter Linux and macOS both guarantee. $1 this run's sandbox, $2
   * its proxy, $3 the resolved podman path (findOnPath has the why), $4 $5
   * its networks.
   *
   * The trap is load-bearing: the reaper shares the launcher's process
   * group, and a terminal SIGINT or SIGHUP would otherwise kill it first.
   */
  val ReaperScript: String =
    withScriptPath(
      """trap '' INT HUP TERM
      |
      |# Wait for the sandbox to be running before waiting for it to stop:
      |# `podman wait` alone would bind a created-but-never-started container
      |# (launcher killed between create and start) forever. After ten
      |# minutes of that, remove the stray and fall through. A container
      |# already gone — it ran and --rm removed it before this loop first
      |# looked — falls through too: removing the proxy is what matters.
      |i=0
      |while [ "$("$3" container inspect --format '{{.State.Running}}' "$1" 2>/dev/null)" != true ]; do
      |  "$3" container exists "$1" 2>/dev/null || break
      |  i=$((i + 1))
      |  [ "$i" -gt 600 ] && { "$3" rm --force "$1"; break; }
      |  sleep 1
      |done
      |
      |"$3" wait "$1"
      |
      |# Unconditional: the proxy is this run's own. --time 2, because it
      |# holds no state worth draining; its audit log is a host file.
      |"$3" rm --force --time 2 "$2"
      |
      |# This run's networks follow its proxy. The sandbox container is --rm
      |# and can still be mid-removal when wait returns, which makes podman
      |# refuse the network rm; retry briefly rather than leave one behind.
      |# One that outlives the retries is a reset's to sweep.
      |for net in "$4" "$5"; do
      |  i=0
      |  while "$3" network exists "$net" 2>/dev/null; do
      |    "$3" network rm "$net" >/dev/null 2>&1 && break
      |    i=$((i + 1))
      |    [ "$i" -gt 10 ] && break
      |    sleep 1
      |  done
      |done
      |
      |# The workspace filter's last-session teardown: $6 is where to run it
      |# ("machine" through the resolved podman in $3, "local" on this host,
      |# "none" for an unfiltered run), $7 the script. Deliberately last, so
      |# a fault in it can never cost the removals above.
      |case "$6" in
      |  machine) "$3" machine ssh "$7" >/dev/null 2>&1 ;;
      |  local) /bin/sh -c "$7" >/dev/null 2>&1 ;;
      |esac
      |""".stripMargin
    )

  /**
   * The argument after the script is $0, naming the reaper for ps; the rest
   * travel as $1-$5 rather than interpolated, keeping the script a constant
   * and the rest data.
   */
  def reaperCommand(
    podman: String,
    sandboxContainer: String,
    proxyContainer: String,
    sandboxNetwork: String,
    egressNetwork: String,
    teardownMode: String,
    teardownScript: String
  ): Vector[String] =
    Vector(
      "/bin/sh", "-c", ReaperScript,
      "ko-agent-sandbox-reaper", sandboxContainer, proxyContainer, podman,
      sandboxNetwork, egressNetwork, teardownMode, teardownScript
    )

  /**
   * Detached: stdio to /dev/null, because the tty belongs to podman and the
   * reaper must never touch it. Children survive execvp, so the reaper
   * outlives the handover and is reparented to init when podman exits.
   * False when the spawn failed; the caller then stays resident so the
   * cleanup still has an owner.
   */
  def spawnReaper(
    podman: String,
    sandboxContainer: String,
    proxyContainer: String,
    sandboxNetwork: String,
    egressNetwork: String,
    teardownMode: String,
    teardownScript: String
  ): Boolean =
    try
      val builder = ProcessBuilder(
        reaperCommand(
          podman, sandboxContainer, proxyContainer, sandboxNetwork, egressNetwork,
          teardownMode, teardownScript
        )*
      )
      builder.redirectInput(ProcessBuilder.Redirect.from(java.io.File("/dev/null")))
      builder.redirectOutput(ProcessBuilder.Redirect.DISCARD)
      builder.redirectError(ProcessBuilder.Redirect.DISCARD)
      builder.start()
      true
    catch case _: IOException => false

  /**
   * The resident-path twin of the reaper's final lines, same brief retry:
   * the --rm sandbox can still be mid-removal, making podman refuse a
   * network rm.
   */
  def removeRunResources(podman: String, proxyContainer: String, networks: Seq[String]): Unit =
    run(podman, "rm", "--force", "--time", "2", proxyContainer)
    networks.foreach: network =>
      @tailrec
      def attempt(remaining: Int): Unit =
        if runOk(podman, "network", "exists", network)
          && !run(podman, "network", "rm", network).ok
          && remaining > 0
        then
          Thread.sleep(1000)
          attempt(remaining - 1)
      attempt(10)
