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
   * wait, forward the exit code, and let the run's own hook remove what it
   * made once podman has exited (armRunCleanup).
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
  def handOver(command: Vector[String], viaExec: Boolean, cleanup: RunCleanup): Nothing =
    System.out.flush()
    System.err.flush()
    // Claimed before either way of starting podman, and before the `start()` that can throw: from
    // here the cleanup removes nothing until it has a process to follow, because the sandbox may
    // already be running by the time a shutdown reaches it.
    if !cleanup.handingOver() then
      // A shutdown got there first and this run's resources are already gone. Starting podman now
      // would leave a sandbox with no proxy to reach and no reaper to remove it, which is the one
      // outcome this file refuses — so decline to be what starts it. The JVM is mid-halt, and a
      // non-zero exit during shutdown halts rather than re-running the sequence.
      sys.exit(1)
    if viaExec && currentOs != Os.Windows then
      try FFMHelper.libc.execvp(command)
      catch case _: Throwable => () // fall through to the wait model
    val process =
      try ProcessBuilder(command*).inheritIO().start()
      catch
        case ex: IOException =>
          // No child exists after all, so what this run made is this process's to remove again.
          cleanup.startFailed()
          throw ex
    cleanup.watching(process)
    sys.exit(process.waitFor())

  // -------------------------------------------------------------------------
  // Removing what the run created
  // -------------------------------------------------------------------------
  //
  // One proxy and two networks per run: nothing shared, so removal needs no coordination; each run's policy and
  // certificate are current; nothing worth keeping dies with any of it (the audit log is a host file).
  //
  // Removal: one shutdown hook covering this JVM from before the first resource to the end of the session
  // (armRunCleanup), plus — on the exec path (POSIX) — a detached sh reaper spawned just before the exec, which is what
  // removes anything at all once execvp has replaced this process and taken its hooks with it.
  //
  // Every open edge fails toward a LINGERING proxy or network — visible, never reused, swept by --reset — never toward
  // a removed proxy under a live sandbox:
  //
  //   - a reaper that dies after a successful spawn removes nothing;
  //   - a launcher SIGKILLed mid-start leaves a running proxy with no reaper,
  //     because no hook runs either. Not swept at the next launch: that is
  //     also what a concurrent launcher mid-start looks like. If it ever
  //     matters, age-gate the sweep on container creation time;
  //   - a failed `podman rm` is not retried.

  /**
   * The one cleanup a run ever has: armed before the first resource that would need removing, and
   * never replaced.
   *
   * A shutdown hook rather than a `try`/`catch`, because `fail` ends the JVM instead of throwing,
   * so a `catch` would catch none of the refusals a launch can make — a proxy that will not create,
   * will not start, or whose address cannot be read, and the sandbox container itself. The hook
   * covers a Ctrl-C among them, which no error handling would have.
   *
   * What it saves is not tidiness. A podman network holds a subnet out of a finite pool — the
   * rootless default is 256 — and a launch that refuses halfway leaks two, so enough failed
   * launches make every later launch fail for want of one, until a reset.
   *
   * One hook and not two, because swapping one for another leaves a window between the swap's
   * halves: a JVM shutting down there would run the half that removes at once, against a sandbox
   * podman had already started. Behaviour follows the run's own state instead, and the three
   * answers are the whole design:
   *
   *   - before the handover, nothing outside this process knows what was made — remove it;
   *   - during the handover, podman is being started and there is no process to wait on yet —
   *     remove *nothing*. A lingering proxy is the direction every edge in this file fails toward;
   *     removing under a sandbox that may already be running is the one it never takes;
   *   - once there is a process, wait for it and then remove, which is a session's ordinary end.
   */
  def armRunCleanup(remove: () => Unit): RunCleanup =
    val cleanup = RunCleanup(remove)
    Runtime.getRuntime.addShutdownHook(cleanup.hook)
    cleanup

  final class RunCleanup private[launcher] (remove: () => Unit):
    /** The registered thread, kept because a test cannot otherwise see that arming happened. */
    private[launcher] val hook: Thread = Thread(() => perform())
    private var handedOver = false
    private var child: Option[Process] = None
    private var claimed = false

    /**
     * Claim the run for the handover: `false` once the cleanup has taken what this run made, which
     * is the caller's signal not to start podman at all.
     *
     * Synchronized against [[perform]], and that is the whole point rather than housekeeping. A
     * snapshot taken and then released would let a hook read "nothing has started yet", the main
     * thread hand over and start podman, and the hook remove the proxy underneath it. Reading the
     * state and acting on it are one critical section on both sides, so whichever arrives first
     * settles it.
     */
    def handingOver(): Boolean = synchronized {
      if claimed then false
      else
        handedOver = true
        true
    }

    /** The start threw, so no process exists and what this run made is the caller's again. */
    def startFailed(): Unit = synchronized { handedOver = false }

    /** There is now a process whose exit the removal must follow. */
    def watching(process: Process): Unit = synchronized { child = Some(process) }

    private[launcher] def perform(): Unit = synchronized {
      // The handover in progress: podman is being started and there is no process to wait on.
      val handingOver = child.isEmpty && handedOver
      if !claimed && !handingOver then
        // Claimed before the removal runs rather than after it succeeds. A `remove` that throws
        // part-way has already taken something away, so allowing a handover after it would start a
        // sandbox whose proxy or networks are half gone: a failed cleanup refuses the handover as
        // permanently as a successful one.
        claimed = true
        try
          child.foreach(_.waitFor())
          remove()
        catch
          // Give up rather than block the JVM's exit any further; what this run made lingers until
          // --reset removes it.
          case _: Exception => ()
    }

  /**
   * sh, because it must outlive the launcher's exec and /bin/sh is the one
   * interpreter Linux and macOS both guarantee. $1 this run's sandbox, $2
   * its proxy, $3 the resolved podman path (findOnPath has the why), $4 $5
   * its networks, $6 $7 the workspace filter's teardown mode and script
   * (documented at the step that reads them).
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
   * travel as $1-$7 rather than interpolated, keeping the script a constant
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
