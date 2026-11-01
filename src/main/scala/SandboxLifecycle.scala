// How a run ends: the handover to podman, and the removal of the proxy and networks that the run created.
// Both removal paths sit here together on purpose:
// - the detached reaper, on POSIX after the exec;
// - removeRunResources, on Windows or in any launch that stayed resident.
// The two paths perform the same removal, and a change to one is nearly always a change to the other. Splitting them by
// platform would put the two paths in different files.

package agentsandbox.launcher

import java.io.IOException
import scala.annotation.tailrec

import HostCommands.*

object SandboxLifecycle:

  // -------------------------------------------------------------------------
  // Handing over to podman
  // -------------------------------------------------------------------------

  /**
   * On POSIX the launcher execs podman, so the terminal, raw mode and signals behave exactly as under podman started
   * directly. The fullscreen TUIs depend on that behavior, which is why cleanup is a detached reaper rather than code
   * after a wait here.
   *
   * Three cases stay resident instead: Windows, which has no execve; a native image whose GraalVM refuses the FFM
   * execvp; and a failed reaper spawn. A resident launcher waits, forwards the exit code, and lets the run's own hook
   * remove what the run made once podman has exited (armRunCleanup).
   *
   * Accepted failure cases:
   * - Podman never exiting blocks the hook, as it would block podman alone.
   * - A Windows console close allows about 5 seconds, which the wait plus rm can exceed. The run's proxy and networks
   *   then linger for a reset.
   * - Execvp failing after the reaper spawned cleans up twice, and the second rm fails harmlessly.
   */
  def handOver(command: Vector[String], viaExec: Boolean, cleanup: RunCleanup): Nothing =
    System.out.flush()
    System.err.flush()
    // The handover claims the run before either way of starting podman, and before the `start()` that can throw.
    if !cleanup.handingOver() then
      // A shutdown got there first, and this run's resources are already gone. This exit blocks indefinitely. The JVM
      // ends when the hook finishes, with the shutdown's own status (HostCommands.shuttingDown has the contract).
      sys.exit(1)
    if viaExec && currentOs != Os.Windows then
      try FFMHelper.libc.execvp(command)
      catch case _: Throwable => ()
    val process =
      try ProcessBuilder(command*).inheritIO().start()
      catch
        case ex: IOException =>
          // No child exists after all, so this process removes what this run made again.
          cleanup.startFailed()
          throw ex
    cleanup.watching(process)
    sys.exit(process.waitFor())

  // -------------------------------------------------------------------------
  // Removing what the run created
  // -------------------------------------------------------------------------
  //
  // Each run has one proxy and two networks.
  // - Runs share nothing, so removal needs no coordination.
  // - Each run's ruleset and certificate are its own.
  // - Nothing worth keeping dies with the run's resources, because the audit log is a host file.
  //
  // Every accepted failure leaves a LINGERING proxy or network, which is visible, never reused, and swept by --reset.
  // No accepted failure removes a proxy under a live sandbox:
  //
  //   - A reaper that dies after a successful spawn removes nothing.
  //   - A launcher SIGKILLed mid-start leaves a running proxy with no reaper, because no hook runs either.
  //     - The next launch does not sweep that proxy, because a concurrent launcher mid-start looks the same.
  //     - If the lingering proxy ever matters, limit the sweep to containers older than some age.
  //   - A failed `podman rm` is not retried.

  /**
   * The one cleanup that a run ever has. The launch arms the cleanup before the first resource that would need
   * removing, and never replaces the cleanup.
   *
   * The cleanup is a shutdown hook rather than a `try`/`catch`, because `fail` ends the JVM instead of throwing.
   * - A `catch` would catch none of the refusals that a launch can make: a proxy that will not create, will not
   *   start, or whose address cannot be read, and the sandbox container itself.
   * - The hook also covers a Ctrl-C, which no error handling would cover.
   *
   * The cleanup saves more than tidiness. A podman network holds a subnet out of a finite pool, whose rootless default
   * is 256. A launch that refuses halfway leaks two networks, so enough failed launches make every later launch fail
   * for want of a subnet, until a reset.
   *
   * A single hook avoids a window in which swapping hooks could let a JVM shutdown remove a sandbox whose podman had
   * already started. The hook's behavior follows the run's own state instead, and these answers are the whole design:
   *
   *   - Before the handover, nothing outside this process knows what the run made, so the hook removes it.
   *   - During the handover, podman is being started, and there is no process to wait on yet, so the hook removes
   *     *nothing*.
   *   - Once there is a process, the hook waits for the process and then removes, which is a session's ordinary end.
   */
  def armRunCleanup(remove: () => Unit): RunCleanup =
    val cleanup = RunCleanup(remove)
    Runtime.getRuntime.addShutdownHook(cleanup.hook)
    cleanup

  final class RunCleanup private[launcher] (remove: () => Unit):
    /** The registered thread. The field exists because a test cannot otherwise see that arming happened. */
    private[launcher] val hook: Thread = Thread(() => perform())
    private var handedOver = false
    private var child: Option[Process] = None
    private var claimed = false

    /**
     * Claim the run for the handover. The answer is `false` once the cleanup has taken what this run made, which
     * signals the caller not to start podman at all.
     *
     * The method synchronizes against [[perform]], and that synchronization is the whole point rather than
     * housekeeping. A snapshot taken and then released would allow this sequence: a hook reads "nothing has started
     * yet", the main thread hands over and starts podman, and the hook removes the proxy underneath podman. Reading the
     * state and acting on it form one critical section on both sides, so whichever side arrives first settles the run.
     */
    def handingOver(): Boolean = synchronized {
      if claimed then false
      else
        handedOver = true
        true
    }

    /** The start threw, so no process exists, and the caller owns what this run made again. */
    def startFailed(): Unit = synchronized { handedOver = false }

    def watching(process: Process): Unit = synchronized { child = Some(process) }

    private[launcher] def perform(): Unit = synchronized {
      val handingOver = child.isEmpty && handedOver
      if !claimed && !handingOver then
        // The cleanup claims the run before the removal runs rather than after the removal succeeds. A `remove` that
        // throws part-way has already removed part of the run. A handover after that `remove` would start a sandbox
        // whose proxy or networks are half gone, so a failed cleanup refuses the handover as permanently as a
        // successful one.
        claimed = true
        try
          child.foreach(_.waitFor())
          remove()
        catch
          // Give up rather than block the JVM's exit any further. What this run made lingers until --reset removes it.
          case _: Exception => ()
    }

  /**
   * Shell functions that signal a process and its descendants.
   * - The functions list processes through the ps that `$ps_command` names. The launcher proved that this ps answers
   *   exactly these arguments (ClipboardRelay.probedPs). A ps that answered nothing would leave every job childless
   *   here, and the cleanup would end the job alone, silently.
   * - The functions send STOP and KILL, the two signals that no disposition can refuse, because the tree inherits the
   *   reaper's ignores.
   * - A stopped process cannot reap, so no pid under the tree changes hands between stop_tree and end_tree. KILL
   *   needs no CONT.
   */
  val TreeFunctions: String =
    """children_of() {
      |  "$ps_command" -A -o pid=,ppid= | while read -r pid ppid; do [ "$ppid" = "$1" ] && echo "$pid"; done
      |}
      |stop_tree() { kill -STOP "$1" 2>/dev/null; for child in $(children_of "$1"); do stop_tree "$child"; done; }
      |end_tree() { for child in $(children_of "$1"); do end_tree "$child"; done; kill -KILL "$1" 2>/dev/null; }
      |
      |""".stripMargin

  /**
   * The reaper is an sh script, because the reaper must outlive the launcher's exec, and /bin/sh is the one
   * interpreter that Linux and macOS both guarantee. The script takes these arguments:
   * - $1, this run's sandbox, and $2, its proxy;
   * - $3, the resolved podman path (findOnPath has the reason);
   * - $4 and $5, the run's networks;
   * - $6 and $7, the FUSE backend's teardown mode and script, documented at the step that reads them;
   * - $8, the clipboard mode, and $9 to ${11}, the clipboard's host programs;
   * - ${12}, the ps with which the cleanup walks the tree;
   * - ${13}, the microphone probe's status file, empty without --audio=mic, and ${14}, the microphone log;
   * - from ${15}, the recorder candidates.
   *
   * The trap is necessary: the reaper shares the launcher's process group, and a terminal SIGINT or SIGHUP would
   * otherwise kill the reaper first.
   *
   * The clipboard relay is a job of this script rather than a process of its own, because the relay's lifetime is
   * exactly the wait below: from the sandbox running to the sandbox stopped.
   * - The relay is a background job, so removal waits on `podman wait` alone, and a relay blocked in a host clipboard
   *   command delays nothing.
   * - The script kills the relay after the wait, so the relay never outlives the container it serves.
   * - ClipboardRelay has the relay's protocol and the Windows counterpart. The image's ko-sandbox-clipboard shim is
   *   the sandbox side.
   *
   * The microphone relay is also a job. The script starts the microphone relay before the wait for the sandbox to
   * run, since the relay's launch probe precedes the sandbox's start (MicrophoneRelay). The relay's directory holds the
   * microphone's audio on its way, and this script makes the directory and removes it after the KILL.
   */
  val ReaperScript: String =
    withScriptPath(
      "trap '' INT HUP TERM\n\n" +
      """# ${12} is read at top level; inside a function the positionals are the function's.
      |ps_command=${12}
      |""".stripMargin + TreeFunctions + ClipboardRelay.hostShellFunctions() + MicrophoneRelay.hostShellFunctions() +
      """# The microphone relay, from before the sandbox starts: its probe is what the launcher
      |# waits on before the start. An `if`, and the job holding its pid, for the clipboard relay's
      |# reasons below.
      |microphone=
      |microphone_dir=
      |if [ -n "${13}" ]; then
      |  microphone_dir=$(mktemp -d "${TMPDIR:-/tmp}/ko-agent-sandbox-microphone.XXXXXX") ||
      |    printf 'failed relay: could not make a directory in %s\nnone\n' "${TMPDIR:-/tmp}" >> "${13}"
      |fi
      |if [ -n "$microphone_dir" ]; then
      |  ( engine=$3 sandbox=$1 status=${13} log=${14}
      |    shift 14
      |    microphone_relay "$engine" "$sandbox" "$microphone_dir" "$status" "$log" "$@"
      |    while kill -0 "$$" 2>/dev/null; do sleep 1; done ) &
      |  microphone=$!
      |fi
      |
      |# Wait for the sandbox to be running before waiting for it to stop:
      |# `podman wait` alone would bind a created-but-never-started container
      |# (launcher killed between create and start) forever. After ten
      |# minutes of that, remove the stray and fall through. A container
      |# already gone (it ran and --rm removed it before this loop first
      |# looked) falls through too: removing the proxy is what matters.
      |i=0
      |while [ "$("$3" container inspect --format '{{.State.Running}}' "$1" 2>/dev/null)" != true ]; do
      |  "$3" container exists "$1" 2>/dev/null || break
      |  i=$((i + 1))
      |  [ "$i" -gt 600 ] && { "$3" rm --force "$1"; break; }
      |  sleep 1
      |done
      |
      |# An `if`, not `[ ... ] || cmd &`: `&` backgrounds the whole and-or list, so that spelling
      |# starts a job under `off` too. The job keeps the trap above: a terminal's INT or HUP, or
      |# a TERM sent to the group, reaches it as it reaches this shell, and one that ended the job
      |# before the wait returned would free its pid for another process, which the cleanup below
      |# would then signal; sh has no process handle to tell the two apart, and dash refuses
      |# `kill %1` non-interactively. For the same reason the job holds its pid after
      |# clipboard_relay returns, until this shell ends it or is gone.
      |relay=
      |if [ "$8" != off ]; then
      |  ( clipboard_relay "$3" "$1" "$8" "$9" "${10}" "${11}"
      |    while kill -0 "$$" 2>/dev/null; do sleep 1; done ) &
      |  relay=$!
      |fi
      |
      |"$3" wait "$1"
      |# The job's whole tree, not the job: xclip -o and wl-paste block for as long as the
      |# selection owner takes, and a child left behind is the channel outliving the session.
      |# What survives by design is xclip -i's own fork, the X selection owner: the clipboard
      |# content, not the channel.
      |if [ -n "$relay" ]; then
      |  stop_tree "$relay"
      |  end_tree "$relay"
      |fi
      |if [ -n "$microphone" ]; then
      |  stop_tree "$microphone"
      |  end_tree "$microphone"
      |  rm -rf "$microphone_dir"
      |fi
      |
      |# A `podman restart` starts the sandbox again right after the stop that
      |# ended the wait, and --rm then fails on the running container, which
      |# would run on without its proxy. This removal ends the session either
      |# way; after an ordinary exit the container is gone and it does nothing.
      |"$3" rm --force --time 2 "$1" >/dev/null 2>&1
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
      |# The FUSE backend's last-session teardown: $6 is where to run it
      |# ("machine" through the resolved podman in $3, "local" on this host,
      |# "none" where no FUSE backend runs), $7 the script. Deliberately last, so
      |# a fault in it can never cost the removals above.
      |case "$6" in
      |  machine) "$3" machine ssh "$7" >/dev/null 2>&1 ;;
      |  local) /bin/sh -c "$7" >/dev/null 2>&1 ;;
      |esac
      |""".stripMargin,
    )

  /** What the reaper passes the microphone relay, as ${13} onward (MicrophoneRelay.hostShellFunctions). */
  final case class MicrophoneJob(
    status: java.nio.file.Path,
    log: java.nio.file.Path,
    recorders: Vector[MicrophoneRelay.Recorder],
  )

  /**
   * The argument after the script is $0, which names the reaper for ps. The other arguments travel as $1 onward
   * rather than interpolated into the script, so the script stays a constant and the arguments stay data.
   */
  def reaperCommand(
    podman: String,
    sandboxContainer: String,
    proxyContainer: String,
    sandboxNetwork: String,
    egressNetwork: String,
    teardownMode: String,
    teardownScript: String,
    clipboardMode: String,
    clipboard: ClipboardRelay.HostBackend,
    microphone: Option[MicrophoneJob] = None,
  ): Vector[String] =
    Vector(
      "/bin/sh", "-c", ReaperScript,
      "ko-agent-sandbox-reaper", sandboxContainer, proxyContainer, podman,
      sandboxNetwork, egressNetwork, teardownMode, teardownScript, clipboardMode,
      clipboard.xclip, clipboard.wlPaste, clipboard.wlCopy, clipboard.ps,
      microphone.fold("")(_.status.toString), microphone.fold("")(_.log.toString),
    ) ++ microphone.toVector.flatMap(_.recorders.map(MicrophoneRelay.encodedCandidate))

  /**
   * Starts the reaper detached, with stdio to /dev/null, because the tty belongs to podman, and the reaper must never
   * touch the tty.
   * - Children survive execvp, so the reaper outlives the handover and is reparented to init when podman exits.
   * - The answer is false when the spawn failed. The caller then stays resident, so the cleanup still has an owner.
   */
  def spawnReaper(
    podman: String,
    sandboxContainer: String,
    proxyContainer: String,
    sandboxNetwork: String,
    egressNetwork: String,
    teardownMode: String,
    teardownScript: String,
    clipboardMode: String,
    clipboard: ClipboardRelay.HostBackend,
    microphone: Option[MicrophoneJob],
  ): Boolean =
    try
      val builder = ProcessBuilder(
        reaperCommand(
          podman, sandboxContainer, proxyContainer, sandboxNetwork, egressNetwork,
          teardownMode, teardownScript, clipboardMode, clipboard, microphone,
        )*
      )
      builder.redirectInput(ProcessBuilder.Redirect.from(java.io.File("/dev/null")))
      builder.redirectOutput(ProcessBuilder.Redirect.DISCARD)
      builder.redirectError(ProcessBuilder.Redirect.DISCARD)
      builder.start()
      true
    catch case _: IOException => false

  /**
   * The resident path's twin of the reaper's final lines, with the same retry (the reaper has the reason).
   * - The sandbox's own removal serves a launch that ends between the container's create and its start, through a
   *   refusal or a Ctrl-C. There --rm never fires, and the container would hold its network.
   * - After a run, the sandbox container is already gone, and the rm is a no-op.
   * - After a `podman restart`, the rm ends the session, for the reason the reaper gives.
   */
  def removeRunResources(
    podman: String, sandboxContainer: String, proxyContainer: String, networks: Seq[String],
  ): Unit =
    run(podman, "rm", "--force", sandboxContainer)
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
