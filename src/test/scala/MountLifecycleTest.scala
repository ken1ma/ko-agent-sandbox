// Tests the FUSE backend's mount lifecycle and its reference count, against real sessions.
//
// The suite runs only under testWithPodman, like the other container-launching suites (WithPodman has the
// condition):
//
//     sbt "testWithPodman *MountLifecycleTest"
//
// The suite's launches need `user_allow_other` in the /etc/fuse.conf where the daemon runs: the podman machine's, or
// a native Linux host's. These launches have no terminal to ask on, so without the line the launcher refuses, and
// the failure prints its output, which names the command that adds the line.
//
// The suite drives sessions with `sleep` rather than an agent. A session runs whatever command it is
// given, so the sequence is scriptable with no terminal. The suite asserts the marker set at every step.
// Asserting the markers, rather than only that the workspace still reads, is the point: the two ways the
// count can be wrong are opposite, and a leaked marker (a mount that nobody uses) is invisible to the user
// who would notice the other way.
//
// Beyond that sequence, the suite covers the two rules that exist for a *concurrent* reap (`KoAgentFs`,
// "The FUSE backend's mount lifecycle"). Neither rule needs a launch that can be paused:
//
// - The state that a launch in flight presents to a reap is a marker whose container exists and is not
//   running. The suite creates that state directly.
// - The marker's mtime against its container's creation shows that a real launch passes through that
//   state and no other.
// - A blocked FLOCK request in /proc/locks, not a stopwatch, shows that the workspace lock serializes a
//   reap against a launch.

package agentsandbox.launcher

import java.nio.file.{Files, Path}

import HostCommands.*
import WithPodman.{*, given}
import KoAgentFs.*

class MountLifecycleTest extends munit.FunSuite:

  override val munitTimeout = scala.concurrent.duration.Duration(15, "min")

  private val Mounts = ".local/share/ko-agent-sandbox/mounts"

  /** Runs a script where the daemon runs, through the launcher's own helper rather than a second copy of
    * that logic. */
  private def vm(script: String): String =
    run(koAgentFsScriptCommand(podman, currentOs, script)*).text

  test("a workspace's mount is created, reused, held through a launch in flight, and released"):
    requireTestWithPodman()

    val workspace = scratchWorkspace()
    var started = Vector.empty[Session]
    var lockHolder = ""
    var id = ""
    var planted = ""

    def launch(log: Path): String =
      // The suite tests the FUSE backend, which a launch selects only by name outside native Linux.
      val appeared =
        WithPodman.launchWith(workspace, log, Vector("--egress=deny-unless-allowed", "--workspace=live,fuse"))
      started = started :+ appeared
      id = appeared.id
      appeared.container

    def markers(): String =
      vm(s"""ls -1 "$$HOME/$Mounts/$id/sessions" 2>/dev/null || true""")
        .linesIterator.toVector.sorted.mkString(" ")

    def daemonPids(): Vector[String] =
      // `pgrep -a NAME`, never `pgrep -f PATTERN`: matching full command lines would match the
      // shell that runs this very check, because the shell's own arguments name the mountpoint.
      vm(s"pgrep -a ko-agent-fs 2>/dev/null | grep -F -- 'mounts/$id/workspace' | cut -d' ' -f1")
        .linesIterator.filter(_.nonEmpty).toVector

    def mounted(): Int =
      vm(s"mount 2>/dev/null | grep -c -F -- 'mounts/$id/workspace' || true").trim.toIntOption
        .getOrElse(0)

    /** Blocked flock requests appear in /proc/locks with a `->` marker, so the test observes a reap
      * that waits on the workspace lock rather than inferring the wait from how long a teardown took. */
    def lockWaiters(): Int =
      vm(s"""ino=$$(stat -c %i "$$HOME/$Mounts/$id/lock" 2>/dev/null || echo 0)
            |grep -E '^[0-9]+: -> FLOCK' /proc/locks 2>/dev/null | grep -c ":$$ino " || true
            |""".stripMargin).trim.toIntOption.getOrElse(0)

    try
      val a = launch(workspace.resolve("a.log"))
      val aLog = Files.readString(workspace.resolve("a.log"))
      assert(
        aLog.contains("FUSE backend: mounted") && !aLog.contains("joined the existing mount"),
        s"session A did not create the mount — another session of $id already holds one; its output:\n$aLog",
      )
      polling.withMaxRetries(30).eventually(assertEquals(markers(), a, "markers after A"))
      assertEquals(mounted(), 1, "A is running but its mountpoint is not mounted")
      assertEquals(daemonPids().size, 1, s"expected one daemon for $id")

      val b = launch(workspace.resolve("b.log"))
      assert(
        Files
          .readString(workspace.resolve("b.log"))
          .contains("FUSE backend: joined the existing mount for this workspace"),
        s"session B did not reuse the mount; its output:\n${Files.readString(workspace.resolve("b.log"))}",
      )
      val both = Vector(a, b).sorted.mkString(" ")
      polling.withMaxRetries(30).eventually(assertEquals(markers(), both, "markers with both up"))
      assertEquals(daemonPids().size, 1, "B started a second daemon")
      // A daemon that holds the workspace lock would block every later reap for the session's whole
      // life. The mount script closes fd 9 across the fork to prevent exactly that.
      daemonPids().foreach: pid =>
        assertEquals(vm(s"[ -e /proc/$pid/fd/9 ] && echo held || echo free").trim, "free")

      // The whole reference count rests on this ordering, which the test measures rather than
      // assumes: the container is created first, and the mount writes the marker after it.
      val written = vm(s"""stat -c %.9Y "$$HOME/$Mounts/$id/sessions/$b" 2>/dev/null""")
        .trim.filter(_.isDigit)
      val created = run(podman, "inspect", "--format", "{{.Created.UnixNano}}", b).text.trim
      assert(written.nonEmpty && created.forall(_.isDigit), s"marker=$written created=$created")
      val afterMillis = (written.toLong - created.toLong) / 1000000
      assert(
        afterMillis > 0,
        s"B's marker was written ${-afterMillis}ms before its container was created; either the " +
          "launcher's ordering changed or the clocks differ",
      )

      run(podman, "stop", "--time", "2", a)
      started = started.filterNot(_.container == a)
      eventually(assertEquals(markers(), b, "markers after A exits"))
      assertEquals(mounted(), 1, "the mount went away while B was still using it")
      val mount = SandboxWorkspace.mountPathOf(currentOs, workspace).fold(fail(_), identity)
      assert(run(podman, "exec", b, "sh", "-c", s"ls '$mount' > /dev/null").ok,
             "B's workspace mount stopped serving when A exited")

      // The test plants exactly the state that a launch in flight presents to a reap, rather than
      // racing for it: a marker whose container exists and is not running. A reap that pruned on
      // anything short of the container's absence would take the marker, find no marker left, and
      // unmount under a launch still on its way to starting.
      planted = s"ko-agent-sandbox-run-$id-0000dead"
      assert(
        run(podman, "create", "--name", planted, "--pull=never", "ko-agent-sandbox:latest", "true").ok,
        "could not create the planted container",
      )
      vm(s"""touch "$$HOME/$Mounts/$id/sessions/$planted"""")
      run(podman, "stop", "--time", "2", b)
      started = started.filterNot(_.container == b)
      eventually:
        assertEquals(markers(), planted, "the planted marker did not survive the last real session's reap")
      assertEquals(mounted(), 1, "the mount was pulled out from under a launch in flight")
      assertEquals(daemonPids().size, 1, "the daemon exited under a launch in flight")

      // Once the marker's container is gone, as the reaper's bounded wait or a reset leaves it, the
      // next reap collects the marker.
      assert(run(podman, "rm", planted).ok, "could not remove the planted container")
      val c = launch(workspace.resolve("c.log"))
      assert(
        Files
          .readString(workspace.resolve("c.log"))
          .contains("FUSE backend: joined the existing mount for this workspace"),
        "the surviving mount was not reusable",
      )

      // While C's reap runs, a process outside holds the lock. The reap must wait for the lock rather
      // than count markers and unmount under the lock's holder. `-o` keeps the child from inheriting
      // the locked descriptor: an flock is held on the open file description, so a child that holds a
      // copy keeps the lock after the holder is killed.
      lockHolder = vm(
        s"""nohup flock -o "$$HOME/$Mounts/$id/lock" -c 'sleep 300' >/dev/null 2>&1 </dev/null &
           |printf '%s\\n' "$$!"
           |sleep 1
           |""".stripMargin
      ).linesIterator.next().trim
      assert(lockHolder.nonEmpty, "could not start a lock holder in the machine")

      run(podman, "stop", "--time", "2", c)
      started = started.filterNot(_.container == c)
      eventually(assert(lockWaiters() >= 1, "no reap ever blocked on the workspace lock; it is not serializing"))
      assertEquals(mounted(), 1, "the mount went down while the lock was held")
      assertEquals(markers(), planted, "expected only the planted marker while the reap is blocked")

      vm(s"kill $lockHolder 2>/dev/null || true")
      lockHolder = ""
      eventually(assertEquals(markers(), "", "the planted marker was collected"))
      polling.withMaxRetries(60).eventually(assertEquals(mounted(), 0, "the mountpoint is still mounted"))
      polling.withMaxRetries(60).eventually(assertEquals(daemonPids().size, 0, "the daemon is still running"))

    finally
      if lockHolder.nonEmpty then vm(s"kill $lockHolder 2>/dev/null || true")
      if planted.nonEmpty then run(podman, "rm", "--force", planted)
      started.foreach(stop)
      discard(workspace)
