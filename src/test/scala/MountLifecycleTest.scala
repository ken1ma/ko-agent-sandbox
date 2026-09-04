// The workspace filter's mount lifecycle and its reference count, against real sessions.
//
// Opt-in like the other container-launching suites (IntegrationSession has the gate):
//
//     KO_AGENT_SANDBOX_INTEGRATION=1 sbt "testOnly *MountLifecycleTest"
//
// Sessions are driven with `sleep` rather than an agent — a session runs whatever command it is
// given, which is what makes the sequence scriptable with no terminal — and the marker set is
// asserted at every step. Asserting the markers rather than just that /workspace still reads is the
// point: the two ways the count can be wrong are opposite, and a leaked marker (a mount nobody
// uses) is invisible to the user who would notice the other one.
//
// Beyond the straight line it covers the two rules that exist for a *concurrent* reap
// (`KoAgentFs`, "The workspace FUSE filter's mount lifecycle"). Neither needs a launch that can be
// paused: the state a launch-in-flight presents to a reap is a marker whose container exists and
// is not running, which can be created directly; that a real launch passes through that state and
// no other is the marker's mtime against its container's creation; and that the project lock
// serializes a reap against a launch is a blocked FLOCK request in /proc/locks, not a stopwatch.

package agentsandbox.launcher

import java.nio.file.{Files, Path}

import HostCommands.*
import IntegrationSession.*
import KoAgentFs.*

class MountLifecycleTest extends munit.FunSuite:

  override val munitTimeout = scala.concurrent.duration.Duration(15, "min")

  private val Mounts = ".local/share/ko-agent-sandbox/mounts"

  /** Where the daemon lives, through the launcher's own helper rather than a second opinion. */
  private def vm(script: String): String =
    run(koAgentFsScriptCommand(podman, currentOs, script)*).text

  test("a project's mount is created, reused, held through a launch in flight, and released"):
    optIn()

    val project = scratchProject()
    var started = Vector.empty[Session]
    var lockHolder = ""
    var id = ""
    var planted = ""

    def launch(log: Path): String =
      val appeared = IntegrationSession.launch(project, log)
      started = started :+ appeared
      id = appeared.id
      appeared.container

    def markers(): String =
      vm(s"""ls -1 "$$HOME/$Mounts/$id/sessions" 2>/dev/null || true""")
        .linesIterator.toVector.sorted.mkString(" ")

    def daemonPids(): Vector[String] =
      // `pgrep -a NAME`, never `pgrep -f PATTERN`: matching full command lines would match the
      // shell running this very check, whose own arguments name the mountpoint.
      vm(s"pgrep -a ko-agent-fs 2>/dev/null | grep -F -- 'mounts/$id/workspace' | cut -d' ' -f1")
        .linesIterator.filter(_.nonEmpty).toVector

    def mounted(): Int =
      vm(s"mount 2>/dev/null | grep -c -F -- 'mounts/$id/workspace' || true").trim.toIntOption
        .getOrElse(0)

    /** Blocked flock requests appear in /proc/locks with a `->` marker, so a reap waiting on the
      * project lock is observed rather than inferred from how long a teardown took. */
    def lockWaiters(): Int =
      vm(s"""ino=$$(stat -c %i "$$HOME/$Mounts/$id/lock" 2>/dev/null || echo 0)
            |grep -E '^[0-9]+: -> FLOCK' /proc/locks 2>/dev/null | grep -c ":$$ino " || true
            |""".stripMargin).trim.toIntOption.getOrElse(0)

    try
      val a = launch(project.resolve("a.log"))
      val aLog = Files.readString(project.resolve("a.log"))
      assert(
        aLog.contains("workspace filter: mounted") && !aLog.contains("reusing the mount"),
        s"session A did not create the mount — another session of $id already holds one; its output:\n$aLog",
      )
      assertEquals(eventually(30)(markers())(_ == a), a, "markers after A")
      assertEquals(mounted(), 1, "A is running but its mountpoint is not mounted")
      assertEquals(daemonPids().size, 1, s"expected one daemon for $id")

      val b = launch(project.resolve("b.log"))
      assert(
        Files
          .readString(project.resolve("b.log"))
          .contains("reusing the mount shared by sessions in the same project directory"),
        s"session B did not reuse the mount; its output:\n${Files.readString(project.resolve("b.log"))}",
      )
      val both = Vector(a, b).sorted.mkString(" ")
      assertEquals(eventually(30)(markers())(_ == both), both, "markers with both up")
      assertEquals(daemonPids().size, 1, "B started a second daemon")
      // A daemon holding the project lock would block every later reap for the session's whole
      // life; the mount script closes fd 9 across the fork to prevent exactly that.
      daemonPids().foreach: pid =>
        assertEquals(vm(s"[ -e /proc/$pid/fd/9 ] && echo held || echo free").trim, "free")

      // The ordering the whole reference count rests on, measured rather than assumed: the
      // container is created first, the marker written at the mount after it.
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
      assertEquals(eventually(Patience)(markers())(_ == b), b, "markers after A exits")
      assertEquals(mounted(), 1, "the mount went away while B was still using it")
      assert(run(podman, "exec", b, "sh", "-c", "ls /workspace > /dev/null").ok,
             "B's /workspace stopped serving when A exited")

      // Exactly the state a launch in flight presents to a reap, planted rather than raced for: a
      // marker whose container exists and is not running. Pruning on anything short of the
      // container's absence would take it, find none left, and unmount under a launch still on its
      // way to starting.
      planted = s"ko-agent-sandbox-run-$id-0000dead"
      assert(
        run(podman, "create", "--name", planted, "--pull=never", "ko-agent-sandbox:latest", "true").ok,
        "could not create the planted container",
      )
      vm(s"""touch "$$HOME/$Mounts/$id/sessions/$planted"""")
      run(podman, "stop", "--time", "2", b)
      started = started.filterNot(_.container == b)
      assertEquals(
        eventually(Patience)(markers())(_ == planted), planted,
        "the planted marker did not survive the last real session's reap",
      )
      assertEquals(mounted(), 1, "the mount was pulled out from under a launch in flight")
      assertEquals(daemonPids().size, 1, "the daemon exited under a launch in flight")

      // Its container gone — as the reaper's bounded wait or a reset leaves it — the marker is the
      // next reap's to collect.
      assert(run(podman, "rm", planted).ok, "could not remove the planted container")
      val c = launch(project.resolve("c.log"))
      assert(
        Files
          .readString(project.resolve("c.log"))
          .contains("reusing the mount shared by sessions in the same project directory"),
        "the surviving mount was not reusable",
      )

      // And while C's reap runs, the lock is held from outside: the reap must wait for it rather
      // than counting markers and unmounting under whoever holds it. `-o` so the child does not
      // inherit the locked descriptor — an flock lives on the open file description, so a child
      // holding a copy keeps the lock after the holder is killed.
      lockHolder = vm(
        s"""nohup flock -o "$$HOME/$Mounts/$id/lock" -c 'sleep 300' >/dev/null 2>&1 </dev/null &
           |printf '%s\\n' "$$!"
           |sleep 1
           |""".stripMargin
      ).linesIterator.next().trim
      assert(lockHolder.nonEmpty, "could not start a lock holder in the machine")

      run(podman, "stop", "--time", "2", c)
      started = started.filterNot(_.container == c)
      assert(
        eventually(Patience)(lockWaiters())(_ >= 1) >= 1,
        "no reap ever blocked on the project lock; it is not serializing",
      )
      assertEquals(mounted(), 1, "the mount went down while the lock was held")
      assertEquals(markers(), planted, "expected only the planted marker while the reap is blocked")

      vm(s"kill $lockHolder 2>/dev/null || true")
      lockHolder = ""
      assertEquals(eventually(Patience)(markers())(_.isEmpty), "", "the planted marker was collected")
      assertEquals(eventually(60)(mounted())(_ == 0), 0, "the mountpoint is still mounted")
      assertEquals(eventually(60)(daemonPids().size)(_ == 0), 0, "the daemon is still running")

    finally
      if lockHolder.nonEmpty then vm(s"kill $lockHolder 2>/dev/null || true")
      if planted.nonEmpty then run(podman, "rm", "--force", planted)
      started.foreach(stop)
      discard(project)
