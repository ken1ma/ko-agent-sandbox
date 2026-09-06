// The --stats record across the resets that can leave a generated volume behind: a --reset under
// a configured shared volume keeps this project's generated volume and, with it, the record; a
// --reset-run-on-host after it asks podman for that volume rather than inferring its absence from the
// state directories the reset removed; the plain --reset then takes both. discard covers the
// common case, a reset with nothing kept, in every suite's teardown. The last test is the project
// whose directory went before any reset: --stats can only name it by id, and --reset takes that.
//
// Runs only under testWithPodman, like the other container-launching suites (WithPodman has the gate):
//
//     sbt "testWithPodman *ResetRecordTest"

package agentsandbox.launcher

import java.nio.file.Files

import HostCommands.*
import WithPodman.*

class ResetRecordTest extends munit.FunSuite:

  override val munitTimeout = scala.concurrent.duration.Duration(15, "min")

  test("the record outlives a generated volume a shared one left behind, and no longer"):
    requireTestWithPodman()

    val project = scratchProject()
    try
      val session = launch(project, project.resolve("launch.log"))
      stop(session)
      val record = projectRecord(project)
      val volume = s"ko-agent-sandbox-persistent-${session.id}"
      assert(Files.exists(record), "the launch recorded the project")
      assert(runOk(podman, "volume", "exists", volume), "the launch created the generated volume")

      val (sharedOk, sharedOutput) =
        reset(project, "KO_AGENT_SANDBOX_PERSISTENT_VOLUME" -> "reset-record-test-shared")
      assert(sharedOk, s"--reset under a shared volume failed; its output:\n$sharedOutput")
      assert(runOk(podman, "volume", "exists", volume), "the reset removed the generated volume it was to keep")
      assert(Files.exists(record), "the record went while the generated volume remained")

      val (cacheOk, cacheOutput) = resetRunOnHost(project)
      assert(cacheOk, s"--reset-run-on-host failed; its output:\n$cacheOutput")
      assert(Files.exists(record), "--reset-run-on-host dropped the record with the generated volume still there")

      val (ok, output) = reset(project)
      assert(ok, s"--reset failed; its output:\n$output")
      assert(!runOk(podman, "volume", "exists", volume), "the reset left the generated volume")
      assert(!Files.exists(record), "the record outlived everything it named")
    finally
      discard(project)

  test("a project whose directory is gone is listed by its id, which --reset takes from anywhere"):
    requireTestWithPodman()

    val project = scratchProject()
    val elsewhere = scratchProject()
    try
      val session = launch(project, project.resolve("launch.log"))
      stop(session)
      val record = projectRecord(project)
      val volume = s"ko-agent-sandbox-persistent-${session.id}"
      assertEquals(
        SandboxStats.projectDirectories(record.getParent).get(session.id),
        Some(project.toRealPath().toString),
        "the launch recorded the project's directory",
      )

      // A cache as a host build would leave, since --reset takes it with the rest.
      val cache = RunOnHostPrereqs.buildCacheDir(
        RunOnHostPrereqs.cacheRootOf(currentOs, env).fold(refusal => fail(refusal.toString), identity), session.id,
      )
      Files.createDirectories(cache)
      Files.writeString(cache.resolve("planted"), "")

      // The reported case: the directory removed before any reset, so the row can only name the id.
      deleteRecursively(project)
      assertEquals(
        SandboxStats.projectDirectories(record.getParent).get(session.id), None, "the gone directory still named",
      )
      assert(Files.exists(record), "the record itself stays until a reset")

      // Several ids at once, each reset before any is reported: the unknown one fails the
      // invocation, and the known one is gone all the same.
      val (ok, output) = resetIds(elsewhere, session.id, "never-000000000000")
      assert(!ok && output.contains("no project never-000000000000"), output)
      assert(!runOk(podman, "volume", "exists", volume), "the reset left the generated volume")
      assert(!Files.exists(record), "the reset left the record")
      assert(!Files.exists(cache), "the reset left the host-build cache")
      assert(
        !SandboxStats.projectIds(currentOs, Vector.empty).contains(session.id), "the reset left state under the id",
      )
    finally
      // The same path is the same id, so a failure above is reset from the recreated directory.
      Files.createDirectories(project)
      discard(project)
      deleteRecursively(elsewhere)
