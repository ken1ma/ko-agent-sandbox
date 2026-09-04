// The --stats record across the resets that can leave a generated volume behind: a --reset under
// a configured shared volume keeps this project's generated volume and, with it, the record; a
// --reset-cache after it asks podman for that volume rather than inferring its absence from the
// state directories the reset removed; the plain --reset then takes both. discard covers the
// common case, a reset with nothing kept, in every suite's teardown.
//
// Opt-in like the other container-launching suites (IntegrationSession has the gate):
//
//     KO_AGENT_SANDBOX_INTEGRATION=1 sbt "testOnly *ResetRecordTest"

package agentsandbox.launcher

import java.nio.file.Files

import HostCommands.*
import IntegrationSession.*

class ResetRecordTest extends munit.FunSuite:

  override val munitTimeout = scala.concurrent.duration.Duration(15, "min")

  test("the record outlives a generated volume a shared one left behind, and no longer"):
    optIn()

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

      val (cacheOk, cacheOutput) = resetCache(project)
      assert(cacheOk, s"--reset-cache failed; its output:\n$cacheOutput")
      assert(Files.exists(record), "--reset-cache dropped the record with the generated volume still there")

      val (ok, output) = reset(project)
      assert(ok, s"--reset failed; its output:\n$output")
      assert(!runOk(podman, "volume", "exists", volume), "the reset left the generated volume")
      assert(!Files.exists(record), "the record outlived everything it named")
    finally
      discard(project)
