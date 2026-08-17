// The bundle version lock, end to end: a default-named image whose label does not carry this
// jar's digest refuses the launch with the rebuild hint, while an explicitly overridden image
// only warns (AgentSandboxLauncher.bundleMismatch decides both; this drives real launches). The
// sandbox image carries the whole demonstration — the proxy image goes through the same
// bundleMismatch, unit-pinned in AgentSandboxLauncherTest.
//
// The mislabelled fixture is built here, FROM the real image with only the label replaced, so
// nothing else about the image changes. The refusal path needs the *default* name to be the
// mislabelled one, so ko-agent-sandbox:latest is retagged aside and restored in the teardown. A
// run that dies between the two leaves the original under ko-agent-sandbox:bundle-lock-backup —
// `podman tag ko-agent-sandbox:bundle-lock-backup ko-agent-sandbox:latest` restores it by hand.
//
// Opt-in like the other container-launching suites (IntegrationSession has the gate):
//
//     KO_AGENT_SANDBOX_INTEGRATION=1 sbt "testOnly *BundleLockTest"

package agentsandbox.launcher

import java.nio.file.{Files, Path}

import AgentSandboxLauncher.BundleLabel
import HostCommands.*
import IntegrationSession.*

class BundleLockTest extends munit.FunSuite:

  override val munitTimeout = scala.concurrent.duration.Duration(15, "min")

  private val Latest = "ko-agent-sandbox:latest"
  private val Backup = "ko-agent-sandbox:bundle-lock-backup"
  private val Mislabelled = "ko-agent-sandbox:bundle-lock-mislabelled"

  /** A launch run to completion, for the path that must refuse before any session exists. */
  private def launcherExit(project: Path, log: Path): Int =
    val builder = ProcessBuilder("java", "-jar", jar.toString, "sleep", "5")
    builder.environment().put(AgentSandboxLauncher.SessionStartVariable, "immediate")
    builder.directory(project.toFile)
    builder.redirectErrorStream(true)
    builder.redirectOutput(log.toFile)
    builder.start().waitFor()

  test("a mislabelled default image refuses the launch; the same image overridden only warns"):
    assume(enabled, requirement)

    val project = scratchProject()
    var retagged = false
    var live: Option[Session] = None
    try
      val context = Files.createTempDirectory("bundle-lock")
      Files.writeString(context.resolve("Containerfile"), s"FROM $Latest\n")
      val built = run(
        podman, "build", "--pull=never",
        "--label", s"$BundleLabel=stale-for-the-bundle-lock-test",
        "-t", Mislabelled, context.toString
      )
      assert(built.ok, s"could not build the mislabelled fixture:\n${built.err}")

      assert(runOk(podman, "tag", Latest, Backup), "could not back up ko-agent-sandbox:latest")
      retagged = true
      assert(runOk(podman, "tag", Mislabelled, Latest))

      val refusedLog = project.resolve("refused.log")
      val exit = launcherExit(project, refusedLog)
      val output = Files.readString(refusedLog)
      assert(exit != 0, s"the launch was not refused:\n$output")
      assert(
        output.contains("was not built from the sources this launcher bundles"),
        s"the refusal does not name the version lock:\n$output"
      )
      assert(output.contains("rebuild with --build"), s"no rebuild hint:\n$output")

      // The honest name back before the warn path, which must owe nothing to the default tag.
      assert(runOk(podman, "tag", Backup, Latest))
      retagged = false

      val session = launch(
        project, project.resolve("warned.log"),
        "KO_AGENT_SANDBOX_IMAGE" -> Mislabelled
      )
      live = Some(session)
      assert(
        session.output.contains("warning:")
          && session.output.contains("was not built from the sources this launcher bundles"),
        s"no warning for the explicitly overridden image:\n${session.output}"
      )
    finally
      live.foreach(stop)
      if retagged then runOk(podman, "tag", Backup, Latest)
      runOk(podman, "rmi", Backup)
      runOk(podman, "rmi", Mislabelled)
      discard(project)
