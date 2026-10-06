// The bundle version lock, end to end: a default-named image whose label does not hold this
// jar's digest refuses the launch with the rebuild hint, while an explicitly overridden image
// only warns (LauncherImages.bundleMismatch decides both; this drives the real launcher). The
// proxy image is locked for the egress actions as well as for a launch, since they run it too.
//
// Each mislabelled fixture is built here, FROM the real image with only the label replaced, so
// nothing else about the image changes. The refusal path needs the *default* name to be the
// mislabelled one, so the `:latest` tag is retagged aside and restored in the teardown. A
// run that dies between the two leaves the original under `<image>:bundle-lock-backup` —
// `podman tag ko-agent-sandbox:bundle-lock-backup ko-agent-sandbox:latest` restores it by hand,
// and likewise for ko-agent-egress-proxy.
//
// Runs only under testWithPodman, like the other container-launching suites (WithPodman has the condition):
//
//     sbt "testWithPodman *BundleLockTest"

package agentsandbox.launcher

import java.nio.file.{Files, Path}

import LauncherImages.BundleLabel
import HostCommands.*
import WithPodman.*

class BundleLockTest extends munit.FunSuite:

  override val munitTimeout = scala.concurrent.duration.Duration(15, "min")

  private val Latest = "ko-agent-sandbox:latest"
  private val Backup = "ko-agent-sandbox:bundle-lock-backup"
  private val Mislabelled = "ko-agent-sandbox:bundle-lock-mislabelled"

  private val ProxyLatest = "ko-agent-egress-proxy:latest"
  private val ProxyBackup = "ko-agent-egress-proxy:bundle-lock-backup"
  private val ProxyMislabelled = "ko-agent-egress-proxy:bundle-lock-mislabelled"

  private val LockRefusal = "was not built from the sources this launcher bundles"

  /** The launcher run to completion, for the paths that end without a session: its exit status
    * and output. */
  private def launcherOutcome(
    project: Path,
    log: Path,
    arguments: Vector[String],
    extra: (String, String)*,
  ): (Int, String) =
    val builder = ProcessBuilder((Vector("java", "-jar", jar.toString) ++ arguments)*)
    builder.environment().put(AgentSandboxLauncher.SessionStartVariable, "immediate")
    extra.foreach((name, value) => builder.environment().put(name, value))
    builder.directory(project.toFile)
    builder.redirectErrorStream(true)
    builder.redirectOutput(log.toFile)
    val exit = builder.start().waitFor()
    (exit, Files.readString(log))

  private def buildMislabelled(latest: String, mislabelled: String): Unit =
    val context = Files.createTempDirectory("bundle-lock")
    Files.writeString(context.resolve("Containerfile"), s"FROM $latest\n")
    val built = run(
      podman, "build", "--pull=never",
      "--label", s"$BundleLabel=stale-for-the-bundle-lock-test",
      "-t", mislabelled, context.toString,
    )
    assert(built.ok, s"could not build the mislabelled fixture:\n${built.err}")

  test("a mislabelled default image refuses the launch; the same image overridden only warns"):
    requireTestWithPodman()

    val project = scratchProject()
    var retagged = false
    var live: Option[Session] = None
    try
      buildMislabelled(Latest, Mislabelled)

      assert(runOk(podman, "tag", Latest, Backup), "could not back up ko-agent-sandbox:latest")
      retagged = true
      assert(runOk(podman, "tag", Mislabelled, Latest))

      val (exit, output) = launcherOutcome(project, project.resolve("refused.log"), Vector("sleep", "5"))
      assert(exit != 0, s"the launch was not refused:\n$output")
      assert(output.contains(LockRefusal), s"the refusal does not name the version lock:\n$output")
      assert(output.contains("rebuild with --build"), s"no rebuild hint:\n$output")

      // The real image back under its name before the warn path, which must not depend on the default tag.
      assert(runOk(podman, "tag", Backup, Latest))
      retagged = false

      val session = launch(
        project, project.resolve("warned.log"),
        "KO_AGENT_SANDBOX_IMAGE" -> Mislabelled,
      )
      live = Some(session)
      assert(
        session.output.contains("warning:") && session.output.contains(LockRefusal),
        s"no warning for the explicitly overridden image:\n${session.output}",
      )
    finally
      live.foreach(stop)
      if retagged then runOk(podman, "tag", Backup, Latest)
      runOk(podman, "rmi", Backup)
      runOk(podman, "rmi", Mislabelled)
      discard(project)

  test("a mislabelled default proxy image refuses a launch and both egress actions; overridden, it only warns"):
    requireTestWithPodman()

    val project = scratchProject()
    var retagged = false
    var live: Option[Session] = None
    try
      buildMislabelled(ProxyLatest, ProxyMislabelled)

      assert(runOk(podman, "tag", ProxyLatest, ProxyBackup), "could not back up ko-agent-egress-proxy:latest")
      retagged = true
      assert(runOk(podman, "tag", ProxyMislabelled, ProxyLatest))

      Vector(
        "launch" -> Vector("sleep", "5"),
        "egress-effective" -> Vector("--egress-effective"),
        "egress-check" -> Vector("--egress-check=unlisted.invalid"),
      ).foreach: (name, arguments) =>
        val (exit, output) = launcherOutcome(project, project.resolve(s"refused-$name.log"), arguments)
        assert(exit != 0, s"$name was not refused:\n$output")
        assert(
          output.contains(s"container image $ProxyLatest $LockRefusal"),
          s"the $name refusal does not name the version lock:\n$output",
        )
        assert(output.contains("rebuild with --build"), s"no rebuild hint from $name:\n$output")

      // The real image back under its name before the warn paths, which must not depend on the default tag.
      assert(runOk(podman, "tag", ProxyBackup, ProxyLatest))
      retagged = false

      val overridden = "KO_AGENT_SANDBOX_PROXY_IMAGE" -> ProxyMislabelled
      def warned(output: String): Boolean =
        output.contains("warning:") && output.contains(s"container image $ProxyMislabelled $LockRefusal")

      val (effectiveExit, effective) = launcherOutcome(
        project, project.resolve("warned-egress-effective.log"), Vector("--egress-effective"), overridden,
      )
      assertEquals(effectiveExit, 0, s"--egress-effective failed on the overridden image:\n$effective")
      assert(warned(effective), s"no warning from --egress-effective:\n$effective")

      // The proxy's own `ruleset:` line shows the check ran after the warning. Its exit status is
      // not asserted: with HTTPS_PROXY set, the proxy exits 2 when it cannot set up the upstream
      // proxy (AgentEgressProxy.checkHost).
      val (_, checked) = launcherOutcome(
        project, project.resolve("warned-egress-check.log"), Vector("--egress-check=unlisted.invalid"), overridden,
      )
      assert(warned(checked), s"no warning from --egress-check:\n$checked")
      assert(
        checked.contains("ruleset: unlisted.invalid"),
        s"--egress-check did not run the overridden image:\n$checked",
      )

      val session = launch(project, project.resolve("warned.log"), overridden)
      live = Some(session)
      assert(warned(session.output), s"no warning for the explicitly overridden image:\n${session.output}")
    finally
      live.foreach(stop)
      if retagged then runOk(podman, "tag", ProxyBackup, ProxyLatest)
      runOk(podman, "rmi", ProxyBackup)
      runOk(podman, "rmi", ProxyMislabelled)
      discard(project)
