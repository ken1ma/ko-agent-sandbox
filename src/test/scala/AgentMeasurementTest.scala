// Runs src/test/measurement/MeasureAgents.scala in a session of this workspace and reads the session's proxy log
// against the records in ko-agent-egress-proxy/doc/preset (doc/agent-measurement.md, "The measurement suite"):
//
//     sbt "testWithPodman *AgentMeasurementTest"
//
// - The session is this workspace's own, so it has the workspace's persistent volume and the agents' sign-ins there.
//   A scratch workspace would have a fresh volume, and --persistent-volume refuses the generated volume names.
// - A test skips when its agent is not signed in in that volume. Sign in to the agent in a session of this workspace.
// - The turns run on the signed-in accounts.
// - Each test writes the driver's output and the report to log/measurement-report-<agent>.log.

package agentsandbox.launcher

import java.nio.file.{Files, Path, Paths}

import HostCommands.*
import Podman.*
import WithPodman.*

class AgentMeasurementTest extends munit.FunSuite:

  override val munitTimeout = scala.concurrent.duration.Duration(30, "min")

  private val workspace: Path = Paths.get("").toAbsolutePath

  /** The driver's line for a mode's start: `measure: <mode> start <UTC time>`. */
  private val DriverStart = raw"measure: .* start (\S+)".r

  private def measured(agent: String, signedIn: Session => Boolean, host: String): Unit =
    requireTestWithPodman()
    val logs = Files.createTempDirectory("agent-measurement")
    val session = launchWith(
      workspace, logs.resolve("session.log"),
      Vector("--egress=deny-unless-allowed", "--egress-preset=anthropic,openai,google,aws,github"),
    )
    try
      assume(signedIn(session), s"$agent is not signed in in this workspace's volume; sign in in a session first")
      // From the workspace's path inside the container, which differs from the host's on Windows. The command is the
      // one that the driver's header gives.
      val driver = execSh(
        session,
        "cd \"$1\" && scala $KO_AGENT_SANDBOX_JAVA_OPTS run --workspace ~/.cache/measure-agents " +
          "src/test/measurement/MeasureAgents.scala -- \"$2\"",
        mountPath(session), agent,
      )
      val proxy = run(podman, "logs", session.proxy)
      val log = (proxy.text + "\n" + proxy.err).linesIterator.toVector
      // From the first mode's start: Scala CLI's compile of the driver downloads its tools before it, and a dropped
      // download there is no agent's.
      val firstStart = driver.text.linesIterator.collectFirst { case DriverStart(stamp) => stamp }
      val reported =
        MeasurementReport.selected(log, firstStart).map(MeasurementReport.report(_, MeasurementReport.records()))
      // Before the assertions, so that a failed run's report, or why it has none, stays without repeating the turns.
      MeasurementReport.saved(
        Paths.get(s"log/measurement-report-$agent.log"),
        s"the driver:\n${driver.text}\n${driver.err}\n\nthe proxy log of ${session.proxy}:\n" +
          reported.fold(reason => s"$reason\n${proxy.err}", _.text),
      )
      assert(driver.ok, s"a mode did not complete:\n${driver.text}\n${driver.err}")
      val result = reported.fold(reason => fail(reason), identity)
      assert(result.findings.isEmpty, s"lines that no record accepts:\n${result.text}\n\nthe driver:\n${driver.text}")
      val probes = result.probes.filter(_.host == host)
      assert(probes.exists(_.framing.startsWith("content-length=")), s"no whole upload to $host:\n${result.text}")
      assert(
        probes.exists(probe => probe.framing == "chunked" && probe.end.endsWith("incomplete")),
        s"no cut chunked upload to $host:\n${result.text}",
      )
    finally
      stop(session)
      FileHelper.deleteRecursively(logs)

  test("Claude Code's unattended modes leave only lines that its record accepts"):
    measured(
      "claude",
      // The JSON's loggedIn decides, as in ko-review's ClaudeReviewer.signed_in.
      session =>
        exec(session, "claude", "auth", "status", "--json").text.matches("(?s).*\"loggedIn\":\\s*true.*"),
      "api.anthropic.com",
    )

  test("Codex's unattended modes leave only lines that its record accepts"):
    measured(
      "codex",
      session => exec(session, "codex", "login", "status").ok,
      "api.openai.com",
    )

  test("agy's unattended modes leave only lines that its record accepts"):
    measured(
      "agy",
      // agy has no status command. Without a D-Bus session, its sign-in writes the token to this file.
      session => execSh(session, "jq -e '.token.refresh_token' ~/.gemini/antigravity-cli/antigravity-oauth-token").ok,
      "daily-cloudcode-pa.googleapis.com",
    )

  test("Kiro's unattended modes leave only lines that its record accepts"):
    measured(
      "kiro-cli",
      session => exec(session, "kiro-cli", "whoami").ok,
      "runtime.us-east-1.kiro.dev",
    )

  test("Copilot's unattended modes leave only lines that its record accepts"):
    measured(
      "copilot",
      // copilot has no status command. Its config.json starts with // comments, which jq does not read.
      session =>
        execSh(session, "grep -v '^ *//' ~/.copilot/config.json | jq -e '(.loggedInUsers // []) | length > 0'").ok,
      "api.githubcopilot.com",
    )

  test("OpenCode's unattended modes leave only lines that its record accepts"):
    measured(
      "opencode",
      // The driver measures the ChatGPT sign-in alone.
      session => execSh(session, "jq -e '.openai.type == \"oauth\"' ~/.local/share/opencode/auth.json").ok,
      "chatgpt.com",
    )
