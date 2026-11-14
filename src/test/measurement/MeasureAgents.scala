//> using scala 3.10.0
//> using file ../../main/scala/JsonText.scala
//> using file ../scala/AgentEvents.scala

/*
  Runs the measurement modes that need no person, inside a session whose agents are signed in
  (doc/plan-tls-inspect-agents.md, "The measurement suite"). The session's proxy log then goes to MeasurementReport on
  the host. Each mode prints its UTC start and end, so that the report can be matched with the modes.

  Run it in the session, from the repository root. Both agents run when none is named:

      scala $KO_AGENT_SANDBOX_JAVA_OPTS run --workspace ~/.cache/measure-agents \
          src/test/measurement/MeasureAgents.scala -- [claude] [codex] [copilot]

  - The image's native scala launcher reads no proxy settings, so the options go on its command line.
  - --workspace keeps Scala CLI's build state out of the workspace, where a host's run of another script would trip
    over the container's compiler paths.

  It exits 1 when a mode did not complete, and 2 on a usage error. The manual items for the release follow the modes.
*/

import agentsandbox.launcher.AgentEvents.*

import java.io.File
import java.lang.ProcessBuilder.Redirect
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path}
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.concurrent.TimeUnit

import scala.jdk.CollectionConverters.*
import scala.util.Using

object MeasureAgents:

  val Agents = Vector("claude", "codex", "copilot")
  val TurnTimeoutSeconds = 900L
  // The turns read these files, so that their tool calls have something to find.
  val NoteNames = Vector("a.txt", "b.txt")

  private var failed = false
  private var mode = ""

  private def stamp: String = Instant.now.truncatedTo(ChronoUnit.SECONDS).toString

  private def start(name: String): Unit =
    mode = name
    println(s"measure: $mode start $stamp")

  private def finish(problem: Option[String]): Unit = problem match
    case None => println(s"measure: $mode end $stamp")
    case Some(why) =>
      println(s"measure: $mode FAILED $stamp: $why")
      failed = true

  private val NoInput = Redirect.from(File("/dev/null"))

  /** Runs an agent's turn with stdin from /dev/null and each output stream to a file, and gives its events. codex exec
    * reads stdin when it is not a terminal. */
  private def turn(work: Path, name: String, command: String*): Vector[agentsandbox.launcher.JsonText.Json] =
    val (out, err) = (work.resolve(s"$name.jsonl"), work.resolve(s"$name.err"))
    val process = ProcessBuilder(command*).directory(work.toFile).redirectInput(NoInput)
      .redirectOutput(out.toFile).redirectError(err.toFile).start()
    if !process.waitFor(TurnTimeoutSeconds, TimeUnit.SECONDS) then process.destroyForcibly().waitFor()
    events(out)

  private def output(command: String*): String =
    val process = ProcessBuilder(command*).redirectErrorStream(true).redirectInput(NoInput).start()
    val text = String(process.getInputStream.readAllBytes(), UTF_8)
    process.waitFor()
    text

  private def onPath(program: String): Boolean =
    sys.env.getOrElse("PATH", "").split(File.pathSeparator).exists(dir => Files.isExecutable(Path.of(dir, program)))

  private def tail(file: Path): String =
    if Files.isRegularFile(file) then Files.readString(file, UTF_8).takeRight(300).replace('\n', ' ') else ""

  /** A foreign credential's upload to a model host: whole, then chunked and cut short. Each shows on the host as a
    * line with client=curl and a credential index of its own, and the cut one as an incomplete chunked-end line. */
  private def upload(work: Path, host: String, url: String, headers: String*): Unit =
    val body = java.util.Base64.getEncoder.encodeToString(scala.util.Random.nextBytes(2000)).take(2000)
    val file = work.resolve("upload.bin")
    Files.writeString(file, body)
    val curl = Vector("curl", "-sS", "--max-time", "60", "-o", "/dev/null", "-X", "POST", url) ++ headers
    start(s"$host upload, whole")
    val answer = output((curl ++ Vector("-w", "%{http_code}", "--data-binary", s"@$file"))*).trim
    finish(Option.when(answer.endsWith("000"))(s"no answer from $url: $answer"))
    start(s"$host upload, chunked and cut short")
    // The trace's "=> Send data" line shows the chunk leaving curl, after the tunnel's and TLS's own records.
    // One file per upload, so that no earlier upload's trace answers for this one.
    val trace = work.resolve(s"$host.trace")
    Files.deleteIfExists(trace)
    // Without `Expect: 100-continue`, which GitHub answers with its 401 at once, so that curl sends no body.
    val sender = ProcessBuilder((curl ++ Vector("-H", "Expect:", "-T", "-", "--trace-ascii", trace.toString))*)
      .redirectOutput(Redirect.DISCARD).redirectError(Redirect.DISCARD).start()
    sender.getOutputStream.write(body.take(500).getBytes(UTF_8))
    sender.getOutputStream.flush()
    def chunkSent =
      Files.isRegularFile(trace) && Files.readString(trace, UTF_8).linesIterator.exists(_.startsWith("=> Send data"))
    val deadline = System.nanoTime + 30_000_000_000L
    while !chunkSent && sender.isAlive && System.nanoTime < deadline do Thread.sleep(100)
    // A curl that exited or never sent the chunk held no body open, so the log has no cut body.
    val cut = chunkSent && sender.isAlive
    // So that the proxy relays the chunk before the cut.
    if cut then Thread.sleep(1000)
    sender.destroy()
    sender.waitFor()
    finish(Option.unless(cut)(s"curl sent no chunk before the cut; see ${tail(trace)}"))

  // Claude Code's print mode, with the flags that ko-review gives it apart from its tool list and schema.
  private def measureClaude(work: Path): Unit =
    start("claude -p with a tool call and a subagent")
    val run = turn(
      work, "claude", "claude", "-p", "--verbose", "--output-format", "stream-json", "--setting-sources", "",
      "--strict-mcp-config", "--permission-prompts", "none",
      "Use the Bash tool to run 'wc -l words.txt'. Then start one subagent with the Agent tool, and have it list the " +
        "notes directory with its own Bash tool. Answer in one line with the line count and the file names. Do not " +
        "modify anything.",
    )
    if !claudeSucceeded(run) then
      val seen = s"${tail(work.resolve("claude.err"))} ${tail(work.resolve("claude.jsonl"))}"
      finish(Some(s"no successful result; see $seen"))
    else
      val lacks = claudeLacks(run)
      finish(Option.when(lacks.nonEmpty)(s"the run lacked ${lacks.mkString(", ")}"))
    upload(work, "api.anthropic.com", "https://api.anthropic.com/v1/files",
      "-H", "x-api-key: sk-ant-api03-measurement-not-a-key", "-H", "anthropic-version: 2023-06-01",
      "-H", "Content-Type: text/plain")

  private def measureCodex(work: Path): Unit =
    val exec = Vector("codex", "exec", "--json", "--dangerously-bypass-approvals-and-sandbox", "--skip-git-repo-check")
    start("codex exec with tool calls")
    val first = turn(work, "codex", (exec :+
      "Run 'wc -l words.txt' and 'ls notes' in the shell, then answer in one line with the line count and the file " +
        "names. Do not modify anything.")*)
    finish(Option.unless(codexCompleted(first) && codexRanCommand(first))(
      s"no completed turn with a command; see ${tail(work.resolve("codex.err"))}",
    ))
    val thread = codexThread(first)
    start("codex exec resume")
    // resume takes the same options after its own name.
    val resumed = thread.toVector.flatMap(id =>
      turn(work, "codex-resume", (exec.take(2) ++ Vector("resume") ++ exec.drop(2) ++ Vector(id,
        "Now run 'cat words.txt' in the shell and answer with its last line. Do not modify anything."))*),
    )
    finish(Option.unless(codexCompleted(resumed) && codexRanCommand(resumed))(
      s"no completed resumed turn with a command${thread.fold("")(id => s" of thread $id")}; see " +
        tail(work.resolve("codex-resume.err")),
    ))
    start("codex exec with a subagent")
    val spawned = turn(work, "spawn", (exec :+
      "Spawn one subagent and have it run 'ls notes' in the shell and report the file names. Wait for it, then " +
        "answer in one line with its result. Do not modify anything.")*)
    val sessions = Path.of(sys.env.getOrElse("CODEX_HOME", s"${sys.props("user.home")}/.codex"), "sessions")
    finish(Option.unless(codexCompleted(spawned) &&
        codexThread(spawned).exists(codexChildAnswered(sessions, _, NoteNames)))(
      s"no completed turn whose subagent answered; see ${tail(work.resolve("spawn.err"))}",
    ))
    upload(work, "api.openai.com", "https://api.openai.com/v1/files",
      "-H", "Authorization: Bearer sk-measurement-not-a-key")

  private def measureCopilot(work: Path): Unit =
    val prompt = Vector("copilot", "--allow-all-tools", "--output-format", "json", "-p")
    start("copilot -p with a shell call and a subagent")
    // 1.0.111's task agent asks for a model of its own, which the origin refused for an individual plan
    // (model_not_supported); a general-purpose agent takes the session's.
    val first = turn(work, "copilot", (prompt :+
      "Use the shell to run 'wc -l words.txt'. Then start one general-purpose subagent with your task tool, and " +
        "have it list the notes directory with its own shell tool. Answer in one line with the line count and the " +
        "file names. Do not modify anything.")*)
    if !copilotSucceeded(first) then
      val seen = s"${tail(work.resolve("copilot.err"))} ${tail(work.resolve("copilot.jsonl"))}"
      finish(Some(s"no successful result; see $seen"))
    else
      val lacks = copilotLacks(first)
      finish(Option.when(lacks.nonEmpty)(s"the run lacked ${lacks.mkString(", ")}"))
    val session = copilotSession(first)
    start("copilot --resume -p")
    val resumed = session.toVector.flatMap(id =>
      turn(work, "copilot-resume", (Vector("copilot", s"--resume=$id") ++ prompt.drop(1) :+
        "Now run 'cat words.txt' in the shell and answer with its last line. Do not modify anything.")*),
    )
    finish(Option.unless(copilotSucceeded(resumed) && copilotRanShell(resumed))(
      s"no successful resumed turn with a shell call${session.fold("")(id => s" of session $id")}; see " +
        tail(work.resolve("copilot-resume.err")),
    ))
    start("copilot -p with the GitHub MCP server")
    val mcp = turn(work, "mcp", (prompt :+
      "Use your GitHub MCP tools, not the shell, to read the title of issue 1 in the repository github/copilot-cli. " +
        "Answer with the title only. Do not modify anything.")*)
    finish(Option.unless(copilotSucceeded(mcp) && copilotCalledGithubMcp(mcp))(
      s"no successful turn with a GitHub MCP call; see ${tail(work.resolve("mcp.err"))}",
    ))
    // The generic host, which every plan's client can reach; the plan's own host varies by account.
    upload(work, "api.githubcopilot.com", "https://api.githubcopilot.com/responses",
      "-H", "Authorization: Bearer gho_measurement-not-a-token")

  // What stays manual (doc/plan-tls-inspect-agents.md, "The measurement suite"). The record names each item with the
  // version it was measured at.
  private val ManualItems = Map(
    "claude" ->
      """- claude: an interactive session with tool calls, a subagent, WebFetch and /compact; /voice under --audio=mic;
        |  /logout, /login and a message; a token refresh, forced by moving claudeAiOauth.expiresAt in
        |  ~/.claude/.credentials.json into the past""".stripMargin,
    "codex" ->
      """- codex: the TUI with two turns and two compactions; codex logout, codex login --device-auth; a token refresh,
        |  forced by a rejected access token; codex exec under an API key, in a throwaway CODEX_HOME""".stripMargin,
    "copilot" ->
      """- copilot: an interactive session with two turns and /compact; /login and a message (/logout fails in the
        |  sandbox); a launch under --egress=deny-unless-model, with copilot as its command""".stripMargin,
  )

  private def deleteTree(root: Path): Unit =
    Using.resource(Files.walk(root))(_.iterator.asScala.toVector.reverse.foreach(Files.deleteIfExists))

  def run(arguments: Seq[String]): Int =
    if !arguments.forall(Agents.contains) then
      System.err.println("usage: src/test/measurement/MeasureAgents.scala -- [claude] [codex] [copilot]")
      return 2
    val agents = if arguments.isEmpty then Agents else arguments.toVector.distinct
    (agents :+ "curl").find(program => !onPath(program)) match
      case Some(program) =>
        System.err.println(s"measure: $program is not on PATH")
        return 1
      case None =>
    // A directory of its own, which is no repository.
    val work = Files.createTempDirectory(Path.of(sys.props("user.home")), "measure-agents")
    try
      Files.writeString(work.resolve("words.txt"), "alpha\nbeta\ngamma\n")
      Files.createDirectories(work.resolve("notes"))
      NoteNames.zip(Vector("one\n", "two\n"))
        .foreach((name, text) => Files.writeString(work.resolve(s"notes/$name"), text))
      agents.foreach: agent =>
        println(s"measure: $agent ${output(agent, "--version").linesIterator.nextOption().getOrElse("")}")
        agent match
          case "claude" => measureClaude(work)
          case "codex"  => measureCodex(work)
          case _        => measureCopilot(work)
    // A failed mode's event files are the evidence for its message.
    finally if failed then println(s"measure: the turns' files stay in $work") else deleteTree(work)
    println()
    println("Manual items, in this session, before the reader runs on the host:")
    agents.foreach(agent => println(ManualItems(agent)))
    println("Then on the host: sbt \"Test/runMain agentsandbox.launcher.MeasurementReport\"")
    if failed then 1 else 0

@main def measure(arguments: String*): Unit = sys.exit(MeasureAgents.run(arguments))
