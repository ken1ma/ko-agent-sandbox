// What src/test/measurement/MeasureAgents.scala reads in the agents' event streams to decide that a mode completed. The
// driver pulls this file in with `//> using file`; sbt compiles it with the tests, and AgentEventsTest holds it to
// recorded events.

package agentsandbox.launcher

import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path}

import scala.jdk.CollectionConverters.*
import scala.util.Using

import JsonText.Json

object AgentEvents:

  /** The text's lines that are JSON values. */
  def parseLines(text: String): Vector[Json] =
    text.linesIterator.toVector.flatMap(line => JsonText.parse(line).toOption)

  def events(file: Path): Vector[Json] =
    if Files.isRegularFile(file) then parseLines(Files.readString(file, UTF_8)) else Vector.empty

  extension (json: Json)
    def at(path: String*): Option[Json] = path.foldLeft(Option(json))((value, key) => value.flatMap(_.field(key)))
    def text(path: String*): Option[String] = at(path*).collect { case Json.Str(value) => value }
    def items(path: String*): Vector[Json] = at(path*).toVector.flatMap:
      case Json.Arr(values) => values
      case _                => Vector.empty
    def is(key: String, value: String): Boolean = text(key).contains(value)

  private val True = Json.Bool(true)
  private val Zero = Json.Num("0")

  /** What a first turn lacks of its three parts, each named with the agent's word for its shell tool. */
  private def lacking(
    shell: Boolean,
    subagent: Boolean,
    subagentShell: Boolean,
    tool: String = "shell",
  ): Vector[String] =
    Vector(
      Option.unless(shell)(s"a $tool call"),
      Option.unless(subagent)("a subagent"),
      Option.unless(subagentShell)(s"the subagent's $tool call"),
    ).flatten

  /** Whether `claude -p --output-format stream-json` ended in success. A run can exit 0 with the error in the result
    * (anthropics/claude-code#79500), so the result event decides. */
  def claudeSucceeded(run: Vector[Json]): Boolean =
    run.exists(event =>
      event.is("type", "result") && event.is("subtype", "success") && !event.at("is_error").contains(True),
    )

  private final case class ToolCall(id: Option[String], name: Option[String], parent: Option[String])

  /** What the run lacks of a Bash call, a subagent and the subagent's own Bash call that all succeeded. A denied or
    * failed call still leaves its tool_use and a successful result, so each call's tool_result decides. */
  def claudeLacks(run: Vector[Json]): Vector[String] =
    def blocks(kind: String, blockType: String) =
      run.filter(_.is("type", kind)).flatMap(event => event.items("message", "content").map(event -> _))
        .filter((_, block) => block.is("type", blockType))
    val calls = blocks("assistant", "tool_use").map((event, block) =>
      ToolCall(block.text("id"), block.text("name"), event.text("parent_tool_use_id")),
    )
    val succeeded = blocks("user", "tool_result").map(_._2).filterNot(_.at("is_error").contains(True))
      .flatMap(_.text("tool_use_id")).toSet
    val done = calls.filter(_.id.exists(succeeded))
    val agents = done.filter(_.name.exists(Set("Agent", "Task"))).flatMap(_.id).toSet
    val denied = run.filter(_.is("type", "result")).flatMap(_.items("permission_denials"))
    def ranBash(by: ToolCall => Boolean) = done.exists(call => call.name.contains("Bash") && by(call))
    Option.when(denied.nonEmpty)("no denied call").toVector ++
      lacking(ranBash(_.parent.isEmpty), agents.nonEmpty, ranBash(_.parent.exists(agents)), tool = "Bash")

  def codexCompleted(run: Vector[Json]): Boolean = run.exists(_.is("type", "turn.completed"))

  /** Whether a shell command of `codex exec --json` completed with exit status 0. A failed command is an
    * item.completed too. */
  def codexRanCommand(run: Vector[Json]): Boolean =
    run.exists(event =>
      event.is("type", "item.completed") && event.text("item", "type").contains("command_execution") &&
        event.text("item", "status").contains("completed") && event.at("item", "exit_code").contains(Zero),
    )

  def codexThread(run: Vector[Json]): Option[String] =
    run.find(_.is("type", "thread.started")).flatMap(_.text("thread_id"))

  /** Whether a rollout is a subagent's of the parent thread that completed its task with an answer holding every
    * word. The rollout's session_meta names the parent thread. */
  def codexChildAnswered(rollout: Vector[Json], parent: String, words: Seq[String]): Boolean =
    rollout.exists(line =>
      line.is("type", "session_meta") && line.text("payload", "parent_thread_id").contains(parent),
    ) &&
      rollout.exists(line =>
        line.is("type", "event_msg") && line.text("payload", "type").contains("task_complete") &&
          line.text("payload", "last_agent_message").exists(answer => words.forall(answer.contains)),
      )

  /** Whether a subagent of the parent thread answered with every word, among the rollouts under `sessions`
    * (~/.codex/sessions). codex exec's events leave the spawn out and show only an empty wait item, so the child's own
    * rollout decides. A rollout's first line is its own session_meta, so only the child's rollout is read whole. */
  def codexChildAnswered(sessions: Path, parent: String, words: Seq[String]): Boolean =
    def firstLine(path: Path): Option[String] = Using.resource(Files.newBufferedReader(path, UTF_8))(reader =>
      Option(reader.readLine()),
    )
    def childOf(path: Path): Boolean =
      firstLine(path).flatMap(line => JsonText.parse(line).toOption)
        .exists(meta => meta.is("type", "session_meta") && meta.text("payload", "parent_thread_id").contains(parent))
    Files.isDirectory(sessions) && Using.resource(Files.walk(sessions)): paths =>
      paths.iterator.asScala
        .filter(path => path.getFileName.toString.matches("rollout-.*\\.jsonl") && childOf(path))
        .exists(path => codexChildAnswered(events(path), parent, words))

  /** Whether `agy -p --output-format stream-json` ended in success: its result event's status. */
  def agySucceeded(run: Vector[Json]): Boolean = run.exists(_.text("result", "status").contains("SUCCESS"))

  // A failed command is a completed step too, and only its output tells the two apart.
  private val AgyCommandSucceeded = "Command exited with code 0."

  private def agyDone(run: Vector[Json], stepType: String): Vector[Json] =
    run.flatMap(_.at("step_update")).filter(step => step.is("state", "DONE") && step.is("step_type", stepType))

  def agyRanShell(run: Vector[Json]): Boolean =
    agyDone(run, "tool").exists(step =>
      step.is("tool_name", "run_command") && step.text("tool_info", "output").exists(_.contains(AgyCommandSucceeded)),
    )

  /** The transcripts of the subagents that the run started. agy's stream leaves a subagent's own steps out; the
    * subagent writes them to the transcript that its log_uri names. */
  def agySubagentTranscripts(run: Vector[Json]): Vector[Path] =
    agyDone(run, "subagent").flatMap(_.items("subagent_info", "subagents")).flatMap(_.text("log_uri"))
      .map(uri => Path.of(java.net.URI(uri)))

  /** Whether a subagent's transcript holds a shell call that exited 0: the call, then a step whose output says so. */
  def agyTranscriptRanShell(transcript: Vector[Json]): Boolean =
    val call = transcript.indexWhere(_.items("tool_calls").exists(_.is("name", "run_command")))
    call >= 0 && transcript.drop(call + 1).exists(_.text("content").exists(_.contains(AgyCommandSucceeded)))

  /** What the run lacks of a shell call, a subagent, and that subagent's own shell call. */
  def agyLacks(run: Vector[Json]): Vector[String] =
    val transcripts = agySubagentTranscripts(run)
    lacking(
      agyRanShell(run), transcripts.nonEmpty, transcripts.exists(path => agyTranscriptRanShell(events(path))),
    )

  def agyConversation(run: Vector[Json]): Option[String] =
    run.flatMap(_.at("result")).flatMap(_.text("conversation_id")).headOption

  /** The engine that `kiro-cli chat --output-format stream-json` ran, from its runStarted event. */
  def kiroEngine(run: Vector[Json]): Option[String] =
    run.find(_.is("type", "runStarted")).flatMap(_.text("data", "engine"))

  def kiroSucceeded(run: Vector[Json]): Boolean =
    run.exists(event => event.is("type", "runFinished") && event.text("data", "status").contains("success"))

  def kiroSession(run: Vector[Json]): Option[String] =
    run.find(_.is("type", "runFinished")).flatMap(_.text("data", "sessionId"))

  private def kiroUpdates(run: Vector[Json], kind: String): Vector[Json] =
    run.filter(_.is("type", "sessionUpdate")).flatMap(_.at("data", "update")).filter(_.is("sessionUpdate", kind))

  // A failed command completes too.
  private def kiroExitedZero(update: Json): Boolean = update.at("rawOutput", "exitCode").contains(Zero)

  private def kiroSubtask(update: Json): Option[String] = update.text("_meta", "kiro", "agentSubtaskId")

  /** The agent subtask of each shell call that exited 0, None for the session's own calls. Only a call's first event
    * names its kind, and only its completed update has the exit code. */
  private def kiroShellCalls(run: Vector[Json]): Vector[Option[String]] =
    val shells = kiroUpdates(run, "tool_call").filter(_.is("kind", "execute"))
      .flatMap(call => call.text("toolCallId").map(_ -> kiroSubtask(call))).toMap
    kiroUpdates(run, "tool_call_update").filter(update => update.is("status", "completed") && kiroExitedZero(update))
      .flatMap(_.text("toolCallId")).flatMap(shells.get)

  def kiroRanShell(run: Vector[Json]): Boolean = kiroShellCalls(run).nonEmpty

  /** What the run lacks of a shell call, a subagent that completed, and that subagent's own shell call. A
    * subagent's calls carry the agentSubtaskId of the call that started it. */
  def kiroLacks(run: Vector[Json]): Vector[String] =
    val shells = kiroShellCalls(run)
    val agents = kiroUpdates(run, "tool_call_update").filter(update =>
      update.is("status", "completed") && update.text("_meta", "kiro", "kind").contains("agent-subtask"),
    ).flatMap(kiroSubtask).toSet
    lacking(shells.contains(None), agents.nonEmpty, shells.exists(_.exists(agents)))

  /** Whether `copilot -p --output-format json` ended in success: its result event's exit code. A subagent's failed
    * model call leaves a session.error in a run that still succeeds. */
  def copilotSucceeded(run: Vector[Json]): Boolean =
    run.exists(event => event.is("type", "result") && event.at("exitCode").contains(Zero))

  private def copilotShellCalls(run: Vector[Json]): Vector[Json] =
    run.filter(_.is("type", "tool.execution_complete")).flatMap(_.at("data"))
      .filter(data => data.at("success").contains(True) && data.at("shellExecution", "exitCode").contains(Zero))

  /** What the run lacks of a shell call, a subagent that completed, and that subagent's own shell call. A failed call
    * is a tool.execution_complete too, so its success and exit code decide. */
  def copilotLacks(run: Vector[Json]): Vector[String] =
    val shells = copilotShellCalls(run)
    val agents = run.filter(_.is("type", "subagent.completed")).flatMap(_.text("data", "toolCallId")).toSet
    lacking(
      shells.exists(_.at("parentToolCallId").isEmpty), agents.nonEmpty,
      shells.exists(_.text("parentToolCallId").exists(agents)),
    )

  def copilotRanShell(run: Vector[Json]): Boolean = copilotShellCalls(run).nonEmpty

  def copilotSession(run: Vector[Json]): Option[String] =
    run.find(_.is("type", "result")).flatMap(_.text("sessionId"))

  /** Whether a call to the built-in GitHub MCP server succeeded. The server's name is on the call's start event
    * alone. */
  def copilotCalledGithubMcp(run: Vector[Json]): Boolean =
    val calls = run.filter(_.is("type", "tool.execution_start")).flatMap(_.at("data"))
      .filter(_.is("mcpServerName", "github-mcp-server")).flatMap(_.text("toolCallId")).toSet
    run.filter(_.is("type", "tool.execution_complete")).flatMap(_.at("data"))
      .exists(data => data.at("success").contains(True) && data.text("toolCallId").exists(calls))

  /** Whether `opencode run --format json` ended its turn: a step_finish whose reason is stop, and no error event. A
    * provider's refusal arrives as an error event. */
  def opencodeSucceeded(run: Vector[Json]): Boolean =
    !run.exists(_.is("type", "error")) &&
      run.exists(event => event.is("type", "step_finish") && event.text("part", "reason").contains("stop"))

  def opencodeSession(run: Vector[Json]): Option[String] = run.flatMap(_.text("sessionID")).headOption

  private def opencodeCompleted(parts: Vector[Json], tool: String): Vector[Json] =
    parts.filter(part =>
      part.is("type", "tool") && part.is("tool", tool) && part.text("state", "status").contains("completed"),
    )

  // A failed command completes too.
  private def opencodePartsRanShell(parts: Vector[Json]): Boolean =
    opencodeCompleted(parts, "bash").exists(_.at("state", "metadata", "exit").contains(Zero))

  private def opencodeParts(run: Vector[Json]): Vector[Json] =
    run.filter(_.is("type", "tool_use")).flatMap(_.at("part"))

  def opencodeRanShell(run: Vector[Json]): Boolean = opencodePartsRanShell(opencodeParts(run))

  /** The sessions of the run's completed subagents. The stream carries a subagent's task call alone; its own calls are
    * in its session, which `opencode export <session>` prints. */
  def opencodeSubagentSessions(run: Vector[Json]): Vector[String] =
    opencodeCompleted(opencodeParts(run), "task").flatMap(_.text("state", "metadata", "sessionId"))

  /** What the run lacks of a shell call, a subagent that completed, and that subagent's own shell call, read from the
    * subagents' exported sessions. */
  def opencodeLacks(run: Vector[Json], subagentExports: Vector[Json]): Vector[String] =
    lacking(
      opencodeRanShell(run), opencodeSubagentSessions(run).nonEmpty,
      subagentExports.exists(session => opencodePartsRanShell(session.items("messages").flatMap(_.items("parts")))),
    )
