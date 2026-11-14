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
    Vector(
      Option.when(denied.nonEmpty)("no denied call"),
      Option.unless(done.exists(call => call.name.contains("Bash") && call.parent.isEmpty))("a Bash call"),
      Option.when(agents.isEmpty)("a subagent"),
      Option.unless(done.exists(call => call.name.contains("Bash") && call.parent.exists(agents)))(
        "the subagent's Bash call",
      ),
    ).flatten

  def codexCompleted(run: Vector[Json]): Boolean = run.exists(_.is("type", "turn.completed"))

  /** Whether a shell command of `codex exec --json` completed with exit status 0. A failed command is an
    * item.completed too. */
  def codexRanCommand(run: Vector[Json]): Boolean =
    run.exists(event =>
      event.is("type", "item.completed") && event.text("item", "type").contains("command_execution") &&
        event.text("item", "status").contains("completed") && event.at("item", "exit_code").contains(Json.Num("0")),
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
