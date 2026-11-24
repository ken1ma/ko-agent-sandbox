package koreview

import io.circe.{Json, JsonObject}
import io.circe.syntax.*
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path, StandardOpenOption}

/** A fake `codex` and `claude`, installed under both names by `bin/<name>` scripts that pass the name first
  * (HelperSuite.installFakeReviewer). The scripts answer `--version` and the sign-in and catalog commands themselves;
  * a reviewer turn runs here.
  *
  * Each turn takes one step from the JSON array in the file that FAKE_REVIEWER_SCRIPT names, and appends its argv,
  * prompt, working directory, process id and process group to FAKE_REVIEWER_LOG. A step's keys:
  * - `result`: the final message, an object or a string; `thread_id`: the thread to name;
  * - `touch`: a file to append to, `git`: git commands to run, as the user on the host would during the turn;
  * - `background`: a process left behind that writes `marker` after `sleep` seconds, in the reviewer's group or,
  *   `escaped`, in a session of its own;
  * - `raw_stdout`: printed instead of the events; `emit_thread_started`, `sleep`, `events`, `claude_result`, `stderr`
  *   and `exit` shape the run.
  */
object FakeReviewer:

  def main(arguments: Array[String]): Unit =
    val name = arguments(0)
    val args = arguments.toSeq.drop(1)
    val env = sys.env
    val prompt = String(System.in.readAllBytes(), UTF_8)
    val scriptPath = Path.of(env("FAKE_REVIEWER_SCRIPT"))
    val script = io.circe.parser.parse(Files.readString(scriptPath)).toOption.flatMap(_.asArray).getOrElse(Vector.empty)
    val step = script.headOption.flatMap(_.asObject).getOrElse(JsonObject.empty)
    Files.writeString(scriptPath, Json.fromValues(script.drop(1)).noSpaces)
    val pid = ProcessHandle.current().pid()
    val log = Path.of(env("FAKE_REVIEWER_LOG"))
    Files.writeString(log, Json.obj(
      "argv" -> args.asJson,
      "prompt" -> prompt.asJson,
      "cwd" -> Path.of("").toAbsolutePath.toString.asJson,
      "pid" -> pid.asJson,
      "pgid" -> Posix.getpgid(pid).asJson,
      "effort_variable" -> env.get("CLAUDE_CODE_EFFORT_LEVEL").asJson,
    ).noSpaces + "\n", StandardOpenOption.APPEND)
    def text(key: String) = step(key).flatMap(_.asString)
    def flag(key: String, default: Boolean) = step(key).flatMap(_.asBoolean).getOrElse(default)
    def emit(event: Json): Unit =
      System.out.println(event.noSpaces) // a PrintStream ignores a reader that is gone, as a reviewer mid-command does
      System.out.flush()
    val resumeOption = if name == "codex" then "resume" else "--resume"
    val resume = args.indexOf(resumeOption) match
      case -1 => None
      case index => Some(args(index + 1))
    val count = Files.readAllLines(log).size
    val threadId = text("thread_id").orElse(resume).getOrElse(s"thread-$count")
    val started =
      if name == "codex" then Json.obj("type" -> "thread.started".asJson, "thread_id" -> threadId.asJson)
      else Json.obj("type" -> "system".asJson, "subtype" -> "init".asJson, "session_id" -> threadId.asJson,
        "model" -> "fake-model".asJson)
    text("touch").foreach: file =>
      Files.writeString(Path.of(file), "changed during review\n", StandardOpenOption.APPEND)
    for command <- step("git").flatMap(_.asArray).getOrElse(Vector.empty) do
      val git = ProcessBuilder(("git" +: command.asArray.get.flatMap(_.asString))*).redirectOutput(
        ProcessBuilder.Redirect.DISCARD).start()
      if git.waitFor() != 0 then sys.error(s"git ${command.noSpaces} failed")
    step("background").flatMap(_.asObject).foreach: background =>
      val seconds = background("sleep").flatMap(_.asNumber).map(_.toDouble).get
      val marker = background("marker").flatMap(_.asString).get
      val body = s"sleep $seconds; echo ran > '$marker'"
      val escaped = background("escaped").flatMap(_.asBoolean).contains(true)
      val command = if escaped then Seq("setsid", "sh", "-c", s"($body) & wait") else Seq("sh", "-c", body)
      ProcessBuilder(command*)
        .redirectInput(ProcessBuilder.Redirect.from(java.io.File("/dev/null")))
        .redirectError(ProcessBuilder.Redirect.DISCARD)
        .redirectOutput(ProcessBuilder.Redirect.DISCARD)
        .start()
    text("raw_stdout") match
      case Some(raw) =>
        System.out.print(raw)
        System.out.flush()
      case None =>
        if flag("emit_thread_started", true) then emit(started)
        Thread.sleep((step("sleep").flatMap(_.asNumber).map(_.toDouble).getOrElse(0.0) * 1000).toLong)
        if name == "codex" then emit(Json.obj("type" -> "turn.started".asJson))
        step("events").flatMap(_.asArray).getOrElse(Vector.empty).foreach(emit)
        val result = step("result").filterNot(_.isNull)
        val resultText = result.map(json => json.asString.getOrElse(json.noSpaces))
        if name == "codex" then
          resultText.foreach: message =>
            emit(Json.obj("type" -> "item.completed".asJson,
              "item" -> Json.obj("type" -> "agent_message".asJson, "text" -> message.asJson)))
            Files.writeString(Path.of(args(args.indexOf("--output-last-message") + 1)), message)
          emit(Json.obj("type" -> "turn.completed".asJson))
        else
          emit(Json.fromJsonObject(JsonObject(
            "type" -> "result".asJson,
            "subtype" -> "success".asJson,
            "is_error" -> false.asJson,
            "session_id" -> threadId.asJson,
            "structured_output" -> result.filter(_.isObject).getOrElse(Json.Null),
            "result" -> resultText.asJson,
          ).deepMerge(step("claude_result").flatMap(_.asObject).getOrElse(JsonObject.empty))))
    System.err.print(text("stderr").getOrElse(""))
    System.err.flush()
    env.get("FAKE_REVIEWER_DONE").foreach(done => Files.writeString(Path.of(done), "ran to the end\n"))
    System.exit(step("exit").flatMap(_.asNumber).flatMap(_.toInt).getOrElse(0))
