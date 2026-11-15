package koreview

import io.circe.{Json, JsonObject}
import io.circe.syntax.*
import java.nio.file.{Files, Path}
import java.util.concurrent.TimeUnit

/** A reviewer CLI: how to start and resume its thread, and how to read its events. */
sealed trait Reviewer:
  def name: String
  def display: String
  /** The event that names the thread, as error messages call it. */
  def threadEvent: String
  def hosts: Seq[String]
  /** Lowercase words of the reviewer's failure when it no longer has the thread. */
  def lostThread: String
  def signInAdvice: String

  def command(program: Path, model: Option[String], effort: Option[String], resume: Option[String], schema: Path,
      lastMessage: Path): Seq[String]
  def environment(base: Map[String, String], effort: Option[String]): Map[String, String]
  /** Refuses a choice that the reviewer would not honor. */
  def checkChoice(ctx: CommandContext, effort: Option[String]): Unit = ()
  def signedIn(ctx: CommandContext, program: Path): (Boolean, String)
  def threadId(event: JsonObject): Option[String]
  def failed(event: JsonObject): Boolean
  def failureText(event: JsonObject): Option[String]
  /** The final message, or None. */
  def finalResult(events: Seq[JsonObject], lastMessage: Path): Option[String]
  def defaults(ctx: CommandContext, root: Path): JsonObject

  def error(code: String, message: String, detail: (String, Json)*): ReviewError =
    ReviewError.ofReviewer(name, code, message, detail*)

object Reviewer:
  val all: Seq[Reviewer] = Seq(Codex, Claude)
  def named(name: String): Option[Reviewer] = all.find(_.name == name)

  /** Runs `command` to its end, with its output, or None when it does not end within `seconds`. */
  def output(ctx: CommandContext, command: Seq[String], seconds: Long = 60): Option[(Int, String, String)] =
    val builder = ProcessBuilder(command*).directory(ctx.cwd.toFile)
    builder.environment().clear()
    ctx.env.foreach((name, value) => builder.environment().put(name, value))
    val stdout = Files.createTempFile("ko-review-", ".out")
    val stderr = Files.createTempFile("ko-review-", ".err")
    try
      val process = builder.redirectOutput(stdout.toFile).redirectError(stderr.toFile).start()
      process.getOutputStream.close()
      if !process.waitFor(seconds, TimeUnit.SECONDS) then
        process.destroyForcibly()
        None
      else Some((process.exitValue(), Files.readString(stdout), Files.readString(stderr)))
    finally
      Files.deleteIfExists(stdout)
      Files.deleteIfExists(stderr)

  def version(ctx: CommandContext, program: Path): Option[String] =
    output(ctx, Seq(program.toString, "--version")).map(_._2.trim)

object Codex extends Reviewer:
  val name = "codex"
  val display = "Codex"
  val threadEvent = "thread.started"
  // A ChatGPT sign-in talks to chatgpt.com, and an API key to api.openai.com.
  val hosts = Seq("api.openai.com", "chatgpt.com")
  val lostThread = "no rollout found"
  val signInAdvice = "run `codex` in this workspace's sandbox, sign in, and retry"

  def environment(base: Map[String, String], effort: Option[String]): Map[String, String] = base

  def command(program: Path, model: Option[String], effort: Option[String], resume: Option[String], schema: Path,
      lastMessage: Path): Seq[String] =
    Seq(program.toString, "exec") ++ resume.toSeq.flatMap(Seq("resume", _)) ++
      model.toSeq.flatMap(Seq("--model", _)) ++
      effort.toSeq.flatMap(level => Seq("-c", "model_reasoning_effort=" + level.asJson.noSpaces)) ++
      Seq("--json", "--output-schema", schema.toString, "--output-last-message", lastMessage.toString, "-")

  /** Asks Codex, which knows its credential stores, the auth.json file or the OS keyring. */
  def signedIn(ctx: CommandContext, program: Path): (Boolean, String) =
    Reviewer.output(ctx, Seq(program.toString, "login", "status")) match
      case Some((status, out, err)) => (status == 0, (out + err).trim.takeRight(500))
      case None => throw error("REVIEWER_FAILED", "codex's sign-in status did not answer within 60s")

  def threadId(event: JsonObject): Option[String] =
    if event("type").flatMap(_.asString).contains("thread.started") then event("thread_id").flatMap(_.asString)
    else None

  def failed(event: JsonObject): Boolean = event("type").flatMap(_.asString).exists(Set("turn.failed", "error"))

  def failureText(event: JsonObject): Option[String] =
    event("error").orElse(event("message")).map: error =>
      error.asObject.flatMap(_("message")).getOrElse(error).asString.getOrElse(error.noSpaces)

  def finalResult(events: Seq[JsonObject], lastMessage: Path): Option[String] =
    Option.when(Files.exists(lastMessage) && Files.size(lastMessage) > 0)(Files.readString(lastMessage))

  def defaults(ctx: CommandContext, root: Path): JsonObject = CodexDefaults(ctx, root)

/** Claude Code as the reviewer, `claude -p` in stream-json. ko-review/doc/design.md, "Claude Code as it is called",
  * gives the reasons for its options. */
object Claude extends Reviewer:
  val name = "claude"
  val display = "Claude"
  val threadEvent = "system init"
  // The hosts carry model traffic, and the OAuth token refresh that a claude.ai sign-in makes.
  val hosts = Seq("api.anthropic.com", "platform.claude.com")
  val lostThread = "no conversation found with session id"
  val signInAdvice = "run `claude` in this workspace's sandbox, sign in with /login, and retry"
  val tools = "Bash,Read,Grep,Glob,WebFetch,WebSearch"
  val allowedTools = Seq(
    "Bash(git diff:*)", "Bash(git log:*)", "Bash(git show:*)", "Bash(git status:*)", "Bash(git ls-files:*)",
    "Bash(git blame:*)", "Bash(git grep:*)", "WebFetch", "WebSearch",
  )

  def command(program: Path, model: Option[String], effort: Option[String], resume: Option[String], schema: Path,
      lastMessage: Path): Seq[String] =
    Seq(program.toString, "-p") ++ resume.toSeq.flatMap(Seq("--resume", _)) ++
      model.toSeq.flatMap(Seq("--model", _)) ++ effort.toSeq.flatMap(Seq("--effort", _)) ++
      Seq("--verbose", "--output-format", "stream-json", "--json-schema", Files.readString(schema),
        "--setting-sources", "", "--disable-slash-commands", "--strict-mcp-config", "--permission-prompts", "none",
        "--tools", tools, "--allowedTools") ++ allowedTools

  /** `CLAUDE_CODE_EFFORT_LEVEL` overrides `--effort`, so an inherited variable would run every turn at its level while
    * the review records the chosen one. */
  override def environment(base: Map[String, String], effort: Option[String]): Map[String, String] =
    effort.fold(base)(level => base + ("CLAUDE_CODE_EFFORT_LEVEL" -> level))

  /** A managed `env` block replaces the variable that `environment` sets, so the effort such a block sets is the only
    * effort that a review can record truthfully. */
  override def checkChoice(ctx: CommandContext, effort: Option[String]): Unit =
    ClaudeDefaults.managedVariable(ctx, "CLAUDE_CODE_EFFORT_LEVEL") match
      case Some((managed, source)) if managed.nonEmpty && effort.exists(_ != managed) =>
        throw error(
          "REVIEWER_CHOICE_REFUSED",
          s"$source sets CLAUDE_CODE_EFFORT_LEVEL to $managed, which Claude Code applies whatever the review chooses:" +
            s" start the review with --effort $managed or without --effort",
        )
      case _ => ()

  def signedIn(ctx: CommandContext, program: Path): (Boolean, String) =
    Reviewer.output(ctx, Seq(program.toString, "auth", "status", "--json")) match
      case Some((status, out, err)) =>
        val loggedIn = io.circe.parser.parse(out).toOption.flatMap(_.hcursor.get[Boolean]("loggedIn").toOption)
        (loggedIn.getOrElse(status == 0), (out + err).trim.takeRight(500))
      case None => throw error("REVIEWER_FAILED", "claude's sign-in status did not answer within 60s")

  def threadId(event: JsonObject): Option[String] =
    val init = event("type").flatMap(_.asString).contains("system") &&
      event("subtype").flatMap(_.asString).contains("init")
    if init then event("session_id").flatMap(_.asString) else None

  /** An API error can end a print-mode run with exit status 0 and the error in the result object
    * (anthropics/claude-code#79500), so the result object says whether the run failed. */
  def failed(event: JsonObject): Boolean =
    event("type").flatMap(_.asString).contains("result") &&
      (event("is_error").flatMap(_.asBoolean).contains(true) ||
        !event("subtype").flatMap(_.asString).contains("success"))

  def failureText(event: JsonObject): Option[String] =
    event("errors").flatMap(_.asArray).filter(_.nonEmpty)
      .map(_.map(error => error.asString.getOrElse(error.noSpaces)).mkString("; "))
      .orElse(event("result").flatMap(_.asString))
      .orElse(event("subtype").flatMap(_.asString))

  def finalResult(events: Seq[JsonObject], lastMessage: Path): Option[String] =
    events.reverseIterator.find(event => event("type").flatMap(_.asString).contains("result"))
      .flatMap(_("structured_output")).filterNot(_.isNull).map(_.noSpaces)

  def defaults(ctx: CommandContext, root: Path): JsonObject = ClaudeDefaults(ctx)

/** Checks what the reviewer returned against the schema's rules: the schema option asks the model for the shape, and
  * the helper decides. */
object ResultValidation:
  val Dispositions = Set("APPROVED", "CHANGES_REQUESTED", "USER_DECISION_REQUIRED")
  val Severities = Set("critical", "high", "medium", "low")
  val SuggestionKinds = Set("design", "simplification", "alternative", "question")
  val ResultKeys = Set("disposition", "summary", "findings", "suggestions", "userDecision")
  val FindingKeys = Set("id", "severity", "location", "description", "evidence")
  val SuggestionKeys = Set("id", "kind", "location", "description", "reason")
  val UserDecisionKeys = Set("issue", "reviewerPosition", "whyTechnicalEvidenceCannotDecide", "decisionRequested")

  /** The first rule that `result` breaks, or None. */
  def problem(result: Json): Option[String] =
    def keys(json: Json) = json.asObject.map(_.keys.toSet)
    def string(json: JsonObject, key: String) = json(key).exists(_.isString)
    def stringOrNull(json: JsonObject, key: String) = json(key).exists(value => value.isString || value.isNull)
    def item(
        json: Json,
        required: Set[String],
        kindKey: String,
        kinds: Set[String],
        textKeys: Seq[String],
        what: String,
    ): Option[String] =
      json.asObject.filter(_ => keys(json).contains(required)) match
        case None => Some(s"a $what's keys are not exactly ${required.toSeq.sorted.mkString(", ")}")
        case Some(item) =>
          val id = item("id").flatMap(_.asString)
          if id.isEmpty then Some(s"a $what's id is not a string")
          else if !item(kindKey).flatMap(_.asString).exists(kinds) then Some(s"$what ${id.get} has no $kindKey")
          else if !stringOrNull(item, "location") then Some(s"$what ${id.get}: location is neither a string nor null")
          else if !textKeys.forall(string(item, _)) then
            Some(s"$what ${id.get}: ${textKeys.mkString(" and ")} must be strings")
          else None
    result.asObject match
      case None => Some("result is not an object")
      case Some(_) if !keys(result).contains(ResultKeys) =>
        Some(s"result keys are not exactly ${ResultKeys.toSeq.sorted.mkString(", ")}")
      case Some(fields) =>
        val disposition = fields("disposition").flatMap(_.asString)
        val findings = fields("findings").flatMap(_.asArray)
        val suggestions = fields("suggestions").flatMap(_.asArray)
        val decision = fields("userDecision").get
        if !disposition.exists(Dispositions) then
          Some(s"disposition is not one of ${Dispositions.toSeq.sorted.mkString(", ")}")
        else if !string(fields, "summary") then Some("summary is not a string")
        else if findings.isEmpty then Some("findings is not an array")
        else if suggestions.isEmpty then Some("suggestions is not an array")
        else
          findings.get.view
            .flatMap(item(_, FindingKeys, "severity", Severities, Seq("description", "evidence"), "finding"))
            .headOption
            .orElse(suggestions.get.view
              .flatMap(item(_, SuggestionKeys, "kind", SuggestionKinds, Seq("description", "reason"), "suggestion"))
              .headOption)
            .orElse:
              if disposition.contains("USER_DECISION_REQUIRED") then
                val complete = keys(decision).contains(UserDecisionKeys) &&
                  decision.asObject.exists(_.values.forall(_.isString))
                Option.unless(complete)("USER_DECISION_REQUIRED without a complete userDecision")
              else Option.unless(decision.isNull)("userDecision given without USER_DECISION_REQUIRED")
            .orElse(Option.when(disposition.contains("APPROVED") && findings.get.nonEmpty)("APPROVED with findings"))
