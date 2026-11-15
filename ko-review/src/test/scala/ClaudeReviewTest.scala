package koreview

import io.circe.Json
import io.circe.syntax.*
import java.nio.file.{Files, Path}
import HelperFixture.*

/** The review-cycle tests against the fake `claude`, plus the tests of what is Claude's own. */
class ClaudeReviewTest extends ReviewCycleTests:
  def reviewer = "claude"

  test("the reviewer session is print mode, resumable, and cannot write"):
    start()
    val args = argv(calls().head)
    assertEquals(args.take(1), Vector("-p"))
    assertEquals(args(args.indexOf("--output-format") + 1), "stream-json")
    assert(args.contains("--verbose")) // stream-json in print mode requires it
    for option <- Seq("--bare", "--no-session-persistence", "--dangerously-skip-permissions", "--permission-mode") do
      assert(!args.contains(option), option)
    assertEquals(args(args.indexOf("--permission-prompts") + 1), "none")
    assertEquals(args(args.indexOf("--setting-sources") + 1), "")
    assert(args.contains("--disable-slash-commands"))
    assert(args.contains("--strict-mcp-config"))
    assertEquals(args(args.indexOf("--tools") + 1).split(",").toVector.sorted,
      Vector("Bash", "Glob", "Grep", "Read", "WebFetch", "WebSearch"))
    val allowed = args.drop(args.indexOf("--allowedTools") + 1)
    assert(allowed.forall(tool => tool.startsWith("Bash(git ") || Set("WebFetch", "WebSearch")(tool)), allowed)

  test("the chosen effort overrides an inherited effort variable"):
    environment = Map("CLAUDE_CODE_EFFORT_LEVEL" -> "max")
    plan(step("result" -> Changes), step("result" -> Approved), step("result" -> Approved))
    val chosen = helper("start", "claude", "--effort", "low", "--message-file", message())
    helper("continue", chosen.str("reviewId"), "--message-file", message())
    assertEquals(calls().map(_("effort_variable").flatMap(_.asString)), Vector(Some("low"), Some("low")))
    start(Approved) // no choice: the variable is the user's, and Claude Code applies it
    assertEquals(calls().last("effort_variable").flatMap(_.asString), Some("max"))
    environment = Map.empty

  /** A managed settings directory of its own, and the environment that points the helper at it. */
  private def managedSettings(main: Option[String] = None, dropIns: Map[String, Json] = Map.empty)
      : Map[String, String] =
    val directory = root.resolve("managed")
    deleteTree(directory)
    Files.createDirectories(directory.resolve("managed-settings.d"))
    main.foreach(text => Files.writeString(directory.resolve("managed-settings.json"), text))
    dropIns.foreach((name, settings) => Files.writeString(directory.resolve("managed-settings.d").resolve(name),
      settings.noSpaces))
    Map("KO_REVIEW_CLAUDE_MANAGED_SETTINGS" -> directory.toString,
      "CLAUDE_CONFIG_DIR" -> root.resolve("config").toString)

  test("an effort that the managed settings set is the only one a review takes"):
    environment = managedSettings(Some("""{"env": {"CLAUDE_CODE_EFFORT_LEVEL": "high"}}"""))
    val refused = helperFails("start", "claude", "--effort", "low", "--message-file", message())
    assertEquals(refused.obj("error").str("code"), "REVIEWER_CHOICE_REFUSED")
    assert(refused.obj("error").str("message").contains("--effort high"))
    assert(!refused.contains("reviewId")) // refused before a review exists
    assertEquals(calls(), Vector.empty)
    plan(step("result" -> Approved), step("result" -> Approved))
    for options <- Seq(Seq("--effort", "high"), Nil) do
      assertEquals(helper((Seq("start", "claude") ++ options ++ Seq("--message-file", message()))*).str("status"),
        "APPROVED")
    // a later drop-in that empties the variable leaves the effort to the review
    environment = managedSettings(Some("""{"env": {"CLAUDE_CODE_EFFORT_LEVEL": "high"}}"""),
      Map("10.json" -> json("""{"env": {"CLAUDE_CODE_EFFORT_LEVEL": ""}}""")))
    plan(step("result" -> Approved))
    val chosen = helper("start", "claude", "--effort", "low", "--message-file", message())
    assertEquals((chosen.str("status"), chosen.str("effort")), ("APPROVED", "low"))
    environment = Map.empty

  test("defaults are what the reviewer's session reads"):
    val allEfforts = Json.arr(Seq("low", "medium", "high", "xhigh", "max").map(_.asJson)*)
    environment = managedSettings()
    var found = helper("defaults", "claude")
    assertEquals((found.isNull("model"), found.isNull("effort"), found.bool("partial")), (true, true, true))
    assertEquals(found.arr("catalog").map(_.asObject.get).map(model => (model.str("model"), model("efforts").get)),
      Vector("fable" -> allEfforts, "opus" -> allEfforts, "sonnet" -> allEfforts, "haiku" -> Json.arr()))
    assertEquals(found("recommended").get,
      json("""{"model": null, "effort": null, "efforts": null, "upgrade": null}"""))
    // the reviewer loads no user, project or local settings file, so none of them selects anything
    Files.createDirectories(root.resolve("config"))
    Files.writeString(root.resolve("config/settings.json"), """{"model": "opus", "effortLevel": "low"}""")
    write(".claude/settings.json", """{"model": "sonnet"}""")
    write(".claude/settings.local.json", """{"model": "haiku", "effortLevel": "medium"}""")
    found = helper("defaults", "claude")
    assertEquals((found.isNull("model"), found.isNull("effort")), (true, true))
    // managed files: the drop-ins in alphabetical order over the main file, hidden ones left out
    val managed = managedSettings(Some("""{"model": "sonnet", "effortLevel": "low"}"""), Map(
      "10.json" -> json("""{"model": "opus"}"""), "20.json" -> json("""{"model": "haiku"}"""),
      ".hidden.json" -> json("""{"model": "fable"}"""), "z.txt" -> json("""{"model": "fable"}""")))
    val directory = Path.of(managed("KO_REVIEW_CLAUDE_MANAGED_SETTINGS"))
    environment = managed
    found = helper("defaults", "claude")
    assertEquals((found.str("model"), found.str("effort")), ("haiku", "low"))
    assertEquals(found("source").get, Json.obj(
      "model" -> directory.resolve("managed-settings.d/20.json").toString.asJson,
      "effort" -> directory.resolve("managed-settings.json").toString.asJson))
    assertEquals(found.obj("recommended")("efforts").get, Json.arr()) // Haiku takes no effort
    // the variables override the managed keys, and a managed env block the inherited variables
    environment = managed ++ Map("ANTHROPIC_MODEL" -> "fable", "CLAUDE_CODE_EFFORT_LEVEL" -> "max",
      "ANTHROPIC_DEFAULT_MODEL" -> "opus")
    found = helper("defaults", "claude")
    assertEquals((found.str("model"), found.str("effort")), ("fable", "max"))
    assertEquals(found("source").get, json("""{"model": "ANTHROPIC_MODEL", "effort": "CLAUDE_CODE_EFFORT_LEVEL"}"""))
    assertEquals(found.obj("recommended")("efforts").get, allEfforts)
    environment = managedSettings(Some(
      """{"env": {"ANTHROPIC_MODEL": "claude-opus-5-5", "CLAUDE_CODE_EFFORT_LEVEL": "xhigh"}}""")) ++
      Map("ANTHROPIC_MODEL" -> "fable", "CLAUDE_CODE_EFFORT_LEVEL" -> "max")
    found = helper("defaults", "claude")
    assertEquals((found.str("model"), found.str("effort")), ("claude-opus-5-5", "xhigh"))
    assert(found.obj("recommended").isNull("efforts")) // not a model of the catalog: unknown
    // an empty managed entry unsets the inherited variable instead of yielding to it
    environment = managedSettings(Some(
      """{"model": "sonnet", "env": {"ANTHROPIC_MODEL": "", "CLAUDE_CODE_EFFORT_LEVEL": ""}}""")) ++
      Map("ANTHROPIC_MODEL" -> "fable", "CLAUDE_CODE_EFFORT_LEVEL" -> "max")
    found = helper("defaults", "claude")
    assertEquals((found.str("model"), found.isNull("effort")), ("sonnet", true))
    assert(found.obj("source").isNull("effort"))
    environment = managedSettings(Some("{}")) ++ Map("ANTHROPIC_DEFAULT_MODEL" -> "opus") // the last source
    assertEquals(helper("defaults", "claude").obj("source").str("model"), "ANTHROPIC_DEFAULT_MODEL")
    // per-model efforts sit under names the helper does not resolve: unknown rather than guessed
    environment = managedSettings(Some(
      """{"effortLevel": "low", "modelSettings": {"claude-opus-5-5": {"effortLevel": "high"}}}"""))
    assert(helper("defaults", "claude").isNull("effort"))
    environment = managedSettings(Some("{not json"))
    assertEquals(error("defaults", "claude").str("code"), "REVIEWER_CONFIG_UNREADABLE")
    environment = Map.empty
