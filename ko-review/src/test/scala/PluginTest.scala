package koreview

import java.nio.file.{Files, Path}
import scala.jdk.CollectionConverters.*
import HelperFixture.{json, run}

/** The plugin's files: the manifest, the skill, the prompts and the schema agree with the helper, and the assembled
  * plugin is what Claude Code and Codex install. */
class PluginTest extends munit.FunSuite:

  private val plugin = HelperFixture.PluginRoot
  private val assembled = Path.of(System.getProperty("ko-review.assembled-plugin"))

  private def onPath(program: String): Option[Path] =
    sys.env.getOrElse("PATH", "").split(java.io.File.pathSeparator).map(Path.of(_, program)).find(Files.isExecutable)

  test("the manifest and the skill agree on names, and the skill names the helper's commands"):
    assertEquals(json(Files.readString(plugin.resolve("claude-plugin/plugin.json"))).hcursor.get[String]("name"),
      Right("ko-review"))
    assertEquals(Files.list(plugin.resolve("skills")).iterator().asScala.map(_.getFileName.toString).toVector,
      Vector("ko-review"))
    val skill = Files.readString(plugin.resolve("skills/ko-review/SKILL.md"))
    assert(skill.contains("name: ko-review\n")) // the plugin's own name, so that the bare /ko-review runs it
    assert(skill.contains("`## Suggestions`")) // the author answers every suggestion, the prompt says
    assert(skill.contains("ko-review start REVIEWER --message-file"))
    assert(skill.contains("ko-review defaults REVIEWER"))
    assert(skill.contains("ko-review transcript REVIEW_ID --turn N"))
    for command <- Seq("continue", "escalate", "check-approval") do
      assert(skill.contains(s"ko-review $command REVIEW_ID"), command)
    for name <- Reviewer.all.map(_.name) do assert(skill.contains(s"`$name`"), name) // the reviewer question offers it
    assert(Files.isExecutable(plugin.resolve("bin/ko-review")))

  test("the schema, the prompts and the helper agree on the result's shape"):
    val schema = json(Files.readString(plugin.resolve("schemas/review-result.schema.json"))).hcursor
    def strings(cursor: io.circe.ACursor) = cursor.as[Vector[String]].toOption.get.toSet
    import ResultValidation.*
    assertEquals(strings(schema.downField("required")), ResultKeys)
    assertEquals(strings(schema.downField("properties").downField("disposition").downField("enum")), Dispositions)
    val findings = schema.downField("properties").downField("findings").downField("items")
    assertEquals(strings(findings.downField("required")), FindingKeys)
    assertEquals(strings(findings.downField("properties").downField("severity").downField("enum")), Severities)
    val suggestions = schema.downField("properties").downField("suggestions").downField("items")
    assertEquals(strings(suggestions.downField("required")), SuggestionKeys)
    assertEquals(strings(suggestions.downField("properties").downField("kind").downField("enum")), SuggestionKinds)
    assertEquals(strings(schema.downField("properties").downField("userDecision").downField("anyOf").downN(1)
      .downField("required")), UserDecisionKeys)
    val prompt = Files.readString(plugin.resolve("prompts/reviewer.md"))
    for word <- Seq("`findings`", "`suggestions`", "`userDecision`") ++ Dispositions do assert(prompt.contains(word))
    assert(Files.readString(plugin.resolve("prompts/continue.md")).contains("suggestion"))
    // The reviewer and the author escalate on one condition, in the same words (ko-review/doc/design.md, "The cycle").
    val userDecides = "what the user owns, the task's scope, ownership of the work, a recorded decision, a product " +
      "requirement or a risk acceptance, or a disagreement evidence cannot settle"
    def words(text: String) = text.split("\\s+").mkString(" ")
    assert(words(prompt).contains(userDecides))
    assert(words(Files.readString(plugin.resolve("skills/ko-review/SKILL.md"))).contains(userDecides))

  test("the assembly renames the manifest's directory, adds the version and the jar, and lists the dependencies"):
    val manifest = json(Files.readString(assembled.resolve(".claude-plugin/plugin.json"))).hcursor
    assertEquals(manifest.get[String]("name"), Right("ko-review"))
    assert(manifest.get[String]("version").isRight)
    assert(!Files.exists(assembled.resolve("claude-plugin")))
    assert(Files.isRegularFile(assembled.resolve("lib/ko-review.jar")))
    val dependencies = Files.readAllLines(assembled.resolve("lib/dependencies.txt")).asScala.toVector
    assert(dependencies.exists(_.startsWith("io.circe:circe-core_3:")), dependencies.toString)
    assert(dependencies.forall(_.split(':').length == 3), dependencies.toString)
    assert(!dependencies.exists(_.contains("munit")), "test dependencies stay out")
    assert(Files.isExecutable(assembled.resolve("bin/ko-review")))
    assertEquals(Files.readString(assembled.resolve("skills/ko-review/SKILL.md")),
      Files.readString(plugin.resolve("skills/ko-review/SKILL.md")))

  test("the assembled plugin validates"):
    val claude = onPath("claude")
    assume(claude.isDefined, "needs claude on PATH")
    val (status, out, err) = run(Path.of("").toAbsolutePath, Map.empty,
      Seq(claude.get.toString, "plugin", "validate", assembled.toString))
    assertEquals(status, 0, out + err)
    assert(out.contains("Validation passed"), out)

  // The test copies the skill, as the image installs it; the image's Containerfile gives the reason.
  test("Codex loads a copy of the skill as ko-review"):
    val codex = onPath("codex")
    assume(codex.isDefined, "needs codex on PATH")
    val home = Files.createTempDirectory("ko-review-codex-home")
    try
      val skill = home.resolve(".agents/skills/ko-review/SKILL.md")
      Files.createDirectories(skill.getParent)
      Files.copy(plugin.resolve("skills/ko-review/SKILL.md"), skill)
      val codexHome = Files.createDirectories(home.resolve(".codex"))
      val (status, out, err) = run(home, Map("HOME" -> home.toString, "CODEX_HOME" -> codexHome.toString),
        Seq(codex.get.toString, "debug", "prompt-input"))
      assertEquals(status, 0, out + err)
      assert(out.contains("- ko-review: "), out)
    finally HelperFixture.deleteTree(home)
