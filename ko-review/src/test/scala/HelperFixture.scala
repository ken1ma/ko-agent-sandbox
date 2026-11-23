package koreview

import io.circe.{Json, JsonObject}
import java.io.{ByteArrayOutputStream, PrintStream}
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path}
import java.util.Comparator
import scala.concurrent.duration.Duration
import scala.jdk.CollectionConverters.*

/** The fixtures of the helper's suites: a repository with something to review, a fake `codex` and `claude` on the
  * PATH, and the helper run in this JVM, as the command line runs it. */
abstract class HelperFixture extends UnixHostSuite:
  import HelperFixture.*

  def unixHostClue = "the helper runs reviewers in POSIX process groups, and the fake reviewers are /bin/sh scripts"

  override val munitTimeout: Duration = Duration(5, "min")

  var root: Path = null
  var bin: Path = null
  var script: Path = null
  var log: Path = null
  var state: Path = null
  var repo: Path = null
  var ruleset = ""
  var environment = Map.empty[String, String]

  /** The reviewer the suite's tests start, and the egress host that admits it. */
  def reviewer: String
  def host: String = if reviewer == "codex" then "api.openai.com" else "api.anthropic.com"
  def otherHost: String = if reviewer == "codex" then "api.anthropic.com" else "api.openai.com"
  def display: String = if reviewer == "codex" then "Codex" else "Claude"

  override def beforeEach(context: BeforeEach): Unit = if unixHost then
    root = Files.createTempDirectory("ko-review-").toRealPath()
    bin = Files.createDirectory(root.resolve("bin"))
    installFakeReviewer(bin)
    script = Files.writeString(root.resolve("script.json"), "[]")
    log = Files.writeString(root.resolve("log.jsonl"), "")
    state = root.resolve("state")
    ruleset = s"egress profile: deny-unless-allowed\nallow https://$host/ tunnel\n"
    environment = Map.empty
    repo = Files.createDirectory(root.resolve("repo"))
    git("init", "-q", "-b", "main")
    write("app.py", "print('hi')\n")
    write(".gitignore", "ignored/\n")
    git("add", "-A")
    git("commit", "-q", "-m", "init")
    write("work.py", "print('work in progress')\n") // something to review: a clean tree is refused

  override def afterEach(context: AfterEach): Unit = if unixHost then deleteTree(root)

  def git(args: String*): String = gitIn(repo, args*)

  def gitIn(directory: Path, args: String*): String =
    val (status, out, err) = run(directory, Map.empty, Seq("git", "-c", "user.name=t", "-c", "user.email=t@example.com",
      "-c", "core.symlinks=true", "-c", "protocol.file.allow=always") ++ args)
    assertEquals(status, 0, s"git ${args.mkString(" ")}: $err")
    out

  def write(relative: String, content: String): Path =
    val path = repo.resolve(relative)
    Files.createDirectories(path.getParent)
    Files.writeString(path, content)

  private var messages = 0
  def message(text: String = "## Task\n\nreview me\n"): String =
    messages += 1
    Files.writeString(root.resolve(s"message-$messages.md"), text).toString

  def plan(steps: Json*): Unit = Files.writeString(script, Json.fromValues(steps).noSpaces)

  def env: Map[String, String] =
    // The session that runs the suites is a coordinator itself; a test that wants one sets its variables.
    sys.env.filterNot((name, _) => name.startsWith("KO_") || CoordinatorVariables(name)) ++ Map(
      "PATH" -> s"$bin:${sys.env("PATH")}",
      "FAKE_REVIEWER_SCRIPT" -> script.toString,
      "FAKE_REVIEWER_LOG" -> log.toString,
      "KO_REVIEW_STATE" -> state.toString,
      "KO_AGENT_SANDBOX_EGRESS_RULESET" -> ruleset,
    ) ++ environment

  /** Runs the helper in this JVM and returns its exit status and output. */
  def helperOutput(args: Seq[String], cwd: Path = repo): (Int, String) =
    val (status, out, _) = helperStreams(args, cwd)
    (status, out)

  /** Runs the helper in this JVM and returns its exit status, standard output and standard error. */
  def helperStreams(args: Seq[String], cwd: Path = repo): (Int, String, String) =
    val out = ByteArrayOutputStream()
    val err = ByteArrayOutputStream()
    val ctx = CommandContext(cwd, env, PrintStream(out, true, UTF_8), PrintStream(err, true, UTF_8), PluginRoot,
      Some("test"), JavaCommand)
    val status = Main.run(ctx, args)
    (status, out.toString(UTF_8), err.toString(UTF_8))

  def helper(args: String*): JsonObject = helperIn(repo, 0, args*)
  def helperFails(args: String*): JsonObject = helperIn(repo, 1, args*)

  def helperIn(cwd: Path, expect: Int, args: String*): JsonObject =
    val (status, output) = helperOutput(args, cwd)
    assertEquals(status, expect, output)
    io.circe.parser.parse(output).toOption.flatMap(_.asObject).getOrElse(fail(s"not a JSON object: $output"))

  def error(args: String*): JsonObject = helperFails(args*).obj("error")

  /** Starts the helper as a process of its own, for a test that signals it or runs it beside another command. */
  def spawn(args: String*): Process =
    val builder = ProcessBuilder((JavaCommand ++ Seq(s"-Dko-review.plugin-root=$PluginRoot", "koreview.Main") ++ args)*)
      .directory(repo.toFile)
    builder.environment().clear()
    env.foreach((name, value) => builder.environment().put(name, value))
    builder.start()

  def calls(): Vector[JsonObject] =
    Files.readAllLines(log).asScala.toVector.filter(_.nonEmpty)
      .map(line => io.circe.parser.parse(line).toOption.get.asObject.get)

  def start(result: Json = Changes, step: (String, Json)*): JsonObject =
    plan(Json.obj(("result" -> result) +: step*))
    helper("start", reviewer, "--message-file", message())

  def reviews(): Vector[JsonObject] =
    helper("list").arr("reviews").map(row => helper("show", row.asObject.get.str("reviewId")))

  def turnDir(reviewId: String, number: Int): Path =
    Path.of(helper("show", reviewId).str("reviewPath")).resolve("turns").resolve(f"$number%03d")

  def argv(call: JsonObject): Vector[String] = call.arr("argv").flatMap(_.asString)

  def assertOpensAThread(args: Vector[String]): Unit =
    if reviewer == "codex" then
      assertEquals(args.take(2), Vector("exec", "--json"))
      assert(!args.contains("resume"))
    else
      assertEquals(args.take(1), Vector("-p"))
      assert(!args.contains("--resume"))

  def assertResumes(args: Vector[String], threadId: String): Unit =
    if reviewer == "codex" then assertEquals(args.take(3), Vector("exec", "resume", threadId))
    else assertEquals(args.take(3), Vector("-p", "--resume", threadId))

  def threadStartedLine(threadId: String): String =
    if reviewer == "codex" then s"""{"type": "thread.started", "thread_id": "$threadId"}\n"""
    else s"""{"type": "system", "subtype": "init", "session_id": "$threadId"}\n"""

  /** Installs `bin/codex` and `bin/claude`, which answer the version, sign-in and catalog commands themselves and run
    * a turn as FakeReviewer. */
  private def installFakeReviewer(bin: Path): Unit =
    val catalog = """{"models": [
      |  {"slug": "gpt-second", "visibility": "list", "priority": 3, "description": "Second model.",
      |   "default_reasoning_level": "high", "supported_reasoning_levels": [{"effort": "high"}],
      |   "upgrade": {"model": "gpt-test", "migration_markdown": "Second retires.", "retirement_at": "2026-10-14"}},
      |  {"slug": "gpt-hidden", "visibility": "hide", "priority": 1, "default_reasoning_level": "low",
      |   "supported_reasoning_levels": [{"effort": "low"}]},
      |  {"slug": "gpt-internal", "visibility": "none", "priority": 1, "default_reasoning_level": "low",
      |   "supported_reasoning_levels": [{"effort": "low"}]},
      |  {"slug": "gpt-test", "visibility": "list", "priority": 2, "description": "Test model.",
      |   "default_reasoning_level": "medium",
      |   "supported_reasoning_levels": [{"effort": "low"}, {"effort": "high"}]}
      |]}""".stripMargin
    val java = JavaCommand.map(argument => s"'$argument'").mkString(" ")
    val text =
      s"""#!/bin/sh
         |name=$$(basename "$$0")
         |case "$$name $$*" in
         |  "$$name --version") echo "fake-$$name 0"; exit 0 ;;
         |  "codex login status")
         |    if [ -n "$$FAKE_REVIEWER_SIGNED_OUT" ]; then echo "Not logged in"; exit 1; fi
         |    echo "Logged in using ChatGPT"; exit 0 ;;
         |  "claude auth status --json")
         |    if [ -n "$$FAKE_REVIEWER_SIGNED_OUT" ]; then logged=false; else logged=true; fi
         |    echo "{\\"loggedIn\\": $$logged, \\"authMethod\\": \\"claude.ai\\"}"; exit 0 ;;
         |  "codex debug models")
         |    if [ -n "$$FAKE_CODEX_NO_CATALOG" ]; then exit 1; fi
         |    cat <<'JSON'
         |$catalog
         |JSON
         |    exit 0 ;;
         |esac
         |exec $java koreview.FakeReviewer "$$name" "$$@"
         |""".stripMargin
    for name <- Seq("codex", "claude") do
      val fake = Files.writeString(bin.resolve(name), text)
      fake.toFile.setExecutable(true)

object HelperFixture:
  val CoordinatorVariables: Set[String] = Set("CLAUDE_CODE_SESSION_ID", "CLAUDE_CODE_EXECPATH", "CLAUDE_EFFORT",
    "CODEX_THREAD_ID", "CODEX_VERSION")

  val PluginRoot: Path = Path.of("plugin").toAbsolutePath

  val JavaCommand: Seq[String] = Seq(
    Path.of(System.getProperty("java.home"), "bin", "java").toString,
    "--enable-native-access=ALL-UNNAMED",
    "--sun-misc-unsafe-memory-access=allow",
    "-XX:TieredStopAtLevel=1",
    "-cp",
    System.getProperty("ko-review.test-classpath"),
  )

  def json(text: String): Json = io.circe.parser.parse(text).fold(throw _, identity)

  val Changes: Json = json("""{"disposition": "CHANGES_REQUESTED", "summary": "one issue", "findings": [
    {"id": "F1", "severity": "high", "location": "app.py:1", "description": "d", "evidence": "e"}],
    "suggestions": [], "userDecision": null}""")
  val Approved: Json =
    json("""{"disposition": "APPROVED", "summary": "fine", "findings": [], "suggestions": [], "userDecision": null}""")
  val Suggestion: Json =
    json("""{"id": "S1", "kind": "design", "location": "app.py:3", "description": "s", "reason": "r"}""")
  val UserDecides: Json = json("""{"disposition": "USER_DECISION_REQUIRED", "summary": "needs a call", "findings": [],
    "suggestions": [], "userDecision": {"issue": "i", "reviewerPosition": "p", "whyTechnicalEvidenceCannotDecide": "w",
    "decisionRequested": "d"}}""")

  def step(fields: (String, Json)*): Json = Json.obj(fields*)

  extension (json: Json)
    /** The object with `fields` set over its own. */
    def set(fields: (String, Json)*): Json = json.deepMerge(Json.obj(fields*))
    def without(key: String): Json = json.mapObject(_.remove(key))

  extension (obj: JsonObject)
    def str(key: String): String = obj(key).flatMap(_.asString).getOrElse(throw AssertionError(s"no string $key: $obj"))
    def int(key: String): Int = obj(key).flatMap(_.asNumber).flatMap(_.toInt).getOrElse(throw AssertionError(s"$key"))
    def bool(key: String): Boolean = obj(key).flatMap(_.asBoolean).getOrElse(throw AssertionError(s"no boolean $key"))
    def obj(key: String): JsonObject = obj(key).flatMap(_.asObject).getOrElse(throw AssertionError(s"no object $key"))
    def arr(key: String): Vector[Json] = obj(key).flatMap(_.asArray).getOrElse(throw AssertionError(s"no array $key"))
    def strings(key: String): Vector[String] = arr(key).flatMap(_.asString)
    def isNull(key: String): Boolean = obj(key).forall(_.isNull)

  def run(directory: Path, environment: Map[String, String], command: Seq[String]): (Int, String, String) =
    val out = Files.createTempFile("ko-review-test-", ".out")
    val err = Files.createTempFile("ko-review-test-", ".err")
    try
      val builder = ProcessBuilder(command*).directory(directory.toFile).redirectOutput(out.toFile)
        .redirectError(err.toFile)
      environment.foreach((name, value) => builder.environment().put(name, value))
      val process = builder.start()
      process.getOutputStream.close()
      val status = process.waitFor()
      (status, Files.readString(out), Files.readString(err))
    finally
      Files.deleteIfExists(out)
      Files.deleteIfExists(err)

  /** Deletes a directory tree, giving every directory in it back its permissions first. */
  def deleteTree(directory: Path): Unit =
    if Files.exists(directory) then
      scala.util.Using.resource(Files.walk(directory)): paths =>
        paths.iterator().asScala.filter(path => Files.isDirectory(path) && !Files.isSymbolicLink(path))
          .foreach(_.toFile.setWritable(true))
      scala.util.Using.resource(Files.walk(directory)): paths =>
        paths.sorted(Comparator.reverseOrder()).forEach(path => Files.deleteIfExists(path): Unit)
