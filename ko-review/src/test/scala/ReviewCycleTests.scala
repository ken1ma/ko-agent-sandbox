package koreview

import io.circe.Json
import io.circe.syntax.*
import java.nio.file.{Files, Path}
import scala.jdk.CollectionConverters.*
import HelperFixture.*

/** The tests that run against each reviewer: CodexReviewTest and ClaudeReviewTest. */
abstract class ReviewCycleTests extends HelperFixture:

  private def lostThreadStderr =
    if reviewer == "codex" then "Error: thread/resume failed: no rollout found for thread id x"
    else "No conversation found with session ID: x"

  /** Failure shapes in the reviewer's own event stream, each with the error it must become. */
  private def reviewerFailureCases: Seq[(Json, String)] =
    if reviewer == "codex" then
      Seq(step("events" -> json("""[{"type": "turn.failed", "error": {"message": "model overloaded"}}]""")) ->
        "REVIEWER_FAILED")
    else
      Seq(
        // an API error in the result with exit status 0 (anthropics/claude-code#79500)
        step("claude_result" -> json("""{"is_error": true, "result": "API Error: 529 overloaded"}""")) ->
          "REVIEWER_FAILED",
        step("claude_result" -> json("""{"is_error": true, "result": "Not logged in · Please run /login"}""")) ->
          "REVIEWER_AUTH_FAILED",
        step("claude_result" -> json("""{"subtype": "error_during_execution", "errors": ["boom"]}""")) ->
          "REVIEWER_FAILED",
        step("result" -> Approved, "claude_result" -> json("""{"subtype": "error_max_turns"}""")) -> "REVIEWER_FAILED",
      )

  test("start opens a thread and records the turn in files written once"):
    val output = start()
    assertEquals(output.str("disposition"), "CHANGES_REQUESTED")
    assertEquals(output.str("status"), "CHANGES_REQUESTED")
    assertEquals(output.int("turn"), 1)
    assertEquals(output.arr("findings").head.asObject.get.str("id"), "F1")
    val id = output.str("reviewId")
    assert(id.matches("""\d{4}-\d{2}-\d{2}-\d{4}-[0-9a-f]{8}"""), id)
    val shown = helper("show", id)
    assertEquals((shown.str("reviewer"), shown.str("threadId")), (reviewer, "thread-1"))
    assertEquals(shown.obj("lastReviewed").str("contentDigest"), output.str("currentContentDigest"))
    assert(shown.isNull("approved"))
    val call = calls().head
    assertOpensAThread(argv(call))
    val schema = PluginRoot.resolve("schemas/review-result.schema.json")
    if reviewer == "codex" then assertEquals(argv(call)(argv(call).indexOf("--output-schema") + 1), schema.toString)
    else assertEquals(argv(call)(argv(call).indexOf("--json-schema") + 1), Files.readString(schema))
    assertEquals(Path.of(call.str("cwd")).toRealPath(), repo.toRealPath())
    assert(call.str("prompt").contains("You are an independent code reviewer"))
    assert(call.str("prompt").contains("review me"))
    val turn = turnDir(id, 1)
    assertEquals(
      Files.list(turn).iterator().asScala.map(_.getFileName.toString).toVector.sorted,
      Vector("manifest.json", "outcome.json", "request.json", "reviewer.stderr", "reviewer.stdout", "start.patch",
        "thread.json"),
    )
    val outcome = json(Files.readString(turn.resolve("outcome.json"))).asObject.get
    assertEquals(outcome("result").get, Changes.mapObject(_.remove("userDecision")))
    assertEquals(outcome.str("formatVersion"), ReviewFiles.FormatVersion)
    val request = json(Files.readString(turn.resolve("request.json"))).asObject.get
    assertEquals(request.strings("scope"), Vector("work.py"))
    assertEquals(request.obj("from").str("store"), "git")
    assertEquals(request.obj("from").str("commit"), git("rev-parse", "HEAD").trim)
    assert(Files.readString(turn.resolve("start.patch")).contains("+print('work in progress')"))
    assertEquals(helper("list").arr("reviews"), Vector(Json.obj(
      "reviewId" -> id.asJson, "reviewer" -> reviewer.asJson, "effectiveStatus" -> "CHANGES_REQUESTED".asJson,
      "turn" -> 1.asJson, "approvalFresh" -> false.asJson, "createdAt" -> output("createdAt").get,
      "updatedAt" -> helper("show", id)("updatedAt").get,
    )))
    val worktree = Files.list(state.resolve("worktrees")).iterator().asScala.toVector.head
    assertEquals(json(Files.readString(worktree.resolve("worktree.json"))).asObject.get.str("worktree"),
      repo.toRealPath().toString)

  test("suggestions never block approval and reach the transcript"):
    val output = start(Approved.set("suggestions" -> Json.arr(Suggestion)))
    assertEquals((output.str("disposition"), output.str("status"), output.arr("findings")), ("APPROVED", "APPROVED",
      Vector.empty))
    assertEquals(output.arr("suggestions"), Vector(Suggestion))
    val id = output.str("reviewId")
    assertEquals(helper("check-approval", id).str("status"), "APPROVED")
    val (_, markdown) = helperOutput(Seq("transcript", id))
    assert(markdown.contains(s"### $display: APPROVED"), markdown)
    val suggestions = "Suggestions, which do not block approval:\n\n- **S1** (design) `app.py:3`: s\n  Reason: r\n"
    assert(markdown.contains(suggestions), markdown)
    // An outcome written without the field, as a helper before suggestions would, reads as no suggestions.
    val outcome = turnDir(id, 1).resolve("outcome.json")
    Files.writeString(outcome, json(Files.readString(outcome)).hcursor.downField("result").downField("suggestions")
      .delete.top.get.noSpaces)
    val (status, older) = helperOutput(Seq("transcript", id))
    assertEquals(status, 0, older)
    assert(older.contains(s"### $display: APPROVED"), older)
    assert(!older.contains("S1"), older)

  test("continue resumes the same thread, and the approval binds the files' content"):
    val id = start().str("reviewId")
    helperFails("check-approval", id)
    write("app.py", "print('fixed')\n")
    plan(step("result" -> Approved))
    val output = helper("continue", id, "--message-file", message("## Accepted findings\n\nF1 fixed\n"))
    assertEquals(output.str("status"), "APPROVED")
    assertEquals(output.int("turn"), 2)
    assert(output.bool("approvalFresh"))
    val call = calls()(1)
    assertResumes(argv(call), "thread-1")
    assert(call.str("prompt").contains("F1 fixed"))
    assert(call.str("prompt").contains("The author responded to your previous review"))
    assertEquals(helper("check-approval", id).str("effectiveStatus"), "APPROVED")
    git("add", "-A")
    assertEquals(helper("check-approval", id).str("effectiveStatus"), "APPROVED") // staged, as approved
    git("commit", "-q", "-m", "the reviewed changes") // the files are the approved ones; only HEAD moved
    assertEquals(helper("check-approval", id).str("effectiveStatus"), "APPROVED")
    write("app.py", "print('staged, unreviewed')\n")
    git("add", "app.py")
    write("app.py", "print('fixed')\n") // only the files' content decides, not what the index holds
    assertEquals(helper("check-approval", id).str("effectiveStatus"), "APPROVED")
    git("reset", "-q", "app.py")
    write("app.py", "print('edited after approval')\n")
    val stale = error("check-approval", id)
    assertEquals((stale.str("code"), stale.str("effectiveStatus")), ("NOT_APPROVED", "STALE_APPROVAL"))
    assert(!helper("show", id).bool("approvalFresh"))
    plan(step("result" -> Approved))
    val again = helper("continue", id, "--message-file", message())
    assertEquals(again.int("turn"), 3)
    assert(again.bool("approvalFresh"))

  test("a resumed thread must be the one the review recorded"):
    val id = start().str("reviewId")
    plan(step("result" -> Approved, "thread_id" -> "thread-other".asJson))
    val failure = error("continue", id, "--message-file", message())
    assertEquals((failure.str("code"), failure.str("reviewer")), ("REVIEWER_RESUME_MISMATCH", reviewer))
    assertEquals((failure.str("expected"), failure.str("actual")), ("thread-1", "thread-other"))
    val shown = helper("show", id)
    assertEquals((shown.str("status"), shown.str("threadId")), ("CHANGES_REQUESTED", "thread-1"))
    assertEquals((shown.obj("lastError").str("code"), shown.obj("lastError").int("turn")),
      ("REVIEWER_RESUME_MISMATCH", 2))
    assert(!Files.exists(turnDir(id, 2).resolve("thread.json")))
    plan(step("result" -> Approved))
    assertEquals(helper("continue", id, "--message-file", message()).int("turn"), 3)

  test("failures are errors, never dispositions"):
    val finding = Changes.hcursor.downField("findings").downArray.focus.get
    val cases = Seq(
      step("raw_stdout" -> "not json\n".asJson) -> "INVALID_RESULT",
      step("result" -> "{not json".asJson) -> "INVALID_RESULT",
      step("result" -> Changes.set("disposition" -> "MAYBE".asJson)) -> "INVALID_RESULT",
      step("result" -> Changes.set("disposition" -> Json.arr())) -> "INVALID_RESULT",
      step("result" -> Changes.set("findings" -> Json.arr(finding.set("severity" -> Json.obj())))) -> "INVALID_RESULT",
      step("result" -> Approved.set("findings" -> Changes.hcursor.get[Json]("findings").toOption.get)) ->
        "INVALID_RESULT",
      step("result" -> UserDecides.set("userDecision" -> Json.Null)) -> "INVALID_RESULT",
      step("result" -> Changes.set("userDecision" -> UserDecides.hcursor.get[Json]("userDecision").toOption.get)) ->
        "INVALID_RESULT",
      step("result" -> Approved.without("userDecision")) -> "INVALID_RESULT",
      step("result" -> Approved.set("extra" -> 1.asJson)) -> "INVALID_RESULT",
      step("result" -> Changes.set("findings" -> json("""[{"id": "F1", "severity": "low", "description": "d"}]"""))) ->
        "INVALID_RESULT",
      step("result" -> Changes.set("findings" -> Json.arr(finding.set("location" -> 3.asJson)))) -> "INVALID_RESULT",
      step("result" -> UserDecides.set("userDecision" -> UserDecides.hcursor.get[Json]("userDecision").toOption.get
        .set("more" -> "x".asJson))) -> "INVALID_RESULT",
      step("result" -> Approved.without("suggestions")) -> "INVALID_RESULT",
      step("result" -> Approved.set("suggestions" -> Json.obj())) -> "INVALID_RESULT",
      step("result" -> Approved.set("suggestions" -> Json.arr(Suggestion.set("kind" -> "nit".asJson)))) ->
        "INVALID_RESULT",
      step("result" -> Approved.set("suggestions" -> Json.arr(Suggestion.set("location" -> 3.asJson)))) ->
        "INVALID_RESULT",
      step("result" -> Approved.set("suggestions" -> Json.arr(Suggestion.without("reason")))) -> "INVALID_RESULT",
      step("result" -> Json.Null) -> "INVALID_RESULT",
      step("exit" -> 1.asJson, "emit_thread_started" -> false.asJson, "stderr" -> "boom".asJson) -> "REVIEWER_FAILED",
      step("exit" -> 1.asJson, "result" -> Approved, "stderr" -> "boom".asJson) -> "REVIEWER_FAILED",
      step("emit_thread_started" -> false.asJson, "result" -> Approved) -> "REVIEWER_FAILED",
      step("exit" -> 1.asJson, "stderr" -> lostThreadStderr.asJson) -> "REVIEWER_FAILED",
      step("exit" -> 1.asJson, "stderr" -> "Not logged in. Run codex login.".asJson) -> "REVIEWER_AUTH_FAILED",
      step("exit" -> 1.asJson, "stderr" -> "error sending request: 403 Forbidden from proxy".asJson) ->
        "REVIEWER_EGRESS_DENIED",
    ) ++ reviewerFailureCases
    for (failing, code) <- cases do
      plan(failing)
      val failure = error("start", reviewer, "--message-file", message())
      assertEquals(failure.str("code"), code, s"$failing: $failure")
      assertEquals(failure.str("reviewer"), reviewer)
    for review <- reviews() do
      assertEquals(review.str("status"), "NEW")
      assert(review.isNull("approved"))
      assertEquals(review.obj("lastError").int("turn"), 1)
      assertEquals(error("check-approval", review.str("reviewId")).str("code"), "NOT_APPROVED")

  test("a change to the files during a turn discards the turn's result"):
    plan(step("result" -> Approved, "touch" -> "app.py".asJson))
    val failure = error("start", reviewer, "--message-file", message())
    assertEquals(failure.str("code"), "WORKTREE_CHANGED_DURING_REVIEW")
    assertNotEquals(failure.str("before"), failure.str("after"))
    assertEquals(failure.strings("paths"), Vector("app.py"))
    val review = reviews().head
    assertEquals(review.str("status"), "NEW")
    assert(review.isNull("approved"))
    assertEquals(review.str("threadId"), "thread-1")
    assert(Files.readString(repo.resolve("app.py")).contains("changed during review"))
    plan(step("result" -> Approved))
    val retried = helper("continue", review.str("reviewId"), "--message-file", message("again\n"))
    assertEquals((retried.str("status"), retried.int("turn")), ("APPROVED", 2))
    assertResumes(argv(calls()(1)), "thread-1")
    assert(calls()(1).str("prompt").contains("You are an independent code reviewer"))

  test("staging or committing during a turn keeps the result"):
    val head = git("rev-parse", "HEAD").trim
    write("app.py", "print('reviewed')\n")
    plan(step("result" -> Approved, "git" -> json("""[["add", "app.py"]]"""))) // work.py stays unstaged
    val output = helper("start", reviewer, "--message-file", message())
    assertEquals(output.str("status"), "APPROVED")
    assert(calls().head.str("prompt").contains(s"`git diff $head` plus untracked files"))
    assertEquals(helper("check-approval", output.str("reviewId")).str("effectiveStatus"), "APPROVED")
    plan(step("result" -> Approved, "git" -> json("""[["add", "-A"],
      ["-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "during the turn"]]""")))
    val again = helper("continue", output.str("reviewId"), "--message-file", message("again\n"))
    assertEquals((again.str("status"), again.int("turn")), ("APPROVED", 2))
    assertNotEquals(git("rev-parse", "HEAD").trim, head)
    assertEquals(helper("check-approval", output.str("reviewId")).str("effectiveStatus"), "APPROVED")

  test("a thread named before an interrupted or truncated turn is kept"):
    val started = threadStartedLine("kept")
    val cases = Seq(
      ("timeout", step("result" -> Approved, "sleep" -> 5.asJson), Seq("--timeout", "1"), "TURN_INTERRUPTED"),
      ("truncated", step("raw_stdout" -> (started + """{"type": "turn.sta""").asJson), Nil, "INVALID_RESULT"),
      ("failed after start", step("raw_stdout" -> started.asJson, "exit" -> 1.asJson, "stderr" -> "boom".asJson), Nil,
        "REVIEWER_FAILED"),
    )
    for (label, failing, options, code) <- cases do
      plan(failing, step("result" -> Approved))
      val failed = helperFails((Seq("start", reviewer) ++ options ++ Seq("--message-file", message()))*)
      assertEquals(failed.obj("error").str("code"), code, s"$label: $failed")
      val review = helper("show", failed.str("reviewId"))
      assertEquals(review.str("status"), "NEW")
      assertEquals(review.str("threadId"), if label == "timeout" then "thread-1" else "kept", label)
      val retried = helper("continue", review.str("reviewId"), "--message-file", message())
      assertEquals(retried.str("status"), "APPROVED")
      assertResumes(argv(calls().last), review.str("threadId"))
      Files.writeString(log, "")

  // An approved exit and a failed exit each leave a background process behind. The process's marker file must still
  // be missing once the process's sleep has passed.
  private def assertBackgroundProcessKilled(background: (String, Json)*): Unit =
    val cases = Seq(
      ("approved", step("result" -> Approved), 0, "APPROVED"),
      ("failed", step("raw_stdout" -> threadStartedLine("kept").asJson, "exit" -> 1.asJson, "stderr" -> "boom".asJson),
        1, "REVIEWER_FAILED"),
    )
    val markers = for (label, behavior, status, expected) <- cases yield
      val marker = root.resolve(s"left-running-$label")
      plan(behavior.set("background" -> Json.obj((Seq("sleep" -> 2.asJson, "marker" -> marker.toString.asJson) ++
        background)*)))
      val output = helperIn(repo, status, "start", reviewer, "--message-file", message())
      assertEquals(if status == 0 then output.str("status") else output.obj("error").str("code"), expected, label)
      marker
    Thread.sleep(3000) // past the background process's sleep: left running, it would have written
    assertEquals(markers.filter(Files.exists(_)).map(_.getFileName.toString), Nil)

  test("a process the reviewer leaves in its group is killed when the reviewer exits"):
    assertBackgroundProcessKilled()
    // the group's id is not the reviewer's pid, which reaping the reviewer frees
    assertNotEquals(calls().last.int("pgid"), calls().last.int("pid"))

  test("a process tree the reviewer leaves in a session of its own is killed when the reviewer exits"):
    assume(Posix.isLinux, "the helper adopts orphans through prctl, on Linux")
    assertBackgroundProcessKilled("escaped" -> true.asJson)

  test("an escaped process holding the reviewer's stdout ends with the turn"):
    assume(Posix.isLinux, "the helper adopts orphans through prctl, on Linux")
    // The turn ends with the reviewer's exit, or with the timeout, not with the end of its output. The escaped holder
    // is killed then, before its sleep ends, so it never writes its marker.
    val cases = Seq(
      ("approved", step("result" -> Approved), Nil, 0, "APPROVED"),
      ("timeout", step("result" -> Approved, "sleep" -> 5.asJson), Seq("--timeout", "1"), 1, "TURN_INTERRUPTED"),
    )
    val markers = for (label, behavior, options, status, expected) <- cases yield
      val marker = root.resolve(s"holding-stdout-$label")
      plan(behavior.set("background" -> Json.obj("sleep" -> 3.asJson, "marker" -> marker.toString.asJson,
        "escaped" -> true.asJson, "holds_stdout" -> true.asJson)))
      val output = helperIn(repo, status, (Seq("start", reviewer) ++ options ++ Seq("--message-file", message()))*)
      assertEquals(if status == 0 then output.str("status") else output.obj("error").str("code"), expected, label)
      marker
    Thread.sleep(4000)
    assertEquals(markers.filter(Files.exists(_)).map(_.getFileName.toString), Nil)

  test("the model and the effort reach every reviewer command"):
    plan(step("result" -> Changes), step("result" -> Approved))
    val output = helper("start", reviewer, "--model", "model-test", "--effort", "high", "--message-file", message())
    assertEquals((output.str("model"), output.str("effort")), ("model-test", "high"))
    helper("continue", output.str("reviewId"), "--message-file", message())
    for call <- calls() do
      val args = argv(call)
      assertEquals(args(args.indexOf("--model") + 1), "model-test")
      if reviewer == "codex" then assertEquals(args(args.indexOf("-c") + 1), "model_reasoning_effort=\"high\"")
      else assertEquals(args(args.indexOf("--effort") + 1), "high")
    start()
    for option <- Seq("--model", "-c", "--effort") do assert(!argv(calls().last).contains(option), option)

  test("a first turn that dies before naming a thread is retried on a new thread"):
    plan(step("exit" -> 1.asJson, "emit_thread_started" -> false.asJson, "stderr" -> "boom".asJson),
      step("result" -> Approved))
    helperFails("start", reviewer, "--message-file", message())
    val id = helper("list").arr("reviews").head.asObject.get.str("reviewId")
    assert(helper("show", id).isNull("threadId"))
    val retried = helper("continue", id, "--message-file", message("the retry\n"))
    assertEquals((retried.str("status"), retried.str("threadId")), ("APPROVED", "thread-2"))
    assert(calls()(1).str("prompt").contains("did not answer\n\nYour turn on it ended in an error before you " +
      "answered. The author's latest message follows the unanswered ones.\n\n## Task\n\nreview me\n"))
    assertOpensAThread(argv(calls()(1)))

  test("preconditions are checked before the reviewer runs, and a new repository's files are all in scope"):
    def startFailsWith(code: String): Unit =
      val failure = error("start", reviewer, "--message-file", message())
      assertEquals((failure.str("code"), failure.str("reviewer")), (code, reviewer), failure.toString)
    environment = Map("FAKE_REVIEWER_SIGNED_OUT" -> "1")
    startFailsWith("REVIEWER_AUTH_FAILED")
    environment = Map.empty
    ruleset = s"egress profile: deny-unless-selected\nallow https://$otherHost/ tunnel\n"
    startFailsWith("REVIEWER_EGRESS_DENIED")
    assertEquals(helper("list").arr("reviews"), Vector.empty) // refused before a review exists
    ruleset = ""
    plan(step("result" -> Approved))
    assertEquals(helper("start", reviewer, "--message-file", message()).str("status"), "APPROVED")
    assertEquals(calls().size, 1)
    assertEquals(error("start", reviewer, "--message-file", message("")).str("code"), "MESSAGE_UNREADABLE")
    assertEquals(error("show", "no-such-review").str("code"), "UNKNOWN_REVIEW")
    val outside = Files.createDirectory(root.resolve("outside"))
    Files.writeString(outside.resolve("program.py"), "print('review me')\n")
    val failure = helperIn(outside, 1, "start", reviewer, "--message-file", message()).obj("error")
    assertEquals(failure.str("code"), "NOT_A_GIT_REPOSITORY")
    val steps = failure.str("message").linesIterator.filter(_.startsWith("git ")).toVector
    assertEquals(steps, Vector("git init", "git commit --allow-empty -m \"Start of the review\""))
    gitIn(outside, "init", "-q") // following the instructions leaves the files in the review's scope
    gitIn(outside, "commit", "--allow-empty", "-q", "-m", "Start of the review")
    plan(step("result" -> Approved))
    val recovered = helperIn(outside, 0, "start", reviewer, "--message-file", message())
    assertEquals(recovered.str("status"), "APPROVED")
    val head = gitIn(outside, "rev-parse", "HEAD").trim
    assert(calls().last.str("prompt").contains(s"`git diff $head` plus untracked files"))
    val restored = root.resolve("restored")
    helperIn(outside, 0, "restore", recovered.str("reviewId"), "--turn", "1", restored.toString)
    assertEquals(Files.list(restored).iterator().asScala.map(_.getFileName.toString).toVector, Vector("program.py"))

  test("the transcript renders every turn"):
    val quotedCode =
      "~~~sh\n# a comment\n~~~\n\n- ```c\n  # include <stdio.h>\n  ```\n\n> ```\n> # quoted\n> ```\n\n" +
        "```\n    ```\n# still code\n```\n\n ```\n    ```\n# still code\n ```\n\n" +
        "```text\n- ```\n# literal content\n```\n"
    plan(step("result" -> Changes), step("result" -> UserDecides))
    val id = helper("start", reviewer, "--instructions-file", message("Be strict.\n"), "--message-file",
      message("## Task\n\nthe task\n\n" + quotedCode + "\n###### Deep\n")).str("reviewId")
    helper("continue", id, "--instructions-file", message("Be lenient.\n"), "--message-file",
      message("## Disputed findings\n\nF1 is fine\n"))
    assert(calls()(1).str("prompt").contains("Be lenient."))
    helper("escalate", id, "--message-file", message("agreed\n"))
    val (status, markdown) = helperOutput(Seq("transcript", id))
    assertEquals(status, 0, markdown)
    assert(markdown.indexOf("## Turn 1") < markdown.indexOf("Be strict."))
    assert(markdown.indexOf("Be strict.") < markdown.indexOf("#### Task"))
    assert(markdown.indexOf("## Turn 2") < markdown.indexOf("Be lenient."))
    for text <- Seq(s"# $display review $id", "- Status: USER_DECISION_REQUIRED", s"- $display thread: thread-1",
        "### Instructions from the user, from this turn on", "Be lenient.", "## Turn 1", "### The author",
        "#### Task", s"### $display: CHANGES_REQUESTED", "- **F1** (high) `app.py:1`: d", "Evidence: e", "## Turn 2",
        s"### $display: USER_DECISION_REQUIRED", s"- $display's position: p", "- Decision requested: d",
        "### The coordinator agreed that the user must decide", "## How to see how it went",
        s"ko-review transcript $id")
    do assert(markdown.contains(text), text)
    assert(markdown.contains(quotedCode + "\n###### Deep\n"), markdown) // code as written, level 6 at most
    val (_, second) = helperOutput(Seq("transcript", id, "--turn", "2"))
    assert(second.startsWith(s"# Review $id, turn 2\n"), second)
    for text <- Seq("F1 is fine", s"### $display: USER_DECISION_REQUIRED",
        "### The coordinator agreed that the user must decide") do assert(second.contains(text), text)
    assert(!second.contains("the task"))
    assertEquals(error("transcript", id, "--turn", "3").str("code"), "UNKNOWN_TURN")
