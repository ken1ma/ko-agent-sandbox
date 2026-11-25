package koreview

import io.circe.Json
import io.circe.syntax.*
import java.nio.file.{Files, Path}
import java.time.{Duration, Instant}
import scala.jdk.CollectionConverters.*
import HelperFixture.*

/** The review-cycle tests against the fake `codex`, plus the tests of what does not depend on the reviewer. */
class CodexReviewTest extends ReviewCycleTests:
  def reviewer = "codex"

  /** Rewrites every JSON file of the review with `writtenAt` set to `moment`. */
  private def age(reviewId: String, moment: Instant): Path =
    ageDirectory(Path.of(helper("show", reviewId).str("reviewPath")), moment)

  private def ageDirectory(dir: Path, moment: Instant): Path =
    for path <- Files.walk(dir).iterator().asScala.toVector if path.toString.endsWith(".json") do
      val text = json(Files.readString(path)).set("writtenAt" -> ReviewFiles.timeText(moment).asJson)
      Files.delete(path)
      Files.writeString(path, text.noSpaces)
    dir

  /** Installs a `git` on the PATH that runs `before` in sh, then the real git. */
  private def wrapGit(before: String): Path =
    val real = HelperFixture.run(root, Map.empty, Seq("sh", "-c", "command -v git"))._2.trim
    val wrapper = Files.writeString(bin.resolve("git"), s"#!/bin/sh\n$before\nexec '$real' \"$$@\"\n")
    wrapper.toFile.setExecutable(true)
    wrapper

  test("list is oldest first, and deterministic on a tie"):
    val first = start().str("reviewId")
    val second = start().str("reviewId")
    def setCreated(id: String, milliseconds: Int): Unit =
      val path = Path.of(helper("show", id).str("reviewPath")).resolve("start.json")
      val text = json(Files.readString(path)).set("writtenAt" -> f"2026-01-01T00:00:00.$milliseconds%03dZ".asJson)
      Files.delete(path)
      Files.writeString(path, text.noSpaces)
    def listed() = helper("list").arr("reviews").map(_.asObject.get.str("reviewId"))
    setCreated(first, 200)
    setCreated(second, 100)
    assertEquals(listed(), Vector(second, first))
    setCreated(first, 100)
    assertEquals(listed(), Vector(first, second).sorted)

  test("terminating the helper kills codex, records the error and keeps the thread"):
    plan(step("result" -> Approved, "sleep" -> 4.asJson), step("result" -> Approved))
    val done = root.resolve("codex-ran-to-the-end")
    environment = Map("FAKE_REVIEWER_DONE" -> done.toString)
    val process = spawn("start", "codex", "--message-file", message())
    environment = Map.empty
    val deadline = System.nanoTime() + 30_000_000_000L
    while (calls().isEmpty || reviews().headOption.forall(_.isNull("threadId"))) && System.nanoTime() < deadline do
      Thread.sleep(100)
    process.toHandle.destroy() // SIGTERM
    val output = String(process.getInputStream.readAllBytes())
    assertEquals(process.waitFor(), 1, output)
    val failure = json(output).asObject.get.obj("error")
    assertEquals((failure.str("code"), failure.str("message")), ("TURN_INTERRUPTED", "terminated by SIGTERM"))
    Thread.sleep(5000) // past the fake's sleep: an orphaned codex would have written the marker
    assert(!Files.exists(done), "codex outlived the helper")
    val review = reviews().head
    assertEquals((review.str("status"), review.str("threadId")), ("NEW", "thread-1"))
    assertEquals(review.obj("lastError").str("code"), "TURN_INTERRUPTED")
    val retried = helper("continue", review.str("reviewId"), "--message-file", message())
    assertEquals(retried.str("status"), "APPROVED")
    assertEquals(argv(calls().last).take(3), Vector("exec", "resume", "thread-1"))

  test("terminating the helper while it records the turn's start stops before codex"):
    val marker = root.resolve("git-marker")
    wrapGit(s"""if [ "$$1" = ls-tree ]; then echo in > '$marker'; sleep 5; fi""")
    plan(step("result" -> Approved))
    val process = spawn("start", "codex", "--message-file", message())
    val deadline = System.nanoTime() + 30_000_000_000L
    while !Files.exists(marker) && System.nanoTime() < deadline do Thread.sleep(100)
    assert(Files.exists(marker))
    process.toHandle.destroy()
    val output = String(process.getInputStream.readAllBytes())
    assertEquals(process.waitFor(), 1, output)
    Files.delete(bin.resolve("git"))
    val parsed = json(output).asObject.get
    assertEquals(parsed.obj("error").str("code"), "TURN_INTERRUPTED")
    assertEquals(calls(), Vector.empty)
    val review = helper("show", parsed.str("reviewId"))
    assertEquals((review.str("status"), review.obj("lastError").str("code")), ("NEW", "TURN_INTERRUPTED"))

  test("each turn records the Claude Code or Codex session that ran it, as far as its environment tells"):
    val claude = Files.writeString(bin.resolve("claude-executable"), "#!/bin/sh\necho '2.1.325 (Claude Code)'\n")
    claude.toFile.setExecutable(true)
    def coordinator(id: String, turn: Int) =
      json(Files.readString(turnDir(id, turn).resolve("request.json"))).hcursor.downField("coordinator").focus
    environment = Map("CLAUDE_CODE_SESSION_ID" -> "claude-session", "CLAUDE_CODE_EXECPATH" -> claude.toString,
      "CLAUDE_EFFORT" -> "high")
    val id = start().str("reviewId")
    assertEquals(coordinator(id, 1), Some(json("""{"tool": "claude", "sessionId": "claude-session",
      "version": "2.1.325 (Claude Code)", "effort": "high"}""")))
    // Another session continues the review; its turn records it.
    environment = Map("CODEX_THREAD_ID" -> "codex-thread", "CODEX_VERSION" -> "0.169.0")
    plan(step("result" -> Approved))
    helper("continue", id, "--message-file", message())
    assertEquals(coordinator(id, 2), Some(json("""{"tool": "codex", "sessionId": "codex-thread",
      "version": "0.169.0"}""")))
    environment = Map.empty
    plan(step("result" -> Approved))
    helper("continue", id, "--message-file", message())
    assertEquals(coordinator(id, 3), None) // run by hand
    val (_, markdown) = helperOutput(Seq("transcript", id))
    assert(markdown.contains("### The author, through the coordinator: claude 2.1.325 (Claude Code), high effort\n"),
      markdown)
    assert(markdown.contains("### The author, through the coordinator: codex 0.169.0\n"), markdown)
    assert(markdown.contains("## Turn 3\n\n### The author\n"), markdown)
    // A version that cannot be read, or that is not Claude Code's, is absent and stops nothing.
    val node = Files.writeString(bin.resolve("node-executable"), "#!/bin/sh\necho v26.0.0\n")
    node.toFile.setExecutable(true)
    for (program, turn) <- Seq(root.resolve("gone").toString -> 4, node.toString -> 5) do
      environment = Map("CLAUDE_CODE_SESSION_ID" -> "claude-session", "CLAUDE_CODE_EXECPATH" -> program)
      plan(step("result" -> Approved))
      assertEquals(helper("continue", id, "--message-file", message()).str("status"), "APPROVED", program)
      assertEquals(coordinator(id, turn), Some(json("""{"tool": "claude", "sessionId": "claude-session"}""")))
    environment = Map.empty

  test("defaults follow Codex's precedence for this repository"):
    val home = Files.createDirectory(root.resolve("codex-home"))
    val config = home.resolve("config.toml")
    environment = Map("CODEX_HOME" -> home.toString)
    var found = helper("defaults", "codex")
    assertEquals((found.isNull("model"), found.bool("partial")), (true, true))
    assertEquals(found("catalog").get, json("""[
      {"model": "gpt-test", "description": "Test model.", "defaultEffort": "medium", "efforts": ["low", "high"]},
      {"model": "gpt-second", "description": "Second model.", "defaultEffort": "high", "efforts": ["high"]}]"""))
    // unconfigured: Codex's default, the first model its picker lists, at that model's default effort
    assertEquals(found("recommended").get,
      json("""{"model": "gpt-test", "effort": "medium", "efforts": ["low", "high"], "upgrade": null}"""))
    Files.writeString(config, "model_reasoning_effort = \"low\"\n")
    assertEquals(helper("defaults", "codex")("recommended").get,
      json("""{"model": "gpt-test", "effort": "low", "efforts": ["low", "high"], "upgrade": null}"""))
    Files.writeString(config, "model = \"gpt-second\"\n") // a retiring model names its upgrade
    assertEquals(helper("defaults", "codex")("recommended").get, json("""{"model": "gpt-second", "effort": "high",
      "efforts": ["high"], "upgrade": {"model": "gpt-test", "migrationMarkdown": "Second retires."}}"""))
    environment = Map("CODEX_HOME" -> home.toString, "FAKE_CODEX_NO_CATALOG" -> "1")
    found = helper("defaults", "codex")
    assert(found.isNull("catalog"))
    assertEquals(found("recommended").get,
      json("""{"model": "gpt-second", "effort": null, "efforts": null, "upgrade": null}"""))
    environment = Map("CODEX_HOME" -> home.toString)
    Files.writeString(config, "model = \"gpt-user\"\nmodel_reasoning_effort = \"high\"\n[tui]\nx = 1\n")
    write(".codex/config.toml", "model = \"gpt-project\"\n")
    found = helper("defaults", "codex") // the project is not trusted: its file is skipped
    assertEquals((found.str("model"), found.str("effort")), ("gpt-user", "high"))
    assertEquals(found.obj("source").str("model"), config.toString)
    Files.writeString(config, "model = \"gpt-user\"\nmodel_reasoning_effort = \"high\"\n" +
      s"[projects.\"${repo.toRealPath()}\"]\ntrust_level = \"trusted\"\n")
    found = helper("defaults", "codex")
    assertEquals((found.str("model"), found.str("effort")), ("gpt-project", "high"))
    assertEquals(found.obj("source").str("model"), repo.resolve(".codex/config.toml").toString)
    // a linked worktree without its own entry takes its main worktree's trust, as Codex does
    val worktree = root.resolve("worktree")
    git("worktree", "add", "-q", worktree.toString)
    Files.createDirectories(worktree.resolve(".codex"))
    Files.writeString(worktree.resolve(".codex/config.toml"),
      "model = \"gpt-worktree\"\nmodel_reasoning_effort = \"low\"\n")
    def modelAndEffort(cwd: Path) =
      val result = helperIn(cwd, 0, "defaults", "codex")
      (result("model").flatMap(_.asString), result("effort").flatMap(_.asString))
    assertEquals(modelAndEffort(worktree), (Some("gpt-worktree"), Some("low")))
    val copy = root.resolve("worktree-copy") // its .git names the worktree's registration, which names the original
    HelperFixture.run(root, Map.empty, Seq("cp", "-R", worktree.toString, copy.toString))
    assertEquals(modelAndEffort(copy), (Some("gpt-user"), Some("high")))
    // Git follows these, Codex refuses them: a symlinked .git, an oversized one, a symlinked registration
    val dotGit = worktree.resolve(".git")
    val pointer = Files.readString(dotGit)
    val registration = Path.of(pointer.stripPrefix("gitdir:").trim).resolve("gitdir")
    val registered = Files.readString(registration)
    def refused(): Unit = assertEquals(modelAndEffort(worktree), (Some("gpt-user"), Some("high")))
    Files.delete(dotGit)
    Files.writeString(worktree.resolve(".git-pointer"), pointer)
    Files.createSymbolicLink(dotGit, Path.of(".git-pointer"))
    refused()
    Files.delete(dotGit)
    Files.writeString(dotGit, pointer + "\n" * 70_000)
    refused()
    Files.writeString(dotGit, pointer)
    Files.delete(registration)
    Files.writeString(registration.resolveSibling("gitdir-target"), registered)
    Files.createSymbolicLink(registration, Path.of("gitdir-target"))
    refused()
    Files.delete(registration)
    Files.writeString(registration, registered)
    assertEquals(modelAndEffort(worktree), (Some("gpt-worktree"), Some("low")))
    Files.writeString(config, "model = \"gpt-user\"\n" +
      s"[projects.\"${repo.toRealPath()}\"]\ntrust_level = \"trusted\"\n" +
      s"[projects.\"${worktree.toRealPath()}\"]\ntrust_level = \"untrusted\"\n")
    assertEquals(modelAndEffort(worktree), (Some("gpt-user"), None)) // the worktree's own entry wins
    Files.writeString(config, "model = [not toml\n")
    assertEquals(error("defaults", "codex").str("code"), "REVIEWER_CONFIG_UNREADABLE")
    environment = Map.empty

  /** Commits into `directory` a `conf` file with a clean filter that strips `local` and `changed` lines. */
  private def filteredRepository(directory: Path): Unit =
    Files.writeString(directory.resolve(".gitattributes"), "conf filter=strip\n")
    gitIn(directory, "config", "filter.strip.clean", "sed -e /^local/d -e /^changed/d")
    Files.writeString(directory.resolve("conf"), "keep\nlocal one\n")
    gitIn(directory, "add", ".gitattributes", "conf")
    gitIn(directory, "commit", "-q", "-m", "filtered file")

  test("a clean filter cannot hide a change"):
    filteredRepository(repo)
    val inner = Files.createDirectory(repo.resolve("inner"))
    gitIn(inner, "init", "-q")
    filteredRepository(inner)
    val id = start(Approved).str("reviewId")
    def stale() = assertEquals(error("check-approval", id).str("effectiveStatus"), "STALE_APPROVAL")
    write("conf", "keep\nlocal two\n") // the filtered blob is unchanged; the file is not
    stale()
    write("conf", "keep\nlocal one\n")
    assertEquals(helper("check-approval", id).str("effectiveStatus"), "APPROVED")
    Files.writeString(inner.resolve("conf"), "keep\nlocal two\n") // the same inside a nested repository
    stale()
    Files.writeString(inner.resolve("conf"), "keep\nlocal one\n")
    git("add", "-A")
    git("commit", "-q", "-m", "after approval")
    assertEquals(helper("check-approval", id).str("effectiveStatus"), "APPROVED")
    write("conf", "keep\nlocal two\n")
    stale()
    write("conf", "keep\nlocal one\n")
    plan(step("result" -> Approved, "touch" -> "conf".asJson)) // appends a line the filter strips
    assertEquals(error("continue", id, "--message-file", message()).str("code"), "WORKTREE_CHANGED_DURING_REVIEW")

  test("an approved deletion or rename survives staging and committing"):
    write("gone.txt", "to be deleted\n")
    write("old.txt", "to be renamed\n")
    git("add", "-A")
    git("commit", "-q", "-m", "two files")
    Files.delete(repo.resolve("gone.txt"))
    Files.move(repo.resolve("old.txt"), repo.resolve("new.txt"))
    val id = start(Approved).str("reviewId")
    git("add", "-A")
    assertEquals(helper("check-approval", id).str("effectiveStatus"), "APPROVED")
    git("commit", "-q", "-m", "deletion and rename")
    assertEquals(helper("check-approval", id).str("effectiveStatus"), "APPROVED")
    write("gone.txt", "back\n")
    assertEquals(error("check-approval", id).str("effectiveStatus"), "STALE_APPROVAL")

  test("an approved staged rename survives unstaging"):
    write("old.txt", "to be renamed\n")
    git("add", "-A")
    git("commit", "-q", "-m", "one file")
    git("mv", "old.txt", "new.txt") // git now detects the rename
    val id = start(Approved).str("reviewId")
    git("reset", "-q") // old.txt deleted, new.txt untracked; no file changes
    assertEquals(helper("check-approval", id).str("effectiveStatus"), "APPROVED")

  test("a usage limit names codex's words, and the retry resends the lost message"):
    val limit = "You've hit your usage limit. Try again at 3:05 PM."
    plan(
      step("result" -> Changes),
      step("exit" -> 1.asJson, "events" -> Json.arr(Json.obj("type" -> "error".asJson, "message" -> limit.asJson),
        Json.obj("type" -> "turn.failed".asJson, "error" -> Json.obj("message" -> limit.asJson)))),
      step("exit" -> 1.asJson, "stderr" -> "Reading prompt from stdin...\nQuota exceeded\n".asJson),
      step("result" -> Changes),
    )
    val id = helper("start", "codex", "--max-answered-turns", "2", "--message-file", message()).str("reviewId")
    val lost = message("## Disputed findings\n\nF1 is fine\n\n```c\n#include <stdio.h>\n```\n")
    val failure = error("continue", id, "--message-file", lost)
    assertEquals((failure.str("code"), failure.str("message")), ("REVIEWER_FAILED", s"codex failed: $limit"))
    assertEquals(error("continue", id, "--message-file", message("nothing changed\n")).str("message"),
      "codex failed: Quota exceeded")
    val retried = helper("continue", id, "--message-file", message("still nothing\n"))
    // Failed turns do not count, so the second answer reaches the limit of two.
    assertEquals((retried.str("disposition"), retried.str("status"), retried.int("turn")),
      ("CHANGES_REQUESTED", "LOOP_LIMIT_REACHED", 4))
    val prompt = calls().last.str("prompt")
    assert(prompt.indexOf("# The author's message of turn 2, which you did not answer") <
      prompt.indexOf("# The author's message of turn 3, which you did not answer"))
    assert(prompt.indexOf("\n\n## Disputed findings\n\nF1 is fine") < prompt.indexOf("\n\nnothing changed"))
    assert(prompt.indexOf("nothing changed") < prompt.indexOf("# The author's response, turn 4"))
    assert(prompt.contains("F1 is fine\n\n```c\n#include <stdio.h>\n```\n")) // as written
    assert(!prompt.contains("review me")) // turn 1 had its answer
    plan(step("result" -> Approved))
    assertEquals(error("continue", id, "--message-file", message()).str("code"), "LOOP_LIMIT_REACHED")
    assertEquals(calls().size, 4) // the limit refuses before codex runs

  test("concurrent commands on one review are refused, and show tells what the running turn does"):
    val id = start().str("reviewId")
    plan(step("result" -> Approved, "sleep" -> 3.asJson), step("result" -> Approved))
    val slow = spawn("continue", id, "--message-file", message("slow\n"))
    val deadline = System.nanoTime() + 30_000_000_000L
    while calls().size < 2 && System.nanoTime() < deadline do Thread.sleep(100)
    assertEquals(error("continue", id, "--message-file", message("fast\n")).str("code"), "REVIEW_LOCKED")
    val shown = helper("show", id)
    assertEquals(shown.str("status"), "REVIEWING")
    val activity = shown.obj("activity")
    assertEquals(activity.int("turn"), 2)
    assert(activity.str("stdoutPath").endsWith("turns/002/reviewer.stdout"))
    assert(activity.int("elapsedSeconds") >= 0)
    assertEquals(activity.obj("lastEventReceived").str("type"), "thread.started")
    for record <- Seq("null\n", "[1]\n", """{"type": "turn.sta""") do // what the reader tolerates, show tolerates
      Files.writeString(Path.of(activity.str("stdoutPath")), record, java.nio.file.StandardOpenOption.APPEND)
      assert(helper("show", id).obj("activity").obj("lastEventReceived").isNull("type"), record)
    val output = String(slow.getInputStream.readAllBytes())
    assertEquals(slow.waitFor(), 0, output)
    assertEquals(json(output).asObject.get.str("status"), "APPROVED")
    assertEquals(calls().size, 2)

  test("the lock is taken before the review's files are read"):
    val id = start().str("reviewId")
    val dir = Path.of(helper("show", id).str("reviewPath"))
    val startFile = dir.resolve("start.json")
    val saved = Files.readString(startFile)
    val lock = ReviewLock.tryTake(dir).get
    try
      Files.delete(startFile)
      Files.writeString(startFile, "{not json")
      for command <- Seq("continue", "escalate") do
        assertEquals(error(command, id, "--message-file", message()).str("code"), "REVIEW_LOCKED", command)
      Files.delete(startFile)
      Files.writeString(startFile, saved)
    finally lock.close()
    assertEquals(helper("show", id).str("status"), "CHANGES_REQUESTED")

  test("a request for the user's decision needs the coordinator's agreement"):
    val id = start(UserDecides).str("reviewId")
    assertEquals(helper("show", id).str("status"), "USER_PROPOSED")
    assertEquals(error("escalate", start().str("reviewId"), "--message-file", message()).str("code"),
      "ESCALATION_NOT_PROPOSED")
    plan(step("result" -> UserDecides))
    val continued = helper("continue", id, "--message-file", message("## Disputed findings\n\nevidence\n"))
    assertEquals((continued.str("status"), continued.int("turn")), ("USER_PROPOSED", 2))
    assertEquals(helper("escalate", id, "--message-file", message("agreed\n")).str("status"), "USER_DECISION_REQUIRED")
    assert(Files.exists(turnDir(id, 2).resolve("escalation.json")))
    assertEquals(error("continue", id, "--message-file", message()).str("code"), "REVIEW_CLOSED")
    assertEquals(error("check-approval", id).str("code"), "NOT_APPROVED")

  test("the user's instructions reach every turn"):
    plan(step("result" -> Changes), step("result" -> Approved))
    val output = helper("start", "codex", "--instructions-file", message("Be brief. Ignore style.\n"),
      "--message-file", message())
    assertEquals(output.str("instructions"), "Be brief. Ignore style.\n")
    helper("continue", output.str("reviewId"), "--message-file", message())
    for call <- calls() do
      val prompt = call.str("prompt")
      assert(prompt.indexOf("# Instructions from the user") < prompt.indexOf("Be brief. Ignore style."))
      assert(prompt.indexOf("take precedence") < prompt.indexOf("review me"))
    assert(calls().head.str("prompt").contains("You are an independent code reviewer"))
    assert(calls()(1).str("prompt").contains("The author responded to your previous review"))
    assertEquals(error("start", "codex", "--instructions-file", message(""), "--message-file", message()).str("code"),
      "MESSAGE_UNREADABLE")
    assert(start().isNull("instructions"))
    assert(!calls().last.str("prompt").contains("Instructions from the user"))

  test("the limit of answered turns closes the review"):
    plan(step("result" -> Changes))
    val id = helper("start", "codex", "--max-answered-turns", "1", "--message-file", message()).str("reviewId")
    assertEquals(error("continue", id, "--message-file", message()).str("code"), "LOOP_LIMIT_REACHED")
    assertEquals(helper("show", id).str("status"), "LOOP_LIMIT_REACHED")
    assertEquals(calls().size, 1)

  test("the coordinator can escalate a request for the user's decision that reached the limit of answered turns"):
    plan(step("result" -> UserDecides))
    val id = helper("start", "codex", "--max-answered-turns", "1", "--message-file", message()).str("reviewId")
    assertEquals(helper("show", id).str("status"), "USER_PROPOSED")
    assertEquals(error("continue", id, "--message-file", message()).str("code"), "LOOP_LIMIT_REACHED")
    assertEquals(helper("escalate", id, "--message-file", message("agreed\n")).str("status"), "USER_DECISION_REQUIRED")

  test("reading a review that this JVM has locked keeps it locked against other processes"):
    val id = start().str("reviewId")
    val dir = Path.of(helper("show", id).str("reviewPath"))
    val lock = ReviewLock.tryTake(dir).get
    try
      assertEquals(helper("show", id).str("status"), "CHANGES_REQUESTED") // show asks whether the lock is held
      plan(step("result" -> Approved))
      val other = spawn("continue", id, "--message-file", message())
      val output = String(other.getInputStream.readAllBytes())
      assertEquals(other.waitFor(), 1, output)
      assertEquals(json(output).asObject.get.obj("error").str("code"), "REVIEW_LOCKED")
    finally lock.close()

  test("the limit of answered turns refuses a turn without ending an approval"):
    plan(step("result" -> Approved))
    val id = helper("start", "codex", "--max-answered-turns", "1", "--message-file", message()).str("reviewId")
    assertEquals(error("continue", id, "--message-file", message()).str("code"), "LOOP_LIMIT_REACHED")
    assertEquals(helper("check-approval", id).str("effectiveStatus"), "APPROVED")

  test("an approval does not cover paths that entered the scope"):
    write("lib.py", "print('committed before the review')\n")
    git("add", "lib.py")
    git("commit", "-q", "-m", "lib")
    val id = start(Approved).str("reviewId") // the scope is work.py
    git("reset", "-q", "--soft", "HEAD~1") // lib.py enters the scope; no file changes
    assertEquals(error("check-approval", id).arr("staleReasons"),
      Vector(json("""{"reason": "paths entered the scope since the approval", "paths": ["lib.py"]}""")))
    val offered = helper("approvals").arr("approvals").map(_.asObject.get)
    assertEquals(offered.map(row => (row.strings("coveredPaths"), row.strings("newPaths"))),
      Vector((Vector("work.py"), Vector("lib.py"))))
    git("commit", "-q", "-m", "lib again")
    assertEquals(helper("check-approval", id).str("effectiveStatus"), "APPROVED")

  test("reviews are kept per worktree"):
    val id = start(Approved).str("reviewId")
    val other = root.resolve("other")
    gitIn(root, "clone", "-q", repo.toString, other.toString)
    assertEquals(helperIn(other, 0, "list").arr("reviews"), Vector.empty)
    assertEquals(helperIn(other, 1, "show", id).obj("error").str("code"), "UNKNOWN_REVIEW")
    assertEquals(Files.list(state.resolve("worktrees")).count(), 1L) // reading created no directory for the clone

  private def digest(): String = helper("digest").str("contentDigest")

  test("the digest covers every kind of change"):
    val clean = digest()
    assertEquals(digest(), clean)
    val seen = collection.mutable.Set(clean)
    def changed(label: String): String =
      val current = digest()
      assert(!seen(current), label)
      seen += current
      current
    write("app.py", "print('unstaged')\n")
    val edited = changed("unstaged edit")
    git("add", "app.py")
    assertEquals(digest(), edited) // staging is no change of content
    write("app.py", "print('staged and unstaged')\n")
    changed("staged plus unstaged")
    git("restore", "--source=HEAD", "--worktree", "app.py")
    assertEquals(digest(), clean) // the staged edit alone is not in the files
    git("reset", "-q", "--hard")
    write("work.py", "print('work in progress')\n")
    assertEquals(digest(), clean)
    Files.delete(repo.resolve("app.py"))
    changed("deletion")
    git("checkout", "--", "app.py")
    git("mv", "app.py", "moved.py")
    changed("rename")
    git("reset", "-q", "--hard")
    write("work.py", "print('work in progress')\n")
    write("untracked.txt", "new\n")
    changed("untracked file")
    Files.write(repo.resolve("untracked.txt"), Array[Byte](0, 1, 2))
    changed("binary content")
    repo.resolve("untracked.txt").toFile.setExecutable(true)
    changed("mode")
    Files.delete(repo.resolve("untracked.txt"))
    assertEquals(digest(), clean)
    write("ignored/file", "ignored\n")
    assertEquals(digest(), clean)
    Files.createSymbolicLink(repo.resolve("link"), Path.of("app.py"))
    changed("symlink")
    Files.delete(repo.resolve("link"))
    Files.createSymbolicLink(repo.resolve("link"), Path.of("elsewhere"))
    changed("symlink target")
    Files.delete(repo.resolve("link"))
    write("ユニコード.txt", "unicode\n")
    changed("unicode name")
    Files.delete(repo.resolve("ユニコード.txt"))
    write("new\nline.txt", "newline\n")
    changed("newline in name")
    Files.delete(repo.resolve("new\nline.txt"))
    Files.createDirectory(repo.resolve("empty"))
    assertEquals(digest(), clean)
    val nested = Files.createDirectory(repo.resolve("nested"))
    gitIn(nested, "init", "-q")
    Files.writeString(nested.resolve("inner.txt"), "one\n")
    changed("nested repository")
    Files.writeString(nested.resolve("inner.txt"), "two\n")
    changed("nested repository content")
    deleteTree(nested)
    assertEquals(digest(), clean)
    write("app.py", "print('committed')\n")
    val committed = changed("edit")
    git("commit", "-q", "-am", "next")
    assertEquals(digest(), committed) // a new HEAD is no change of content
    if Posix.isLinux then // macOS refuses such a name
      HelperFixture.run(repo, Map.empty, Seq("sh", "-c", "printf one > \"$(printf '\\377.txt')\""))
      assertEquals(error("digest").str("code"), "PATH_NOT_UTF8") // a file the helper cannot read is no silent gap

  test("the digest follows a submodule past its dirty flags, and the patches leave its files out"):
    val library = Files.createDirectory(root.resolve("library"))
    gitIn(library, "init", "-q", "-b", "main")
    Files.writeString(library.resolve("lib.py"), "v1\n")
    gitIn(library, "add", "-A")
    gitIn(library, "commit", "-q", "-m", "v1")
    git("submodule", "add", "-q", library.toString, "vendor")
    git("commit", "-q", "-m", "add submodule")
    val clean = digest()
    val id = start(Approved).str("reviewId")
    val manifest = json(Files.readString(turnDir(id, 1).resolve("manifest.json"))).asObject.get
    assertEquals(manifest.strings("repositories"), Vector("vendor"))
    val vendor = repo.resolve("vendor")
    Files.writeString(vendor.resolve("lib.py"), "edited once\n")
    val once = digest()
    assertNotEquals(once, clean)
    Files.writeString(vendor.resolve("lib.py"), "edited twice\n")
    var twice = digest()
    assert(!Set(clean, once).contains(twice))
    for text <- Seq("c1", "c2") do
      Files.writeString(vendor.resolve("lib.py"), text + "\n")
      gitIn(vendor, "commit", "-q", "-am", text)
      val committed = digest()
      assert(!Set(clean, once, twice).contains(committed))
      twice = committed
    gitIn(vendor, "commit", "-q", "--allow-empty", "-m", "empty")
    assertEquals(digest(), twice) // a commit inside the submodule changes no content
    plan(step("result" -> Approved))
    helper("continue", id, "--message-file", message())
    assert(!Files.readString(turnDir(id, 2).resolve("start.patch")).contains("lib.py"))

  test("each turn's start is rebuilt from its patches without touching the worktree"):
    write("ignored/tracked", "tracked though ignored\n")
    write("ignored/removed", "removed from the index\n")
    git("add", "-f", "ignored/tracked", "ignored/removed")
    git("commit", "-q", "-m", "force-added")
    git("rm", "-q", "--cached", "ignored/removed")
    write("ignored/tracked", "tracked though ignored, edited\n")
    write("ignored/staged", "staged, not committed\n")
    git("add", "-f", "ignored/staged")
    write("app.py", "print('changed')\n")
    write("untracked.txt", "new\n")
    write("ignored/file", "ignored\n")
    val statusBefore = git("status", "--porcelain=v2", "--untracked-files=all")
    val indexBefore = git("diff", "--cached", "--stat")
    val refsBefore = git("for-each-ref")
    plan(step("result" -> Changes), step("result" -> Approved))
    val id = helper("start", "codex", "--message-file", message()).str("reviewId")
    assertEquals(git("status", "--porcelain=v2", "--untracked-files=all"), statusBefore)
    assertEquals(git("diff", "--cached", "--stat"), indexBefore)
    assertEquals(git("for-each-ref"), refsBefore)
    val first = root.resolve("first")
    helper("restore", id, "--turn", "1", first.toString)
    def files(directory: Path) = Files.walk(directory).iterator().asScala.filter(Files.isRegularFile(_))
      .map(directory.relativize(_).toString).toVector.sorted
    assertEquals(files(first), Vector(".gitignore", "app.py", "ignored/staged", "ignored/tracked", "untracked.txt",
      "work.py"))
    assertEquals(Files.readString(first.resolve("ignored/tracked")), "tracked though ignored, edited\n")
    assertEquals(Files.readString(first.resolve("app.py")), "print('changed')\n")
    write("app.py", "print('fixed')\n")
    val approved = helper("continue", id, "--message-file", message())
    assertEquals(approved.obj("approved").int("turn"), 2)
    assertEquals(approved.strings("inspect"), Vector(
      s"ko-review transcript $id  # one section per turn",
      s"ko-review diff $id  # your tree against the approved turn's start",
      s"ko-review diff $id --from 1 --to 2  # what changed during the review",
      "ko-review list  # this worktree's reviews, by id",
      s"ko-review delete $id  # the review's files, once you no longer need them",
    ))
    val (_, between) = helperOutput(Seq("diff", id, "--from", "1", "--to", "2", "--", "--name-only"))
    assertEquals(between.linesIterator.toVector, Vector("app.py"))
    write("created-later.txt", "new\n")
    write("app.py", "print('edited after approval')\n")
    val (status, stat) = helperOutput(Seq("diff", id, "--", "--stat"))
    assertEquals(status, 0, stat)
    assertEquals(stat.linesIterator.toVector.init.map(_.trim.split(" ").head).sorted,
      Vector("app.py", "created-later.txt"), stat)
    val (_, names) = helperOutput(Seq("diff", id, "--from", "1", "--", "--name-status"))
    assert(names.contains("A\tcreated-later.txt"), names)
    assert(!names.contains("untracked.txt"), names)
    assertEquals(helper("delete", id).str("reviewId"), id)
    assertEquals(helper("list").arr("reviews"), Vector.empty)
    assertEquals(error("show", id).str("code"), "UNKNOWN_REVIEW")

  test("start deletes the reviews of every worktree not updated for 30 days"):
    val now = Instant.now()
    val other = root.resolve("other")
    gitIn(root, "clone", "-q", repo.toString, other.toString)
    Files.writeString(other.resolve("work.py"), "other work\n")
    plan(step("result" -> Changes))
    val elsewhere = helperIn(other, 0, "start", "codex", "--message-file", message()).str("reviewId")
    val elsewhereDir = Path.of(helperIn(other, 0, "show", elsewhere).str("reviewPath"))
    val kept = start().str("reviewId")
    val expired = start().str("reviewId")
    val locked = start().str("reviewId")
    ageDirectory(elsewhereDir, now.minus(Duration.ofDays(31))) // a worktree that no longer starts reviews
    age(kept, now.minus(Duration.ofDays(29)))
    age(expired, now.minus(Duration.ofDays(30)).minusSeconds(60))
    val lockedDir = age(locked, now.minus(Duration.ofDays(400)))
    val unreadable = "2020-01-01-0000-deadbeef" // its files say nothing, so its id's start minute dates it
    val unreadableDir = Files.createDirectories(lockedDir.getParent.resolve(unreadable))
    Files.writeString(unreadableDir.resolve("start.json"), "not JSON")
    val lock = ReviewLock.tryTake(lockedDir).get // as a command running in another session would hold it
    try
      val current = start()
      assertEquals(current.strings("expiredReviews").sorted, Vector(elsewhere, unreadable, expired).sorted)
      assertEquals(current.arr("expiryFailures"), Vector.empty)
      assertEquals(helper("list").arr("reviews").map(_.asObject.get.str("reviewId")).sorted,
        Vector(kept, locked, current.str("reviewId")).sorted)
      assert(Files.exists(lockedDir))
      assert(!Files.exists(elsewhereDir.getParent.getParent), "the other worktree's directory holds no review")
      assert(!helper("show", current.str("reviewId")).contains("expiredReviews")) // `start` alone names them
    finally lock.close()

  test("start proceeds when an expired review cannot be deleted"):
    val first = start().str("reviewId")
    val second = start().str("reviewId")
    val readOnly = age(first, Instant.parse("2020-01-01T00:00:00Z"))
    val unlockable = age(second, Instant.parse("2020-01-01T00:00:00Z"))
    Files.delete(unlockable.resolve("review.lock"))
    Files.createDirectory(unlockable.resolve("review.lock")) // the lock cannot be opened
    readOnly.resolve("turns").toFile.setWritable(false)
    val started = start(Approved)
    assertEquals(started.str("status"), "APPROVED")
    assertEquals(started.strings("expiredReviews"), Vector.empty)
    assertEquals(started.arr("expiryFailures").map(_.asObject.get).map(row => (row.str("reviewId"),
      row.obj("error").str("code"))).sorted, Vector((first, "STATE_IO_FAILED"), (second, "STATE_IO_FAILED")).sorted)
    readOnly.resolve("turns").toFile.setWritable(true)
    Files.delete(unlockable.resolve("review.lock"))
    val again = start(Approved)
    assert(again.strings("expiredReviews").toSet.subsetOf(Set(first, second)))
    assertEquals(again.arr("expiryFailures"), Vector.empty)
    assertEquals(helper("list").arr("reviews").map(_.asObject.get.str("reviewId")).sorted,
      Vector(started.str("reviewId"), again.str("reviewId")).sorted)

  test("a linked worktree whose main Git directory is read-only goes through a review"):
    val worktree = root.resolve("linked")
    git("worktree", "add", "-q", worktree.toString)
    Files.writeString(worktree.resolve("work.py"), "linked work\n")
    val gitDir = repo.resolve(".git")
    val directories = Files.walk(gitDir).iterator().asScala.filter(Files.isDirectory(_)).toVector
    directories.foreach(_.toFile.setWritable(false))
    try
      plan(step("result" -> Changes), step("result" -> Approved))
      val id = helperIn(worktree, 0, "start", "codex", "--message-file", message()).str("reviewId")
      Files.writeString(worktree.resolve("work.py"), "linked work, fixed\n")
      val approved = helperIn(worktree, 0, "continue", id, "--message-file", message())
      assertEquals(approved.str("status"), "APPROVED")
      assert(helperIn(worktree, 0, "check-approval", id).bool("approvalFresh"))
      val offered = helperIn(worktree, 0, "approvals").arr("approvals").map(_.asObject.get)
      assertEquals(offered.map(row => (row.str("reviewId"), row.strings("coveredPaths"))),
        Vector((id, Vector("work.py"))))
    finally directories.foreach(_.toFile.setWritable(true))

  test("a failed turn's transcript shows the error"):
    plan(step("exit" -> 1.asJson, "stderr" -> "boom".asJson))
    val failed = helperFails("start", "codex", "--message-file", message("## Task\n\nmy request\n"))
    val (_, markdown) = helperOutput(Seq("transcript", failed.str("reviewId")))
    assert(markdown.contains("my request"), markdown)
    assert(markdown.contains("### Error: REVIEWER_FAILED"), markdown)

  test("a git failure in diff is a structured error that names the review"):
    val id = start(Approved).str("reviewId")
    wrapGit("""if [ "$1" = apply ]; then echo 'apply refused' >&2; exit 1; fi""")
    write("app.py", "print('edited')\n")
    val failed = helperFails("diff", id)
    assertEquals((failed.obj("error").str("code"), failed.str("reviewId")), ("GIT_FAILED", id))
    assert(failed.obj("error").str("stderr").contains("apply refused"))

  test("an unborn repository's files are in scope, and its first turn starts from an empty tree"):
    val unborn = Files.createDirectory(root.resolve("unborn"))
    gitIn(unborn, "init", "-q")
    assertEquals(helperIn(unborn, 1, "start", "codex", "--message-file", message()).obj("error").str("code"),
      "NOTHING_TO_REVIEW")
    Files.writeString(unborn.resolve("first.txt"), "first\n")
    gitIn(unborn, "add", "first.txt") // staged, no commit yet
    Files.delete(unborn.resolve("first.txt")) // still in the index, gone from the files
    assertEquals(helperIn(unborn, 1, "start", "codex", "--message-file", message()).obj("error").str("code"),
      "NOTHING_TO_REVIEW")
    Files.writeString(unborn.resolve("first.txt"), "first\n")
    plan(step("result" -> Approved))
    val output = helperIn(unborn, 0, "start", "codex", "--message-file", message())
    assert(output.isNull("currentHead"))
    assert(calls().last.str("prompt").contains("Review every file in the working tree"))
    val restored = root.resolve("restored")
    helperIn(unborn, 0, "restore", output.str("reviewId"), "--turn", "1", restored.toString)
    assertEquals(Files.readString(restored.resolve("first.txt")), "first\n")

  test("a review of nothing is refused before it exists"):
    Files.delete(repo.resolve("work.py"))
    val failure = error("start", "codex", "--message-file", message())
    assertEquals(failure.str("code"), "NOTHING_TO_REVIEW")
    assert(failure.str("message").contains("--base REF"))
    assertEquals(helper("list").arr("reviews"), Vector.empty)
    assertEquals(calls(), Vector.empty)
    assertEquals(error("start", "codex", "--base", "HEAD", "--message-file", message()).str("code"),
      "NOTHING_TO_REVIEW")
    write("app.py", "print('committed work')\n")
    git("commit", "-q", "-am", "work")
    plan(step("result" -> Approved))
    assertEquals(helper("start", "codex", "--base", "main~1", "--message-file", message()).int("turn"), 1)
    write("app.py", "print('hi')\n") // dirty against HEAD, but the edit restores the base's content
    val restoring = error("start", "codex", "--base", "main~1", "--message-file", message())
    assertEquals(restoring.str("code"), "NOTHING_TO_REVIEW")
    assert(!restoring.str("message").contains("--base REF"))
    plan(step("result" -> Approved))
    assertEquals(helper("start", "codex", "--message-file", message()).int("turn"), 1)
    git("checkout", "--", "app.py")
    write("untracked.txt", "new\n")
    plan(step("result" -> Approved))
    assertEquals(helper("start", "codex", "--message-file", message()).int("turn"), 1)
    Files.delete(repo.resolve("untracked.txt"))
    wrapGit("""if [ "$1" = diff ]; then echo 'fatal: diff refused' >&2; exit 128; fi""")
    val refused = error("start", "codex", "--message-file", message())
    assertEquals(refused.str("code"), "GIT_FAILED")
    assert(refused.str("stderr").contains("diff refused"))

  test("a base names the range that codex reviews"):
    write("app.py", "print('committed work')\n")
    git("commit", "-q", "-am", "work")
    plan(step("result" -> Approved))
    val output = helper("start", "codex", "--base", "main~1", "--message-file", message())
    val commit = git("rev-parse", "main~1").trim
    assertEquals(output("base").get, json(s"""{"store": "git", "ref": "main~1", "commit": "$commit"}"""))
    val prompt = calls().head.str("prompt")
    assert(prompt.contains("# Scope"))
    assert(prompt.contains(s"`git diff $commit`"))
    assert(!prompt.contains("`git diff main~1`"))
    assert(prompt.indexOf("# Scope") < prompt.indexOf("# Review request"))
    assert(!prompt.contains("git diff HEAD"))
    assertEquals(error("start", "codex", "--base", "nowhere", "--message-file", message()).str("code"), "BASE_UNKNOWN")
    start()
    assert(calls().last.str("prompt").contains(s"`git diff ${git("rev-parse", "HEAD").trim}` plus untracked files"))

  test("a stale approval says why"):
    write("untracked.txt", "new\n")
    val id = start(Approved).str("reviewId")
    assertEquals(helper("show", id).arr("staleReasons"), Vector.empty)
    write("app.py", "print('edited')\n")
    Files.delete(repo.resolve("untracked.txt"))
    write("added.txt", "added\n")
    assertEquals(error("check-approval", id).arr("staleReasons"), Vector(json(
      """{"reason": "working files changed", "paths": ["added.txt", "app.py", "untracked.txt"]}""")))
    write("app.py", "print('hi')\n")
    Files.delete(repo.resolve("added.txt"))
    write("untracked.txt", "new\n")
    git("add", "-A")
    git("commit", "-q", "-m", "approved content") // a changed HEAD alone is no reason
    assertEquals(helper("show", id).arr("staleReasons"), Vector.empty)
    write("app.py", "print('staged only')\n")
    git("add", "app.py")
    write("app.py", "print('hi')\n")
    assertEquals(helper("show", id).arr("staleReasons"), Vector.empty) // the index is no reason
    git("reset", "-q", "app.py")
    plan(step("exit" -> 1.asJson, "stderr" -> "boom".asJson))
    helperFails("continue", id, "--message-file", message())
    assertEquals(helper("check-approval", id).str("effectiveStatus"), "APPROVED") // a failed turn
    plan(step("exit" -> 1.asJson, "stderr" -> "boom".asJson))
    helperFails("continue", id, "--instructions-file", message("Be strict.\n"), "--message-file", message())
    assertEquals(error("check-approval", id).arr("staleReasons"),
      Vector(json("""{"reason": "the review instructions changed after the approval", "paths": []}""")))
    plan(step("result" -> Approved))
    helper("continue", id, "--message-file", message())
    assertEquals(helper("show", id).arr("staleReasons"), Vector.empty)
    plan(step("exit" -> 1.asJson, "stderr" -> "boom".asJson))
    helperFails("continue", id, "--instructions-file", message("Be strict.\n"), "--message-file", message())
    assertEquals(helper("check-approval", id).str("effectiveStatus"), "APPROVED") // the same text

  test("approvals names the paths that an earlier approval still covers"):
    assertEquals(helper("approvals").arr("approvals"), Vector.empty)
    val id = start(Approved).str("reviewId")
    write("app.py", "print('edited')\n")
    write("new.py", "print('new')\n")
    var listed = helper("approvals")
    assertEquals(listed.strings("scopePaths"), Vector("app.py", "new.py", "work.py"))
    def rows(listing: io.circe.JsonObject) = listing.arr("approvals").map(_.asObject.get)
    assertEquals(rows(listed).map(row => (row.str("reviewId"), row.int("turn"), row.strings("coveredPaths"),
      row.strings("newPaths"), row.bool("approvalFresh"))),
      Vector((id, 1, Vector("work.py"), Vector("app.py", "new.py"), false)))
    assertEquals(helper("approvals", "--base", "HEAD").arr("approvals"), Vector.empty) // the review has no base
    plan(step("result" -> Approved))
    helper("continue", id, "--message-file", message("more work\n"))
    val prompt = calls().last.str("prompt")
    assert(prompt.contains("Since your answer in turn 1, the content of these paths changed: `app.py`, `new.py`. " +
      "Every other path is as you read it then."), prompt)
    assert(prompt.indexOf("# Scope") < prompt.indexOf("# Changes since your last turn"))
    assert(prompt.indexOf("# Changes since your last turn") < prompt.indexOf("# The author's response, turn 2"))
    listed = helper("approvals")
    assertEquals(rows(listed).map(row => (row.int("turn"), row.strings("coveredPaths"), row.strings("newPaths"),
      row.bool("approvalFresh"))), Vector((2, Vector("app.py", "new.py", "work.py"), Vector.empty, true)))
    // A path the reviewer was not told to look at is new, however long its content has been the approved one.
    write(".gitignore", "ignored/\nbuild/\n")
    git("commit", "-q", "-m", "ignore more", "--", ".gitignore")
    git("checkout", "-q", "HEAD~1", "--", ".gitignore")
    listed = helper("approvals")
    assertEquals(rows(listed).map(row => (row.strings("coveredPaths"), row.strings("newPaths"))),
      Vector((Vector("app.py", "new.py", "work.py"), Vector(".gitignore"))))
    plan(step("result" -> Approved))
    helper("continue", id, "--message-file", message("ignore list\n"))
    assert(calls().last.str("prompt").contains("No file's content changed since your answer in turn 2. These paths " +
      "entered the scope since then without a content change, as when HEAD moves under a file: `.gitignore`. Every " +
      "other path is as you read it then."))
    git("add", "-A")
    git("commit", "-q", "-m", "approved work")
    assertEquals((helper("approvals").strings("scopePaths"), helper("approvals").arr("approvals")),
      (Vector.empty, Vector.empty))

  test("approvals offers only reviews with the requested instructions"):
    plan(step("result" -> Approved))
    val id = helper("start", "codex", "--instructions-file", message("Be strict.\n"), "--message-file", message())
      .str("reviewId")
    assertEquals(helper("approvals").arr("approvals"), Vector.empty)
    val same = helper("approvals", "--instructions-file", message("Be strict.")) // without the newline
    assertEquals(same.arr("approvals").map(_.asObject.get.str("reviewId")), Vector(id))
    assertEquals(helper("approvals", "--instructions-file", message("Be lenient.\n")).arr("approvals"), Vector.empty)
    // The review takes new instructions; its approval keeps the old.
    plan(step("exit" -> 1.asJson, "stderr" -> "boom".asJson))
    helperFails("continue", id, "--instructions-file", message("Be lenient.\n"), "--message-file", message())
    for text <- Seq("Be strict.\n", "Be lenient.\n") do
      assertEquals(helper("approvals", "--instructions-file", message(text)).arr("approvals"), Vector.empty, text)

  test("new instructions make the approval stale until codex approves again"):
    val id = start(Approved).str("reviewId")
    helper("check-approval", id)
    plan(step("exit" -> 1.asJson, "stderr" -> "boom".asJson))
    val failed =
      helperFails("continue", id, "--instructions-file", message("Be strict.\n"), "--message-file", message())
    assertEquals(failed.obj("error").str("code"), "REVIEWER_FAILED")
    assertEquals((failed.str("reviewId"), failed.str("status")), (id, "APPROVED"))
    assertEquals(error("check-approval", id).str("effectiveStatus"), "STALE_APPROVAL")

  test("failures name the review and its inspect lines"):
    plan(step("exit" -> 1.asJson, "stderr" -> "boom".asJson))
    val failed = helperFails("start", "codex", "--message-file", message())
    val id = helper("list").arr("reviews").head.asObject.get.str("reviewId")
    assertEquals((failed.str("reviewId"), failed.str("status")), (id, "NEW"))
    assert(failed.strings("inspect").head.startsWith(s"ko-review transcript $id"))
    assert(!helperFails("show", "no-such-review").contains("reviewId"))

  test("a review that this helper cannot continue stays readable and deletable"):
    val id = start().str("reviewId")
    val request = turnDir(id, 1).resolve("request.json")
    def rewrite(path: Path, change: io.circe.Json => io.circe.Json): Unit =
      val text = change(json(Files.readString(path))).noSpaces
      Files.delete(path)
      Files.writeString(path, text)
    rewrite(request, _.set("reviewer" -> "agy".asJson))
    assertEquals(error("continue", id, "--message-file", message()).str("code"), "REVIEWER_UNSUPPORTED")
    assertEquals(helper("show", id).str("reviewer"), "agy")
    rewrite(request, _.set("reviewer" -> "codex".asJson, "formatVersion" -> "0.3.0".asJson, "added" -> 1.asJson))
    val newer = error("continue", id, "--message-file", message())
    assertEquals(newer.str("code"), "REVIEW_FORMAT_NEWER")
    assert(newer.str("message").contains("turns/001/request.json follows format 0.3.0"), newer.str("message"))
    assertEquals(helper("show", id).str("status"), "CHANGES_REQUESTED") // read-only commands work at any version
    rewrite(request, _.set("formatVersion" -> "0.2.9".asJson)) // a newer patch only adds what may be ignored
    plan(step("result" -> Approved))
    assertEquals(helper("continue", id, "--message-file", message()).str("status"), "APPROVED")
    for (text, mode) <- Seq(("not JSON", true), ("{}", true), ("""{"formatVersion": "0.2.0"}""", true),
        (Files.readString(request), false)) do
      val doomed = start().str("reviewId")
      val startFile = Path.of(helper("show", doomed).str("reviewPath")).resolve("start.json")
      Files.delete(startFile)
      Files.writeString(startFile, text)
      startFile.toFile.setReadable(mode)
      assertEquals(error("show", doomed).str("code"), "STATE_IO_FAILED", text)
      val listed = helper("list").arr("reviews").map(_.asObject.get).find(_.str("reviewId") == doomed).get
      assertEquals(listed.str("effectiveStatus"), "STATE_IO_FAILED")
      assertEquals(helper("delete", doomed).str("reviewId"), doomed)
      assert(!Files.exists(startFile))
    for arguments <- Seq(Seq("start", "--message-file", message()), Seq("start", "agy", "--message-file", message())) do
      assertEquals(helperOutput(arguments)._1, 2) // no reviewer, or an unknown one: a usage error

  test("one command computes each scope once"):
    start(Approved)
    start(Approved)
    val diffs = root.resolve("diffs.log")
    wrapGit(s"""if [ "$$1" = diff ]; then echo "$$*" >> '$diffs'; fi""")
    assertEquals(helper("list").arr("reviews").size, 2)
    assertEquals(Files.readAllLines(diffs).size, 1, "one scope per command, not one per review")
    Files.delete(diffs)
    assertEquals(helper("approvals").arr("approvals").size, 2)
    assertEquals(Files.readAllLines(diffs).size, 1)

  test("command IO failures return JSON with the review context"):
    val id = start().str("reviewId")
    val blocked = Files.createDirectory(root.resolve("blocked"))
    blocked.toFile.setWritable(false)
    try
      val failed = helperFails("restore", id, "--turn", "1", blocked.resolve("restored").toString)
      assertEquals(failed.obj("error").str("code"), "HELPER_FAILED")
      assertEquals(failed.str("reviewId"), id)
    finally blocked.toFile.setWritable(true)
    val reviewDir = Path.of(helper("show", id).str("reviewPath"))
    reviewDir.resolve("turns").toFile.setWritable(false)
    try
      val failed = helperFails("delete", id)
      assertEquals(failed.obj("error").str("code"), "HELPER_FAILED")
    finally reviewDir.resolve("turns").toFile.setWritable(true)
