package agentsandbox.launcher

import java.nio.file.Files

import AgentEvents.*

// The events follow claude 2.1.323's and codex 0.169.0's, with the fields that the checks do not read left out.
class AgentEventsTest extends munit.FunSuite:

  private def message(kind: String, parent: String, block: String) =
    s"""{"type":"$kind","parent_tool_use_id":$parent,"message":{"content":[$block]}}"""

  private def toolUse(id: String, name: String, parent: String = "null") =
    message("assistant", parent, s"""{"type":"tool_use","id":"$id","name":"$name"}""")

  private def toolResult(id: String, isError: String, parent: String = "null") =
    message("user", parent, s"""{"type":"tool_result","tool_use_id":"$id","is_error":$isError}""")

  private def result(isError: Boolean = false, denials: String = "[]") =
    s"""{"type":"result","subtype":"success","is_error":$isError,"permission_denials":$denials}"""

  /** A run whose Bash call, subagent and subagent's Bash call each end as given. The Agent's result carries a null
    * is_error, as 2.1.323's does. */
  private def claudeRun(bash: String = "false", agent: String = "null", childBash: String = "false",
      end: String = result()) =
    parseLines(
      Vector(
        toolUse("t1", "Bash"), toolResult("t1", bash),
        toolUse("t2", "Agent"),
        toolUse("t3", "Bash", "\"t2\""), toolResult("t3", childBash, "\"t2\""),
        toolResult("t2", agent),
        end,
      ).mkString("\n"),
    )

  test("a claude run whose Bash call, subagent and the subagent's Bash call all succeeded lacks nothing"):
    assert(claudeSucceeded(claudeRun()))
    assertEquals(claudeLacks(claudeRun()), Vector.empty)

  test("a claude call that failed or was denied counts as missing, though the run's result is a success"):
    assertEquals(claudeLacks(claudeRun(bash = "true")), Vector("a Bash call"))
    assertEquals(claudeLacks(claudeRun(childBash = "true")), Vector("the subagent's Bash call"))
    assertEquals(claudeLacks(claudeRun(agent = "true")), Vector("a subagent", "the subagent's Bash call"))
    val denied = claudeRun(end = result(denials = """[{"tool_name":"Bash"}]"""))
    assert(claudeSucceeded(denied))
    assertEquals(claudeLacks(denied), Vector("no denied call"))
    assert(!claudeSucceeded(claudeRun(end = result(isError = true))))

  private def command(status: String, exitCode: String) =
    s"""{"type":"item.completed","item":{"type":"command_execution","exit_code":$exitCode,"status":"$status"}}"""

  test("a codex turn ran a command only when one completed with exit status 0"):
    val turn = Vector("""{"type":"thread.started","thread_id":"th-1"}""", """{"type":"turn.completed"}""")
    val ran = parseLines((turn :+ command("completed", "0")).mkString("\n"))
    assert(codexCompleted(ran) && codexRanCommand(ran))
    assertEquals(codexThread(ran), Some("th-1"))
    assert(!codexRanCommand(parseLines((turn :+ command("failed", "1")).mkString("\n"))))
    assert(!codexRanCommand(parseLines((turn :+ command("completed", "2")).mkString("\n"))))

  private def rollout(parent: String, answer: Option[String]) =
    (Vector(
      s"""{"type":"session_meta","payload":{"id":"child","parent_thread_id":"$parent"}}""",
      """{"type":"session_meta","payload":{"id":"th-1"}}""",
      """{"type":"event_msg","payload":{"type":"turn_aborted","reason":"interrupted"}}""",
    ) ++ answer.map(text => s"""{"type":"event_msg","payload":{"type":"task_complete","last_agent_message":"$text"}}""")
    ).mkString("\n")

  test("a codex subagent answered only in a rollout that names the parent and completed with every word"):
    val words = Vector("a.txt", "b.txt")
    assert(codexChildAnswered(parseLines(rollout("th-1", Some("a.txt, b.txt"))), "th-1", words))
    assert(!codexChildAnswered(parseLines(rollout("th-2", Some("a.txt, b.txt"))), "th-1", words))
    assert(!codexChildAnswered(parseLines(rollout("th-1", Some("a.txt"))), "th-1", words))
    assert(!codexChildAnswered(parseLines(rollout("th-1", None)), "th-1", words))
    val sessions = Files.createTempDirectory("codex-sessions")
    try
      val day = Files.createDirectories(sessions.resolve("2026/11/14"))
      Files.writeString(day.resolve("rollout-2026-11-14T08-47-13-th-1.jsonl"), rollout("th-0", Some("a.txt, b.txt")))
      assert(!codexChildAnswered(sessions, "th-1", words))
      Files.writeString(day.resolve("rollout-2026-11-14T08-47-18-child.jsonl"), rollout("th-1", Some("a.txt, b.txt")))
      assert(codexChildAnswered(sessions, "th-1", words))
    finally FileHelper.deleteRecursively(sessions)
