package agentsandbox.launcher

import java.nio.file.{Files, Path}

class RunOnHostIdleTest extends munit.FunSuite:

  // The lock file stands in for the open descriptors that lsof observes: it holds the pids that hold it. So these
  // cases need neither macOS nor a live runner in the developer's checkout.
  private def holdersInFile(lock: Path): Vector[Long] =
    Files.readString(lock).linesIterator.flatMap(_.trim.toLongOption).toVector

  private def check(root: Path, workspaces: String*): Either[String, Unit] =
    RunOnHostIdle.requireIdle(root, workspaces.map(Path.of(_)), holdersInFile)

  private def runner(root: Path, name: String, workspace: String, open: Boolean = true): Path =
    val session = Files.createDirectories(root.resolve(name))
    Files.createDirectories(session.resolve("records"))
    Files.writeString(session.resolve(RunOnHostSession.WorkspaceFile), workspace + "\n")
    Files.writeString(session.resolve(RunOnHostSession.LockFile), if open then "1234\n" else "")
    session

  test("the copied session layout names are the launcher's"):
    assertEquals(RunOnHostIdle.supervisorRoot(501), RunOnHostSession.root(501))
    assertEquals(RunOnHostIdle.LockFile, RunOnHostSession.LockFile)
    assertEquals(RunOnHostIdle.WorkspaceFile, RunOnHostSession.WorkspaceFile)
    assertEquals(RunOnHostIdle.RunFile, RunOnHostSession.RunFile)
    assertEquals(RunOnHostIdle.CondemnedDir, RunOnHostSession.CondemnedDir)
    assertEquals(RunOnHostIdle.BuildFilePrefix, RunOnHostSession.BuildFilePrefix)
    assertEquals(RunOnHostIdle.PendingSuffix, RunOnHostSession.PendingSuffix)
    assertEquals(RunOnHostIdle.RunnerPrefix, RunOnHostSession.Kind.Runner.prefix)

  test("an owning runner is refused even with no server or portfile, live or condemned"):
    val workspace = "/Users/test/my workspace"
    for name <- Seq("r1", "condemned/r1") do
      val root = Files.createTempDirectory("idle-owner")
      val owner = runner(root, name, workspace)
      val refusal = check(root, workspace).swap.getOrElse("")
      assert(refusal.contains("end that sandbox session"), clue = refusal)
      assert(refusal.contains(owner.toString), clue = refusal)
      assert(refusal.contains(workspace), clue = refusal)
      assert(Files.exists(owner.resolve("lock")), "the check leaves the owning session intact")

  test("an enclosing workspace and a published build directory are claims"):
    val workspace = "/Users/test/workspace"
    val cases = Seq(
      ("/Users/test", None, workspace),
      ("/elsewhere", Some("build-0123456789abcdef"), workspace),
      ("/elsewhere", Some("build-0123456789abcdef"), workspace + "/nested"),
    )
    for (ownerWorkspace, record, requested) <- cases do
      val root = Files.createTempDirectory("idle-build")
      val owner = runner(root, "r1", ownerWorkspace)
      record.foreach(name => Files.writeString(owner.resolve(name), workspace + "\n"))
      assert(check(root, "/unrelated", requested).isLeft, clue = (ownerWorkspace, record, requested))

  test("unrelated, ended and unpublished claims are no claims"):
    val workspace = "/Users/test/workspace"
    val root = Files.createTempDirectory("idle-unowned")
    assertEquals(check(root, workspace), Right(()))
    runner(root, "r1", workspace + "-other")
    runner(root, "r2", workspace, open = false)
    runner(root, "s1", workspace)
    val pending = runner(root, "r3", "/elsewhere")
    Files.writeString(pending.resolve("build-0123456789abcdef.pending"), workspace + "\n")
    assertEquals(check(root, workspace), Right(()))

  test("the refusal names the sandbox to stop instead of suggesting sbt shutdown or a runner kill"):
    val workspace = "/Users/test/my workspace"
    val root = Files.createTempDirectory("idle-remedy")
    val owner = runner(root, "r1", workspace)
    val container = "ko-agent-sandbox-my-workspace-0123456789ab-abcdef123456"
    Files.writeString(owner.resolve("run"), container + "\n")
    val refusal = check(root, workspace).swap.getOrElse("")
    assert(refusal.contains("pid 1234)"), clue = refusal)
    assert(refusal.contains("--run-on-host=sbt,mill"), clue = refusal)
    assert(refusal.contains(s"podman stop $container\n"), clue = refusal)
    assert(refusal.contains("stops its agent and host builds"), clue = refusal)
    assert(!refusal.contains("kill "), clue = refusal)
    assertEquals(Files.readString(owner.resolve("run")), container + "\n")

  test("an unusable sandbox name does not become a suggested shell command"):
    val root = Files.createTempDirectory("idle-remedy-name")
    val owner = runner(root, "r1", "/workspace")
    for name <- Seq("", "--all", "name; echo injected", "$(echo injected)", "one\ntwo") do
      Files.writeString(owner.resolve("run"), name + "\n")
      val refusal = check(root, "/workspace").swap.getOrElse("")
      assert(refusal.contains("end that sandbox session"), clue = refusal)
      assert(!refusal.contains("podman stop"), clue = refusal)

  test("cleanup leaves live runner claims, unknown directories and reused pids alone"):
    for
      kind <- Seq("sbt", "mill", "gradle", "proxy")
      state <- Seq("owned", "ended", "unrelated", "unknown", "reused")
    do
      val root = Files.createTempDirectory("idle-cleanup")
      runner(root, "r1", if state == "unrelated" then "/other" else "/workspace",
        open = state != "ended" && state != "reused")
      var observations = 0
      var signalled = Vector.empty[Long]
      val reports = Vector.newBuilder[String]
      val ended = RunOnHostIdle.endUnclaimed(
        root, 123, reports += _,
        start = _ =>
          observations += 1
          Some(if state == "reused" && observations > 1 then "new-start" else "original-start"),
        cwd = _ => Option.when(state != "unknown")(Path.of(s"/workspace/$kind")),
        holders = holdersInFile,
        terminate = pid => signalled :+= pid,
      )
      val permitted = state == "ended" || state == "unrelated"
      assertEquals(signalled, if permitted then Vector(123L) else Vector.empty, clue = (kind, state))
      assertEquals(ended, permitted, clue = (kind, state))
      assertEquals(reports.result().nonEmpty, state == "owned" || state == "unknown", clue = (kind, state))
