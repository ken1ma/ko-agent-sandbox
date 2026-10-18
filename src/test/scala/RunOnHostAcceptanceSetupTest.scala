package agentsandbox.launcher

import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path}

class RunOnHostAcceptanceSetupTest extends munit.FunSuite:

  private val setup = Path.of("src/probe/run-on-host-acceptance-setup.sh").toAbsolutePath.toString

  private def preflight(root: Path, workspaces: String*): (Int, String) =
    // The lock file stands in for lsof's observed open descriptors. The real setup function runs
    // unchanged; these cases need neither macOS nor a live runner in the developer's checkout.
    val process = ProcessBuilder(
      (Seq(
        "sh", "-c",
        """. "$1"
          |shift
          |lsof() { cat "$2"; }
          |acceptance_require_idle "$@"
          |""".stripMargin,
        "acceptance-test", setup, root.toString,
      ) ++ workspaces)*,
    ).redirectErrorStream(true).start()
    val output = String(process.getInputStream.readAllBytes(), UTF_8)
    process.waitFor() -> output

  private def runner(root: Path, name: String, workspace: String, open: Boolean = true): Path =
    val session = Files.createDirectories(root.resolve(name))
    Files.createDirectories(session.resolve("records"))
    Files.writeString(session.resolve(RunOnHostSession.WorkspaceFile), workspace + "\n")
    Files.writeString(session.resolve("lock"), if open then "1234\n" else "")
    session

  test("preflight refuses an owning runner even with no server or portfile"):
    val workspace = "/Users/test/my workspace"
    for name <- Seq("r1", "condemned/r1") do
      val root = Files.createTempDirectory("acceptance-owner")
      val owner = runner(root, name, workspace)
      val (status, output) = preflight(root, workspace)
      assertEquals(status, 1, clue = name)
      assert(output.contains("end that sandbox session"), clue = output)
      assert(output.contains(owner.toString), clue = output)
      assert(output.contains(workspace), clue = output)
      assert(Files.exists(owner.resolve("lock")), "preflight leaves the owning session intact")

  test("preflight checks enclosing workspaces and published build directories"):
    val workspace = "/Users/test/workspace"
    val cases = Seq(
      ("/Users/test", None, workspace),
      ("/elsewhere", Some("build-0123456789abcdef"), workspace),
      ("/elsewhere", Some("build-0123456789abcdef"), workspace + "/nested"),
    )
    for (ownerWorkspace, record, requested) <- cases do
      val root = Files.createTempDirectory("acceptance-build")
      val owner = runner(root, "r1", ownerWorkspace)
      record.foreach(name => Files.writeString(owner.resolve(name), workspace + "\n"))
      assertEquals(preflight(root, "/unrelated", requested)._1, 1, clue = (ownerWorkspace, record, requested))

  test("preflight permits unrelated, ended and unpublished claims"):
    val workspace = "/Users/test/workspace"
    val root = Files.createTempDirectory("acceptance-unowned")
    assertEquals(preflight(root, workspace), 0 -> "")
    runner(root, "r1", workspace + "-other")
    runner(root, "r2", workspace, open = false)
    runner(root, "s1", workspace)
    val pending = runner(root, "r3", "/elsewhere")
    Files.writeString(pending.resolve("build-0123456789abcdef.pending"), workspace + "\n")
    assertEquals(preflight(root, workspace), 0 -> "")

  test("preflight names the sandbox to stop instead of suggesting sbt shutdown or a runner kill"):
    val workspace = "/Users/test/my workspace"
    val root = Files.createTempDirectory("acceptance-remedy")
    val owner = runner(root, "r1", workspace)
    val container = "ko-agent-sandbox-my-workspace-0123456789ab-abcdef123456"
    Files.writeString(owner.resolve("run"), container + "\n")
    val (status, output) = preflight(root, workspace)
    assertEquals(status, 1)
    assert(output.contains("pid 1234)"), clue = output)
    assert(output.contains("--run-on-host=sbt,mill"), clue = output)
    assert(output.contains(s"podman stop $container\n"), clue = output)
    assert(output.contains("stops its agent and host builds"), clue = output)
    assert(!output.contains("kill "), clue = output)
    assertEquals(Files.readString(owner.resolve("run")), container + "\n")

  test("an unusable sandbox name does not become a suggested shell command"):
    val root = Files.createTempDirectory("acceptance-remedy-name")
    val owner = runner(root, "r1", "/workspace")
    for name <- Seq("", "--all", "name; echo injected", "$(echo injected)", "one\ntwo") do
      Files.writeString(owner.resolve("run"), name + "\n")
      val (status, output) = preflight(root, "/workspace")
      assertEquals(status, 1)
      assert(output.contains("end that sandbox session"), clue = output)
      assert(!output.contains("podman stop"), clue = output)

  test("cancellation requires both a running requester and a startup marker"):
    for
      alive <- Seq("yes", "no")
      started <- Seq("yes", "no")
    do
      val process = ProcessBuilder(
        "sh", "-c",
        """. "$1"
          |alive=$2; started=$3
          |kill() { test "$alive" = yes; }
          |acceptance_wait_started 1234 0 test "$started" = yes
          |""".stripMargin,
        "acceptance-test", setup, alive, started,
      ).redirectErrorStream(true).start()
      val output = String(process.getInputStream.readAllBytes(), UTF_8)
      assertEquals(process.waitFor(), if alive == "yes" && started == "yes" then 0 else 1,
        clue = (alive, started, output))

  test("cleanup leaves live runner claims, unknown directories and reused pids alone"):
    for
      kind <- Seq("sbt", "mill", "gradle", "proxy")
      state <- Seq("owned", "ended", "unrelated", "unknown", "reused")
    do
      val root = Files.createTempDirectory("acceptance-cleanup")
      runner(root, "r1", if state == "unrelated" then "/other" else "/workspace",
        open = state != "ended" && state != "reused")
      val process = ProcessBuilder(
        "sh", "-c",
        """. "$1"
          |root=$2; state=$3; kind=$4
          |ps() {
          |  if [ "$state" = reused ] && [ -f "$root/observed" ]; then echo new-start
          |  else echo original-start; fi
          |  : > "$root/observed"
          |}
          |lsof() {
          |  if [ "$1" = -t ]; then cat "$2"
          |  elif [ "$state" != unknown ]; then echo "n/workspace/$kind"; fi
          |}
          |kill() { echo "SIGNALLED $1"; }
          |acceptance_end_unclaimed_process "$root" 123
          |""".stripMargin,
        "acceptance-test", setup, root.toString, state, kind,
      ).redirectErrorStream(true).start()
      val output = String(process.getInputStream.readAllBytes(), UTF_8)
      val status = process.waitFor()
      val permitted = state == "ended" || state == "unrelated"
      assertEquals(output.contains("SIGNALLED 123"), permitted, clue = (kind, state, output))
      assertEquals(status, if permitted then 0 else 1, clue = (kind, state, output))

  test("failed supervisor setup skips cache-dependent sbt rows but retains the failure"):
    val script = Files.readString(Path.of("src/probe/run-on-host-acceptance-test.sh"))
    val start = script.indexOf("if want sbt; then", script.indexOf("echo \"positive rows\""))
    val rows = script.substring(start, script.indexOf("\nif want mill; then", start))
    val work = Files.createTempDirectory("acceptance-setup-failure")
    Files.createDirectories(work.resolve("project"))
    Files.writeString(work.resolve("project/build.properties"), "sbt.version=2.0.8\n")
    for failedCommand <- Seq("compile", "test") do
      val process = ProcessBuilder(
        "sh", "-c",
        """work=$1; workspace=$work; ivy_workspace=$work/.; quick=0; JAVA_HOME=/jdk; failed_command=$2
          |want() { return 0; }
          |use_profile() { :; }
          |supervisor() {
          |    if [ "$2" = "$workspace" ] && [ "$3" = "$failed_command" ]; then
          |        echo 'refused: setup failed'; return 2
          |    fi
          |    echo '[success] built'
          |}
          |run_sbt() {
          |    case "$*" in
          |        *--version*) echo 'sbt runner version: stub' ;;
          |        *) echo "UNEXPECTED direct client: $*" >&2; return 99 ;;
          |    esac
          |}
          |report() { printf '%s|%s|%s\n' "$1" "$2" "${3:-}"; }
          |""".stripMargin + rows,
        "acceptance-test", work.toString, failedCommand,
      ).redirectErrorStream(true).start()
      val output = String(process.getInputStream.readAllBytes(), UTF_8)
      assertEquals(process.waitFor(), 0, clue = output)
      assert(output.contains(s"FAIL|sbt $failedCommand (supervisor)|refused: setup failed"), clue = output)
      assertEquals(output.linesIterator.count(_.startsWith("SKIP|")), 4, clue = output)
      assert(!output.contains("UNEXPECTED"), clue = output)
