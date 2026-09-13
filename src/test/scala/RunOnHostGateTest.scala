package agentsandbox.launcher

import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path}

class RunOnHostGateTest extends munit.FunSuite:

  private val setup = Path.of("src/probe/run-on-host-gate-setup.sh").toAbsolutePath.toString

  private def preflight(root: Path, projects: String*): (Int, String) =
    // The lock file stands in for lsof's observed open descriptors. The real gate function runs
    // unchanged; these cases need neither macOS nor a live broker in the developer's checkout.
    val process = ProcessBuilder(
      (Seq(
        "sh", "-c",
        """. "$1"
          |shift
          |lsof() { cat "$2"; }
          |gate_require_idle "$@"
          |""".stripMargin,
        "gate-test", setup, root.toString,
      ) ++ projects)*,
    ).redirectErrorStream(true).start()
    val output = String(process.getInputStream.readAllBytes(), UTF_8)
    process.waitFor() -> output

  private def broker(root: Path, name: String, project: String, open: Boolean = true): Path =
    val session = Files.createDirectories(root.resolve(name))
    Files.createDirectories(session.resolve("records"))
    Files.writeString(session.resolve("project"), project + "\n")
    Files.writeString(session.resolve("lock"), if open then "1234\n" else "")
    session

  test("preflight refuses an owning broker even with no server or portfile"):
    val project = "/Users/test/my project"
    for name <- Seq("b1", "condemned/b1") do
      val root = Files.createTempDirectory("gate-owner")
      val owner = broker(root, name, project)
      val (status, output) = preflight(root, project)
      assertEquals(status, 1, clue = name)
      assert(output.contains("end that sandbox session"), clue = output)
      assert(output.contains(owner.toString), clue = output)
      assert(output.contains(project), clue = output)
      assert(Files.exists(owner.resolve("lock")), "preflight leaves the owning session intact")

  test("preflight checks enclosing projects and published build directories"):
    val project = "/Users/test/project"
    val cases = Seq(
      ("/Users/test", None, project),
      ("/elsewhere", Some("build-0123456789abcdef"), project),
      ("/elsewhere", Some("build-0123456789abcdef"), project + "/nested"),
    )
    for (ownerProject, record, requested) <- cases do
      val root = Files.createTempDirectory("gate-build")
      val owner = broker(root, "b1", ownerProject)
      record.foreach(name => Files.writeString(owner.resolve("records").resolve(name), project + "\n"))
      assertEquals(preflight(root, "/unrelated", requested)._1, 1, clue = (ownerProject, record, requested))

  test("preflight permits unrelated, ended and unpublished claims"):
    val project = "/Users/test/project"
    val root = Files.createTempDirectory("gate-unowned")
    assertEquals(preflight(root, project), 0 -> "")
    broker(root, "b1", project + "-other")
    broker(root, "b2", project, open = false)
    broker(root, "s1", project)
    val pending = broker(root, "b3", "/elsewhere")
    Files.writeString(pending.resolve("records/build-0123456789abcdef.pending"), project + "\n")
    assertEquals(preflight(root, project), 0 -> "")

  test("preflight names the sandbox to stop instead of suggesting sbt shutdown or a broker kill"):
    val project = "/Users/test/my project"
    val root = Files.createTempDirectory("gate-remedy")
    val owner = broker(root, "b1", project)
    val container = "ko-agent-sandbox-my-project-0123456789ab-abcdef123456"
    Files.writeString(owner.resolve("run"), container + "\n")
    val (status, output) = preflight(root, project)
    assertEquals(status, 1)
    assert(output.contains("pid 1234)"), clue = output)
    assert(output.contains("--run-on-host=sbt,mill"), clue = output)
    assert(output.contains(s"podman stop $container\n"), clue = output)
    assert(output.contains("stops its agent and host builds"), clue = output)
    assert(!output.contains("kill "), clue = output)
    assertEquals(Files.readString(owner.resolve("run")), container + "\n")

  test("an unusable sandbox name does not become a suggested shell command"):
    val root = Files.createTempDirectory("gate-remedy-name")
    val owner = broker(root, "b1", "/project")
    for name <- Seq("", "--all", "name; echo injected", "$(echo injected)", "one\ntwo") do
      Files.writeString(owner.resolve("run"), name + "\n")
      val (status, output) = preflight(root, "/project")
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
          |gate_wait_started 1234 0 test "$started" = yes
          |""".stripMargin,
        "gate-test", setup, alive, started,
      ).redirectErrorStream(true).start()
      val output = String(process.getInputStream.readAllBytes(), UTF_8)
      assertEquals(process.waitFor(), if alive == "yes" && started == "yes" then 0 else 1,
        clue = (alive, started, output))

  test("cleanup leaves live broker claims, unknown directories and reused pids alone"):
    for
      kind <- Seq("sbt", "mill", "gradle", "proxy")
      state <- Seq("owned", "ended", "unrelated", "unknown", "reused")
    do
      val root = Files.createTempDirectory("gate-cleanup")
      broker(root, "b1", if state == "unrelated" then "/other" else "/project",
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
          |  elif [ "$state" != unknown ]; then echo "n/project/$kind"; fi
          |}
          |kill() { echo "SIGNALLED $1"; }
          |gate_end_unclaimed_process "$root" 123
          |""".stripMargin,
        "gate-test", setup, root.toString, state, kind,
      ).redirectErrorStream(true).start()
      val output = String(process.getInputStream.readAllBytes(), UTF_8)
      val status = process.waitFor()
      val permitted = state == "ended" || state == "unrelated"
      assertEquals(output.contains("SIGNALLED 123"), permitted, clue = (kind, state, output))
      assertEquals(status, if permitted then 0 else 1, clue = (kind, state, output))

  test("failed wrapper setup skips cache-dependent sbt rows but retains the failure"):
    val gate = Files.readString(Path.of("src/probe/run-on-host-profile-gate.sh"))
    val start = gate.indexOf("if want sbt; then", gate.indexOf("echo \"positive rows\""))
    val rows = gate.substring(start, gate.indexOf("\nif want mill; then", start))
    val work = Files.createTempDirectory("gate-setup-failure")
    Files.createDirectories(work.resolve("project"))
    Files.writeString(work.resolve("project/build.properties"), "sbt.version=2.0.8\n")
    for failedCommand <- Seq("compile", "test") do
      val process = ProcessBuilder(
        "sh", "-c",
        """work=$1; project=$work; ivy_project=$work/.; quick=0; JAVA_HOME=/jdk; failed_command=$2
          |want() { return 0; }
          |use_profile() { :; }
          |wrapper() {
          |    if [ "$2" = "$project" ] && [ "$3" = "$failed_command" ]; then
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
        "gate-test", work.toString, failedCommand,
      ).redirectErrorStream(true).start()
      val output = String(process.getInputStream.readAllBytes(), UTF_8)
      assertEquals(process.waitFor(), 0, clue = output)
      assert(output.contains(s"FAIL|sbt $failedCommand (wrapper)|refused: setup failed"), clue = output)
      assertEquals(output.linesIterator.count(_.startsWith("SKIP|")), 4, clue = output)
      assert(!output.contains("UNEXPECTED"), clue = output)
