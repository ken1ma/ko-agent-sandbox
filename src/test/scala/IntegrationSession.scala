// The machinery the container-launching suites share: the opt-in gate, a scratch project of their
// own, and starting and stopping real sessions.
//
// Split out so each suite reads as its assertions rather than its plumbing — and so a run's
// resource names come from the launcher's own builders rather than from a second spelling of them,
// which is the drift a test like this is otherwise the first to introduce.

package agentsandbox.launcher

import java.nio.file.{Files, Path, Paths}

import HostCommands.*

object IntegrationSession:

  val jar: Path = Paths.get("target/dist/ko-agent-sandbox.jar").toAbsolutePath

  /** Opt-in rather than venue-detected: these launch containers, and an ordinary `sbt test` must
    * never start a session. */
  val enabled: Boolean = env("KO_AGENT_SANDBOX_INTEGRATION").isDefined && Files.isRegularFile(jar)

  val requirement: String = s"set KO_AGENT_SANDBOX_INTEGRATION, and build $jar first"

  /** Long enough that a session outlives its suite; they are stopped explicitly, never waited out. */
  private val Linger = "900"

  /** A launch does the self-test, the mount, the certificates and the proxy before its container
    * runs; a teardown waits on `podman wait` and retries the network removals. */
  val Patience = 180

  /** One live session, the names of everything its run created, and the launcher process that
    * owns its teardown. */
  case class Session(
    container: String, id: String, suffix: String, project: Path, log: Path, launcher: Process
  ):
    def proxy: String = AgentSandboxLauncher.proxyRunContainer(id, suffix)
    def sandboxNetwork: String = AgentSandboxLauncher.sandboxRunNetwork(id, suffix)
    def egressNetwork: String = AgentSandboxLauncher.egressRunNetwork(id, suffix)
    def output: String = Files.readString(log)

  def running(): Vector[String] =
    run(podman, "ps", "--format", "{{.Names}}").text.linesIterator
      .map(_.trim)
      .filter(_.startsWith("ko-agent-sandbox-run-"))
      .toVector
      .sorted

  def networks(): Vector[String] =
    run(podman, "network", "ls", "--format", "{{.Name}}").text.linesIterator.map(_.trim).toVector

  def scratchProject(): Path = Files.createTempDirectory("ko-agent-integration")

  def eventually[A](seconds: Int)(what: => A)(until: A => Boolean): A =
    val deadline = System.nanoTime() + seconds.toLong * 1000000000L
    var seen = what
    while !until(seen) && System.nanoTime() < deadline do
      Thread.sleep(1000)
      seen = what
    seen

  /**
   * The shared sessions state --egress=deny-unless-allowed rather than inheriting it as the
   * default: the suites' assertions are written against the baseline policy and must not drift
   * with the default. A suite asserting a profile's own behavior launches through launchWith
   * and passes its own options.
   */
  def launch(project: Path, log: Path, extra: (String, String)*): Session =
    launchWith(project, log, Vector("--egress=deny-unless-allowed"), extra*)

  def launchWith(
    project: Path,
    log: Path,
    options: Vector[String],
    extra: (String, String)*
  ): Session =
    // The id the launcher will compute for this directory, derived through its own function rather
    // than parsed back out of whatever container turns up. Waiting for *any* new session instead
    // would adopt one another suite started concurrently — which is exactly what happened when
    // these first ran together, and produced a marker set belonging to two different projects.
    // `toRealPath` because the launcher resolves the project directory before hashing it, and on
    // macOS a temporary directory is reached through a symlink.
    val id = SandboxProject.projectIdOf(project.toRealPath(), currentOs)
    val prefix = AgentSandboxLauncher.sandboxRunContainer(id, "")

    val before = running()
    val builder = ProcessBuilder(
      (Vector("java", "-jar", jar.toString) ++ options ++ Vector("sleep", Linger))*
    )
    builder.environment().put(AgentSandboxLauncher.SessionStartVariable, "immediate")
    extra.foreach((name, value) => builder.environment().put(name, value))
    builder.directory(project.toFile)
    builder.redirectErrorStream(true)
    builder.redirectOutput(log.toFile)
    val launcher = builder.start()

    val appeared =
      eventually(Patience)(running().diff(before).filter(_.startsWith(prefix)))(_.nonEmpty)
    if appeared.isEmpty then
      throw AssertionError(s"a session never started; its output:\n${Files.readString(log)}")

    Session(appeared.head, id, appeared.head.stripPrefix(prefix), project, log, launcher)

  def stop(session: Session): Unit =
    run(podman, "stop", "--time", "2", session.container)
    // The launcher outlives its container by the teardown it stays resident for on Windows — and
    // it holds session.log open, which on Windows makes the discard's delete a sharing violation.
    // On POSIX the exec'd podman exits with the container and the wait is instant.
    session.launcher.waitFor(Patience, java.util.concurrent.TimeUnit.SECONDS): Unit

  /** `--reset` in a project, as the user runs it after a crash: whether it succeeded, and its own
    * output, which is the only useful thing to print when it did not. */
  def reset(project: Path): (Boolean, String) =
    val log = project.resolve("reset.log")
    val builder = ProcessBuilder("java", "-jar", jar.toString, "--reset")
    builder.directory(project.toFile)
    builder.redirectErrorStream(true)
    builder.redirectOutput(log.toFile)
    val ok = builder.start().waitFor() == 0
    (ok, Files.readString(log))

  /** What a session leaves behind is the state every project accumulates — a volume, a CA, a policy
    * cache, logs and the mount tree — so a scratch project is reset before it is deleted. */
  def discard(project: Path): Unit =
    reset(project)
    deleteRecursively(project)

  /** A command inside a live session, run the way the agent in it would. */
  def exec(session: Session, command: String*): Run =
    run((Vector(podman, "exec", session.container) ++ command)*)

  /** `podman inspect` through a Go template, as one trimmed string. */
  def inspect(target: String, template: String): String =
    run(podman, "inspect", "--format", template, target).text.trim
