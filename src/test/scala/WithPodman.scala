// What the container-launching suites share: the testWithPodman gate, a scratch project of their
// own, and starting and stopping real sessions.
//
// Split out so each suite reads as its assertions rather than its setup — and so a run's
// resource names come from the launcher's own builders rather than from a second spelling of them,
// which is the drift a test like this is otherwise the first to introduce.

package agentsandbox.launcher

import java.nio.file.{Files, Path, Paths}
import java.util.jar.JarFile
import scala.concurrent.duration.DurationInt
import scala.jdk.CollectionConverters.*
import scala.util.Using

import munit.EventuallyOptions

import HostCommands.*

object WithPodman extends munit.Assertions:

  val jar: Path = Paths.get("target/dist/ko-agent-sandbox.jar").toAbsolutePath

  /** Whether this is a `testWithPodman` run, never detected from the machine: these launch
    * containers, and an ordinary `sbt test` must never start a session. The property is that
    * command's, set for its run alone (build.sbt has why a command rather than an environment
    * variable). */
  def underTestWithPodman: Boolean = sys.props.contains("ko-agent-sandbox.testWithPodman")

  /** Skips outside a `testWithPodman` run; inside one, a missing jar is a broken run, not a machine
    * without one, and fails rather than lets the run pass with every session suite skipped. */
  def requireTestWithPodman(): Unit =
    assume(underTestWithPodman, "run `sbt testWithPodman` to run the container-launching suites")
    assert(Files.isRegularFile(jar), s"testWithPodman needs $jar: run `sbt dist` first")
    requireJarCurrent()
    requireImagesCurrent()
    sweepEarlierRuns()

  /** The distribution jar must contain every class and resource compiled for this test JVM, byte
    * for byte. Otherwise a stale parser or source digest fails only after launch begins, with the
    * reason at the bottom of its log. Check before starting any session; sbt may expose compiled
    * output as a directory or jar, so both are read. */
  private def requireJarCurrent(): Unit =
    val built = Paths.get(AgentSandboxLauncher.getClass.getProtectionDomain.getCodeSource.getLocation.toURI)
    Using.resource(JarFile(jar.toFile)): distJar =>
      def missingOrDifferent(name: String, bytes: => Array[Byte]): Boolean =
        !name.startsWith("META-INF/") && !Option(distJar.getJarEntry(name)).exists: entry =>
          java.util.Arrays.equals(Using.resource(distJar.getInputStream(entry))(_.readAllBytes()), bytes)
      val stale =
        if Files.isDirectory(built) then
          Using.resource(Files.walk(built)): files =>
            files.iterator().asScala.filter(Files.isRegularFile(_)).map(built.relativize).find: path =>
              missingOrDifferent(path.iterator().asScala.mkString("/"), Files.readAllBytes(built.resolve(path)))
            .map(_.toString)
        else
          Using.resource(JarFile(built.toFile)): own =>
            own.entries().asScala.filterNot(_.isDirectory).find: entry =>
              missingOrDifferent(entry.getName, Using.resource(own.getInputStream(entry))(_.readAllBytes()))
            .map(_.getName)
      assert(stale.isEmpty, s"$jar differs from the compiled ${stale.get}: run `sbt dist` first")

  /** The launch's version lock, applied before any launch: the launcher rejects images another jar
    * built, which each test would otherwise wait for, one poll at a time, with the refusal at
    * the bottom of its log. The digests are the jar's, by the check above; an overridden image
    * only warns at launch, and this preflight accepts overrides just as the launcher does. */
  private def requireImagesCurrent(): Unit =
    Seq(
      AgentSandboxLauncher.sandboxImageChoice -> "ko-agent-sandbox",
      AgentSandboxLauncher.proxyImageChoice -> "ko-agent-egress-proxy",
    ).foreach:
      case ((image, overridden), context) =>
        assert(runOk(podman, "image", "exists", image), s"$image is not built; run `java -jar $jar --build` first")
        val label = inspect(image, LauncherImages.BundleLabelTemplate)
        AgentSandboxLauncher.bundleMismatch(image, KoAgentFs.bundledSourceId(context), label).foreach: mismatch =>
          assert(overridden, mismatch)

  /** One scratch project as the registry records it: the id the launcher gives its directory, the
    * JVM that created it — its pid and start time, since a pid alone is reused — and the directory
    * itself, so it is deleted even when no launch ever wrote state for it. */
  case class Scratch(id: String, ownerPid: Long, ownerStart: Long, directory: Path)

  /** A process as an owner: its pid and its start time in epoch milliseconds, 0 where the platform
    * does not report one. */
  private def owner(handle: ProcessHandle): (Long, Long) =
    (handle.pid, handle.info.startInstant.map(_.toEpochMilli).orElse(0L))

  /** Whether the owner recorded in `entry` is still running: the pid is live and, where start
    * times are known, is the same process rather than one that inherited the number. */
  private def ownerAlive(entry: Scratch): Boolean =
    ProcessHandle.of(entry.ownerPid).map[Boolean]: handle =>
      val (_, start) = owner(handle)
      handle.isAlive && (entry.ownerStart == 0L || start == 0L || start == entry.ownerStart)
    .orElse(false)

  /** The scratch projects the suites created and have not discarded: the sweep's evidence that
    * an id is theirs, since a name matching the id pattern is one a real project could carry. Under target/ so
    * it outlives the scratch directory and the run, and goes with `sbt clean`, after which a
    * leftover is the user's `--reset <id>`. */
  private val ScratchRegistry = Paths.get("target/ko-agent-scratch-projects").toAbsolutePath
  private val ScratchRegistryLock = ScratchRegistry.resolveSibling("ko-agent-scratch-projects.lock")

  private def registered(): Vector[Scratch] =
    if !Files.exists(ScratchRegistry) then Vector.empty
    else
      Files.readAllLines(ScratchRegistry).asScala.toVector.flatMap: line =>
        line.split('\t') match
          case Array(id, pid, start, directory) =>
            for p <- pid.toLongOption; s <- start.toLongOption yield Scratch(id, p, s, Paths.get(directory))
          case _ => None

  /** Read, changed and replaced whole under a lock across processes: two runs on one machine must
    * not lose each other's entries, and an interrupted write must not truncate the evidence. */
  private def updateRegistry(change: Vector[Scratch] => Vector[Scratch]): Unit =
    withFileLock(ScratchRegistryLock):
      val lines = change(registered()).map: entry =>
        s"${entry.id}\t${entry.ownerPid}\t${entry.ownerStart}\t${entry.directory}"
      writeReadable(ScratchRegistry, lines.mkString("", "\n", "\n"))

  private def scratchId(project: Path): String = SandboxProject.projectIdOf(project.toRealPath(), currentOs)

  private def forget(id: String): Unit = updateRegistry(_.filterNot(_.id == id))

  /** The registered scratch projects a sweep may delete: the orphans, whose owning JVM is gone, and
    * this JVM's own, whose test runs are sequential — never another live JVM's, whichever of its
    * sessions are running at the moment. `alive` reports whether an entry's recorded owner still runs. */
  def orphanScratch(entries: Vector[Scratch], selfPid: Long, alive: Scratch => Boolean): Vector[Scratch] =
    entries.filter(entry => entry.ownerPid == selfPid || !alive(entry))

  private var swept = false

  /** Scratch projects an earlier run left — the test failed before `discard` removed them, or a
    * launch wrote after its poll ended and after the reset — are discarded now: reset by id
    * where state remains, and the registered directory deleted where it remains. Once per JVM,
    * before this run's first launch; marked done only when it succeeded, so a failed sweep fails
    * every test rather than one. */
  private def sweepEarlierRuns(): Unit =
    if !swept then
      val volumes = listed(podman, "volume", "ls", "--format", "{{.Name}}")
      val known = SandboxStats.projectIds(currentOs, volumes).toSet
      val orphans = orphanScratch(registered(), ProcessHandle.current.pid, ownerAlive)
      val stale = orphans.map(_.id).filter(known)
      if stale.nonEmpty then
        val from = scratchProject()
        val fromId = scratchId(from)
        try
          val (ok, output) = resetIds(from, stale*)
          assert(ok, s"--reset ${stale.mkString(" ")}, sweeping earlier runs' scratch projects, failed:\n$output")
        finally
          deleteRecursively(from)
          forget(fromId)
      orphans.map(_.directory).filter(Files.exists(_)).foreach(deleteRecursively)
      updateRegistry(_.filterNot(entry => orphans.exists(_.id == entry.id)))
      swept = true

  /** Long enough that a session outlives its suite; the tests stop sessions explicitly before this
    * command ends. */
  private val Linger = "900"

  /** A launch does the self-test, the mount, the certificates and the proxy before its container
    * runs; a teardown waits on `podman wait` and retries the network removals. */
  val Patience = 180

  /** One poll a second, for as long as a launch or a teardown can take. */
  given polling: EventuallyOptions = EventuallyOptions(Patience, 1.second)

  /** One live session, the names of everything its run created, and the launcher process that
    * performs its teardown. */
  case class Session(
    container: String, id: String, suffix: String, project: Path, log: Path, launcher: Process,
  ):
    def proxy: String = AgentSandboxLauncher.proxyRunContainer(id, suffix)
    def sandboxNetwork: String = AgentSandboxLauncher.sandboxRunNetwork(id, suffix)
    def egressNetwork: String = AgentSandboxLauncher.egressRunNetwork(id, suffix)
    def output: String = Files.readString(log)

  /** A listing that did not answer is a failure, never an empty set: an absence a suite asserts
    * on, or a sweep acts on, must be podman's answer. */
  private def listed(command: String*): Vector[String] =
    val answer = run(command*)
    assert(answer.ok, s"${command.mkString(" ")} failed: ${answer.err}")
    answer.text.linesIterator.map(_.trim).toVector

  def running(): Vector[String] =
    listed(podman, "ps", "--format", "{{.Names}}").filter(_.startsWith("ko-agent-sandbox-run-")).sorted

  def networks(): Vector[String] = listed(podman, "network", "ls", "--format", "{{.Name}}")

  /** A scratch project, registered by the id the launcher will give it ([[ScratchRegistry]]). */
  def scratchProject(): Path =
    val project = Files.createTempDirectory("ko-agent-scratch").toRealPath()
    val (pid, start) = owner(ProcessHandle.current)
    updateRegistry(_ :+ Scratch(SandboxProject.projectIdOf(project, currentOs), pid, start, project))
    project

  /**
   * The shared sessions state --egress=deny-unless-allowed rather than inheriting it as the
   * default: the suites' assertions are written against the defaults and must not drift
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
    // could select one another suite started concurrently.
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

    // Poll directly rather than through eventually, so a launcher that exits before creating a
    // container reports its refusal immediately.
    var appeared = Vector.empty[String]
    var polls = 0
    while appeared.isEmpty && launcher.isAlive && polls < Patience do
      Thread.sleep(1000)
      appeared = running().diff(before).filter(_.startsWith(prefix))
      polls += 1
    val ended = if launcher.isAlive then "" else s" (the launcher exited with ${launcher.exitValue})"
    assert(appeared.nonEmpty, s"a session never started$ended; its output:\n${Files.readString(log)}")
    val container = appeared.head

    Session(container, id, container.stripPrefix(prefix), project, log, launcher)

  def stop(session: Session): Unit =
    run(podman, "stop", "--time", "2", session.container)
    // On Windows the launcher remains running after the container exits while it removes the run's
    // resources — and it holds session.log open, which on Windows makes the discard's delete a sharing violation.
    // On POSIX the exec'd podman exits with the container and the wait is instant.
    session.launcher.waitFor(Patience, java.util.concurrent.TimeUnit.SECONDS): Unit

  /** `--reset` in a project, as the user runs it after a crash: whether it succeeded, and its own
    * output, all that is worth printing when it did not. */
  def reset(project: Path, extra: (String, String)*): (Boolean, String) = action(project, Vector("--reset"), extra*)

  /** `--reset <id>...`, run from `from`: the projects' own directories are gone. */
  def resetIds(from: Path, ids: String*): (Boolean, String) = action(from, Vector("--reset") ++ ids)

  def resetRunOnHost(project: Path): (Boolean, String) = action(project, Vector("--reset-run-on-host"))

  private def action(project: Path, action: Vector[String], extra: (String, String)*): (Boolean, String) =
    val log = project.resolve(s"${action.head.stripPrefix("--")}.log")
    val builder = ProcessBuilder((Vector("java", "-jar", jar.toString) ++ action)*)
    extra.foreach((name, value) => builder.environment().put(name, value))
    builder.directory(project.toFile)
    builder.redirectErrorStream(true)
    builder.redirectOutput(log.toFile)
    val ok = builder.start().waitFor() == 0
    (ok, Files.readString(log))

  /** The file `--stats` names this project's directory from. */
  def projectRecord(project: Path): Path =
    val id = SandboxProject.projectIdOf(project.toRealPath(), currentOs)
    AgentSandboxLauncher.projectsStateRoot(currentOs).resolve(id)

  /** Each session creates project state — a volume, a CA, a ruleset cache, logs and the mount
    * tree — so a scratch project is reset before it is deleted. A scratch
    * project never builds on the host, so the reset removes its --stats record with the rest. */
  def discard(project: Path): Unit =
    try
      val (ok, output) = reset(project)
      assert(ok, s"--reset failed; its output:\n$output")
      val record = projectRecord(project)
      assert(!Files.exists(record), s"--reset left the project's --stats record $record; its output:\n$output")
      forget(scratchId(project))
    finally deleteRecursively(project)

  /** A command inside a live session, run the way the agent in it would. */
  def exec(session: Session, command: String*): Run =
    run((Vector(podman, "exec", session.container) ++ command)*)

  /** `podman inspect` through a Go template, as one trimmed string. An inspect that did not
    * answer fails here: read as an empty string, it would pass every assertion of
    * absence, the security ones included. */
  def inspect(target: String, template: String): String =
    val answer = run(podman, "inspect", "--format", template, target)
    assert(answer.ok, s"podman inspect $target failed: ${answer.err}")
    answer.text.trim
