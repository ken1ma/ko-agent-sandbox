// The project mounted at its own path, against real sessions: the working directory is the
// launch line's path and both guards hold there under every mode, a macOS launch from the
// data-volume alias mounts at the plain path, and a path the image has an entry at is refused
// before anything is created. What a session may write there is the other suites' — this one
// asks where the session is.
//
// Runs only under testWithPodman, like the other container-launching suites (WithPodman has the gate):
//
//     sbt "testWithPodman *MountPathTest"

package agentsandbox.launcher

import java.nio.file.{Files, Path, Paths}

import HostCommands.*
import WithPodman.*

class MountPathTest extends munit.FunSuite:

  override val munitTimeout = scala.concurrent.duration.Duration(15, "min")

  private val Modes = Vector("live", "reject")

  private def repository(): Path =
    val project = scratchProject()
    assert(run("git", "init", "--quiet", project.toString).ok, "could not create a scratch repository")
    project

  private def sessionFrom(from: Path, log: Path, mode: String): Session =
    launchWith(from, log, Vector(s"--write=$mode", "--egress=deny-unless-allowed"))

  /** Where the session is, and that the protection is there too: the launch line names the path,
    * `pwd` answers it, and the two protected writes are refused at it. Appending nothing to
    * `.git/config` asks without changing the repository. */
  private def assertAtOwnPath(session: Session, expected: String, mode: String): Unit =
    assert(session.output.contains(expected), s"$mode: the launch line does not name $expected:\n${session.output}")
    assertEquals(exec(session, "pwd").text.trim, expected, s"$mode: pwd")
    assert(!exec(session, "sh", "-c", ": >> .git/config").ok, s"$mode: .git/config accepted a write")
    assert(
      !exec(session, "sh", "-c", "mkdir -p .ko-agent-sandbox && : > .ko-agent-sandbox/x").ok,
      s"$mode: .ko-agent-sandbox accepted a write",
    )

  test("the session runs at the project's own path, where both guards hold, under every mode"):
    requireTestWithPodman()
    val project = repository()
    try
      for mode <- Modes do
        val session = sessionFrom(project, project.resolve(s"$mode.log"), mode)
        try assertAtOwnPath(session, mountPath(session), mode)
        finally stop(session)
    finally discard(project)

  test("a macOS launch from the data-volume alias mounts at the plain path, under every mode"):
    requireTestWithPodman()
    assume(currentOs == Os.Mac, "the firmlink alias is macOS's")
    val project = repository()
    val alias = Paths.get(SandboxProject.MacDataVolumePrefix + project.toString)
    assume(Files.isDirectory(alias), s"$alias does not reach the project on this machine")
    try
      for mode <- Modes do
        val session = sessionFrom(alias, project.resolve(s"alias-$mode.log"), mode)
        try assertAtOwnPath(session, project.toString, mode)
        finally stop(session)
    finally discard(project)

  /** The state a launch may create before its container, listed by name so an addition shows. */
  private def stateEntries(): Vector[String] =
    Vector(
      AgentSandboxLauncher.rulesetStateRoot(currentOs),
      AgentSandboxLauncher.tlsStateRoot(currentOs),
      AgentSandboxLauncher.logStateRoot(currentOs),
      AgentSandboxLauncher.projectsStateRoot(currentOs),
    ).flatMap(root => FileHelper.directoryEntries(root).map(_.toString))

  test("a path the image has an entry at is refused, naming it, before anything is created"):
    requireTestWithPodman()
    // Judged on additions: another session's teardown may remove its networks meanwhile.
    def refusedFrom(from: Path, entry: String): Unit =
      assume(Files.isDirectory(from), s"$from exists on this host")
      val before = stateEntries() ++ networks()
      val (exit, output) = launchOutcome(from, Files.createTempFile("mount-path-refusal", ".log"))
      assertNotEquals(exit, 0, s"a launch from $from ran:\n$output")
      assert(output.contains(s"has an entry at $entry"), output)
      assertEquals((stateEntries() ++ networks()).diff(before), Vector.empty, "the refusal created state or a network")
    refusedFrom(Paths.get("/usr/local/bin"), "/usr/local/bin")
    // /tmp is the image's on every host, but only a Linux host launches from its own /tmp: the
    // macOS one is /private/tmp, which the image lacks and the machine does not share.
    if currentOs == Os.Linux then refusedFrom(Paths.get("/tmp"), "/tmp")
