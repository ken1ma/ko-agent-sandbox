// The guard=none session binds `/workspace` directly. It mounts `.git/config` and `.git/hooks`
// read-only when `.git` is a directory, the whole `.git` file in a linked worktree, an empty `.git`
// mount when no repository exists, and `.ko-agent-sandbox`. Every default session runs the filter
// instead, so nothing else here can reach this path — the in-session probe skips its git rows
// whenever the filter is on, which is always. The tests cover a directory repository's mounts and
// the other layouts gitGuardVolumes mounts — a pointer-file `.git` mounted read-only in full, and
// the empty whole-directory mount a repository-less project gets.
//
// These are nested read-only mounts inside a writable bind. Docker Sandboxes #388 reported losing
// protection with this layout after a host-side mutation. The tests mutate files from the host and
// check whether the sandbox can write them, independently of whether the mount remains listed.
//  The protection survives mutations that keep the file's inode, but not one that replaces it,
//which  the second test measures along with the delay before the bypass shows; SECURITY.md ("The
//read-only `.git` mounts  under `WORKSPACE_GUARD=none`") has what that costs.
//  That second measurement is per host family, and the test expects each family's own answer: the
//macOS machine's share follows the replacement within seconds, the Windows machine's held against
//it for the whole window (SECURITY.md has both). Linux rootless is the row still missing
//(SECURITY.md, "The read-only `.git` mounts under `WORKSPACE_GUARD=none`"); a failure there is the
//result worth  recording, not a red suite to silence.
//
// Runs only under testWithPodman, like the other container-launching suites (WithPodman has the gate):
//
//     sbt "testWithPodman *WorkspaceGuardOffTest"

package agentsandbox.launcher

import java.nio.file.{Files, Path, StandardCopyOption, StandardOpenOption}

import HostCommands.*
import WithPodman.{*, given}

class WorkspaceGuardOffTest extends munit.FunSuite:

  override val munitTimeout = scala.concurrent.duration.Duration(15, "min")

  private val GuardOff = "KO_AGENT_SANDBOX_WORKSPACE_GUARD" -> "none"

  private val Config = "/workspace/.git/config"
  private val Hooks = "/workspace/.git/hooks"

  /** Whether a path is still a mount point in the sandbox's own namespace. Reported rather than
    * asserted: the mount table keeps its entry even where resolution has stopped honouring it, so
    * it is a symptom to print, never the property to test. */
  private def mounted(session: Session, path: String): Boolean =
    exec(session, "sh", "-c", s"grep -q ' $path ' /proc/self/mountinfo").ok

  /** Asked by writing rather than by reading a mode bit: the mount's flags are what refuses, and
    * only an attempt sees them. */
  private def writable(session: Session, path: String): Boolean =
    exec(session, "sh", "-c", s"printf x >> $path").ok

  private def hookWritable(session: Session): Boolean =
    exec(session, "sh", "-c", s"touch $Hooks/probe").ok

  private def report(session: Session, what: String): Unit =
    println(
      f"[guard-off] $what%-42s config mount=${mounted(session, Config)}%-5s " +
        f"read=${exec(session, "cat", Config).ok}%-5s  " +
        f"hooks mount=${mounted(session, Hooks)}%-5s list=${exec(session, "ls", Hooks).ok}%-5s",
    )

  /** The boundary, and so the only assertion. `what` names the host-side operation that ran. */
  private def assertGitReadOnly(session: Session, what: String): Unit =
    val configWrite = writable(session, Config)
    val hooksWrite = hookWritable(session)
    report(session, what)
    assert(!configWrite, s"SECURITY: after $what the sandbox can write .git/config")
    assert(!hooksWrite, s"SECURITY: after $what the sandbox can write .git/hooks")

  private def repository(): Path =
    val project = scratchProject()
    assert(run("git", "init", "--quiet", project.toString).ok, "could not create a scratch repository")
    project

  private def guardedSession(project: Path): Session =
    val session = launch(project, project.resolve("session.log"), GuardOff)
    assert(
      session.output.contains("workspace: live; guard none"),
      s"this session is not running with the guard off:\n${session.output}",
    )
    session

  test("the read-only .git mounts protect against writes across host-side mutations that keep the file's inode"):
    requireTestWithPodman()

    val project = repository()
    val config = project.resolve(".git").resolve("config")
    val hooks = project.resolve(".git").resolve("hooks")
    var live: Option[Session] = None
    try
      val session = guardedSession(project)
      live = Some(session)

      assertGitReadOnly(session, "the launch")

      // The control: with the filter off, the rest of .git is ordinary writable workspace. Without
      // it a session that had lost /workspace entirely would satisfy every assertion here.
      assert(
        writable(session, "/workspace/.git/HEAD"),
        "all of .git is read-only; cannot distinguish the guard's protection from a lost workspace mount",
      )

      // Edit in place: the inode the mount resolved at launch is the one being written. Anything
      // that replaces it belongs to the second test — including `git config`, which writes through
      // a lock file and renames over.
      Files.writeString(config, "\n# host edit\n", StandardOpenOption.APPEND)
      assertGitReadOnly(session, "an in-place host edit")

      Files.writeString(config, "\n# a second host edit\n", StandardOpenOption.APPEND)
      assertGitReadOnly(session, "a second in-place host edit")

      // Entries below the hooks directory, created and removed while the session holds it: the
      // directory's own inode is untouched.
      Files.writeString(hooks.resolve("post-commit"), "#!/bin/sh\n")
      assertGitReadOnly(session, "a host-created hook")

      Files.delete(hooks.resolve("post-commit"))
      assertGitReadOnly(session, "a host-deleted hook")

      // The bypass in the second test arrives seconds after its mutation, not with it, so a run
      // that only ever looked immediately afterwards would call this mode sound.
      Thread.sleep(30000)
      assertGitReadOnly(session, "30s of no host activity")
    finally
      live.foreach(stop)
      discard(project)

  test("a host-side inode replacement is what stops a read-only .git mount protecting the file"):
    requireTestWithPodman()

    // One replacement, then watch: a check made in the stale instant after it reports read-only
    // protection that no longer applies to the host's replacement file.
    //
    // Asserted rather than left failing: no mount over a path closes this, so a red suite would
    // report the same failure every run, while an assertion turns a podman release that changes it
    // into the one result worth hearing about.
    val project = repository()
    val config = project.resolve(".git").resolve("config")
    val marker = "# written from inside the sandbox"
    var live: Option[Session] = None
    try
      val session = guardedSession(project)
      live = Some(session)
      assert(!writable(session, Config), "the read-only mount does not prevent writes even at launch")

      val replacement = config.resolveSibling("config.replacement")
      Files.writeString(replacement, "[core]\n\trepositoryformatversion = 0\n")
      Files.move(replacement, config, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)

      val started = System.nanoTime()
      val deadline = started + 120L * 1000000000L
      var fellThrough = false
      while !fellThrough && System.nanoTime() < deadline do
        val at = (System.nanoTime() - started) / 1000000000L
        val isMounted = mounted(session, Config)
        val readable = exec(session, "cat", Config).ok
        fellThrough = writable(session, Config)
        println(f"[guard-off] t=$at%3ds  mount=$isMounted%-5s read=$readable%-5s write=$fellThrough")
        if !fellThrough then Thread.sleep(2000)

      // Linux rootless expects the macOS answer until measured.
      if currentOs == Os.Windows then
        assert(!fellThrough, "the mount lost read-only protection on Windows; record the new result (SECURITY.md)")
      else
        assert(fellThrough, "read-only protection survives a host-side inode replacement; SECURITY.md says it does not")
        assert(
          exec(session, "sh", "-c", s"printf '$marker\\n' >> $Config").ok,
          "the mount refuses a second write; the first one reached a different file",
        )
        assert(
          Files.readString(config).contains(marker),
          "the sandbox's write went somewhere other than the host's current .git/config",
        )

        // The hooks mount goes the same way once its own inode is replaced. Only its entries
        // changing leaves it alone, which is what the first test exercises.
        val hooks = project.resolve(".git").resolve("hooks")
        Files.move(hooks, hooks.resolveSibling("hooks.renamed"))
        Files.createDirectories(hooks)
        polling.withMaxRetries(120).eventually:
          assert(
            hookWritable(session),
            ".git/hooks remains protected after its inode is replaced; SECURITY.md says it does not",
          )
    finally
      live.foreach(stop)
      discard(project)

  test("a pointer-file .git is mounted read-only in full, so its redirection cannot be re-aimed"):
    requireTestWithPodman()

    // The second of gitGuardVolumes' layouts: a linked worktree's `.git` is a file naming the real
    // gitdir, and rewriting it re-aims a repository's Git metadata
    // (fuse/ko-agent-fs/doc/git-metadata.md, group 3). Fabricated rather than a real worktree:
    // the guard reads only the layout, never the target.
    val project = scratchProject()
    val pointer = "gitdir: /elsewhere/real/.git"
    Files.writeString(project.resolve(".git"), pointer + "\n")
    var live: Option[Session] = None
    try
      val session = guardedSession(project)
      live = Some(session)

      assertEquals(exec(session, "cat", "/workspace/.git").text, pointer)
      assert(!writable(session, "/workspace/.git"), "SECURITY: the pointer file accepts a write")
      assert(
        !exec(session, "sh", "-c", "rm -f /workspace/.git").ok,
        "SECURITY: the pointer file can be removed",
      )
      assert(
        !exec(session, "sh", "-c", "mv /workspace/.git /workspace/.git-moved").ok,
        "SECURITY: the pointer file can be renamed away",
      )
      // The control, as in the first test: the rest of the workspace stays ordinary and writable.
      assert(
        writable(session, "/workspace/ordinary"),
        "the workspace is not writable; cannot distinguish the guard's protection from a lost workspace mount",
      )

      // An in-place host edit keeps the inode, so the mount still prevents writes; replacing the
      // inode is the second test's measurement, and this layout shares it.
      Files.writeString(project.resolve(".git"), "gitdir: /elsewhere/other/.git\n")
      assert(!writable(session, "/workspace/.git"), "an in-place host edit defeated the read-only protection")
    finally
      live.foreach(stop)
      discard(project)

  test("a project with no repository gets an empty read-only .git the host cannot seed mid-session"):
    requireTestWithPodman()

    // The third layout: no `.git` at all, so the launcher's own empty directory is mounted
    // read-only at that name and a sandbox cannot fabricate a repository for host git to discover.
    // The mount target podman creates in the project is one of SECURITY.md's two enumerated writes
    // ("Silent changes to what you own"); what the session sees behind the name is the launcher's
    // empty directory, whatever the host later puts in the project's own.
    val project = scratchProject()
    var live: Option[Session] = None
    try
      val session = guardedSession(project)
      live = Some(session)

      assert(exec(session, "sh", "-c", "test -d /workspace/.git").ok, "no read-only .git directory is mounted")
      assertEquals(exec(session, "sh", "-c", "ls -A /workspace/.git").text.trim, "")
      assert(
        !exec(session, "sh", "-c", "touch /workspace/.git/config").ok,
        "SECURITY: the sandbox can write into the read-only .git mount",
      )
      assert(
        !exec(session, "sh", "-c", "rmdir /workspace/.git").ok,
        "SECURITY: the sandbox can remove the read-only .git mount",
      )
      assert(
        writable(session, "/workspace/ordinary"),
        "the workspace is not writable; cannot distinguish the guard's protection from a lost workspace mount",
      )

      // A repository the host creates mid-session is created in the project's own .git; the mount's
      // source is the launcher's empty directory, so the session must keep seeing nothing. The
      // wait matches the second test's observation that a bypass arrives seconds late, never
      // with its mutation.
      assert(run("git", "init", "--quiet", project.toString).ok, "host git init failed")
      Files.writeString(project.resolve(".git").resolve("probe"), "host\n")
      Thread.sleep(5000)
      assertEquals(
        exec(session, "sh", "-c", "ls -A /workspace/.git").text.trim, "",
        "a host-created repository became visible behind the empty mount",
      )
      assert(
        !exec(session, "sh", "-c", "touch /workspace/.git/config").ok,
        "SECURITY: the read-only .git mount became writable after a host-side git init",
      )
    finally
      live.foreach(stop)
      discard(project)
