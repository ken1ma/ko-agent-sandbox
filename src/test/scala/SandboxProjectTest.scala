// The project directory as the launcher judges it: identity, the refused directories, and the
// .git / .ko-agent-sandbox mount guards — where a wrong answer either exposes the host or lets a
// session write the configuration governing the next one. The .git pin tests cover
// KO_AGENT_SANDBOX_WORKSPACE_GUARD=none; default sessions get the FUSE filter, whose policy is
// tested in fuse/ko-agent-fs.

package agentsandbox.launcher

import java.nio.file.{Files, Path, Paths}

import HostCommands.Os
import SandboxProject.*

class SandboxProjectTest extends munit.FunSuite:

  /** Stand-ins for the launcher-owned empty bind sources (emptyMountSources), outside any project. */
  private object emptyFixture:
    val dir = Files.createTempDirectory("git-guard-empty-dir")
    val file = Files.createTempFile("git-guard-empty", "file")

  private val isWindows = System.getProperty("os.name").toLowerCase.contains("win")

  private def protectedHomes(os: Os, values: Map[String, String]): HomeProtection =
    protectedHomeDirectories(os, values.get).fold(message => fail(message), identity)

  /** The launcher asks the guard *why* a directory is refused; these tests mostly ask whether. */
  private def isForbiddenProjectDir(dir: Path, homes: HomeProtection): Boolean =
    forbiddenProjectDirReason(dir, homes).isDefined

  test("slug keeps podman-safe characters and folds the rest"):
    assertEquals(slugOf("my-app_1.0"), "my-app_1.0")
    assertEquals(slugOf("my app (2)"), "my-app--2-")
    assertEquals(slugOf("日本語プロジェクト"), "---------")

  test("slug is truncated to 32 characters"):
    assertEquals(slugOf("a" * 40), "a" * 32)

  test("project hash is stable, hex, and 12 characters"):
    val hash = projectHash("/home/user/project", Os.Linux)
    assertEquals(hash.length, 12)
    assert(hash.matches("[0-9a-f]{12}"))
    assertEquals(hash, projectHash("/home/user/project", Os.Linux))

  test("Windows hashes case-insensitively, POSIX as spelled"):
    assertEquals(
      projectHash("C:\\Src\\App", Os.Windows),
      projectHash("c:\\src\\app", Os.Windows),
    )
    assertNotEquals(
      projectHash("/home/User/App", Os.Linux),
      projectHash("/home/user/app", Os.Linux),
    )

  test("home boundary refuses homes and their ancestors, never the projects inside"):
    assume(!isWindows)
    val homes = protectedHomes(Os.Linux, Map("HOME" -> "/home/user"))

    Seq(
      "/" -> true,
      "/home" -> true,
      "/home/user" -> true,
      // Another account's home, reached by name rather than through HOME.
      "/home/other" -> true,
      "/home/user/project" -> false,
      "/home/user/src/project" -> false,
      "/work/project" -> false,
    ).foreach: (path, expected) =>
      assertEquals(isForbiddenProjectDir(Paths.get(path), homes), expected, path)

  test("well-known home containers are refused on POSIX, wherever HOME points"):
    assume(!isWindows)
    Seq(Os.Linux -> "/srv/homes/user", Os.Mac -> "/srv/homes/user").foreach: (os, home) =>
      val homes = protectedHomes(os, Map("HOME" -> home))
      Seq("/home", "/Users", "/root", "/var/root").foreach: container =>
        assert(isForbiddenProjectDir(Paths.get(container), homes), s"$os $container")
      Seq("/home/someone", "/Users/someone").foreach: otherHome =>
        assert(isForbiddenProjectDir(Paths.get(otherHome), homes), s"$os $otherHome")
      assert(!isForbiddenProjectDir(Paths.get("/root/project"), homes), s"$os /root/project")

  test("no home variable at all degrades to the well-known containers, with a warning"):
    val posix = protectedHomes(Os.Linux, Map.empty)
    assert(posix.warnings.exists(_.contains("HOME is not set")))
    assert(isForbiddenProjectDir(Paths.get("/home"), posix))
    assert(isForbiddenProjectDir(Paths.get("/Users"), posix))
    assert(isForbiddenProjectDir(Paths.get("/home/someone"), posix))
    assert(!isForbiddenProjectDir(Paths.get("/srv/build/app"), posix))

    val windows = protectedHomes(Os.Windows, Map.empty)
    assert(windows.warnings.exists(_.contains("USERPROFILE")))
    assert(windows.paths.exists(_.endsWith("Users")), windows.paths.toString)

  test("a home that does not resolve to a real path is refused by its spelling, with a warning"):
    assume(!isWindows)
    val result = protectedHomes(Os.Linux, Map("HOME" -> "/nonexistent-launcher-home/user"))
    assert(result.warnings.exists(_.contains("real path")))
    assert(isForbiddenProjectDir(Paths.get("/nonexistent-launcher-home/user"), result))
    assert(isForbiddenProjectDir(Paths.get("/nonexistent-launcher-home"), result))

  test("macOS data-volume spellings protect the same boundary as their aliases"):
    assume(!isWindows)
    val homes = protectedHomes(Os.Mac, Map("HOME" -> "/Users/user"))
    assert(isForbiddenProjectDir(Paths.get("/System/Volumes/Data/Users/user"), homes))
    assert(isForbiddenProjectDir(Paths.get("/System/Volumes/Data/Users"), homes))
    // The container's children too, in both spellings.
    assert(isForbiddenProjectDir(Paths.get("/System/Volumes/Data/Users/someone"), homes))
    assert(!isForbiddenProjectDir(Paths.get("/System/Volumes/Data/Users/user/project"), homes))

    val reversed = protectedHomes(Os.Mac, Map("HOME" -> "/System/Volumes/Data/Users/user"))
    assert(isForbiddenProjectDir(Paths.get("/Users/user"), reversed))

  test("the refusal reason names the rule that fired"):
    assume(!isWindows)
    val homes = protectedHomes(Os.Linux, Map("HOME" -> "/home/user"))
    assert(forbiddenProjectDirReason(Paths.get("/"), homes).exists(_.contains("filesystem root")))
    assert(forbiddenProjectDirReason(Paths.get("/home/user"), homes).exists(_.contains("home directory")))
    assert(forbiddenProjectDirReason(Paths.get("/work/.config/app"), homes).exists(_.contains("'.config'")))
    assertEquals(forbiddenProjectDirReason(Paths.get("/work/app"), homes), None)

  test("a dot-prefixed current or ancestor directory is refused"):
    assume(!isWindows)
    val homes = protectedHomes(Os.Linux, Map("HOME" -> "/home/user"))

    Seq("/work/.hidden/project", "/work/src/.project").foreach { path =>
      assert(isForbiddenProjectDir(Paths.get(path), homes), path)
    }

    assert(!isForbiddenProjectDir(Paths.get("/work/src/project"), homes))

  test("an invalid HOME fails closed on POSIX; Windows drops it when another home resolved"):
    assert(protectedHomeDirectories(Os.Linux, Map("HOME" -> "relative/home").get).isLeft)
    assert(protectedHomeDirectories(Os.Linux, Map("HOME" -> "\u0000").get).isLeft)
    assert(
      protectedHomeDirectories(
        Os.Windows,
        Map("USERPROFILE" -> "relative/profile", "HOME" -> "relative/home").get,
      ).isLeft,
    )

    val secondaryBase = Files.createTempDirectory("windows-secondary").toRealPath()
    val secondaryProfile = Files.createDirectories(secondaryBase.resolve("Users").resolve("me"))
    val result = protectedHomes(
      Os.Windows,
      Map("USERPROFILE" -> secondaryProfile.toString, "HOME" -> "relative/home"),
    )
    assert(result.paths.contains(secondaryProfile))
    assert(result.warnings.exists(_.contains("HOME")))
    assert(!result.paths.exists(_.toString.contains("relative")))

  test("Windows homes, their ancestors and the profiles root are refused, from any runner"):
    val base = Files.createTempDirectory("windows-boundary").toRealPath()
    val userProfile = Files.createDirectories(base.resolve("Profiles").resolve("me"))
    val homes = protectedHomes(
      Os.Windows,
      Map("USERPROFILE" -> userProfile.toString, "SystemDrive" -> base.toString),
    )
    assert(isForbiddenProjectDir(userProfile, homes))
    assert(isForbiddenProjectDir(userProfile.getParent, homes))
    // SystemDrive\Users stays protected although the current profile lives elsewhere, and so do
    // the profiles it holds.
    assert(isForbiddenProjectDir(base.resolve("Users"), homes))
    assert(isForbiddenProjectDir(base.resolve("Users").resolve("someone"), homes))
    assert(!isForbiddenProjectDir(userProfile.resolve("src"), homes))

  test("Windows selects USERPROFILE, HOME and PUBLIC"):
    val base = Files.createTempDirectory("windows-protected-homes")
    val userProfile = base.resolve("profiles").resolve("user")
    val home = base.resolve("alternate").resolve("user")
    val public = base.resolve("shared").resolve("Public")
    val homes = protectedHomes(
      Os.Windows,
      Map("USERPROFILE" -> userProfile.toString, "HOME" -> home.toString, "PUBLIC" -> public.toString),
    )

    Seq(userProfile, home, public).foreach: protectedHome =>
      assert(homes.paths.contains(protectedHome), protectedHome.toString)

  test("canonical home aliases protect the same boundary"):
    assume(!isWindows)
    val base = Files.createTempDirectory("canonical-home").toRealPath()
    val realHome = Files.createDirectories(base.resolve("real/users/user"))
    val linkedHome = Files.createSymbolicLink(base.resolve("home"), realHome)
    val homes = protectedHomes(Os.Linux, Map("HOME" -> linkedHome.toString))

    // The real spelling of the home, and its ancestors, are refused even though HOME names the
    // symlink; a project inside the home stays valid.
    assert(isForbiddenProjectDir(realHome, homes))
    assert(isForbiddenProjectDir(realHome.getParent, homes))
    assert(!isForbiddenProjectDir(realHome.resolve("project"), homes))

  test("drive and UNC roots are refused on Windows"):
    assume(isWindows)
    val homes = protectedHomes(Os.Windows, Map("USERPROFILE" -> "C:\\Users\\me"))

    assert(isForbiddenProjectDir(Paths.get("C:\\"), homes))
    assert(isForbiddenProjectDir(Paths.get("\\\\server\\share\\"), homes))
    assert(!isForbiddenProjectDir(Paths.get("C:\\src\\app"), homes))

  test("the git guard pins config and hooks of a real repository"):
    val git = Files.createTempDirectory("git-guard").resolve(".git")
    Files.createDirectory(git)
    Files.createFile(git.resolve("config"))
    Files.createDirectory(git.resolve("hooks"))
    assertEquals(
      gitGuardVolumes(git, emptyFixture.file, emptyFixture.dir),
      Right(
        Vector(
          s"--volume=${git.resolve("config")}:/workspace/.git/config:ro",
          s"--volume=${git.resolve("hooks")}:/workspace/.git/hooks:ro",
        ),
      ),
    )

  test("missing config and hooks are pinned from the launcher's empty sources, the project untouched"):
    val git = Files.createTempDirectory("git-guard").resolve(".git")
    Files.createDirectory(git)
    assertEquals(
      gitGuardVolumes(git, emptyFixture.file, emptyFixture.dir),
      Right(
        Vector(
          s"--volume=${emptyFixture.file}:/workspace/.git/config:ro",
          s"--volume=${emptyFixture.dir}:/workspace/.git/hooks:ro",
        ),
      ),
    )
    // The guard must never write into the user's repository (SECURITY.md, "Silent changes to what
    // you own").
    assert(!Files.exists(git.resolve("config")))
    assert(!Files.exists(git.resolve("hooks")))

  test("a pointer-file .git is pinned whole"):
    val git = Files.createTempDirectory("git-guard").resolve(".git")
    Files.writeString(git, "gitdir: ../elsewhere/.git/worktrees/x\n")
    assertEquals(
      gitGuardVolumes(git, emptyFixture.file, emptyFixture.dir),
      Right(Vector(s"--volume=$git:/workspace/.git:ro")),
    )

  test("an absent .git is pinned over the launcher's empty directory, none created in the project"):
    val git = Files.createTempDirectory("git-guard").resolve(".git")
    assertEquals(
      gitGuardVolumes(git, emptyFixture.file, emptyFixture.dir),
      Right(Vector(s"--volume=${emptyFixture.dir}:/workspace/.git:ro")),
    )
    assert(!Files.exists(git), "the guard fabricated a .git in the project")

  test("a symlinked .git, config or hooks refuses the launch"):
    val project = Files.createTempDirectory("git-guard")
    val target = Files.createDirectory(project.resolve("target"))

    val linkedGit = Files.createSymbolicLink(project.resolve(".git"), target)
    assert(gitGuardVolumes(linkedGit, emptyFixture.file, emptyFixture.dir).isLeft)

    val git = Files.createDirectory(project.resolve("repo.git"))
    Files.createSymbolicLink(git.resolve("config"), project.resolve("secret"))
    Files.createDirectory(git.resolve("hooks"))
    assert(gitGuardVolumes(git, emptyFixture.file, emptyFixture.dir).isLeft)

    val git2 = Files.createDirectory(project.resolve("repo2.git"))
    Files.createFile(git2.resolve("config"))
    Files.createSymbolicLink(git2.resolve("hooks"), target)
    assert(gitGuardVolumes(git2, emptyFixture.file, emptyFixture.dir).isLeft)

  test("a session without git is reported with the launch that would have it"):
    val root = Files.createTempDirectory("no-git").toRealPath()
    // A home of this test's own, beside the fixtures rather than above them, so that only the
    // cases meant to reach it do.
    val home = Files.createTempDirectory("no-git-home").toRealPath()
    val homes = protectedHomes(Os.Linux, Map("HOME" -> home.toString))
    def noGit(dir: Path): Option[NoGit] = SandboxProject.noGit(dir, homes)
    def launchOf(dir: Path): Option[Option[Path]] = noGit(dir).map:
      case NoGit.Gitdir(_, _, launchFrom) => launchFrom
      case NoGit.Above(_, launchFrom) => launchFrom
    // What git's own discovery tests for (is_git_directory): a valid HEAD, and objects and refs
    // under the gitdir itself or under the one its commondir names.
    def gitdirAt(path: Path): Path =
      Files.createDirectories(path.resolve("objects"))
      Files.createDirectories(path.resolve("refs"))
      Files.writeString(path.resolve("HEAD"), "ref: refs/heads/main\n")
      path
    def worktreeGitdirAt(path: Path, common: Path): Path =
      Files.createDirectories(path)
      Files.writeString(path.resolve("commondir"), s"${path.relativize(common)}\n")
      Files.writeString(path.resolve("HEAD"), "ref: refs/heads/feature\n")
      path

    // A submodule checkout: the superproject's .git/modules holds the gitdir.
    val superproject = Files.createDirectories(root.resolve("super"))
    gitdirAt(superproject.resolve(".git"))
    val moduleGitdir = gitdirAt(superproject.resolve(".git/modules/lib"))
    val submodule = Files.createDirectories(superproject.resolve("lib"))
    Files.writeString(submodule.resolve(".git"), "gitdir: ../.git/modules/lib\n")
    assertEquals(
      noGit(submodule),
      Some(NoGit.Gitdir("../.git/modules/lib", moduleGitdir, Some(superproject))),
    )
    // A linked worktree names its gitdir absolutely, under the main worktree's .git — which is
    // another checkout, not a tree holding this one, so there is no launch to offer.
    val main = Files.createDirectories(root.resolve("main"))
    val mainGitdir = gitdirAt(main.resolve(".git"))
    val worktreeGitdir = worktreeGitdirAt(mainGitdir.resolve("worktrees/feature"), mainGitdir)
    val linked = Files.createDirectories(root.resolve("feature"))
    Files.writeString(linked.resolve(".git"), s"gitdir: $worktreeGitdir\n")
    assertEquals(noGit(linked), Some(NoGit.Gitdir(worktreeGitdir.toString, worktreeGitdir, None)))
    // --separate-git-dir: no tree holds the project, so the warning has no launch to offer.
    val separate = gitdirAt(root.resolve("repo.git"))
    val project = Files.createDirectories(root.resolve("project"))
    Files.writeString(project.resolve(".git"), s"gitdir: $separate\n")
    assertEquals(noGit(project), Some(NoGit.Gitdir(separate.toString, separate, None)))
    assert(noGitWarning(noGit(project).get).contains("stay on the host"))
    // An absolute gitdir is a host path even where it lands inside the project, which the
    // container has at /workspace and not where the host keeps it.
    val absolute = Files.createDirectories(root.resolve("absolute"))
    val ownGitdir = gitdirAt(absolute.resolve("real.git"))
    Files.writeString(absolute.resolve(".git"), s"gitdir: $ownGitdir\n")
    assertEquals(noGit(absolute), Some(NoGit.Gitdir(ownGitdir.toString, ownGitdir, None)))
    // A `.git` symlink is the same absence when it leads out of the project: only the mount pins
    // of WORKSPACE_GUARD=none refuse that shape, and the filter serves it as the host wrote it.
    val symlinked = Files.createDirectories(root.resolve("symlinked"))
    Files.createSymbolicLink(symlinked.resolve(".git"), separate)
    assertEquals(noGit(symlinked), Some(NoGit.Gitdir(separate.toString, separate, None)))
    // Launched below the repository root: the host finds .git above, and the container has
    // neither it nor anything else above the project.
    val below = Files.createDirectories(superproject.resolve("src/main"))
    assertEquals(noGit(below), Some(NoGit.Above(superproject, Some(superproject))))
    assert(noGitWarning(noGit(below).get).contains(superproject.toString))
    // Below a submodule checkout, and below a linked worktree: host git discovers a repository
    // whose control directory is elsewhere, which the launch predicate would never call one. The
    // launch offered is the nearest tree that holds the project and has git of its own.
    assertEquals(
      noGit(Files.createDirectories(submodule.resolve("src"))),
      Some(NoGit.Above(submodule, Some(superproject))),
    )
    assertEquals(
      noGit(Files.createDirectories(linked.resolve("src"))),
      Some(NoGit.Above(linked, None)),
    )
    // A hollow .git is no repository: the search passes it as git's does, and reaches the one
    // above, which is also the launch offered.
    val hollow = Files.createDirectories(superproject.resolve("hollow"))
    Files.createDirectories(hollow.resolve(".git"))
    assertEquals(noGit(hollow), Some(NoGit.Above(superproject, Some(superproject))))
    assertEquals(
      noGit(Files.createDirectories(hollow.resolve("deep"))),
      Some(NoGit.Above(superproject, Some(superproject))),
    )
    // Nothing said where the host's own git fails: a `.git` naming a gitdir git rejects — absent,
    // or an unrelated directory — ends git's search inside the superproject, and so ends this one;
    // a pointer that is not a path at all never reaches the filesystem.
    val dangling = Files.createDirectories(superproject.resolve("dangling"))
    Files.writeString(dangling.resolve(".git"), "gitdir: ../gone/.git/modules/x\n")
    assertEquals(noGit(dangling), None)
    val stray = Files.createDirectories(superproject.resolve("stray"))
    Files.createDirectories(superproject.resolve("unrelated"))
    Files.writeString(stray.resolve(".git"), "gitdir: ../unrelated\n")
    assertEquals(noGit(stray), None)
    val unparseable = Files.createDirectories(root.resolve("unparseable"))
    Files.writeString(unparseable.resolve(".git"), "gitdir: ../mod" + 0.toChar + "ule\n")
    assertEquals(noGit(unparseable), None)
    // A `.git` file git does not read as a pointer at all — the spelling is not at its start — is
    // the same silence: git fails there rather than searching above.
    val prefixed = Files.createDirectories(superproject.resolve("prefixed"))
    Files.writeString(prefixed.resolve(".git"), "# note\ngitdir: ../.git/modules/lib\n")
    assertEquals(noGit(prefixed), None)
    // And the same silence from below each of them: git's search ends at the `.git` it rejects,
    // so the superproject above is not the repository it would have used, nor a launch to offer.
    for rejected <- Vector(dangling, stray, prefixed) do
      assertEquals(noGit(Files.createDirectories(rejected.resolve("src"))), None, rejected.toString)
    // A nested repository whose pointer is absolute stays as absolute under its parent, so the
    // parent's own good `.git` earns it no suggestion — from the nested root, or from below it.
    val nested = Files.createDirectories(superproject.resolve("nested"))
    Files.writeString(nested.resolve(".git"), s"gitdir: $separate\n")
    assertEquals(noGit(nested), Some(NoGit.Gitdir(separate.toString, separate, None)))
    assertEquals(noGit(Files.createDirectories(nested.resolve("src"))), Some(NoGit.Above(nested, None)))
    // A parent with no repository of its own is still the launch when the pointer stays inside it.
    val siblings = Files.createDirectories(root.resolve("siblings"))
    val sibling = gitdirAt(siblings.resolve("b/real.git"))
    val pointing = Files.createDirectories(siblings.resolve("a"))
    Files.writeString(pointing.resolve(".git"), "gitdir: ../b/real.git\n")
    assertEquals(noGit(pointing), Some(NoGit.Gitdir("../b/real.git", sibling, Some(siblings))))
    // A launch the launcher would refuse is none: the home directory and its ancestors, the
    // filesystem root, a dot-prefixed directory. A pointer that climbs to one of those and back
    // is reachable from there and nowhere nearer, so from the first two nothing is offered, and
    // past the third the next directory up is.
    val underHome = Files.createDirectories(home.resolve("proj"))
    gitdirAt(underHome.resolve("real.git"))
    Files.writeString(underHome.resolve(".git"), "gitdir: ../proj/real.git\n")
    assertEquals(launchOf(underHome), Some(None))
    val climber = Files.createDirectories(root.resolve("climber"))
    gitdirAt(climber.resolve("real.git"))
    val toRoot = "../" * (root.getNameCount + 1) + root.toString.stripPrefix("/")
    Files.writeString(climber.resolve(".git"), s"gitdir: $toRoot/climber/real.git\n")
    assertEquals(launchOf(climber), Some(None))
    val hidden = Files.createDirectories(root.resolve(".hidden/proj"))
    gitdirAt(hidden.resolve("real.git"))
    Files.writeString(hidden.resolve(".git"), "gitdir: ../proj/real.git\n")
    assertEquals(launchOf(hidden), Some(Some(root)))
    // A `.git` file past git's 1 MiB bound is not read, whatever it begins with.
    val oversized = Files.createDirectories(superproject.resolve("oversized"))
    Files.writeString(oversized.resolve(".git"), "gitdir: " + "x" * (1 << 20))
    assertEquals(noGit(oversized), None)
    // A relative gitdir that climbs out and re-enters the project by its host name lands inside on
    // the host and nowhere in the container, whose base is /workspace — and one level up it climbs
    // nowhere, so the parent is the launch.
    val reentrant = Files.createDirectories(root.resolve("reentrant"))
    val reentered = gitdirAt(reentrant.resolve("real.git"))
    Files.writeString(reentrant.resolve(".git"), "gitdir: ../reentrant/real.git\n")
    assertEquals(noGit(reentrant), Some(NoGit.Gitdir("../reentrant/real.git", reentered, Some(root))))
    // A `.git` symlink to a pointer file in a subdirectory: the OS follows the link to read the
    // file, and the gitdir it names resolves against the directory holding `.git` — the project —
    // not against the pointer's own, which would land inside and hide that the container cannot
    // follow it. From the parent both steps stay inside, so the parent is the launch.
    val chained = Files.createDirectories(root.resolve("chained"))
    val elsewhere = gitdirAt(root.resolve("elsewhere.git"))
    Files.createDirectories(chained.resolve("metadata"))
    Files.writeString(chained.resolve("metadata/pointer"), "gitdir: ../elsewhere.git\n")
    Files.createSymbolicLink(chained.resolve(".git"), Paths.get("metadata/pointer"))
    assertEquals(noGit(chained), Some(NoGit.Gitdir("../elsewhere.git", elsewhere, Some(root))))
    // The warning names the pointer as written, the resolved gitdir and the launch; the agent's
    // sentence names the path git fails on inside.
    val warning = noGitWarning(noGit(submodule).get)
    assert(warning.contains("../.git/modules/lib"), warning)
    assert(warning.contains(moduleGitdir.toString), warning)
    assert(warning.contains(superproject.toString), warning)
    assert(noGitInstruction(noGit(submodule).get).contains("`/workspace/.git`"))
    assert(noGitInstruction(noGit(below).get).contains("above the project directory"))
    // Nothing said where git works: a relative pointer into the project, a symlink to one, a .git
    // directory, and a directory in no repository at all.
    val inside = Files.createDirectories(root.resolve("inside"))
    gitdirAt(inside.resolve("real.git"))
    Files.writeString(inside.resolve(".git"), "gitdir: real.git\n")
    assertEquals(noGit(inside), None)
    val relinked = Files.createDirectories(root.resolve("relinked"))
    gitdirAt(relinked.resolve("real.git"))
    Files.createSymbolicLink(relinked.resolve(".git"), Paths.get("real.git"))
    assertEquals(noGit(relinked), None)
    val plain = Files.createDirectories(root.resolve("plain"))
    gitdirAt(plain.resolve(".git"))
    assertEquals(noGit(plain), None)
    assertEquals(noGit(Files.createDirectories(root.resolve("none"))), None)

  test("a refused symlink form leaves no artifact through the link"):
    // bazelbuild/bazel#28515: setup must not write through a pre-seeded symlink, so the refusal comes before any
    // creation.
    val project = Files.createTempDirectory("git-guard-no-write")
    val target = Files.createDirectory(project.resolve("target"))

    val linkedGit = Files.createSymbolicLink(project.resolve(".git"), target)
    assert(gitGuardVolumes(linkedGit, emptyFixture.file, emptyFixture.dir).isLeft)
    assert(Files.list(target).count() == 0, "wrote through the .git link")

    val linkedBoundary =
      Files.createSymbolicLink(project.resolve(".ko-agent-sandbox"), target)
    assert(boundaryDirError(linkedBoundary).isDefined)
    assert(Files.list(target).count() == 0, "wrote through the boundary link")

  test("an absent boundary directory is empty configuration, never a directory to materialize"):
    val dir = Files.createTempDirectory("boundary-guard").resolve(".ko-agent-sandbox")
    assertEquals(boundaryDirError(dir), None)
    assert(!Files.exists(dir))
    assertEquals(boundaryGuardVolume(dir), s"--volume=$dir:/workspace/.ko-agent-sandbox:ro")
    assert(Files.isDirectory(dir))
    // The directory it just created passes the next launch unchanged.
    assertEquals(boundaryDirError(dir), None)

  test("a file where the boundary directory belongs refuses the launch"):
    val dir = Files.createTempDirectory("boundary-guard").resolve(".ko-agent-sandbox")
    Files.createFile(dir)
    assert(boundaryDirError(dir).isDefined)
    // Refused, not replaced: whatever sits there is the user's to remove.
    assert(Files.isRegularFile(dir))

  test(".ko-agent-sandbox is a closed namespace: a stray entry refuses, metadata does not"):
    val dir = Files.createTempDirectory("boundary-guard").resolve(".ko-agent-sandbox")
    Files.createDirectory(dir)
    Files.createDirectory(dir.resolve("egress"))
    Files.createFile(dir.resolve(".DS_Store"))
    assertEquals(boundaryDirError(dir), None)

    Files.createDirectory(dir.resolve("egres"))
    val refused = boundaryDirError(dir)
    assert(refused.exists(_.contains("egres")), refused.toString)
    Files.delete(dir.resolve("egres"))

    // The other entries are admitted by name, and a symlink of one refused like egress.
    Files.createDirectory(dir.resolve("agent"))
    Files.createDirectory(dir.resolve("host-command"))
    assertEquals(boundaryDirError(dir), None)
    Files.delete(dir.resolve("host-command"))
    Files.createSymbolicLink(dir.resolve("host-command"), dir.resolve("egress"))
    val linkedTenant = boundaryDirError(dir)
    assert(linkedTenant.exists(_.contains("host-command")), linkedTenant.toString)
    Files.delete(dir.resolve("host-command"))
    Files.delete(dir.resolve("agent"))
    Files.createSymbolicLink(dir.resolve("agent"), dir.resolve("egress"))
    val linked = boundaryDirError(dir)
    assert(linked.exists(_.contains("agent")), linked.toString)

  test("a stray entry's refusal says it may be a newer launcher's file, not only a typo"):
    val dir = Files.createTempDirectory("boundary-guard").resolve(".ko-agent-sandbox")
    Files.createDirectory(dir)
    Files.createDirectory(dir.resolve("future-config"))
    val refused = boundaryDirError(dir)
    assert(refused.exists(_.contains("update the launcher")), refused.toString)

  test("agent/ holds one file, with the forms egress/ refuses refused for the same reasons"):
    val parent = Files.createTempDirectory("agent-shapes")
    assertEquals(readAgentInstructions(parent.resolve("agent")), Right(None))

    val asFile = parent.resolve("agent")
    Files.writeString(asFile, "# Priorities\n")
    assert(readAgentInstructions(asFile).swap.exists(_.contains("is a file")))
    Files.delete(asFile)

    val dir = Files.createDirectory(asFile)
    Files.createFile(dir.resolve(".DS_Store"))
    assertEquals(readAgentInstructions(dir), Right(None))

    Files.writeString(dir.resolve("AGENTS-CUSTOM.md"), "# Priorities\n\nBe brief.\n")
    assertEquals(readAgentInstructions(dir), Right(Some("# Priorities\n\nBe brief.\n")))

    // The typo differs by more than case, which macOS and Windows would fold into the real file.
    Files.writeString(dir.resolve("AGENT-CUSTOM.md"), "x")
    assert(readAgentInstructions(dir).swap.exists(_.contains("not agent instructions")))
    Files.delete(dir.resolve("AGENT-CUSTOM.md"))
    Files.writeString(dir.resolve("AGENTS-CUSTOM.md"), "\n")
    assert(readAgentInstructions(dir).swap.exists(_.contains("is empty")))

    Files.delete(dir.resolve("AGENTS-CUSTOM.md"))
    Files.createDirectory(dir.resolve("AGENTS-CUSTOM.md"))
    assert(readAgentInstructions(dir).swap.exists(_.contains("not a regular file")))
    Files.delete(dir.resolve("AGENTS-CUSTOM.md"))
    Files.createSymbolicLink(dir.resolve("AGENTS-CUSTOM.md"), parent.resolve("elsewhere"))
    assert(readAgentInstructions(dir).swap.exists(_.contains("symlink")))

  test("a symlinked boundary directory or egress refuses the launch"):
    val project = Files.createTempDirectory("boundary-guard")
    val target = Files.createDirectory(project.resolve("target"))

    val linked = Files.createSymbolicLink(project.resolve(".ko-agent-sandbox"), target)
    assert(boundaryDirError(linked).isDefined)

    val dir = Files.createDirectory(project.resolve("real.ko-agent-sandbox"))
    Files.createSymbolicLink(dir.resolve("egress"), project.resolve("secret"))
    val refused = boundaryDirError(dir)
    assert(refused.isDefined)
    // The refusal names the symlink itself, not merely the boundary directory around it.
    assert(refused.exists(_.contains("egress")), refused.toString)
