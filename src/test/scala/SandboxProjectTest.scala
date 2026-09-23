// The project directory as the launcher judges it: identity, the refused directories, and the
// .ko-agent-sandbox forms — where a wrong answer either exposes the host or lets a session write
// the configuration governing the next one. What a session may write under .git is the FUSE
// filter's policy, tested in fuse/ko-agent-fs.

package agentsandbox.launcher

import java.nio.file.{Files, Path, Paths}

import HostCommands.Os
import SandboxProject.*

class SandboxProjectTest extends munit.FunSuite:

  private val isWindows = System.getProperty("os.name").toLowerCase.contains("win")

  /** A project's mount path as noGitInstruction receives it: any absolute path, since it only spells it. */
  private val Mount = "/Users/me/src/app"

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

  test("every id projectIdOf generates has the pattern --stats lists and --reset accepts"):
    Vector("my-app_1.0", "my app (2)", "日本語プロジェクト", "a" * 40, ".hidden").foreach: name =>
      val id = projectIdOf(Paths.get("/home/user").resolve(name), Os.Linux)
      assert(isProjectId(id), id)
    Vector("app", "app-", "app-0123456789a", "app-0123456789abc", "/home/me/app", "").foreach: name =>
      assert(!isProjectId(name), name)

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
    assume(!isWindows, "a Windows JVM does not read the test's POSIX paths as absolute")
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
    assume(!isWindows, "a Windows JVM does not read the test's POSIX paths as absolute")
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
    assume(!isWindows, "a Windows JVM does not read the test's POSIX paths as absolute")
    val result = protectedHomes(Os.Linux, Map("HOME" -> "/nonexistent-launcher-home/user"))
    assert(result.warnings.exists(_.contains("real path")))
    assert(isForbiddenProjectDir(Paths.get("/nonexistent-launcher-home/user"), result))
    assert(isForbiddenProjectDir(Paths.get("/nonexistent-launcher-home"), result))

  test("macOS data-volume spellings protect the same boundary as their aliases"):
    assume(!isWindows, "a Windows JVM does not read the test's POSIX paths as absolute")
    val homes = protectedHomes(Os.Mac, Map("HOME" -> "/Users/user"))
    assert(isForbiddenProjectDir(Paths.get("/System/Volumes/Data/Users/user"), homes))
    assert(isForbiddenProjectDir(Paths.get("/System/Volumes/Data/Users"), homes))
    // The container's children too, in both spellings.
    assert(isForbiddenProjectDir(Paths.get("/System/Volumes/Data/Users/someone"), homes))
    assert(!isForbiddenProjectDir(Paths.get("/System/Volumes/Data/Users/user/project"), homes))

    val reversed = protectedHomes(Os.Mac, Map("HOME" -> "/System/Volumes/Data/Users/user"))
    assert(isForbiddenProjectDir(Paths.get("/Users/user"), reversed))

  test("the refusal reason names the rule that fired"):
    assume(!isWindows, "a Windows JVM does not read the test's POSIX paths as absolute")
    val homes = protectedHomes(Os.Linux, Map("HOME" -> "/home/user"))
    assert(forbiddenProjectDirReason(Paths.get("/"), homes).exists(_.contains("filesystem root")))
    assert(forbiddenProjectDirReason(Paths.get("/home/user"), homes).exists(_.contains("home directory")))
    assert(forbiddenProjectDirReason(Paths.get("/work/.config/app"), homes).exists(_.contains("'.config'")))
    assertEquals(forbiddenProjectDirReason(Paths.get("/work/app"), homes), None)
    // The container's own home, at any depth: mounted at its own path, the project would sit among
    // the session's home, the persistent volume and the agents' state.
    assert(forbiddenProjectDirReason(Paths.get("/home/nonroot/app"), homes).exists(_.contains("/home/nonroot")))
    assert(forbiddenProjectDirReason(Paths.get("/home/nonroot/src/deep"), homes).exists(_.contains("/home/nonroot")))
    assertEquals(forbiddenProjectDirReason(Paths.get("/home/nonroot-2/app"), homes), None)

  test("the mount path is the project's own, spelled as the machine has it on Windows"):
    def mount(os: Os, path: String): Either[String, String] = mountPathOf(os, Paths.get(path))
    assertEquals(mount(Os.Windows, """C:\work\ko-agent-sandbox"""), Right("/mnt/c/work/ko-agent-sandbox"))
    assertEquals(mount(Os.Windows, """D:\a b\proj"""), Right("/mnt/d/a b/proj"))
    // A UNC path has no /mnt spelling: refused with the reason and the remedy, never guessed at.
    val unc = mount(Os.Windows, """\\server\share\proj""")
    assert(unc.left.exists(_.contains("fixed drive")), unc.toString)
    // POSIX paths pass through as the runner's Path type spells them — a POSIX host is the only
    // one that produces them for real, and a Windows runner respells them with its own separator.
    assertEquals(mount(Os.Mac, "/Users/me/proj"), Right(Paths.get("/Users/me/proj").toString))
    assertEquals(mount(Os.Linux, "/home/me/proj"), Right(Paths.get("/home/me/proj").toString))

  test("a macOS launch from the data-volume alias is the same project as one from its own spelling"):
    assume(!isWindows, "a Windows JVM does not read the test's POSIX paths as absolute")
    val alias = Paths.get("/System/Volumes/Data/Users/me/src/app")
    assertEquals(canonicalProjectDir(alias, Os.Mac), Paths.get("/Users/me/src/app"))
    assertEquals(canonicalProjectDir(Paths.get("/Users/me/src/app"), Os.Mac), Paths.get("/Users/me/src/app"))
    // The prefix alone is a root, refused later; a name that merely begins like it is a directory.
    assertEquals(canonicalProjectDir(Paths.get("/System/Volumes/Data"), Os.Mac), Paths.get("/System/Volumes/Data"))
    val lookalike = Paths.get("/System/Volumes/DataX/app")
    assertEquals(canonicalProjectDir(lookalike, Os.Mac), lookalike)
    // Only macOS has the firmlink; a Linux directory of that name is itself.
    assertEquals(canonicalProjectDir(alias, Os.Linux), alias)

  test("a dot-prefixed current or ancestor directory is refused"):
    assume(!isWindows, "a Windows JVM does not read the test's POSIX paths as absolute")
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
    // SystemDrive\Users stays protected although the current profile is elsewhere, and so do
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
    assume(!isWindows, "creates a symbolic link and gives the host's own paths to the Linux home rules")
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
    assume(isWindows, "this test requires Windows drive-letter and UNC path semantics")
    val homes = protectedHomes(Os.Windows, Map("USERPROFILE" -> "C:\\Users\\me"))

    assert(isForbiddenProjectDir(Paths.get("C:\\"), homes))
    assert(isForbiddenProjectDir(Paths.get("\\\\server\\share\\"), homes))
    assert(!isForbiddenProjectDir(Paths.get("C:\\src\\app"), homes))

  test("a session without git is reported with the launch that would have it"):
    val root = Files.createTempDirectory("no-git").toRealPath()
    // A home of this test's own, beside the fixtures rather than above them, so that only the
    // cases meant to reach it do.
    val home = Files.createTempDirectory("no-git-home").toRealPath()
    val homes = protectedHomes(Os.Linux, Map("HOME" -> home.toString))
    def noGit(dir: Path, os: Os = Os.Linux): Option[NoGit] = SandboxProject.noGit(dir, homes, os)
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
    // A linked worktree names its gitdir absolutely, under the main worktree's .git. The container
    // spells the project as the host does, so the tree holding both checkouts is a launch with git;
    // on Windows, where it spells drives under /mnt, an absolute pointer leads nowhere, and there
    // is no launch to offer.
    val main = Files.createDirectories(root.resolve("main"))
    val mainGitdir = gitdirAt(main.resolve(".git"))
    val worktreeGitdir = worktreeGitdirAt(mainGitdir.resolve("worktrees/feature"), mainGitdir)
    val linked = Files.createDirectories(root.resolve("feature"))
    Files.writeString(linked.resolve(".git"), s"gitdir: $worktreeGitdir\n")
    assertEquals(noGit(linked), Some(NoGit.Gitdir(worktreeGitdir.toString, worktreeGitdir, Some(root))))
    assertEquals(noGit(linked, Os.Windows), Some(NoGit.Gitdir(worktreeGitdir.toString, worktreeGitdir, None)))
    // --separate-git-dir, the same way.
    val separate = gitdirAt(root.resolve("repo.git"))
    val project = Files.createDirectories(root.resolve("project"))
    Files.writeString(project.resolve(".git"), s"gitdir: $separate\n")
    assertEquals(noGit(project), Some(NoGit.Gitdir(separate.toString, separate, Some(root))))
    assertEquals(noGit(project, Os.Windows), Some(NoGit.Gitdir(separate.toString, separate, None)))
    assert(noGitWarning(noGit(project).get).contains(s"launch from $root"))
    assert(noGitWarning(noGit(project, Os.Windows).get).contains("stay on the host"))
    // An absolute gitdir inside the project is reachable where the container spells the project as
    // the host does, and is a host path the container lacks where it does not: on Windows, whose
    // drive paths the container has under /mnt (this POSIX path has no /mnt spelling at all).
    val absolute = Files.createDirectories(root.resolve("absolute"))
    val ownGitdir = gitdirAt(absolute.resolve("real.git"))
    Files.writeString(absolute.resolve(".git"), s"gitdir: $ownGitdir\n")
    assertEquals(noGit(absolute), None)
    assertEquals(noGit(absolute, Os.Windows), Some(NoGit.Gitdir(ownGitdir.toString, ownGitdir, None)))
    // A `.git` symlink is the same absence when it leads out of the project. A live session never
    // starts on that form (the filter's guard refuses it, guard.rs); a reject session does.
    val symlinked = Files.createDirectories(root.resolve("symlinked"))
    Files.createSymbolicLink(symlinked.resolve(".git"), separate)
    assertEquals(noGit(symlinked), Some(NoGit.Gitdir(separate.toString, separate, Some(root))))
    assertEquals(noGit(symlinked, Os.Windows), Some(NoGit.Gitdir(separate.toString, separate, None)))
    // Launched below the repository root: the host finds .git above, and the container has
    // neither it nor anything else above the project.
    val below = Files.createDirectories(superproject.resolve("src/main"))
    assertEquals(noGit(below), Some(NoGit.Above(superproject, Some(superproject))))
    assert(noGitWarning(noGit(below).get).contains(superproject.toString))
    // Below a submodule checkout, and below a linked worktree: host git discovers a repository
    // whose Git directory is elsewhere, which the launch predicate would never call one. The
    // launch offered is the nearest tree that holds the project and has git of its own.
    assertEquals(
      noGit(Files.createDirectories(submodule.resolve("src"))),
      Some(NoGit.Above(submodule, Some(superproject))),
    )
    val belowLinked = Files.createDirectories(linked.resolve("src"))
    assertEquals(noGit(belowLinked), Some(NoGit.Above(linked, Some(root))))
    assertEquals(noGit(belowLinked, Os.Windows), Some(NoGit.Above(linked, None)))
    // An empty .git directory is no repository: the search passes it as git's does, and reaches the one
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
    // parent's own good `.git` earns it no suggestion — from the nested root, or from below it. The
    // launch offered is the tree holding both the project and what the pointer names, where the
    // container spells it as the host does; on Windows there is none.
    val nested = Files.createDirectories(superproject.resolve("nested"))
    Files.writeString(nested.resolve(".git"), s"gitdir: $separate\n")
    assertEquals(noGit(nested), Some(NoGit.Gitdir(separate.toString, separate, Some(root))))
    assertEquals(noGit(nested, Os.Windows), Some(NoGit.Gitdir(separate.toString, separate, None)))
    val belowNested = Files.createDirectories(nested.resolve("src"))
    assertEquals(noGit(belowNested), Some(NoGit.Above(nested, Some(root))))
    assertEquals(noGit(belowNested, Os.Windows), Some(NoGit.Above(nested, None)))
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
    // A relative gitdir that climbs out and re-enters the project by its host name resolves inside on
    // the host and nowhere in the container, which has nothing above the project — and one level
    // up it climbs nowhere, so the parent is the launch.
    val reentrant = Files.createDirectories(root.resolve("reentrant"))
    val reentered = gitdirAt(reentrant.resolve("real.git"))
    Files.writeString(reentrant.resolve(".git"), "gitdir: ../reentrant/real.git\n")
    assertEquals(noGit(reentrant), Some(NoGit.Gitdir("../reentrant/real.git", reentered, Some(root))))
    // A `.git` symlink to a pointer file in a subdirectory: the OS follows the link to read the
    // file, and the gitdir it names resolves against the directory holding `.git` — the project —
    // not against the pointer's own, which would resolve inside and hide that the container cannot
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
    assert(noGitInstruction(noGit(submodule).get, Mount).contains(s"`$Mount/.git`"))
    assert(noGitInstruction(noGit(below).get, Mount).contains("above the project directory"))
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


  test("the bare scan reads git's config forms and leaves every doubt open"):
    for text <- Seq(
        "[core]\n\tbare = true\n",
        "[core]\n\tbare = \"true\"\n",
        "[core]\n\tbare = true # a comment\n",
        "[core]\n\tbare = yes ; a comment\n",
        "[core] bare = on\n",
        "[core]\n\tBare = 1\n",
        "[core]\n\tbare\n",
        "[core \"sub]section\"] bare = true\n",
        "[core \"a\\\"]b\"] bare = true\n",
        "[core]\n\tbare = true # \\\" a comment\n",
        "\uFEFF[core] bare = true\n",
        "[unused][core] bare = true\n",
      )
    do assertEquals(scanBare(text), Some(true), text)
    for text <- Seq(
        "",
        "[core]\n\tbare = false\n",
        "[core]\n\tbare = \"no\"\n",
        "[core]\n\tbare = off # not true\n",
        "[core]\n\tbare = 0\n",
        "[core]\n\tbare =\n",
        "[core]\n\t# bare = true\n",
        "[core]\n\thooksPath = \"#bare\"\n",
      )
    do assertEquals(scanBare(text), Some(false), text)
    for text <- Seq(
        "[include]\n\tpath = ../other\n",
        "[includeIf \"gitdir:/x/\"]\n\tpath = ../other\n",
        "[includeIf \"gitdir:a]b\"] path = ../other\n",
        "[includeIf \"gitdir:/repos/a\\\"[0-9]\\\"/\"] path = ../other\n",
        "[core]\n\tbare = \"true\\\"\n",
        "[core]\n\t= true\n",
        "[core]\n\tbare bare = true\n",
        "[core\n",
        "[core]\n\tbare = \"true\n",
        "[core]\n\tbare = maybe\n",
        "[core\n\tbare = false\n",
      )
    do assertEquals(scanBare(text), None, text)

  test("a linked worktree names the main worktree whose volume it may share, from its own commondir"):
    val root = Files.createTempDirectory("main-worktree").toRealPath()
    val home = Files.createTempDirectory("main-worktree-home").toRealPath()
    val homes = protectedHomes(Os.Linux, Map("HOME" -> home.toString))
    // The config as `git init` writes it, with `core.bare` stated.
    def gitdirAt(path: Path, bare: Boolean = false): Path =
      Files.createDirectories(path)
      Files.writeString(path.resolve("HEAD"), "ref: refs/heads/main\n")
      Files.writeString(path.resolve("config"), s"[core]\n\trepositoryformatversion = 0\n\tbare = $bare\n")
      path
    // A linked worktree as `git worktree add` lays it out: the pointer absolute, the gitdir one
    // component under the common gitdir's `worktrees`, and the commondir as given.
    def linkedAt(name: String, gitdir: Path, commondir: Option[String]): Path =
      gitdirAt(gitdir)
      commondir.foreach(text => Files.writeString(gitdir.resolve("commondir"), text))
      val linked = Files.createDirectories(root.resolve(name))
      Files.writeString(linked.resolve(".git"), s"gitdir: $gitdir\n")
      linked
    val main = Files.createDirectories(root.resolve("main"))
    val mainGitdir = gitdirAt(main.resolve(".git"))
    def underMain(name: String, commondir: Option[String] = Some("../..\n")): Path =
      linkedAt(name, mainGitdir.resolve("worktrees").resolve(name), commondir)
    val linked = underMain("feature")
    assertEquals(mainWorktreeOf(linked, homes, Os.Linux), Some(main))
    // On Windows too: the volume is named from host paths, which the container's spelling of the
    // project does not enter.
    assertEquals(mainWorktreeOf(linked, homes, Os.Windows), Some(main))
    // The main worktree itself has none; an absolute commondir names the same directory.
    assertEquals(mainWorktreeOf(main, homes, Os.Linux), None)
    assertEquals(mainWorktreeOf(underMain("absolute", Some(s"$mainGitdir\n")), homes, Os.Linux), Some(main))
    // Spelled as a launch from the main worktree spells it: a pointer through a symlink to the
    // main worktree still names the real path, and so the same project id.
    val alias = root.resolve("alias")
    Files.createSymbolicLink(alias, main)
    val viaAlias = Files.createDirectories(root.resolve("via-alias"))
    Files.writeString(viaAlias.resolve(".git"), s"gitdir: ${alias.resolve(".git/worktrees/feature")}\n")
    assertEquals(mainWorktreeOf(viaAlias, homes, Os.Linux), Some(main))
    assertEquals(
      mainWorktreeOf(viaAlias, homes, Os.Linux).map(projectIdOf(_, Os.Linux)),
      Some(projectIdOf(main, Os.Linux)),
    )
    // A commondir that is missing, names nothing, or names a `.git` that does not hold this
    // gitdir: no main worktree can be named from it.
    assertEquals(mainWorktreeOf(underMain("no-commondir", None), homes, Os.Linux), None)
    assertEquals(mainWorktreeOf(underMain("dangling", Some("../../gone\n")), homes, Os.Linux), None)
    // A NUL between path characters: trim would take one at the end away with the newline.
    assertEquals(mainWorktreeOf(underMain("malformed", Some("../" + 0.toChar + "..\n")), homes, Os.Linux), None)
    val other = gitdirAt(root.resolve("other/.git"))
    assertEquals(mainWorktreeOf(underMain("elsewhere", Some(s"$other\n")), homes, Os.Linux), None)
    // A gitdir the common gitdir holds other than under `worktrees` is not a linked worktree's.
    assertEquals(
      mainWorktreeOf(linkedAt("module", mainGitdir.resolve("modules/x"), Some("..\n")), homes, Os.Linux),
      None,
    )
    // A bare repository's worktrees, and those of a main worktree with a separate git dir: the
    // common gitdir is not a `.git` directory, so the main checkout is not named by it.
    val bare = gitdirAt(root.resolve("bare.git"))
    assertEquals(
      mainWorktreeOf(linkedAt("of-bare", bare.resolve("worktrees/of-bare"), Some("../..\n")), homes, Os.Linux),
      None,
    )
    val separate = gitdirAt(root.resolve("separate"))
    val separateMain = Files.createDirectories(root.resolve("separate-main"))
    Files.writeString(separateMain.resolve(".git"), s"gitdir: $separate\n")
    assertEquals(
      mainWorktreeOf(
        linkedAt("of-separate", separate.resolve("worktrees/of-separate"), Some("../..\n")), homes, Os.Linux,
      ),
      None,
    )
    // A bare repository whose directory is named `.git` is what git's `get_main_worktree` would
    // name too, and what `core.bare` then marks bare — in the common config, or in the
    // `config.worktree` git consults from a linked worktree. A config that cannot be read decides
    // nothing, so it names no main worktree either.
    val bareDotGit = gitdirAt(root.resolve("bare-dot/.git"), bare = true)
    assertEquals(
      mainWorktreeOf(
        linkedAt("of-bare-dot", bareDotGit.resolve("worktrees/of-bare-dot"), Some("../..\n")), homes, Os.Linux,
      ),
      None,
    )
    val bareByWorktreeConfig = gitdirAt(root.resolve("bare-wt/.git"))
    Files.writeString(bareByWorktreeConfig.resolve("config.worktree"), "[core]\n\tbare\n")
    assertEquals(
      mainWorktreeOf(
        linkedAt("of-bare-wt", bareByWorktreeConfig.resolve("worktrees/of-bare-wt"), Some("../..\n")), homes, Os.Linux,
      ),
      None,
    )
    val noConfig = gitdirAt(root.resolve("no-config/.git"))
    Files.delete(noConfig.resolve("config"))
    assertEquals(
      mainWorktreeOf(
        linkedAt("of-no-config", noConfig.resolve("worktrees/of-no-config"), Some("../..\n")), homes, Os.Linux,
      ),
      None,
    )
    // A `config.worktree` that exists but exceeds what is read is unknown content, not absence.
    val hugeWorktreeConfig = gitdirAt(root.resolve("huge-wt/.git"))
    Files.write(hugeWorktreeConfig.resolve("config.worktree"), new Array[Byte]((1 << 20) + 1))
    assertEquals(
      mainWorktreeOf(
        linkedAt("of-huge-wt", hugeWorktreeConfig.resolve("worktrees/of-huge-wt"), Some("../..\n")), homes, Os.Linux,
      ),
      None,
    )
    // A main worktree the launcher refuses as a project — the home directory — is no volume
    // owner, whether the pointer spells it directly or through a symlink that hides it.
    val homeGitdir = gitdirAt(home.resolve(".git"))
    assertEquals(
      mainWorktreeOf(linkedAt("of-home", homeGitdir.resolve("worktrees/of-home"), Some("../..\n")), homes, Os.Linux),
      None,
    )
    val homeAlias = root.resolve("home-alias")
    Files.createSymbolicLink(homeAlias, home)
    assertEquals(
      mainWorktreeOf(
        linkedAt("of-home-alias", homeAlias.resolve(".git/worktrees/of-home-alias"), Some("../..\n")), homes, Os.Linux,
      ),
      None,
    )
  test("a linked worktree's main Git directory is bound read-only where the container can follow the pointer"):
    val root = Files.createTempDirectory("gitdir-bind").toRealPath()
    def gitdirAt(path: Path): Path =
      Files.createDirectories(path)
      Files.writeString(path.resolve("HEAD"), "ref: refs/heads/main\n")
      path
    def linkedAt(name: String, pointer: String): Path =
      val linked = Files.createDirectories(root.resolve(name))
      Files.writeString(linked.resolve(".git"), s"gitdir: $pointer\n")
      linked
    val main = Files.createDirectories(root.resolve("main"))
    val mainGitdir = gitdirAt(main.resolve(".git"))
    def worktreeAt(name: String, commondir: String = "../..\n"): Path =
      val gitdir = gitdirAt(mainGitdir.resolve("worktrees").resolve(name))
      Files.writeString(gitdir.resolve("commondir"), commondir)
      gitdir
    val bind = GitdirBind(mainGitdir, mainGitdir.toString)
    // The pointer as `git worktree add` writes it, absolute: followed where the container spells
    // the project as the host does, and not on Windows, whose drives it has under /mnt.
    val absolute = linkedAt("absolute", worktreeAt("absolute").toString)
    assertEquals(linkedGitdirBind(absolute, main, Os.Linux), Some(bind))
    assertEquals(linkedGitdirBind(absolute, main, Os.Mac), Some(bind))
    assertEquals(linkedGitdirBind(absolute, main, Os.Windows), None)
    // A relative pointer, as `--relative-paths` writes it, resolves the same way from either
    // spelling of the project, so it is followed everywhere; this fixture's host spelling has no
    // drive, which is what mountPathOf refuses on Windows.
    worktreeAt("relative")
    val relative = linkedAt("relative", "../main/.git/worktrees/relative")
    assertEquals(linkedGitdirBind(relative, main, Os.Linux), Some(bind))
    assertEquals(linkedGitdirBind(relative, main, Os.Windows), None)
    // Through a symlink alias of the main worktree: the target is the alias's spelling, where the
    // container's git looks, and the source the real directory.
    val alias = root.resolve("alias")
    Files.createSymbolicLink(alias, main)
    worktreeAt("via-alias")
    val viaAlias = linkedAt("via-alias", alias.resolve(".git/worktrees/via-alias").toString)
    assertEquals(
      linkedGitdirBind(viaAlias, main, Os.Linux),
      Some(GitdirBind(mainGitdir, alias.resolve(".git").toString)),
    )
    // The commondir is git's second step, used as written: absolute in the target's spelling it
    // lands on the bind, absolute in the real spelling behind an alias it names a path the
    // container lacks, and relative it climbs within the bind or not at all.
    val absoluteCommon = linkedAt("absolute-common", worktreeAt("absolute-common", s"$mainGitdir\n").toString)
    assertEquals(linkedGitdirBind(absoluteCommon, main, Os.Linux), Some(bind))
    assertEquals(linkedGitdirBind(absoluteCommon, main, Os.Windows), None)
    val realBehindAlias =
      linkedAt("real-behind-alias", alias.resolve(".git/worktrees/real-behind-alias").toString)
    worktreeAt("real-behind-alias", s"$mainGitdir\n")
    assertEquals(linkedGitdirBind(realBehindAlias, main, Os.Linux), None)
    val climbingCommon = linkedAt("climbing-common", worktreeAt("climbing-common", "../../../.git\n").toString)
    assertEquals(linkedGitdirBind(climbingCommon, main, Os.Linux), Some(bind))
    val noCommon = linkedAt("no-common", worktreeAt("no-common").toString)
    Files.delete(mainGitdir.resolve("worktrees/no-common/commondir"))
    assertEquals(linkedGitdirBind(noCommon, main, Os.Linux), None)
    // Not followed: a `.git` symlink, a pointer into another repository's worktrees, a relative
    // pointer climbing past the root, and a common gitdir inside the project.
    val symlinked = Files.createDirectories(root.resolve("symlinked"))
    Files.createSymbolicLink(symlinked.resolve(".git"), worktreeAt("symlinked"))
    assertEquals(linkedGitdirBind(symlinked, main, Os.Linux), None)
    val other = gitdirAt(root.resolve("other/.git"))
    val ofOther = linkedAt("of-other", gitdirAt(other.resolve("worktrees/of-other")).toString)
    assertEquals(linkedGitdirBind(ofOther, main, Os.Linux), None)
    worktreeAt("climbing")
    val climbing =
      linkedAt("climbing", "../" * (root.getNameCount + 2) + s"${root.toString.drop(1)}/main/.git/worktrees/climbing")
    assertEquals(linkedGitdirBind(climbing, main, Os.Linux), None)
    val holding = Files.createDirectories(root.resolve("holding"))
    val inner = Files.createDirectories(holding.resolve("inner"))
    val innerWorktree = gitdirAt(inner.resolve(".git/worktrees/holding"))
    Files.writeString(holding.resolve(".git"), s"gitdir: $innerWorktree\n")
    assertEquals(linkedGitdirBind(holding, inner, Os.Linux), None)
    // The extension `--relative-paths` sets, which the image's git refuses: read from the common
    // config in any section, an unreadable config counting as set.
    Files.writeString(mainGitdir.resolve("config"), "[core]\n\tbare = false\n")
    assert(!setsRelativeWorktrees(mainGitdir))
    Files.writeString(mainGitdir.resolve("config"), "[extensions]\n\trelativeWorktrees = true\n")
    assert(setsRelativeWorktrees(mainGitdir))
    Files.writeString(mainGitdir.resolve("config"), "[other] RelativeWorktrees\n")
    assert(setsRelativeWorktrees(mainGitdir))
    Files.writeString(mainGitdir.resolve("config"), "[core]\n\tbare = \"unclosed\n")
    assert(setsRelativeWorktrees(mainGitdir))
    Files.delete(mainGitdir.resolve("config"))
    assert(setsRelativeWorktrees(mainGitdir))
    // The warning names the directory as every host path is named; the agent's sentence names
    // the path git reads inside and what fails there.
    val warning = readOnlyGitWarning(bind, Os.Linux)
    assert(warning.contains(mainGitdir.toString) && warning.contains("stay on the host"), warning)
    val instruction = readOnlyGitInstruction(bind, Mount)
    assert(instruction.contains(s"`$Mount/.git`") && instruction.contains(s"`$mainGitdir`"), instruction)
    assert(instruction.contains("`commit`") && instruction.contains("`clean`"), instruction)

  test("a refused symlink form leaves no artifact through the link"):
    // bazelbuild/bazel#28515: setup must not write through a pre-seeded symlink, so the refusal comes before any
    // creation.
    val project = Files.createTempDirectory("git-guard-no-write")
    val target = Files.createDirectory(project.resolve("target"))

    val linkedBoundary =
      Files.createSymbolicLink(project.resolve(".ko-agent-sandbox"), target)
    assert(boundaryDirError(linkedBoundary).isDefined)
    assert(FileHelper.directoryEntries(target).isEmpty, "wrote through the boundary link")

  test("an absent boundary directory is empty configuration, never a directory to materialize"):
    val dir = Files.createTempDirectory("boundary-guard").resolve(".ko-agent-sandbox")
    assertEquals(boundaryDirError(dir), None)
    assert(!Files.exists(dir))

  test("a file where the boundary directory belongs refuses the launch"):
    val dir = Files.createTempDirectory("boundary-guard").resolve(".ko-agent-sandbox")
    Files.createFile(dir)
    assert(boundaryDirError(dir).isDefined)
    // Refused, not replaced: whatever is there is the user's to remove.
    assert(Files.isRegularFile(dir))

  test(".ko-agent-sandbox refuses unrecognized configuration entries but accepts editor and OS metadata"):
    val dir = Files.createTempDirectory("boundary-guard").resolve(".ko-agent-sandbox")
    Files.createDirectory(dir)
    Files.createDirectory(dir.resolve("egress"))
    Files.createFile(dir.resolve(".DS_Store"))
    assertEquals(boundaryDirError(dir), None)

    Files.createDirectory(dir.resolve("egres"))
    val refused = boundaryDirError(dir)
    assert(refused.exists(_.contains("egres")), refused.toString)
    Files.delete(dir.resolve("egres"))

    // The other entry is allowed by name, and a symlink of it refused like egress.
    Files.createDirectory(dir.resolve("run-on-host"))
    assertEquals(boundaryDirError(dir), None)
    Files.delete(dir.resolve("run-on-host"))
    Files.createSymbolicLink(dir.resolve("run-on-host"), dir.resolve("egress"))
    val linked = boundaryDirError(dir)
    assert(linked.exists(_.contains("run-on-host")), linked.toString)

  test("doc/egress-proxy.md names the boundary directory's accepted entries"):
    val names = BoundaryDirEntries.toVector.sorted.map(name => s"`$name`")
    val sentence = s"`.ko-agent-sandbox/` accepts ${names.init.mkString(", ")} and ${names.last}."
    val document = Files.readString(Paths.get("doc/egress-proxy.md")).replaceAll("\\s+", " ")
    assert(document.contains(sentence), sentence)

  test("a stray entry's refusal says it may be a newer launcher's file, not only a typo"):
    val dir = Files.createTempDirectory("boundary-guard").resolve(".ko-agent-sandbox")
    Files.createDirectory(dir)
    Files.createDirectory(dir.resolve("future-config"))
    val refused = boundaryDirError(dir)
    assert(refused.exists(_.contains("update the launcher")), refused.toString)

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
