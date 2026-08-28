// The project directory as the launcher judges it: identity, the refused directories, and the
// .git / .ko-agent-sandbox mount guards — where a wrong answer either exposes the host or lets a
// session write the policy governing the next one. The .git pin tests cover the opt-out fallback
// (KO_AGENT_SANDBOX_WORKSPACE_GUARD=none); default sessions get the FUSE filter, whose policy is
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
      // A container holds homes, so its children go too; /root is a home itself and its
      // children are ordinary projects.
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

    // Windows falls back to C: for the profiles root, so an environment with neither a home
    // variable nor SystemDrive still refuses somewhere rather than nowhere.
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

    // Git Bash and MSYS2 export a POSIX-style HOME beside a valid USERPROFILE; the bad
    // secondary is dropped with a warning, never the reason a launch fails.
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

  test("a refused symlink shape leaves no artifact through the link"):
    // bazelbuild/bazel#28515: setup must not write through a pre-seeded symlink, so the refusal comes before any
    // creation.
    val project = Files.createTempDirectory("git-guard-no-write")
    val target = Files.createDirectory(project.resolve("target"))

    val linkedGit = Files.createSymbolicLink(project.resolve(".git"), target)
    assert(gitGuardVolumes(linkedGit, emptyFixture.file, emptyFixture.dir).isLeft)
    assert(Files.list(target).count() == 0, "wrote through the .git link")

    val linkedPolicy =
      Files.createSymbolicLink(project.resolve(".ko-agent-sandbox"), target)
    assert(policyDirError(linkedPolicy).isDefined)
    assert(Files.list(target).count() == 0, "wrote through the policy link")

  test("an absent policy directory is empty policy input, never a directory to materialize"):
    val dir = Files.createTempDirectory("policy-guard").resolve(".ko-agent-sandbox")
    assertEquals(policyDirError(dir), None)
    assert(!Files.exists(dir))
    // The pin fallback's mount-back alone creates it, because that mount must exist to guard a
    // writable raw tree.
    assertEquals(policyGuardVolume(dir), s"--volume=$dir:/workspace/.ko-agent-sandbox:ro")
    assert(Files.isDirectory(dir))
    // The directory it just created passes the next launch unchanged.
    assertEquals(policyDirError(dir), None)

  test("a file where the policy directory belongs refuses the launch"):
    val dir = Files.createTempDirectory("policy-guard").resolve(".ko-agent-sandbox")
    Files.createFile(dir)
    assert(policyDirError(dir).isDefined)
    // Refused, not replaced: whatever sits there is the user's to remove.
    assert(Files.isRegularFile(dir))

  test(".ko-agent-sandbox is a closed namespace: a stray entry refuses, metadata does not"):
    // A typo'd egress one level up would otherwise be silently ignored config — the exact
    // failure class the unknown-filename rule inside egress/ exists to kill. Dot-named
    // editor and OS metadata is exempt: no configuration will ever be named that way.
    val dir = Files.createTempDirectory("policy-guard").resolve(".ko-agent-sandbox")
    Files.createDirectory(dir)
    Files.createDirectory(dir.resolve("egress"))
    Files.createFile(dir.resolve(".DS_Store"))
    assertEquals(policyDirError(dir), None)

    Files.createDirectory(dir.resolve("egres"))
    val refused = policyDirError(dir)
    assert(refused.exists(_.contains("egres")), refused.toString)
    Files.delete(dir.resolve("egres"))

    // The second tenant is admitted by name, and a symlink of it refused like egress.
    Files.createDirectory(dir.resolve("agent"))
    assertEquals(policyDirError(dir), None)
    Files.delete(dir.resolve("agent"))
    Files.createSymbolicLink(dir.resolve("agent"), dir.resolve("egress"))
    val linked = policyDirError(dir)
    assert(linked.exists(_.contains("agent")), linked.toString)

  test("agent/ holds one file, with the shapes egress/ refuses refused for the same reasons"):
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

    // A typo'd name configures nothing; an empty file is a forgotten edit, not an opt-out.
    Files.writeString(dir.resolve("AGENTS-CUSTOM.MD"), "x")
    assert(readAgentInstructions(dir).swap.exists(_.contains("not agent instructions")))
    Files.delete(dir.resolve("AGENTS-CUSTOM.MD"))
    Files.writeString(dir.resolve("AGENTS-CUSTOM.md"), "\n")
    assert(readAgentInstructions(dir).swap.exists(_.contains("is empty")))

    Files.delete(dir.resolve("AGENTS-CUSTOM.md"))
    Files.createDirectory(dir.resolve("AGENTS-CUSTOM.md"))
    assert(readAgentInstructions(dir).swap.exists(_.contains("not a regular file")))
    Files.delete(dir.resolve("AGENTS-CUSTOM.md"))
    Files.createSymbolicLink(dir.resolve("AGENTS-CUSTOM.md"), parent.resolve("elsewhere"))
    assert(readAgentInstructions(dir).swap.exists(_.contains("symlink")))

  test("a symlinked policy directory or egress refuses the launch"):
    val project = Files.createTempDirectory("policy-guard")
    val target = Files.createDirectory(project.resolve("target"))

    val linked = Files.createSymbolicLink(project.resolve(".ko-agent-sandbox"), target)
    assert(policyDirError(linked).isDefined)

    val dir = Files.createDirectory(project.resolve("real.ko-agent-sandbox"))
    Files.createSymbolicLink(dir.resolve("egress"), project.resolve("secret"))
    val refused = policyDirError(dir)
    assert(refused.isDefined)
    // The refusal names the symlink itself, not merely the policy directory around it.
    assert(refused.exists(_.contains("egress")), refused.toString)
