// The project directory as the launcher judges it: identity, the refused directories, and the
// .git / .ko-agent-sandbox mount guards — where a wrong answer either exposes the host or lets a
// session write the policy governing the next one.

package agentsandbox.launcher

import java.nio.file.{Files, Paths}

import HostCommands.Os
import SandboxProject.*

class SandboxProjectTest extends munit.FunSuite:

  private object emptyFixture:
    val dir = Files.createTempDirectory("git-guard-empty-dir")
    val file = Files.createTempFile("git-guard-empty", "file")

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
      projectHash("c:\\src\\app", Os.Windows)
    )
    assertNotEquals(
      projectHash("/home/User/App", Os.Linux),
      projectHash("/home/user/app", Os.Linux)
    )

  test("home and top-level directories are refused on POSIX"):
    val env = Map("HOME" -> "/home/user").get
    assert(isForbiddenProjectDir(Paths.get("/home/user"), Os.Linux, env))
    assert(isForbiddenProjectDir(Paths.get("/"), Os.Linux, env))
    assert(isForbiddenProjectDir(Paths.get("/home"), Os.Linux, env))
    assert(isForbiddenProjectDir(Paths.get("/Users"), Os.Mac, env))
    assert(isForbiddenProjectDir(Paths.get("/root"), Os.Linux, env))
    assert(!isForbiddenProjectDir(Paths.get("/home/user/project"), Os.Linux, env))

  test("the Windows home directories are refused, from any runner"):
    // The comparison is textual, so a POSIX runner exercises it; only the drive-root check below needs a real Windows
    // filesystem.
    val env = Map("USERPROFILE" -> "C:\\Users\\me", "PUBLIC" -> "C:\\Users\\Public").get
    assert(isForbiddenProjectDir(Paths.get("C:\\Users\\me"), Os.Windows, env))
    assert(isForbiddenProjectDir(Paths.get("C:\\Users\\me\\"), Os.Windows, env))
    assert(isForbiddenProjectDir(Paths.get("C:\\Users\\Public"), Os.Windows, env))
    assert(!isForbiddenProjectDir(Paths.get("C:\\Users\\me\\project"), Os.Windows, env))

  test("drive roots are refused on Windows"):
    // Only meaningful where the default filesystem is Windows: Paths.get on POSIX never parses "C:\" into a rooted
    // path.
    assume(System.getProperty("os.name").toLowerCase.contains("win"))
    assert(isForbiddenProjectDir(Paths.get("C:\\"), Os.Windows, _ => None))
    assert(!isForbiddenProjectDir(Paths.get("C:\\src\\app"), Os.Windows, _ => None))

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
          s"--volume=${git.resolve("hooks")}:/workspace/.git/hooks:ro"
        )
      )
    )

  test("missing config and hooks are pinned from the launcher's empty sources, the project untouched"):
    val git = Files.createTempDirectory("git-guard").resolve(".git")
    Files.createDirectory(git)
    assertEquals(
      gitGuardVolumes(git, emptyFixture.file, emptyFixture.dir),
      Right(
        Vector(
          s"--volume=${emptyFixture.file}:/workspace/.git/config:ro",
          s"--volume=${emptyFixture.dir}:/workspace/.git/hooks:ro"
        )
      )
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
      Right(Vector(s"--volume=$git:/workspace/.git:ro"))
    )

  test("an absent .git is pinned over the launcher's empty directory, none created in the project"):
    val git = Files.createTempDirectory("git-guard").resolve(".git")
    assertEquals(
      gitGuardVolumes(git, emptyFixture.file, emptyFixture.dir),
      Right(Vector(s"--volume=${emptyFixture.dir}:/workspace/.git:ro"))
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
    assert(policyGuardVolume(linkedPolicy).isLeft)
    assert(Files.list(target).count() == 0, "wrote through the policy link")

  test("an absent policy directory is created here, never left for podman"):
    val dir = Files.createTempDirectory("policy-guard").resolve(".ko-agent-sandbox")
    assertEquals(
      policyGuardVolume(dir),
      Right(s"--volume=$dir:/workspace/.ko-agent-sandbox:ro")
    )
    assert(Files.isDirectory(dir))
    // The directory it just created passes the next launch unchanged.
    assert(policyGuardVolume(dir).isRight)

  test("a file where the policy directory belongs refuses the launch"):
    val dir = Files.createTempDirectory("policy-guard").resolve(".ko-agent-sandbox")
    Files.createFile(dir)
    assert(policyGuardVolume(dir).isLeft)
    // Refused, not replaced: whatever sits there is the user's to remove.
    assert(Files.isRegularFile(dir))

  test("a symlinked policy directory or egress-hosts refuses the launch"):
    val project = Files.createTempDirectory("policy-guard")
    val target = Files.createDirectory(project.resolve("target"))

    val linked = Files.createSymbolicLink(project.resolve(".ko-agent-sandbox"), target)
    assert(policyGuardVolume(linked).isLeft)

    val dir = Files.createDirectory(project.resolve("real.ko-agent-sandbox"))
    Files.createSymbolicLink(dir.resolve("egress-hosts"), project.resolve("secret"))
    val refused = policyGuardVolume(dir)
    assert(refused.isLeft)
    // The refusal names the symlink itself, not merely the policy directory around it.
    assert(refused.swap.exists(_.contains("egress-hosts")), refused.toString)
