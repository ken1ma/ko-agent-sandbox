// PLAN-SBT-ON-HOST.md Phase 1's exit criterion: supported and unsupported layouts are classified
// correctly. The fixtures are a real macOS host's, not invented ones — the Coursier JDK home
// carries a percent-encoded '+', a literal '+' and a directory named like an archive, and the
// install directory contains a space, which is exactly the shape a quoting or regex bug eats.

package agentsandbox.launcher

import java.nio.file.{Files, Path, Paths}

import BuildSandboxPolicy.*
import HostCommands.Os

class BuildSandboxPolicyTest extends munit.FunSuite:

  private val home = "/Users/kenichi"
  private val project = Paths.get(s"$home/ko-agent-sandbox")

  private val jdkHome = Paths.get(
    s"$home/Library/Caches/Coursier/arc/https/github.com/adoptium/temurin25-binaries/releases/" +
      "download/jdk-25.0.4%252B7/OpenJDK25U-jdk_aarch64_mac_hotspot_25.0.4_7.tar.gz/" +
      "jdk-25.0.4+7/Contents/Home",
  )
  private val coursierCache = Paths.get(s"$home/Library/Caches/Coursier")
  private val installDir = Paths.get(s"$home/Library/Application Support/Coursier/bin")

  private def env(pairs: (String, String)*): String => Option[String] =
    val map = pairs.toMap
    name => map.get(name)

  /** Canonicalization for paths that do not exist on the test host: identity for the ones the
    * fixture declares real, None otherwise, so "does not exist" stays a distinct outcome. */
  private def exists(paths: Path*): Path => Option[Path] =
    val set = paths.map(_.normalize()).toSet
    path => Option.when(set.contains(path.normalize()))(path.normalize())

  // --------------------------------------------------------------------------
  // Cache root
  // --------------------------------------------------------------------------

  test("cache root falls back to $HOME/.cache when XDG_CACHE_HOME is unset"):
    // The ordinary case on macOS, not the exception; Mill's own bootstrap takes the same fallback.
    assertEquals(
      cacheRootOf(Os.Mac, env("HOME" -> home)),
      Right(Paths.get(s"$home/.cache/ko-agent-sandbox")),
    )

  test("cache root honours an absolute XDG_CACHE_HOME"):
    assertEquals(
      cacheRootOf(Os.Mac, env("HOME" -> home, "XDG_CACHE_HOME" -> "/var/cache/mine")),
      Right(Paths.get("/var/cache/mine/ko-agent-sandbox")),
    )

  test("an empty XDG_CACHE_HOME is treated as unset, not as a relative path"):
    assertEquals(
      cacheRootOf(Os.Mac, env("HOME" -> home, "XDG_CACHE_HOME" -> "")),
      Right(Paths.get(s"$home/.cache/ko-agent-sandbox")),
    )

  test("a relative XDG_CACHE_HOME is refused, as stateRootOf refuses one"):
    val refused = cacheRootOf(Os.Mac, env("HOME" -> home, "XDG_CACHE_HOME" -> "cache"))
    assert(clue(refused).isLeft)

  test("no HOME and no XDG_CACHE_HOME is a refusal, not a path relative to nowhere"):
    assert(cacheRootOf(Os.Mac, env()).isLeft)

  test("a cache root inside the project is refused"):
    val inside = project.resolve(".cache/ko-agent-sandbox")
    assert(cacheRootOutsideProject(inside, project, Os.Mac).isLeft)

  test("a cache root containing the project is refused"):
    assert(cacheRootOutsideProject(Paths.get(home), project, Os.Mac).isLeft)

  test("the ordinary cache root is accepted beside the project"):
    val root = Paths.get(s"$home/.cache/ko-agent-sandbox")
    assertEquals(cacheRootOutsideProject(root, project, Os.Mac), Right(root))

  test("the project's caches sit under one removable directory"):
    val root = Paths.get(s"$home/.cache/ko-agent-sandbox")
    assertEquals(agentCoursierV1(root, "abc123"), Paths.get(s"$root/cache/abc123/coursier/v1"))
    // One removal reaches all of them: what --reset-cache relies on.
    assert(agentCoursierV1(root, "abc123").startsWith(agentCacheDir(root, "abc123")))

  // --------------------------------------------------------------------------
  // Discovery
  // --------------------------------------------------------------------------

  test("the macOS Coursier cache root and install directory are the Library spellings"):
    assertEquals(coursierCacheRoot(Os.Mac, env("HOME" -> home)), Some(coursierCache))
    assertEquals(coursierInstallDir(Os.Mac, env("HOME" -> home)), Some(installDir))
    // The install directory contains a space; nothing downstream may split on one.
    assert(clue(installDir.toString).contains(" "))

  test("the Linux spellings differ, and are testable from either host"):
    assertEquals(coursierCacheRoot(Os.Linux, env("HOME" -> home)), Some(Paths.get(s"$home/.cache/coursier")))
    assertEquals(
      coursierInstallDir(Os.Linux, env("HOME" -> home)),
      Some(Paths.get(s"$home/.local/share/coursier/bin")),
    )

  test("COURSIER_CACHE and COURSIER_BIN_DIR override discovery"):
    assertEquals(
      coursierCacheRoot(Os.Mac, env("HOME" -> home, "COURSIER_CACHE" -> "/opt/cs")),
      Some(Paths.get("/opt/cs")),
    )
    assertEquals(
      coursierInstallDir(Os.Mac, env("HOME" -> home, "COURSIER_BIN_DIR" -> "/opt/cs/bin")),
      Some(Paths.get("/opt/cs/bin")),
    )

  // --------------------------------------------------------------------------
  // JDK
  // --------------------------------------------------------------------------

  test("a Coursier-unpacked JDK home is accepted through its URL-derived path"):
    assertEquals(
      resolveJdkHome(env("JAVA_HOME" -> jdkHome.toString), coursierCache, exists(jdkHome, coursierCache), Os.Mac),
      Right(jdkHome),
    )

  test("/usr/bin/java is refused: the stub is a redirector, not a JDK"):
    val stub = Paths.get("/usr/bin/java")
    assert(resolveJdkHome(env("JAVA_HOME" -> stub.toString), coursierCache, exists(stub, coursierCache), Os.Mac).isLeft)

  test("a system or Homebrew JDK is refused"):
    for candidate <- Seq(
        "/Library/Java/JavaVirtualMachines/temurin-25.jdk/Contents/Home",
        "/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home",
        s"$home/.sdkman/candidates/java/current",
      )
    do
      val path = Paths.get(candidate)
      assert(
        resolveJdkHome(env("JAVA_HOME" -> candidate), coursierCache, exists(path, coursierCache), Os.Mac).isLeft,
        clue(candidate),
      )

  test("JAVA_HOME unset is a prerequisite refusal, not a fallback to PATH"):
    assert(resolveJdkHome(env(), coursierCache, exists(coursierCache), Os.Mac).isLeft)

  test("a JAVA_HOME that does not exist is refused rather than assumed"):
    val absent = coursierCache.resolve("arc/gone/Contents/Home")
    assert(resolveJdkHome(env("JAVA_HOME" -> absent.toString), coursierCache, exists(coursierCache), Os.Mac).isLeft)

  // --------------------------------------------------------------------------
  // sbt and Mill
  // --------------------------------------------------------------------------

  test("an sbt launcher inside the install directory is accepted"):
    val launcher = installDir.resolve("sbt")
    assertEquals(validateSbtLauncher(launcher, installDir, exists(launcher, installDir), Os.Mac), Right(launcher))

  test("a PATH symlink resolving into the install directory is accepted"):
    val linked = Paths.get("/usr/local/bin/sbt")
    val real = installDir.resolve("sbt")
    val canonical: Path => Option[Path] =
      path => if path == linked then Some(real) else exists(real, installDir)(path)
    assertEquals(validateSbtLauncher(linked, installDir, canonical, Os.Mac), Right(real))

  test("an sbt from anywhere else is refused"):
    val other = Paths.get("/usr/local/bin/sbt")
    assert(validateSbtLauncher(other, installDir, exists(other, installDir), Os.Mac).isLeft)

  test("Mill needs the project's own bootstrap; a global Mill is not a fallback"):
    val bootstrap = project.resolve("mill")
    assertEquals(validateMillBootstrap(project, _ == bootstrap), Right(bootstrap))
    assertEquals(validateMillBootstrap(project, _ => false), Left(Refusal.PrereqMillBootstrapMissing))

  private val millDownload = Paths.get(s"$home/.cache/mill/download")

  private def files(pairs: (String, Seq[String])*): Path => Option[Seq[String]] =
    val map = pairs.toMap
    path => map.get(project.relativize(path).toString)

  test("the Mill download folder follows the bootstrap's own fallback"):
    assertEquals(millDownloadDir(env("HOME" -> home)), Some(millDownload))

  test("MILL_FINAL_DOWNLOAD_FOLDER and MILL_USER_CACHE_DIR override it, in that order"):
    assertEquals(
      millDownloadDir(env("HOME" -> home, "MILL_FINAL_DOWNLOAD_FOLDER" -> "/opt/mill/dl")),
      Some(Paths.get("/opt/mill/dl")),
    )
    assertEquals(
      millDownloadDir(env("HOME" -> home, "MILL_USER_CACHE_DIR" -> "/opt/mill")),
      Some(Paths.get("/opt/mill/download")),
    )

  test("the pinned version is read from each place the bootstrap reads, in its order"):
    assertEquals(millVersion(project, env(), files(".mill-version" -> Seq("1.1.8"))), Right("1.1.8"))
    assertEquals(
      millVersion(project, env(), files(".config/mill-version" -> Seq("1.1.8"))),
      Right("1.1.8"),
    )
    assertEquals(
      millVersion(project, env(), files("build.mill.yaml" -> Seq("mill-version: 1.1.8"))),
      Right("1.1.8"),
    )
    assertEquals(
      millVersion(project, env(), files("build.mill" -> Seq("//| mill-version: 1.1.8", "package build"))),
      Right("1.1.8"),
    )
    // The environment wins, as it does in the script.
    assertEquals(
      millVersion(project, env("MILL_VERSION" -> "1.0.0"), files(".mill-version" -> Seq("1.1.8"))),
      Right("1.0.0"),
    )

  test("the bootstrap's own trimming is reproduced: quotes and trailing comments"):
    assertEquals(
      millVersion(project, env(), files("build.mill.yaml" -> Seq("  mill-version: \"1.1.8\"  # pinned"))),
      Right("1.1.8"),
    )

  test("an unpinned version is refused, not taken from the committed script's default"):
    assertEquals(millVersion(project, env(), files()), Left(Refusal.PrereqMillVersionUnpinned))
    assertEquals(
      millVersion(project, env(), files(".mill-version" -> Seq(""))),
      Left(Refusal.PrereqMillVersionUnpinned),
    )

  test("a version that could name something other than a directory entry is refused"):
    for bad <- Seq("../../etc", "a/b", "1.1.8 --flag") do
      assertEquals(millVersion(project, env("MILL_VERSION" -> bad), files()), Left(Refusal.PrereqMillVersionUnpinned), clue(bad))

  test("the launcher is matched on its prefix, so the platform suffix is never replicated"):
    val entries = Seq("1.1.6-native-mac-aarch64", "1.1.8-native-mac-aarch64", "0.11.5")
    assertEquals(
      millLauncher(millDownload, "1.1.8", _ => entries),
      Right(millDownload.resolve("1.1.8-native-mac-aarch64")),
    )
    // A jar-era version with no suffix at all matches the same way.
    assertEquals(millLauncher(millDownload, "0.11.5", _ => entries), Right(millDownload.resolve("0.11.5")))

  test("an unprovisioned launcher is a refusal naming the version and the folder to fix"):
    assertEquals(
      millLauncher(millDownload, "1.2.0", _ => Seq("1.1.8-native-mac-aarch64")),
      Left(Refusal.PrereqMillLauncherMissing("1.2.0", millDownload)),
    )
    assertEquals(
      millLauncher(millDownload, "1.1.8", _ => Seq.empty),
      Left(Refusal.PrereqMillLauncherMissing("1.1.8", millDownload)),
    )

  test("sbt boot must exist; the sandbox does not provision it"):
    val boot = Paths.get(s"$home/.sbt/boot")
    assertEquals(sbtBoot(env("HOME" -> home), _ == boot), Right(boot))
    assertEquals(sbtBoot(env("HOME" -> home), _ => false), Left(Refusal.PrereqSbtBootMissing))

  // --------------------------------------------------------------------------
  // The channel's working directory
  // --------------------------------------------------------------------------

  private def cwd(requested: String, canonical: Path => Option[Path] = path => Some(path.normalize())) =
    workingDirectory(requested, "/workspace", project, canonical, Os.Mac)

  test("the mount root translates to the project root"):
    assertEquals(cwd("/workspace"), Right(project))

  test("a subdirectory translates beneath the project"):
    assertEquals(cwd("/workspace/modules/a"), Right(project.resolve("modules/a")))

  test("climbing out of the mount is refused, not clamped"):
    for requested <- Seq("/workspace/../..", "/workspace/../../etc", "/workspace/a/../../..") do
      assert(cwd(requested).isLeft, clue(requested))

  test("a path outside the mount is refused"):
    for requested <- Seq("/etc", "/Users/kenichi", "/workspacex", "workspace/a", "") do
      assert(cwd(requested).isLeft, clue(requested))

  test("a symlink inside the project that leaves it is refused"):
    // The textual check passes and the canonical one does not: why both run.
    val escaping = project.resolve("link")
    val canonical: Path => Option[Path] =
      path => if path == escaping then Some(Paths.get("/etc")) else Some(path.normalize())
    assert(cwd("/workspace/link", canonical).isLeft)

  test("a working directory that does not exist is refused"):
    assert(cwd("/workspace/gone", _ => None).isLeft)

  test("a refusal names what was requested, so the diagnostic can quote it"):
    assertEquals(cwd("/etc/passwd"), Left(Refusal.WorkingDirectoryOutsideProject("/etc/passwd")))

  // --------------------------------------------------------------------------
  // The session temporary directory
  // --------------------------------------------------------------------------

  test("the session temp budget is what sbt's boot socket leaves of sun_path"):
    assertEquals(SessionTmpMaxLength, 53)
    val fits = Paths.get("/private/tmp/" + "y" * 40)
    val traps = Paths.get("/private/tmp/" + "y" * 43)
    assertEquals(sessionTmpFits(fits), Right(fits))
    assertEquals(sessionTmpFits(traps), Left(Refusal.SessionTmpTooLong(traps, 53)))
    // The macOS per-user temporary directory is 49 characters before anything is added to it, so
    // a session directory under it can never fit; the wrapper's root is elsewhere.
    assert(sessionTmpFits(Paths.get("/var/folders/w6/grf54s4d7bz6j0fypwdxvmq40000gn/T/ko-agent")).isLeft)

  // --------------------------------------------------------------------------
  // Case folding
  // --------------------------------------------------------------------------

  test("containment folds case where the filesystem does"):
    // The probe reports this host's project volume as case-insensitive, so a guard that compares
    // exactly would accept a path the filesystem treats as the same one.
    assert(startsWith(Paths.get("/Users/K/P/.GIT/config"), Paths.get("/Users/k/p/.git"), Os.Mac))
    assert(!startsWith(Paths.get("/Users/K/P/.GIT/config"), Paths.get("/Users/k/p/.git"), Os.Linux))

  test("folding does not make unrelated siblings overlap"):
    assert(!startsWith(Paths.get("/a/bc"), Paths.get("/a/b"), Os.Mac))
    assert(!overlaps(Paths.get("/a/b"), Paths.get("/a/c"), Os.Mac))

  test("overlap is symmetric"):
    assert(overlaps(project, project.resolve("sub"), Os.Mac))
    assert(overlaps(project.resolve("sub"), project, Os.Mac))

  // --------------------------------------------------------------------------
  // Against the running host
  // --------------------------------------------------------------------------

  test("realPath answers None for an absent path rather than throwing"):
    assertEquals(realPath(Paths.get("/definitely/not/here")), None)
    val real = realPath(Files.createTempDirectory("build-sandbox-policy"))
    assert(real.isDefined)
