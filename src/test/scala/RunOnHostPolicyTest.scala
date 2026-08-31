// PLAN-SBT-ON-HOST.md Phase 1's exit criterion: supported and unsupported layouts are classified
// correctly. The fixtures are a real macOS host's, not invented ones — the Coursier JDK home
// carries a percent-encoded '+', a literal '+' and a directory named like an archive, and the
// install directory contains a space, which is exactly the shape a quoting or regex bug eats.

package agentsandbox.launcher

import java.nio.file.{Files, Path, Paths}

import RunOnHostPolicy.*
import HostCommands.Os

class RunOnHostPolicyTest extends munit.FunSuite:

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
    assert(cacheRootOutsideProject(inside, project, Os.Mac, Right(_)).isLeft)

  test("a cache root containing the project is refused"):
    assert(cacheRootOutsideProject(Paths.get(home), project, Os.Mac, Right(_)).isLeft)

  test("the ordinary cache root is accepted beside the project"):
    val root = Paths.get(s"$home/.cache/ko-agent-sandbox")
    assertEquals(cacheRootOutsideProject(root, project, Os.Mac, Right(_)), Right(root))

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

  test("a cache root whose symlink lands inside the project is refused on its canonical path"):
    val alias = Paths.get("/opt/cache/ko-agent-sandbox")
    val canonical: Path => Either[String, Path] =
      path => Right(if path == alias then project.resolve(".cache") else path)
    assert(cacheRootOutsideProject(alias, project, Os.Mac, canonical).isLeft)
    assert(cacheRootOutsideProject(alias, project, Os.Mac, _ => Left("cannot inspect")).isLeft)

  test("the data-volume spelling of the project is the project"):
    val inside = Paths.get("/System/Volumes/Data" + project.toString + "/.cache/ko-agent-sandbox")
    assert(cacheRootOutsideProject(inside, project, Os.Mac, Right(_)).isLeft)

  // --------------------------------------------------------------------------
  // JDK
  // --------------------------------------------------------------------------

  private val javaBinary = jdkHome.resolve("bin/java")

  test("a Coursier-unpacked JDK home is accepted through its URL-derived path"):
    assertEquals(
      resolveJdkHome(
        env("JAVA_HOME" -> jdkHome.toString),
        coursierCache,
        exists(jdkHome, javaBinary, coursierCache),
        _ == javaBinary,
      ),
      Right(jdkHome),
    )

  test("bin/java must be an executable file under the home, not a symlink out of it"):
    val elsewhere = Paths.get("/Library/Java/JavaVirtualMachines/temurin-25.jdk/Contents/Home/bin/java")
    val escaping: Path => Option[Path] =
      path => if path == javaBinary then Some(elsewhere) else exists(jdkHome, coursierCache, elsewhere)(path)
    assert(resolveJdkHome(env("JAVA_HOME" -> jdkHome.toString), coursierCache, escaping, _ => true).isLeft)
    assert(
      resolveJdkHome(
        env("JAVA_HOME" -> jdkHome.toString),
        coursierCache,
        exists(jdkHome, javaBinary, coursierCache),
        _ => false,
      ).isLeft,
    )

  test("inside the cache is not enough: the cache root, arc, v1 and a home without bin/java are refused"):
    val arc = coursierCache.resolve("arc")
    val v1 = coursierCache.resolve("v1")
    for candidate <- Seq(coursierCache, arc, v1, jdkHome) do
      val known = Seq(coursierCache, arc, v1, jdkHome, arc.resolve("bin/java"), v1.resolve("bin/java"),
        coursierCache.resolve("bin/java"))
      assert(
        resolveJdkHome(env("JAVA_HOME" -> candidate.toString), coursierCache, exists(known*), _ => true).isLeft,
        clue(candidate),
      )

  test("/usr/bin/java is refused: the stub is a redirector, not a JDK"):
    val stub = Paths.get("/usr/bin/java")
    val known = exists(stub, coursierCache)
    assert(resolveJdkHome(env("JAVA_HOME" -> stub.toString), coursierCache, known, _ => true).isLeft)

  test("a system or Homebrew JDK is refused"):
    for candidate <- Seq(
        "/Library/Java/JavaVirtualMachines/temurin-25.jdk/Contents/Home",
        "/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home",
        s"$home/.sdkman/candidates/java/current",
      )
    do
      val path = Paths.get(candidate)
      assert(
        resolveJdkHome(env("JAVA_HOME" -> candidate), coursierCache, exists(path, coursierCache), _ => true)
          .isLeft,
        clue(candidate),
      )

  test("JAVA_HOME unset is a prerequisite refusal, not a fallback to PATH"):
    assert(resolveJdkHome(env(), coursierCache, exists(coursierCache), _ => true).isLeft)

  test("a JAVA_HOME that does not exist is refused rather than assumed"):
    val absent = coursierCache.resolve("arc/gone/Contents/Home")
    val known = exists(coursierCache)
    assert(resolveJdkHome(env("JAVA_HOME" -> absent.toString), coursierCache, known, _ => true).isLeft)

  // --------------------------------------------------------------------------
  // sbt and Mill
  // --------------------------------------------------------------------------

  test("an sbt launcher inside the install directory is accepted"):
    val launcher = installDir.resolve("sbt")
    val known = exists(launcher, installDir)
    assertEquals(validateSbtLauncher(launcher, installDir, known, _ => true), Right(launcher))
    assert(validateSbtLauncher(launcher, installDir, exists(launcher, installDir), _ => false).isLeft)

  test("a PATH symlink resolving into the install directory is accepted"):
    val linked = Paths.get("/usr/local/bin/sbt")
    val real = installDir.resolve("sbt")
    val canonical: Path => Option[Path] =
      path => if path == linked then Some(real) else exists(real, installDir)(path)
    assertEquals(validateSbtLauncher(linked, installDir, canonical, _ => true), Right(real))

  test("an sbt from anywhere else is refused"):
    val other = Paths.get("/usr/local/bin/sbt")
    assert(validateSbtLauncher(other, installDir, exists(other, installDir), _ => true).isLeft)

  test("the inner sbt launcher yields its home: <home>/bin/sbt, strictly inside arc"):
    val home = coursierCache.resolve("arc/sbt-2.0.4.zip/sbt")
    val inner = home.resolve("bin/sbt")
    val known = exists(inner, coursierCache)
    assertEquals(validateSbtDistribution(inner, coursierCache, known, _ => true), Right(home))
    assert(validateSbtDistribution(inner, coursierCache, known, _ => false).isLeft)
    val escaping: Path => Option[Path] =
      path => if path == inner then Some(Paths.get("/opt/sbt/bin/sbt")) else known(path)
    assert(validateSbtDistribution(inner, coursierCache, escaping, _ => true).isLeft)

  test("a launcher whose home would be the cache root, arc, a v1 entry or a non-bin path is refused"):
    for bad <- Seq("bin/sbt", "arc/bin/sbt", "v1/x/bin/sbt", "arc/sbt-2.0.4.zip/sbt/sbt", "arc/x/bin/sbtn") do
      val inner = coursierCache.resolve(bad)
      assert(validateSbtDistribution(inner, coursierCache, exists(inner, coursierCache), _ => true).isLeft, clue(bad))

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

  test("MILL_FINAL_DOWNLOAD_FOLDER overrides it; MILL_USER_CACHE_DIR is assigned by the script, never read"):
    assertEquals(
      millDownloadDir(env("HOME" -> home, "MILL_FINAL_DOWNLOAD_FOLDER" -> "/opt/mill/dl")),
      Some(Paths.get("/opt/mill/dl")),
    )
    assertEquals(millDownloadDir(env("HOME" -> home, "MILL_USER_CACHE_DIR" -> "/opt/mill")), Some(millDownload))
    assertEquals(
      millDownloadDir(env("HOME" -> home, "XDG_CACHE_HOME" -> "/opt/xdg")),
      Some(Paths.get("/opt/xdg/mill/download")),
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

  test("mill-jvm-version must be system, wherever Mill would read it"):
    assertEquals(millJvmIsSystem(project, files("build.mill.yaml" -> Seq("mill-jvm-version: system"))), Right(()))
    assertEquals(millJvmIsSystem(project, files("build.mill" -> Seq("//| mill-jvm-version: system"))), Right(()))
    assertEquals(millJvmIsSystem(project, files(".mill-jvm-version" -> Seq("system"))), Right(()))
    assertEquals(
      millJvmIsSystem(project, files("build.mill.yaml" -> Seq("mill-jvm-version: temurin:25"))),
      Left(Refusal.PrereqMillJvmNotSystem(Some("temurin:25"))),
    )
    // Absent is Mill's own default, a JVM fetched by the build.
    assertEquals(millJvmIsSystem(project, files("build.mill.yaml" -> Seq("extends: ScalaModule"))),
      Left(Refusal.PrereqMillJvmNotSystem(None)))

  test("the JVM source is the launcher's loadMillConfig order, the first existing file authoritative"):
    assertEquals(millJvmIsSystem(project, files(".config/mill-jvm-version" -> Seq("system"))), Right(()))
    // .mill-jvm-version beats .config, which beats the header; an empty first file is the answer.
    val dotBeatsConfig = files(".mill-jvm-version" -> Seq("temurin:25"), ".config/mill-jvm-version" -> Seq("system"))
    assertEquals(millJvmIsSystem(project, dotBeatsConfig), Left(Refusal.PrereqMillJvmNotSystem(Some("temurin:25"))))
    val emptyFirst = files(".mill-jvm-version" -> Seq(""), "build.mill.yaml" -> Seq("mill-jvm-version: system"))
    assertEquals(millJvmIsSystem(project, emptyFirst), Left(Refusal.PrereqMillJvmNotSystem(None)))
    // Compared as written: Mill keeps the opts-file line untrimmed and tests equality.
    assertEquals(millJvmIsSystem(project, files(".mill-jvm-version" -> Seq(" system "))),
      Left(Refusal.PrereqMillJvmNotSystem(Some(" system "))))
    assertEquals(millJvmIsSystem(project, files(".mill-jvm-version" -> Seq("# comment", "", "system"))), Right(()))
    // A nested YAML key is not the key; a //| line after the header is not the header.
    assertEquals(
      millJvmIsSystem(project, files("build.mill.yaml" -> Seq("mill-build:", "  mill-jvm-version: system"))),
      Left(Refusal.PrereqMillJvmNotSystem(None)),
    )
    // Refused as a stray //| line: readBuildHeader scans the whole file and errors on it.
    assert(millJvmIsSystem(project, files("build.mill" -> Seq("package build", "//| mill-jvm-version: system"))).isLeft)
    val quoted = files("build.mill.yaml" -> Seq("mill-jvm-version: \"system\" # x"))
    assertEquals(millJvmIsSystem(project, quoted), Right(()))
    // Not system, whatever a lax reader would strip: a YAML comment needs whitespace before its
    // #, and an unmatched quote is not the plain scalar.
    for bad <- Seq("mill-jvm-version: system#other", "mill-jvm-version: \"system", "mill-jvm-version: system'") do
      assert(millJvmIsSystem(project, files("build.mill.yaml" -> Seq(bad))).isLeft, clue(bad))
    // YAML's `key:value` is one scalar, not a mapping: Mill never sees the key.
    assertEquals(
      millJvmIsSystem(project, files("build.mill.yaml" -> Seq("mill-jvm-version:system"))),
      Left(Refusal.PrereqMillJvmNotSystem(None)),
    )
    // A malformed //| line is an error in Mill's readBuildHeader, and a refusal here; so is a
    // stray //| after the header, and so are two keys, whichever Mill's map would keep.
    assert(millJvmIsSystem(project, files("build.mill" -> Seq("//|mill-jvm-version: system"))).isLeft)
    val stray = files("build.mill" -> Seq("//| mill-jvm-version: system", "package build", "//| x"))
    assert(millJvmIsSystem(project, stray).isLeft)
    // A second YAML document is territory Mill never reads; a marker anywhere is a refusal.
    val secondDoc = files("build.mill.yaml" -> Seq("extends: ScalaModule", "---", "mill-jvm-version: system"))
    assertEquals(millJvmIsSystem(project, secondDoc), Left(Refusal.PrereqMillJvmNotSystem(Some("multi-document YAML"))))
    val headerDoc = files("build.mill" -> Seq("//| mill-jvm-version: system", "//| ..."))
    assert(millJvmIsSystem(project, headerDoc).isLeft)
    // A commented marker is still a marker; an indented or embedded one is not.
    val commented = files("build.mill.yaml" -> Seq("--- # next", "mill-jvm-version: system"))
    assertEquals(millJvmIsSystem(project, commented), Left(Refusal.PrereqMillJvmNotSystem(Some("multi-document YAML"))))
    val dashesInValue = files("build.mill.yaml" -> Seq("mill-jvm-version: system", "x: --- y"))
    assertEquals(millJvmIsSystem(project, dashesInValue), Right(()))
    val doubled = files("build.mill.yaml" -> Seq("mill-jvm-version: system", "mill-jvm-version: temurin:25"))
    assertEquals(millJvmIsSystem(project, doubled),
      Left(Refusal.PrereqMillJvmNotSystem(Some("duplicate mill-jvm-version keys"))))
    // build.mill.yaml is consulted before build.mill, and one existing root file ends the search.
    val yamlFirst =
      files("build.mill.yaml" -> Seq("extends: ScalaModule"), "build.mill" -> Seq("//| mill-jvm-version: system"))
    assertEquals(millJvmIsSystem(project, yamlFirst), Left(Refusal.PrereqMillJvmNotSystem(None)))

  test("no version anywhere is a refusal"):
    assertEquals(millVersion(project, env(), files()), Left(Refusal.PrereqMillVersionUnpinned))
    assertEquals(
      millVersion(project, env(), files(".mill-version" -> Seq(""))),
      Left(Refusal.PrereqMillVersionUnpinned),
    )

  private val bootstrap = Seq(
    "#!/usr/bin/env sh",
    """if [ -z "${DEFAULT_MILL_VERSION}" ] ; then DEFAULT_MILL_VERSION="1.1.8"; fi""",
  )

  test("with nothing else pinned, the version is the bootstrap's own DEFAULT_MILL_VERSION"):
    assertEquals(millVersion(project, env(), files("mill" -> bootstrap)), Right("1.1.8"))
    val fromEnv = env("DEFAULT_MILL_VERSION" -> "1.1.9")
    assertEquals(millVersion(project, fromEnv, files("mill" -> bootstrap)), Right("1.1.9"))
    // A pin anywhere in the chain wins over the default, as in the script.
    val pinned = files("mill" -> bootstrap, ".mill-version" -> Seq("1.1.7"))
    assertEquals(millVersion(project, env(), pinned), Right("1.1.7"))
    val noDefault = files("mill" -> Seq("#!/bin/sh"))
    assertEquals(millVersion(project, env(), noDefault), Left(Refusal.PrereqMillVersionUnpinned))

  test("the first existing file decides, empty or not: the bootstrap's elif chain has no fall-through"):
    assertEquals(
      millVersion(project, env(), files(".mill-version" -> Seq(""), "build.mill.yaml" -> Seq("mill-version: 1.1.8"))),
      Left(Refusal.PrereqMillVersionUnpinned),
    )
    // An empty chain result falls to the default, as the script's `if [ -z "$MILL_VERSION" ]` does.
    assertEquals(
      millVersion(project, env(), files(".mill-version" -> Seq(""), "mill" -> bootstrap)),
      Right("1.1.8"),
    )
    // build.mill exists and carries no marker: build.mill.scala is never consulted.
    assertEquals(
      millVersion(
        project,
        env(),
        files("build.mill" -> Seq("package build"), "build.mill.scala" -> Seq("//| mill-version: 1.1.8")),
      ),
      Left(Refusal.PrereqMillVersionUnpinned),
    )
    assertEquals(millVersion(project, env(), files("build.sc" -> Seq("//| mill-version: 0.11.5"))), Right("0.11.5"))
    // grep's `//\|.*mill-version`: the marker before the key, never after it.
    assertEquals(
      millVersion(project, env(), files("build.mill" -> Seq("mill-version//|: 1.1.8"))),
      Left(Refusal.PrereqMillVersionUnpinned),
    )

  test("canonical paths compare exactly: a case-sensitive volume keeps coursier and Coursier apart"):
    val sibling = Paths.get(s"$home/Library/Caches/coursier/arc/jdk/Contents/Home")
    val binary = sibling.resolve("bin/java")
    val known = exists(sibling, binary, coursierCache)
    assert(resolveJdkHome(env("JAVA_HOME" -> sibling.toString), coursierCache, known, _ => true).isLeft)

  test("two markers are no version, and a version file's whitespace is kept as the script keeps it"):
    assertEquals(
      millVersion(project, env(), files("build.mill.yaml" -> Seq("mill-version: 1.1.8", "mill-version: 1.1.9"))),
      Left(Refusal.PrereqMillVersionUnpinned),
    )
    assertEquals(
      millVersion(project, env(), files(".mill-version" -> Seq("1.1.8 "))),
      Left(Refusal.PrereqMillVersionUnpinned),
    )

  test("a version that could name something other than a directory entry is refused"):
    for bad <- Seq("../../etc", "a/b", "1.1.8 --flag") do
      assertEquals(
        millVersion(project, env("MILL_VERSION" -> bad), files()),
        Left(Refusal.PrereqMillVersionUnpinned),
        clue(bad),
      )

  test("the launcher name is the bootstrap's own derivation, suffix rules included"):
    // The `case "$MILL_VERSION"` block of the official script, one row per branch.
    assertEquals(millLauncherName("1.1.8", "arm64"), "1.1.8-native-mac-aarch64")
    assertEquals(millLauncherName("1.1.8", "x86_64"), "1.1.8-native-mac-amd64")
    assertEquals(millLauncherName("1.1.8-jvm", "arm64"), "1.1.8")
    assertEquals(millLauncherName("1.1.8-native", "arm64"), "1.1.8-native-mac-aarch64")
    assertEquals(millLauncherName("0.11.5", "arm64"), "0.11.5")
    assertEquals(millLauncherName("0.12.14", "arm64"), "0.12.14")
    assertEquals(millLauncherName("0.13.0-M1", "arm64"), "0.13.0-M1-native-mac-aarch64")
    assertEquals(millLauncherName("1.1.6-104-5bbe1e", "arm64"), "1.1.6-104-5bbe1e-native-mac-aarch64")

  test("a provisioned launcher is that exact file, present and executable"):
    val launcher = millDownload.resolve("1.1.8-native-mac-aarch64")
    assertEquals(millLauncher(millDownload, "1.1.8", "arm64", _ == launcher), Right(launcher))
    // A similarly prefixed neighbour is not it.
    assertEquals(
      millLauncher(millDownload, "1.1.8", "arm64", _ == millDownload.resolve("1.1.8-native-mac-aarch64.part")),
      Left(Refusal.PrereqMillLauncherMissing("1.1.8", millDownload)),
    )

  test("an unprovisioned launcher is a refusal naming the version and the folder to fix"):
    assertEquals(
      millLauncher(millDownload, "1.2.0", "arm64", _ => false),
      Left(Refusal.PrereqMillLauncherMissing("1.2.0", millDownload)),
    )

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

  test("a canonical case-different sibling is outside the project; a lexical one still folds"):
    // Canonical spellings are the volume's own: on a case-sensitive volume `Ko-Agent-Sandbox` is
    // another directory. The lexical check before canonicalization keeps folding, since a request
    // on a folding volume may arrive in either case.
    val sibling = Paths.get(s"$home/Ko-Agent-Sandbox/sub")
    assert(cwd("/workspace/sub", _ => Some(sibling)).isLeft)
    // Lexically a case-different spelling of the project itself, which the real filesystem folds.
    val folded = cwd("/workspace/../KO-AGENT-SANDBOX/sub", _ => Some(project.resolve("sub")))
    assertEquals(folded, Right(project.resolve("sub")))

  test("a canonical case-different sibling of the project is a safe cache root"):
    val sibling = Paths.get(s"$home/Ko-Agent-Sandbox/.cache")
    assertEquals(cacheRootOutsideProject(sibling, project, Os.Mac, Right(_)), Right(sibling))

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
  // The build's egress allowlist
  // --------------------------------------------------------------------------

  test("the allowlist accepts +host entries, comments and blank lines, in file order, once each"):
    val text =
      """# artifact repositories this build resolves from
        |+host repo.example.org
        |
        |+host mirror.example.org  # inline comment
        |+host repo.example.org
        |""".stripMargin
    assertEquals(
      buildAllowlist(text),
      Right(Vector("repo.example.org", "mirror.example.org")),
    )

  test("an empty or comment-only allowlist is valid and contributes nothing"):
    for text <- Seq("", "\n\n", "# nothing yet\n") do
      assertEquals(buildAllowlist(text), Right(Vector.empty))

  test("every entry of the proxy's wider grammar is outside the file's"):
    for
      entry <- Seq(
        "-**",
        "+model-provider openai",
        "-model-provider openai",
        "+host repo.example.org allow=git-fetch",
        "+host repo.example.org unrestricted",
        "+host repo.example.org restricted",
        "-host repo.example.org",
        "repo.example.org",
        "+host",
        "+host -**",
        "+host +evil",
      )
    do
      buildAllowlist(entry) match
        case Left(Refusal.AllowlistEntryOutsideGrammar(seen)) => assertEquals(seen, entry)
        case other => fail(s"'$entry' -> $other")

  test("a refused entry names itself even after a comment is stripped"):
    assertEquals(
      buildAllowlist("-host x # a removal\n"),
      Left(Refusal.AllowlistEntryOutsideGrammar("-host x")),
    )

  test("the composed allowed input is a complete replacement: -**, baseline, then the file"):
    assertEquals(
      egressAllowedText(Vector("repo.example.org")),
      "-**\n+host repo1.maven.org\n+host repo.example.org",
    )

  test("a file restating the baseline host composes it once"):
    assertEquals(
      egressAllowedText(Vector("repo1.maven.org")),
      "-**\n+host repo1.maven.org",
    )

  test("the sbt global base sits beside the project's Coursier cache, one --reset-cache removal"):
    val cacheRoot = Paths.get("/Users/u/.cache/ko-agent-sandbox")
    assertEquals(
      agentSbtGlobal(cacheRoot, "proj-abc123"),
      Paths.get("/Users/u/.cache/ko-agent-sandbox/cache/proj-abc123/sbt-global"),
    )
    assertEquals(
      agentSbtGlobal(cacheRoot, "proj-abc123").getParent,
      agentCoursierV1(cacheRoot, "proj-abc123").getParent.getParent,
    )

  test("the allowlist path is per tool under the frozen boundary directory"):
    val project = Paths.get("/Users/u/proj")
    assertEquals(
      buildAllowlistPath(project, Tool.Sbt),
      Paths.get("/Users/u/proj/.ko-agent-sandbox/host-command/sbt/egress/allowed"),
    )
    assertEquals(
      buildAllowlistPath(project, Tool.Mill),
      Paths.get("/Users/u/proj/.ko-agent-sandbox/host-command/mill/egress/allowed"),
    )

  // --------------------------------------------------------------------------
  // Against the running host
  // --------------------------------------------------------------------------

  test("realPath answers None for an absent path rather than throwing"):
    assertEquals(realPath(Paths.get("/definitely/not/here")), None)
    val real = realPath(Files.createTempDirectory("build-sandbox-policy"))
    assert(real.isDefined)
