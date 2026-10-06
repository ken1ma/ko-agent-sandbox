// The prerequisite validator's exit criterion: supported and unsupported layouts are classified
// correctly. The fixtures are a real macOS host's, not invented ones — the Coursier JDK home
// contains a percent-encoded '+', a literal '+' and a directory named like an archive, and the
// install directory contains a space, which is exactly the input a quoting or regex bug mishandles.
// The run-on-host rule files are read from temporary projects.

package agentsandbox.launcher

import java.net.URI
import java.nio.file.{Files, Path, Paths}

import RunOnHostPrereqs.*
import HostCommands.Os

class RunOnHostPrereqsTest extends munit.FunSuite:

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
    // The ordinary case on macOS, not the exception; mill's own bootstrap takes the same fallback.
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

  test("the project's caches are stored under one removable directory"):
    val root = Paths.get(s"$home/.cache/ko-agent-sandbox")
    assertEquals(coursierV1Of(root, "abc123"), Paths.get(s"$root/run-on-host/abc123/coursier/v1"))
    // One removal reaches all of them: what --reset-run-on-host relies on.
    assert(coursierV1Of(root, "abc123").startsWith(runOnHostCacheDir(root, "abc123")))

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

  test("a cache root whose symlink resolves inside the project is refused on its canonical path"):
    val alias = Paths.get("/opt/cache/ko-agent-sandbox")
    val canonical: Path => Either[String, Path] =
      path => Right(if path == alias then project.resolve(".cache") else path)
    assert(cacheRootOutsideProject(alias, project, Os.Mac, canonical).isLeft)
    assert(cacheRootOutsideProject(alias, project, Os.Mac, _ => Left("cannot inspect")).isLeft)

  test("the data-volume spelling of the project is the project"):
    val inside = Paths.get("/System/Volumes/Data" + project.toString + "/.cache/ko-agent-sandbox")
    assert(cacheRootOutsideProject(inside, project, Os.Mac, Right(_)).isLeft)

  test("a cache path overlapping the state root is refused, unless under the state root's own tree"):
    val state = Paths.get(s"$home/.local/state/ko-agent-sandbox")
    val tree = runOnHostCachesOf(Paths.get(s"$home/.cache/ko-agent-sandbox"))
    assertEquals(cachePathClearOfStateRoot(tree, state, Os.Mac), Right(tree))
    assertEquals(cachePathClearOfStateRoot(tree.resolve("a-0123456789ab"), state, Os.Mac).isRight, true)
    // Holding the state root: XDG_STATE_HOME under the tree, or a symlinked tree resolving above it.
    val holding = state.getParent.getParent
    assertEquals(
      cachePathClearOfStateRoot(holding, state, Os.Mac), Left(Refusal.CachePathOverlapsStateRoot(holding, state)),
    )
    assert(cachePathClearOfStateRoot(Paths.get("/System/Volumes/Data" + holding.toString), state, Os.Mac).isLeft)
    // Under a state subtree: every project's caches would go with that project's --reset.
    assert(cachePathClearOfStateRoot(runOnHostCachesOf(state.resolve("tls/a-0123456789ab")), state, Os.Mac).isLeft)
    assert(cachePathClearOfStateRoot(state.resolve("image-build/x"), state, Os.Mac).isLeft)
    // The shared-root layout, %LOCALAPPDATA%\ko-agent-sandbox for both: the tree beside the subtrees.
    assertEquals(cachePathClearOfStateRoot(runOnHostCachesOf(state), state, Os.Windows).isRight, true)
    val sharedProject = runOnHostCachesOf(state).resolve("b-0123456789ab")
    assertEquals(cachePathClearOfStateRoot(sharedProject, state, Os.Mac), Right(sharedProject))

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
  // sbt and mill
  // --------------------------------------------------------------------------

  test("an sbt executable inside the install directory is accepted"):
    val executable = installDir.resolve("sbt")
    val known = exists(executable, installDir)
    assertEquals(validateSbtExecutable(executable, installDir, known, _ => true), Right(executable))
    assert(validateSbtExecutable(executable, installDir, exists(executable, installDir), _ => false).isLeft)

  test("a PATH symlink resolving into the install directory is accepted"):
    val linked = Paths.get("/usr/local/bin/sbt")
    val real = installDir.resolve("sbt")
    val canonical: Path => Option[Path] =
      path => if path == linked then Some(real) else exists(real, installDir)(path)
    assertEquals(validateSbtExecutable(linked, installDir, canonical, _ => true), Right(real))

  test("an sbt from anywhere else is refused"):
    val other = Paths.get("/usr/local/bin/sbt")
    assert(validateSbtExecutable(other, installDir, exists(other, installDir), _ => true).isLeft)

  private val distributionExec =
    coursierCache.resolve("arc/https/github.com/sbt/sbt/releases/download/v2.0.4/sbt-2.0.4.zip/sbt/bin/sbt")

  test("the distribution is read out of the script, not derived from a convention"):
    val script =
      s"""#!/usr/bin/env sh
         |exec "$distributionExec" "$$@"
         |""".stripMargin
    assertEquals(sbtDistribution(script, coursierCache), Some(distributionExec))

  test("the longest cache path wins, so a grant never applies to a prefix"):
    val script =
      s"""CACHE="$coursierCache"
         |exec "$distributionExec" "$$@"
         |""".stripMargin
    assertEquals(sbtDistribution(script, coursierCache), Some(distributionExec))

  test("a path escaping the cache root is not accepted"):
    val escaping = s"$coursierCache/../../../etc/passwd"
    assertEquals(sbtDistribution(s"""exec "$escaping"""", coursierCache), None)

  test("a script naming no cache path yields nothing rather than a guess"):
    assertEquals(sbtDistribution("#!/bin/sh\nexec /usr/local/bin/sbt \"$@\"\n", coursierCache), None)

  test("the distribution's sbt yields its home: <home>/bin/sbt, strictly inside arc"):
    val home = coursierCache.resolve("arc/sbt-2.0.4.zip/sbt")
    val inner = home.resolve("bin/sbt")
    val known = exists(inner, coursierCache)
    assertEquals(validateSbtDistribution(inner, coursierCache, known, _ => true), Right(home))
    assert(validateSbtDistribution(inner, coursierCache, known, _ => false).isLeft)
    val escaping: Path => Option[Path] =
      path => if path == inner then Some(Paths.get("/opt/sbt/bin/sbt")) else known(path)
    assert(validateSbtDistribution(inner, coursierCache, escaping, _ => true).isLeft)

  test("an executable whose home would be the cache root, arc, a v1 entry or a non-bin path is refused"):
    for bad <- Seq("bin/sbt", "arc/bin/sbt", "v1/x/bin/sbt", "arc/sbt-2.0.4.zip/sbt/sbt", "arc/x/bin/sbtn") do
      val inner = coursierCache.resolve(bad)
      assert(validateSbtDistribution(inner, coursierCache, exists(inner, coursierCache), _ => true).isLeft, clue(bad))

  test("mill needs the project's own bootstrap; a global mill is not a fallback"):
    val bootstrap = project.resolve("mill")
    assertEquals(validateMillBootstrap(project, _ == bootstrap), Right(bootstrap))
    assertEquals(validateMillBootstrap(project, _ => false), Left(Refusal.PrereqMillBootstrapMissing))

  private val millDownload = Paths.get(s"$home/.cache/mill/download")

  private def files(pairs: (String, Seq[String])*): Path => Option[Seq[String]] =
    val map = pairs.toMap
    path => map.get(project.relativize(path).toString)

  test("the mill download folder follows the bootstrap's own fallback"):
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
    assertEquals(millVersion(project, files(".mill-version" -> Seq("1.1.8"))), Right("1.1.8"))
    assertEquals(
      millVersion(project, files(".config/mill-version" -> Seq("1.1.8"))),
      Right("1.1.8"),
    )
    assertEquals(
      millVersion(project, files("build.mill.yaml" -> Seq("mill-version: 1.1.8"))),
      Right("1.1.8"),
    )
    assertEquals(
      millVersion(project, files("build.mill" -> Seq("//| mill-version: 1.1.8", "package build"))),
      Right("1.1.8"),
    )

  test("the bootstrap's own trimming is reproduced: quotes and trailing comments"):
    assertEquals(
      millVersion(project, files("build.mill.yaml" -> Seq("  mill-version: \"1.1.8\"  # pinned"))),
      Right("1.1.8"),
    )

  test("mill-jvm-version is system, one JVM id or unset, wherever mill would read it"):
    assertEquals(millJvm(project, files("build.mill.yaml" -> Seq("mill-jvm-version: system"))), Right(MillJvm.System))
    assertEquals(millJvm(project, files("build.mill" -> Seq("//| mill-jvm-version: system"))), Right(MillJvm.System))
    assertEquals(millJvm(project, files(".mill-jvm-version" -> Seq("system"))), Right(MillJvm.System))
    val pinned = Right(MillJvm.Pinned("temurin:25"))
    assertEquals(millJvm(project, files("build.mill.yaml" -> Seq("mill-jvm-version: temurin:25"))), pinned)
    assertEquals(millJvm(project, files("build.mill" -> Seq("//| mill-jvm-version: 'temurin:25' # LTS"))), pinned)
    assertEquals(millJvm(project, files(".mill-jvm-version" -> Seq("temurin:25"))), pinned)
    assertEquals(
      millJvm(project, files(".mill-jvm-version" -> Seq("graalvm-community:25.0.1"))),
      Right(MillJvm.Pinned("graalvm-community:25.0.1")),
    )
    assertEquals(millJvm(project, files("build.mill.yaml" -> Seq("extends: ScalaModule"))), Right(MillJvm.Unset))
    assertEquals(millJvm(project, files("build.mill" -> Seq("//| mill-version: 1.1.10", "package build"))),
      Right(MillJvm.Unset))
    assertEquals(millJvm(project, files()), Right(MillJvm.Unset))

  test("an unset mill-jvm-version is accepted under the launchers that resolve it to an id"):
    for accepted <- Seq("1.1.0-jvm", "1.1.10-jvm", "1.1.10", "1.2.0-RC1-jvm", "1.10.0-jvm", "2.0.0-jvm") do
      assertEquals(millUnsetJvmAccepted(MillJvm.Unset, accepted), Right(()), accepted)
    // 1.0 takes `java` from PATH or its built-in id, whichever its `which java` decides; a version
    // that is not two leading numbers is not known to be 1.1.0 or later.
    for refused <- Seq("1.0.6-jvm", "1.0.0", "0.12.14-jvm", "0.13.0-M2-jvm", "main-jvm", "1-jvm", "1.x-jvm", "") do
      assertEquals(
        millUnsetJvmAccepted(MillJvm.Unset, refused), Left(Refusal.PrereqMillJvmUnset(refused)), refused,
      )
      // A set version is mill's to read the same way under every launcher.
      assertEquals(millUnsetJvmAccepted(MillJvm.System, refused), Right(()), refused)
      assertEquals(millUnsetJvmAccepted(MillJvm.Pinned("temurin:25"), refused), Right(()), refused)
    val worded = wording(Refusal.PrereqMillJvmUnset("1.0.6-jvm"))
    assert(clue(worded).contains("1.0.6-jvm") && worded.contains("before mill 1.1.0") && worded.contains("`system`"))

  test("a mill-jvm-version that is neither system nor one id is refused as found"):
    // Digits alone are a number to YAML; a `|` chain, a list and an interpolation are not one id.
    for value <- Seq("25", "17.0.6", "system|temurin:25", "temurin:25:1", "[temurin:25]", "${JVM}", "temurin 25") do
      assertEquals(
        millJvm(project, files("build.mill.yaml" -> Seq(s"mill-jvm-version: $value"))),
        Left(Refusal.PrereqMillJvmUnreadable(value)),
      )
      assertEquals(millJvm(project, files(".mill-jvm-version" -> Seq(value))),
        Left(Refusal.PrereqMillJvmUnreadable(value)))

  test("the JVM source is mill's loadMillConfig order, the first existing file authoritative"):
    assertEquals(millJvm(project, files(".config/mill-jvm-version" -> Seq("system"))), Right(MillJvm.System))
    // .mill-jvm-version beats .config, which beats the header; an empty first file is the answer,
    // and mill reads no line of it as unset.
    val dotBeatsConfig = files(".mill-jvm-version" -> Seq("temurin:25"), ".config/mill-jvm-version" -> Seq("system"))
    assertEquals(millJvm(project, dotBeatsConfig), Right(MillJvm.Pinned("temurin:25")))
    val emptyFirst = files(".mill-jvm-version" -> Seq(""), "build.mill.yaml" -> Seq("mill-jvm-version: system"))
    assertEquals(millJvm(project, emptyFirst), Right(MillJvm.Unset))
    // Compared as written: mill keeps the opts-file line untrimmed and tests equality.
    assertEquals(millJvm(project, files(".mill-jvm-version" -> Seq(" system "))),
      Left(Refusal.PrereqMillJvmUnreadable(" system ")))
    // A key with no value is not unset; what mill makes of it is its parser's business.
    val noValue = millJvm(project, files("build.mill.yaml" -> Seq("mill-jvm-version:")))
    assertEquals(noValue, Left(Refusal.PrereqMillJvmUnreadable("")))
    assert(clue(wording(Refusal.PrereqMillJvmUnreadable(""))).endsWith("found an empty value"))
    assertEquals(millJvm(project, files(".mill-jvm-version" -> Seq("# comment", "", "system"))), Right(MillJvm.System))
    // A nested YAML key is not the key; a //| line after the header is not the header.
    assertEquals(
      millJvm(project, files("build.mill.yaml" -> Seq("mill-build:", "  mill-jvm-version: system"))),
      Right(MillJvm.Unset),
    )
    // Refused as a stray //| line: readBuildHeader scans the whole file and errors on it.
    assert(millJvm(project, files("build.mill" -> Seq("package build", "//| mill-jvm-version: system"))).isLeft)
    val quoted = files("build.mill.yaml" -> Seq("mill-jvm-version: \"system\" # x"))
    assertEquals(millJvm(project, quoted), Right(MillJvm.System))
    // Not system, whatever a lax reader would strip: a YAML comment needs whitespace before its
    // #, and an unmatched quote is not the plain scalar.
    for bad <- Seq("mill-jvm-version: system#other", "mill-jvm-version: \"system", "mill-jvm-version: system'") do
      assert(millJvm(project, files("build.mill.yaml" -> Seq(bad))).isLeft, clue(bad))
    // YAML's `key:value` is one scalar, not a mapping: mill never sees the key.
    assertEquals(millJvm(project, files("build.mill.yaml" -> Seq("mill-jvm-version:system"))), Right(MillJvm.Unset))
    // A malformed //| line is an error in mill's readBuildHeader, and a refusal here; so is a
    // stray //| after the header, and so are two keys, whichever mill's map would keep.
    assert(millJvm(project, files("build.mill" -> Seq("//|mill-jvm-version: system"))).isLeft)
    val stray = files("build.mill" -> Seq("//| mill-jvm-version: system", "package build", "//| x"))
    assert(millJvm(project, stray).isLeft)
    // A second YAML document is one mill never reads; a marker anywhere is a refusal.
    val secondDoc = files("build.mill.yaml" -> Seq("extends: ScalaModule", "---", "mill-jvm-version: system"))
    assertEquals(millJvm(project, secondDoc), Left(Refusal.PrereqMillJvmUnreadable("multi-document YAML")))
    val headerDoc = files("build.mill" -> Seq("//| mill-jvm-version: system", "//| ..."))
    assert(millJvm(project, headerDoc).isLeft)
    // A commented marker is still a marker; an indented or embedded one is not.
    val commented = files("build.mill.yaml" -> Seq("--- # next", "mill-jvm-version: system"))
    assertEquals(millJvm(project, commented), Left(Refusal.PrereqMillJvmUnreadable("multi-document YAML")))
    val dashesInValue = files("build.mill.yaml" -> Seq("mill-jvm-version: system", "x: --- y"))
    assertEquals(millJvm(project, dashesInValue), Right(MillJvm.System))
    val doubled = files("build.mill.yaml" -> Seq("mill-jvm-version: system", "mill-jvm-version: temurin:25"))
    assertEquals(millJvm(project, doubled),
      Left(Refusal.PrereqMillJvmUnreadable("duplicate mill-jvm-version keys")))
    // build.mill.yaml is consulted before build.mill, and one existing root file ends the search.
    val yamlFirst =
      files("build.mill.yaml" -> Seq("extends: ScalaModule"), "build.mill" -> Seq("//| mill-jvm-version: system"))
    assertEquals(millJvm(project, yamlFirst), Right(MillJvm.Unset))

  test("no version anywhere is a refusal"):
    assertEquals(millVersion(project, files()), Left(Refusal.PrereqMillVersionUnpinned))
    assertEquals(
      millVersion(project, files(".mill-version" -> Seq(""))),
      Left(Refusal.PrereqMillVersionUnpinned),
    )

  private val bootstrap = Seq(
    "#!/usr/bin/env sh",
    """if [ -z "${DEFAULT_MILL_VERSION}" ] ; then DEFAULT_MILL_VERSION="1.1.8"; fi""",
  )

  test("with nothing else pinned, the version is the bootstrap's own DEFAULT_MILL_VERSION"):
    assertEquals(millVersion(project, files("mill" -> bootstrap)), Right("1.1.8"))
    // A pin anywhere in the chain wins over the default, as in the script.
    val pinned = files("mill" -> bootstrap, ".mill-version" -> Seq("1.1.7"))
    assertEquals(millVersion(project, pinned), Right("1.1.7"))
    val noDefault = files("mill" -> Seq("#!/bin/sh"))
    assertEquals(millVersion(project, noDefault), Left(Refusal.PrereqMillVersionUnpinned))

  test("the first existing file decides, empty or not: the bootstrap's elif chain has no fall-through"):
    assertEquals(
      millVersion(project, files(".mill-version" -> Seq(""), "build.mill.yaml" -> Seq("mill-version: 1.1.8"))),
      Left(Refusal.PrereqMillVersionUnpinned),
    )
    // An empty chain result falls to the default, as the script's `if [ -z "$MILL_VERSION" ]` does.
    assertEquals(
      millVersion(project, files(".mill-version" -> Seq(""), "mill" -> bootstrap)),
      Right("1.1.8"),
    )
    // build.mill exists and has no marker: build.mill.scala is never consulted.
    assertEquals(
      millVersion(
        project,
        files("build.mill" -> Seq("package build"), "build.mill.scala" -> Seq("//| mill-version: 1.1.8")),
      ),
      Left(Refusal.PrereqMillVersionUnpinned),
    )
    assertEquals(millVersion(project, files("build.sc" -> Seq("//| mill-version: 0.11.5"))), Right("0.11.5"))
    // grep's `//\|.*mill-version`: the marker before the key, never after it.
    assertEquals(
      millVersion(project, files("build.mill" -> Seq("mill-version//|: 1.1.8"))),
      Left(Refusal.PrereqMillVersionUnpinned),
    )

  test("canonical paths compare exactly: a case-sensitive volume keeps coursier and Coursier apart"):
    val sibling = Paths.get(s"$home/Library/Caches/coursier/arc/jdk/Contents/Home")
    val binary = sibling.resolve("bin/java")
    val known = exists(sibling, binary, coursierCache)
    assert(resolveJdkHome(env("JAVA_HOME" -> sibling.toString), coursierCache, known, _ => true).isLeft)

  test("two markers are no version, and a version file's whitespace is kept as the script keeps it"):
    assertEquals(
      millVersion(project, files("build.mill.yaml" -> Seq("mill-version: 1.1.8", "mill-version: 1.1.9"))),
      Left(Refusal.PrereqMillVersionUnpinned),
    )
    assertEquals(
      millVersion(project, files(".mill-version" -> Seq("1.1.8 "))),
      Left(Refusal.PrereqMillVersionUnpinned),
    )

  test("a version that could name a path other than a directory entry is refused"):
    for bad <- Seq("../../etc", "a/b", "1.1.8 --flag") do
      assertEquals(
        millVersion(project, files(".mill-version" -> Seq(bad))),
        Left(Refusal.PrereqMillVersionUnpinned),
        clue(bad),
      )

  test("the launcher is the JVM one for a bare or -jvm pin; a -native pin is refused by name"):
    assertEquals(millLauncherVersion("1.1.9"), Right("1.1.9-jvm"))
    assertEquals(millLauncherVersion("1.1.9-jvm"), Right("1.1.9-jvm"))
    assertEquals(millLauncherVersion("1.1.9-native"), Left(Refusal.PrereqMillNativeLauncher("1.1.9-native")))
    val worded = wording(Refusal.PrereqMillNativeLauncher("1.1.9-native"))
    assert(worded.contains("`1.1.9`") && worded.contains("`1.1.9-jvm`"), worded)

  test("a provisioned launcher is the bootstrap's file for a -jvm pin, present and executable"):
    val executable = millDownload.resolve("1.1.9")
    assertEquals(millExecutable(millDownload, "1.1.9-jvm", _ == executable), Right(executable))
    // A similarly prefixed neighbour is not it.
    assertEquals(
      millExecutable(millDownload, "1.1.9-jvm", _ == millDownload.resolve("1.1.9-native-mac-aarch64")),
      Left(Refusal.PrereqMillExecutableMissing("1.1.9-jvm", millDownload)),
    )

  test("an unprovisioned launcher is a refusal naming the host command that provisions it"):
    val refusal = millExecutable(millDownload, "1.2.0-jvm", _ => false)
    assertEquals(refusal, Left(Refusal.PrereqMillExecutableMissing("1.2.0-jvm", millDownload)))
    assert(wording(refusal.swap.toOption.get).contains("MILL_VERSION=1.2.0-jvm ./mill version"))

  test("a pinned or unset mill-jvm-version runs on the JDK mill's java-home file records, checked as JAVA_HOME is"):
    val present = exists(jdkHome, javaBinary, coursierCache)
    def recordedJdk(id: Option[String], recorded: Option[String], canonicalize: Path => Option[Path]) =
      millRecordedJdk(id, "1.1.10-jvm", recorded, coursierCache, canonicalize, _ == javaBinary)
    def pinnedJdk(recorded: Option[String], canonicalize: Path => Option[Path] = present) =
      recordedJdk(Some("temurin:25"), recorded, canonicalize)
    def unsetJdk(recorded: Option[String], canonicalize: Path => Option[Path] = present) =
      recordedJdk(None, recorded, canonicalize)
    def recorded(key: String, home: Any) = Some(s"""["$key","$home"]""")
    val key = "temurin:25:0.0.4-162-4be9be:"
    assertEquals(pinnedJdk(recorded(key, jdkHome)), Right(jdkHome))
    assertEquals(pinnedJdk(recorded("temurin:25:0.0.4-162-4be9be:https://r.example", jdkHome)), Right(jdkHome))
    // Absent, recording another id, or not the pair mill writes: the host run provisions it.
    val missing = Left(Refusal.PrereqMillJdkMissing(Some("temurin:25"), "1.1.10-jvm"))
    val unsetMissing = Left(Refusal.PrereqMillJdkMissing(None, "1.1.10-jvm"))
    assertEquals(pinnedJdk(None), missing)
    assertEquals(unsetJdk(None), unsetMissing)
    assertEquals(pinnedJdk(recorded("temurin:21:0.0.4-162-4be9be:", jdkHome)), missing)
    assertEquals(pinnedJdk(recorded("temurin:251:0.0.4-162-4be9be:", jdkHome)), missing)
    // The id of an unset version is the launcher's own, so the home is taken under any key.
    for anyKey <- Seq("zulu:21:0.0.4-162-4be9be:", "zulu:21:0.0.4-125-77e06d", key) do
      assertEquals(unsetJdk(recorded(anyKey, jdkHome)), Right(jdkHome), anyKey)
    for malformed <- Seq("", "{}", s"""["$key"]""", s"""["$key","$jdkHome"]\n""", s"""["$key","$jdkHome","x"]""",
        s"""["$key","/a\\u002fb"]""")
    do
      assertEquals(pinnedJdk(Some(malformed)), missing, malformed)
      assertEquals(unsetJdk(Some(malformed)), unsetMissing, malformed)
    // A command can write the file: a home outside the Coursier cache, a relative one, the cache's
    // own directories and a home whose bin/java leads out of it are not granted.
    val notCoursier = Left(Refusal.PrereqMillJdkNotCoursier(Some("temurin:25"), "1.1.10-jvm", coursierCache))
    val unsetNotCoursier = Left(Refusal.PrereqMillJdkNotCoursier(None, "1.1.10-jvm", coursierCache))
    val planted = project.resolve("jdk")
    val everything: Path => Option[Path] = path => Some(path.normalize())
    assertEquals(pinnedJdk(recorded(key, planted), everything), notCoursier)
    assertEquals(unsetJdk(recorded(key, planted), everything), unsetNotCoursier)
    assertEquals(pinnedJdk(recorded(key, "Library/Caches/Coursier/arc/jdk"), everything), notCoursier)
    assertEquals(pinnedJdk(recorded(key, coursierCache.resolve("arc")), everything), notCoursier)
    assertEquals(pinnedJdk(recorded(key, jdkHome), exists(coursierCache)), notCoursier)
    val escaping: Path => Option[Path] =
      path => if path == javaBinary then Some(planted.resolve("bin/java")) else Some(path.normalize())
    assertEquals(pinnedJdk(recorded(key, jdkHome), escaping), notCoursier)
    assertEquals(unsetJdk(recorded(key, jdkHome), escaping), unsetNotCoursier)

  test("the daemon configuration changes with what Mill restarts on, from the source Mill selects"):
    val pinned = Seq("mill-version: 1.1.9", "mill-jvm-version: system")
    def yaml(extra: String*) = files("build.mill.yaml" -> (pinned ++ extra))
    def yamlAnd(extra: (String, Seq[String])*) = files(("build.mill.yaml" -> pinned) +: extra*)
    val baseConfig = millDaemonConfig(project, yaml("extends: ScalaModule"))
    assertEquals(baseConfig, millDaemonConfig(project, yaml("extends: ScalaModule")), "deterministic")
    // The header is taken whole: an edit outside the keys restarts too, the cheaper error.
    assertNotEquals(millDaemonConfig(project, yaml("extends: JavaModule")), baseConfig)
    // Each key, from each of its sources.
    assertNotEquals(millDaemonConfig(project, yaml("mill-jvm-opts:", "  - -Xmx1g")), baseConfig)
    val dotOpts = millDaemonConfig(project, yamlAnd(".mill-jvm-opts" -> Seq("-Xmx1g")))
    val configOpts = millDaemonConfig(project, yamlAnd(".config/mill-jvm-opts" -> Seq("-Xmx1g")))
    assertNotEquals(dotOpts, baseConfig)
    assertNotEquals(configOpts, baseConfig)
    // An empty file is a source Mill selects, over the header: creating one, in either place,
    // changes the configuration, and so does removing it.
    val headerOpts = yaml("mill-jvm-opts: [-Xmx1g]")
    for empty <- Seq(".mill-jvm-opts", ".config/mill-jvm-opts", ".mill-repositories", ".config/mill-repositories") do
      val withEmpty = files(("build.mill.yaml" -> (pinned :+ "mill-jvm-opts: [-Xmx1g]")) , empty -> Seq.empty)
      assertNotEquals(millDaemonConfig(project, withEmpty), millDaemonConfig(project, headerOpts), empty)
    // One file's lines never read as another's.
    assertNotEquals(
      millDaemonConfig(project, yamlAnd(".mill-jvm-opts" -> Seq("-Xmx1g", "-Xss1m"))),
      millDaemonConfig(project, yamlAnd(".mill-jvm-opts" -> Seq("-Xmx1g"), ".mill-repositories" -> Seq("-Xss1m"))),
    )
    assertNotEquals(millDaemonConfig(project, yaml("mill-repositories: [https://r.example]")), baseConfig)
    val version = files("build.mill.yaml" -> Seq("mill-version: 1.1.8", "mill-jvm-version: system"))
    assertNotEquals(millDaemonConfig(project, version), baseConfig)
    val jvm = files("build.mill.yaml" -> Seq("mill-version: 1.1.9", "mill-jvm-version: temurin:25"))
    assertNotEquals(millDaemonConfig(project, jvm), baseConfig)
    // Under a pinned or unset mill-jvm-version the java-home file's text is the JDK the daemon runs
    // on; under system mill does not read the file.
    val recordedHome = Some("""["temurin:25:0.0.4:","/jdk-25"]""")
    assertNotEquals(millDaemonConfig(project, jvm, recordedHome), millDaemonConfig(project, jvm))
    assertNotEquals(
      millDaemonConfig(project, jvm, recordedHome),
      millDaemonConfig(project, jvm, Some("""["temurin:25:0.0.4:","/jdk-21"]""")),
    )
    assertEquals(millDaemonConfig(project, yaml("extends: ScalaModule"), recordedHome), baseConfig)
    val unset = files("build.mill.yaml" -> Seq("mill-version: 1.1.9"))
    assertNotEquals(millDaemonConfig(project, unset, recordedHome), millDaemonConfig(project, unset))
    assertNotEquals(
      millDaemonConfig(project, unset, recordedHome),
      millDaemonConfig(project, unset, Some("""["zulu:21:0.0.4:","/jdk-21"]""")),
    )
    // A key in a spelling only a YAML parser recognizes changes it all the same.
    assertNotEquals(
      millDaemonConfig(project, yaml("\"mill-jvm-\\u006fpts\": [-Xmx1g]")),
      millDaemonConfig(project, yaml("\"mill-jvm-\\u006fpts\": [-Xmx2g]")),
    )
    // The header of build.mill is its //| lines, and the body is not the header.
    def header(opt: String, body: String*) =
      val lines = Seq("//| mill-version: 1.1.9", "//| mill-jvm-opts:", s"//| - $opt", "package build")
      files("build.mill" -> (lines ++ body))
    assertNotEquals(millDaemonConfig(project, header("-Xmx1g")), millDaemonConfig(project, header("-Xmx2g")))
    assertEquals(millDaemonConfig(project, header("-Xmx1g")), millDaemonConfig(project, header("-Xmx1g", "object x")))

  // --------------------------------------------------------------------------
  // The channel's working directory
  // --------------------------------------------------------------------------

  // The project is mounted at its own path, so the mount is the project's spelling; the value
  // still arrives from inside the container and is validated as such.
  private def cwd(requested: String, canonical: Path => Option[Path] = path => Some(path.normalize())) =
    workingDirectory(requested, project.toString, project, canonical, Os.Mac)

  test("the mount root translates to the project root"):
    assertEquals(cwd(project.toString), Right(project))

  test("a subdirectory translates beneath the project"):
    assertEquals(cwd(s"$project/modules/a"), Right(project.resolve("modules/a")))

  test("climbing out of the mount is refused, not clamped"):
    for requested <- Seq(s"$project/../..", s"$project/../../etc", s"$project/a/../../..") do
      assert(cwd(requested).isLeft, clue(requested))

  test("a path outside the mount is refused"):
    for requested <- Seq("/etc", "/Users/kenichi", s"${project}x", project.getFileName.toString + "/a", "") do
      assert(cwd(requested).isLeft, clue(requested))

  test("a symlink inside the project that leaves it is refused"):
    // The textual check passes and the canonical one does not: why both run.
    val escaping = project.resolve("link")
    val canonical: Path => Option[Path] =
      path => if path == escaping then Some(Paths.get("/etc")) else Some(path.normalize())
    assert(cwd(s"$project/link", canonical).isLeft)

  test("a canonical case-different sibling is outside the project; a lexical one still folds"):
    // Canonical spellings are the volume's own: on a case-sensitive volume `Ko-Agent-Sandbox` is
    // another directory. The lexical check before canonicalization keeps folding, since a request
    // on a folding volume may arrive in either case.
    val sibling = Paths.get(s"$home/Ko-Agent-Sandbox/sub")
    assert(cwd(s"$project/sub", _ => Some(sibling)).isLeft)
    // Lexically a case-different spelling of the project itself, which the real filesystem folds.
    val folded = cwd(s"$project/../KO-AGENT-SANDBOX/sub", _ => Some(project.resolve("sub")))
    assertEquals(folded, Right(project.resolve("sub")))

  test("a canonical case-different sibling of the project is a safe cache root"):
    val sibling = Paths.get(s"$home/Ko-Agent-Sandbox/.cache")
    assertEquals(cacheRootOutsideProject(sibling, project, Os.Mac, Right(_)), Right(sibling))

  test("a working directory that does not exist is refused"):
    assert(cwd(s"$project/gone", _ => None).isLeft)

  test("a refusal names what was requested, so the diagnostic can quote it"):
    assertEquals(cwd("/etc/passwd"), Left(Refusal.WorkingDirectoryOutsideProject("/etc/passwd")))

  // --------------------------------------------------------------------------
  // The command's temporary directory
  // --------------------------------------------------------------------------

  test("the command's temporary path budget is what sbt's boot socket leaves of sun_path"):
    assertEquals(SessionTmpMaxLength, 53)
    val fits = Paths.get("/private/tmp/" + "y" * 40)
    val traps = Paths.get("/private/tmp/" + "y" * 43)
    assertEquals(sessionTmpFits(fits), Right(fits))
    assertEquals(sessionTmpFits(traps), Left(Refusal.SessionTmpTooLong(traps, 53)))
    // The macOS per-user temporary directory is 49 characters before anything is added to it, so
    // a command directory under it can never fit; the supervisor's root is elsewhere.
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

  // --------------------------------------------------------------------------
  // The program's egress rule file
  // --------------------------------------------------------------------------

  test("the program's rule file accepts read lines, comments and blank lines, in file order, once each"):
    val text =
      """# artifact repositories this project resolves from
        |allow https://repo.example.org/ read
        |
        |allow https://mirror.example.org/ read  # inline comment
        |allow https://repo.example.org/ read
        |""".stripMargin
    assertEquals(
      programRuleHosts(text),
      Right(Vector("repo.example.org", "mirror.example.org")),
    )

  test("an empty or comment-only rule file is valid and contributes nothing"):
    for text <- Seq("", "\n\n", "# nothing yet\n") do
      assertEquals(programRuleHosts(text), Right(Vector.empty))

  test("every line of the proxy's wider grammar is outside the file's"):
    for
      line <- Seq(
        "deny defaults",
        "allow model-provider openai",
        "deny model-provider openai",
        "allow https://repo.example.org/ read git-fetch",
        "allow https://repo.example.org/ git-fetch",
        "allow https://repo.example.org/ tunnel",
        "allow https://repo.example.org/ method=POST",
        "allow https://repo.example.org/",
        "allow https://repo.example.org/maven2/ read",
        "allow https://repo.example.org read",
        "allow https://**.example.org/ read",
        "allow https://repo.example.org/ read#typo",
        "allow https://repo.example.org/#x read",
        "allow#x https://repo.example.org/ read",
        "allow https:///read read",
        "deny https://repo.example.org/",
        "+host repo.example.org",
        "repo.example.org",
        "allow",
      )
    do
      programRuleHosts(line) match
        case Left(Refusal.RuleOutsideProgramGrammar(seen)) => assertEquals(seen, line)
        case other => fail(s"'$line' -> $other")

  test("a refused line names itself even after a comment is stripped"):
    assertEquals(
      programRuleHosts("deny https://x/ # a removal\n"),
      Left(Refusal.RuleOutsideProgramGrammar("deny https://x/")),
    )
    // A comment starts at a token, as in the proxy: a `#` inside one is the line, not a comment.
    assertEquals(
      programRuleHosts("allow https://repo.example.org/ read#comment\n"),
      Left(Refusal.RuleOutsideProgramGrammar("allow https://repo.example.org/ read#comment")),
    )
    assertEquals(programRuleHosts("allow https://repo.example.org/ read #comment\n"), Right(Vector("repo.example.org")))

  test("the composed rule input is the whole ruleset: deny defaults, Maven Central, then the file"):
    assertEquals(
      egressRuleText(Program.Sbt, Vector("repo.example.org")),
      "deny defaults\nallow https://repo1.maven.org/ read\nallow https://repo.example.org/ read",
    )

  test("a file restating Maven Central composes it once"):
    assertEquals(
      egressRuleText(Program.Sbt, Vector("repo1.maven.org")),
      "deny defaults\nallow https://repo1.maven.org/ read",
    )

  test("the sbt global base and Ivy home sit beside the project's Coursier cache, one --reset-run-on-host removal"):
    val cacheRoot = Paths.get("/Users/u/.cache/ko-agent-sandbox")
    assertEquals(
      sbtGlobalOf(cacheRoot, "proj-abc123"),
      Paths.get("/Users/u/.cache/ko-agent-sandbox/run-on-host/proj-abc123/sbt-global"),
    )
    assertEquals(
      ivyHomeOf(cacheRoot, "proj-abc123"),
      Paths.get("/Users/u/.cache/ko-agent-sandbox/run-on-host/proj-abc123/ivy-home"),
    )
    assertEquals(
      m2RepositoryOf(cacheRoot, "proj-abc123"),
      Paths.get("/Users/u/.cache/ko-agent-sandbox/run-on-host/proj-abc123/m2/repository"),
    )
    for cache <- Seq(sbtGlobalOf(cacheRoot, "proj-abc123"), ivyHomeOf(cacheRoot, "proj-abc123"),
        m2RepositoryOf(cacheRoot, "proj-abc123").getParent)
    do assertEquals(cache.getParent, coursierV1Of(cacheRoot, "proj-abc123").getParent.getParent)

  test("the central host is the program's own: Coursier's for sbt and mill, the alias for gradle and mvn"):
    assertEquals(centralHost(Program.Sbt), "repo1.maven.org")
    assertEquals(centralHost(Program.Mill), "repo1.maven.org")
    assertEquals(centralHost(Program.Gradle), "repo.maven.apache.org")
    assertEquals(centralHost(Program.Mvn), "repo.maven.apache.org")
    assertEquals(egressRuleText(Program.Mvn, Vector.empty), "deny defaults\nallow https://repo.maven.apache.org/ read")

  // --------------------------------------------------------------------------
  // Gradle
  // --------------------------------------------------------------------------

  private val gradleUrl = "https://services.gradle.org/distributions/gradle-9.7.1-bin.zip"
  private val wrapperDir = project.resolve("gradle/wrapper")

  test("the distribution URL is read as the wrapper reads it: Properties escapes, defaults, relative files"):
    def read(text: String, projectProperties: Option[String] = None) =
      gradleDistributionUrl(text, wrapperDir, projectProperties)
    assertEquals(read(s"distributionUrl=$gradleUrl\n"), Right(URI(gradleUrl)))
    assertEquals(read("distributionBase=GRADLE_USER_HOME\ndistributionPath=wrapper/dists\n" +
      "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.7.1-bin.zip\n"), Right(URI(gradleUrl)))
    // A `!` comment line, a key with spaces around `=`, a value continued over a line: Properties' grammar.
    assertEquals(
      read("! wrapper\ndistributionUrl = https://services.gradle.org/\\\n    distributions/gradle-9.7.1-bin.zip\n"),
      Right(URI(gradleUrl)),
    )
    // No scheme: a file relative to the properties file's directory, spelled as File.toURI spells it.
    assertEquals(
      read("distributionUrl=../../dist/gradle-9.7.1-bin.zip"),
      Right(java.io.File(wrapperDir.toFile, "../../dist/gradle-9.7.1-bin.zip").toURI),
    )
    assertEquals(read("distributionSha256Sum=abc\n"),
      Left(Refusal.PrereqGradleWrapperUnreadable("no distributionUrl in gradle/wrapper/gradle-wrapper.properties")))
    assert(read(s"distributionUrl=$gradleUrl\ndistributionBase=PROJECT\n").swap.exists(wording(_).contains("PROJECT")))
    assert(read(s"distributionUrl=$gradleUrl\ndistributionPath=dists\n").swap.exists(wording(_).contains("dists")))
    assert(read(s"distributionUrl=$gradleUrl\n", Some("systemProp.gradle.user.home=/elsewhere\n")).swap
      .exists(wording(_).contains("systemProp.gradle.user.home")))
    assertEquals(read(s"distributionUrl=$gradleUrl\n", Some("org.gradle.jvmargs=-Xmx1g\n")), Right(URI(gradleUrl)))
    assert(read("distributionUrl=mailto:x@example.org\n").swap.exists(wording(_).contains("names no file")))
    assert(read("distributionUrl=https://example.org/\n").swap.exists(wording(_).contains("names no file")))
    assert(read("distributionUrl=https://example.org/a b.zip\n").swap.exists(wording(_).contains("not a URI")))
    // A control character never reaches the terminal through a refusal, whatever branch quotes the value.
    for
      text <- Seq(
        "distributionUrl=https://x.example/\u001b[31ma.zip\n",
        s"distributionUrl=$gradleUrl\ndistributionBase=\u001b[31mX\n",
      )
    do
      val refused = read(text)
      assert(refused.swap.exists(refusal => !wording(refusal).contains("\u001b")), refused.toString)
    assert(read("distributionUrl=\\u12\n").swap.exists(wording(_).contains("malformed")))

  test("the Gradle user home is GRADLE_USER_HOME, else ~/.gradle, as the wrapper takes it"):
    assertEquals(gradleUserHome(env("HOME" -> home)), Some(Paths.get(s"$home/.gradle")))
    assertEquals(
      gradleUserHome(env("HOME" -> home, "GRADLE_USER_HOME" -> "/opt/gradle")),
      Some(Paths.get("/opt/gradle")),
    )

  test("the distribution directory is the wrapper's: the name without its extension, then the URL's MD5 in base 36"):
    val userHome = Paths.get(s"$home/.gradle")
    val dists = userHome.resolve("wrapper/dists")
    val bin = dists.resolve("gradle-9.7.1-bin/1w1c7tv4s851m17nbqdsro2tv")
    assertEquals(gradleDistributionDir(userHome, URI(gradleUrl)), bin)
    // The hash is over the URL without its user information (Download.safeUri), so a credential
    // in the URL changes nothing.
    val withCredential = URI("https://user:pw@services.gradle.org/distributions/gradle-9.7.1-bin.zip")
    assertEquals(gradleDistributionDir(userHome, withCredential), bin)
    val all = URI("https://services.gradle.org/distributions/gradle-9.7.1-all.zip")
    assertEquals(gradleDistributionDir(userHome, all), dists.resolve("gradle-9.7.1-all/62v79ucs7za836kmh1huc3s8x"))

  test("the home is the one directory inside, provisioned; else a refusal naming what ./gradlew would fix"):
    val dir = Paths.get(s"$home/.gradle/wrapper/dists/gradle-9.7.1-bin/1w1c7tv4s851m17nbqdsro2tv")
    val gradleHome = dir.resolve("gradle-9.7.1")
    val executable = gradleHome.resolve("bin/gradle")
    assertEquals(gradleDistributionHome(dir, URI(gradleUrl), _ => Seq(gradleHome), _ == executable), Right(gradleHome))
    val missing = Refusal.PrereqGradleDistributionMissing(gradleUrl, dir)
    assertEquals(gradleDistributionHome(dir, URI(gradleUrl), _ => Seq.empty, _ == executable), Left(missing))
    assertEquals(gradleDistributionHome(dir, URI(gradleUrl), _ => Seq(gradleHome), _ => false), Left(missing))
    assertEquals(
      gradleDistributionHome(dir, URI(gradleUrl), _ => Seq(gradleHome, dir.resolve("other")), _ == executable),
      Left(missing),
    )
    assert(wording(missing).contains("./gradlew --version"))

  // --------------------------------------------------------------------------
  // Maven
  // --------------------------------------------------------------------------

  private val mvnUrl =
    "https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.16/apache-maven-3.9.16-bin.zip"

  test("mvn needs the project's own wrapper; a global mvn is not a fallback"):
    val wrapper = project.resolve("mvnw")
    assertEquals(validateMvnWrapper(project, _ == wrapper), Right(wrapper))
    assertEquals(validateMvnWrapper(project, _ => false), Left(Refusal.PrereqMvnWrapperMissing))

  test("only the only-script wrapper, recognized by the script that runs; any other type is refused"):
    assertEquals(validateMvnWrapperScript(Seq("#!/bin/sh", "hash_string() {", "}")), Right(()))
    assertEquals(
      validateMvnWrapperScript(Seq("#!/bin/sh", "exec java -classpath .mvn/wrapper/maven-wrapper.jar")),
      Left(Refusal.PrereqMvnWrapperNotOnlyScript),
    )

  test("the distribution URL is read as the script reads it, MVNW_REPOURL applied"):
    def read(lines: String*) = mvnDistributionUrl(lines.mkString("", "\n", "\n"), None)
    assertEquals(read("wrapperVersion=3.3.4", s"distributionUrl= $mvnUrl "), Right(mvnUrl))
    // The key is matched exactly; the value loses every whitespace character, inside included;
    // the last line wins; a last line without a newline is never read.
    assert(read(s" distributionUrl=$mvnUrl").isLeft)
    assertEquals(
      read("distributionUrl=https://x.example/apache -\tmaven-3.9.16-bin.zip"),
      Right("https://x.example/apache-maven-3.9.16-bin.zip"),
    )
    assertEquals(read("distributionUrl=https://first.example/a-bin.zip", s"distributionUrl=$mvnUrl"), Right(mvnUrl))
    assert(mvnDistributionUrl(s"distributionUrl=$mvnUrl", None).isLeft)
    assertEquals(mvnDistributionUrl(s"distributionUrl=$mvnUrl\r\n", None), Right(mvnUrl))
    // The shell takes the line as is, escapes included, and hashes it as is.
    val escaped = mvnUrl.replace(":", "\\:")
    assertEquals(read(s"distributionUrl=$escaped"), Right(escaped))
    assertEquals(
      mvnDistributionUrl(s"distributionUrl=$mvnUrl\n", Some("https://mirror.example/repo")),
      Right("https://mirror.example/repo/org/apache/maven/apache-maven/3.9.16/apache-maven-3.9.16-bin.zip"),
    )
    // The script's `${distributionUrl#*"$pattern"}` strips nothing when the pattern is absent.
    assertEquals(
      mvnDistributionUrl("distributionUrl=https://x.example/apache-maven-3.9.16-bin.zip\n", Some("https://m.example")),
      Right("https://m.example/org/apache/maven/https://x.example/apache-maven-3.9.16-bin.zip"),
    )
    assertEquals(mvnDistributionUrl(s"distributionUrl=$mvnUrl\n", Some("")), Right(mvnUrl))
    assert(read("wrapperVersion=3.3.4").isLeft)
    assert(read("distributionUrl=https://example.org/apache-maven-3.9.16.zip").isLeft)
    assert(read("distributionUrl=https://example.org/mavén-bin.zip").isLeft)
    // tr's [:space:] is six ASCII characters: a control character stays, and Java's wider
    // notion of whitespace must not remove what tr keeps.
    assert(read("distributionUrl=https://example.org/apache\u001c-maven-3.9.16-bin.zip").isLeft)
    assertEquals(
      read("distributionUrl=https://example.org/apache\u000b-maven-3.9.16-bin.zip"),
      Right("https://example.org/apache-maven-3.9.16-bin.zip"),
    )
    // The effective URL is what is checked: a mirror that breaks the URL is refused.
    assert(mvnDistributionUrl(s"distributionUrl=$mvnUrl\n", Some("https://mirrör.example")).isLeft)
    val mvnd = "https://example.org/maven/mvnd/1.0.2/maven-mvnd-1.0.2-bin.zip"
    assertEquals(read(s"distributionUrl=$mvnd"), Left(Refusal.PrereqMvnDistributionIsMvnd(mvnd)))
    // A refusal quotes a URL only once it is printable ASCII, so no control character reaches
    // the terminal through it — through the mvnd branch, the -bin.zip branch, or MVNW_REPOURL.
    for value <- Seq(s"https://x.example/\u001b[31mmaven-mvnd-1.0.2-bin.zip", "https://x.example/\u001b[31ma.zip") do
      val refused = read(s"distributionUrl=$value")
      assert(refused.left.exists(refusal => !wording(refusal).contains('\u001b')), refused.toString)
    val badMirror = mvnDistributionUrl(s"distributionUrl=$mvnUrl\n", Some("https://\u001b[31mm.example"))
    assert(badMirror.left.exists(refusal => !wording(refusal).contains('\u001b')), badMirror.toString)

  test("the distribution directory is the script's own derivation, hash function included"):
    val m2 = Paths.get("/Users/kenichi/.m2")
    // The vector is String.hashCode computed with Java 25, which the script's hash_string reproduces.
    assertEquals(mvnDistributionDir(m2, mvnUrl), m2.resolve("wrapper/dists/apache-maven-3.9.16/56ba1f9f"))

  test("the home is that directory, provisioned; else a refusal naming what ./mvnw would fix"):
    val derived = Paths.get("/Users/kenichi/.m2/wrapper/dists/apache-maven-3.9.16/56ba1f9f")
    assertEquals(mvnDistributionHome(derived, mvnUrl, _ == derived.resolve("bin/mvn")), Right(derived))
    assertEquals(
      mvnDistributionHome(derived, mvnUrl, _ => false),
      Left(Refusal.PrereqMvnDistributionMissing(mvnUrl, derived)),
    )
    assert(wording(Refusal.PrereqMvnDistributionMissing(mvnUrl, derived)).contains("./mvnw --version"))

  test("every refusal is worded for the blocked reader, never through its enum spelling"):
    val cases = Seq(
      Refusal.PrereqJvmNotCoursier("/usr/bin/java"), Refusal.PrereqSbtNotCoursier(Paths.get("/usr/local/bin/sbt")),
      Refusal.PrereqMillBootstrapMissing, Refusal.PrereqMillVersionUnpinned,
      Refusal.PrereqMillExecutableMissing("1.1.8", millDownload), Refusal.PrereqMillJvmUnreadable("25"),
      Refusal.PrereqMillJvmUnset("1.0.6-jvm"),
      Refusal.PrereqMillJdkMissing(Some("temurin:25"), "1.1.8-jvm"), Refusal.PrereqMillJdkMissing(None, "1.1.8-jvm"),
      Refusal.PrereqMillJdkNotCoursier(Some("temurin:25"), "1.1.8-jvm", coursierCache),
      Refusal.PrereqMillJdkNotCoursier(None, "1.1.8-jvm", coursierCache),
      Refusal.PrereqMillNativeLauncher("1.1.8-native"),
      Refusal.PrereqGradleWrapperMissing, Refusal.PrereqGradleWrapperUnreadable("no distributionUrl"),
      Refusal.PrereqGradleDistributionMissing(gradleUrl, project),
      Refusal.PrereqMvnWrapperMissing, Refusal.PrereqMvnWrapperNotOnlyScript,
      Refusal.PrereqMvnDistributionIsMvnd(mvnUrl),
      Refusal.PrereqMvnWrapperUnreadable("no distributionUrl"), Refusal.PrereqMvnDistributionMissing(mvnUrl, project),
      Refusal.PrerequisiteFileUnreadable(project.resolve("mvnw"), "not valid UTF-8"),
      Refusal.CacheRootUnusable("HOME is not set"), Refusal.CacheRootInsideProject(project, project),
      Refusal.CachePathOverlapsStateRoot(project, project),
      Refusal.WorkingDirectoryOutsideProject("/elsewhere"), Refusal.SessionTmpTooLong(project, 60),
      Refusal.RuleOutsideProgramGrammar("allow x tunnel"),
    )
    for refusal <- cases do
      assert(!clue(wording(refusal)).contains("Prereq") && !wording(refusal).contains("Refusal"), refusal.toString)
    // The ones a host command fixes name that command.
    assert(wording(Refusal.PrereqMillExecutableMissing("1.1.8-jvm", millDownload))
      .contains("MILL_VERSION=1.1.8-jvm ./mill version"))
    for fixedByMillRun <- Seq(
        Refusal.PrereqMillJdkMissing(Some("temurin:25"), "1.1.8-jvm"),
        Refusal.PrereqMillJdkMissing(None, "1.1.8-jvm"),
        Refusal.PrereqMillJdkNotCoursier(Some("temurin:25"), "1.1.8-jvm", coursierCache),
        Refusal.PrereqMillJdkNotCoursier(None, "1.1.8-jvm", coursierCache),
      )
    do assert(clue(wording(fixedByMillRun)).contains("`MILL_VERSION=1.1.8-jvm ./mill version`"))
    assert(wording(Refusal.PrereqMvnWrapperNotOnlyScript).contains("./mvnw wrapper:wrapper -Dtype=only-script"))
    val mvndWording = wording(Refusal.PrereqMvnDistributionIsMvnd(mvnUrl))
    assert(mvndWording.contains(".mvn/wrapper/maven-wrapper.properties"))
    assert(mvndWording.contains("apache-maven-…-bin.zip URL"))

  test("the Maven user home is MAVEN_USER_HOME, else ~/.m2, as the script takes it"):
    assertEquals(mvnUserHome(env("HOME" -> home)), Some(Paths.get(s"$home/.m2")))
    assertEquals(mvnUserHome(env("HOME" -> home, "MAVEN_USER_HOME" -> "/opt/m2")), Some(Paths.get("/opt/m2")))

  test("the rule file path is per program under the frozen boundary directory"):
    val project = Paths.get("/Users/u/proj")
    assertEquals(
      programRulePath(project, Program.Sbt),
      Paths.get("/Users/u/proj/.ko-agent-sandbox/run-on-host/sbt/egress/rule"),
    )
    assertEquals(
      programRulePath(project, Program.Mill),
      Paths.get("/Users/u/proj/.ko-agent-sandbox/run-on-host/mill/egress/rule"),
    )

  // --------------------------------------------------------------------------
  // run-on-host/ refuses unrecognized configuration entries
  // --------------------------------------------------------------------------

  private def projectWith(paths: String*): Path =
    val project = Files.createTempDirectory("run-on-host")
    paths.foreach: path =>
      val full = project.resolve(path)
      Files.createDirectories(full.getParent)
      Files.writeString(full, "allow https://repo.example.org/ read\n")
    project

  test("readProgramRules reads the program's file and defaults to nothing"):
    assertEquals(readProgramRules(Files.createTempDirectory("empty"), Program.Sbt), Right(Vector.empty))
    val project = projectWith(".ko-agent-sandbox/run-on-host/sbt/egress/rule")
    assertEquals(readProgramRules(project, Program.Sbt), Right(Vector("repo.example.org")))
    assertEquals(readProgramRules(project, Program.Mill), Right(Vector.empty), "mill has no file here")

  test("a program rule file with no rule line reads as absent"):
    val project = projectWith(".ko-agent-sandbox/run-on-host/sbt/egress/rule")
    val rule = project.resolve(".ko-agent-sandbox/run-on-host/sbt/egress/rule")
    for text <- Seq("", "# allow https://repo.example.org/ read\n", "\n  \n") do
      Files.writeString(rule, text)
      assertEquals(readProgramRules(project, Program.Sbt), Right(Vector.empty), clue(text))

  test("a line outside the program's grammar is refused, quoted with what a terminal acts on spelled out"):
    val project = projectWith(".ko-agent-sandbox/run-on-host/sbt/egress/rule")
    val rule = project.resolve(".ko-agent-sandbox/run-on-host/sbt/egress/rule")
    Files.writeString(rule, "allow model-provider openai\n")
    val refused = readProgramRules(project, Program.Sbt)
    assert(refused.swap.exists(_.contains("allow model-provider openai")), refused.toString)
    assert(refused.swap.exists(_.contains(ProgramRuleForm)), refused.toString)
    Files.writeString(rule, "allow https://a.example/ read now‮\n")
    val escaped = readProgramRules(project, Program.Sbt)
    assert(escaped.swap.exists(reason => reason.contains("now\\u202e") && !reason.contains("‮")), escaped.toString)

  test("a host the proxy refuses is refused when the file is read, naming the file and the proxy's reason"):
    val project = projectWith(".ko-agent-sandbox/run-on-host/sbt/egress/rule")
    val rule = project.resolve(".ko-agent-sandbox/run-on-host/sbt/egress/rule")
    val refusals = Seq(
      "192.0.2.1" -> "contains an IP literal '192.0.2.1'",
      "repo_a.example" -> "contains an invalid hostname 'repo_a.example'",
      "repo.example:8443" -> "carries a port in its host",
    )
    for (host, said) <- refusals do
      Files.writeString(rule, s"allow https://repo.example.org/ read\nallow https://$host/ read\n")
      val refused = readProgramRules(project, Program.Sbt)
      assert(refused.swap.exists(reason => reason.contains(rule.toString) && reason.contains(said)), refused.toString)
      assertEquals(readProgramRules(project, Program.Mill), Right(Vector.empty), "mill's proxy does not read this file")
    // A spelling the proxy resolves is read as the file spells it.
    Files.writeString(rule, "allow https://Repo.Example.ORG./ read\n")
    assertEquals(readProgramRules(project, Program.Sbt), Right(Vector("Repo.Example.ORG.")))

  test("a stray name at any level refuses another program's command too, naming itself; metadata does not"):
    for
      stray <- Seq(
        ".ko-agent-sandbox/run-on-host/ant/egress/rule",
        ".ko-agent-sandbox/run-on-host/sbt/egres/rule",
        ".ko-agent-sandbox/run-on-host/sbt/egress/rules",
      )
    do
      val refused = readProgramRules(projectWith(stray), Program.Mill)
      assert(
        refused.swap.exists(reason => reason.contains("update the launcher") || reason.contains("not a rule file")),
        s"$stray: $refused",
      )
    val metadata = projectWith(
      ".ko-agent-sandbox/run-on-host/.DS_Store",
      ".ko-agent-sandbox/run-on-host/sbt/egress/.DS_Store",
      ".ko-agent-sandbox/run-on-host/sbt/egress/rule",
    )
    assertEquals(readProgramRules(metadata, Program.Sbt), Right(Vector("repo.example.org")))

  test("a symlinked component refuses"):
    val project = projectWith(".ko-agent-sandbox/run-on-host/sbt/egress/rule")
    Files.createSymbolicLink(
      project.resolve(".ko-agent-sandbox/run-on-host/mill"),
      project.resolve(".ko-agent-sandbox/run-on-host/sbt"),
    )
    val refused = readProgramRules(project, Program.Sbt)
    assert(refused.swap.exists(_.contains("symlink")), refused.toString)
    val linkedRule = projectWith("elsewhere")
    val elsewhere = linkedRule.resolve("elsewhere")
    val egress = Files.createDirectories(linkedRule.resolve(".ko-agent-sandbox/run-on-host/sbt/egress"))
    Files.createSymbolicLink(egress.resolve("rule"), elsewhere)
    val linked = readProgramRules(linkedRule, Program.Sbt)
    assert(linked.swap.exists(_.contains("symlink")), linked.toString)

  test("a file where a directory belongs refuses instead of reading as absent config"):
    for directory <- Seq("sbt", "sbt/egress") do
      val project = Files.createTempDirectory("run-on-host")
      val path = project.resolve(s".ko-agent-sandbox/run-on-host/$directory")
      Files.createDirectories(path.getParent)
      Files.writeString(path, "")
      val refused = readProgramRules(project, Program.Mill)
      assert(refused.isLeft, s"$directory: $refused")

  test("a non-regular file where rule belongs refuses instead of being read"):
    val project = Files.createTempDirectory("run-on-host")
    val egress = project.resolve(".ko-agent-sandbox/run-on-host/sbt/egress")
    Files.createDirectories(egress.resolve("rule")) // a directory; a FIFO would block a read
    val refused = readProgramRules(project, Program.Sbt)
    assert(refused.swap.exists(r => r.contains("rule") && r.contains("not a regular file")), refused.toString)

  test("only the selected program's rule file is read; another's is checked for its form alone"):
    val project = projectWith(".ko-agent-sandbox/run-on-host/sbt/egress/rule")
    val millRule = project.resolve(".ko-agent-sandbox/run-on-host/mill/egress/rule")
    Files.createDirectories(millRule.getParent)
    Files.write(millRule, Array[Byte](0xff.toByte, 0xfe.toByte))
    assertEquals(readProgramRules(project, Program.Sbt), Right(Vector("repo.example.org")))
    val malformed = readProgramRules(project, Program.Mill)
    assert(malformed.swap.exists(reason => reason.contains("not UTF-8") && reason.contains("mill")), malformed.toString)

  test("an unreadable rule file is refused by name, not thrown"):
    val project = projectWith(".ko-agent-sandbox/run-on-host/sbt/egress/rule")
    val rule = project.resolve(".ko-agent-sandbox/run-on-host/sbt/egress/rule")
    Files.setPosixFilePermissions(rule, java.nio.file.attribute.PosixFilePermissions.fromString("---------"))
    assume(!Files.isReadable(rule), "a user who reads any file (root) cannot test an unreadable one")
    val refused = readProgramRules(project, Program.Sbt)
    assert(refused.swap.exists(reason => reason.contains("cannot read") && reason.contains("sbt")), refused.toString)

  test("every path a refusal names is spelled out where a terminal would act on it"):
    val parent = Files.createTempDirectory("run-on-host")
    def projectNamed(paths: String*): Path =
      val project = Files.createDirectory(parent.resolve(s"proj\u001b[2K\r${paths.size}"))
      paths.foreach: path =>
        val full = project.resolve(path)
        Files.createDirectories(full.getParent)
        Files.writeString(full, "allow model-provider openai\n")
      project
    val grammar = readProgramRules(projectNamed(".ko-agent-sandbox/run-on-host/sbt/egress/rule"), Program.Sbt)
    val stray = readProgramRules(projectNamed(".ko-agent-sandbox/run-on-host/sbt/egress/rules", "x"), Program.Sbt)
    val wrongType = readProgramRules(projectNamed(".ko-agent-sandbox/run-on-host/sbt", "x", "y"), Program.Sbt)
    for refused <- Seq(grammar, stray, wrongType) do
      assert(
        refused.swap.exists: reason =>
          reason.contains("proj\\x1b[2K\\r") && !reason.exists(ch => ch == '\u001b' || ch == '\r'),
        refused.toString,
      )
