// What the generated profile says, asserted here rather than only on a Mac. The rules under test
// are the ones probe/seatbelt-semantics.sh measured: a non-canonical path grants rather than
// denies, so it is refused; the guard denies come last, because SBPL is last-match-wins.

package agentsandbox.launcher

import java.nio.file.{Path, Paths}

import BuildSandboxPolicy.{BuildPolicy, Tool}
import SeatbeltProfile.*

class SeatbeltProfileTest extends munit.FunSuite:

  private val home = "/Users/kenichi"
  private val project = Paths.get(s"$home/ko-agent-sandbox")
  private val cacheRoot = Paths.get(s"$home/Library/Caches/Coursier")
  private val jdkHome = cacheRoot.resolve(
    "arc/https/github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.4%252B7/" +
      "OpenJDK25U-jdk_aarch64_mac_hotspot_25.0.4_7.tar.gz/jdk-25.0.4+7/Contents/Home",
  )
  private val launcher = Paths.get(s"$home/Library/Application Support/Coursier/bin/sbt")
  private val distributionExec =
    cacheRoot.resolve("arc/https/github.com/sbt/sbt/releases/download/v2.0.4/sbt-2.0.4.zip/sbt/bin/sbt")
  private val distribution = distributionHome(distributionExec)

  private val policy = BuildPolicy(
    project = project,
    jdkHome = jdkHome,
    coursierV1 = Paths.get(s"$home/.cache/ko-agent-sandbox/cache/abc123/coursier/v1"),
    tool = Tool.Sbt,
    launcher = launcher,
    sbtBoot = Some(Paths.get(s"$home/.sbt/boot")),
  )

  private def inputs(
    runtime: RuntimeAuthority = RuntimeAuthority(Seq(Paths.get("/usr/lib")), Seq(Paths.get("/bin/sh"))),
    port: Int = 51234,
    tmp: Path = Paths.get("/private/tmp/ko-agent-build/abc/tmp"),
  ) = ProfileInputs(policy, tmp, Some(distribution), port, runtime)

  private def rendered(in: ProfileInputs = inputs()): String =
    render(in).fold(reason => fail(s"render refused: $reason"), identity)

  // --------------------------------------------------------------------------
  // Canonicality — the rule that fails open
  // --------------------------------------------------------------------------

  test("a path that is not canonical is refused, because such a rule would grant"):
    val viaSymlinkSpelling = Paths.get("/tmp/ko-agent-build/abc/tmp")
    // Not normalized rather than not-real: purity keeps realpath out of here, and `..` is the
    // shape a test can express.
    val dotted = Paths.get("/private/tmp/ko-agent-build/../abc")
    assert(render(inputs(tmp = dotted)).isLeft)
    // A merely different-but-canonical spelling still renders; resolving /tmp is the caller's job.
    assert(render(inputs(tmp = viaSymlinkSpelling)).isRight)

  test("a relative path is refused"):
    assert(render(inputs(tmp = Paths.get("relative/tmp"))).isLeft)

  test("the refusal explains why it grants rather than denies"):
    val reason = render(inputs(tmp = Paths.get("relative/tmp"))).left.getOrElse("")
    assert(clue(reason).contains("grant"))

  test("a port outside the range is refused"):
    assert(render(inputs(port = 0)).isLeft)
    assert(render(inputs(port = 70000)).isLeft)

  // --------------------------------------------------------------------------
  // Ordering — SBPL is last-match-wins
  // --------------------------------------------------------------------------

  test("the guard denies come after every allow"):
    val text = rendered()
    val lastAllow = text.linesIterator.zipWithIndex.filter(_._1.startsWith("(allow")).map(_._2).max
    val firstDeny = text.linesIterator.zipWithIndex.filter(_._1.startsWith("(deny file")).map(_._2).min
    assert(clue(firstDeny) > clue(lastAllow))

  test("the root directory entry is granted, and is not a subpath of everything"):
    val text = rendered()
    assert(clue(text).contains("""(allow file-read* file-test-existence (literal "/"))"""))
    assert(!text.contains("""(subpath "/")"""))

  test("the profile denies by default"):
    assert(rendered().linesIterator.contains("(deny default)"))

  // --------------------------------------------------------------------------
  // The guard
  // --------------------------------------------------------------------------

  test("both guarded names are denied at any depth, with their dots escaped"):
    val text = rendered()
    assert(clue(text).contains("""(deny file-write* file-read* file-link (regex #"/\.git(/|$)"))"""))
    assert(text.contains("""(deny file-write* file-read* file-link (regex #"/\.ko-agent-sandbox(/|$)"))"""))

  test("the guard is the only regex; every wrapper-supplied path is a subpath literal"):
    val regexLines = rendered().linesIterator.filter(_.contains("(regex")).toSeq
    assertEquals(regexLines.size, GuardedNames.size)
    assert(regexLines.forall(_.startsWith("(deny")))

  // --------------------------------------------------------------------------
  // Paths that break naive quoting
  // --------------------------------------------------------------------------

  test("a space and a '+' survive into the profile verbatim"):
    val text = rendered()
    assert(clue(text).contains("""(subpath "/Users/kenichi/Library/Application Support/Coursier/bin/sbt")"""))
    assert(text.contains("jdk-25.0.4+7/Contents/Home\")"))
    assert(text.contains("jdk-25.0.4%252B7"))

  test("the tool's two halves are both granted, and neither is writable"):
    val text = rendered()
    val executable = text.linesIterator.filter(_.startsWith("(allow process-exec*")).mkString("\n")
    assert(clue(executable).contains(launcher.toString))
    assert(executable.contains(distribution.toString))
    val writable = text.linesIterator.filter(_.contains("file-write*")).filter(_.startsWith("(allow")).mkString("\n")
    assert(!writable.contains(launcher.toString))
    assert(!writable.contains(distribution.toString))
    assert(!writable.contains(jdkHome.toString))

  test("only the project, its Coursier cache and the session temp are writable"):
    val writable = rendered().linesIterator
      .filter(line => line.startsWith("(allow") && line.contains("file-write*"))
      .toSeq
    assertEquals(writable.size, 3)
    assert(writable.exists(_.contains(project.toString)))
    assert(writable.exists(_.contains("coursier/v1")))
    assert(writable.exists(_.contains("/tmp/")))

  test("every ancestor of a granted path is a literal read"):
    // Measured: a subpath grant covers what is under it, never the directories above, and without
    // the chain the JVM dies in the loader.
    val text = rendered()
    for ancestor <- Seq("/Users", "/Users/kenichi", "/Users/kenichi/Library/Caches") do
      assert(clue(text).contains(s"""(allow file-read* file-test-existence (literal "$ancestor"))"""), ancestor)
    // The root is its own line and not repeated in the chain.
    assertEquals(text.linesIterator.count(_.contains("""(literal "/")""")), 1)

  test("/dev is in the ancestor chain, or SecureRandom cannot open /dev/urandom"):
    assert(clue(rendered()).contains("""(allow file-read* file-test-existence (literal "/dev"))"""))

  test("file-map-executable is absent: measurement says it is not needed"):
    assert(!clue(rendered()).contains("file-map-executable"))

  test("the proxy is the only outbound destination"):
    val text = rendered()
    val outbound = text.linesIterator.filter(_.contains("network")).toSeq
    assertEquals(outbound, Seq("""(allow network-outbound (remote tcp "localhost:51234"))"""))

  // --------------------------------------------------------------------------
  // The sbt launcher's second half
  // --------------------------------------------------------------------------

  test("the distribution is read out of the wrapper, not derived from a convention"):
    val wrapper =
      s"""#!/usr/bin/env sh
         |exec "$distributionExec" "$$@"
         |""".stripMargin
    assertEquals(sbtDistribution(wrapper, cacheRoot), Some(distributionExec))

  test("the longest cache path wins, so a grant never lands on a prefix"):
    val wrapper =
      s"""CACHE="$cacheRoot"
         |exec "$distributionExec" "$$@"
         |""".stripMargin
    assertEquals(sbtDistribution(wrapper, cacheRoot), Some(distributionExec))

  test("a path escaping the cache root is not accepted"):
    val escaping = s"$cacheRoot/../../../etc/passwd"
    assertEquals(sbtDistribution(s"""exec "$escaping"""", cacheRoot), None)

  test("a wrapper naming no cache path yields nothing rather than a guess"):
    assertEquals(sbtDistribution("#!/bin/sh\nexec /usr/local/bin/sbt \"$@\"\n", cacheRoot), None)

  test("the distribution grant is its home, not the executable: sbt-launch.jar lives beside it"):
    assertEquals(
      distributionHome(distributionExec),
      cacheRoot.resolve("arc/https/github.com/sbt/sbt/releases/download/v2.0.4/sbt-2.0.4.zip/sbt"),
    )
    assert(rendered().contains(s"(subpath \"$distribution\")"))

  test("Mill renders without the sbt-only paths"):
    val mill = policy.copy(
      tool = Tool.Mill,
      launcher = project.resolve("mill"),
      sbtBoot = None,
    )
    val text = render(inputs().copy(policy = mill, sbtDistribution = None))
      .fold(reason => fail(reason), identity)
    assert(!clue(text).contains(".sbt/boot"))
    assert(text.contains(project.resolve("mill").toString))
