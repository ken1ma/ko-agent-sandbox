// Unit tests assert the generated SBPL without requiring macOS. The rules under test
// are the ones src/probe/seatbelt-semantics.sh measured. Callers resolve symlinks; the renderer
// requires absolute, normalized paths and puts guard denies last, because SBPL is last-match-wins.

package agentsandbox.launcher

import java.nio.file.{Files, Path, Paths}

import RunOnHostPrereqs.{CommandPrereqs, Program}
import SeatbeltProfile.*

class SeatbeltProfileTest extends munit.FunSuite:

  private val home = "/Users/kenichi"
  private val project = Paths.get(s"$home/ko-agent-sandbox")
  private val cacheRoot = Paths.get(s"$home/Library/Caches/Coursier")
  private val jdkHome = cacheRoot.resolve(
    "arc/https/github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.4%252B7/" +
      "OpenJDK25U-jdk_aarch64_mac_hotspot_25.0.4_7.tar.gz/jdk-25.0.4+7/Contents/Home",
  )
  private val executable = Paths.get(s"$home/Library/Application Support/Coursier/bin/sbt")
  private val distributionExec =
    cacheRoot.resolve("arc/https/github.com/sbt/sbt/releases/download/v2.0.4/sbt-2.0.4.zip/sbt/bin/sbt")
  private val distribution = distributionExec.getParent.getParent

  private val prereqs = CommandPrereqs(
    project = project,
    jdkHome = jdkHome,
    coursierV1 = Paths.get(s"$home/.cache/ko-agent-sandbox/run-on-host/abc123/coursier/v1"),
    program = Program.Sbt,
    executable = executable,
  )

  private val sbtGlobal = Paths.get(s"$home/.cache/ko-agent-sandbox/run-on-host/abc123/sbt-global")
  private val ivyHome = Paths.get(s"$home/.cache/ko-agent-sandbox/run-on-host/abc123/ivy-home")

  private def inputs(
    systemPaths: SystemPaths = SystemPaths(Seq(Paths.get("/usr/lib")), Seq(Paths.get("/bin/sh"))),
    port: Int = 51234,
    tmp: Path = Paths.get("/private/tmp/ko-agent-command/abc/tmp"),
    fileRules: FileRules.Resolved = FileRules.Resolved.Empty,
  ) = ProfileInputs(
    prereqs, tmp, Some(distribution), Some(sbtGlobal), Some(ivyHome), None, None, port, trust, systemPaths,
    Network.ProxyOnly, fileRules,
  )

  private val trust = Paths.get("/private/tmp/ko-agent-command/abc/proxy.trust")

  private def rendered(in: ProfileInputs = inputs()): String =
    render(in).fold(reason => fail(s"render refused: $reason"), identity)

  test("the proxy's CA certificate is granted as its two files, read-only, never as their directory"):
    val profile = rendered()
    Seq("ca.crt", "truststore.p12").foreach: name =>
      assert(profile.contains(s"""(allow file-read* (literal "$trust/$name"))"""), profile)
    assert(!profile.contains(s"""(subpath "$trust"""), profile)
    assert(profile.contains(s"""(allow file-read-metadata file-test-existence (literal "$trust"))"""), profile)

  // --------------------------------------------------------------------------
  // Absolute, normalized paths
  // --------------------------------------------------------------------------

  test("every profile path must be absolute and normalized"):
    val fields: Seq[(String, Path => ProfileInputs)] = Seq(
      "project" -> (path => inputs().copy(prereqs = prereqs.copy(project = path))),
      "JDK" -> (path => inputs().copy(prereqs = prereqs.copy(jdkHome = path))),
      "executable" -> (path => inputs().copy(prereqs = prereqs.copy(executable = path))),
      "Coursier cache" -> (path => inputs().copy(prereqs = prereqs.copy(coursierV1 = path))),
      "temporary directory" -> (path => inputs(tmp = path)),
      "trust directory" -> (path => inputs().copy(trust = path)),
      "distribution" -> (path => inputs().copy(distribution = Some(path))),
      "sbt global base" -> (path => inputs().copy(sbtGlobal = Some(path))),
      "Ivy home" -> (path => inputs().copy(ivyHome = Some(path))),
      "Gradle user home" -> (path => gradleInputs.copy(gradleUserHome = Some(path))),
      "Maven repository" -> (path => mvnInputs.copy(m2Repository = Some(path))),
      "system-path read" -> (path => inputs(systemPaths = SystemPaths(Seq(path), Seq.empty))),
      "system-path executable" -> (path => inputs(systemPaths = SystemPaths(Seq.empty, Seq(path)))),
      "server tmp" -> (path => inputs().copy(network = Network.SbtClient(path))),
    )
    for
      (name, withPath) <- fields
      path <- Seq(Paths.get("relative/path"), Paths.get("/private/tmp/../other"))
    do
      val reason = render(withPath(path)).left.getOrElse(fail(s"$name accepted $path"))
      assert(reason.contains("supply an absolute path with no . or .. components"), s"$name: $reason")

  test("symlink resolution belongs to the caller, not the renderer's lexical check"):
    val viaSymlinkSpelling = Paths.get("/tmp/ko-agent-command/abc/tmp")
    assert(render(inputs(tmp = viaSymlinkSpelling)).isRight)

  test("the program and the distribution agree: sbt needs it, mill has none"):
    assert(render(inputs().copy(distribution = None)).isLeft)
    assert(render(inputs().copy(prereqs = millPrereqs)).isLeft)

  test("the program and the global base agree the same way, and the Ivy home with them"):
    assert(render(inputs().copy(sbtGlobal = None)).isLeft)
    assert(render(inputs().copy(ivyHome = None)).isLeft)
    assert(render(inputs().copy(prereqs = millPrereqs, distribution = None)).isLeft)
    assert(render(inputs().copy(prereqs = millPrereqs, distribution = None, sbtGlobal = None)).isLeft)

  test("the sbt global base and Ivy home permit reads and writes without a process-exec grant"):
    val text = rendered()
    for cache <- Seq(sbtGlobal, ivyHome) do
      assert(text.contains(s"""(allow file-read* file-write* (subpath "$cache"))"""), text)
      assert(!text.contains(s"""process-exec* (subpath "$cache")"""), text)

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

  test("both guarded names are denied at any depth under the project, with their dots escaped"):
    val text = rendered()
    val scope = "(deny file-write* file-read* file-link (require-all (subpath \"" + project + "\") "
    assert(clue(text).contains(scope + """(regex #"/\.git(/|$)")))"""))
    assert(text.contains(scope + """(regex #"/\.ko-agent-sandbox(/|$)")))"""))

  test("the guard does not reach the command's temporary directory: a test's throwaway .git is under it"):
    // The project path is the only path in the guard, and it is a subpath filter, never part of
    // the regex.
    val guard = rendered().linesIterator.filter(_.startsWith("(deny file")).toSeq
    assert(guard.forall(_.contains(s"""(subpath "$project")""")))
    assert(guard.forall(line => !line.contains("/tmp/")))

  test("without file rules the guard is the only regex; every supervisor-supplied path is a subpath literal"):
    val regexLines = rendered().linesIterator.filter(_.contains("(regex")).toSeq
    assertEquals(regexLines.size, FileRules.GuardedComponents.size)
    assert(regexLines.forall(_.startsWith("(deny")))

  // --------------------------------------------------------------------------
  // Paths that break naive quoting
  // --------------------------------------------------------------------------

  test("a space and a '+' survive into the profile verbatim"):
    val text = rendered()
    assert(clue(text).contains("""(subpath "/Users/kenichi/Library/Application Support/Coursier/bin/sbt")"""))
    assert(text.contains("jdk-25.0.4+7/Contents/Home\")"))
    assert(text.contains("jdk-25.0.4%252B7"))

  test("the program's two halves are both granted, and neither is writable"):
    val text = rendered()
    val executionRules = text.linesIterator.filter(_.startsWith("(allow process-exec*")).mkString("\n")
    assert(clue(executionRules).contains(executable.toString))
    assert(executionRules.contains(distribution.toString))
    val writable = text.linesIterator.filter(_.contains("file-write*")).filter(_.startsWith("(allow")).mkString("\n")
    assert(!writable.contains(executable.toString))
    assert(!writable.contains(distribution.toString))
    assert(!writable.contains(jdkHome.toString))

  test("only the project, its caches and the command's temporary directory are writable"):
    val writable = rendered().linesIterator
      .filter(line => line.startsWith("(allow") && line.contains("file-write*"))
      .toSeq
    assertEquals(writable.size, 5)
    assert(writable.exists(_.contains(project.toString)))
    assert(writable.exists(_.contains("coursier/v1")))
    assert(writable.exists(_.contains("sbt-global")))
    assert(writable.exists(_.contains("ivy-home")))
    assert(writable.exists(_.contains("/tmp/")))

  test("every program permits direct execution from writable project and temporary paths, but not caches"):
    for profile <- Seq(inputs(), millInputs, gradleInputs, mvnInputs) do
      val writable = rendered(profile).linesIterator
        .filter(line => line.startsWith("(allow") && line.contains("file-write*"))
        .toVector
      val executable = writable.filter(_.contains("process-exec*"))
      assertEquals(executable.size, 2, profile.prereqs.program.name)
      assert(executable.exists(_.contains(s"(subpath \"$project\")")))
      assert(executable.exists(_.contains(s"(subpath \"${profile.sessionTmp}\")")))
      val caches = Seq(prereqs.coursierV1) ++ profile.sbtGlobal ++ profile.ivyHome ++ profile.gradleUserHome ++
        profile.m2Repository
      for cache <- caches do
        val grants = writable.filter(_.contains(s"(subpath \"$cache\")"))
        assert(grants.nonEmpty, cache.toString)
        assert(grants.forall(line => line.contains("file-read*") && !line.contains("process-exec*")), cache.toString)

  test("every ancestor of a granted path is a literal metadata read, never a listing"):
    // Measured: a subpath grant covers what is under it, never the directories above, and without
    // the chain the JVM dies in the loader; and file-read* on the chain lists every ancestor.
    val text = rendered()
    for ancestor <- Seq("/Users", "/Users/kenichi", "/Users/kenichi/Library/Caches") do
      assert(clue(text).contains(s"""(allow file-read-metadata file-test-existence (literal "$ancestor"))"""), ancestor)
    val literalReads = text.linesIterator.filter(line => line.contains("(literal") && line.contains("file-read*")).toSeq
    // A file granted alone — a device, the proxy's CA certificate — is a literal read; no directory is.
    val trustReads = Seq("ca.crt", "truststore.p12").map(name => s"""(allow file-read* (literal "$trust/$name"))""")
    assertEquals(literalReads, (RootComponent +: Devices.linesIterator.toSeq) ++ trustReads)
    // The root is its own line and not repeated in the chain.
    assertEquals(text.linesIterator.count(_.contains("""(literal "/")""")), 1)

  test("no /dev/tty: a closed stdin does not detach the controlling terminal; random devices read-only"):
    val text = rendered()
    assert(!clue(text).contains("/dev/tty"))
    assert(text.contains("""(allow file-read* (literal "/dev/random") (literal "/dev/urandom"))"""))
    assert(text.contains("""(allow file-read* file-write-data (literal "/dev/null"))"""))

  test("/dev is in the ancestor chain, or SecureRandom cannot open /dev/urandom"):
    assert(clue(rendered()).contains("""(allow file-read-metadata file-test-existence (literal "/dev"))"""))

  test("another process's arguments are denied by name and by pidinfo, after the sysctl-read grant they narrow"):
    val lines = rendered().linesIterator.toVector
    val grant = lines.indexOf("(allow process-fork sysctl-read)")
    val afterGrant = lines.drop(grant + 1).filterNot(_.startsWith(";;"))
    assertEquals(afterGrant.take(3), SeatbeltProfile.ProcessReadRule)
    assertEquals(lines.filterNot(_.startsWith(";;")).count(_.contains("process-info")), 2)

  test("file-map-executable is absent: measurement says it is not needed"):
    assert(!clue(rendered()).contains("file-map-executable"))

  test("the proxy is the only TCP destination, and UNIX sockets are confined to the command's temporary directory"):
    val text = rendered()
    val network = text.linesIterator.filter(_.startsWith("(allow network")).toSeq
    assertEquals(
      network,
      Seq(
        """(allow network-outbound (remote ip "localhost:51234"))""",
        """(allow network-bind network-inbound network-outbound """ +
          """(local unix-socket (subpath "/private/tmp/ko-agent-command/abc/tmp")) """ +
          """(remote unix-socket (subpath "/private/tmp/ko-agent-command/abc/tmp")))""",
      ),
    )

  test("an sbt client reaches the sockets under the runner's tmp, and nothing else there"):
    val runnerTmp = Paths.get("/private/tmp/ko-agent-command/bxyz/tmp")
    val text = rendered(inputs().copy(network = Network.SbtClient(runnerTmp)))
    val network = text.linesIterator.filter(_.startsWith("(allow network")).toSeq
    assertEquals(
      network,
      Seq(
        """(allow network-outbound (remote ip "localhost:51234"))""",
        """(allow network-bind network-inbound network-outbound """ +
          """(local unix-socket (subpath "/private/tmp/ko-agent-command/abc/tmp")) """ +
          """(remote unix-socket (subpath "/private/tmp/ko-agent-command/abc/tmp")))""",
        """(allow network-outbound (remote unix-socket (subpath "/private/tmp/ko-agent-command/bxyz/tmp")))""",
      ),
    )
    // The socket's directory resolves; the runner's directory is an ancestor like any other.
    assert(text.contains(
      """(allow file-read-metadata file-test-existence (subpath "/private/tmp/ko-agent-command/bxyz/tmp"))""",
    ))
    assert(text.contains(
      """(allow file-read-metadata file-test-existence (literal "/private/tmp/ko-agent-command/bxyz"))""",
    ))
    assert(!text.contains("""(allow file-read* (subpath "/private/tmp/ko-agent-command/bxyz/tmp"))"""))
    // Only an sbt client has a server to reach.
    assert(render(inputs().copy(prereqs = millPrereqs, distribution = None, sbtGlobal = None, ivyHome = None,
      network = Network.SbtClient(runnerTmp))).isLeft)

  test("the mill daemon binds listeners on any port, and its client reaches the one port it was observed listening on"):
    val daemonRules = render(millInputs.copy(network = Network.MillDaemon)).fold(fail(_), identity)
      .linesIterator.filter(_.startsWith("(allow network")).toSeq
    assertEquals(
      daemonRules,
      Seq(
        """(allow network-outbound (remote ip "localhost:51234"))""",
        """(allow network-bind network-inbound network-outbound """ +
          """(local unix-socket (subpath "/private/tmp/ko-agent-command/abc/tmp")) """ +
          """(remote unix-socket (subpath "/private/tmp/ko-agent-command/abc/tmp")))""",
        """(allow network-bind network-inbound (local ip "localhost:*"))""",
      ),
    )
    val clientRules = render(millInputs.copy(network = Network.MillClient(50123, 4321))).fold(fail(_), identity)
      .linesIterator.filter(_.startsWith("(allow network")).toSeq
    assertEquals(
      clientRules,
      Seq(
        """(allow network-outbound (remote ip "localhost:51234"))""",
        """(allow network-bind network-inbound network-outbound """ +
          """(local unix-socket (subpath "/private/tmp/ko-agent-command/abc/tmp")) """ +
          """(remote unix-socket (subpath "/private/tmp/ko-agent-command/abc/tmp")))""",
        """(allow network-outbound (remote ip "localhost:50123"))""",
      ),
    )
    // Neither grant reaches another program, the client's port is a port, and its daemon's pid a pid.
    assert(render(inputs().copy(network = Network.MillDaemon)).isLeft)
    assert(render(inputs().copy(network = Network.MillClient(50123, 4321))).isLeft)
    assert(render(mvnInputs.copy(network = Network.MillClient(50123, 4321))).isLeft)
    assert(render(millInputs.copy(network = Network.MillClient(0, 4321))).isLeft)
    assert(render(millInputs.copy(network = Network.MillClient(70000, 4321))).isLeft)
    assert(render(millInputs.copy(network = Network.MillClient(50123, 0))).isLeft)

  test("a mill client reads its daemon's arguments alone, after the rule that denies every other process's"):
    // Mill's client checks its daemon with ProcessHandle.info(), which reads the daemon's arguments.
    val lines = render(millInputs.copy(network = Network.MillClient(50123, 4321))).fold(fail(_), identity)
      .linesIterator.toVector
    val opened = lines.filter(_.startsWith("(allow sysctl-read (sysctl-name"))
    assertEquals(opened, Vector("""(allow sysctl-read (sysctl-name "kern.procargs2.4321"))"""))
    assert(lines.indexOf(opened.head) > lines.indexOf(SeatbeltProfile.ProcessReadRule.head))
    for network <- Vector(Network.MillDaemon, Network.ProxyOnly) do
      val other = render(millInputs.copy(network = network)).fold(fail(_), identity)
      assert(!other.contains("kern.procargs2."), network)

  // --------------------------------------------------------------------------
  // The host proxy's own profile
  // --------------------------------------------------------------------------

  private val proxyJdk = Paths.get("/Library/Java/JavaVirtualMachines/temurin-25.jdk/Contents/Home")
  private val proxyJar = Paths.get(s"$home/.cache/ko-agent-sandbox/launcher/ko-agent-sandbox.jar")
  private def proxyInputs(
    executables: Seq[Path] = Seq(proxyJdk),
    reads: Seq[Path] = Seq(proxyJar),
    systemPaths: SystemPaths = SystemPaths(
      Seq(Paths.get("/System/Library/CoreServices/SystemVersion.plist")), Seq(Paths.get("/bin")),
    ),
  ) = ProxyInputs(executables, reads, systemPaths)
  private def renderedProxy(in: ProxyInputs = proxyInputs()): String =
    renderProxy(in).fold(reason => fail(s"renderProxy refused: $reason"), identity)

  test("the proxy profile grants its executable, what it loads, the system paths as reads, and no write"):
    val text = renderedProxy()
    assert(text.linesIterator.contains("(deny default)"))
    val allows = text.linesIterator.filter(_.startsWith("(allow")).filterNot(_.startsWith("(allow network")).toSeq
    assertEquals(
      allows,
      Seq(
        RootComponent,
        """(allow file-read-metadata file-test-existence (literal "/Library"))""",
        """(allow file-read-metadata file-test-existence (literal "/Library/Java"))""",
        """(allow file-read-metadata file-test-existence (literal "/Library/Java/JavaVirtualMachines"))""",
        "(allow file-read-metadata file-test-existence " +
          """(literal "/Library/Java/JavaVirtualMachines/temurin-25.jdk"))""",
        "(allow file-read-metadata file-test-existence " +
          """(literal "/Library/Java/JavaVirtualMachines/temurin-25.jdk/Contents"))""",
        """(allow file-read-metadata file-test-existence (literal "/System"))""",
        """(allow file-read-metadata file-test-existence (literal "/System/Library"))""",
        """(allow file-read-metadata file-test-existence (literal "/System/Library/CoreServices"))""",
        """(allow file-read-metadata file-test-existence (literal "/Users"))""",
        s"""(allow file-read-metadata file-test-existence (literal "$home"))""",
        s"""(allow file-read-metadata file-test-existence (literal "$home/.cache"))""",
        s"""(allow file-read-metadata file-test-existence (literal "$home/.cache/ko-agent-sandbox"))""",
        s"""(allow file-read-metadata file-test-existence (literal "$home/.cache/ko-agent-sandbox/launcher"))""",
        """(allow file-read-metadata file-test-existence (literal "/dev"))""",
        """(allow file-read-metadata file-test-existence (literal "/private"))""",
        """(allow file-read-metadata file-test-existence (literal "/private/var"))""",
        """(allow file-read-metadata file-test-existence (literal "/private/var/run"))""",
        """(allow file-read-metadata file-test-existence (literal "/var"))""",
        "(allow sysctl-read)",
        """(allow mach-lookup (global-name "com.apple.system.opendirectoryd.libinfo"))""",
        """(allow file-read* file-write-data (literal "/dev/null"))""",
        """(allow file-read* (literal "/dev/random") (literal "/dev/urandom"))""",
        """(allow file-read* (subpath "/System/Library/CoreServices/SystemVersion.plist"))""",
        """(allow file-read* (subpath "/bin"))""",
        "(allow process-exec* file-read* " +
          """(subpath "/Library/Java/JavaVirtualMachines/temurin-25.jdk/Contents/Home"))""",
        s"""(allow file-read* (subpath "$home/.cache/ko-agent-sandbox/launcher/ko-agent-sandbox.jar"))""",
      ),
    )

  test("neither profile looks up a Mach service it does not name"):
    for text <- Seq(rendered(), renderedProxy()) do
      val lookups = text.linesIterator.filter(_.contains("mach-lookup")).toSeq
      assertEquals(
        lookups,
        Seq("""(allow mach-lookup (global-name "com.apple.system.opendirectoryd.libinfo"))"""),
      )

  test("the proxy profile's network is every remote, the resolver's socket, and a listener of the localhost class"):
    val network = renderedProxy().linesIterator.filter(_.startsWith("(allow network")).toSeq
    assertEquals(
      network,
      Seq(
        """(allow network-outbound (remote ip "*:*"))""",
        """(allow network-outbound (remote unix-socket (literal "/private/var/run/mDNSResponder")))""",
        """(allow network-bind network-inbound (local ip "localhost:*"))""",
      ),
    )

  test("the proxy profile refuses a relative path and an empty executable set"):
    assert(renderProxy(proxyInputs(reads = Seq(Paths.get("launcher.jar")))).isLeft)
    assert(renderProxy(proxyInputs(executables = Seq(Paths.get("/Library/../usr/bin")))).isLeft)
    assert(renderProxy(proxyInputs(executables = Seq.empty)).isLeft)
    // The native image: the binary alone, nothing to load beside it.
    val native =
      renderedProxy(proxyInputs(executables = Seq(Paths.get("/usr/local/bin/ko-agent-sandbox")), reads = Seq.empty))
    assert(native.contains("""(allow process-exec* file-read* (subpath "/usr/local/bin/ko-agent-sandbox"))"""))
    assert(!native.contains(home))

  // --------------------------------------------------------------------------
  // The cs-installed sbt script's second half
  // --------------------------------------------------------------------------

  test("the distribution grant is its home, not the executable: sbt-launch.jar is beside it"):
    assert(rendered().contains(s"(subpath \"$distribution\")"))
    assert(!rendered().contains(s"(subpath \"$distributionExec\")"))

  private val millPrereqs = prereqs.copy(
    program = Program.Mill,
    executable = Paths.get(s"$home/.cache/mill/download/1.1.9"),
  )

  private def millInputs = inputs().copy(prereqs = millPrereqs, distribution = None, sbtGlobal = None, ivyHome = None)

  private def millText: String = render(millInputs).fold(reason => fail(reason), identity)

  test("a mill build's recorded JDK is granted to read and run, once when it is JAVA_HOME's, and never to write"):
    val recorded = cacheRoot.resolve(
      "arc/https/github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.10%252B7/" +
        "OpenJDK21U-jdk_aarch64_mac_hotspot_21.0.10_7.tar.gz/jdk-21.0.10+7/Contents/Home",
    )
    def grant(home: Path) = s"""(allow process-exec* file-read* (subpath "$home"))"""
    assert(!millText.contains("temurin21"))
    val text = rendered(millInputs.copy(distribution = Some(recorded)))
    assert(clue(text).contains(grant(recorded)) && text.contains(grant(jdkHome)))
    assert(text.contains(s"""(allow file-read-metadata file-test-existence (literal "${recorded.getParent}"))"""))
    assert(!text.linesIterator.exists(line => line.contains("file-write") && line.contains(s""""$recorded"""")))
    val same = rendered(millInputs.copy(distribution = Some(jdkHome)))
    assertEquals(same.linesIterator.count(_ == grant(jdkHome)), 1)

  private val gradleHome =
    Paths.get(s"$home/.gradle/wrapper/dists/gradle-9.7.1-bin/1w1c7tv4s851m17nbqdsro2tv/gradle-9.7.1")
  private val gradleUserHome = Paths.get(s"$home/.cache/ko-agent-sandbox/run-on-host/abc123/gradle-user-home")
  private val gradlePrereqs = prereqs.copy(program = Program.Gradle, executable = gradleHome.resolve("bin/gradle"))
  private def gradleInputs = millInputs.copy(
    prereqs = gradlePrereqs, distribution = Some(gradleHome), gradleUserHome = Some(gradleUserHome),
    network = Network.Gradle,
  )

  test("gradle grants its distribution to run and its user home to write, and no other program's cache"):
    val text = render(gradleInputs).fold(reason => fail(reason), identity)
    assert(clue(text).contains(s"""(allow process-exec* file-read* (subpath "$gradleHome"))"""))
    assert(text.contains(s"""(allow file-read* file-write* (subpath "$gradleUserHome"))"""))
    assert(!text.contains(s"""process-exec* (subpath "$gradleUserHome")"""))
    assert(!text.contains("sbt-global") && !text.contains("ivy-home") && !text.contains("m2/repository"))

  test("gradle's network is the mill daemon's grant plus outbound to any port of this host"):
    val text = render(gradleInputs).fold(reason => fail(reason), identity)
    assert(clue(text).contains("""(allow network-bind network-inbound (local ip "localhost:*"))"""))
    assert(text.contains("""(allow network-outbound (remote ip "localhost:*"))"""))
    assert(text.contains("""(allow network-outbound (remote ip "localhost:51234"))"""))
    // Under any other program the wide outbound rule is absent, and Gradle's network names no other program.
    for other <- Seq(inputs(), millInputs, mvnInputs) do
      assert(!rendered(other).contains("""(remote ip "localhost:*")"""), other.prereqs.program.name)
    assert(render(mvnInputs.copy(network = Network.Gradle)).isLeft)
    assert(render(gradleInputs.copy(network = Network.ProxyOnly)).isRight)

  test("the program and the Gradle user home agree: gradle needs it and its distribution, the others have none"):
    assert(render(gradleInputs.copy(gradleUserHome = None)).isLeft)
    assert(render(gradleInputs.copy(distribution = None)).isLeft)
    assert(render(gradleInputs.copy(m2Repository = Some(m2Repository))).isLeft)
    assert(render(inputs().copy(gradleUserHome = Some(gradleUserHome))).isLeft)
    assert(render(mvnInputs.copy(gradleUserHome = Some(gradleUserHome))).isLeft)

  private val mvnHome = Paths.get(s"$home/.m2/wrapper/dists/apache-maven-3.9.16/56ba1f9f")
  private val m2Repository = Paths.get(s"$home/.cache/ko-agent-sandbox/run-on-host/abc123/m2/repository")
  private val mvnPrereqs = prereqs.copy(program = Program.Mvn, executable = mvnHome.resolve("bin/mvn"))
  private def mvnInputs =
    millInputs.copy(prereqs = mvnPrereqs, distribution = Some(mvnHome), m2Repository = Some(m2Repository))

  test("mvn grants its distribution to run and its local repository to write, and no sbt cache"):
    val text = render(mvnInputs).fold(reason => fail(reason), identity)
    assert(clue(text).contains(s"""(allow process-exec* file-read* (subpath "$mvnHome"))"""))
    assert(text.contains(s"""(allow file-read* file-write* (subpath "$m2Repository"))"""))
    assert(!text.contains(s"""process-exec* (subpath "$m2Repository")"""))
    assert(!text.contains("sbt-global"))
    assert(!text.contains("ivy-home"))

  test("the program and the Maven local repository agree: mvn needs it, the others have none"):
    assert(render(mvnInputs.copy(m2Repository = None)).isLeft)
    assert(render(mvnInputs.copy(distribution = None)).isLeft)
    assert(render(mvnInputs.copy(sbtGlobal = Some(sbtGlobal))).isLeft)
    assert(render(inputs().copy(m2Repository = Some(m2Repository))).isLeft)
    assert(render(millInputs.copy(m2Repository = Some(m2Repository))).isLeft)

  test("mill renders without the sbt distribution"):
    val text = millText
    assert(!clue(text).contains("sbt-2.0.4.zip"))
    assert(text.contains(millPrereqs.executable.toString))

  test("mill's bootstrap needs no grant of its own: it is a project file, and the project runs"):
    val text = millText
    assert(!clue(text).contains(project.resolve("mill").toString))
    assert(text.contains(s"""(allow file-read* file-write* process-exec* (subpath "$project"))"""))

  // --------------------------------------------------------------------------
  // File rules
  // --------------------------------------------------------------------------

  private val fileRules = FileRules.Resolved(
    Vector(
      FileRules.Line(FileRules.Word.ReadOnly, ".vscode"),
      FileRules.Line(FileRules.Word.ReadOnly, ".kiro/settings/mcp.json"),
      FileRules.Line(FileRules.Word.ReadOnly, "*.code-workspace"),
      FileRules.Line(FileRules.Word.Writable, "node_modules"),
    ),
    Vector(".husky/_"),
    Vector("tools"),
  )

  test("the file rules render in their order between the other allows and the guard, anchored below the project"):
    val text = rendered(inputs(fileRules = fileRules))
    val escaped = project.toString.replace(".", "\\.")
    val rules = Seq(
      s"""(deny file-write* file-link (regex #"^$escaped/(.*/)?\\.vscode(/|$$)"))""",
      s"""(deny file-write-create file-write-unlink file-link (regex #"^$escaped/(.*/)?\\.kiro$$"))""",
      s"""(deny file-write-create file-write-unlink file-link (regex #"^$escaped/(.*/)?\\.kiro/settings$$"))""",
      s"""(deny file-write* file-link (regex #"^$escaped/(.*/)?\\.kiro/settings/mcp\\.json(/|$$)"))""",
      s"""(deny file-write* file-link (regex #"^$escaped/(.*/)?[^/]*\\.code-workspace(/|$$)"))""",
      s"""(allow file-write* (regex #"^$escaped/(.*/)?node_modules(/|$$)"))""",
      s"""(deny file-write* file-link (subpath "$project/.husky/_"))""",
      s"""(deny file-write-create file-write-unlink file-link (literal "$project/.husky"))""",
      s"""(deny file-write-create file-write-unlink file-link (literal "$project/tools"))""",
    )
    val textLines = text.linesIterator.toVector
    val positions = rules.map(rule => textLines.indexOf(rule))
    rules.zip(positions).foreach((rule, position) => assert(position >= 0, s"$rule\n$text"))
    // SBPL's last matching filter decides, as the filter's last matching line does, so the order is the lines' own.
    assertEquals(positions, positions.sorted)
    val lastOtherAllow = textLines.lastIndexWhere(line => line.startsWith("(allow") && !line.contains("node_modules"))
    val guard = textLines.indexWhere(_.contains("\\.git(/|$)"))
    assert(lastOtherAllow < positions.head && positions.last < guard, text)

  test("a writable line after a readonly one lifts its deny, and an equal filter keeps its last position"):
    val lifted = FileRules.Resolved(
      Vector(
        FileRules.Line(FileRules.Word.ReadOnly, ".claude/settings.json"),
        FileRules.Line(FileRules.Word.Writable, ".claude"),
        FileRules.Line(FileRules.Word.ReadOnly, ".claude/settings.json"),
      ),
      Vector.empty,
      Vector.empty,
    )
    val filters = fileRuleFilters(project, lifted).fold(reason => fail(reason), identity)
    assertEquals(filters.map(_(0)), Vector(Protection.Writable, Protection.Pinned, Protection.ReadOnly))
    assertEquals(conformanceAnswer(filters, s"$project/.claude"), "pinned")
    assertEquals(conformanceAnswer(filters, s"$project/.claude/settings.json"), "readonly")
    assertEquals(conformanceAnswer(filters, s"$project/.claude/notes.md"), "free")

  test("a readonly-under rest renders last, anchored at its directory, its interiors pinned"):
    val under = FileRules.Resolved(
      Vector(
        FileRules.Line(FileRules.Word.ReadOnly, ".claude/skills/*.md"),
        FileRules.Line(FileRules.Word.Writable, "shared"),
      ),
      Vector.empty,
      Vector("shared/claude"),
      Vector("shared/claude" -> "skills/*.md"),
    )
    val filters = fileRuleFilters(project, under).fold(reason => fail(reason), identity)
    assertEquals(conformanceAnswer(filters, s"$project/shared/claude/skills/new.md"), "readonly")
    assertEquals(conformanceAnswer(filters, s"$project/shared/claude/skills"), "pinned")
    assertEquals(conformanceAnswer(filters, s"$project/shared/claude"), "pinned")
    assertEquals(conformanceAnswer(filters, s"$project/shared"), "pinned")
    assertEquals(conformanceAnswer(filters, s"$project/shared/claude/notes.md"), "free")
    assertEquals(conformanceAnswer(filters, s"$project/shared/other/skills/new.md"), "free")
    for directory <- Vector("../x", "", "/etc", "a\"b") do
      assert(fileRuleFilters(project, under.copy(readOnlyUnder = Vector(directory -> "a"))).isLeft, directory)
    val odd = under.copy(pinnedPaths = Vector.empty, readOnlyUnder = Vector("c++ (x)/claude" -> "skills/*.md"))
    val oddFilters = fileRuleFilters(project, odd).fold(reason => fail(reason), identity)
    assertEquals(conformanceAnswer(oddFilters, s"$project/c++ (x)/claude/skills/new.md"), "readonly")
    assertEquals(conformanceAnswer(oddFilters, s"$project/cxx (x)/claude/skills/new.md"), "free")

  test("what the filter prints for a symlinked directory renders as the filter decides it"):
    // rulefile.rs, an_alias_prints_the_read_only_rests_it_carries_and_decides_below_its_path.
    val printed = "readonly .claude/settings.json\nreadonly .claude/skills\npinned-path Shared/claude\n" +
      "readonly-under Shared/claude settings.json\nreadonly-under Shared/claude skills\n"
    val resolved = FileRules.parseResolved(printed).fold(reason => fail(reason), identity)
    val filters = fileRuleFilters(project, resolved).fold(reason => fail(reason), identity)
    assertEquals(conformanceAnswer(filters, s"$project/Shared/claude/skills/new.md"), "readonly")
    assertEquals(conformanceAnswer(filters, s"$project/Shared/claude/settings.json"), "readonly")
    assertEquals(conformanceAnswer(filters, s"$project/Shared/claude/notes.md"), "free")

  test("a project path SBPL cannot spell, and a guard path leaving the project, are refused"):
    assert(fileRuleFilters(Paths.get("/Users/a\"b/p"), fileRules).isLeft)
    assert(fileRuleFilters(project, fileRules.copy(readOnlyPaths = Vector("../outside"))).isLeft)
    assert(fileRuleFilters(project, fileRules.copy(pinnedPaths = Vector(""))).isLeft)
    assert(render(inputs(fileRules = fileRules.copy(readOnlyPaths = Vector("a/../../b")))).isLeft)

  test("regex metacharacters in the project's own path are literal"):
    val odd = Paths.get("/Users/u/c++ (work)/p.1")
    val filters = fileRuleFilters(odd, fileRules).fold(reason => fail(reason), identity)
    val vscode = filters.collectFirst { case (Protection.ReadOnly, filter) if filter.contains("vscode") => filter }.get
    assert(clue(vscode).startsWith("""(regex #"^/Users/u/c\+\+ \(work\)/p\.1/(.*/)?"""))
    assert(conformanceAnswer(filters, "/Users/u/c++ (work)/p.1/src/.vscode/tasks.json") == "readonly")
    assert(conformanceAnswer(filters, "/Users/u/cxx (work)/p.1/src/.vscode/tasks.json") == "free")

  /** How SBPL decides a path against the file-rule filters alone: the last filter matching it.
    * An allow, or no match, leaves it free; a deny keeps it read-only when the last read-only or
    * writable filter matching it is read-only, since that one's subtree is what a child sees, and
    * pinned otherwise. The regexes use no syntax where Java's and SBPL's differ: anchors, groups,
    * alternation, `.*`, `[^/]` and backslash escapes. */
  private def conformanceAnswer(filters: Vector[(Protection, String)], path: String): String =
    val Regex = """\(regex #"(.*)"\)""".r
    val Subpath = """\(subpath "(.*)"\)""".r
    val Literal = """\(literal "(.*)"\)""".r
    def matches(filter: String): Boolean = filter match
      case Regex(pattern)   => java.util.regex.Pattern.compile(pattern).matcher(path).find()
      case Subpath(root)    => path == root || path.startsWith(root + "/")
      case Literal(literal) => path == literal
      case other            => fail(s"no conformance reading of $other")
    val matching = filters.filter((_, filter) => matches(filter)).map(_(0))
    matching.lastOption match
      case None | Some(Protection.Writable) => "free"
      case _ if matching.filterNot(_ == Protection.Pinned).lastOption.contains(Protection.ReadOnly) => "readonly"
      case _ => "pinned"

  test("the profile answers the file rules' conformance table as the filter does"):
    // The table the filter's own test reads (fuse/ko-agent-fs/tests/file_rules.rs): one contract,
    // both enforcement points. `folded` rows are the filter's alone.
    val text = Files.readString(Paths.get("fuse/ko-agent-fs/tests/data/file-rules.conformance"))
    case class Case(name: String, lines: Vector[(String, String)], rows: Vector[(String, String)])
    val cases = text.linesIterator.foldLeft(Vector.empty[Case]): (cases, line) =>
      line.split(" ").toVector match
        case Vector("") => cases
        case first +: _ if first.startsWith("#") => cases
        case "case" +: name => cases :+ Case(name.mkString(" "), Vector.empty, Vector.empty)
        case Vector("line", word, name) => cases.init :+ cases.last.copy(lines = cases.last.lines :+ (word -> name))
        case Vector("path", path, expected) =>
          cases.init :+ cases.last.copy(rows = cases.last.rows :+ (path -> expected))
        case Vector("folded", _, _) => cases
        case _ => fail(s"not a conformance line: $line")
    assert(cases.size >= 10, "the table did not parse into its cases")
    val failures = cases.flatMap: testCase =>
      val ruleLines = testCase.lines.collect:
        case ("readonly", name) => FileRules.Line(FileRules.Word.ReadOnly, name)
        case ("writable", name) => FileRules.Line(FileRules.Word.Writable, name)
      val resolved = FileRules.Resolved(
        ruleLines,
        testCase.lines.collect { case ("readonly-path", path) => path },
        testCase.lines.collect { case ("pinned-path", path) => path },
      )
      val filters = fileRuleFilters(project, resolved).fold(reason => fail(reason), identity)
      testCase.rows.flatMap: (path, expected) =>
        val got = conformanceAnswer(filters, s"$project/$path")
        Option.when(got != expected)(s"${testCase.name}: $path: expected $expected, got $got")
    assert(failures.isEmpty, failures.mkString("\n"))
