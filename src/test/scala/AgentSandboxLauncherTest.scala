// What remains launcher-owned after the per-file suites split off: the run/reset naming that
// keeps projects apart, the configuration surface, the build verbs, and the documents the code
// must stay in step with (README's --help copy, SECURITY.md's forge list against the proxy's
// source, the bundled context).

package agentsandbox.launcher

import java.nio.file.{Files, Paths}

import AgentSandboxLauncher.*
import EgressProxyPolicy.*
import KoAgentFs.bundledSourceId

class AgentSandboxLauncherTest extends munit.FunSuite:

  /** Stand-ins for the launcher-owned empty bind sources (emptyMountSources), outside any project. */

  test("a misspelled launcher variable is reported, a foreign or known one is not"):
    // A typo'd KO_AGENT_SANDBOX_MEMORY silently configures nothing; the warning in main is what
    // closes that, and this is the classification it relies on.
    assertEquals(
      unknownSandboxVariables(Seq("KO_AGENT_SANDBOX_MEMROY", "PATH", "KO_AGENT_SANDBOX_MEMORY")),
      Vector("KO_AGENT_SANDBOX_MEMROY")
    )
    // Every documented variable is known — including EGRESS_POLICY, which the launcher sets inside
    // the sandbox rather than reads, so a launcher nested in a session is not warned about it.
    assertEquals(unknownSandboxVariables(KnownSandboxVariables), Vector.empty)
    assertEquals(unknownSandboxVariables(Seq("HOME", "JAVA_HOME")), Vector.empty)

  test("the nesting opt-in fails closed and its loosenings are exactly the priced ones"):
    // The same fail-closed contract as the workspace guard, through the same closedChoice —
    // the old on/off values are refused, not remapped.
    assertEquals(nestingMode(None), Right("none"))
    assertEquals(nestingMode(Some("")), Right("none"))
    assertEquals(nestingMode(Some("none")), Right("none"))
    assertEquals(nestingMode(Some("same-uid")), Right("same-uid"))
    Vector("on", "off", "ON", "1", "true", "single-uid", "SAME-UID", " same-uid ").foreach: value =>
      assert(nestingMode(Some(value)).isLeft, s"'$value' was not refused")
    val refused = nestingMode(Some("on")).swap.getOrElse("")
    assert(refused.contains("the only values are none and same-uid, exactly"), refused)
    assert(refused.contains("Unset it (or set it to none) to keep /proc masked"), refused)
    // What a nesting-enabled session loosens is these three flags and nothing else; SECURITY.md
    // prices exactly this set, so a fourth entry here is a doc change too.
    assertEquals(
      NestingLoosenings,
      Vector("--security-opt=unmask=ALL", "--security-opt=label=disable", "--cap-add=SYS_CHROOT")
    )

  test("--help's Environment section and KnownSandboxVariables cannot drift apart"):
    // A variable in one but not the other is either undocumented or warned about as a typo. This
    // is also why the pair lives beside UsageText rather than in HostCommands, whose contract is
    // to know nothing of the sandbox.
    val documented = "KO_AGENT_SANDBOX_[A-Z_]+".r.findAllIn(UsageText).toSet
    assertEquals(unknownSandboxVariables(documented), Vector.empty)
    // Everything known is documented, except the one the launcher sets rather than reads.
    assertEquals(KnownSandboxVariables -- documented, Set("KO_AGENT_SANDBOX_EGRESS_POLICY"))

  test("README reproduces the --help text"):
    // README's Reference section is a copy of UsageText, and a copy that can drift is one that
    // will — the --reset wording had to be changed in both. This is what makes the duplication
    // safe to keep. The path is relative because sbt runs tests from the repository root.
    val readme = Files.readString(Paths.get("README.md")).linesIterator.toVector
    UsageText.linesIterator.filter(_.trim.nonEmpty).foreach: line =>
      assert(readme.contains("    " + line), s"README is missing the --help line: '$line'")

  test("the proxy address is read for the right network only"):
    val output =
      "ko-agent-egress-app-abc123-1a2b3c4d 10.89.0.2\n" +
        "ko-agent-sandbox-app-abc123-1a2b3c4d 10.89.1.2\n"
    assertEquals(addressOn(output, "ko-agent-sandbox-app-abc123-1a2b3c4d"), Some("10.89.1.2"))
    assertEquals(addressOn(output, "ko-agent-egress-app-abc123-1a2b3c4d"), Some("10.89.0.2"))
    assertEquals(addressOn(output, "missing"), None)

  test("build commands run in dependency order with the pinned base tag"):
    val commands = buildCommands("podman", "1.2-3", "sourceid", "sandboxid", "proxyid")
    assertEquals(commands.map(_.last), Vector(
      "debian-temurin",
      "debian-coursier",
      "ko-agent-sandbox",
      "ko-agent-egress-proxy",
      "ko-agent-fs"
    ))
    assert(commands(0).contains("debian-temurin:1.2-3"))
    // debian-temurin's Containerfile does not consume IMG_TAG_VER.
    assert(!commands(0).contains("--build-arg"))
    assert(commands(1).contains("debian-coursier:1.2-3"))
    assert(commands(2).contains("ko-agent-sandbox:latest"))
    assert(commands(3).contains("ko-agent-egress-proxy:latest"))
    // Keeps the proxy's compile stage cached across builds; see the buildCommands doc comment.
    assert(commands(3).contains("--save-stages"))
    // The single-stage builds have no stages to save.
    (commands.take(3) :+ commands(4)).foreach(command => assert(!command.contains("--save-stages")))
    commands.slice(1, 4).foreach: command =>
      assert(command.containsSlice(Seq("--build-arg", "IMG_TAG_VER=1.2-3")))
    // ko-agent-fs builds on rust:slim with its own pins; its identity is the source digest instead.
    assert(commands(4).contains("ko-agent-fs:latest"))
    assert(commands(4).containsSlice(Seq("--build-arg", "KO_AGENT_FS_SOURCE_ID=sourceid")))
    assert(!commands(4).exists(_.startsWith("IMG_TAG_VER=")))
    // The two launcher-facing images carry their bundle digest (the version lock); the base
    // images and the filter do not — the filter's identity is its own source id above.
    assert(commands(2).containsSlice(Seq("--build-arg", "BUNDLE_ID=sandboxid")))
    assert(commands(3).containsSlice(Seq("--build-arg", "BUNDLE_ID=proxyid")))
    (commands.take(2) :+ commands(4)).foreach: command =>
      assert(!command.exists(_.startsWith("BUNDLE_ID=")))

  test("update rebuilds only the sandbox image, without cache"):
    val commands = updateCommands("podman", "1.2-3", "sandboxid")
    assertEquals(commands.map(_.last), Vector("ko-agent-sandbox"))
    assert(commands.head.contains("--no-cache"))
    assert(commands.head.contains("ko-agent-sandbox:latest"))
    assert(commands.head.containsSlice(Seq("--build-arg", "BUNDLE_ID=sandboxid")))

  test("the bundle version lock refuses a mismatch and knows an unlabeled image"):
    // The digests compared come from the jar's own bundle, one per image directory — real,
    // 64-hex, and distinct, or the lock would equate the two images.
    val sandboxId = bundledSourceId("ko-agent-sandbox")
    val proxyId = bundledSourceId("ko-agent-egress-proxy")
    Vector(sandboxId, proxyId).foreach: id =>
      assert(id.length == 64 && id.forall(ch => ch.isDigit || (ch >= 'a' && ch <= 'f')), id)
    assert(sandboxId != proxyId)

    assertEquals(bundleMismatch("ko-agent-sandbox:latest", sandboxId, sandboxId), None)
    // podman's template yields a trailing newline; the comparison must not trip on it.
    assertEquals(bundleMismatch("ko-agent-sandbox:latest", sandboxId, s"$sandboxId\n"), None)
    val stale = bundleMismatch("ko-agent-sandbox:latest", sandboxId, proxyId)
    assert(stale.exists(_.contains("rebuild with --build")), stale.toString)
    val unlabeled = bundleMismatch("ko-agent-sandbox:latest", sandboxId, "")
    assert(unlabeled.exists(_.contains("no bundle label")), unlabeled.toString)

  private def buildContextResource(name: String): String =
    val stream = getClass.getResourceAsStream(s"/sandbox-build/$name")
    assert(stream != null, name)
    try String(stream.readAllBytes(), "UTF-8")
    finally stream.close()

  test("the bundled build context carries every Containerfile and an INDEX"):
    // The resourceGenerators task in build.sbt put these in the jar; this pins that the launcher can find what --build
    // unpacks.
    val index = buildContextResource("INDEX").linesIterator.filter(_.nonEmpty).toVector
    Vector(
      "debian-temurin/Containerfile",
      "debian-coursier/Containerfile",
      "ko-agent-sandbox/Containerfile",
      "ko-agent-egress-proxy/Containerfile",
      "ko-agent-fs/Containerfile"
    ).foreach: path =>
      assert(index.contains(path), s"INDEX missing $path")
      assert(buildContextResource(path).contains("FROM"), path)

    // The one executable the sandbox image adds itself. It is the only way an agent-installed JVM
    // reaches an inspected forge host, so a bundle without it is a silently degraded sandbox.
    assert(index.contains("ko-agent-sandbox/sandbox-trust-ca"), "trust-ca script missing")
    assert(
      buildContextResource("ko-agent-sandbox/sandbox-trust-ca").contains("-importcert"),
      "the trust-ca script does not import anything"
    )
    assert(index.contains("ko-agent-sandbox/sandbox-apt-get"), "sandbox-apt-get script missing")
    assert(
      buildContextResource("ko-agent-sandbox/sandbox-apt-get").contains("--download-only"),
      "sandbox-apt-get does not resolve dependencies"
    )

    // ko-agent-fs is compiled from source on the user's machine rather than shipped as a binary, so its sources —
    // not just its Containerfile — have to travel in the jar. The policy core is the one that matters most.
    Vector("ko-agent-fs/src/policy.rs", "ko-agent-fs/Cargo.lock", "ko-agent-fs/deny.toml").foreach: path =>
      assert(index.contains(path), s"INDEX missing $path")
    assert(buildContextResource("ko-agent-fs/src/policy.rs").contains("is_dotgit_name"))

    // Build output must not have been swept into the bundle — Rust's target/ as well as sbt's.
    assert(!index.exists(_.split("/").contains("target")), "target leaked")

    // ko-agent-fs/docs and ko-agent-fs/probes are deliberately absent: neither is distribution nor
    // a build input, and keeping them out is what stops editing a design document or a platform
    // probe from changing koAgentFsSourceId and invalidating every installed filter binary.
    Vector("ko-agent-fs/docs/", "ko-agent-fs/probes/").foreach: prefix =>
      assert(!index.exists(_.startsWith(prefix)), s"$prefix leaked into the jar")

  test("ImgTagVersion mirrors debian-temurin's Debian and Temurin pins"):
    // The two pins live in debian-temurin's Containerfile, the combined tag here; a bump edits both
    // files, and this is the check that they moved together.
    val tag = "([0-9.]+)-([0-9.]+)-[0-9]+".r
    ImgTagVersion match
      case tag(debian, temurin) =>
        val lines = buildContextResource("debian-temurin/Containerfile").linesIterator.toVector
        assert(
          lines.contains(s"FROM docker.io/library/debian:$debian-slim"),
          s"debian-temurin does not pin debian:$debian-slim"
        )
        assert(
          lines.contains(s"ARG TEMURIN_VERSION=$temurin"),
          s"debian-temurin does not pin TEMURIN_VERSION=$temurin"
        )
      case _ => fail(s"ImgTagVersion '$ImgTagVersion' is not <debian>-<temurin>-<revision>")

  test("SECURITY.md names exactly the =git-tagged hosts the proxy ships"):
    // The git-host list has two homes: the =git-fetch entries of the proxy's DefaultReadOnlyHosts and
    // the SECURITY.md section that reasons about them (the launcher carries no copy — the leaf's
    // names come from the image's own --print-policy at launch). This scrapes both texts; it
    // depends on the rest of the read-only tier never being written as a `1. \`host\`` list in
    // SECURITY.md — prose or a different marker keeps this green.
    val Listed = """^1\. `([^`]+)`$""".r
    val listed = Files
      .readString(Paths.get("docs/SECURITY.md"))
      .linesIterator
      .collect { case Listed(host) => host }
      .toVector
    val proxySource = Files.readString(
      Paths.get("container/ko-agent-egress-proxy/app/src/main/scala/AgentEgressProxy.scala")
    )
    val block = proxySource.substring(proxySource.indexOf("val DefaultReadOnlyHosts"))
    val gitHosts = "\"([^\"]+)=git-fetch\"".r
      .findAllMatchIn(block.substring(0, block.indexOf(").map(")))
      .map(_.group(1))
      .toVector
    assertEquals(listed, gitHosts)

  test("the read-only line of --print-policy parses to the leaf's names, tags stripped"):
    // What launch feeds mintLeaf: the image's own read-only line — the leaf names hosts; which
    // treatment each gets is the proxy's business. A zero-count line is a real answer, not a
    // parse error: it means no leaf at all.
    assertEquals(
      inspectedHostsOf(
        "read-write hosts (1): api.example\n" +
          "read-only hosts (3): docs.example github.com=git-fetch gitlab.com=git-fetch"
      ),
      Right(Vector("docs.example", "github.com", "gitlab.com"))
    )
    assertEquals(
      inspectedHostsOf("read-write hosts (1): api.example\nread-only hosts (0):"),
      Right(Vector.empty[String])
    )
    assert(inspectedHostsOf("garbage").isLeft)

  test("reset removes exactly this project's per-run networks"):
    val names = Seq(
      "ko-agent-sandbox-app-abc123-1a2b3c4d",
      "ko-agent-egress-app-abc123-1a2b3c4d",
      "ko-agent-sandbox-other-def456-99aabbcc", // another project's
      "podman"
    )
    assertEquals(
      projectNetworks(names, "app-abc123"),
      Seq(
        "ko-agent-sandbox-app-abc123-1a2b3c4d",
        "ko-agent-egress-app-abc123-1a2b3c4d"
      )
    )

  test("a directory named after another project's id cannot match its run filters"):
    // Hex is slug-legal, so a checkout named after a victim's id ("app-abc123-9f8e7d6c" here) produces resources whose
    // names extend the victim's prefix; the eight-hex suffix anchor in isRunNamed keeps them apart, so the victim's
    // --reset and --proxy-log never touch them.
    val victimId = "app-abc123"
    assertEquals(
      projectNetworks(Seq("ko-agent-sandbox-app-abc123-9f8e7d6c-1a2b3c4d"), victimId),
      Seq()
    )
    assert(!isRunNamed(proxyRunContainer, victimId)("ko-agent-egress-proxy-app-abc123-9f8e7d6c-1a2b3c4d"))
    assert(!isRunNamed(sandboxRunContainer, victimId)("ko-agent-sandbox-run-app-abc123-9f8e7d6c-1a2b3c4d"))
    // The honest names — an eight-hex suffix right after the id — still match.
    assert(isRunNamed(proxyRunContainer, victimId)("ko-agent-egress-proxy-app-abc123-1a2b3c4d"))
    assert(isRunNamed(sandboxRunContainer, victimId)("ko-agent-sandbox-run-app-abc123-1a2b3c4d"))
    // And the minted suffix is what the anchor assumes: exactly eight hex characters.
    assert(newRunSuffix().matches("[0-9a-f]{8}"))

  test("reset filters keep only launcher-created podman objects"):
    assertEquals(
      proxyContainers(Seq("ko-agent-egress-proxy-app-abc", "some-other-container")),
      Seq("ko-agent-egress-proxy-app-abc")
    )
    assertEquals(
      sandboxRunContainers(
        Seq("ko-agent-sandbox-run-app-abc-1a2b3c4d", "ko-agent-egress-proxy-app-abc", "other")
      ),
      Seq("ko-agent-sandbox-run-app-abc-1a2b3c4d")
    )
    assertEquals(
      persistentVolumes(Seq("ko-agent-sandbox-persistent-app-abc", "my-shared-volume")),
      Seq("ko-agent-sandbox-persistent-app-abc")
    )
    assertEquals(
      launcherNetworks(
        Seq(
          "ko-agent-sandbox-app-abc-1a2b3c4d",
          "ko-agent-egress-app-abc-1a2b3c4d",
          "podman",
          "bridge"
        )
      ),
      Seq("ko-agent-sandbox-app-abc-1a2b3c4d", "ko-agent-egress-app-abc-1a2b3c4d")
    )

  test("per-run resources are named apart from every other resource"):
    val sandbox = sandboxRunContainer("app-abc123", "1a2b3c4d")
    val proxy = proxyRunContainer("app-abc123", "1a2b3c4d")
    assertEquals(sandbox, "ko-agent-sandbox-run-app-abc123-1a2b3c4d")
    assertEquals(proxy, "ko-agent-egress-proxy-app-abc123-1a2b3c4d")
    assertEquals(
      sandboxRunNetwork("app-abc123", "1a2b3c4d"),
      "ko-agent-sandbox-app-abc123-1a2b3c4d"
    )
    assertEquals(
      egressRunNetwork("app-abc123", "1a2b3c4d"),
      "ko-agent-egress-app-abc123-1a2b3c4d"
    )
    // The reset filters must sweep each through its own filter and never through the other's.
    assertEquals(proxyContainers(Seq(sandbox, proxy)), Seq(proxy))
    assertEquals(sandboxRunContainers(Seq(sandbox, proxy)), Seq(sandbox))
