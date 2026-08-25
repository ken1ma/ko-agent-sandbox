// What remains launcher-owned after the per-file suites split off: the run/reset naming that
// keeps projects apart, the configuration surface, the build verbs, and the documents the code
// must stay in step with (the --help text's Environment section, SECURITY.md's forge list against
// the proxy's source, the bundled context).

package agentsandbox.launcher

import java.nio.file.{Files, Paths}
import scala.jdk.CollectionConverters.*

import AgentSandboxLauncher.*
import HostCommands.Os
import ContainerfileSources.*
import LauncherImages.*
import KoAgentFs.bundledSourceId

class AgentSandboxLauncherTest extends munit.FunSuite:

  /** What the parser fixtures below treat as launcher-built rather than an external image. */
  private val LocalImages = Set("local-base:1")


  test("a misspelled launcher variable is reported, a foreign or known one is not"):
    // A typo'd KO_AGENT_SANDBOX_MEMORY silently configures nothing; the warning in main is what
    // closes that, and this is the classification it relies on.
    assertEquals(
      unknownSandboxVariables(Seq("KO_AGENT_SANDBOX_MEMROY", "PATH", "KO_AGENT_SANDBOX_MEMORY")),
      Vector("KO_AGENT_SANDBOX_MEMROY")
    )
    // Every documented variable is known — KO_AGENT_SANDBOX_EGRESS_POLICY included, which the
    // launcher sets inside the sandbox rather than reads, so a launcher nested in a session is not
    // warned about it.
    assertEquals(unknownSandboxVariables(KnownSandboxVariables), Vector.empty)
    assertEquals(unknownSandboxVariables(Seq("HOME", "JAVA_HOME")), Vector.empty)

  test("the nesting opt-in fails closed and its loosenings are exactly the priced ones"):
    // The same fail-closed contract as the workspace guard, through the same closedChoice.
    assertEquals(nestingMode(None), Right("none"))
    assertEquals(nestingMode(Some("")), Right("none"))
    assertEquals(nestingMode(Some("none")), Right("none"))
    assertEquals(nestingMode(Some("same-uid")), Right("same-uid"))
    Vector("on", "off", "ON", "1", "true", "single-uid", "SAME-UID", " same-uid ").foreach: value =>
      assert(nestingMode(Some(value)).isLeft, s"'$value' was not refused")
    val refused = nestingMode(Some("on")).swap.getOrElse("")
    assert(refused.contains("the only values are none and same-uid, exactly"), refused)
    assert(refused.contains("Unset it (or set it to none) to allow no runtime"), refused)
    // What a nesting-enabled session loosens is these three flags and nothing else; SECURITY.md
    // prices exactly this set, so a fourth entry here is a doc change too.
    assertEquals(
      NestingLoosenings,
      Vector("--security-opt=unmask=ALL", "--security-opt=label=disable", "--cap-add=SYS_CHROOT")
    )

  test("the session start defaults to pausing and fails closed on anything else"):
    // The pause is what makes the launch's lines readable at all, so an unrecognized value must
    // not be read as the silent side — the same closedChoice contract as the two above. `none`
    // among the refusals: it is the other two variables' off-switch, and nothing here is spelled
    // by analogy with a neighbouring variable.
    assertEquals(sessionStart(None), Right("pause"))
    assertEquals(sessionStart(Some("")), Right("pause"))
    assertEquals(sessionStart(Some("pause")), Right("pause"))
    assertEquals(sessionStart(Some("immediate")), Right("immediate"))
    Vector("none", "off", "0", "false", "no", "PAUSE", " pause ", "now", "skip").foreach: value =>
      assert(sessionStart(Some(value)).isLeft, s"'$value' was not refused")

  test("the clipboard defaults to off and fails closed on anything else"):
    assertEquals(clipboardMode(None), Right("off"))
    assertEquals(clipboardMode(Some("")), Right("off"))
    assertEquals(clipboardMode(Some("off")), Right("off"))
    assertEquals(clipboardMode(Some("paste")), Right("paste"))
    assertEquals(clipboardMode(Some("bidirectional")), Right("bidirectional"))
    Vector("on", "true", "1", "read", "copy", "both", "PASTE", " paste ").foreach: value =>
      assert(clipboardMode(Some(value)).isLeft, s"'$value' was not refused")

  test("a clipboard mode is refused where the host cannot serve it"):
    // Windows needs PowerShell by absolute path; Linux one of the two tools the broker calls; off
    // needs nothing anywhere. `here` is a checkout: an entry in it must never satisfy the search.
    val bin = java.nio.file.Files.createTempDirectory("clipboard-host")
    def tool(name: String): Unit =
      val path = bin.resolve(name)
      java.nio.file.Files.writeString(path, "")
      path.toFile.setExecutable(true)
    assertEquals(ClipboardBroker.hostBackend("off", Os.Linux, ""), Right(None))
    assert(ClipboardBroker.hostBackend("paste", Os.Linux, bin.toString).isLeft)
    assert(ClipboardBroker.hostBackend("paste", Os.Windows, bin.toString).isLeft)
    assertEquals(ClipboardBroker.hostBackend("paste", Os.Mac, ""), Right(None))
    tool("wl-paste")
    assertEquals(ClipboardBroker.hostBackend("bidirectional", Os.Linux, bin.toString), Right(None))
    tool("powershell.exe")
    assertEquals(
      ClipboardBroker.hostBackend("paste", Os.Windows, bin.toString),
      Right(Some(bin.resolve("powershell.exe")))
    )

  test("--help's Environment section and KnownSandboxVariables cannot drift apart"):
    // A variable in one but not the other is either undocumented or warned about as a typo. This
    // is also why the pair lives beside UsageText rather than in HostCommands, whose contract is
    // to know nothing of the sandbox.
    val documented = "KO_AGENT_SANDBOX_[A-Z_]+".r.findAllIn(UsageText).toSet
    assertEquals(unknownSandboxVariables(documented), Vector.empty)
    // Everything known is documented, except the one the launcher sets rather than reads.
    assertEquals(KnownSandboxVariables -- documented, Set("KO_AGENT_SANDBOX_EGRESS_POLICY"))

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
      "ko-agent-egress-proxy",
      "ko-agent-fs",
      "ko-agent-fs"
    ))
    assert(commands(0).contains("debian-temurin:1.2-3"))
    // debian-temurin's Containerfile does not consume IMG_TAG_VER.
    assert(!commands(0).contains("--build-arg"))
    assert(commands(1).contains("debian-coursier:1.2-3"))
    assert(commands(2).contains("ko-agent-sandbox:latest"))
    assert(commands(3).contains(ProxyBuildImage))
    assert(commands(3).containsSlice(Seq("--target", "build")))
    assert(commands(4).contains("ko-agent-egress-proxy:latest"))
    commands.foreach(command => assert(!command.contains("--save-stages")))
    commands.slice(1, 5).foreach: command =>
      assert(command.containsSlice(Seq("--build-arg", "IMG_TAG_VER=1.2-3")))
    // ko-agent-fs builds on rust:slim with its own pins; its identity is the source digest instead.
    assert(commands(5).contains(KoAgentFsBuildImage))
    assert(commands(5).containsSlice(Seq("--target", "build")))
    assert(commands(6).contains("ko-agent-fs:latest"))
    commands.slice(5, 7).foreach: command =>
      assert(command.containsSlice(Seq("--build-arg", "KO_AGENT_FS_SOURCE_ID=sourceid")))
      assert(!command.exists(_.startsWith("IMG_TAG_VER=")))
    // The two launcher-facing images carry their bundle digest (the version lock); the base
    // images and the filter do not — the filter's identity is its own source id above. The
    // digest travels both as the Containerfile's build arg and as a commit-time --label,
    // because podman's layer cache serves ARG-derived LABEL steps stale (buildCommands doc).
    assert(commands(2).containsSlice(Seq("--build-arg", "BUNDLE_ID=sandboxid")))
    assert(commands(4).containsSlice(Seq("--build-arg", "BUNDLE_ID=proxyid")))
    assert(commands(2).containsSlice(Seq("--label", s"$BundleLabel=sandboxid")))
    assert(commands(4).containsSlice(Seq("--label", s"$BundleLabel=proxyid")))
    (commands.take(2) ++ Vector(commands(3), commands(5), commands(6))).foreach: command =>
      assert(!command.exists(_.startsWith("BUNDLE_ID=")))
      assert(!command.contains("--label"))

  test("image-producing verbs refresh exactly the remote sources their Containerfiles use"):
    val readContainerfile: String => String = buildContextResource
    val localImages = managedImageTags("1.2-3").toSet
    val buildCommands = AgentSandboxLauncher.buildCommands(
      "podman", "1.2-3", "sourceid", "sandboxid", "proxyid"
    )
    val buildImages = remoteImagesForBuildCommands(buildCommands, readContainerfile, localImages)
    def repository(image: String): String = image.take(image.lastIndexOf(':'))
    assertEquals(
      buildImages.map(repository),
      Vector(
        "docker.io/library/debian",
        "ghcr.io/astral-sh/uv",
        "gcr.io/distroless/java25-debian13",
        "docker.io/library/rust"
      )
    )
    assertEquals(
      remoteImagesForBuildCommands(
        updateCommands("podman", "1.2-3", "sandboxid"), readContainerfile, localImages
      ),
      buildImages.filter(_.startsWith("ghcr.io/astral-sh/uv:"))
    )
    assertEquals(
      remoteImagesForBuildCommands(
        selfTestBuildCommands("podman", "test-rust", "sourceid", "selftestid"),
        readContainerfile,
        localImages
      ),
      Vector("docker.io/library/rust:test-rust-slim-trixie")
    )
    assertEquals(
      remoteImagePullCommands("podman", buildImages),
      buildImages.map(image => Vector("podman", "pull", image))
    )
    buildCommands.foreach: command =>
      assert(!command.exists(_.startsWith("--pull")), command.mkString(" "))

  test("remote image parsing reads every shape the bundled Containerfiles use"):
    assertEquals(
      remoteImagesInContainerfile(
        "Containerfile",
        """# a comment
          |ARG REGISTRY=example.invalid
          |ARG NAME=first
          |ARG NAME=second
          |ARG SUPPLIED
          |from ${REGISTRY}/one/${NAME}:current as build
          |FROM local-base:${SUPPLIED}
          |FROM scratch
          |ARG REGISTRY
          |RUN --mount=type=cache,target=/build/target \
          |    --mount=type=cache,target=/usr/local/cargo/registry \
          |    cargo build
          |COPY --chown=nonroot:nonroot app /build/app
          |COPY --from=${REGISTRY}/two/tool:latest /tool /tool
          |COPY --from=build /a /b
          |""".stripMargin,
        Map("SUPPLIED" -> "1"),
        LocalImages,
        None
      ),
      Right(Vector("example.invalid/one/second:current", "example.invalid/two/tool:latest"))
    )

  test("an image reaches the build through a mount or a continued COPY, and is refreshed too"):
    // Podman takes an image from a --mount's own from=, not only from COPY --from. Reading COPY
    // alone would leave --build silently skipping a source the build then pulls itself.
    assertEquals(
      remoteImagesInContainerfile(
        "Containerfile",
        """FROM example.invalid/base:1 AS build
          |RUN --mount=type=bind,from=example.invalid/mounted:2,target=/m true
          |COPY \
          |  --from=example.invalid/tool:3 /a /b
          |RUN --mount=type=cache,target=/build/target \
          |    --mount=type=bind,from=example.invalid/continued:4,target=/m \
          |    cargo build
          |FROM scratch
          |RUN --mount=type=bind,from=build,target=/m true
          |RUN --mount=type=bind,from=0,target=/m true
          |""".stripMargin,
        Map.empty,
        LocalImages,
        None
      ),
      Right(Vector(
        "example.invalid/base:1",
        "example.invalid/mounted:2",
        "example.invalid/tool:3",
        "example.invalid/continued:4"
      ))
    )

  test("from= in an instruction's own words is not an image source"):
    // Scanning every line for from= would have --build reach a registry for a string a RUN merely
    // prints. Only the option words of a COPY or RUN name an image.
    assertEquals(
      remoteImagesInContainerfile(
        "Containerfile",
        """FROM example.invalid/base:1
          |RUN echo from=example.invalid/tool:1
          |LABEL note="see" from=example.invalid/tool:2
          |RUN cargo build --mount=type=bind,from=example.invalid/tool:3
          |""".stripMargin,
        Map.empty,
        LocalImages,
        None
      ),
      Right(Vector("example.invalid/base:1"))
    )

  test("a FROM reads the global arguments, not a later stage's"):
    // Podman gives a FROM only the arguments declared before the first one. Sharing one scope
    // would have --build refresh two.invalid while the build itself pulls one.invalid.
    assertEquals(
      remoteImagesInContainerfile(
        "Containerfile",
        """ARG REGISTRY=one.invalid
          |FROM scratch
          |ARG REGISTRY=two.invalid
          |FROM ${REGISTRY}/tool:1
          |""".stripMargin,
        Map.empty,
        LocalImages,
        None
      ),
      Right(Vector("one.invalid/tool:1"))
    )
    // A stage's own arguments reach its COPY, and a global reaches the stage only where the stage
    // redeclares it — which is why ko-agent-sandbox declares ARG IMG_TAG_VER twice.
    assertEquals(
      remoteImagesInContainerfile(
        "Containerfile",
        """ARG REGISTRY=one.invalid
          |FROM ${REGISTRY}/base:1
          |ARG REGISTRY
          |ARG VERSION=2.0
          |COPY --from=${REGISTRY}/tool:${VERSION} /t /t
          |""".stripMargin,
        Map.empty,
        LocalImages,
        None
      ),
      Right(Vector("one.invalid/base:1", "one.invalid/tool:2.0"))
    )
    val unshared = remoteImagesInContainerfile(
      "Containerfile",
      "ARG REGISTRY=one.invalid\nFROM scratch\nCOPY --from=${REGISTRY}/tool:1 /t /t\n",
      Map.empty,
      LocalImages,
      None
    )
    assert(unshared.swap.exists(_.contains("no value for build-image variable")), unshared.toString)

  test("a stage built on an earlier one keeps the arguments that stage declared"):
    // imagebuilder seeds a stage's arguments from the stage its FROM names, so dropping the scope
    // at every FROM would resolve a descendant's image differently from the build itself.
    assertEquals(
      remoteImagesInContainerfile(
        "Containerfile",
        """FROM scratch AS base
          |ARG REGISTRY=example.invalid
          |FROM base
          |COPY --from=${REGISTRY}/tool:1 /t /t
          |""".stripMargin,
        Map.empty,
        LocalImages,
        None
      ),
      Right(Vector("example.invalid/tool:1"))
    )
    // An unrelated stage inherits nothing, and still says so rather than guessing.
    val unrelated = remoteImagesInContainerfile(
      "Containerfile",
      """FROM scratch AS base
        |ARG REGISTRY=example.invalid
        |FROM scratch
        |COPY --from=${REGISTRY}/tool:1 /t /t
        |""".stripMargin,
      Map.empty,
      LocalImages,
      None
    )
    assert(unrelated.swap.exists(_.contains("no value for build-image variable")), unrelated.toString)

  test("a short image name is identified, not discarded"):
    // Podman resolves a bare name through the host's registries.conf, so one this cannot place is
    // an external image --build would never refresh. Stages, scratch and the launcher's own images
    // are the names it can place; anything else has to stop the verb.
    Vector("FROM alpine:3.20\n", "FROM scratch\nCOPY --from=busybox:1.36 /b /b\n",
      "FROM scratch\nRUN --mount=type=bind,from=busybox:1.36,target=/m true\n"
    ).foreach: text =>
      val refused = remoteImagesInContainerfile("Containerfile", text, Map.empty, LocalImages, None)
      assert(refused.swap.exists(_.contains("unqualified image source")), s"$text -> $refused")
    assertEquals(
      remoteImagesInContainerfile(
        "Containerfile",
        "FROM scratch AS one\nFROM local-base:1\nCOPY --from=one /a /b\nCOPY --from=0 /c /d\n",
        Map.empty,
        LocalImages,
        None
      ),
      Right(Vector.empty)
    )

  test("a reference naming its registry is refreshed, one naming a launcher image is not"):
    // Podman reads the component before the first slash as a host when it is localhost, carries a
    // dot or colon, or holds uppercase. Testing that before the launcher's own images would have
    // --build schedule a pull for an image it is about to build.
    assertEquals(
      remoteImagesInContainerfile(
        "Containerfile",
        """FROM localhost/registry-held:1
          |FROM MyRegistry/uppercase-host:1
          |FROM registry.example:5000/ported:1
          |FROM localhost/local-base:1
          |FROM local-base:1
          |""".stripMargin,
        Map.empty,
        LocalImages,
        None
      ),
      Right(Vector(
        "localhost/registry-held:1",
        "MyRegistry/uppercase-host:1",
        "registry.example:5000/ported:1"
      ))
    )
    // A declared local image is not pulled even when it is spelled with its registry.
    assertEquals(
      remoteImagesInContainerfile(
        "Containerfile",
        "FROM registry.example/base:1\n",
        Map.empty,
        Set("registry.example/base:1"),
        None
      ),
      Right(Vector.empty)
    )
    // Either spelling names the image whichever spelling the caller declared, so both sides of
    // the comparison carry the same normalization.
    Vector(Set("localhost/base:1"), Set("base:1")).foreach: local =>
      assertEquals(
        remoteImagesInContainerfile(
          "Containerfile",
          "FROM localhost/base:1\nFROM base:1\n",
          Map.empty,
          local,
          None
        ),
        Right(Vector.empty),
        local.toString
      )

  test("an unnamed stage keeps its arguments for a descendant that names its position"):
    // imagebuilder records every stage under its position as well as its name, so a chain through
    // an unnamed one still resolves; dropping it would refuse a Containerfile Podman builds.
    assertEquals(
      remoteImagesInContainerfile(
        "Containerfile",
        """FROM scratch
          |ARG REGISTRY=example.invalid
          |FROM 0
          |ARG VERSION=2
          |FROM 1
          |COPY --from=${REGISTRY}/tool:${VERSION} /t /t
          |""".stripMargin,
        Map.empty,
        LocalImages,
        None
      ),
      Right(Vector("example.invalid/tool:2"))
    )

  test("a targeted build reads only the stages it reaches"):
    // --target stops the build there. A later stage is never evaluated, so its images are not
    // this command's to refresh, and the arguments it needs are not the ones this command passes
    // — reading it would refuse, or pull for, a build Podman completes without either.
    val twoStages =
      """ARG REACHED=example.invalid
        |FROM ${REACHED}/base:1 AS build
        |FROM ${UNPASSED}/later:2
        |COPY --from=${UNPASSED}/tool:3 /t /t
        |""".stripMargin
    val targeted = Vector(
      Vector("podman", "build", "--target", "build", "-t", "out:1", "ctx")
    )
    assertEquals(
      remoteImagesForBuildCommands(targeted, _ => twoStages, Set.empty),
      Vector("example.invalid/base:1")
    )
    // Without the target the same Containerfile reaches the stage whose argument is unpassed.
    val whole = remoteImagesInContainerfile("Containerfile", twoStages, Map.empty, Set.empty, None)
    assert(whole.swap.exists(_.contains("${UNPASSED}")), whole.toString)

    // Buildah builds a target and the stages it depends on, not every stage before it, so only a
    // first-stage target is read. A later one would need the stage graph; a target that names no
    // stage would have Podman reject the command after this had already pulled for it.
    val threeStages =
      """FROM example.invalid/zero:1 AS zero
        |FROM example.invalid/one:2 AS one
        |FROM example.invalid/two:3
        |""".stripMargin
    Vector("one", "2", "absent").foreach: stop =>
      val refused =
        remoteImagesInContainerfile("Containerfile", threeStages, Map.empty, Set.empty, Some(stop))
      assert(refused.swap.exists(_.contains(s"unsupported build target $stop")), refused.toString)
    Vector("zero", "0").foreach: stop =>
      assertEquals(
        remoteImagesInContainerfile("Containerfile", threeStages, Map.empty, Set.empty, Some(stop)),
        Right(Vector("example.invalid/zero:1")),
        stop
      )
    // A Containerfile of one stage closes it at end of input rather than at a later FROM.
    assertEquals(
      remoteImagesInContainerfile(
        "Containerfile",
        "FROM example.invalid/only:1 AS only\n",
        Map.empty,
        Set.empty,
        Some("only")
      ),
      Right(Vector("example.invalid/only:1"))
    )

  test("a stage alias is matched exactly, as Buildah matches it"):
    // Instructions are case-insensitive but stage names are not: Buildah compares them exactly,
    // so `AS Build` leaves `build` an ordinary short image name — which nothing here can place.
    assertEquals(
      remoteImagesInContainerfile(
        "Containerfile",
        "FROM scratch AS Build\nARG R=example.invalid\nFROM Build\nCOPY --from=${R}/t:1 /t /t\n",
        Map.empty,
        LocalImages,
        None
      ),
      Right(Vector("example.invalid/t:1"))
    )
    val mismatched = remoteImagesInContainerfile(
      "Containerfile",
      "FROM scratch AS Build\nARG R=example.invalid\nFROM build\nCOPY --from=${R}/t:1 /t /t\n",
      Map.empty,
      LocalImages,
      None
    )
    assert(mismatched.swap.exists(_.contains("unqualified image source build")), mismatched.toString)
    val expanded = remoteImagesInContainerfile(
      "Containerfile",
      "ARG N=one\nFROM scratch AS ${N}\n",
      Map.empty,
      LocalImages,
      None
    )
    assert(expanded.swap.exists(_.contains("unsupported stage alias")), expanded.toString)

  test("remote image parsing refuses a shape it does not resolve"):
    // Every one of these is a Containerfile Podman accepts. Approximating them is what would let a
    // refresh be skipped without a word, so each has to stop the verb instead.
    Vector(
      "FROM example.invalid/base:${UNSET}\n" -> "no value for build-image variable ${UNSET}",
      "ARG V=1.0\nFROM example.invalid/base:$V\n" -> "unsupported build-image variable",
      "ARG V=1.0 # pin\nFROM example.invalid/base:${V}\n" -> "unsupported ARG instruction",
      "ARG A=1.0 B=2.0\nFROM example.invalid/base:${A}\n" -> "unsupported ARG instruction",
      "ARG V=\"1.0\"\nFROM example.invalid/base:${V}\n" -> "unsupported ARG instruction",
      "FROM --platform=linux/arm64 example.invalid/base:1\n" -> "unsupported FROM instruction",
      "ARG V=1.0 \\\n  W=2.0\n" -> "continued instruction",
      "FROM \\\n  example.invalid/base:1\n" -> "continued instruction",
      // `# escape=` is not a comment: it rewrites what a continuation looks like, so a COPY
      // continued with a backtick would hide its --from= on the next line.
      "# escape=`\nCOPY `\n  --from=example.invalid/tool:1 /a /b\n" -> "unsupported parser directive",
      "# syntax=docker/dockerfile:1\nFROM example.invalid/base:1\n" -> "unsupported parser directive",
      // A here-document's body is shell input; the COPY below is text a shell reads, not an
      // instruction, and pulling what it names would reach a registry the build never asks for.
      "FROM scratch\nRUN <<EOF\nCOPY --from=example.invalid/not-an-image:1 /a /b\nEOF\n" ->
        "unsupported here-document"
    ).foreach: (text, expected) =>
      val refused = remoteImagesInContainerfile("Containerfile", text, Map.empty, LocalImages, None)
      assert(refused.swap.exists(_.contains(expected)), s"$text -> $refused")

  test("every generated build command uses only flags the remote-source scan reads"):
    // imageBuildSpecification reads `--build-arg VALUE` and `-f FILE`; a spelling outside the set
    // — --build-arg=NAME=value, --file, a --build-context naming an image — would resolve sources
    // from a different Containerfile than the one Podman builds.
    val generated = buildCommands("podman", "1.2-3", "sourceid", "sandboxid", "proxyid") ++
      updateCommands("podman", "1.2-3", "sandboxid") ++
      selfTestBuildCommands("podman", "test-rust", "sourceid", "selftestid")
    generated.foreach: command =>
      val operands = command.drop(2).init
      operands.filter(_.startsWith("-")).foreach: flag =>
        assert(BuildCommandFlags.contains(flag), s"$flag in ${command.mkString(" ")}")
      operands.sliding(2).foreach:
        // Podman takes a valueless --build-arg from the environment, which this cannot resolve.
        case Vector("--build-arg", value) =>
          assert(value.contains('='), s"--build-arg $value in ${command.mkString(" ")}")
        case _ => ()

  test("a build argument reaches only the references declared before it"):
    // Podman expands an ARG that no earlier declaration named to the empty string; refusing is the
    // half of that trade that cannot build a broken reference.
    val early = remoteImagesInContainerfile(
      "Containerfile",
      "FROM example.invalid/base:${LATER}\nARG LATER=default\n",
      Map("LATER" -> "override"),
      LocalImages,
      None
    )
    assert(early.isLeft, early.toString)
    assertEquals(
      remoteImagesInContainerfile(
        "Containerfile",
        "ARG LATER=default\nFROM example.invalid/base:${LATER}\n",
        Map("LATER" -> "override"),
        LocalImages,
        None
      ),
      Right(Vector("example.invalid/base:override"))
    )

  test("update rebuilds only the sandbox image, without cache"):
    val commands = updateCommands("podman", "1.2-3", "sandboxid")
    assertEquals(commands.map(_.last), Vector("ko-agent-sandbox"))
    assertEquals(buildOutputImages(commands), Vector("ko-agent-sandbox:latest"))
    assert(commands.head.contains("--no-cache"))
    assert(commands.head.contains("ko-agent-sandbox:latest"))
    assert(commands.head.containsSlice(Seq("--build-arg", "BUNDLE_ID=sandboxid")))
    assert(commands.head.containsSlice(Seq("--label", s"$BundleLabel=sandboxid")))

  test("build cleanup removes replaced ids and launcher tags from older versions"):
    val builds = buildCommands("podman", "1.2-3", "sourceid", "sandboxid", "proxyid")
    assertEquals(
      buildOutputImages(builds),
      buildImageTags("1.2-3")
    )
    assertEquals(
      staleVersionedBaseImageTags(
        Vector(
          TaggedImage("localhost/debian-temurin:1.1-2", "temurin-old"),
          TaggedImage("debian-coursier:1.1-2", "coursier-old"),
          TaggedImage("localhost/debian-temurin:1.2-3", "temurin-current"),
          TaggedImage("localhost/ko-agent-sandbox:latest", "sandbox-current"),
          TaggedImage("ko-agent-sandbox:mine", "custom-sandbox"),
          TaggedImage("ko-agent-egress-proxy:mine", "custom-proxy"),
          TaggedImage("ko-agent-self-test:latest", "self-test"),
          TaggedImage("example.invalid/ko-agent-sandbox:old", "other-project")
        ),
        buildImageTags("1.2-3")
      ),
      Vector(
        TaggedImage("debian-coursier:1.1-2", "coursier-old"),
        TaggedImage("localhost/debian-temurin:1.1-2", "temurin-old")
      )
    )
    assertEquals(
      supersededImageRemoveCommands(
        "podman",
        Vector("fs-old", "proxy-old", "base-old", "coursier-old", "temurin-old"),
        Vector("base-current", "proxy-current", "fs-current")
      ),
      Vector(
        Vector("podman", "image", "rm", "--ignore", "fs-old"),
        Vector("podman", "image", "rm", "--ignore", "proxy-old"),
        Vector("podman", "image", "rm", "--ignore", "base-old"),
        Vector("podman", "image", "rm", "--ignore", "coursier-old"),
        Vector("podman", "image", "rm", "--ignore", "temurin-old")
      )
    )
    assertEquals(
      protectedImageNames(
        managedImageTags("1.2-3"),
        Vector(TaggedImage("localhost/ko-agent-self-test:latest", "self-test-old"))
      ),
      managedImageTags("1.2-3").filterNot(_ == "ko-agent-self-test:latest")
    )

  test("an interrupted image cleanup is journalled in removal order"):
    def id(digit: Char): String = s"sha256:${digit.toString * 64}"

    assertEquals(
      imageListCommand("podman"),
      Vector(
        "podman",
        "image",
        "ls",
        "--no-trunc",
        "--format",
        "{{.Repository}}:{{.Tag}}\t{{.Id}}"
      )
    )
    val journalDir = Files.createTempDirectory("image-cleanup-journal")
    val journal = journalDir.resolve("cleanup.ids")
    val interrupted = Vector(id('1'), id('2'))
    writeImageCleanupJournal(journal, interrupted)
    assertEquals(readImageCleanupJournal(journal), Right(interrupted))

    val listedBefore = imageIdsForTags(
      Vector(TaggedImage("localhost/ko-agent-fs:latest", "3" * 64)),
      Vector("ko-agent-fs:latest")
    )
    val candidates = prepareImageCleanupJournal(
      journal,
      listedBefore :+ id('4'),
      Vector(TaggedImage("debian-temurin:old", id('5')))
    )
    assertEquals(candidates, Vector(id('1'), id('2'), id('4'), "3" * 64, id('5')))
    assertEquals(readImageCleanupJournal(journal), Right(candidates))
    assertEquals(
      prependImageCleanupDependents(
        candidates,
        Vector(
          TaggedImage("ko-agent-self-test:latest", id('6')),
          TaggedImage("ko-agent-self-test-build:cache", id('2'))
        )
      ),
      Vector(id('6'), id('2'), id('1'), id('4'), "3" * 64, id('5'))
    )

    Files.writeString(journal, s"${id('1')}\nshort-id\n")
    assert(validateImageCleanupIds(journal, Vector("short-id")).isLeft)
    assertEquals(repairImageCleanupJournal(journal), Vector("short-id"))
    assertEquals(readImageCleanupJournal(journal), Right(Vector(id('1'))))
    writeImageCleanupJournal(journal, Vector.empty)
    assert(!Files.exists(journal))

  test("every cleanup order is a reverse topological order of the Containerfiles' FROM graph"):
    val version = "1.2-3"
    val verbs =
      buildCommands("podman", version, "sourceid", "sandboxid", "proxyid") ++
        updateCommands("podman", version, "sandboxid") ++
        selfTestBuildCommands("podman", "1.2.3", "sourceid", "selftestid")
    val declared = managedImageTags(version)
    // child -> parent, read from the bundled Containerfiles rather than restated here.
    val edges = buildOutputImages(verbs)
      .zip(imageSourcesForBuildCommands(verbs, buildContextResource, declared.toSet))
      .flatMap((child, sources) => sources.parents.map(child -> _))
      .distinct
    // Not empty by an accident of parsing: the sandbox image builds on the coursier base.
    assert(edges.contains("ko-agent-sandbox:latest" -> s"debian-coursier:$version"), edges.toString)

    def precedes(order: Vector[String], first: String, second: String): Boolean =
      order.indexOf(first) >= 0 && order.indexOf(second) > order.indexOf(first)

    // The declared dependency orders build a parent before its child.
    edges.foreach: (child, parent) =>
      assert(precedes(declared, parent, child), s"$parent must be declared before $child")

    // Every cleanup list removes the child first, whatever order Podman lists the images in.
    def id(index: Int): String = f"sha256:$index%064x"
    val listing = declared.zipWithIndex.map((tag, index) => TaggedImage(s"localhost/$tag", id(index))).reverse
    val ids = listing.map(image => image.tag.stripPrefix("localhost/") -> image.id).toMap
    val journal = prependImageCleanupDependents(
      imageCleanupCandidates(Vector.empty, imageIdsForTags(listing, buildImageTags(version)), Vector.empty),
      selfTestCleanupOrder(listing)
    )
    edges.foreach: (child, parent) =>
      assert(precedes(journal, ids(child), ids(parent)), s"$child must be removed before $parent")
    // The self-test order is constructed, not inherited: a listing in the wrong order, with a
    // duplicate, still comes out leaves first and once.
    assertEquals(
      selfTestCleanupOrder(listing ++ listing.take(1)).map(_.tag),
      SelfTestImageTags.reverse.map(tag => s"localhost/$tag")
    )

  test("an image retained by a container is reported as a later cleanup retry"):
    val imageId = "1" * 64
    val containerId = "2" * 64
    val error = s"Error: image used by $containerId: image is in use by a container"
    val note = supersededImageRetentionNote(imageId, error)
    assert(note.contains(s"container $containerId still uses it"), note)
    assert(note.contains("a later --build, --update, or --self-test will retry"), note)
    assert(!note.contains("Error:"), note)

    val unexpected = supersededImageRetentionNote(imageId, "Error: storage is unavailable")
    assert(unexpected.contains("Podman did not remove it"), unexpected)
    assert(unexpected.contains("Error: storage is unavailable"), unexpected)

  test("every internal multi-stage build has one named compile-cache target"):
    val containerRoot = Paths.get("container")
    val listed = Files.list(containerRoot)
    val containerfiles =
      try listed.iterator().asScala.map(_.resolve("Containerfile")).filter(Files.isRegularFile(_)).toVector
      finally listed.close()
    val allContainerfiles = containerfiles :+ Paths.get("fuse/ko-agent-fs/Containerfile")
    val multiStage = allContainerfiles.filter: path =>
      Files.readAllLines(path).asScala.count(_.startsWith("FROM ")) > 1

    val commands =
      buildCommands("podman", "1.2-3", "sourceid", "sandboxid", "proxyid") ++
        selfTestBuildCommands("podman", "1.2.3", "sourceid", "selftestid")
    val tracked = commands.filter(_.containsSlice(Seq("--target", "build"))).map: command =>
      val fileIndex = command.indexOf("-f")
      if fileIndex >= 0 then containerRoot.resolve(command(fileIndex + 1))
      else
        val context = command.last
        val containerPath = containerRoot.resolve(context).resolve("Containerfile")
        if Files.isRegularFile(containerPath) then containerPath
        else Paths.get("fuse").resolve(context).resolve("Containerfile")
    assertEquals(tracked.toSet, multiStage.toSet)
    commands.filter(_.containsSlice(Seq("--target", "build"))).foreach: command =>
      assert(buildOutputImages(Vector(command)).head.endsWith(":cache"), command.mkString(" "))

  test("the self-test identity covers its source, filter, and actual inherited sandbox image"):
    val original = selfTestBundleId("fs-source-1", "self-test-source-1", "sandbox-image-1")
    assert(selfTestBundleId("fs-source-2", "self-test-source-1", "sandbox-image-1") != original)
    assert(selfTestBundleId("fs-source-1", "self-test-source-2", "sandbox-image-1") != original)
    assert(selfTestBundleId("fs-source-1", "self-test-source-1", "sandbox-image-2") != original)

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
    // Named for the reader who is upgrading the launcher, not thinking about images.
    assert(stale.exists(_.startsWith("container image ko-agent-sandbox:latest")), stale.toString)
    // Both digests are in the message, so the reader can tell which side is stale.
    assert(stale.exists(_.contains(sandboxId)), stale.toString)
    assert(stale.exists(_.contains(proxyId)), stale.toString)
    val unlabeled = bundleMismatch("ko-agent-sandbox:latest", sandboxId, "")
    assert(unlabeled.exists(_.contains("no bundle label")), unlabeled.toString)
    assert(unlabeled.exists(_.contains(s"$sandboxId")), unlabeled.toString)
    assert(unlabeled.exists(_.contains("(none)")), unlabeled.toString)

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

    // The only way an agent-installed JVM reaches an inspected forge host at all — it needs both
    // the CA and the proxy — so a bundle without it is a silently degraded sandbox.
    assert(index.contains("ko-agent-sandbox/sandbox-prepare-jdk"), "prepare-jdk script missing")
    val prepareJdk = buildContextResource("ko-agent-sandbox/sandbox-prepare-jdk")
    assert(prepareJdk.contains("-importcert"), "the prepare-jdk script imports no certificate")
    assert(prepareJdk.contains("net.properties"), "the prepare-jdk script sets no proxy")
    assert(index.contains("ko-agent-sandbox/sandbox-apt-get"), "sandbox-apt-get script missing")
    assert(
      buildContextResource("ko-agent-sandbox/sandbox-apt-get").contains("--download-only"),
      "sandbox-apt-get does not resolve dependencies"
    )
    assert(
      index.contains("ko-agent-sandbox/sandbox-install-podman"),
      "sandbox-install-podman script missing"
    )
    assert(
      buildContextResource("ko-agent-sandbox/sandbox-install-podman").contains("same-uid"),
      "sandbox-install-podman does not gate on the nesting opt-in"
    )

    // ko-agent-fs is compiled from source on the user's machine rather than shipped as a binary, so its sources —
    // not just its Containerfile — have to travel in the jar. The policy core is the one that matters most.
    Vector("ko-agent-fs/src/policy.rs", "ko-agent-fs/Cargo.lock", "ko-agent-fs/deny.toml").foreach: path =>
      assert(index.contains(path), s"INDEX missing $path")
    assert(buildContextResource("ko-agent-fs/src/policy.rs").contains("is_dotgit_name"))

    // Build output must not have been swept into the bundle — Rust's target/ as well as sbt's.
    assert(!index.exists(_.split("/").contains("target")), "target leaked")

    // ko-agent-fs/doc and ko-agent-fs/probe are deliberately absent: neither is distribution nor
    // a build input, and keeping them out is what stops editing a design document or a platform
    // probe from changing koAgentFsSourceId and invalidating every installed filter binary.
    Vector("ko-agent-fs/doc/", "ko-agent-fs/probe/").foreach: prefix =>
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

  test("SECURITY.md names exactly the =git-fetch hosts the proxy ships"):
    // The git-host list has two homes: the =git-fetch entries of the proxy's DefaultReadOnlyHosts and
    // the SECURITY.md section that reasons about them (the launcher carries no copy — the leaf's
    // names come from the image's own --print-policy at launch). This scrapes both texts; it
    // depends on the rest of the read-only tier never being written as a `1. \`host\`` list in
    // SECURITY.md — prose or a different marker keeps this green.
    val Listed = """^1\. `([^`]+)`$""".r
    val listed = Files
      .readString(Paths.get("SECURITY.md"))
      .linesIterator
      .collect { case Listed(host) => host }
      .toVector
    val proxySource = Files.readString(
      Paths.get("container/ko-agent-egress-proxy/app/src/main/scala/AgentEgressProxy.scala")
    )
    val block = proxySource.substring(proxySource.indexOf("val CuratedRestrictedHosts"))
    val gitHosts = "\"([^\"]+)=git-fetch\"".r
      .findAllMatchIn(block.substring(0, block.indexOf(").map(")))
      .map(_.group(1))
      .toVector
    assertEquals(listed, gitHosts)

  test("the appended egress section names only tags the proxy defines"):
    // The launcher writes this prose; the proxy owns the vocabulary. An agent following a tag the
    // proxy does not define writes a policy file that fails the *next* launch, so the drift shows
    // up nowhere near the text that caused it. Scraped from the proxy's source, like the git-host
    // list above, because the launcher carries no copy of the tag set.
    val proxySource = Files.readString(
      Paths.get("container/ko-agent-egress-proxy/app/src/main/scala/AgentEgressProxy.scala")
    )
    val declared = """val KnownTags: Set\[String\] = Set\(([^)]*)\)""".r
      .findFirstMatchIn(proxySource)
      .getOrElse(fail("the proxy no longer declares KnownTags as a literal Set"))
    val known = """"([^"]+)"""".r.findAllMatchIn(declared.group(1)).map(_.group(1)).toSet
    assert(known.nonEmpty, "scraped no tags at all")

    // A resolved policy with no tags of its own, so every `=tag` found is the prose's own. The
    // lookbehind keeps an option spelling (--egress=profile) out of the tag hunt: a tag mention
    // is `=name` with nothing word-like before the `=`.
    val emptyResolution = "egress profile: deny-all\nrestricted hosts (0):\ndenied rules (0):"
    val named = "(?<![a-z-])=([a-z-]+)".r
      .findAllMatchIn(authoritySection("live", emptyResolution))
      .map(_.group(1))
      .toSet
    assert(named.nonEmpty, "the section names no tag, so it teaches an agent nothing about them")
    assertEquals(named -- known, Set.empty[String], s"the proxy defines only $known")

  test("the authority section directs the agent by write mode, never leaves it to probing"):
    val resolution = "egress profile: deny-all\nrestricted hosts (0):\ndenied rules (0):"
    val readOnly = authoritySection("reject", resolution)
    assert(readOnly.contains("read-only"), readOnly)
    assert(readOnly.contains("--write=live"), readOnly)
    val writable = authoritySection("live", resolution)
    assert(writable.contains("writable"), writable)
    // Both name the relaunch path for a host the policy does not admit.
    Vector(readOnly, writable).foreach: section =>
      assert(section.contains(".ko-agent-sandbox/egress/allowed"), section)
      assert(section.contains("deny-unless-allowed"), section)

  test("option parsing: the first non-option ends launcher parsing, -- is an optional escape"):
    assertEquals(
      parseCommandLine(List("--write=reject", "--egress=deny-all", "claude", "--write=live")),
      Right(
        ParsedCommandLine(
          Some("reject"), Some("deny-all"), None, List("claude", "--write=live")
        )
      )
    )
    // After `--` everything is the command, launcher-option lookalikes included.
    assertEquals(
      parseCommandLine(List("--", "--write=live", "claude")),
      Right(ParsedCommandLine(None, None, None, List("--write=live", "claude")))
    )
    // No arguments launches the image's default command.
    assertEquals(parseCommandLine(Nil), Right(ParsedCommandLine(None, None, None, Nil)))
    assertEquals(parseCommandLine(Nil).map(_.writeMode), Right("live"))
    assertEquals(parseCommandLine(Nil).map(_.egressProfile), Right("deny-unless-allowed"))

  test("option parsing: authority values are a closed set and are selected once"):
    assert(parseCommandLine(List("--write=maybe")).swap.exists(_.contains("reject, staged, live")))
    assert(parseCommandLine(List("--egress=allow-all")).isLeft)
    assert(parseCommandLine(List("--write=live", "--write=reject")).swap.exists(_.contains("twice")))
    assert(parseCommandLine(List("--write", "live")).swap.exists(_.contains("--write=<mode>")))
    assert(parseCommandLine(List("--frobnicate")).swap.exists(_.contains("unknown option")))

  test("--self-test's container leaves nothing behind and carries what the mount needs"):
    // A measurement that changes its subject is worth nothing, so the run binds no host path and
    // keeps no container. The capability is not
    // redundant with the image's setuid fusermount3 — a setuid binary does not escape a container's
    // bounding set, measured in fuse/ko-agent-fs/doc/verification-log.md — so its absence here
    // would be a venue that cannot mount at all.
    val command = selfTestRunCommand("podman", Some("a_handle_held"), asRoot = false)
    assert(command.contains("--rm"), command.mkString(" "))
    assert(command.containsSlice(Seq("--device", "/dev/fuse")), command.mkString(" "))
    assert(command.containsSlice(Seq("--cap-add", "SYS_ADMIN")), command.mkString(" "))
    assert(command.contains("--network=none"), command.mkString(" "))
    assert(command.contains("--pull=never"), command.mkString(" "))
    assert(command.endsWith(Seq("ko-agent-self-test:latest", "a_handle_held")), command.mkString(" "))
    assert(
      !command.exists(argument => argument == "-v" || argument.startsWith("--volume")),
      s"--self-test binds a host path into the container: ${command.mkString(" ")}"
    )
    assert(
      !command.exists(_.startsWith("--mount")),
      s"--self-test mounts something into the container: ${command.mkString(" ")}"
    )
    // The root retry exists to measure the bounding-set question, not to be the default.
    assert(!command.containsSlice(Seq("--user", "0")), command.mkString(" "))
    assert(selfTestRunCommand("podman", None, asRoot = true).containsSlice(Seq("--user", "0")))
    assertEquals(selfTestRunCommand("podman", None, asRoot = false).last, "ko-agent-self-test:latest")

  test("--self-test builds its image from the bundle root against the pinned toolchain"):
    // `-f` with `.`: the crate the image compiles lives beside its Containerfile in the unpacked
    // bundle, not under it, so the directory cannot be the context.
    val commands = selfTestBuildCommands("podman", "1.2.3", "fsdigest", "selftestdigest")
    assertEquals(commands.size, 2)
    assertEquals(buildOutputImages(commands), SelfTestImageTags)
    commands.foreach: build =>
      assert(build.containsSlice(Seq("--build-arg", "RUST_VERSION=1.2.3")), build.mkString(" "))
      assert(build.containsSlice(Seq("--build-arg", "KO_AGENT_FS_SOURCE_ID=fsdigest")), build.mkString(" "))
      assert(build.containsSlice(Seq("--label", s"$BundleLabel=selftestdigest")), build.mkString(" "))
      assert(build.containsSlice(Seq("-f", "ko-agent-self-test/Containerfile")), build.mkString(" "))
    assert(commands.head.containsSlice(Seq("--target", "build")), commands.head.mkString(" "))
    assert(commands.head.endsWith(Seq("-t", SelfTestBuildImage, ".")), commands.head.mkString(" "))
    assert(commands.last.endsWith(Seq("-t", "ko-agent-self-test:latest", ".")), commands.last.mkString(" "))

  test("the pinned toolchain is read from the context the launcher unpacks"):
    val context = Files.createTempDirectory("pinned-rust")
    val crate = Files.createDirectories(context.resolve("ko-agent-fs"))
    Files.writeString(
      crate.resolve("Containerfile"),
      "# a comment\nARG RUST_VERSION=9.9.9\nFROM docker.io/library/rust:${RUST_VERSION}-slim\n"
    )
    assertEquals(pinnedRustVersion(context), "9.9.9")

  test("option parsing: management verbs take the rest as operands, renamed spellings refuse"):
    assertEquals(
      parseCommandLine(List("--proxy-log", "-f")),
      Right(ParsedCommandLine(None, None, Some(("--proxy-log", List("-f"))), Nil))
    )
    assertEquals(
      parseCommandLine(List("--egress=deny-unless-allowed", "--egress-effective", "--", "claude")),
      Right(
        ParsedCommandLine(
          None, Some("deny-unless-allowed"),
          Some(("--egress-effective", List("--", "claude"))), Nil
        )
      )
    )
    assertEquals(
      parseCommandLine(List("--egress-check=pypi.org", "claude")),
      Right(ParsedCommandLine(None, None, Some(("--egress-check", List("pypi.org", "claude"))), Nil))
    )
    assertEquals(
      parseCommandLine(List("--self-test", "a_handle_held")),
      Right(ParsedCommandLine(None, None, Some(("--self-test", List("a_handle_held"))), Nil))
    )
    assert(parseCommandLine(List("--proxy-effective")).swap.exists(_.contains("--egress-effective")))

  test("the state root must be absolute, resolves canonically, and stays outside the project"):
    // A relative value resolves against the current directory — the repository being sandboxed —
    // which would hand the sandbox the CA signing key and aim the resets' recursive deletions
    // into the checkout; refused rather than resolved, on every platform spelling.
    assert(stateRootOf(HostCommands.Os.Linux, Map("XDG_STATE_HOME" -> "relative/state").get).isLeft)
    assert(stateRootOf(HostCommands.Os.Linux, Map("HOME" -> "relative/home").get).isLeft)
    assert(stateRootOf(HostCommands.Os.Windows, Map("LOCALAPPDATA" -> "relative").get).isLeft)
    assert(stateRootOf(HostCommands.Os.Linux, Map.empty[String, String].get).isLeft)

    val base = Files.createTempDirectory("state-root").toRealPath()
    assertEquals(
      stateRootOf(HostCommands.Os.Linux, Map("XDG_STATE_HOME" -> base.toString).get),
      Right(base.resolve("ko-agent-sandbox"))
    )
    // A symlinked spelling resolves to the real location, so the outside-the-project comparison
    // sees the directory that will actually hold the key — even before it exists.
    val real = Files.createDirectories(base.resolve("real"))
    val linked = Files.createSymbolicLink(base.resolve("linked"), real)
    assertEquals(
      stateRootOf(
        HostCommands.Os.Linux,
        Map("XDG_STATE_HOME" -> linked.resolve("not-yet/state").toString).get
      ),
      Right(real.resolve("not-yet/state/ko-agent-sandbox"))
    )

    val project = Files.createTempDirectory("state-root-project").toRealPath()
    val linux = HostCommands.Os.Linux
    assert(
      forbiddenStateRootReason(linux, project.resolve("state/ko-agent-sandbox"), project).isDefined
    )
    assertEquals(forbiddenStateRootReason(linux, base.resolve("ko-agent-sandbox"), project), None)
    // The macOS data volume is a firmlink, which toRealPath leaves uncollapsed: the two spellings
    // are one directory, so containment must hold across them — and only on macOS. Not exercised
    // from a Windows runner, whose Path type cannot spell a POSIX absolute path.
    if !scala.util.Properties.isWin then
      val mac = HostCommands.Os.Mac
      val aliasedProject = Paths.get("/System/Volumes/Data/Users/me/proj")
      val plainProject = Paths.get("/Users/me/proj")
      assert(forbiddenStateRootReason(mac, plainProject.resolve("state"), aliasedProject).isDefined)
      assert(forbiddenStateRootReason(mac, aliasedProject.resolve("state"), plainProject).isDefined)
      assertEquals(forbiddenStateRootReason(linux, plainProject.resolve("state"), aliasedProject), None)

  test("a run's TLS mount copies are pruned only when provably dead and past the launch bound"):
    val names = Seq("run-1a2b3c4d", "run-ffffffff", "run-short", "ca.crt", ".lock", "run-1A2B3C4D")
    // Only the run-<8 hex> shape is the launcher's to sweep; a live run's copies are its proxy's
    // mount sources, and a fresh dir may belong to a launch that has no container yet.
    assertEquals(
      tlsRunDirsToPrune(names, Set("1a2b3c4d"), _ => true),
      Seq("run-ffffffff")
    )
    assertEquals(tlsRunDirsToPrune(names, Set.empty, _ != "run-ffffffff"), Seq("run-1a2b3c4d"))
    assertEquals(tlsRunDirsToPrune(names, Set("1a2b3c4d", "ffffffff"), _ => true), Seq())

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

  test("reset filters match exactly the launcher's reserved name shapes"):
    // The `--reset-all` sweeps force-remove what they match, so a bare prefix match would take a
    // user's own ko-agent-sandbox-persistent-backup with it. What separates launcher-owned from
    // user-owned is the reserved shape — slug, twelve-hex hash, and for per-run resources the
    // eight-hex suffix — a namespace contract rather than provenance: SECURITY.md ("Silent
    // changes to what you own") states it, and the sharedVolumeNameError test below keeps the
    // one launcher-adopted name out of it.
    val id = "app-0123456789ab"
    assertEquals(
      proxyContainers(
        Seq(s"ko-agent-egress-proxy-$id-1a2b3c4d", "ko-agent-egress-proxy-manual", "other")
      ),
      Seq(s"ko-agent-egress-proxy-$id-1a2b3c4d")
    )
    assertEquals(
      sandboxRunContainers(
        Seq(
          s"ko-agent-sandbox-run-$id-1a2b3c4d",
          s"ko-agent-egress-proxy-$id-1a2b3c4d",
          "ko-agent-sandbox-run-mine"
        )
      ),
      Seq(s"ko-agent-sandbox-run-$id-1a2b3c4d")
    )
    assertEquals(
      persistentVolumes(
        Seq(
          s"ko-agent-sandbox-persistent-$id",
          "ko-agent-sandbox-persistent-backup",
          "my-shared-volume"
        )
      ),
      Seq(s"ko-agent-sandbox-persistent-$id")
    )
    assertEquals(
      launcherNetworks(
        Seq(
          s"ko-agent-sandbox-$id-1a2b3c4d",
          s"ko-agent-egress-$id-1a2b3c4d",
          "ko-agent-sandbox-mynet",
          "podman",
          "bridge"
        )
      ),
      Seq(s"ko-agent-sandbox-$id-1a2b3c4d", s"ko-agent-egress-$id-1a2b3c4d")
    )

  test("a shared volume name inside the reserved shape is refused, ordinary names are not"):
    // Without this, KO_AGENT_SANDBOX_PERSISTENT_VOLUME could adopt a name --reset-all removes —
    // another project's real volume included, which would also alias its sign-ins.
    assertEquals(sharedVolumeNameError("my-shared-volume"), None)
    assertEquals(sharedVolumeNameError("ko-agent-sandbox-persistent-backup"), None)
    val reserved = sharedVolumeNameError("ko-agent-sandbox-persistent-app-0123456789ab")
    assert(reserved.exists(_.contains("--reset-all")), reserved.toString)
    assert(reserved.exists(_.contains("Choose a name")), reserved.toString)

  test("per-run resources are named apart from every other resource"):
    val sandbox = sandboxRunContainer("app-0123456789ab", "1a2b3c4d")
    val proxy = proxyRunContainer("app-0123456789ab", "1a2b3c4d")
    assertEquals(sandbox, "ko-agent-sandbox-run-app-0123456789ab-1a2b3c4d")
    assertEquals(proxy, "ko-agent-egress-proxy-app-0123456789ab-1a2b3c4d")
    assertEquals(
      sandboxRunNetwork("app-0123456789ab", "1a2b3c4d"),
      "ko-agent-sandbox-app-0123456789ab-1a2b3c4d"
    )
    assertEquals(
      egressRunNetwork("app-0123456789ab", "1a2b3c4d"),
      "ko-agent-egress-app-0123456789ab-1a2b3c4d"
    )
    // The reset filters must sweep each through its own filter and never through the other's.
    assertEquals(proxyContainers(Seq(sandbox, proxy)), Seq(proxy))
    assertEquals(sandboxRunContainers(Seq(sandbox, proxy)), Seq(sandbox))
