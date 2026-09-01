// The launcher's own surface: the run/reset naming that keeps projects apart, the configuration
// surface, the build verbs, and the documents the code must stay in step with (the --help text's
// Environment section, SECURITY.md's forge list against the proxy's source, the bundled context).

package agentsandbox.launcher

import java.nio.file.{Files, Paths}
import scala.jdk.CollectionConverters.*

import java.time.ZoneId

import AgentSandboxLauncher.*
import HostCommands.Os
import ContainerfileSources.*
import LauncherImages.*
import KoAgentFs.bundledSourceId
import agentsandbox.egress.AgentEgressProxy.resolvePolicy

class AgentSandboxLauncherTest extends munit.FunSuite:

  private val LauncherBuiltImages = Set("local-base:1")

  test("a misspelled launcher variable is reported, a foreign or known one is not"):
    assertEquals(
      unknownSandboxVariables(Seq("KO_AGENT_SANDBOX_MEMROY", "PATH", "KO_AGENT_SANDBOX_MEMORY")),
      Vector("KO_AGENT_SANDBOX_MEMROY"),
    )
    assertEquals(unknownSandboxVariables(KnownSandboxVariables), Vector.empty)
    assertEquals(unknownSandboxVariables(Seq("HOME", "JAVA_HOME")), Vector.empty)

  test("the sandbox gets a memory ceiling below the machine's total, and never swaps"):
    assertEquals(memoryCeiling(8L << 30, None), 7L << 30)
    assertEquals(memoryCeiling(2L << 30, None), MinimumCeiling)
    assertEquals(memoryCeiling(1L << 30, None), MinimumCeiling)
    assertEquals(memoryCeiling(16L << 30, Some(10L << 30)), 10L << 30)
    assertEquals(memoryCeiling(16L << 30, Some(2L << 30)), 2L << 30)
    assertEquals(memoryCeiling(16L << 30, Some(20L << 30)), 15L << 30)
    // Nothing available, less than the agent needs, and a machine smaller than the minimum.
    assertEquals(memoryCeiling(16L << 30, Some(0L)), MinimumCeiling)
    assertEquals(memoryCeiling(16L << 30, Some(200L << 20)), MinimumCeiling)
    assertEquals(memoryCeiling(512L << 20, None), 512L << 20)
    assertEquals(memoryCeiling(512L << 20, Some(0L)), 512L << 20)
    assert(memoryCeiling(1L, Some(0L)) > 0)
    assertEquals(
      memoryArguments(None, Some(8L << 30), None),
      Vector(s"--memory=${7L << 30}", s"--memory-swap=${7L << 30}"),
    )
    assertEquals(memoryArguments(Some("8g"), Some(16L << 30), None), Vector("--memory=8g", "--memory-swap=8g"))
    assertEquals(memoryArguments(Some(" "), Some(2L << 30), None), memoryArguments(None, Some(2L << 30), None))
    assertEquals(memoryArguments(None, None, None), Vector.empty)
    val meminfo = "MemTotal:       16000000 kB\nMemFree:          100000 kB\nMemAvailable:   10000000 kB\n"
    assertEquals(memoryAvailable(meminfo), Some(10000000L * 1024))
    assertEquals(memoryAvailable("MemTotal: 1 kB\n"), None)
    assertEquals(hostMemoryAvailable(Os.Linux, meminfo), Some(10000000L * 1024))
    assertEquals(hostMemoryAvailable(Os.Mac, meminfo), None)
    assertEquals(hostMemoryAvailable(Os.Windows, meminfo), None)
    assertEquals(memoryTotal(HostCommands.Run(0, "8589934592\n".getBytes, "")), Some(8589934592L))
    assertEquals(memoryTotal(HostCommands.Run(0, "0".getBytes, "")), None)
    assertEquals(memoryTotal(HostCommands.Run(1, "".getBytes, "not running")), None)

  test("build verbs ask first only below what a default machine idles at, read from the machine's own meminfo"):
    assertEquals(buildMemoryWarning(None), None)
    assertEquals(buildMemoryWarning(Some(3L << 30)), None)
    val warning = buildMemoryWarning(Some((3L << 30) - 1))
    assert(warning.exists(_.contains("podman machine set --memory")), warning)
    // Each OS consults exactly its own route: /proc/meminfo is this host's only on native Linux,
    // and the machine ssh is a subprocess native Linux must not spawn.
    val meminfo = "MemAvailable:   2000000 kB\n"
    assertEquals(
      machineMemoryAvailable(Os.Linux, meminfo, throw AssertionError("native Linux asks no machine ssh")),
      Some(2000000L * 1024),
    )
    assertEquals(
      machineMemoryAvailable(
        Os.Mac,
        throw AssertionError("a VM host reads no host meminfo"),
        HostCommands.Run(0, meminfo.getBytes, ""),
      ),
      Some(2000000L * 1024),
    )
    val sshRefused = HostCommands.Run(255, Array.emptyByteArray, "no machine")
    assertEquals(machineMemoryAvailable(Os.Windows, "", sshRefused), None)
    assertEquals(machineMemoryAvailable(Os.Mac, "", HostCommands.Run(0, "MemTotal: 1 kB\n".getBytes, "")), None)

  test("every podman verb says the machine's headroom, when the machine can say it"):
    assertEquals(
      machineMemoryLine(Os.Mac, Some(8L << 30), Some((46L << 30) / 10)),
      Some("podman machine memory: 4.6 / 8.0 GiB available"),
    )
    // Native Linux has no podman machine: the figures are this host's, and the label says no more.
    assertEquals(
      machineMemoryLine(Os.Linux, Some(8L << 30), Some((46L << 30) / 10)),
      Some("memory: 4.6 / 8.0 GiB available"),
    )
    assertEquals(machineMemoryLine(Os.Windows, None, Some(1L << 30)), None)
    assertEquals(machineMemoryLine(Os.Mac, Some(8L << 30), None), None)

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
      Vector("--security-opt=unmask=ALL", "--security-opt=label=disable", "--cap-add=SYS_CHROOT"),
    )

  test("the session start defaults to pausing and fails closed on anything else"):
    // `none` among the refusals: it is the other two variables' off-switch, and nothing here is
    // spelled by analogy with a neighbouring variable.
    assertEquals(sessionStart(None), Right("pause"))
    assertEquals(sessionStart(Some("")), Right("pause"))
    assertEquals(sessionStart(Some("pause")), Right("pause"))
    assertEquals(sessionStart(Some("immediate")), Right("immediate"))
    Vector("none", "off", "0", "false", "no", "PAUSE", " pause ", "now", "skip").foreach: value =>
      assert(sessionStart(Some(value)).isLeft, s"'$value' was not refused")

  test("the hold starts on Enter or y, declines on n or EOF, and asks again on anything else"):
    // Every terminal outcome, over a scripted reader: the answers are consumed in order, and the
    // prompts show how many times the hold asked.
    def hold(mode: String, answers: Option[String]*): (Boolean, Vector[String]) =
      val prompts = Vector.newBuilder[String]
      val remaining = answers.iterator
      val reader = Reader(prompts += _, () => if remaining.hasNext then remaining.next() else None)
      (holdForReader(mode, Vector("claude", "--resume"), Some(reader)), prompts.result())
    assertEquals(hold("pause", Some("")), (true, Vector("\nstart: claude --resume [Y/n] ")))
    Vector("y", "Y", "yes", " YES ").foreach(answer => assertEquals(hold("pause", Some(answer))._1, true, answer))
    Vector("n", "N", "no", " No ").foreach(answer => assertEquals(hold("pause", Some(answer))._1, false, answer))
    // EOF at the prompt is a decline, never a start: nothing was agreed to. (Stdin that was never a
    // terminal is the no-reader case below, and starts.)
    assertEquals(hold("pause")._1, false)
    assertEquals(hold("pause", Some("maybe"), Some("?"), Some("y")), (true, Vector.fill(3)("\nstart: claude --resume [Y/n] ")))
    assertEquals(hold("pause", Some("maybe"))._1, false)
    assertEquals(hold("immediate", Some("n")), (true, Vector()))
    assertEquals(holdForReader("pause", Vector("claude"), None), true)

  test("the hold renders each argument unambiguously"):
    def rendered(command: String*): String =
      val prompts = Vector.newBuilder[String]
      holdForReader("pause", command, Some(Reader(prompts += _, () => Some("n"))))
      prompts.result().mkString
    assertNotEquals(rendered("tool", "a b"), rendered("tool", "a", "b"))
    assertEquals(rendered("tool", "a b"), "\nstart: tool 'a b' [Y/n] ")
    assertEquals(renderArgument("--write=live"), "--write=live")
    assertEquals(renderArgument("/usr/local/bin/x.sh"), "/usr/local/bin/x.sh")
    assertEquals(renderArgument(""), "''")
    assertEquals(renderArgument("it's"), "'it'\\''s'")
    assertEquals(renderArgument("a\"b$c"), "'a\"b$c'")
    assertEquals(renderArgument("a\nb"), "$'a\\nb'")
    assertEquals(renderArgument("\u001b[2J\u009b1m\u007f\\'"), "$'\\x1b[2J\\u009b1m\\x7f\\\\\\''")
    // Bidi overrides and isolates, which reorder what is displayed, and the Unicode line breaks.
    assertEquals(renderArgument("a\u202eb\u2066c"), "$'a\\u202eb\\u2066c'")
    assertEquals(renderArgument("a\u2028b\u2029c"), "$'a\\u2028b\\u2029c'")
    assertEquals(renderArgument("a\ud83c\udff4\udb40\udc67b"), "$'a🏴\\U000e0067b'")
    assertEquals(renderArgument("日本語 café"), "'日本語 café'")
    // Nothing rendered carries a character the terminal would act on, whatever the argument held:
    // every code point, in an argument that already needs quoting.
    (0 to Character.MAX_CODE_POINT).foreach: cp =>
      val out = renderArgument(new String(Character.toChars(cp)) + " ")
      out.codePoints().forEach: rendered =>
        assert(!InvisibleTypes.contains(Character.getType(rendered)), f"U+$cp%04X rendered as $out")

  test("the clipboard defaults to off and fails closed on anything else"):
    assertEquals(clipboardMode(None), Right("off"))
    assertEquals(clipboardMode(Some("")), Right("off"))
    assertEquals(clipboardMode(Some("off")), Right("off"))
    assertEquals(clipboardMode(Some("paste")), Right("paste"))
    assertEquals(clipboardMode(Some("bidirectional")), Right("bidirectional"))
    Vector("on", "true", "1", "read", "copy", "both", "PASTE", " paste ").foreach: value =>
      assert(clipboardMode(Some(value)).isLeft, s"'$value' was not refused")

  test("a clipboard mode is refused where the host cannot serve it"):
    import ClipboardBroker.{hostBackend, HostBackend}
    // findOnPath answers with the real path, and macOS keeps its temp directory behind /var -> /private/var.
    val bin = java.nio.file.Files.createTempDirectory("clipboard-host").toRealPath()
    def tool(name: String, body: String = ""): String =
      val path = bin.resolve(name)
      java.nio.file.Files.writeString(path, body)
      path.toFile.setExecutable(true)
      path.toString
    assertEquals(hostBackend("off", Os.Linux, ""), Right(HostBackend()))
    assert(hostBackend("paste", Os.Linux, bin.toString).isLeft)
    assert(hostBackend("paste", Os.Windows, bin.toString).isLeft)
    val noPs = hostBackend("paste", Os.Mac, bin.toString)
    assert(noPs.swap.exists(_.contains("needs ps")), noPs.toString)
    // Windows resolves its shell and executes nothing, so this holds on every runner.
    val powershell = tool("powershell.exe")
    assertEquals(
      hostBackend("paste", Os.Windows, bin.toString),
      Right(HostBackend(powershell = Some(java.nio.file.Paths.get(powershell)))),
    )
    // From here the fakes are executed, as shell scripts: a POSIX runner only.
    assume(!scala.util.Properties.isWin, "the fake tools are /bin/sh scripts")
    tool("ps", "#!/bin/sh\nexit 0\n")
    val mutePs = hostBackend("paste", Os.Mac, bin.toString)
    assert(mutePs.swap.exists(_.contains("pid=,ppid=")), mutePs.toString)
    // A ps answering the shape with this JVM's own row, pid and parent — the parent baked in by
    // the test, so the fake proves the parser and needs no ps of the host's own.
    val parent = ProcessHandle.current.parent.map[String](_.pid.toString).orElse("1")
    val ps = tool("ps", s"#!/bin/sh\nprintf '%s %s\\n' \"$$PPID\" $parent\n")
    assertEquals(hostBackend("paste", Os.Mac, bin.toString), Right(HostBackend(ps = ps)))
    val wlPaste = tool("wl-paste")
    assertEquals(hostBackend("paste", Os.Linux, bin.toString), Right(HostBackend(wlPaste = wlPaste, ps = ps)))
    assert(hostBackend("bidirectional", Os.Linux, bin.toString).isLeft, "a write mode without wl-copy")
    val wlCopy = tool("wl-copy")
    assertEquals(
      hostBackend("bidirectional", Os.Linux, bin.toString),
      Right(HostBackend(wlPaste = wlPaste, wlCopy = wlCopy, ps = ps)),
    )
    // Every tool found travels: xclip answers first, the Wayland pair when it cannot.
    val xclip = tool("xclip")
    assertEquals(
      hostBackend("bidirectional", Os.Linux, bin.toString),
      Right(HostBackend(xclip = xclip, wlPaste = wlPaste, wlCopy = wlCopy, ps = ps)),
    )

  test("the sandbox waits for the proxy's ready line, and a proxy that exits or stalls fails the launch"):
    // The run's host log, beside a liveness answer from a fake podman.
    assume(!scala.util.Properties.isWin, "the fake podman is a /bin/sh script")
    val dir = Files.createTempDirectory("proxy-ready").toRealPath()
    def podman(running: Boolean, logs: Option[String] = None): String =
      val path = dir.resolve(s"podman-$running-${logs.hashCode.toHexString}")
      // `logs` on a container `--rm` already took: podman's own complaint, and a failure.
      val relay = logs.fold("echo 'no such container' >&2; exit 125")(text => s"printf '%s' '$text' >&2")
      Files.writeString(
        path,
        s"""#!/bin/sh
           |case "$$1 $$2" in
           |  'container inspect') echo $running ;;
           |  'logs proxy') $relay ;;
           |  *) exit 9 ;;
           |esac
           |""".stripMargin,
      )
      path.toFile.setExecutable(true)
      path.toString
    val bound = java.time.Duration.ofSeconds(2)
    // Stamped as the proxy writes it, and with a policy line after it: the line, not the last line.
    val listened = dir.resolve("listened.log")
    Files.writeString(
      listened,
      s"2026-08-29T00:00:00Z $EgressProxyReadyLine\n2026-08-29T00:00:00Z restricted hosts (1): a\n",
    )
    assertEquals(awaitProxyReady(podman(running = true), "proxy", listened, bound), Right(()))
    val refused = dir.resolve("refused.log")
    Files.writeString(refused, "2026-08-29T00:00:00Z the leaf certificate names 2 hosts; the policy inspects 3\n")
    val reason = awaitProxyReady(podman(running = false), "proxy", refused, bound).swap
      .getOrElse(fail("a refusal must fail"))
    assert(reason.startsWith("the egress proxy exited before listening\n"), reason)
    assert(reason.contains("names 2 hosts"), reason)
    val unopened = dir.resolve("unopened.log")
    Files.writeString(unopened, "")
    val podmanOnly =
      awaitProxyReady(podman(running = false, logs = Some("cannot open the log")), "proxy", unopened, bound)
    assert(podmanOnly.swap.exists(_.endsWith("cannot open the log")), podmanOnly.toString)
    val vanished = awaitProxyReady(podman(running = false), "proxy", unopened, bound)
    assert(vanished.swap.exists(_.contains(s"nothing was written to $unopened")), vanished.toString)
    assert(!vanished.swap.exists(_.contains("no such container")), vanished.toString)
    val silent = awaitProxyReady(podman(running = true), "proxy", unopened, bound).swap
      .getOrElse(fail("a stall must fail"))
    assert(silent.startsWith("the egress proxy did not report ready within 2s"), silent)

  test("this build carries the proxy for --serve-proxy-on-host: resources load, spellings agree"):
    // Class initialization reads /baseline eagerly, so nonEmpty proves the resources are on this
    // classpath — the same classpath the assembled jar packages.
    assert(agentsandbox.egress.AgentEgressProxy.CuratedRestrictedHosts.nonEmpty)
    assertEquals(agentsandbox.egress.AgentEgressProxy.ReadyLine, EgressProxyReadyLine)

  test("--help's Environment section and KnownSandboxVariables cannot drift apart"):
    // A variable in one but not the other is either undocumented or warned about as a typo. This
    // is also why the pair lives beside UsageText rather than in HostCommands, whose contract is
    // to know nothing of the sandbox.
    val documented = "KO_AGENT_SANDBOX_[A-Z_]+".r.findAllIn(UsageText).toSet
    assertEquals(unknownSandboxVariables(documented), Vector.empty)
    // The ones the launcher sets rather than reads are documented where their reader is — the
    // agent instructions, and for RUN_ON_HOST the image's shim.
    assertEquals(
      KnownSandboxVariables -- documented,
      Set(
        "KO_AGENT_SANDBOX_EGRESS_POLICY", "KO_AGENT_SANDBOX_JAVA_OPTS",
        RunOnHostChannel.RunOnHostVariable,
      ),
    )

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
      "ko-agent-fs",
    ))
    assert(commands(0).contains("debian-temurin:1.2-3"))
    assert(!commands(0).contains("--build-arg"))
    assert(commands(1).contains("debian-coursier:1.2-3"))
    assert(commands(2).contains("ko-agent-sandbox:latest"))
    assert(commands(3).contains(ProxyBuildImage))
    assert(commands(3).containsSlice(Seq("--target", "build")))
    assert(commands(4).contains("ko-agent-egress-proxy:latest"))
    commands.foreach(command => assert(!command.contains("--save-stages")))
    commands.slice(1, 5).foreach: command =>
      assert(command.containsSlice(Seq("--build-arg", "IMG_TAG_VER=1.2-3")))
    assert(commands(5).contains(KoAgentFsBuildImage))
    assert(commands(5).containsSlice(Seq("--target", "build")))
    assert(commands(6).contains("ko-agent-fs:latest"))
    commands.slice(5, 7).foreach: command =>
      assert(command.containsSlice(Seq("--build-arg", "KO_AGENT_FS_SOURCE_ID=sourceid")))
      assert(!command.exists(_.startsWith("IMG_TAG_VER=")))
    // The digest travels as build arg and as --label both (buildCommands has why).
    assert(commands(2).containsSlice(Seq("--build-arg", "BUNDLE_ID=sandboxid")))
    assert(commands(4).containsSlice(Seq("--build-arg", "BUNDLE_ID=proxyid")))
    assert(commands(2).containsSlice(Seq("--label", s"$BundleLabel=sandboxid")))
    assert(commands(4).containsSlice(Seq("--label", s"$BundleLabel=proxyid")))
    (commands.take(2) ++ Vector(commands(3), commands(5), commands(6))).foreach: command =>
      assert(!command.exists(_.startsWith("BUNDLE_ID=")))
      assert(!command.contains("--label"))

  test("image-producing verbs refresh exactly the remote sources their Containerfiles use"):
    val readContainerfile: String => String = BundledBuildContext.resource
    val localImages = managedImageTags("1.2-3").toSet
    val buildCommands = AgentSandboxLauncher.buildCommands(
      "podman", "1.2-3", "sourceid", "sandboxid", "proxyid",
    )
    val buildImages = remoteImagesForBuildCommands(buildCommands, readContainerfile, localImages)
    def repository(image: String): String = image.take(image.lastIndexOf(':'))
    assertEquals(
      buildImages.map(repository),
      Vector(
        "docker.io/library/debian",
        "ghcr.io/astral-sh/uv",
        "gcr.io/distroless/base-debian13",
        "docker.io/library/rust",
      ),
    )
    assertEquals(
      remoteImagesForBuildCommands(
        updateCommands("podman", "1.2-3", "sandboxid"), readContainerfile, localImages,
      ),
      buildImages.filter(_.startsWith("ghcr.io/astral-sh/uv:")),
    )
    assertEquals(
      remoteImagesForBuildCommands(
        selfTestBuildCommands("podman", "test-rust", "sourceid", "selftestid"),
        readContainerfile,
        localImages,
      ),
      Vector("docker.io/library/rust:test-rust-slim-trixie"),
    )
    assertEquals(
      remoteImagePullCommands("podman", buildImages),
      buildImages.map(image => Vector("podman", "pull", image, "--quiet")),
    )
    buildCommands.foreach: command =>
      assert(!command.exists(_.startsWith("--pull")), command.mkString(" "))

  test("an echoed command shows each word unambiguously on one line, a script argument included"):
    import HostCommands.shellWord
    assertEquals(shellWord("/opt/podman/bin/podman"), "/opt/podman/bin/podman")
    assertEquals(shellWord("--format"), "--format")
    assertEquals(shellWord("{{.Id}}"), "'{{.Id}}'")
    assertEquals(shellWord("set -eu\npodman rm x >/dev/null"), "'set -eu\\npodman rm x >/dev/null'")
    assertEquals(shellWord("it's\tnot\\"), "'it'\\''s\\tnot\\\\'")
    assertEquals(shellWord("C:\\new"), "'C:\\\\new'")
    assertNotEquals(shellWord("\\n"), shellWord("\n"))
    assertEquals(shellWord("it's"), "'it'\\''s'")
    assertEquals(shellWord(""), "''")
    import HostCommands.renderCommand
    val pull = Vector("/opt/podman/bin/podman", "pull", "docker.io/library/debian:13.6-slim", "--quiet")
    assertEquals(renderCommand(pull, Some("/opt/podman/bin/podman")), "+ podman pull docker.io/library/debian:13.6-slim --quiet")
    assertEquals(renderCommand(pull, None), "+ /opt/podman/bin/podman pull docker.io/library/debian:13.6-slim --quiet")
    assertEquals(renderCommand(Vector("rm", "-rf", "/a b"), Some("/opt/podman/bin/podman")), "+ rm -rf '/a b'")
    val script = "set -eu\nsudo sh -c 'echo user_allow_other >> /etc/fuse.conf'\n"
    val rendered = renderCommand(Vector("podman", "machine", "ssh", script), None)
    assert(!rendered.contains('\n'), rendered)
    assert(rendered.startsWith("+ podman machine ssh 'set -eu\\nsudo"), rendered)

  test("a --quiet pull's verdict comes from the image id before and after"):
    val old = "sha256:7e3898f7b011a107d0ef7393d5f604a6e0c0ff05ac4f2476630a8af21059ec9b"
    val now = "sha256:e46eecd22d3291011dd3f0b1c627d5a7222406fc1429e537bf0e6a2bd9f55c92"
    assertEquals(pullVerdict(Some(old), Some(old)), "unchanged")
    assertEquals(pullVerdict(Some(old), Some(now)), "updated from 7e3898f7b011")
    assertEquals(pullVerdict(None, Some(now)), "new on this machine")

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
        LauncherBuiltImages,
        None,
      ),
      Right(Vector("example.invalid/one/second:current", "example.invalid/two/tool:latest")),
    )

  test("an image reaches the build through a mount or a continued COPY, and is refreshed too"):
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
        LauncherBuiltImages,
        None,
      ),
      Right(Vector(
        "example.invalid/base:1",
        "example.invalid/mounted:2",
        "example.invalid/tool:3",
        "example.invalid/continued:4",
      )),
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
        LauncherBuiltImages,
        None,
      ),
      Right(Vector("example.invalid/base:1")),
    )

  test("a FROM reads the global arguments, not a later stage's"):
    // Sharing one scope would have --build refresh two.invalid while the build itself pulls one.invalid.
    assertEquals(
      remoteImagesInContainerfile(
        "Containerfile",
        """ARG REGISTRY=one.invalid
          |FROM scratch
          |ARG REGISTRY=two.invalid
          |FROM ${REGISTRY}/tool:1
          |""".stripMargin,
        Map.empty,
        LauncherBuiltImages,
        None,
      ),
      Right(Vector("one.invalid/tool:1")),
    )
    // ko-agent-sandbox declares ARG IMG_TAG_VER twice for this (ContainerfileSources has the scope rule).
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
        LauncherBuiltImages,
        None,
      ),
      Right(Vector("one.invalid/base:1", "one.invalid/tool:2.0")),
    )
    val unshared = remoteImagesInContainerfile(
      "Containerfile",
      "ARG REGISTRY=one.invalid\nFROM scratch\nCOPY --from=${REGISTRY}/tool:1 /t /t\n",
      Map.empty,
      LauncherBuiltImages,
      None,
    )
    assert(unshared.swap.exists(_.contains("no value for build-image variable")), unshared.toString)

  test("a stage built on an earlier one keeps the arguments that stage declared"):
    assertEquals(
      remoteImagesInContainerfile(
        "Containerfile",
        """FROM scratch AS base
          |ARG REGISTRY=example.invalid
          |FROM base
          |COPY --from=${REGISTRY}/tool:1 /t /t
          |""".stripMargin,
        Map.empty,
        LauncherBuiltImages,
        None,
      ),
      Right(Vector("example.invalid/tool:1")),
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
      LauncherBuiltImages,
      None,
    )
    assert(unrelated.swap.exists(_.contains("no value for build-image variable")), unrelated.toString)

  test("a short image name is identified, not discarded"):
    Vector("FROM alpine:3.20\n", "FROM scratch\nCOPY --from=busybox:1.36 /b /b\n",
      "FROM scratch\nRUN --mount=type=bind,from=busybox:1.36,target=/m true\n",
    ).foreach: text =>
      val refused = remoteImagesInContainerfile("Containerfile", text, Map.empty, LauncherBuiltImages, None)
      assert(refused.swap.exists(_.contains("unqualified image source")), s"$text -> $refused")
    assertEquals(
      remoteImagesInContainerfile(
        "Containerfile",
        "FROM scratch AS one\nFROM local-base:1\nCOPY --from=one /a /b\nCOPY --from=0 /c /d\n",
        Map.empty,
        LauncherBuiltImages,
        None,
      ),
      Right(Vector.empty),
    )

  test("a reference naming its registry is refreshed, one naming a launcher image is not"):
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
        LauncherBuiltImages,
        None,
      ),
      Right(Vector(
        "localhost/registry-held:1",
        "MyRegistry/uppercase-host:1",
        "registry.example:5000/ported:1",
      )),
    )
    // A declared local image is not pulled even when it is spelled with its registry.
    assertEquals(
      remoteImagesInContainerfile(
        "Containerfile",
        "FROM registry.example/base:1\n",
        Map.empty,
        Set("registry.example/base:1"),
        None,
      ),
      Right(Vector.empty),
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
          None,
        ),
        Right(Vector.empty),
        local.toString,
      )

  test("an unnamed stage keeps its arguments for a descendant that names its position"):
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
        LauncherBuiltImages,
        None,
      ),
      Right(Vector("example.invalid/tool:2")),
    )

  test("a targeted build reads only the stages it reaches"):
    val twoStages =
      """ARG REACHED=example.invalid
        |FROM ${REACHED}/base:1 AS build
        |FROM ${UNPASSED}/later:2
        |COPY --from=${UNPASSED}/tool:3 /t /t
        |""".stripMargin
    val targeted = Vector(
      Vector("podman", "build", "--target", "build", "-t", "out:1", "ctx"),
    )
    assertEquals(
      remoteImagesForBuildCommands(targeted, _ => twoStages, Set.empty),
      Vector("example.invalid/base:1"),
    )
    // Without the target the same Containerfile reaches the stage whose argument is unpassed.
    val whole = remoteImagesInContainerfile("Containerfile", twoStages, Map.empty, Set.empty, None)
    assert(whole.swap.exists(_.contains("${UNPASSED}")), whole.toString)

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
        stop,
      )
    assertEquals(
      remoteImagesInContainerfile(
        "Containerfile",
        "FROM example.invalid/only:1 AS only\n",
        Map.empty,
        Set.empty,
        Some("only"),
      ),
      Right(Vector("example.invalid/only:1")),
    )

  test("a stage alias is matched exactly, as Buildah matches it"):
    assertEquals(
      remoteImagesInContainerfile(
        "Containerfile",
        "FROM scratch AS Build\nARG R=example.invalid\nFROM Build\nCOPY --from=${R}/t:1 /t /t\n",
        Map.empty,
        LauncherBuiltImages,
        None,
      ),
      Right(Vector("example.invalid/t:1")),
    )
    val mismatched = remoteImagesInContainerfile(
      "Containerfile",
      "FROM scratch AS Build\nARG R=example.invalid\nFROM build\nCOPY --from=${R}/t:1 /t /t\n",
      Map.empty,
      LauncherBuiltImages,
      None,
    )
    assert(mismatched.swap.exists(_.contains("unqualified image source build")), mismatched.toString)
    val expanded = remoteImagesInContainerfile(
      "Containerfile",
      "ARG N=one\nFROM scratch AS ${N}\n",
      Map.empty,
      LauncherBuiltImages,
      None,
    )
    assert(expanded.swap.exists(_.contains("unsupported stage alias")), expanded.toString)

  test("remote image parsing refuses a shape it does not resolve"):
    // Every one of these is a Containerfile podman accepts. Approximating them is what would let a
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
      "# escape=`\nCOPY `\n  --from=example.invalid/tool:1 /a /b\n" -> "unsupported parser directive",
      "# syntax=docker/dockerfile:1\nFROM example.invalid/base:1\n" -> "unsupported parser directive",
      "FROM scratch\nRUN <<EOF\nCOPY --from=example.invalid/not-an-image:1 /a /b\nEOF\n" ->
        "unsupported here-document",
    ).foreach: (text, expected) =>
      val refused = remoteImagesInContainerfile("Containerfile", text, Map.empty, LauncherBuiltImages, None)
      assert(refused.swap.exists(_.contains(expected)), s"$text -> $refused")

  test("every generated build command uses only flags the remote-source scan reads"):
    val generated = buildCommands("podman", "1.2-3", "sourceid", "sandboxid", "proxyid") ++
      updateCommands("podman", "1.2-3", "sandboxid") ++
      selfTestBuildCommands("podman", "test-rust", "sourceid", "selftestid")
    generated.foreach: command =>
      val operands = command.drop(2).init
      operands.filter(_.startsWith("-")).foreach: flag =>
        assert(BuildCommandFlags.contains(flag), s"$flag in ${command.mkString(" ")}")
      operands.sliding(2).foreach:
        case Vector("--build-arg", value) =>
          assert(value.contains('='), s"--build-arg $value in ${command.mkString(" ")}")
        case _ => ()

  test("a build argument reaches only the references declared before it"):
    // podman expands an ARG that no earlier declaration named to the empty string; refusing is the
    // half of that trade that cannot build a broken reference.
    val early = remoteImagesInContainerfile(
      "Containerfile",
      "FROM example.invalid/base:${LATER}\nARG LATER=default\n",
      Map("LATER" -> "override"),
      LauncherBuiltImages,
      None,
    )
    assert(early.isLeft, early.toString)
    assertEquals(
      remoteImagesInContainerfile(
        "Containerfile",
        "ARG LATER=default\nFROM example.invalid/base:${LATER}\n",
        Map("LATER" -> "override"),
        LauncherBuiltImages,
        None,
      ),
      Right(Vector("example.invalid/base:override")),
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
      buildImageTags("1.2-3"),
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
          TaggedImage("example.invalid/ko-agent-sandbox:old", "other-project"),
        ),
        buildImageTags("1.2-3"),
      ),
      Vector(
        TaggedImage("debian-coursier:1.1-2", "coursier-old"),
        TaggedImage("localhost/debian-temurin:1.1-2", "temurin-old"),
      ),
    )
    assertEquals(
      supersededImageRemoveCommands(
        "podman",
        Vector("fs-old", "proxy-old", "base-old", "coursier-old", "temurin-old"),
        Vector("base-current", "proxy-current", "fs-current"),
      ),
      Vector(
        Vector("podman", "image", "rm", "--ignore", "fs-old"),
        Vector("podman", "image", "rm", "--ignore", "proxy-old"),
        Vector("podman", "image", "rm", "--ignore", "base-old"),
        Vector("podman", "image", "rm", "--ignore", "coursier-old"),
        Vector("podman", "image", "rm", "--ignore", "temurin-old"),
      ),
    )
    assertEquals(
      protectedImageNames(
        managedImageTags("1.2-3"),
        Vector(TaggedImage("localhost/ko-agent-self-test:latest", "self-test-old")),
      ),
      managedImageTags("1.2-3").filterNot(_ == "ko-agent-self-test:latest"),
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
        "{{.Repository}}:{{.Tag}}\t{{.Id}}",
      ),
    )
    val journalDir = Files.createTempDirectory("image-cleanup-journal")
    val journal = journalDir.resolve("cleanup.ids")
    val interrupted = Vector(id('1'), id('2'))
    writeImageCleanupJournal(journal, interrupted)
    assertEquals(readImageCleanupJournal(journal), Right(interrupted))

    val listedBefore = imageIdsForTags(
      Vector(TaggedImage("localhost/ko-agent-fs:latest", "3" * 64)),
      Vector("ko-agent-fs:latest"),
    )
    val candidates = prepareImageCleanupJournal(
      journal,
      listedBefore :+ id('4'),
      Vector(TaggedImage("debian-temurin:old", id('5'))),
    )
    assertEquals(candidates, Vector(id('1'), id('2'), id('4'), "3" * 64, id('5')))
    assertEquals(readImageCleanupJournal(journal), Right(candidates))
    assertEquals(
      prependImageCleanupDependents(
        candidates,
        Vector(
          TaggedImage("ko-agent-self-test:latest", id('6')),
          TaggedImage("ko-agent-self-test-build:cache", id('2')),
        ),
      ),
      Vector(id('6'), id('2'), id('1'), id('4'), "3" * 64, id('5')),
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
      .zip(imageSourcesForBuildCommands(verbs, BundledBuildContext.resource, declared.toSet))
      .flatMap((child, sources) => sources.parents.map(child -> _))
      .distinct
    // Not empty by an accident of parsing: the sandbox image builds on the coursier base.
    assert(edges.contains("ko-agent-sandbox:latest" -> s"debian-coursier:$version"), edges.toString)

    def precedes(order: Vector[String], first: String, second: String): Boolean =
      order.indexOf(first) >= 0 && order.indexOf(second) > order.indexOf(first)

    // The declared dependency orders build a parent before its child.
    edges.foreach: (child, parent) =>
      assert(precedes(declared, parent, child), s"$parent must be declared before $child")

    // Every cleanup list removes the child first, whatever order podman lists the images in.
    def id(index: Int): String = f"sha256:$index%064x"
    val listing = declared.zipWithIndex.map((tag, index) => TaggedImage(s"localhost/$tag", id(index))).reverse
    val ids = listing.map(image => image.tag.stripPrefix("localhost/") -> image.id).toMap
    val journal = prependImageCleanupDependents(
      imageCleanupCandidates(Vector.empty, imageIdsForTags(listing, buildImageTags(version)), Vector.empty),
      selfTestCleanupOrder(listing),
    )
    edges.foreach: (child, parent) =>
      assert(precedes(journal, ids(child), ids(parent)), s"$child must be removed before $parent")
    // The self-test order is constructed, not inherited: a listing in the wrong order, with a
    // duplicate, still comes out leaves first and once.
    assertEquals(
      selfTestCleanupOrder(listing ++ listing.take(1)).map(_.tag),
      SelfTestImageTags.reverse.map(tag => s"localhost/$tag"),
    )

  test("an image retained by a container is reported as a later cleanup retry"):
    val imageId = "sha256:" + "1" * 64
    val containerId = "2" * 64
    val error = s"Error: image used by $containerId: image is in use by a container"
    val note = supersededImageRetentionNote(imageId, error)
    assert(note.contains(s"image ${"1" * 12} while container ${"2" * 12} still uses it"), note)
    assert(!note.contains(containerId) && !note.contains("sha256"), note)
    assert(note.contains("\n  a later --build, --update, or --self-test will retry"), note)
    assert(!note.contains("Error:"), note)

    val unexpected = supersededImageRetentionNote(imageId, "Error: storage is unavailable")
    assert(unexpected.contains("podman did not remove it"), unexpected)
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
    assert(stale.exists(_.startsWith("container image ko-agent-sandbox:latest")), stale.toString)
    assert(stale.exists(_.contains(sandboxId)), stale.toString)
    assert(stale.exists(_.contains(proxyId)), stale.toString)
    val unlabeled = bundleMismatch("ko-agent-sandbox:latest", sandboxId, "")
    assert(unlabeled.exists(_.contains("no bundle label")), unlabeled.toString)
    assert(unlabeled.exists(_.contains(s"$sandboxId")), unlabeled.toString)
    assert(unlabeled.exists(_.contains("(none)")), unlabeled.toString)

  test("the bundled build context carries every Containerfile and an INDEX"):
    // The resourceGenerators task in build.sbt put these in the jar; this pins that the launcher can find what --build
    // unpacks.
    val index = BundledBuildContext.resource("INDEX").linesIterator.filter(_.nonEmpty).toVector
    Vector(
      "debian-temurin/Containerfile",
      "debian-coursier/Containerfile",
      "ko-agent-sandbox/Containerfile",
      "ko-agent-egress-proxy/Containerfile",
      "ko-agent-fs/Containerfile",
    ).foreach: path =>
      assert(index.contains(path), s"INDEX missing $path")
      assert(BundledBuildContext.resource(path).contains("FROM"), path)

    // The only way an agent-installed JVM reaches an inspected forge host at all — it needs both
    // the CA and the proxy — so a bundle without it is a silently degraded sandbox.
    assert(index.contains("ko-agent-sandbox/sandbox-jdk-use-proxy"), "sandbox-jdk-use-proxy script missing")
    val useProxy = BundledBuildContext.resource("ko-agent-sandbox/sandbox-jdk-use-proxy")
    assert(useProxy.contains("-importcert"), "sandbox-jdk-use-proxy imports no certificate")
    assert(useProxy.contains("net.properties"), "sandbox-jdk-use-proxy sets no proxy")
    assert(index.contains("ko-agent-sandbox/sandbox-apt-get"), "sandbox-apt-get script missing")
    assert(
      BundledBuildContext.resource("ko-agent-sandbox/sandbox-apt-get").contains("--download-only"),
      "sandbox-apt-get does not resolve dependencies",
    )
    assert(
      index.contains("ko-agent-sandbox/sandbox-install-podman"),
      "sandbox-install-podman script missing",
    )
    assert(
      BundledBuildContext.resource("ko-agent-sandbox/sandbox-install-podman").contains("same-uid"),
      "sandbox-install-podman does not gate on the nesting opt-in",
    )

    // ko-agent-fs is compiled from source on the user's machine rather than shipped as a binary, so its sources —
    // not just its Containerfile — have to travel in the jar. The policy core is the one that matters most.
    Vector("ko-agent-fs/src/policy.rs", "ko-agent-fs/Cargo.lock", "ko-agent-fs/deny.toml").foreach: path =>
      assert(index.contains(path), s"INDEX missing $path")
    assert(BundledBuildContext.resource("ko-agent-fs/src/policy.rs").contains("is_dotgit_name"))

    // Build output must not have been swept into the bundle — Rust's target/ as well as sbt's.
    assert(!index.exists(_.split("/").contains("target")), "target leaked")

    // ko-agent-fs/doc and probe are deliberately absent (build.sbt, the bundling task, has why).
    Vector("ko-agent-fs/doc/", "ko-agent-fs/probe/").foreach: prefix =>
      assert(!index.exists(_.startsWith(prefix)), s"$prefix leaked into the jar")

  test("ImgTagVersion mirrors debian-temurin's Debian and Temurin pins"):
    val tag = "([0-9.]+)-([0-9.]+)-[0-9]+".r
    ImgTagVersion match
      case tag(debian, temurin) =>
        val lines = BundledBuildContext.resource("debian-temurin/Containerfile").linesIterator.toVector
        assert(
          lines.contains(s"FROM docker.io/library/debian:$debian-slim"),
          s"debian-temurin does not pin debian:$debian-slim",
        )
        assert(
          lines.contains(s"ARG TEMURIN_VERSION=$temurin"),
          s"debian-temurin does not pin TEMURIN_VERSION=$temurin",
        )
      case _ => fail(s"ImgTagVersion '$ImgTagVersion' is not <debian>-<temurin>-<revision>")

  test("SECURITY.md names exactly the allow=git-fetch hosts the proxy ships"):
    // The git-host list has two homes: the allow=git-fetch entries of the proxy's baseline/host and
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
    val catalog = Files.readString(
      Paths.get("container/ko-agent-egress-proxy/app/src/main/resources/baseline/host"),
    )
    val gitHosts = "(?m)^\\+host (\\S+)\\s+allow=git-fetch".r.findAllMatchIn(catalog).map(_.group(1)).toVector
    assertEquals(listed, gitHosts)

  test("every egress-policy example is a complete policy the production parser accepts"):
    def entries(directory: java.nio.file.Path) =
      val stream = Files.list(directory)
      try stream.iterator.asScala.toVector
      finally stream.close()

    val root = Paths.get("doc/egress-policy-examples")
    val examples = entries(root).filter(Files.isDirectory(_)).sortBy(_.getFileName.toString)
    assert(examples.nonEmpty, "no egress-policy examples found")

    examples.foreach: directory =>
      val files = entries(directory)
      val names = files.map(_.getFileName.toString).toSet
      assert(names.nonEmpty, s"$directory is empty")
      assertEquals(names -- Set("allowed", "denied"), Set.empty[String], directory.toString)

      def contents(name: String) =
        files.find(_.getFileName.toString == name).map(Files.readString(_))

      resolvePolicy(
        Some("deny-unless-allowed"),
        None,
        contents("allowed"),
        contents("denied"),
      )

  test("agent egress instructions use the proxy's allowance vocabulary without denying its exceptions"):
    // The launcher writes this prose; the proxy owns the vocabulary. An agent following a tag the
    // proxy does not define writes a policy file that fails the *next* launch, so the drift shows
    // up nowhere near the text that caused it. Scraped from the proxy's source, like the git-host
    // list above, because the launcher carries no copy of the tag set.
    val proxySource = Files.readString(
      Paths.get("container/ko-agent-egress-proxy/app/src/main/scala/AgentEgressProxy.scala"),
    )
    val declared = """val KnownTags: Set\[String\] = Set\(([^)]*)\)""".r
      .findFirstMatchIn(proxySource)
      .getOrElse(fail("the proxy no longer declares KnownTags as a literal Set"))
    val known = """"([^"]+)"""".r.findAllMatchIn(declared.group(1)).map(_.group(1)).toSet
    assert(known.nonEmpty, "scraped no tags at all")

    // A resolved policy with no allowances of its own, so every `allow=tag` found is the prose's
    // own.
    val emptyResolution = "egress profile: deny-all\nrestricted hosts (0):\ndenied rules (0):"
    val named = "allow=([a-z-]+)".r
      .findAllMatchIn(authoritySection("live", "fuse", emptyResolution))
      .map(_.group(1))
      .toSet
    assert(named.nonEmpty, "the section names no allowance, so it teaches an agent nothing about them")
    assertEquals(named -- known, Set.empty[String], s"the proxy defines only $known")
    val section = authoritySection("live", "fuse", emptyResolution)
    assert(section.contains("named allowances"), section)
    val baseInstructions = Files.readString(
      Paths.get("container/ko-agent-sandbox/AGENTS-SANDBOX.md"),
    )
    assert(baseInstructions.contains("outside a named allowance"), baseInstructions)

  test("the authority section directs the agent by write mode, never leaves it to probing"):
    val resolution = "egress profile: deny-all\nrestricted hosts (0):\ndenied rules (0):"
    val readOnly = authoritySection("reject", "fuse", resolution)
    assert(readOnly.contains("read-only"), readOnly)
    assert(readOnly.contains("--write=live"), readOnly)
    val filtered = authoritySection("live", "fuse", resolution)
    assert(filtered.contains("ko-agent-fs"), filtered)
    assert(filtered.contains("at any depth"), filtered)
    assert(filtered.contains("symlink targets"), filtered)
    val raw = authoritySection("live", "none", resolution)
    assert(raw.contains("raw writable bind"), raw)
    assert(raw.contains(KoAgentFs.RawWorkspaceBoundary), raw)
    assert(raw.contains("Nested repository control state"), raw)
    assert(raw.contains("non-portable"), raw)
    assert(raw.contains("symlinks remain writable"), raw)
    // Both name the relaunch path for a host the policy does not admit.
    Vector(readOnly, filtered, raw).foreach: section =>
      assert(section.contains(".ko-agent-sandbox/egress/allowed"), section)
      assert(section.contains("deny-unless-allowed"), section)
    // --run-on-host adds the venue instruction, naming each served tool's command. Without the
    // option, a macOS session gets one discovery line — only the launcher knows the platform —
    // and other platforms hear nothing about a command they can never have.
    val hostBuilds = authoritySection("live", "fuse", resolution, Vector("sbt", "mill"))
    assert(hostBuilds.contains("sandbox-run-on-host sbt"), hostBuilds)
    assert(hostBuilds.contains("sandbox-run-on-host mill"), hostBuilds)
    assert(hostBuilds.contains("starts and ends its own sbt server"), hostBuilds)
    assert(hostBuilds.contains("never re-run in the container"), hostBuilds)
    assert(!filtered.contains("sandbox-run-on-host"), filtered)
    val discoverable =
      authoritySection("live", "fuse", resolution, Vector.empty, hostBuildsAvailable = true)
    assert(discoverable.contains("absent from this session"), discoverable)
    assert(discoverable.contains("--run-on-host=sbt,mill"), discoverable)
    assert(!discoverable.contains("sandbox-run-on-host sbt …"), discoverable)
    // reject's instruction flips when a host build can write the project (the §9.1 composition):
    // the blanket "do not attempt writes" would be false.
    val rejectWithBuilds = authoritySection("reject", "fuse", resolution, Vector("sbt"))
    assert(rejectWithBuilds.contains("session's own writes"), rejectWithBuilds)
    assert(rejectWithBuilds.contains("sandbox-run-on-host"), rejectWithBuilds)
    assert(rejectWithBuilds.contains("--write=live"), rejectWithBuilds)

  test("the generated agent document cache varies with every authority input"):
    def stamp(
      imageId: String = "image-a",
      writeMode: String = "live",
      guard: String = "fuse",
      policy: String = "policy-a",
      instructions: Option[String] = None,
      runOnHost: Vector[String] = Vector.empty,
    ) = agentDocumentStamp(imageId, writeMode, guard, policy, instructions, runOnHost)

    val variants = Vector(
      stamp(),
      stamp(imageId = "image-b"),
      stamp(writeMode = "reject"),
      stamp(guard = "none"),
      stamp(policy = "policy-b"),
      stamp(instructions = Some("project instructions")),
      stamp(runOnHost = Vector("sbt")),
      stamp(runOnHost = Vector("sbt", "mill")),
    )
    assertEquals(variants.distinct.size, variants.size)

  test("option parsing: the first non-option ends launcher parsing, -- is an optional escape"):
    assertEquals(
      parseCommandLine(List("--write=reject", "--egress=deny-all", "claude", "--write=live")),
      Right(
        ParsedCommandLine(
          Some("reject"), Some("deny-all"), None, List("claude", "--write=live"),
        ),
      ),
    )
    // After `--` everything is the command, launcher-option lookalikes included.
    assertEquals(
      parseCommandLine(List("--", "--write=live", "claude")),
      Right(ParsedCommandLine(None, None, None, List("--write=live", "claude"))),
    )
    // No arguments launches the image's default command.
    assertEquals(parseCommandLine(Nil), Right(ParsedCommandLine(None, None, None, Nil)))
    assertEquals(parseCommandLine(Nil).map(_.writeMode), Right("live"))
    assertEquals(parseCommandLine(Nil).map(_.egressProfile), Right("deny-unless-allowed"))

  test("option parsing: authority values are a closed set and are selected once"):
    assert(parseCommandLine(List("--write=maybe")).swap.exists(_.contains("reject, live")))
    assert(parseCommandLine(List("--egress=allow-all")).isLeft)
    assert(parseCommandLine(List("--write=live", "--write=reject")).swap.exists(_.contains("twice")))
    assert(parseCommandLine(List("--write", "live")).swap.exists(_.contains("--write=<mode>")))
    assert(parseCommandLine(List("--frobnicate")).swap.exists(_.contains("unknown option")))

  test("option parsing: --run-on-host names tools from a closed set, each once, selected once"):
    assertEquals(
      parseCommandLine(List("--run-on-host=sbt,mill", "claude")).map(_.runOnHost),
      Right(Some(Vector("sbt", "mill"))),
    )
    assertEquals(parseCommandLine(List("claude")).map(_.runOnHost), Right(None))
    assert(parseCommandLine(List("--run-on-host=gradle")).swap.exists(_.contains("sbt, mill")))
    assert(parseCommandLine(List("--run-on-host=")).isLeft)
    assert(parseCommandLine(List("--run-on-host=sbt,sbt")).swap.exists(_.contains("twice")))
    assert(
      parseCommandLine(List("--run-on-host=sbt", "--run-on-host=mill")).swap
        .exists(_.contains("twice")),
    )
    assert(
      parseCommandLine(List("--run-on-host", "sbt")).swap.exists(_.contains("--run-on-host=<tools>")),
    )
    // After the command, it is the command's.
    assertEquals(parseCommandLine(List("claude", "--run-on-host=sbt")).map(_.runOnHost), Right(None))

  test("option parsing: --env forwards a host variable or sets one, repeatable, each name once"):
    assertEquals(
      parseCommandLine(List("--env=SBT_OPTS", "--env=FOO=a=b", "--env=EMPTY=", "claude")).map(_.env),
      Right(Vector(EnvForward("SBT_OPTS", None), EnvForward("FOO", Some("a=b")), EnvForward("EMPTY", Some("")))),
    )
    assert(parseCommandLine(List("--env=SBT_OPTS", "--env=SBT_OPTS=x")).swap.exists(_.contains("twice")))
    assert(parseCommandLine(List("--env=1BAD")).swap.exists(_.contains("[A-Za-z_]")))
    assert(parseCommandLine(List("--env=")).isLeft)
    assert(parseCommandLine(List("--env", "SBT_OPTS")).swap.exists(_.contains("--env=<name>")))
    // After the command, it is the command's.
    assertEquals(parseCommandLine(List("claude", "--env=X")).map(_.env), Right(Vector.empty))

  test("a forward reads the host at launch, fails on an unset name, and never replaces a boundary variable"):
    val host = Map("SBT_OPTS" -> "-Xmx2g", "EMPTY" -> "")
    assertEquals(
      forwardedEnvironment(Vector(EnvForward("SBT_OPTS", None), EnvForward("FOO", Some("v=1"))), host.get),
      Right(Vector("--env=SBT_OPTS=-Xmx2g", "--env=FOO=v=1")),
    )
    // Set but empty is a value; a name the host lacks is not.
    assertEquals(forwardedEnvironment(Vector(EnvForward("EMPTY", None)), host.get), Right(Vector("--env=EMPTY=")))
    assert(forwardedEnvironment(Vector(EnvForward("MISSING", None)), host.get).swap.exists(_.contains("not set")))
    // An explicit value never consults the host, so it need not be exported there.
    assertEquals(
      forwardedEnvironment(Vector(EnvForward("MISSING", Some("x"))), host.get),
      Right(Vector("--env=MISSING=x")),
    )
    Vector("KO_AGENT_SANDBOX_EGRESS_POLICY", "KO_AGENT_SANDBOX_NESTING", "KO_AGENT_SANDBOX_MEMORY").foreach: name =>
      val refused = forwardedEnvironment(Vector(EnvForward(name, Some("x"))), host.get)
      assert(refused.swap.exists(_.contains("KO_AGENT_SANDBOX_*")), s"$name: $refused")
    // Everything else the launcher or the image sets is the user's to override, by name.
    Vector("HTTPS_PROXY", "SSL_CERT_FILE", "TZ", "PAGER", "PATH").foreach: name =>
      assertEquals(forwardedEnvironment(Vector(EnvForward(name, Some("v"))), host.get), Right(Vector(s"--env=$name=v")))

  test("what the launcher tells the sandbox is in force is all KO_AGENT_SANDBOX_*, the prefix --env refuses"):
    // The refusal is a prefix, so a variable the launcher passes to say what is enforced must
    // carry it: the interpolated `--env=$Constant=` forms are those, and EgressProxyPolicy's
    // `$variable` names the proxy container's policy files, which no forward reaches.
    val sources = Files.list(Paths.get("src/main/scala")).iterator.asScala
      .filter(_.toString.endsWith(".scala")).map(Files.readString).toVector
    val interpolated = sources.flatMap("\"--env=\\$([A-Za-z]+)".r.findAllMatchIn(_).map(_.group(1))).toSet
    assertEquals(interpolated, Set("SessionStartVariable", "NestingVariable", "ClipboardVariable", "variable"))
    Vector(SessionStartVariable, NestingVariable, ClipboardVariable, "KO_AGENT_SANDBOX_EGRESS_POLICY").foreach: name =>
      assert(name.startsWith(RefusedForwardPrefix), name)
    assert(sources.exists(_.contains("\"--env=KO_AGENT_SANDBOX_EGRESS_POLICY=")))

  test("--self-test's container leaves nothing behind and carries what the mount needs"):
    // A measurement that changes its subject is worth nothing, so the run binds no host path and
    // keeps no container.
    val command = selfTestRunCommand("podman", Some("a_handle_held"), asRoot = false)
    assert(command.contains("--rm"), command.mkString(" "))
    assert(command.containsSlice(Seq("--device", "/dev/fuse")), command.mkString(" "))
    assert(command.containsSlice(Seq("--cap-add", "SYS_ADMIN")), command.mkString(" "))
    assert(command.contains("--network=none"), command.mkString(" "))
    assert(command.contains("--pull=never"), command.mkString(" "))
    assert(command.endsWith(Seq("ko-agent-self-test:latest", "a_handle_held")), command.mkString(" "))
    assert(
      !command.exists(argument => argument == "-v" || argument.startsWith("--volume")),
      s"--self-test binds a host path into the container: ${command.mkString(" ")}",
    )
    assert(
      !command.exists(_.startsWith("--mount")),
      s"--self-test mounts something into the container: ${command.mkString(" ")}",
    )
    // The root retry exists to measure the bounding-set question, not to be the default.
    assert(!command.containsSlice(Seq("--user", "0")), command.mkString(" "))
    assert(selfTestRunCommand("podman", None, asRoot = true).containsSlice(Seq("--user", "0")))
    assertEquals(selfTestRunCommand("podman", None, asRoot = false).last, "ko-agent-self-test:latest")

  test("--self-test builds its image from the bundle root against the pinned toolchain"):
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
      "# a comment\nARG RUST_VERSION=9.9.9\nFROM docker.io/library/rust:${RUST_VERSION}-slim\n",
    )
    assertEquals(pinnedRustVersion(context), "9.9.9")

  test("option parsing: management verbs take the rest as operands"):
    assertEquals(
      parseCommandLine(List("--proxy-log", "-f")),
      Right(ParsedCommandLine(None, None, Some(("--proxy-log", List("-f"))), Nil)),
    )
    assertEquals(
      parseCommandLine(List("--egress=deny-unless-allowed", "--egress-effective", "--", "claude")),
      Right(
        ParsedCommandLine(
          None, Some("deny-unless-allowed"),
          Some(("--egress-effective", List("--", "claude"))), Nil,
        ),
      ),
    )
    assertEquals(
      parseCommandLine(List("--egress-check=pypi.org", "claude")),
      Right(ParsedCommandLine(None, None, Some(("--egress-check", List("pypi.org", "claude"))), Nil)),
    )
    assertEquals(
      parseCommandLine(List("--self-test", "a_handle_held")),
      Right(ParsedCommandLine(None, None, Some(("--self-test", List("a_handle_held"))), Nil)),
    )

  test("the state root must be absolute, resolves canonically, and stays outside the project"):
    // Refused rather than resolved, on every platform spelling.
    assert(stateRootOf(HostCommands.Os.Linux, Map("XDG_STATE_HOME" -> "relative/state").get).isLeft)
    assert(stateRootOf(HostCommands.Os.Linux, Map("HOME" -> "relative/home").get).isLeft)
    assert(stateRootOf(HostCommands.Os.Windows, Map("LOCALAPPDATA" -> "relative").get).isLeft)
    assert(stateRootOf(HostCommands.Os.Linux, Map.empty[String, String].get).isLeft)

    val base = Files.createTempDirectory("state-root").toRealPath()
    assertEquals(
      stateRootOf(HostCommands.Os.Linux, Map("XDG_STATE_HOME" -> base.toString).get),
      Right(base.resolve("ko-agent-sandbox")),
    )
    val real = Files.createDirectories(base.resolve("real"))
    val linked = Files.createSymbolicLink(base.resolve("linked"), real)
    assertEquals(
      stateRootOf(
        HostCommands.Os.Linux,
        Map("XDG_STATE_HOME" -> linked.resolve("not-yet/state").toString).get,
      ),
      Right(real.resolve("not-yet/state/ko-agent-sandbox")),
    )

    val project = Files.createTempDirectory("state-root-project").toRealPath()
    val linux = HostCommands.Os.Linux
    assert(
      forbiddenStateRootReason(linux, project.resolve("state/ko-agent-sandbox"), project).isDefined,
    )
    assertEquals(forbiddenStateRootReason(linux, base.resolve("ko-agent-sandbox"), project), None)
    // Not exercised from a Windows runner, whose Path type cannot spell a POSIX absolute path.
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
      Seq("run-ffffffff"),
    )
    assertEquals(tlsRunDirsToPrune(names, Set.empty, _ != "run-ffffffff"), Seq("run-1a2b3c4d"))
    assertEquals(tlsRunDirsToPrune(names, Set("1a2b3c4d", "ffffffff"), _ => true), Seq())

  test("reset removes exactly this project's per-run networks"):
    val names = Seq(
      "ko-agent-sandbox-app-abc123-1a2b3c4d",
      "ko-agent-egress-app-abc123-1a2b3c4d",
      "ko-agent-sandbox-other-def456-99aabbcc", // another project's
      "podman",
    )
    assertEquals(
      projectNetworks(names, "app-abc123"),
      Seq(
        "ko-agent-sandbox-app-abc123-1a2b3c4d",
        "ko-agent-egress-app-abc123-1a2b3c4d",
      ),
    )

  test("a directory named after another project's id cannot match its run filters"):
    val victimId = "app-abc123"
    assertEquals(
      projectNetworks(Seq("ko-agent-sandbox-app-abc123-9f8e7d6c-1a2b3c4d"), victimId),
      Seq(),
    )
    assert(!isRunNamed(proxyRunContainer, victimId)("ko-agent-egress-proxy-app-abc123-9f8e7d6c-1a2b3c4d"))
    assert(!isRunNamed(sandboxRunContainer, victimId)("ko-agent-sandbox-run-app-abc123-9f8e7d6c-1a2b3c4d"))
    // The honest names — an eight-hex suffix right after the id — still match.
    assert(isRunNamed(proxyRunContainer, victimId)("ko-agent-egress-proxy-app-abc123-1a2b3c4d"))
    assert(isRunNamed(sandboxRunContainer, victimId)("ko-agent-sandbox-run-app-abc123-1a2b3c4d"))
    // And the minted suffix is what the anchor assumes: exactly eight hex characters.
    assert(newRunSuffix().matches("[0-9a-f]{8}"))

  test("reset filters match exactly the launcher's reserved name shapes"):
    val id = "app-0123456789ab"
    assertEquals(
      proxyContainers(
        Seq(s"ko-agent-egress-proxy-$id-1a2b3c4d", "ko-agent-egress-proxy-manual", "other"),
      ),
      Seq(s"ko-agent-egress-proxy-$id-1a2b3c4d"),
    )
    assertEquals(
      sandboxRunContainers(
        Seq(
          s"ko-agent-sandbox-run-$id-1a2b3c4d",
          s"ko-agent-egress-proxy-$id-1a2b3c4d",
          "ko-agent-sandbox-run-mine",
        ),
      ),
      Seq(s"ko-agent-sandbox-run-$id-1a2b3c4d"),
    )
    assertEquals(
      persistentVolumes(
        Seq(
          s"ko-agent-sandbox-persistent-$id",
          "ko-agent-sandbox-persistent-backup",
          "my-shared-volume",
        ),
      ),
      Seq(s"ko-agent-sandbox-persistent-$id"),
    )
    assertEquals(
      launcherNetworks(
        Seq(
          s"ko-agent-sandbox-$id-1a2b3c4d",
          s"ko-agent-egress-$id-1a2b3c4d",
          "ko-agent-sandbox-mynet",
          "podman",
          "bridge",
        ),
      ),
      Seq(s"ko-agent-sandbox-$id-1a2b3c4d", s"ko-agent-egress-$id-1a2b3c4d"),
    )

  test("a shared volume name inside the reserved shape is refused, ordinary names are not"):
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
      "ko-agent-sandbox-app-0123456789ab-1a2b3c4d",
    )
    assertEquals(
      egressRunNetwork("app-0123456789ab", "1a2b3c4d"),
      "ko-agent-egress-app-0123456789ab-1a2b3c4d",
    )
    // The reset filters must sweep each through its own filter and never through the other's.
    assertEquals(proxyContainers(Seq(sandbox, proxy)), Seq(proxy))
    assertEquals(sandboxRunContainers(Seq(sandbox, proxy)), Seq(sandbox))

  test("TZ is a tzdata name or a POSIX offset, whose sign is the reverse of ISO's"):
    assertEquals(posixTz(ZoneId.of("Asia/Tokyo")), "Asia/Tokyo")
    assertEquals(posixTz(ZoneId.of("America/St_Johns")), "America/St_Johns")
    assertEquals(posixTz(ZoneId.of("UTC")), "UTC")
    assertEquals(posixTz(ZoneId.of("Z")), "UTC")
    assertEquals(posixTz(ZoneId.of("GMT+09:00")), "UTC-9")
    assertEquals(posixTz(ZoneId.of("UTC-03:30")), "UTC+3:30")
    assertEquals(posixTz(ZoneId.of("+05:45")), "UTC-5:45")
    assertEquals(posixTz(ZoneId.of("+05:45:30")), "UTC-5:45")
    assertEquals(posixTz(ZoneId.of("-00:00:30")), "UTC")
