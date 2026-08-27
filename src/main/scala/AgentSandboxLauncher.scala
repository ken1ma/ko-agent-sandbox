// Run Claude Code, Codex, Antigravity, or Copilot CLI inside a rootless Podman container.
//
// One launcher for Linux, macOS, WSL and native Windows. This file is the policy, the flags, and the flow; the
// threat model is SECURITY.md. Its neighbours, each the whole blast radius of one thing:
//
//   HostCommands.scala          running a host executable, and the platform tag — the bottom layer
//   LauncherImages.scala        the images this launcher owns: names, identity, inventory, cleanup
//   ContainerfileSources.scala  the remote images the bundled Containerfiles name, for the refresh
//   SandboxLifecycle.scala      the handover to podman, and both paths that remove a run's proxy
//   EgressProxyPolicy.scala     this project's egress policy, its resolution, and the audit log
//   KoAgentFs.scala             the workspace FUSE filter: build, install, identity, mount lifecycle
//   SandboxProject.scala        the project directory: real path, refusals, identity, mount guards
//   BouncyCastleHelper.scala    building certificates and PEM — the only file importing bouncycastle
//   JdkTrust.scala              making JVMs trust the inspection CA — locate, merge, mount
//   FFMHelper.scala             the execvp downcall
//
// This file is the canonical description of what the boundary is made of:
//
//   Host
//    |
//    +-- current project -------------------> /workspace
//    |     (--write selects the mount: live — the default — is the
//    |      ko-agent-fs mountpoint, RW with git and policy control
//    |      state frozen (ensureKoAgentFsMounted; the .git pins of
//    |      gitGuardVolumes are the opted-out fallback); reject is a
//    |      read-only bind of the raw tree)
//    |
//    +-- .ko-agent-sandbox: the egress policy, read on the host; the
//    |      write mode is what keeps a session from writing the next
//    |      one's — only the pin fallback still mounts it back RO
//    |      (policyGuardVolume)
//    |
//    +-- Podman named volume -----------> ~/persistent-volume RW/persistent
//    |                                       (~/.claude, ~/.codex, ~/.gemini,
//    |                                        ~/.copilot are symlinks into it)
//    |
//    X-- ~/.ssh                             NOT EXPOSED
//    X-- ~/.aws                             NOT EXPOSED
//    X-- ~/.config                          NOT EXPOSED
//    X-- Podman/Docker socket               NOT EXPOSED
//    X-- rest of host filesystem            NOT EXPOSED
//
//   Internet
//    |
//    +-- egress proxy ------------------> the hosts --egress=<profile> admits, CONNECT :443 only
//    |                                       (EgressProxyPolicy.scala; the flags are below)
//    |                                    restricted hosts TLS-inspected read-only;
//    |                                       git hosts additionally refuse git push
//    X-- everything else                    NO ROUTE
//
// The rest of /home/nonroot is an anonymous Podman volume: build caches work, and disappear with the container.
//
// The image pre-accepts Claude Code's trust dialog for /workspace and marks it trusted for Codex and Copilot, so a
// mounted project's own agent configuration — MCP servers included — takes effect unconfirmed. The container, not
// those dialogs, is the boundary; whatever they name runs inside it, never in a host-side helper.
//
// Podman arguments are NOT accepted: podman merges rather than replaces
// most flags, so a caller-supplied --volume or --cap-add could silently
// reopen the boundary. The launcher parses only its authority options and
// management verbs (parseCommandLine); the first non-option is the command,
// and from there everything is forwarded verbatim to the container.

package agentsandbox.launcher

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, Paths, StandardCopyOption}
import java.nio.file.attribute.PosixFilePermissions
import java.time.{Instant, ZoneId, ZoneOffset}
import java.time.format.DateTimeFormatter
import scala.jdk.CollectionConverters.*

import BouncyCastleHelper.*
import ContainerfileSources.*
import JdkTrust.*
import EgressProxyPolicy.*
import HostCommands.*
import KoAgentFs.*
import LauncherImages.*
import SandboxProject.*
import SandboxLifecycle.*

object AgentSandboxLauncher:

  // Must agree with the UID/GID created in the Containerfile.
  val ContainerUid = 65532
  val ContainerGid = 65532

  // A month before expiry, so no session starts on a certificate that expires mid-run.
  val ReissueMarginSeconds = 2592000L

  // -------------------------------------------------------------------------
  // Run resource names and reset filters
  //
  // Pure, and unit-tested: what this run's containers and networks are
  // called, and which podman objects the resets may touch. The project's own
  // identity and guards are SandboxProject.scala.
  // -------------------------------------------------------------------------

  /**
   * Whether a container runtime may run inside the sandbox: `none` — the default, what an unset
   * variable means — or `same-uid`, which buys the three loosenings below for the whole session,
   * the cost SECURITY.md's "No containers inside the sandbox by default" section prices. `unmask=ALL`
   * because a nested pid namespace must mount a fresh /proc, and the kernel refuses that while
   * the masked entries sit on it (measured: EPERM from a bare unshare with the masks in
   * place, SELinux permitting the mount and SYS_CHROOT granted);
   * label=disable because that mount is denied for plain container_t (EACCES, reproduced by
   * bare unshare with no runtime involved), and the narrower candidate — container_engine_t,
   * container-selinux's type for containers that run containers — permits the mount but cannot
   * exec the `--init` podman injects (measured: "exec /run/podman-init: Permission denied" at
   * session start), so any future candidate must be probed with --init in the run;
   * SYS_CHROOT because layer unpack
   * chroots, and the seccomp profile compiled for a no-capability container answers chroot with
   * EPERM even for root in a nested user namespace (the measured failure is every pull's "after
   * fallback to chroot: operation not permitted") — inner podman 6.0.2 behaves identically to
   * the 5.4.2 the recipe installs: the vendored unpack is the same code, and the deciding
   * filter is this outer container's. /dev/fuse is deliberately absent: nested
   * storage runs on kernel-native overlay in the user namespace — measured, the container rootfs
   * mounts as `overlay` and the matrix passes with the fuse-overlayfs binary removed.
   * The resolved mode is always set in the session's environment — `none` included — so an
   * agent reads one variable with one spelling instead of also handling unset.
   *
   * What is deliberately NOT loosened names the value: no-new-privileges stays, which blocks
   * setuid newuidmap, so a nested runtime maps only the uid this session already runs as —
   * images that switch USER or chown to a second uid fail by design, this repository's own among
   * them.
   */
  val NestingVariable = "KO_AGENT_SANDBOX_NESTING"
  val NestingLoosenings =
    Vector("--security-opt=unmask=ALL", "--security-opt=label=disable", "--cap-add=SYS_CHROOT")

  def nestingMode(value: Option[String]): Either[String, String] =
    closedChoice(
      NestingVariable,
      value,
      Vector("none", "same-uid"),
      "none",
      "Unset it (or set it to none) to allow no runtime; set it to same-uid to unmask\n/proc, " +
        "disable SELinux labeling and add SYS_CHROOT so a container runtime installed\nin the " +
        "session can run (SECURITY.md).",
    )

  /**
   * How the sandbox addresses the proxy: a name `--add-host` puts in /etc/hosts, so no resolver is
   * involved, and the port the proxy listens on. Named apart rather than only spelled into a URL,
   * because a JVM wants them as two properties rather than one (JdkTrust.jdkProxyMount).
   */
  val EgressProxyHost = "egress-proxy"
  val EgressProxyPort = 3128

  /**
   * Everything a launch prints — which guard this session runs under, the egress policy, every
   * warning — is on screen for as long as it takes the agent to start, and claude's fullscreen TUI
   * and codex both clear the screen as they do. So a hold stands between the last of those lines
   * and the handover: the terminal stays the reader's until they release it. `immediate` prints the
   * same lines and starts the agent at once, for whoever has read them enough times; with no
   * terminal there is nothing to hold.
   */
  val SessionStartVariable = "KO_AGENT_SANDBOX_SESSION_START"

  /**
   * Whether the host clipboard is offered to the sandbox (ClipboardBroker). Off by default, and
   * `paste` before `bidirectional`, because each step hands the agent more of the host: reading
   * what the user last copied, then writing what the user will next paste.
   */
  val ClipboardVariable = "KO_AGENT_SANDBOX_CLIPBOARD"

  def clipboardMode(value: Option[String]): Either[String, String] =
    closedChoice(
      ClipboardVariable,
      value,
      Vector("off", "paste", "bidirectional"),
      "off",
      "Unset it (or set it to off) to keep the clipboard out; set it to paste to let the\nagent " +
        "read an image you copied, or to bidirectional to also let it set your clipboard\n" +
        "(SECURITY.md).",
    )

  def sessionStart(value: Option[String]): Either[String, String] =
    closedChoice(
      SessionStartVariable,
      value,
      Vector("pause", "immediate"),
      "pause",
      "Unset it (or set it to pause) to keep the hold; set it to immediate to start the\nagent " +
        "at once, leaving what the launch printed to be read from the scrollback afterwards.",
    )

  /**
   * The command names what is about to take the screen, so the prompt says what it is waiting on.
   * isTerminal, not a null check: since JDK 22 System.console() answers a Console for a redirected
   * stream too, and holding a pipe open would hang a scripted launch instead of skipping the hold.
   */
  def holdForReader(mode: String, command: String): Unit =
    val console = System.console()
    if mode == "pause" && console != null && console.isTerminal then
      console.printf("%nPress Enter to start %s ", command)
      console.readLine()

  /** Below this a JVM build in the sandbox does not fit; the launch says so once. */
  val SmallMachineMemory: Long = 4L << 30

  /** `podman info --format '{{.Host.MemTotal}}'`, bytes; None when podman did not answer with one. */
  def memoryTotal(answer: HostCommands.Run): Option[Long] =
    if !answer.ok then None else answer.text.trim.toLongOption.filter(_ > 0)

  /**
   * The sandbox's default memory ceiling: 1 GiB under the total of the machine podman runs on —
   * the podman machine VM, or the host on native Linux — which is what podman, the workspace
   * filter and the kernel need to keep answering while the sandbox is at its limit; and never
   * below half the total, so a small machine still gets a sandbox that can build.
   */
  def memoryCeiling(machineTotal: Long): Long =
    Math.max(machineTotal - (1L << 30), machineTotal / 2)

  /**
   * `--memory-swap` equal to `--memory` forbids swap: it is the thrash a ceiling exists to
   * prevent, and podman's default of twice the memory in swap is the wrong side of that. An
   * explicit ceiling gets the same treatment, for the same reason.
   */
  def memoryArguments(explicit: Option[String], machineTotal: Option[Long]): Vector[String] =
    explicit.map(_.trim).filter(_.nonEmpty) match
      case Some(value) => Vector(s"--memory=$value", s"--memory-swap=$value")
      case None =>
        machineTotal.map(memoryCeiling).toVector.flatMap: bytes =>
          Vector(s"--memory=$bytes", s"--memory-swap=$bytes")

  def gib(bytes: Long): String = f"${bytes.toDouble / (1L << 30)}%.1f GiB"

  /**
   * The KO_AGENT_SANDBOX_* names this launcher reads — plus KO_AGENT_SANDBOX_EGRESS_POLICY, which
   * it sets inside the sandbox rather than reads, so a launcher nested in a sandbox session is not
   * warned about the variable that session legitimately carries.
   */
  val KnownSandboxVariables: Set[String] = Set(
    "KO_AGENT_SANDBOX_IMAGE",
    "KO_AGENT_SANDBOX_PROXY_IMAGE",
    "KO_AGENT_SANDBOX_PERSISTENT_VOLUME",
    "KO_AGENT_SANDBOX_MEMORY",
    WorkspaceGuardVariable,
    NestingVariable,
    SessionStartVariable,
    ClipboardVariable,
    "KO_AGENT_SANDBOX_EGRESS_POLICY",
  )

  /**
   * Environment names that look like this launcher's but are not: almost certainly a misspelling
   * of one above, and a misspelled variable silently configuring nothing — no memory ceiling, the
   * wrong volume — is the failure mode the warning in main closes. A warning rather than a refused
   * launch, because a shell profile legitimately carries variables for a newer or older launcher.
   */
  def unknownSandboxVariables(names: Iterable[String]): Vector[String] =
    names.toVector
      .filter(_.startsWith("KO_AGENT_SANDBOX_"))
      .filterNot(KnownSandboxVariables)
      .sorted

  /**
   * The proxy's address on one named network, out of the per-network listing
   * the Go template below prints as `<network> <ip>` lines.
   */
  def addressOn(networksOutput: String, network: String): Option[String] =
    networksOutput.linesIterator
      .find(_.startsWith(network + " "))
      .map(_.drop(network.length + 1).trim)
      .filter(_.nonEmpty)

  /**
   * The sandbox container's name: what the reaper waits on. The suffix
   * keeps concurrent sandboxes in one project distinct.
   */
  def sandboxRunContainer(projectId: String, suffix: String): String =
    s"ko-agent-sandbox-run-$projectId-$suffix"

  /**
   * The proxy container's name, sharing the sandbox's run suffix: each run
   * gets its own proxy, removed with its sandbox — SandboxLifecycle.scala has the
   * why.
   */
  def proxyRunContainer(projectId: String, suffix: String): String =
    s"ko-agent-egress-proxy-$projectId-$suffix"

  /**
   * This run's internal network — the one the sandbox joins, with no
   * gateway. Per run like the proxy; createNetwork has why nothing is
   * reused.
   */
  def sandboxRunNetwork(projectId: String, suffix: String): String =
    s"ko-agent-sandbox-$projectId-$suffix"

  /** This run's outbound network — the proxy's route out. Per run, as above. */
  def egressRunNetwork(projectId: String, suffix: String): String =
    s"ko-agent-egress-$projectId-$suffix"

  /** This run's disambiguator: always exactly eight hex characters, which
    * is what lets isRunNamed anchor on it. */
  def newRunSuffix(): String =
    java.util.UUID.randomUUID().toString.take(8)

  /**
   * Whether `name` is `builder(projectId, <run suffix>)` — the anchored
   * form of a bare prefix check. The anchor matters because hex is
   * slug-legal and a slug may be 32 characters: a directory literally named
   * after another project's id yields resources that extend this project's
   * prefix, and a --reset here would end that project's live sessions.
   * With the suffix anchored, a name matches exactly one project. Taking
   * the builder keeps the name shape stated once, in the builders above.
   */
  def isRunNamed(builder: (String, String) => String, projectId: String)(name: String): Boolean =
    val prefix = builder(projectId, "")
    name.length == prefix.length + 8 &&
      name.startsWith(prefix) &&
      name.drop(prefix.length).forall(ch => (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))

  /**
   * The gate every podman-talking verb runs first: a client that runs, and a service that
   * answers. On macOS and Windows the service is the podman machine, started here when stopped —
   * never created or resized, the boundary SECURITY.md draws ("Silent changes to what you own") —
   * so `machine init` stays the one manual step of a fresh install: the next verb, usually
   * --build, brings the machine up itself.
   */
  def requirePodman(os: Os): Unit =
    if !runOk(podman, "--version") then
      fail(
        s"""error: $podman does not run
           |
           |Reinstall it: https://podman.io/docs/installation""".stripMargin,
        127,
      )
    if !runOk(podman, "info") then
      os match
        case Os.Linux =>
          fail(
            "error: Podman is not usable.\nOn Linux, run rootless Podman as your normal user, without sudo.",
          )
        case _ =>
          System.err.println("the podman machine is not running; starting it")
          val started = run(podman, "machine", "start")
          if !started.ok then
            fail(
              s"""error: Podman Machine could not be started.
                 |${started.err}
                 |
                 |Initialize it once, for example:
                 |  podman machine init""".stripMargin
            )

  /**
   * The build context is bundled into the jar (build.sbt) so --build works
   * with no checkout present; unpacked to a temp directory, removed by
   * runBuilds on success.
   *
   * A new directory every time, and Files.copy carries no mtime over from the
   * jar entry, so every file reaches podman freshly stamped. ko-agent-fs's
   * Containerfile leans on that: it is what stops a warm cargo cache from
   * reusing a build with an older source id compiled into it.
   */
  private def bundleResource(name: String): Array[Byte] =
    val stream = getClass.getResourceAsStream(s"/sandbox-build/$name")
    if stream == null then
      fail(
        s"""error: the launcher jar has no bundled build-context entry '$name'
           |
           |Rebuild the launcher: sbt dist, from the repository root""".stripMargin
      )
    try stream.readAllBytes()
    finally stream.close()

  private def bundleIndex(): Vector[String] =
    String(bundleResource("INDEX"), StandardCharsets.UTF_8).linesIterator.filter(_.nonEmpty).toVector

  def unpackBuildContext(): Path =
    val root = Files.createTempDirectory("ko-agent-sandbox-build")

    bundleIndex().foreach: relative =>
      val target = root.resolve(relative)
      Files.createDirectories(target.getParent)
      Files.write(target, bundleResource(relative))

    System.err.println(s"build context: $root")
    root

  /**
   * The version-lock verdict for one built image: None when its label
   * carries the jar's own digest of that image's bundled sources. The only
   * way a default-named image exists is --build, so a mismatch means a jar
   * other than this one built it — launch refuses it. An explicitly overridden
   * KO_AGENT_SANDBOX_*_IMAGE only warns: a custom image is a supported
   * case, and its interface drift still fails closed at runtime (the
   * --print-policy parse, the leaf's exact names).
   *
   * "container image", spelled out: the reader of this message is upgrading
   * the launcher, not thinking about images at all, and the bare name reads
   * as noise until the mechanism is named.
   *
   * Both digests are printed because the mismatch alone cannot say which
   * side is stale — an old image, or a launch through a different jar than
   * the one that ran --build.
   */
  def bundleMismatch(image: String, expected: String, label: String): Option[String] =
    Option.when(label.trim != expected)(
      s"container image $image was not built from the sources this launcher bundles" +
        (if label.trim.isEmpty then " (it carries no bundle label)" else "") +
        "; rebuild with --build" +
        s"\n  launcher bundle digest: $expected" +
        s"\n  image label $BundleLabel: " +
        (if label.trim.isEmpty then "(none)" else label.trim),
    )

  /**
   * The five product images and both named build caches, in dependency order. Leaf images stay on
   * `latest`: a
   * rebuild there picks up new agent releases, which the base version says
   * nothing about; the base is an image label instead. debian-temurin does
   * not consume IMG_TAG_VER, and neither does ko-agent-fs — it builds on
   * rust:slim with its own pins, and its identity is the source digest.
   *
   * Each multi-stage compile stage is built first under a stable cache tag. The final build reuses
   * its ordinary local layer cache; naming the stage keeps one current cache image and lets the
   * successful build remove the previous one by the same exact-id rule as every final image.
   *
   * The bundle id travels twice: as BUNDLE_ID for the Containerfile's LABEL
   * (what a hand-run `podman build` from a checkout uses) and as `--label`
   * on the command line, which wins. The duplication is deliberate: podman's
   * layer cache does not key ARG-derived config instructions on the arg's
   * value (buildah #5501, #5095), so a cached LABEL step can commit a stale
   * digest; a command-line --label is applied at commit, outside that cache.
   * --build still verifies the committed label (verifyBuiltBundleLabels).
   */
  def buildCommands(
    podman: String,
    version: String,
    fsSourceId: String,
    sandboxBundleId: String,
    proxyBundleId: String,
  ): Vector[Vector[String]] =
    Vector(
      Vector(podman, "build", "-t", s"debian-temurin:$version", "debian-temurin"),
      Vector(
        podman, "build", "--build-arg", s"IMG_TAG_VER=$version",
        "-t", s"debian-coursier:$version", "debian-coursier",
      ),
      Vector(
        podman, "build", "--build-arg", s"IMG_TAG_VER=$version",
        "--build-arg", s"BUNDLE_ID=$sandboxBundleId",
        "--label", s"$BundleLabel=$sandboxBundleId",
        "-t", "ko-agent-sandbox:latest", "ko-agent-sandbox",
      ),
      Vector(
        podman, "build", "--target", "build", "--build-arg", s"IMG_TAG_VER=$version",
        "-t", ProxyBuildImage, "ko-agent-egress-proxy",
      ),
      Vector(
        podman, "build", "--build-arg", s"IMG_TAG_VER=$version",
        "--build-arg", s"BUNDLE_ID=$proxyBundleId",
        "--label", s"$BundleLabel=$proxyBundleId",
        "-t", "ko-agent-egress-proxy:latest", "ko-agent-egress-proxy",
      ),
      Vector(
        podman, "build", "--target", "build",
        "--build-arg", s"KO_AGENT_FS_SOURCE_ID=$fsSourceId",
        "-t", KoAgentFsBuildImage, "ko-agent-fs",
      ),
      Vector(
        podman, "build", "--build-arg", s"KO_AGENT_FS_SOURCE_ID=$fsSourceId",
        "-t", "ko-agent-fs:latest", "ko-agent-fs",
      ),
    )

  /**
   * The toolchain the filter ships, read from the image build that pins it rather than repeated
   * here. A second copy of the version is a self-test image that quietly stops exercising the
   * compiler that ships, and nothing else would notice — the same rule `probe/rig.sh` follows.
   */
  def pinnedRustVersion(context: Path): String =
    val containerfile = context.resolve("ko-agent-fs").resolve("Containerfile")
    val pinned = Files
      .readAllLines(containerfile)
      .asScala
      .collectFirst:
        case line if line.startsWith("ARG RUST_VERSION=") => line.stripPrefix("ARG RUST_VERSION=").trim
    pinned.filter(_.nonEmpty).getOrElse(
      fail(s"error: no 'ARG RUST_VERSION=' in $containerfile; there is no toolchain to build with"),
    )

  /**
   * `--self-test`'s image: the crate's suites compiled against the pinned toolchain, on top of the
   * sandbox image. Built on demand rather than by --build, so a user who only wants to run agents
   * never compiles a test suite; a rebuild is a cache hit whenever the bundled sources and remote
   * Rust image are unchanged (`fuse/ko-agent-fs/doc/testing.md`).
   *
   * `-f` with `.` as the context, not the directory: the crate this compiles lives beside the
   * Containerfile in the unpacked bundle, not under it.
   */
  def selfTestBuildCommands(
    podman: String,
    rustVersion: String,
    fsSourceId: String,
    selfTestBundleId: String,
  ): Vector[Vector[String]] =
    Vector(
      Vector(
        podman, "build", "--target", "build",
        "--build-arg", s"RUST_VERSION=$rustVersion",
        "--build-arg", s"KO_AGENT_FS_SOURCE_ID=$fsSourceId",
        "--label", s"$BundleLabel=$selfTestBundleId",
        "-f", "ko-agent-self-test/Containerfile",
        "-t", SelfTestBuildImage, ".",
      ),
      Vector(
        podman, "build",
        "--build-arg", s"RUST_VERSION=$rustVersion",
        "--build-arg", s"KO_AGENT_FS_SOURCE_ID=$fsSourceId",
        "--label", s"$BundleLabel=$selfTestBundleId",
        "-f", "ko-agent-self-test/Containerfile",
        "-t", "ko-agent-self-test:latest", ".",
      ),
    )

  /**
   * The verification container. Nothing is bound in or written out: the suites build their own
   * trees under the container's /tmp, and `--rm` takes the container with it. Image building and
   * replacement cleanup belong to selfTest, not this command.
   *
   * `--cap-add SYS_ADMIN` is the one place this project runs a container with more than a session
   * gets, and it is never a session's container. It is not redundant with the setuid fusermount3
   * the image installs: a setuid binary does not escape the container's capability bounding set,
   * measured rather than assumed (`fuse/ko-agent-fs/doc/verification-log.md`).
   *
   * `--network=none` because no case reaches a host, and nothing is fetched at this point.
   */
  def selfTestRunCommand(podman: String, filter: Option[String], asRoot: Boolean): Vector[String] =
    Vector(podman, "run", "--rm", "--pull=never", "--network=none", "--device", "/dev/fuse",
      "--cap-add", "SYS_ADMIN")
      ++ (if asRoot then Vector("--user", "0") else Vector.empty)
      ++ Vector("ko-agent-self-test:latest")
      ++ filter.toVector

  /**
   * The exit code for a self-test that failed before its behavioural checks began, as against one
   * of those checks failing. The filter's own `--self-test` decides which, being the only party
   * that knows the stage it reached, and run-suite passes the verdict up; its message says what it
   * can about the cause, which this launcher repeats and does not sharpen
   * (fuse/ko-agent-fs/src/main.rs, SelfTestFailure). Spelled there as SELF_TEST_VENUE_EXIT, and a
   * test holds the two together.
   */
  val SelfTestVenueExit = 3

  /**
   * `--no-cache`: new agent releases arrive through RUN steps whose inputs
   * look unchanged to the cache. Base images and the proxy are --build's.
   */
  def updateCommands(podman: String, version: String, sandboxBundleId: String): Vector[Vector[String]] =
    Vector(
      Vector(
        podman, "build", "--no-cache", "--build-arg", s"IMG_TAG_VER=$version",
        "--build-arg", s"BUNDLE_ID=$sandboxBundleId",
        "--label", s"$BundleLabel=$sandboxBundleId",
        "-t", "ko-agent-sandbox:latest", "ko-agent-sandbox",
      ),
    )

  /**
   * A build's check of what it just stamped, immediately after committing the images:
   * the layer-cache staleness above is exactly the kind of silent drift the
   * version lock exists for, so the freshly committed labels are read back
   * rather than assumed. A failure here is podman misbehaving, not a wrong
   * jar — the remediation is clearing the build cache, not --build again.
   */
  def verifyBuiltBundleLabels(expected: Seq[(String, String)]): Unit =
    expected.foreach: (image, id) =>
      val inspected = run(
        podman, "image", "inspect", "--format", BundleLabelTemplate, image,
      )
      if !inspected.ok then
        fail(s"error: could not inspect the just-built image $image\n${inspected.err}")
      if inspected.text.trim != id then
        fail(
          s"""error: the image build committed $image with a stale bundle label
             |  launcher bundle digest: $id
             |  image label $BundleLabel: ${
                if inspected.text.trim.isEmpty then "(none)" else inspected.text.trim}
             |
             |podman's layer cache can serve a LABEL derived from a changed
             |build arg stale (buildah #5501); this launcher passes --label to
             |bypass that cache, so this failing means podman dropped --label
             |too. Remove $image, then rerun the same launcher verb.""".stripMargin
        )

  def runBuilds(context: Path, commands: Vector[Vector[String]]): Unit =
    commands.foreach: command =>
      System.err.println(command.mkString(" "))
      val exit = ProcessBuilder(command*)
        .directory(context.toFile)
        .inheritIO()
        .start()
        .waitFor()
      if exit != 0 then
        if command.lift(1).contains("pull") then
          deleteRecursively(context)
          fail(s"error: image refresh failed: ${command.mkString(" ")}", exit)
        else
          fail(
            s"error: build failed: ${command.mkString(" ")}\n" +
              s"build context retained at $context",
            exit,
          )
    deleteRecursively(context)

  private def buildContextReader(context: Path): String => String =
    relative => Files.readString(context.resolve(relative))

  /** The output tags committed by build commands, in their dependency order. */
  def buildOutputImages(commands: Vector[Vector[String]]): Vector[String] =
    commands.flatMap: command =>
      command.sliding(2).collectFirst:
        case Seq("-t", image) => image

  /**
   * Image tags are workstation-wide, so every image-producing verb shares one lock and journal.
   * The journal is written before the first build: if the process dies after a tag moves, the next
   * invocation still knows the exact old id. A global lock keeps two launcher versions from
   * retagging `latest` around each other's snapshots.
   */
  def withImageBuildLock[A](os: Os)(body: Path => A): A =
    requireStateRootOutside(os, workingDirectory())
    val imageState = stateRoot(os).resolve("image-build")
    withFileLock(imageState.resolve("lock")):
      body(imageState.resolve("cleanup.ids"))

  /**
   * The generated tail every launcher-made name carries: the folded directory slug, the
   * twelve-hex path hash (SandboxProject.projectIdOf), and — for per-run resources — the
   * eight-hex run suffix. `--reset-all` matches whole names against these shapes rather than
   * bare prefixes: it force-removes what it matches, and a prefix alone would also take a
   * user's own `ko-agent-sandbox-persistent-backup`. A shape is not provenance, so the shapes
   * are a reserved namespace, stated as such in SECURITY.md ("Silent changes to what you own"):
   * an object hand-named inside one is removed like the launcher's own, and the one
   * launcher-adopted name — the shared volume — is refused when it strays into it
   * (sharedVolumeNameError).
   */
  private val ProjectIdShape = "[A-Za-z0-9._-]{1,32}-[0-9a-f]{12}"
  private val RunShape = s"$ProjectIdShape-[0-9a-f]{8}"

  /**
   * Why `name` may not serve as the shared agent-state volume, or None. The generated volume
   * shape is `--reset-all`'s to remove by name, so adopting a user-supplied name inside it
   * would hand that sweep a volume it must not own — including another project's real volume,
   * spelled out to alias its sign-ins. Refused at launch, where the volume would be created and
   * used, rather than discovered at the reset that deletes it.
   */
  def sharedVolumeNameError(name: String): Option[String] =
    Option.when(name.matches(s"ko-agent-sandbox-persistent-$ProjectIdShape"))(
      s"KO_AGENT_SANDBOX_PERSISTENT_VOLUME is '$name', which has the launcher's generated " +
        "volume-name shape, and --reset-all removes every volume matching it\n\n" +
        "Choose a name outside ko-agent-sandbox-persistent-<slug>-<12 hex>.",
    )

  def proxyContainers(names: Seq[String]): Seq[String] =
    names.filter(_.matches(s"ko-agent-egress-proxy-$RunShape"))

  /**
   * Run containers are --rm and normally remove themselves; one survives
   * only when its launcher died between create and start and its reaper
   * failed too. This filter is the resets' belt-and-braces sweep, not the
   * primary cleanup.
   */
  def sandboxRunContainers(names: Seq[String]): Seq[String] =
    names.filter(_.matches(s"ko-agent-sandbox-run-$RunShape"))

  /**
   * Volumes named through KO_AGENT_SANDBOX_PERSISTENT_VOLUME are deliberately left alone — and
   * cannot sit inside this shape, because such a value refuses the launch (sharedVolumeNameError).
   */
  def persistentVolumes(names: Seq[String]): Seq[String] =
    names.filter(_.matches(s"ko-agent-sandbox-persistent-$ProjectIdShape"))

  /** Both per-run network families, for `--reset-all`. */
  def launcherNetworks(names: Seq[String]): Seq[String] =
    names.filter: name =>
      name.matches(s"ko-agent-sandbox-$RunShape") || name.matches(s"ko-agent-egress-$RunShape")

  /**
   * The per-run TLS mount-source directories a launch may sweep: named for a run (`run-<8 hex>`),
   * not live, and past the launch bound — a launch makes its copies before its proxy container
   * exists, so inside that window a live launch has no run for the listing to find, and removing
   * its copies would fail the `podman start` that mounts them. The reaper deliberately does not
   * remove these (its argument surface stays fixed); the next launch's sweep and the resets do.
   */
  def tlsRunDirsToPrune(
    names: Seq[String],
    liveRuns: Set[String],
    oldEnough: String => Boolean,
  ): Seq[String] =
    names
      .filter(_.matches("run-[0-9a-f]{8}"))
      .filterNot(name => liveRuns.contains(name.stripPrefix("run-")))
      .filter(oldEnough)

  /** Past the same ten-minute bound the reaper and the marker prune use; false on any doubt. */
  def olderThanLaunchBound(path: Path): Boolean =
    try
      Files
        .getLastModifiedTime(path)
        .toInstant
        .isBefore(Instant.now().minusSeconds(600))
    catch case _: java.io.IOException => false

  /**
   * This project's networks out of `podman network ls`: the per-run names carry a run suffix after the project id.
   */
  def projectNetworks(names: Seq[String], projectId: String): Seq[String] =
    names.filter: name =>
      isRunNamed(sandboxRunNetwork, projectId)(name)
        || isRunNamed(egressRunNetwork, projectId)(name)

  /**
   * Creation is the whole story: the name carries a random run suffix, so
   * nothing can already carry it, nothing is ever reused, and no
   * pre-existing object's properties need vetting before the boundary rests
   * on them. A creation failure is a failed launch, stated with podman's
   * own reason.
   */
  def createNetwork(network: String, internal: Boolean): Unit =
    val created =
      if internal then run(podman, "network", "create", "--internal", network)
      else run(podman, "network", "create", network)
    if !created.ok then
      fail(s"error: could not create the network $network\n${created.err}")

  /**
   * `--self-test`: build the self-test image if it is not already current, then run the crate's
   * suites in it (`fuse/ko-agent-fs/doc/testing.md`). Two runs against the same remote Rust image
   * give the same verdict and leave the same state — the image build is a cache hit, the container
   * is `--rm`, and nothing is bound in.
   *
   * The sandbox image is a precondition rather than something to build here: verifying is not the
   * command that decides which agent image a user runs.
   *
   * An unprivileged uid mounting through the setuid `fusermount3` is the route a session takes,
   * and the image runs as its `nonroot` user for exactly that reason. A venue where that cannot
   * work is retried once as root, so the run reports which of the two served rather than guessing.
   * What made the venue unusable is the filter's to report and this launcher's to pass on
   * unchanged; only a venue failure reaches here, because a failed check exits with its own status.
   */
  def selfTest(os: Os, operands: List[String]): Nothing =
    if operands.sizeIs > 1 then
      fail("error: --self-test takes at most one operand, a test-name filter")
    val filter = operands.headOption.filter(_.nonEmpty)

    if !runOk(podman, "image", "exists", "ko-agent-sandbox:latest") then
      fail(
        """error: the sandbox image is not built, and --self-test does not build it
          |
          |Run --build first; --self-test then layers its suites on top of it.""".stripMargin
    )

    withImageBuildLock(os): journal =>
      val context = unpackBuildContext()
      val readContainerfile = buildContextReader(context)
      val existingTags = existingImageTags(podman)
      val sandboxImageId = requiredImageId(existingTags, "ko-agent-sandbox:latest", "self-test did not start")
      val fsSourceId = koAgentFsSourceId(context)
      val rustVersion = pinnedRustVersion(context)
      val bundleId = selfTestBundleId(
        fsSourceId,
        contextSourceId(context, "ko-agent-self-test"),
        sandboxImageId,
      )
      val commands = selfTestBuildCommands(
        podman,
        rustVersion,
        fsSourceId,
        bundleId,
      )
      val remoteImages =
        remoteImagesForBuildCommands(commands, readContainerfile, managedImageTags(ImgTagVersion).toSet)
      val images = buildOutputImages(commands)
      val candidates = prepareImageCleanupJournal(
        journal,
        imageIdsForTags(existingTags, images),
        Vector.empty,
      )
      runBuilds(context, remoteImagePullCommands(podman, remoteImages) ++ commands)
      verifyBuiltBundleLabels(SelfTestImageTags.map(_ -> bundleId))
      val remaining = removeSupersededImages(
        podman,
        candidates,
        managedImageTags(ImgTagVersion),
        Vector.empty,
      )
      writeImageCleanupJournal(journal, remaining)

    System.err.println(s"venue: ${os.toString.toLowerCase(java.util.Locale.ROOT)}, ${podmanVersion()}")
    val unprivileged = selfTestRunCommand(podman, filter, asRoot = false)
    System.err.println(unprivileged.mkString(" "))
    val exit = ProcessBuilder(unprivileged*).inheritIO().start().waitFor()
    if exit != SelfTestVenueExit then sys.exit(exit)

    System.err.println(
      "note: the filter's self-test failed at the venue rather than at a check; retrying as\n" +
        "root. Its own message above is the report of what failed, and this launcher does not\n" +
        "narrow it further. If root serves, this venue never exercises the setuid fusermount3\n" +
        "route a session takes, which is worth recording with its venue\n" +
        "(fuse/ko-agent-fs/doc/verification-log.md).",
    )
    val privileged = selfTestRunCommand(podman, filter, asRoot = true)
    System.err.println(privileged.mkString(" "))
    sys.exit(ProcessBuilder(privileged*).inheritIO().start().waitFor())

  /** The podman build the venue record names, so a run is evidence rather than an outcome. */
  def podmanVersion(): String =
    val reported = run(podman, "--version")
    if reported.ok then reported.text.trim else "podman version unknown"

  /** A command that is printed before it runs; returns false on failure. */
  def stepOk(command: String*): Boolean =
    System.err.println(command.mkString(" "))
    ProcessBuilder(command*).inheritIO().start().waitFor() == 0

  /**
   * No arguments: the retained host files, oldest first — works after every
   * container is gone. With arguments: passed through to `podman logs` on
   * the running proxies, the live view of the same lines.
   */
  def proxyLog(os: Os, extra: List[String]): Nothing =
    val projectDir = resolveProjectDir()
    requireStateRootOutside(os, projectDir)
    val id = projectIdOf(projectDir, os)
    val logDir = logStateRoot(os).resolve(id)

    if extra.isEmpty then
      val files = retainedLogs(logDir)
      if files.isEmpty then fail(s"no proxy logs for this project under $logDir")
      files.foreach: file =>
        System.err.println(s"==> $file")
        Files.copy(file, System.out)
      System.out.flush()
      sys.exit(0)
    else
      requirePodman(os)
      val running = run(podman, "ps", "--format", "{{.Names}}")
      if !running.ok then
        fail(s"error: could not list the running containers\n${running.err}")
      val proxies = running.text.linesIterator
        .map(_.trim)
        .filter(isRunNamed(proxyRunContainer, id))
        .toList
      if proxies.isEmpty then
        fail(
          s"""no running egress proxy for this project; each run's proxy is
             |removed when its sandbox exits. Its retained logs are files:
             |run --proxy-log without arguments, or read $logDir""".stripMargin
        )
      val command = List(podman, "logs") ++ extra ++ proxies
      sys.exit(if stepOk(command*) then 0 else 1)

  /** The shared front half of the two egress preflights: this project's vetted policy files,
    * the provider the given command selects, and the proxy image to consult — with the
    * command-selection notes a launch would print. `operands` is the verb's optional
    * `[--] [command [arguments...]]`, accepted without launching anything. */
  private def egressPreflight(
    os: Os,
    operands: List[String],
  ): (String, String, Vector[(String, String)], Option[String]) =
    val command = operands match
      case "--" :: rest => rest
      case rest         => rest
    val projectDir = resolveProjectDir()
    requireStateRootOutside(os, projectDir)
    val projectId = projectIdOf(projectDir, os)
    val proxyImage =
      env("KO_AGENT_SANDBOX_PROXY_IMAGE").getOrElse("ko-agent-egress-proxy:latest")

    if !runOk(podman, "image", "exists", proxyImage) then
      fail(
        s"""error: egress proxy image not found: $proxyImage
           |
           |Build it first: run this launcher with --build.""".stripMargin
      )

    val policyDir = projectDir.resolve(".ko-agent-sandbox")
    policyDirError(policyDir).foreach(fail(_))
    val policyFiles = readPolicyFiles(policyDir.resolve("egress")).fold(fail(_), identity)

    val provider = commandProvider(command.headOption)
    command.headOption match
      case None       => System.err.println("egress: no command given, so no model provider is selected")
      case Some(name) if provider.isEmpty =>
        System.err.println(s"egress: '$name' is not a recognized agent command; it selects no model provider")
      case Some(_) => ()

    if policyFiles.nonEmpty then
      policyFiles.foreach: (name, text) =>
        System.err.println(s"egress policy (.ko-agent-sandbox/egress/$name): ${entriesSummary(text)}")
    else System.err.println("egress policy: no project policy files; the launcher-owned baseline")

    (projectId, proxyImage, policyFiles, provider)

  /**
   * The policy this project would apply, without a session: the same readPolicyFiles +
   * resolvedPolicy a launch uses, under the accompanying --egress=<profile>, plus per-entry
   * provenance. Data to stdout, context to stderr, so the effective lists pipe cleanly.
   */
  def egressEffective(os: Os, profile: String, operands: List[String]): Nothing =
    val (projectId, proxyImage, policyFiles, provider) = egressPreflight(os, operands)

    val resolved = resolvedPolicy(podman, proxyImage, profile, provider, policyFiles, provenance = true)
    System.out.write(resolved.out)
    System.out.flush()
    if !resolved.ok then
      fail(s"error: this project's egress policy is not valid\n${resolved.err}")
    resolved.err.linesIterator.filter(_.startsWith("warning:")).foreach(System.err.println)

    val caCert = tlsStateRoot(os).resolve(projectId).resolve("ca.crt")
    if Files.isRegularFile(caCert) then System.err.println(s"egress tls ca: $caCert")
    System.err.println(s"egress log dir: ${logStateRoot(os).resolve(projectId)}")
    sys.exit(0)

  /**
   * One host's policy decision and current resolution, through a one-shot proxy container on an
   * egress-shaped per-run network — the same image, network configuration and resolver path as
   * enforcement, never the launcher's host resolver. The resolution is reported separately from
   * the decision because a connection resolves and validates the destination again when it is
   * made.
   */
  def egressCheck(os: Os, profile: String, host: String, operands: List[String]): Nothing =
    val (projectId, proxyImage, policyFiles, provider) = egressPreflight(os, operands)

    val network = egressRunNetwork(projectId, newRunSuffix())
    createNetwork(network, internal = false)
    val checked =
      try
        run(
          (Vector(podman, "run", "--rm", "--pull=never", s"--network=$network")
            ++ policyEnvArgs(profile, provider, policyFiles)
            ++ Vector(proxyImage, "--check-host", host))*
        )
      finally
        if !runOk(podman, "network", "rm", network) then
          System.err.println(s"note: could not remove the check network $network")

    System.out.write(checked.out)
    System.out.flush()
    if !checked.ok then fail(s"error: the egress check failed\n${checked.err}")
    sys.exit(0)

  /**
   * Removes just this project's runtime state: its per-run egress proxy and
   * sandbox containers (stray or live), agent-state volume (signing
   * its agents out), sandbox-side and egress-side networks, TLS inspection
   * CA, cached policy resolution, retained proxy audit logs, and its
   * workspace-filter mount. Every other project's state and the
   * built images are left alone. `--reset-all` is the workstation-wide
   * version. Every command is printed before it runs.
   */
  def resetProject(os: Os): Nothing =
    val projectDir = resolveProjectDir()
    // Before the deletions below: a state root inside the checkout must refuse here, not aim
    // `rm -rf` at it.
    requireStateRootOutside(os, projectDir)
    val id = projectIdOf(projectDir, os)
    var failures = 0
    def remove(command: String*): Unit = if !stepOk(command*) then failures += 1

    // Everything this project's launches created, stray or live — removing a running session's containers ends that
    // session, which is what "reset" means.
    val containers = run(podman, "ps", "--all", "--format", "{{.Names}}")
    if !containers.ok then
      failures += 1
      System.err.println(containers.err)
    containers.text.linesIterator
      .map(_.trim)
      .filter: name =>
        isRunNamed(proxyRunContainer, id)(name) || isRunNamed(sandboxRunContainer, id)(name)
      .foreach(name => remove(podman, "rm", "--force", name))

    // Only the computed per-project volume; a volume shared through KO_AGENT_SANDBOX_PERSISTENT_VOLUME belongs to other
    // projects too.
    env("KO_AGENT_SANDBOX_PERSISTENT_VOLUME") match
      case Some(shared) =>
        System.err.println(s"note: leaving shared volume $shared in place")
      case None =>
        val volume = s"ko-agent-sandbox-persistent-$id"
        if runOk(podman, "volume", "exists", volume) then
          remove(podman, "volume", "rm", volume)

    // This project's per-run networks. Containers went first above, so nothing still holds them.
    val networks = run(podman, "network", "ls", "--format", "{{.Name}}")
    if !networks.ok then
      failures += 1
      System.err.println(networks.err)
    projectNetworks(networks.text.linesIterator.map(_.trim).toSeq, id)
      .foreach(network => remove(podman, "network", "rm", network))

    val tls = tlsStateRoot(os).resolve(id)
    System.err.println(s"rm -rf $tls")
    deleteRecursively(tls)

    val policyCache = policyStateRoot(os).resolve(id)
    System.err.println(s"rm -rf $policyCache")
    deleteRecursively(policyCache)

    // The audit trail goes with the rest of the project's state: "reset" means "as if this project had never been
    // opened". Copy the files out first if a session's refusals still matter.
    val logs = logStateRoot(os).resolve(id)
    System.err.println(s"rm -rf $logs")
    deleteRecursively(logs)

    // The project's filter daemon and mountpoint, where the feature has been used. Best effort by
    // design: with no machine running there is nothing mounted to tear down.
    System.err.println("unmounting the workspace FUSE filter, if mounted")
    if !runOk(koAgentFsScriptCommand(podman, os, koAgentFsUnmountScript(id))*) then
      System.err.println("note: filter unmount skipped (no machine running, or nothing mounted)")

    if failures > 0 then fail(s"error: $failures reset steps failed")
    sys.exit(0)

  /**
   * The workstation-wide version of `--reset`: removes every project's
   * runtime state — the egress proxy containers, the sandbox run containers
   * (stray or live), the persisted agent-state
   * volumes (signing every agent out), the Podman networks, all the TLS
   * inspection CAs, every cached policy resolution, every retained proxy
   * audit log, and every workspace-filter mount. It deliberately does NOT remove built images or
   * their valid pending-cleanup journal: image-producing verbs own both, and the images are costly
   * to rebuild (`podman image rm` removes them by hand). A malformed journal is repaired because
   * it names no image the launcher can safely remove. Every command is printed before it runs.
   * Networks and CAs are recreated on the next launch.
   */
  def resetAll(os: Os): Nothing =
    // The workstation-wide deletions below run wherever the state root points; checked against
    // the current directory before any of them, like every other verb that touches it.
    requireStateRootOutside(os, resolveProjectDir())
    val imageState = stateRoot(os).resolve("image-build")
    val cleanupJournal = imageState.resolve("cleanup.ids")
    if Files.exists(cleanupJournal) then
      withFileLock(imageState.resolve("lock")):
        repairImageCleanupJournal(cleanupJournal)
    var failures = 0

    def listed(command: String*): Vector[String] =
      System.err.println(command.mkString(" "))
      val result = run(command*)
      if !result.ok then
        failures += 1
        System.err.println(result.err)
      result.text.linesIterator.map(_.trim).filter(_.nonEmpty).toVector

    def remove(command: String*): Unit = if !stepOk(command*) then failures += 1

    val containers = listed(podman, "ps", "-a", "--format", "{{.Names}}")
    (proxyContainers(containers) ++ sandboxRunContainers(containers))
      .foreach(name => remove(podman, "rm", "--force", name))

    persistentVolumes(listed(podman, "volume", "ls", "--format", "{{.Name}}"))
      .foreach(name => remove(podman, "volume", "rm", name))

    launcherNetworks(listed(podman, "network", "ls", "--format", "{{.Name}}"))
      .foreach(name => remove(podman, "network", "rm", name))

    val tls = tlsStateRoot(os)
    System.err.println(s"rm -rf $tls")
    deleteRecursively(tls)

    val policyCache = policyStateRoot(os)
    System.err.println(s"rm -rf $policyCache")
    deleteRecursively(policyCache)

    val logs = logStateRoot(os)
    System.err.println(s"rm -rf $logs")
    deleteRecursively(logs)

    // Every project's filter mount. Best effort, as in the per-project reset.
    System.err.println("unmounting all workspace FUSE filters, if mounted")
    if !runOk(koAgentFsScriptCommand(podman, os, koAgentFsUnmountAllScript)*) then
      System.err.println("note: filter unmount skipped (no machine running, or nothing mounted)")

    if failures > 0 then fail(s"error: $failures reset steps failed")
    sys.exit(0)

  /**
   * Per-user state, outside any project directory: nothing in it is the
   * agent's to read or rewrite. %LOCALAPPDATA% is per user and not roamed.
   *
   * Validated, not adopted: the value must be absolute — a relative one resolves against the
   * current directory, which is the repository being sandboxed, and would hand the CA signing key
   * to the sandbox (and aim `--reset-all`'s recursive deletions into the checkout). It is
   * canonicalized through its nearest existing ancestor, so a symlinked spelling cannot place it
   * somewhere the outside-the-project comparison (forbiddenStateRootReason) never sees; on a first
   * launch the directory does not exist yet, which is why a plain toRealPath is not enough.
   */
  def stateRoot(os: Os): Path = stateRootOf(os, env).fold(fail(_), identity)

  def stateRootOf(os: Os, env: String => Option[String]): Either[String, Path] =
    val (variable, configured) = os match
      case Os.Windows => ("LOCALAPPDATA", env("LOCALAPPDATA"))
      case _ =>
        env("XDG_STATE_HOME") match
          case Some(value) => ("XDG_STATE_HOME", Some(value))
          case None        => ("HOME", env("HOME").map(_ + "/.local/state"))
    configured match
      case None => Left(s"error: $variable is not set")
      case Some(value) =>
        val base =
          try Some(Paths.get(value))
          catch case _: java.nio.file.InvalidPathException => None
        base match
          case None => Left(s"error: $variable is not a valid path: '$value'")
          case Some(path) if !path.isAbsolute =>
            Left(
              s"""error: $variable is '$value', which is not an absolute path
                 |The launcher's state root holds the CA signing key and audit logs; a relative
                 |value would resolve against the current directory, the repository being
                 |sandboxed, so it is refused rather than resolved.""".stripMargin
            )
          case Some(path) =>
            canonicalizedFuturePath(path.resolve("ko-agent-sandbox"))
              .left.map(reason => s"error: $variable: $reason")

  /**
   * Why the resolved state root may not serve this project, or None. startsWith on two canonical
   * paths — the project directory is toRealPath-resolved, and stateRootOf canonicalized its
   * answer — with each compared under its macOS data-volume spellings too: a firmlink is not a
   * symlink, so toRealPath leaves `/System/Volumes/Data/...` and its `/...` alias as two
   * spellings of one directory (SandboxProject.withMacDataVolumeAliases).
   */
  def forbiddenStateRootReason(os: Os, stateRoot: Path, projectDir: Path): Option[String] =
    def spellings(path: Path): Seq[Path] =
      if os == Os.Mac then withMacDataVolumeAliases(Seq(path)) else Seq(path)
    Option.when(spellings(stateRoot).exists(root => spellings(projectDir).exists(root.startsWith)))(
      s"error: the launcher's state root $stateRoot is inside the project directory\n" +
        "It holds the CA signing key, proxy audit logs and launch state, which the sandbox must\n" +
        "not reach; point XDG_STATE_HOME (or LOCALAPPDATA) outside the project.",
    )

  /**
   * The containment check for the verbs run *from* a directory: refuse when the state root lies
   * inside what a launch would accept as this project. Directories a launch itself refuses — a
   * home, a filesystem root — are exempt, because the default state layout (`~/.local/state`)
   * sits inside a home and is the normal case, not a breach; an unanswerable home discovery keeps
   * the check, the fail-closed side. Every caller that deletes or reads under the state root
   * calls this before touching it.
   */
  def requireStateRootOutside(os: Os, projectDir: Path): Unit =
    val couldBeAProject = protectedHomeDirectories(os, env) match
      case Right(protection) => forbiddenProjectDirReason(projectDir, protection).isEmpty
      case Left(_)           => true
    if couldBeAProject then forbiddenStateRootReason(os, stateRoot(os), projectDir).foreach(fail(_))

  /**
   * Every project's inspection CA: the agent can neither read the signing key nor replace it for the next session.
   */
  def tlsStateRoot(os: Os): Path = stateRoot(os).resolve("tls")

  /**
   * Proxy audit logs, one file per run. A sibling of tls/, never inside it:
   * the proxy writes here and must not sit beside the CA key.
   */
  def logStateRoot(os: Os): Path = stateRoot(os).resolve("log")

  /**
   * Stamped copies of --print-policy dry runs. A cache, never an authority:
   * the proxy re-resolves the policy at every startup.
   */
  def policyStateRoot(os: Os): Path = stateRoot(os).resolve("policy")

  // -------------------------------------------------------------------------
  // Command line
  // -------------------------------------------------------------------------

  /**
   * The two independent authority options, selected on every launch and never persisted by a
   * stage or an agent resume. `--write=staged` is parsed but refuses at launch until the staged
   * engine ships (doc/PLAN-STAGED.md); the writable default stays `live` until then — no
   * distributable build may make ordinary launches read-only before the staged workflow is
   * usable.
   */
  val WriteModes = Vector("reject", "staged", "live")
  val DefaultWriteMode = "live"
  val EgressProfiles =
    Vector("deny-all", "deny-unless-model", "deny-unless-allowed", "allow-unless-denied")
  val DefaultEgressProfile = "deny-unless-allowed"

  /** Parsed launcher invocation: the authority options as given (None when defaulted), then
    * either one management verb with its operands, or the command forwarded verbatim. */
  case class ParsedCommandLine(
    write: Option[String],
    egress: Option[String],
    verb: Option[(String, List[String])],
    command: List[String],
  ):
    def writeMode: String = write.getOrElse(DefaultWriteMode)
    def egressProfile: String = egress.getOrElse(DefaultEgressProfile)

  val ManagementVerbs: Set[String] =
    Set(
      "--help", "--build", "--update", "--reset", "--reset-all", "--proxy-log",
      "--egress-effective", "--self-test",
    )

  /**
   * Outside a management verb's documented operands, the first non-option is the command and
   * ends launcher parsing; everything after it is passed verbatim. `--` is an optional escape
   * for a command that could look like a launcher option; no launcher option is parsed after
   * the command. The renamed and removed spellings refuse with their replacement — stale
   * authority configuration is never silently ignored.
   */
  def parseCommandLine(args: List[String]): Either[String, ParsedCommandLine] =
    def choose(option: String, value: String, choices: Vector[String]): Either[String, String] =
      if choices.contains(value) then Right(value)
      else Left(s"error: $option=$value; the values are ${choices.mkString(", ")}, exactly")

    def loop(
      rest: List[String],
      write: Option[String],
      egress: Option[String],
    ): Either[String, ParsedCommandLine] =
      rest match
        case Nil             => Right(ParsedCommandLine(write, egress, None, Nil))
        case "--" :: command => Right(ParsedCommandLine(write, egress, None, command))

        case arg :: tail if arg.startsWith("--write=") =>
          if write.isDefined then Left("error: --write is given twice")
          else choose("--write", arg.stripPrefix("--write="), WriteModes)
            .flatMap(value => loop(tail, Some(value), egress))

        case arg :: tail if arg.startsWith("--egress=") =>
          if egress.isDefined then Left("error: --egress is given twice")
          else choose("--egress", arg.stripPrefix("--egress="), EgressProfiles)
            .flatMap(value => loop(tail, write, Some(value)))

        case ("--write" | "--egress") :: _ =>
          Left("error: the authority options are spelled --write=<mode> and --egress=<profile>")

        case "--proxy-effective" :: _ =>
          Left(
            "error: --proxy-effective was renamed\n" +
              "Run --egress-effective [--] [command] instead; it uses the accompanying --egress=<profile>.",
          )

        case arg :: tail if arg.startsWith("--egress-check=") =>
          Right(
            ParsedCommandLine(
              write, egress,
              Some(("--egress-check", arg.stripPrefix("--egress-check=") :: tail)),
              Nil,
            ),
          )

        case verb :: tail if ManagementVerbs(verb) =>
          Right(ParsedCommandLine(write, egress, Some((verb, tail)), Nil))

        case arg :: _ if arg.startsWith("--") =>
          Left(s"error: unknown option $arg\nRun --help for the launcher verbs.")

        case command => Right(ParsedCommandLine(write, egress, None, command))

    loop(args, None, None)

  // -------------------------------------------------------------------------
  // Main
  // -------------------------------------------------------------------------

  /** The `--help` text, extracted from README.md's Reference block by build.sbt. */
  val UsageText: String =
    val stream = getClass.getResourceAsStream("/agentsandbox/usage.txt")
    if stream == null then fail("error: usage.txt is missing from this jar; rebuild it")
    try String(stream.readAllBytes(), StandardCharsets.UTF_8)
    finally stream.close()

  def usage(): Nothing =
    println(UsageText)
    sys.exit(0)

  /**
   * The section appended to the image's agent instructions, telling the agent what to do under
   * this session's authority selection rather than leaving it to be inferred from failing
   * commands. Directive by design: it says what to do, never how to probe. It states the *tag*
   * vocabulary and the proxy owns that: an agent told a tag the proxy does not define writes a
   * policy file that fails the next launch with "no treatment this proxy defines", which is a
   * confusing way to learn that these instructions drifted. A test holds the two together
   * (AgentSandboxLauncherTest, "the appended egress section names only tags the proxy defines").
   */
  def authoritySection(writeMode: String, resolved: String): String =
    val indented = resolved.linesIterator.map("    " + _).mkString("\n")
    val workspace = writeMode match
      case "reject" =>
        """`/workspace` is read-only this session. Do not attempt writes there; put results under
          |`~` or `/tmp` and tell the user, who relaunches with `--write=live` for a writable
          |session.""".stripMargin
      case _ =>
        "`/workspace` is writable and shared live with the host project directory."
    s"""
       |
       |# Authority in force for this session
       |
       |$workspace
       |
       |## Egress
       |
       |Resolved at launch by the proxy itself, so it is what is enforced rather than a copy
       |that can drift. `KO_AGENT_SANDBOX_EGRESS_POLICY` carries the same lines.
       |Anything not admitted below is refused. An unrestricted host is an opaque tunnel; a
       |restricted host answers only GET and HEAD, and one tagged `=git-fetch` also serves
       |`git fetch`, so `clone` and `pull` — `git push` is refused.
       |
       |$indented
       |
       |If a package registry or clone host you need is not admitted, do not look for another
       |route: name the host to the user, who adds it to `.ko-agent-sandbox/egress/allowed` on
       |the host and relaunches — under the default deny-unless-allowed profile or a broader
       |one, if this session's profile does not admit project hosts at all.
       |""".stripMargin

  def main(args: Array[String]): Unit =
    unknownSandboxVariables(System.getenv().keySet().asScala).foreach: name =>
      System.err.println(s"warning: $name is not a variable this launcher reads; a misspelling configures nothing")

    val parsed = parseCommandLine(args.toList).fold(fail(_), identity)

    // The verbs that read no authority option refuse one rather than ignoring it: a selection
    // that configures nothing is the silent-authority failure mode the options must not have.
    def noAuthorityOptions(verb: String): Unit =
      if parsed.write.isDefined || parsed.egress.isDefined then
        fail(s"error: $verb reads no authority option; drop --write/--egress")
    def noWriteOption(verb: String): Unit =
      if parsed.write.isDefined then
        fail(s"error: $verb reads no --write option; drop it")

    parsed.verb match
      case Some(("--help", _)) =>
        noAuthorityOptions("--help")
        usage()

      case Some(("--build", rest)) =>
        noAuthorityOptions("--build")
        if rest.nonEmpty then fail("error: --build takes no further arguments")
        requirePodman(currentOs)
        withImageBuildLock(currentOs): journal =>
          val context = unpackBuildContext()
          val fsSourceId = koAgentFsSourceId(context)
          val selfTestSourceId = contextSourceId(context, "ko-agent-self-test")
          val sandboxBundleId = contextSourceId(context, "ko-agent-sandbox")
          val proxyBundleId = contextSourceId(context, "ko-agent-egress-proxy")
          val readContainerfile = buildContextReader(context)
          val commands =
            buildCommands(podman, ImgTagVersion, fsSourceId, sandboxBundleId, proxyBundleId)
          val remoteImages =
            remoteImagesForBuildCommands(commands, readContainerfile, managedImageTags(ImgTagVersion).toSet)
          val images = buildOutputImages(commands)
          val existingTags = existingImageTags(podman)
          val staleBaseTags = staleVersionedBaseImageTags(existingTags, buildImageTags(ImgTagVersion))
          val initialCandidates = prepareImageCleanupJournal(
            journal,
            imageIdsForTags(existingTags, images),
            staleBaseTags,
          )
          runBuilds(context, remoteImagePullCommands(podman, remoteImages) ++ commands)
          verifyBuiltBundleLabels(Seq(
            "ko-agent-sandbox:latest" -> sandboxBundleId,
            "ko-agent-egress-proxy:latest" -> proxyBundleId,
          ))
          installKoAgentFs(podman, currentOs, fsSourceId)
          val (candidates, staleTags) = includeStaleSelfTestCleanup(
            podman,
            journal,
            initialCandidates,
            staleBaseTags,
            fsSourceId,
            selfTestSourceId,
          )
          val remaining = removeSupersededImages(
            podman,
            candidates,
            managedImageTags(ImgTagVersion),
            staleTags,
          )
          writeImageCleanupJournal(journal, remaining)
        sys.exit(0)

      case Some(("--update", rest)) =>
        noAuthorityOptions("--update")
        if rest.nonEmpty then fail("error: --update takes no further arguments")
        requirePodman(currentOs)
        withImageBuildLock(currentOs): journal =>
          val context = unpackBuildContext()
          val fsSourceId = koAgentFsSourceId(context)
          val selfTestSourceId = contextSourceId(context, "ko-agent-self-test")
          val sandboxBundleId = contextSourceId(context, "ko-agent-sandbox")
          val readContainerfile = buildContextReader(context)
          val commands = updateCommands(podman, ImgTagVersion, sandboxBundleId)
          val remoteImages =
            remoteImagesForBuildCommands(commands, readContainerfile, managedImageTags(ImgTagVersion).toSet)
          val images = buildOutputImages(commands)
          val existingTags = existingImageTags(podman)
          val staleBaseTags = staleVersionedBaseImageTags(existingTags, buildImageTags(ImgTagVersion))
          val initialCandidates = prepareImageCleanupJournal(
            journal,
            imageIdsForTags(existingTags, images),
            staleBaseTags,
          )
          runBuilds(context, remoteImagePullCommands(podman, remoteImages) ++ commands)
          verifyBuiltBundleLabels(Seq("ko-agent-sandbox:latest" -> sandboxBundleId))
          val (candidates, staleTags) = includeStaleSelfTestCleanup(
            podman,
            journal,
            initialCandidates,
            staleBaseTags,
            fsSourceId,
            selfTestSourceId,
          )
          val remaining = removeSupersededImages(
            podman,
            candidates,
            managedImageTags(ImgTagVersion),
            staleTags,
          )
          writeImageCleanupJournal(journal, remaining)
        sys.exit(0)

      case Some(("--reset", rest)) =>
        noAuthorityOptions("--reset")
        if rest.nonEmpty then fail("error: --reset takes no further arguments")
        requirePodman(currentOs)
        resetProject(currentOs)

      case Some(("--reset-all", rest)) =>
        noAuthorityOptions("--reset-all")
        if rest.nonEmpty then fail("error: --reset-all takes no further arguments")
        requirePodman(currentOs)
        resetAll(currentOs)

      // No requirePodman() here: with no arguments this reads host files only, and the retained
      // logs are documented as readable after every container is gone. proxyLog asks for podman on
      // the branch that needs it.
      case Some(("--proxy-log", rest)) =>
        noAuthorityOptions("--proxy-log")
        proxyLog(currentOs, rest)

      case Some(("--self-test", rest)) =>
        noAuthorityOptions("--self-test")
        requirePodman(currentOs)
        selfTest(currentOs, rest)

      case Some(("--egress-effective", rest)) =>
        noWriteOption("--egress-effective")
        requirePodman(currentOs)
        egressEffective(currentOs, parsed.egressProfile, rest)

      case Some(("--egress-check", operands)) =>
        noWriteOption("--egress-check")
        val host = operands.headOption.filter(_.nonEmpty).getOrElse(
          fail("error: --egress-check=<host> names the host to check"),
        )
        requirePodman(currentOs)
        egressCheck(currentOs, parsed.egressProfile, host, operands.tail)

      case Some((verb, _)) => fail(s"error: unhandled verb $verb") // ManagementVerbs and this match drifted

      case None => launch(parsed)

  /**
   * Whether the directory's own SELinux context already admits container reads, so a raw bind
   * needs no relabel: a container type with no MCS categories. A category-carrying context — what
   * a previous run's `:Z` leaves — is private to the container it was minted for, unreadable to a
   * new one, so it does not count. Only the root is asked: a partially labeled tree fails at
   * runtime with EACCES on the stray files, the host's own labeling to finish. Fail closed — a
   * missing stat, an unreadable or unexpected context all answer false.
   *
   * stat resolves through findOnPath like every host executable: this runs before the sandbox
   * exists, and the working directory is the repository being sandboxed.
   */
  def selinuxContainerReadable(dir: Path): Boolean =
    findOnPath("stat", env("PATH").getOrElse(""), Os.Linux).exists: stat =>
      val context = run(stat.toString, "-c", "%C", dir.toString)
      val parts = if context.ok then context.text.trim.split(":") else Array.empty[String]
      parts.length == 4 && parts.lift(2).exists(Set("container_file_t", "container_share_t"))

  /**
   * The zone as a POSIX `TZ` value. A tzdata name passes through; a fixed offset — what the JVM
   * falls back to on a host it cannot map to one, as `GMT+09:00` — is spelled `UTC-9`, because
   * POSIX reads the sign the other way round from ISO: `TZ=GMT+09:00` is nine hours *behind*
   * UTC to every native tool, while the JVM would read it as ahead. Seconds are dropped: glibc
   * honours `UTC-5:45:30`, but a JVM reads it as `+05:45` (measured on Java 25), so carrying them
   * would split the sandbox's own tools two ways; no zone has had one for over fifty years.
   */
  def posixTz(zone: ZoneId): String =
    val offset = zone.normalized() match
      case fixed: ZoneOffset => Some(fixed.getTotalSeconds)
      case _                 => None
    offset match
      case None | Some(0) if ZoneId.getAvailableZoneIds.contains(zone.getId) => zone.getId
      case None                                                              => "UTC"
      case Some(0)                                                           => "UTC"
      case Some(total) =>
        val magnitude = math.abs(total) / 60
        val sign = if total > 0 then "-" else "+"
        if magnitude == 0 then "UTC"
        else s"UTC$sign${magnitude / 60}" + (if magnitude % 60 == 0 then "" else f":${magnitude % 60}%02d")

  def launch(parsed: ParsedCommandLine): Unit =
    val os = currentOs
    val command = parsed.command
    val writeMode = parsed.writeMode
    val egressProfile = parsed.egressProfile

    if writeMode == "staged" then
      fail(
        """error: --write=staged is not implemented yet
          |The staged workspace ships in a later increment (doc/PLAN-STAGED.md); until then a
          |writable session is --write=live, the default.""".stripMargin
      )

    val image = env("KO_AGENT_SANDBOX_IMAGE").getOrElse("ko-agent-sandbox:latest")

    // Read before anything is created, like the egress policy below: a variable that would weaken
    // the boundary must not be discovered halfway through a launch that has already made resources.
    // The pin fallback it selects exists only for live mode; reject binds the tree read-only and
    // has nothing for either mechanism to guard.
    val guard = workspaceGuard(env(WorkspaceGuardVariable)).fold(fail(_), identity)
    val nesting = nestingMode(env(NestingVariable)).fold(fail(_), identity)
    val sessionStartMode = sessionStart(env(SessionStartVariable)).fold(fail(_), identity)
    val clipboard = clipboardMode(env(ClipboardVariable)).fold(fail(_), identity)
    val clipboardHost =
      ClipboardBroker.hostBackend(clipboard, os, env("PATH").getOrElse("")).fold(fail(_), identity)

    val projectDir = resolveProjectDir()

    // -----------------------------------------------------------------------
    // Refuse obviously wrong project directories
    // -----------------------------------------------------------------------
    val homeProtection = protectedHomeDirectories(os, env).fold(fail(_), identity)
    homeProtection.warnings.foreach(warning => System.err.println(s"warning: $warning"))
    forbiddenProjectDirReason(projectDir, homeProtection).foreach: reason =>
      fail(s"error: refusing to mount $projectDir as /workspace\n\n$reason")
    forbiddenStateRootReason(os, stateRoot(os), projectDir).foreach(fail(_))

    // Detected this early because reject's refusal below must come before any resource exists;
    // the log-file and raw project mounts read it again further down. Enforcing specifically:
    // permissive and disabled hosts read every mount unrelabeled, so relabeling there would be
    // a host-metadata write with nothing to buy.
    val selinuxEnforcing = os == Os.Linux &&
      findOnPath("getenforce", env("PATH").getOrElse(""), os)
        .exists(path => run(path.toString).text.trim == "Enforcing")

    // A raw bind on an SELinux-enforcing host is readable to the container only after :Z
    // relabels the checkout — a recursive host-metadata write, which is exactly the authority
    // reject withholds. Refused rather than relabeled, unless the tree already carries a
    // shared container-accessible context, where a plain read-only bind needs no host write.
    if writeMode == "reject" && selinuxEnforcing && !selinuxContainerReadable(projectDir) then
      fail(
        s"""error: --write=reject cannot mount $projectDir on this SELinux-enforcing host
           |Reading a raw bind here requires relabeling the checkout (:Z), a recursive
           |host-metadata write that reject must not perform. Use --write=live — the filter's
           |mountpoint needs no relabel — or relabel the project yourself
           |(chcon -R -t container_file_t -l s0 <dir>; the level clears any categories a
           |previous :Z minted for one container) and relaunch.""".stripMargin
      )

    // -----------------------------------------------------------------------
    // Per-project identity
    // -----------------------------------------------------------------------
    //
    // Names this checkout and suffixes everything Podman holds for it. The directory name alone would collide — two
    // checkouts called `app` must not share credentials or a policy — so the hash covers the whole path; moving a
    // project yields new resources and new sign-ins.
    val projectSlug = slugOf(projectDir.getFileName.toString)
    val projectId = projectIdOf(projectDir, os)

    // -----------------------------------------------------------------------
    // Per-project persistent volume
    // -----------------------------------------------------------------------
    //
    // Per project: the volume is startup input, not just storage — agent settings and MCP definitions in it name
    // commands to run, and a shared volume would let one hostile repository seed every later session (see the
    // disableAllHooks note in the Containerfile). Costs one sign-in per project. KO_AGENT_SANDBOX_PERSISTENT_VOLUME
    // deliberately shares one.
    val persistentVolume = env("KO_AGENT_SANDBOX_PERSISTENT_VOLUME") match
      case Some(shared) =>
        sharedVolumeNameError(shared).foreach(reason => fail(s"error: $reason"))
        shared
      case None => s"ko-agent-sandbox-persistent-$projectId"

    requirePodman(os)

    // -----------------------------------------------------------------------
    // Sandbox image
    // -----------------------------------------------------------------------
    //
    // No implicit pull: image rollout is separate from running an agent.
    if !runOk(podman, "image", "exists", image) then
      fail(
        s"""error: sandbox image not found: $image
           |
           |Build it first: run this launcher with --build.""".stripMargin
      )

    // One inspect answers three questions: the id (the CA-bundle and agents.md stamps below),
    // the bundle label (the version lock), and Config.Env (JdkTrust's JAVA_HOME) — the first
    // line is the id, the second the label, the rest the environment.
    val imageInspect = run(
      podman, "image", "inspect",
      "--format",
      s"{{.Id}}{{println}}$BundleLabelTemplate{{println}}" +
        "{{range .Config.Env}}{{println .}}{{end}}",
      image,
    ).text
    val imageId = imageInspect.linesIterator.nextOption().getOrElse("")
    val imageLabel = imageInspect.linesIterator.drop(1).nextOption().getOrElse("")
    val imageEnv = imageInspect.linesIterator.drop(2).mkString("\n")

    // A jar upgrade must never run silently against last month's images; checked before any
    // resource exists. bundleMismatch has the refuse-versus-warn reasoning.
    bundleMismatch(image, bundledSourceId("ko-agent-sandbox"), imageLabel).foreach: mismatch =>
      if env("KO_AGENT_SANDBOX_IMAGE").isDefined then System.err.println(s"warning: $mismatch")
      else fail(s"error: $mismatch")

    // -----------------------------------------------------------------------
    // This run's egress proxy
    // -----------------------------------------------------------------------
    //
    // The sandbox joins an internal network with no gateway; the only thing on it is this run's proxy, whose second
    // interface has the route out. A network boundary, not a configuration hint: removing the proxy env variables below
    // does not restore Internet access, it just makes the failure less legible. All per run — see the run-lifetime
    // section.
    val proxyImage = env("KO_AGENT_SANDBOX_PROXY_IMAGE").getOrElse("ko-agent-egress-proxy:latest")

    // One suffix ties this run's containers, networks and log file together in podman output and the retained logs.
    val runSuffix = newRunSuffix()
    val proxyContainer = proxyRunContainer(projectId, runSuffix)

    // Per run, not per project, so concurrent sessions cannot reach each other — a compromised proxy reaches the
    // Internet and its own sandbox, never a neighbour with a wider policy.
    val sandboxNetwork = sandboxRunNetwork(projectId, runSuffix)
    val egressNetwork = egressRunNetwork(projectId, runSuffix)

    if !runOk(podman, "image", "exists", proxyImage) then
      fail(
        s"""error: egress proxy image not found: $proxyImage
           |
           |The sandbox has no route to the Internet of its own; this proxy is
           |what it reaches instead. Build it first: run this launcher with
           |--build.""".stripMargin
      )

    // The proxy side of the version lock above: this is the image whose --print-policy output
    // and environment interface the launcher parses, so a mismatched default image must not get
    // as far as a cryptic parse failure.
    val proxyInspect = run(
      podman, "image", "inspect",
      "--format", s"{{.Id}}{{println}}$BundleLabelTemplate",
      proxyImage,
    ).text
    val proxyImageId = proxyInspect.linesIterator.nextOption().getOrElse("")
    val proxyImageLabel = proxyInspect.linesIterator.drop(1).nextOption().getOrElse("")

    bundleMismatch(proxyImage, bundledSourceId("ko-agent-egress-proxy"), proxyImageLabel).foreach:
      mismatch =>
        if env("KO_AGENT_SANDBOX_PROXY_IMAGE").isDefined then
          System.err.println(s"warning: $mismatch")
        else fail(s"error: $mismatch")

    // -----------------------------------------------------------------------
    // This project's policy
    // -----------------------------------------------------------------------
    //
    // The project's egress/ is read here on the host and handed to the proxy at startup.
    // policyDirError and readPolicyFiles have the shapes, SECURITY.md the why. What keeps a
    // session from writing the next one's policy is the write mode itself: reject's read-only
    // tree, or live's FUSE reserved-name rule; only the pin fallback still needs the read-only
    // mount-back (policyGuardArgs below).
    val policyDir = projectDir.resolve(".ko-agent-sandbox")
    policyDirError(policyDir).foreach(fail(_))

    val policyFiles = readPolicyFiles(policyDir.resolve("egress")).fold(fail(_), identity)

    // The provider the launched command selects, and the one warning that is the launcher's to
    // print: the proxy never sees the command, so "this command selects no provider" cannot come
    // from its resolution.
    val provider = commandProvider(command.headOption)
    if egressProfile == "deny-unless-model" && provider.isEmpty then
      System.err.println(
        s"warning: '${command.headOption.getOrElse("bash")}' is not a recognized agent command, " +
          "so deny-unless-model selects no model provider and admits no host; " +
          "the default --egress=deny-unless-allowed admits the project's allowed policy instead",
      )

    // Validated before anything is created: an invalid policy would otherwise surface as "could not determine the
    // egress proxy's address" after the --rm proxy died, the reason buried in its log. Cached like the CA bundle below,
    // keyed on (image Id, policy files verbatim) — everything the dry run reads — and only success is written.
    // Enforcement never reads this cache: the proxy re-resolves the same variables at startup, so corruption can at
    // worst misprint the banner, never widen what is enforced.
    val policyCacheDir = policyStateRoot(os).resolve(projectId)
    Files.createDirectories(policyCacheDir)
    if posixPermissions(policyCacheDir) then
      Files.setPosixFilePermissions(policyCacheDir, PosixFilePermissions.fromString("rwx------"))

    val resolvedHostsFile = policyCacheDir.resolve("resolved.hosts")
    val resolvedWarningsFile = policyCacheDir.resolve("resolved.warnings")
    // The stamp covers everything the dry run reads: the image, the authority selection — the
    // profile and the command-classified provider both shape the resolution — and the files,
    // hashed into its one line because they are multi-part. It is the first line of each cached
    // file rather than a file of its own, and a hit needs both to carry it: concurrent launches of
    // one project under different authority selections write here without a lock, and a stamp
    // beside the content can end up describing the other launch's (HostCommands.stampedEntry).
    val policyStamp =
      s"$proxyImageId $egressProfile ${provider.getOrElse("none")} " +
        sha256Hex(policyFiles.map((name, text) => s"$name: $text").mkString("\n"))

    // The dry run's warnings are cached beside the hosts, so an idle denial or an unreachable
    // provider is said at every launch, not only the one that missed the cache.
    // stampedEntry gives back exactly what was cached, trailing newline and all removed, so a hit
    // and a miss are one string. This one is hashed into the agent instructions' stamp: two
    // spellings of the same policy would make every launch after a re-resolve rewrite the shared
    // agents.md for nothing (HostCommands, writeWithMode).
    val cachedPolicy =
      (stampedEntry(resolvedHostsFile, policyStamp).filter(_.nonEmpty),
        stampedEntry(resolvedWarningsFile, policyStamp))
    val (policyResolvedText, policyWarnings) =
      cachedPolicy match
        case (Some(hosts), Some(warnings)) => (hosts, warnings)
        case _ =>
          val resolved = resolvedPolicy(podman, proxyImage, egressProfile, provider, policyFiles)
          if !resolved.ok then
            fail(s"error: this project's egress policy is not valid\n${resolved.err}")
          val warnings = resolved.err.linesIterator.filter(_.startsWith("warning:")).mkString("\n")
          writeStamped(resolvedHostsFile, policyStamp, resolved.text)
          writeStamped(resolvedWarningsFile, policyStamp, warnings)
          (resolved.text, warnings)

    // The leaf certificate's names: the restricted line of the dry run above, tags stripped — the
    // proxy image's own answer under this project's policy — so no second copy of any list
    // exists to drift (the proxy still refuses a mismatched leaf at startup), and a policy that
    // moves a host in or out of the restricted set reissues the leaf through leaf.sans below.
    // Empty is a policy that inspects nothing: no leaf, and no inspection material for the proxy.
    val inspectedHosts = inspectedHostsOf(policyResolvedText).fold(fail(_), identity)

    // The workspace FUSE filter, mounted before any volume is assembled (the lifecycle banner above
    // ensureKoAgentFsMounted has the shape). Every session's enforcement now, on every platform;
    // the .git pins below are what a session that opted out gets instead. The two are alternatives
    // rather than a stack: the filter's policy is a strict superset of the pins', and preparing a
    // pin's bind target means creating `.git` entries *through* the filter, which the filter denies
    // (observed as a container-start failure, not deduced).
    val sandboxContainer = sandboxRunContainer(projectId, runSuffix)

    // Derived from the mode rather than from the mount, so it exists before the mount does: the
    // mount script writes this session's marker as its first act (KoAgentFs, koAgentFsMountScript),
    // and a failure after that would otherwise leave the marker to age out of a later reap. Only
    // live sessions behind the filter have a mount to reap.
    val filterReap = Option.when(writeMode == "live" && guard != "none")(
      koAgentFsReapScript(koAgentFsReapPodman(podman, os), projectId, sandboxContainer),
    )

    // This project's TLS/trust state, and this run's own copies of the files podman will mount —
    // shared state is derived under the project lock further down, and what a container mounts is
    // the per-run copy, so a later launch's legitimate rewrite (a rebuilt image, an edited
    // policy) cannot take a mounted file from a session already running: a bind mount does not
    // survive its source's inode being replaced, and these files have nothing behind them to fall
    // through to.
    val tlsDir = tlsStateRoot(os).resolve(projectId)
    Files.createDirectories(tlsDir)
    if posixPermissions(tlsDir) then
      Files.setPosixFilePermissions(tlsDir, PosixFilePermissions.fromString("rwx------"))
    val runFiles = tlsDir.resolve(s"run-$runSuffix")

    // Which of this project's runs are still live, for every pruning decision this launch makes.
    // A failed listing prunes nothing — unknown liveness must not read as "no live runs" and
    // delete a running session's files out from under it. Two liveness notions, because the two
    // pruned things have different writers: the audit log is the proxy's alone, so the proxy
    // decides a log's fate; the mount copies serve the sandbox container too, so a run whose
    // proxy crashed while its sandbox lives on must keep them.
    val proxyPrefix = proxyRunContainer(projectId, "")
    val sandboxPrefix = sandboxRunContainer(projectId, "")
    val runningContainers = run(podman, "ps", "--format", "{{.Names}}")
    val runningNames: Option[Vector[String]] =
      Option.when(runningContainers.ok)(
        runningContainers.text.linesIterator.map(_.trim).toVector,
      )
    def liveSuffixes(prefix: String): Option[Set[String]] =
      runningNames.map(_.filter(_.startsWith(prefix)).map(_.stripPrefix(prefix)).toSet)
    val liveProxyRuns = liveSuffixes(proxyPrefix)
    val liveRuns =
      for
        proxies <- liveProxyRuns
        sandboxes <- liveSuffixes(sandboxPrefix)
      yield proxies ++ sandboxes
    if runningNames.isEmpty then
      System.err.println(
        "note: could not list the running containers; keeping every retained log and run file\n"
          + runningContainers.err,
      )

    // Everything this run creates, in one place: the shutdown hook and the resident teardown both
    // run exactly this, so the two cannot drift into removing different sets.
    val removeWhatThisRunCreated = () =>
      // Said rather than left silent, here and at the start below: podman takes about a second
      // either way, and on every path that reaches this one — a Ctrl-C, a refused launch, the
      // resident model's ordinary end — the terminal is the user's again, so a silent second reads
      // as a hang.
      System.err.println("\nremoving this run's containers and networks")  // newline after Ctrl-C
      removeRunResources(podman, sandboxContainer, proxyContainer, Seq(sandboxNetwork, egressNetwork))
      // This run's mount-source copies. The reaper deliberately does not remove them (its
      // argument surface stays fixed); a run it cleans up leaves its copies to the next launch's
      // age-and-liveness sweep, or a reset's.
      try deleteRecursively(runFiles)
      catch case _: Exception => ()
      // Best effort, as on the reaper's path: this run's session marker goes now rather than
      // waiting out the launch bound, and the mount follows if no other session holds it.
      filterReap.foreach(script => runOk(koAgentFsScriptCommand(podman, os, script)*))

    // Armed before the first resource this run owns — the filter's session marker, which the mount
    // below writes. What precedes it is this project's policy cache, which outlives every run by
    // design. From here on this process is the only thing that knows what to remove, and every
    // refusal below ends the JVM rather than raising (SandboxLifecycle, armRunCleanup).
    val cleanup = armRunCleanup(removeWhatThisRunCreated)

    val filteredWorkspace = (writeMode, guard) match
      case ("reject", _) => None
      case (_, "none") =>
        // Said every session it happens, because this is the weaker boundary and silence about it
        // is how a user forgets which one they are running under — the relabel notice included,
        // so the one raw-bind arrangement that rewrites host metadata is never a silent one.
        System.err.println(
          s"workspace guard: NONE by $WorkspaceGuardVariable; /workspace is bound directly, with " +
            "only .git/config and .git/hooks pinned read-only, and only until the host rewrites one"
            + (if selinuxEnforcing then "; the checkout is relabeled for container access (:Z)"
               else ""),
        )
        None
      case _ => Some(ensureKoAgentFsMounted(podman, os, projectId, projectDir, sandboxContainer))

    // gitGuardVolumes has the threat and the shapes. Reject mode needs no pin: the whole tree is
    // bound read-only, git control state included.
    val gitGuardArgs =
      if writeMode == "reject" || filteredWorkspace.isDefined then Vector.empty
      else
        val (emptyFile, emptyDir) = emptyMountSources(stateRoot(os))
        gitGuardVolumes(projectDir.resolve(".git"), emptyFile, emptyDir).fold(fail(_), identity)

    // The pin fallback is the one arrangement still needing the read-only mount-back of the
    // policy directory: the raw tree is writable there, so without it a session could mkdir
    // .ko-agent-sandbox and write the policy governing the next one (SECURITY.md). Reject's tree
    // is read-only whole; the filter refuses the reserved name at any depth.
    val policyGuardArgs =
      if writeMode == "live" && guard == "none" then Vector(policyGuardVolume(policyDir))
      else Vector.empty

    // -----------------------------------------------------------------------
    // This project's TLS inspection CA, and this run's mount sources
    // -----------------------------------------------------------------------
    //
    // The CA the sandbox trusts for TLS inspection. Minted here; the key stays on the host, only the leaf and its own
    // key reach the proxy. SECURITY.md ("Who holds the CA key") has the reasoning.
    //
    // Under the project lock, because every step is check-then-act over shared files: two first
    // launches that both find no current CA would otherwise interleave their writes and leave one
    // launch's ca.key beside the other's ca.crt. The lock spans the checks through the per-run
    // copies, so what this run mounts is one launch's consistent set; it cannot span further —
    // podman resolves bind sources at container *start*, past the interactive hold — and the
    // per-run copies are what close that remainder. What the lock cannot cover is a launch that
    // *died* between two writes, which is the coherence gates' job below: they test that key and
    // certificate answer each other, not merely that both look current.
    val caCertFile = tlsDir.resolve("ca.crt")
    val caKeyFile = tlsDir.resolve("ca.key")
    val leafCertFile = tlsDir.resolve("leaf.crt")
    val leafKeyFile = tlsDir.resolve("leaf.key")
    val leafSansFile = tlsDir.resolve("leaf.sans")
    val bundleFile = tlsDir.resolve("sandbox-ca-bundle.crt")
    val bundleStampFile = tlsDir.resolve("bundle.stamp")

    val sanList = inspectedHosts.map("DNS:" + _).mkString(",")
    val reissueDeadline = Instant.now().plusSeconds(ReissueMarginSeconds)

    // The egress policy, appended to the agent instructions the image ships, so an agent starts the
    // session knowing what it can reach instead of learning it from a refused request. Same
    // technique as the CA bundle below — read the image's own file, add this project's part, mount
    // the result back over it — and the image points all three agents' instruction files at this one
    // path by symlink, so a single mount reaches every one of them. Cached on (image Id, resolved
    // policy), the only two inputs; the policy is hashed into the stamp because it is multi-line.
    val agentDocPath = "/etc/ko-agent-sandbox/AGENTS.md"
    val agentDocFile = policyCacheDir.resolve("agents.md")
    val agentDocStampFile = policyCacheDir.resolve("agents.stamp")
    // The write mode is a stamp input of its own; the profile and provider need none — the
    // resolved text's first line carries both.
    val agentDocStamp = s"$imageId $writeMode ${sha256Hex(policyResolvedText)}"

    val (proxyTlsArgs, sandboxTlsArgs, agentDocArgs, jdkProxy) = withFileLock(tlsDir.resolve(".lock")):
      // Run copies whose runs are provably gone — and past the launch bound, so a launch between
      // its copies and its `podman create` is never swept — leave with this launch rather than
      // accumulating; the resets take the rest.
      liveRuns.foreach: live =>
        val entries = Files.list(tlsDir).iterator().asScala.map(_.getFileName.toString).toVector
        tlsRunDirsToPrune(entries, live, name => olderThanLaunchBound(tlsDir.resolve(name)))
          .foreach(name => deleteRecursively(tlsDir.resolve(name)))

      // Coherence, not just currency: a launch that died between writing the key and the
      // certificate leaves a pair that is current, non-empty and useless — every handshake fails
      // while both files look fine — and only a correspondence test re-mints it.
      def coherentPair(certFile: Path, keyFile: Path): Boolean =
        (readIfPresent(certFile), readIfPresent(keyFile)) match
          case (Some(cert), Some(key)) => keyMatchesCertificate(cert, key)
          case _                       => false

      if !certificateCurrent(readIfPresent(caCertFile), reissueDeadline)
        || !coherentPair(caCertFile, caKeyFile)
      then
        try
          val ca = mintCa(projectSlug)
          // The leaf this CA no longer signs is retired by emptying it, not by deleting it: the
          // names stay stable for the copies below and for anything still reading them
          // (HostCommands, writeWithMode). Empty fails every currency test below, so the leaf is
          // reissued in this same launch — and it is emptied before the CA is written, so a
          // launch that dies here leaves a leaf that the next one reissues rather than one
          // silently signed by the old CA.
          Seq(leafCertFile, leafKeyFile).foreach(writePrivate(_, ""))
          writeReadable(leafSansFile, "")
          writePrivate(caKeyFile, ca.privateKeyPem)
          writePrivate(caCertFile, ca.certificatePem)
        catch
          case ex: Exception =>
            fail(s"error: could not create this project's inspection CA in $tlsDir\n$ex")

      // The leaf is reissued when the CA is (emptied just above), when the list of inspected names changes, and before
      // it expires — and not minted at all for a policy that inspects nothing. Its own coherence
      // gate, plus the chain to this CA: a leaf another launch minted under a CA since replaced
      // is internally consistent and still fails every handshake.
      if inspectedHosts.nonEmpty
        && (!certificateCurrent(readIfPresent(leafCertFile), reissueDeadline)
          || firstLine(leafSansFile) != sanList
          || !coherentPair(leafCertFile, leafKeyFile)
          || !readIfPresent(leafCertFile).exists(signedBy(_, Files.readString(caCertFile))))
      then
        try
          val leaf = mintLeaf(
            Files.readString(caCertFile),
            Files.readString(caKeyFile),
            inspectedHosts,
          )
          writePrivate(leafKeyFile, leaf.privateKeyPem)
          writePrivate(leafCertFile, leaf.certificatePem)
          writeReadable(leafSansFile, sanList + "\n")
        catch
          case ex: Exception =>
            fail(s"error: could not issue this project's inspection certificate\n$ex")

      // The sandbox's trust: the image's own CA bundle — not the workstation's, a different set entirely — plus this
      // project's CA. Re-read when image or CA changes; the stamp records both (imageId came from
      // the inspect beside the image-exists check).
      val caFingerprint = certificateFingerprint(pemBody(Files.readString(caCertFile)))
      val bundleStamp = s"$imageId $caFingerprint"

      if readIfPresent(bundleFile).forall(_.isEmpty) || firstLine(bundleStampFile) != bundleStamp then
        val imageBundle = run(
          podman, "run", "--rm", "--pull=never", "--network=none",
          image, "cat", "/etc/ssl/certs/ca-certificates.crt",
        )
        if !imageBundle.ok || imageBundle.out.isEmpty then
          fail(s"error: could not read the CA bundle out of $image\n${imageBundle.err}")
        val bundleText =
          String(imageBundle.out, StandardCharsets.US_ASCII).stripLineEnd + "\n" +
            Files.readString(caCertFile)
        writeReadable(bundleFile, bundleText)
        writeReadable(bundleStampFile, bundleStamp + "\n")

      // The JVM reads a `cacerts` keystore and no proxy variable, so the bundle above and the
      // HTTPS_PROXY family cannot reach it; JdkTrust.scala is that whole story, and None means
      // the image ships no JDK.
      val cacertsMount = jdkTrustMount(podman, image, imageEnv, tlsDir, bundleStamp, caCertFile)
      val netPropertiesMount =
        jdkProxyMount(podman, image, imageEnv, tlsDir, imageId, EgressProxyHost, EgressProxyPort)

      if readIfPresent(agentDocFile).forall(_.isEmpty)
        || firstLine(agentDocStampFile) != agentDocStamp
      then
        val imageDoc = run(
          podman, "run", "--rm", "--pull=never", "--network=none", image, "cat", agentDocPath,
        )
        if !imageDoc.ok || imageDoc.out.isEmpty then
          fail(s"error: could not read the agent instructions out of $image\n${imageDoc.err}")
        writeReadable(
          agentDocFile,
          String(imageDoc.out, StandardCharsets.UTF_8).stripLineEnd
            + authoritySection(writeMode, policyResolvedText),
        )
        writeReadable(agentDocStampFile, agentDocStamp + "\n")

      // This run's copies, made while the lock still holds so no concurrent launch's rewrite can
      // land between a currency check above and a copy below. Modes travel with the copy: the
      // leaf key stays owner-only, and the run directory itself admits only this user.
      Files.createDirectories(runFiles)
      if posixPermissions(runFiles) then
        Files.setPosixFilePermissions(runFiles, PosixFilePermissions.fromString("rwx------"))
      def carried(source: Path): Path =
        val target = runFiles.resolve(source.getFileName)
        Files.copy(
          source, target,
          StandardCopyOption.COPY_ATTRIBUTES, StandardCopyOption.REPLACE_EXISTING,
        )
        target

      // The leaf and its key only: the CA key sits beside them and is never copied or mounted.
      // --userns makes the owner-only key readable as uid 65532; without it the key would have to
      // be world-readable on the host. (The userns flag itself stays on the create call: the
      // proxy writes its owner-only log file through the same mapping.) A policy that inspects
      // nothing gets no material — the proxy refuses material it has nothing to inspect with.
      val proxyTls =
        if inspectedHosts.isEmpty then Vector.empty
        else
          Vector(
            s"--volume=${carried(leafCertFile)}:/etc/agent-egress-proxy/leaf.crt:ro",
            s"--volume=${carried(leafKeyFile)}:/etc/agent-egress-proxy/leaf.key:ro",
            "--env=EGRESS_TLS_CERTIFICATE=/etc/agent-egress-proxy/leaf.crt",
            "--env=EGRESS_TLS_PRIVATE_KEY=/etc/agent-egress-proxy/leaf.key",
          )

      // The bundle replaces the image's; the variables cover tools carrying their own trust store
      // (certifi, Node's roots), and the keystore covers the JVM, which reads neither.
      val sandboxCaBundle = "/etc/ssl/certs/ca-certificates.crt"
      // The CA on its own, for sandbox-prepare-jdk: a JVM the agent installs itself is out of
      // the launcher's reach, and that script hands it this file. No new exposure — the same
      // certificate is already inside the bundle above — it just saves a script parsing one out.
      val sandboxEgressCa = "/etc/ko-agent-sandbox/egress-ca.crt"
      val sandboxTls = Vector(
        s"--volume=${carried(bundleFile)}:$sandboxCaBundle:ro",
        s"--volume=${carried(caCertFile)}:$sandboxEgressCa:ro",
        s"--env=SSL_CERT_FILE=$sandboxCaBundle",
        s"--env=CURL_CA_BUNDLE=$sandboxCaBundle",
        s"--env=REQUESTS_CA_BUNDLE=$sandboxCaBundle",
        s"--env=NODE_EXTRA_CA_CERTS=$sandboxCaBundle",
        s"--env=GIT_SSL_CAINFO=$sandboxCaBundle",
      ) ++ cacertsMount.map((file, at) => s"--volume=${carried(file)}:$at:ro").toVector

      (
        proxyTls,
        sandboxTls,
        Vector(s"--volume=${carried(agentDocFile)}:$agentDocPath:ro"),
        netPropertiesMount.map((file, at) => s"--volume=${carried(file)}:$at:ro").toVector,
      )

    // -----------------------------------------------------------------------
    // Networks
    // -----------------------------------------------------------------------
    //
    // --internal removes the gateway; without it the proxy would be
    // advisory.
    // Armed before the first network exists, not after both: `createNetwork` refuses by ending the
    // JVM, so arming between the two would leak the first when the second fails. Removing what was
    // never created costs a failed `podman rm` nobody sees.
    createNetwork(sandboxNetwork, internal = true)
    createNetwork(egressNetwork, internal = false)

    // -----------------------------------------------------------------------
    // This run's audit log
    // -----------------------------------------------------------------------
    //
    // Appended by the proxy through a bind-mounted host file, so the record
    // outlives the per-run container. Not --log-opt path=: conmon interprets
    // that inside the podman-machine VM. A single-file mount — the directory
    // would hand the proxy every previous session's record — and owner-only:
    // refusal lines carry full URLs, and a URL can carry a secret.
    val logDir = logStateRoot(os).resolve(projectId)
    Files.createDirectories(logDir)
    if posixPermissions(logDir) then
      Files.setPosixFilePermissions(logDir, PosixFilePermissions.fromString("rwx------"))

    // A log names its run in the same suffix its proxy container carries; the proxy is the log's
    // only writer, so proxy liveness alone decides it, and an unreadable running set pruned
    // nothing.
    liveProxyRuns.foreach: live =>
      logsToPrune(retainedLogs(logDir).map(_.getFileName.toString), RetainedProxyLogs, live)
        .foreach(name => Files.deleteIfExists(logDir.resolve(name)))

    val logStamp = DateTimeFormatter
      .ofPattern("uuuuMMdd-HHmmss")
      .withZone(ZoneOffset.UTC)
      .format(Instant.now())
    val hostLogFile = logDir.resolve(s"proxy-$logStamp-$runSuffix.log")
    writePrivate(hostLogFile, "")

    // :Z relabels privately, right for a file only this run's proxy writes — launcher-owned
    // state, never the user's.
    val containerLogFile = "/var/log/agent-egress-proxy/proxy.log"
    val proxyLogArgs = Vector(
      s"--volume=$hostLogFile:$containerLogFile:rw${if selinuxEnforcing then ",Z" else ""}",
      s"--env=EGRESS_LOG_FILE=$containerLogFile",
    )

    // -----------------------------------------------------------------------
    // Proxy container
    // -----------------------------------------------------------------------
    //
    // A session keeps the policy it started with; the next launch re-reads.
    // --rm, so a proxy whose JVM exits removes itself.
    // The sandbox's hardening; --tmpfs /tmp because the JVM writes its perf-data file at startup.
    val proxyCreated = run(
      Vector(
        podman, "create",
        s"--name=$proxyContainer",
        "--rm",
        "--pull=never",
        "--init",
        s"--network=$sandboxNetwork",
        s"--network=$egressNetwork",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--read-only",
        "--tmpfs=/tmp",
        "--pids-limit=512",
        "--http-proxy=false",
        s"--userns=keep-id:uid=$ContainerUid,gid=$ContainerGid",
      ) ++ policyEnvArgs(egressProfile, provider, policyFiles)
        ++ proxyTlsArgs ++ proxyLogArgs ++ Vector(proxyImage)*
    )
    if !proxyCreated.ok then
      fail(s"error: could not create the egress proxy container\n${proxyCreated.err}")

    val proxyStarted = run(podman, "start", proxyContainer)
    if !proxyStarted.ok then
      fail(s"error: could not start the egress proxy container\n${proxyStarted.err}")

    val networksFormat =
      "{{range $net, $conf := .NetworkSettings.Networks}}{{$net}} {{$conf.IPAddress}}{{println}}{{end}}"
    val proxyIp = addressOn(
      run(podman, "container", "inspect", "--format", networksFormat, proxyContainer).text,
      sandboxNetwork,
    ).getOrElse(fail(s"error: could not determine the egress proxy's address on $sandboxNetwork"))

    // Both authorities and their relevant state, said every launch — and a policy that arrived
    // with the repository never takes effect unseen: the files as written, then the dry run's
    // counts, the proxy's own answers to exactly what is enforced.
    System.err.println(writeMode match
      case "reject" => "Workspace: REJECT; /workspace is read-only this session"
      case _ if filteredWorkspace.isDefined =>
        "Workspace: LIVE; one FUSE mount and daemon shared by this project's live sessions"
      case _ => "Workspace: LIVE; /workspace bound directly (pin fallback)")
    if policyFiles.nonEmpty then
      policyFiles.foreach: (name, text) =>
        System.err.println(s"egress policy (.ko-agent-sandbox/egress/$name): ${entriesSummary(text)}")
    System.err.println(egressBanner(policyResolvedText))
    if policyWarnings.nonEmpty then System.err.println(policyWarnings)
    if inspectedHosts.isEmpty then
      System.err.println("egress tls inspection: this policy inspects no hosts; no leaf minted")
    System.err.println(s"egress log: $hostLogFile")

    // -----------------------------------------------------------------------
    // How the sandbox reaches it
    // -----------------------------------------------------------------------
    //
    // --dns=none: proxied tools CONNECT by name and never resolve; the
    // effective no-external-DNS property comes from the internal network.
    // Defence in depth, not a fix for a known hole — SECURITY.md has the
    // measurement; do not remove this believing it closes one. --add-host
    // supplies the one name that must work, read back from podman so no
    // subnet is reserved. Both spellings of each variable: traditional
    // tools read lowercase. HTTP_PROXY is set although plain HTTP is
    // refused, so an http:// attempt lands in the proxy log instead of
    // failing as an unexplained resolution error.
    val egressProxyUrl = s"http://$EgressProxyHost:$EgressProxyPort"

    // A JVM reads none of the variables below, so the image's JDK is pointed at the proxy through
    // its own configuration instead — the same read-add-mount the CA bundle gets, one directory
    // over (JdkTrust.jdkProxyMount); `jdkProxy` carried it out of the locked derivation above.

    val egressArgs = Vector(
      s"--network=$sandboxNetwork",
      "--dns=none",
      s"--add-host=$EgressProxyHost:$proxyIp",
      s"--env=HTTPS_PROXY=$egressProxyUrl",
      s"--env=https_proxy=$egressProxyUrl",
      s"--env=HTTP_PROXY=$egressProxyUrl",
      s"--env=http_proxy=$egressProxyUrl",
      "--env=NO_PROXY=localhost,127.0.0.1",
      "--env=no_proxy=localhost,127.0.0.1",

      // The policy, handed to the agent rather than left to be discovered by failing requests. The
      // value is the proxy's own --print-policy answer, verbatim and unparsed, so this is the same
      // string the banner above prints and there is no second derivation of the list to drift from
      // it. It grants nothing: an agent can already enumerate the policy by probing, slowly and
      // noisily, and reading a refusal as breakage is the usual outcome of not knowing.
      s"--env=KO_AGENT_SANDBOX_EGRESS_POLICY=$policyResolvedText",

      // The entrypoint holds its machine-health warning on screen under the same setting as
      // holdForReader, for the same reason: the TUI clears it otherwise.
      s"--env=$SessionStartVariable=$sessionStartMode",
    ) ++ sandboxTlsArgs ++ jdkProxy ++ agentDocArgs ++ policyGuardArgs ++ gitGuardArgs

    // The nested-container loosenings (NestingLoosenings has the what and why). Loud every session
    // they apply: the weaker boundary must never be the silent one. The resolved mode goes into
    // the session either way — none included — so agents read one variable with one spelling and
    // never also handle unset.
    val nestingEnv = s"--env=$NestingVariable=$nesting"
    val nestedArgs = nesting match
      case "none" => Vector(nestingEnv)
      case mode =>
        System.err.println(
          s"nested containers: $mode by $NestingVariable; /proc unmasked, SELinux label " +
            "disabled and CAP_SYS_CHROOT added, for the whole session",
        )
        NestingLoosenings :+ nestingEnv

    // Loud for the same reason. WAYLAND_DISPLAY, because Claude Code and Copilot copy through
    // wl-copy only when they see a display, and otherwise through OSC 52, which Terminal.app
    // ignores; the value names the shim so nothing mistakes it for a compositor.
    val clipboardArgs = clipboard match
      case "off" => Vector.empty
      case mode =>
        System.err.println(
          s"clipboard: $mode by $ClipboardVariable; the agent can read an image you copy" +
            (if mode == "bidirectional" then " and set your clipboard" else ""),
        )
        Vector(s"--env=$ClipboardVariable=$mode") ++
          (if mode == "bidirectional" then Vector("--env=WAYLAND_DISPLAY=ko-agent-clipboard") else Vector.empty)

    // -----------------------------------------------------------------------
    // Project bind mount
    // -----------------------------------------------------------------------
    //
    // With the workspace filter on — every session but one that opted out — /workspace binds the
    // filter's mountpoint, never the raw tree, and a failure anywhere in the gate aborted the launch
    // above; there is no fallback to an unfiltered bind. The .git pins were skipped in that case,
    // where the volumes were assembled.
    //
    // :Z only on native SELinux-enforcing Linux, and only on the raw bind; podman-machine sources
    // must not be relabelled, and neither must a FUSE mountpoint.
    val projectVolume = (writeMode, filteredWorkspace) match
      // Never :Z: the reject gate above established the tree is already container-readable, and
      // relabeling is the host write the mode withholds.
      case ("reject", _)                 => s"$projectDir:/workspace:ro"
      case (_, Some(mountpoint))         => s"$mountpoint:/workspace:rw"
      case (_, None) if selinuxEnforcing => s"$projectDir:/workspace:rw,Z"
      case (_, None)                     => s"$projectDir:/workspace:rw"

    // -----------------------------------------------------------------------
    // Memory ceiling
    // -----------------------------------------------------------------------
    //
    // Memory is the runaway this environment invites (the cs java OOM in the Containerfile), and
    // the sandbox must die before the machine does: one in-sandbox build exhausting the VM takes
    // podman's own service with it, and every session on the machine (the troubleshooting
    // document's "The whole machine degrades"). Hence a ceiling by default, below the machine's
    // total (memoryCeiling), and no swap: a build that swaps is the thrash that makes every podman
    // command slow. KO_AGENT_SANDBOX_MEMORY replaces the default for a machine shared with other
    // sessions.
    val machineMemory = memoryTotal(run(podman, "info", "--format", "{{.Host.MemTotal}}"))
    if machineMemory.isEmpty then
      System.err.println(
        "warning: podman info reports no machine memory; the sandbox runs without a memory ceiling",
      )
    machineMemory.filter(_ < SmallMachineMemory).foreach: total =>
      System.err.println(
        s"warning: podman runs on ${gib(total)} of memory; builds in the sandbox OOM below about 4 GiB\n" +
          "  on a podman machine, raise it with `podman machine set --memory` (machine stopped)",
      )
    val memoryArgs = memoryArguments(env("KO_AGENT_SANDBOX_MEMORY"), machineMemory)

    // -----------------------------------------------------------------------
    // The sandbox container: create, arm the reaper, then attach
    // -----------------------------------------------------------------------
    //
    // create + start --attach rather than one `podman run`, so the reaper's `podman wait` has a container to bind to
    // before anything watches it. Killed between the two, the launcher leaves a never-started stray; the reaper removes
    // it after a bounded wait, the resets sweep the rest.
    val createCommand = Vector(
      podman, "create",

      // What the reaper waits on; --rm, so a session normally leaves nothing behind carrying this name.
      s"--name=$sandboxContainer",
      "--rm",
      "-it",

      // Never update or pull implicitly at execution time.
      "--pull=never",

      // Reap orphaned grandchildren and forward signals correctly.
      "--init",

      // Map the invoking rootless Podman user to our fixed non-root user. Files created under /workspace consequently
      // remain host-user-owned.
      s"--userns=keep-id:uid=$ContainerUid,gid=$ContainerGid",
      s"--user=$ContainerUid:$ContainerGid",

      // The agents need no Linux capability.
      "--cap-drop=ALL",

      // Prevent setuid/file-capability binaries from regaining privilege.
      "--security-opt=no-new-privileges",

      // /tmp and /var/tmp stay writable through podman's --read-only-tmpfs default — the writability
      // SANDBOX.md promises the agents.
      "--read-only",

      // Defense against accidental or hostile fork bombs. Raise this if a particular parallel build genuinely needs
      // more.
      "--pids-limit=2048",

      // Do not inherit the host's proxy variables; egressArgs passes the sandbox's own explicitly.
      "--http-proxy=false",
    ) ++ nestedArgs ++ clipboardArgs ++ egressArgs ++ Vector(

      // The host's zone, for the JVM resolves it on every platform the launcher runs on. The image
      // ships tzdata and nothing else sets a zone, so without this a commit made in the sandbox
      // carries +0000 and the agent's "today" turns over at the wrong hour.
      s"--env=TZ=${posixTz(ZoneId.systemDefault())}",

      // The deliberate host exposure; what the agent writes here is untrusted input to host tools (SECURITY.md, "The
      // project checkout").
      "--volume", projectVolume,

      // Anonymous, removed on exit: caches work without becoming cross-session attack state.
      "--mount", "type=volume,dst=/home/nonroot",

      // Persist auth/config; ~/.claude, ~/.codex, ~/.gemini and ~/.copilot are symlinks into this volume. This is
      // Podman-owned storage, not a bind mount into the host HOME.
      "--mount", s"type=volume,src=$persistentVolume,dst=/home/nonroot/persistent-volume",

      // Chromium treats podman's 64 MB /dev/shm default as fatal; agy's browser automation needs more. Not a host RAM
      // reservation.
      "--shm-size=512m",
    ) ++ memoryArgs ++ Vector(
      "--workdir", "/workspace",

      // The image's ENTRYPOINT seeds the persistent volume and execs the command; with none, its CMD, bash.
      image,
    ) ++ command.toVector

    // Before the container exists, and so before the reaper that waits on it: a Ctrl-C at the hold
    // is then an ordinary shutdown, the hook removing this run's proxy and networks and the launch
    // ending at once. Held after the create, it would sit inside the reaper's
    // created-but-never-started wait (SandboxLifecycle, ReaperScript) and leave it polling podman
    // for minutes after the launcher was gone. The cost is that the note below — the reaper could
    // not be spawned — prints after the release, and the TUI then clears it with the rest.
    holdForReader(sessionStartMode, command.headOption.getOrElse("bash"))

    // The create and the start behind it, for the reason removeWhatThisRunCreated states.
    System.err.println(s"starting in sandbox")

    val created = run(createCommand*)
    if !created.ok then
      fail(s"error: could not create the sandbox container\n${created.err}")

    // A failed spawn is not fatal — it downgrades the handover to the resident path (handOver), which is the fully
    // supported Windows model, not a degraded one.
    val reaperArmed =
      os != Os.Windows &&
        spawnReaper(
          podman, sandboxContainer, proxyContainer, sandboxNetwork, egressNetwork,
          filterReap.map(_ => koAgentFsTeardownMode(os)).getOrElse("none"),
          filterReap.getOrElse(""),
          clipboard,
          clipboardHost,
        )
    if os != Os.Windows && !reaperArmed then
      // Not a downgrade when the clipboard was asked for: the sandbox would wait the shim's bound
      // on every paste for a broker that never comes. The cleanup hook removes what was created,
      // the never-started sandbox included (removeRunResources).
      if clipboard != "off" then
        fail(s"error: could not spawn the proxy reaper, which serves $ClipboardVariable=$clipboard")
      System.err.println("note: could not spawn the proxy reaper; staying resident to remove the proxy on exit")
    // The resident twin; it waits for the container the start below brings up.
    clipboardHost.powershell.foreach(ClipboardBroker.startResident(_, podman, sandboxContainer, clipboard))

    handOver(
      Vector(podman, "start", "--attach", "--interactive", sandboxContainer),
      viaExec = reaperArmed,
      cleanup = cleanup,
    )
