// Run Claude Code, Codex, or Antigravity inside a rootless Podman container.
//
// One launcher for Linux, macOS, WSL and native Windows. This file is the policy, the flags, and the flow; the
// threat model is SECURITY.md. Its neighbours, each the whole blast radius of one thing:
//
//   HostCommands.scala        running a host executable, and the platform tag — the bottom layer
//   SandboxLifecycle.scala    the handover to podman, and both paths that remove a run's proxy
//   EgressProxyPolicy.scala   this project's egress policy, its resolution, and the audit log
//   KoAgentFs.scala           the workspace FUSE filter: build, install, identity, mount lifecycle
//   SandboxProject.scala      the project directory: real path, refusals, identity, mount guards
//   BouncyCastleHelper.scala  building certificates and PEM — the only file importing bouncycastle
//   JdkTrust.scala            making JVMs trust the inspection CA — locate, merge, mount
//   FFMHelper.scala           the execvp downcall
//
// This file is the canonical description of what the boundary is made of:
//
//   Host
//    |
//    +-- current project -------------------> /workspace      RW
//    |     (.git/config and .git/hooks re-mounted read-only;
//    |      see gitGuardVolumes. Those pins are the fallback: by
//    |      default /workspace is the ko-agent-fs mountpoint
//    |      instead; see ensureKoAgentFsMounted)
//    |
//    +-- .ko-agent-sandbox ---------> /workspace/.ko-agent-sandbox RO
//    |     (the egress policy, mounted back over itself so a
//    |      session cannot write the next one's; policyGuardVolume)
//    |
//    +-- Podman named volume -----------> ~/persistent-volume RW/persistent
//    |                                       (~/.claude, ~/.codex, ~/.gemini
//    |                                        are symlinks into it)
//    |
//    X-- ~/.ssh                             NOT EXPOSED
//    X-- ~/.aws                             NOT EXPOSED
//    X-- ~/.config                          NOT EXPOSED
//    X-- Podman/Docker socket               NOT EXPOSED
//    X-- rest of host filesystem            NOT EXPOSED
//
//   Internet
//    |
//    +-- egress proxy ------------------> allowlisted hosts, CONNECT :443 only
//    |                                       (EgressProxyPolicy.scala; the flags are below)
//    |                                    most hosts TLS-inspected read-only;
//    |                                       git hosts additionally refuse git push
//    X-- everything else                    NO ROUTE
//
// The rest of /home/nonroot is an anonymous Podman volume: build caches work, and disappear with the container.
//
// The image pre-accepts Claude Code's trust dialog for /workspace and marks it trusted for Codex, so a mounted
// project's own agent configuration — MCP servers included — takes effect unconfirmed. The container, not those
// dialogs, is the boundary; whatever they name runs inside it, never in a host-side helper.
//
// Podman arguments are NOT accepted: podman merges rather than replaces
// most flags, so a caller-supplied --volume or --cap-add could silently
// reopen the boundary. Every argument is forwarded verbatim to the
// container; the first is the command to run. Launcher verbs are the
// exception, recognized only as the first argument; a container command
// never begins with `--`, so an unrecognized `--` argument is refused as a
// mistyped verb.

package agentsandbox.launcher

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, Paths}
import java.nio.file.attribute.PosixFilePermissions
import java.time.{Instant, ZoneOffset}
import java.time.format.DateTimeFormatter
import scala.jdk.CollectionConverters.*

import BouncyCastleHelper.*
import JdkTrust.*
import EgressProxyPolicy.*
import HostCommands.*
import KoAgentFs.*
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
  /**
   * How the sandbox addresses the proxy: a name `--add-host` puts in /etc/hosts, so no resolver is
   * involved, and the port the proxy listens on. Named apart rather than only spelled into a URL,
   * because a JVM wants them as two properties rather than one (JdkTrust.jdkProxyArgs).
   */
  val EgressProxyHost = "egress-proxy"
  val EgressProxyPort = 3128

  val NestingVariable = "KO_AGENT_SANDBOX_NESTING"
  val NestingLoosenings =
    Vector("--security-opt=unmask=ALL", "--security-opt=label=disable", "--cap-add=SYS_CHROOT")

  def nestingMode(value: Option[String]): Either[String, String] =
    closedChoice(
      NestingVariable,
      value,
      Vector("none", "same-uid"),
      "none",
      "Unset it (or set it to none) to keep /proc masked and /dev/fuse absent; set it\nto " +
        "same-uid to loosen both so a container runtime installed in the session can run " +
        "(SECURITY.md)."
    )

  /**
   * Everything a launch prints — which guard this session runs under, the egress policy, every
   * warning — is on screen for as long as it takes the agent to start, and claude's fullscreen TUI
   * and codex both clear the screen as they do. So the last thing before the handover is a hold:
   * the terminal stays the reader's until they release it. `immediate` prints the same lines and
   * starts the agent at once, for whoever has read them enough times; with no terminal there is
   * nothing to hold.
   */
  val SessionStartVariable = "KO_AGENT_SANDBOX_SESSION_START"

  def sessionStart(value: Option[String]): Either[String, String] =
    closedChoice(
      SessionStartVariable,
      value,
      Vector("pause", "immediate"),
      "pause",
      "Unset it (or set it to pause) to keep the hold; set it to immediate to start the\nagent " +
        "at once, leaving what the launch printed to be read from the scrollback afterwards."
    )

  /**
   * The command names what is about to take the screen, so the prompt says what it is waiting on.
   * isTerminal, not a null check: since JDK 22 System.console() answers a Console for a redirected
   * stream too, and holding a pipe open would hang a scripted launch instead of skipping the hold.
   */
  def holdForReader(mode: String, command: String): Unit =
    val console = System.console()
    if mode == "pause" && console != null && console.isTerminal then
      console.printf("%nPress Enter to start %s. ", command)
      console.readLine()

  /**
   * The KO_AGENT_SANDBOX_* names this launcher reads — plus EGRESS_POLICY, which it sets inside
   * the sandbox rather than reads, so a launcher nested in a sandbox session is not warned about
   * the variable that session legitimately carries.
   */
  val KnownSandboxVariables: Set[String] = Set(
    "KO_AGENT_SANDBOX_IMAGE",
    "KO_AGENT_SANDBOX_PROXY_IMAGE",
    "KO_AGENT_SANDBOX_PERSISTENT_VOLUME",
    "KO_AGENT_SANDBOX_MEMORY",
    WorkspaceGuardVariable,
    NestingVariable,
    SessionStartVariable,
    "KO_AGENT_SANDBOX_EGRESS_POLICY"
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
   * gateway. Per run like the proxy: created by the launch, removed with
   * it, never reused, so no pre-existing object is ever trusted to carry
   * the boundary.
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

  def requirePodman(): Unit =
    if !runOk(podman, "--version") then
      fail(
        s"""error: $podman does not run
           |
           |Reinstall it: https://podman.io/docs/installation""".stripMargin,
        127
      )

  /**
   * The Debian/Temurin base the two base images pin, passed to every image
   * as IMG_TAG_VER; leaf images stay on `latest` (buildCommands). Mirrors
   * the pins in debian-temurin's Containerfile — a bump edits both files,
   * and the "ImgTagVersion mirrors" test fails when they disagree.
   */
  val ImgTagVersion = "13.6-25.0.4-0"

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

  val BundleLabel = "ko-agent-sandbox.bundle"

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
        (if label.trim.isEmpty then "(none)" else label.trim)
    )

  /**
   * The five images in dependency order. Leaf images stay on `latest`: a
   * rebuild there picks up new agent releases, which the base version says
   * nothing about; the base is an image label instead. debian-temurin does
   * not consume IMG_TAG_VER, and neither does ko-agent-fs — it builds on
   * rust:slim with its own pins, and its identity is the source digest.
   *
   * `--save-stages` keeps the proxy's compile-and-test stage as ordinary
   * layer cache; podman otherwise deletes non-final stages, re-running the
   * expensive sbt step on every --build.
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
    proxyBundleId: String
  ): Vector[Vector[String]] =
    Vector(
      Vector(podman, "build", "-t", s"debian-temurin:$version", "debian-temurin"),
      Vector(
        podman, "build", "--build-arg", s"IMG_TAG_VER=$version",
        "-t", s"debian-coursier:$version", "debian-coursier"
      ),
      Vector(
        podman, "build", "--build-arg", s"IMG_TAG_VER=$version",
        "--build-arg", s"BUNDLE_ID=$sandboxBundleId",
        "--label", s"$BundleLabel=$sandboxBundleId",
        "-t", "ko-agent-sandbox:latest", "ko-agent-sandbox"
      ),
      Vector(
        podman, "build", "--save-stages", "--build-arg", s"IMG_TAG_VER=$version",
        "--build-arg", s"BUNDLE_ID=$proxyBundleId",
        "--label", s"$BundleLabel=$proxyBundleId",
        "-t", "ko-agent-egress-proxy:latest", "ko-agent-egress-proxy"
      ),
      Vector(
        podman, "build", "--build-arg", s"KO_AGENT_FS_SOURCE_ID=$fsSourceId",
        "-t", "ko-agent-fs:latest", "ko-agent-fs"
      )
    )

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
        "-t", "ko-agent-sandbox:latest", "ko-agent-sandbox"
      )
    )

  /**
   * --build's check of what it just stamped, immediately after the builds:
   * the layer-cache staleness above is exactly the kind of silent drift the
   * version lock exists for, so the freshly committed labels are read back
   * rather than assumed. A failure here is podman misbehaving, not a wrong
   * jar — the remediation is clearing the build cache, not --build again.
   */
  def verifyBuiltBundleLabels(expected: Seq[(String, String)]): Unit =
    expected.foreach: (image, id) =>
      val inspected = run(
        podman, "image", "inspect",
        "--format", s"{{with .Config.Labels}}{{index . \"$BundleLabel\"}}{{end}}",
        image
      )
      if !inspected.ok then
        fail(s"error: could not inspect the just-built image $image\n${inspected.err}")
      if inspected.text.trim != id then
        fail(
          s"""error: --build committed $image with a stale bundle label
             |  launcher bundle digest: $id
             |  image label $BundleLabel: ${
                if inspected.text.trim.isEmpty then "(none)" else inspected.text.trim}
             |
             |podman's layer cache can serve a LABEL derived from a changed
             |build arg stale (buildah #5501); this launcher passes --label to
             |bypass that cache, so this failing means podman dropped --label
             |too. Clear the cache and rebuild:
             |  podman image rm $image && podman image prune -f
             |then run --build again.""".stripMargin
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
        fail(
          s"error: build failed: ${command.mkString(" ")}\nbuild context retained at $context",
          exit
        )
    deleteRecursively(context)

  def proxyContainers(names: Seq[String]): Seq[String] =
    names.filter(_.startsWith("ko-agent-egress-proxy-"))

  /**
   * Run containers are --rm and normally remove themselves; one survives
   * only when its launcher died between create and start and its reaper
   * failed too. This filter is the resets' belt-and-braces sweep, not the
   * primary cleanup.
   */
  def sandboxRunContainers(names: Seq[String]): Seq[String] =
    names.filter(_.startsWith("ko-agent-sandbox-run-"))

  /**
   * Volumes named through KO_AGENT_SANDBOX_PERSISTENT_VOLUME do not carry this prefix and are deliberately left alone.
   */
  def persistentVolumes(names: Seq[String]): Seq[String] =
    names.filter(_.startsWith("ko-agent-sandbox-persistent-"))

  /** Both per-run network families, for `--reset-all`. */
  def launcherNetworks(names: Seq[String]): Seq[String] =
    names.filter: name =>
      name.startsWith("ko-agent-sandbox-") || name.startsWith("ko-agent-egress-")

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
    val id = projectIdOf(resolveProjectDir(), os)
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
      requirePodman()
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

  /**
   * The policy this project would apply, without a session: the same
   * readPolicyFiles + resolvedPolicy a launch uses. Data to stdout, context
   * to stderr, so the effective lists pipe cleanly.
   */
  def proxyEffective(os: Os): Nothing =
    val projectDir = resolveProjectDir()
    val projectId = projectIdOf(projectDir, os)
    val proxyImage =
      env("KO_AGENT_SANDBOX_PROXY_IMAGE").getOrElse("ko-agent-egress-proxy:latest")

    if !runOk(podman, "image", "exists", proxyImage) then
      fail(
        s"""error: egress proxy image not found: $proxyImage
           |
           |Build it first: run this launcher with --build.""".stripMargin
      )

    val hostsDir = projectDir.resolve(".ko-agent-sandbox").resolve("egress-hosts")
    val policyFiles = readPolicyFiles(hostsDir).fold(fail(_), identity)

    if policyFiles.nonEmpty then
      policyFiles.foreach: (name, text) =>
        System.err.println(s"egress policy ($hostsDir/$name): $text")
    else System.err.println("egress policy: the proxy image's built-in lists")

    val resolved = resolvedPolicy(podman, proxyImage, policyFiles)
    System.out.write(resolved.out)
    System.out.flush()
    if !resolved.ok then
      fail(s"error: this project's egress policy is not valid\n${resolved.err}")

    val caCert = tlsStateRoot(os).resolve(projectId).resolve("ca.crt")
    if Files.isRegularFile(caCert) then System.err.println(s"egress tls ca: $caCert")
    System.err.println(s"egress log dir: ${logStateRoot(os).resolve(projectId)}")
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
    val id = projectIdOf(resolveProjectDir(), os)
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
   * audit log, and every workspace-filter mount. It deliberately does NOT remove the built images; those
   * are `--build` and `--update`'s to manage and are costly to rebuild
   * (`podman image rm` removes them by hand). Every command is printed before
   * it runs. Networks and CAs are recreated on the next launch.
   */
  def resetAll(os: Os): Nothing =
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
   */
  def stateRoot(os: Os): Path = os match
    case Os.Windows =>
      Paths.get(
        env("LOCALAPPDATA").getOrElse(fail("error: LOCALAPPDATA is not set")),
        "ko-agent-sandbox"
      )
    case _ =>
      Paths.get(
        env("XDG_STATE_HOME").getOrElse(env("HOME").getOrElse(fail("error: HOME is not set")) + "/.local/state"),
        "ko-agent-sandbox"
      )

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
  // Main
  // -------------------------------------------------------------------------

  /**
   * The `--help` text. A named value rather than a literal inside usage()
   * because README reproduces it, and a copy that can drift is one that will:
   * a test holds the two together (AgentSandboxLauncherTest, "README
   * reproduces the --help text").
   */
  val UsageText: String =
    """Run an AI agent inside the sandbox container.
       |
       |Usage, from a project directory (which becomes /workspace):
       |  java -jar ko-agent-sandbox.jar [<command> [args...]]
       |
       |<command> runs inside the sandbox: claude, codex, agy, bash, ...
       |Everything is forwarded verbatim except the verbs below, each recognized
       |only as the first argument; whatever follows belongs to the verb:
       |
       |  --build            build the container images for the sandbox
       |  --update           rebuild only the sandbox container without cache,
       |                     for new claude/codex/agy releases
       |
       |  --reset            remove this project's containers (ending any live
       |                     session), volume (signing its agents out), networks,
       |                     TLS inspection CA, cached policy resolution, logs,
       |                     and workspace-filter mount; images and any shared
       |                     volume are left untouched
       |  --reset-all        the same, for every project
       |
       |  --proxy-effective  print this project's effective egress policy
       |  --proxy-log        print this project's retained proxy audit logs;
       |                     with extra args (-f, --tail 50), run podman logs on the
       |                     running proxies instead
       |
       |  --help             this text
       |
       |Environment:
       |  KO_AGENT_SANDBOX_IMAGE              sandbox image (default ko-agent-sandbox:latest)
       |  KO_AGENT_SANDBOX_PROXY_IMAGE        egress proxy image (default ko-agent-egress-proxy:latest)
       |  KO_AGENT_SANDBOX_PERSISTENT_VOLUME  share one agent-state volume across projects
       |  KO_AGENT_SANDBOX_MEMORY             container memory ceiling, e.g. 8g
       |  KO_AGENT_SANDBOX_WORKSPACE_GUARD    "fuse" (default) mounts /workspace through the ko-agent-fs
       |                                      filter; "none" binds it directly — a weaker boundary,
       |                                      pinning only .git/config and .git/hooks (SECURITY.md)
       |  KO_AGENT_SANDBOX_NESTING            "none" (default) allows no container runtime; "same-uid"
       |                                      allows one: unmasks /proc, disables SELinux
       |                                      labeling and adds SYS_CHROOT for the whole
       |                                      session, one mapped uid only (SECURITY.md)
       |  KO_AGENT_SANDBOX_SESSION_START      "pause" (default) holds a launch's startup lines on
       |                                      screen until you press Enter, because the agent TUIs
       |                                      clear the screen; "immediate" starts the agent at once
       |
       |Files in .ko-agent-sandbox/egress-hosts/ modify the egress policy: a +/- delta file per
       |tier ("read-write", "read-only"), and "blocked" applied with highest precedence.""".stripMargin

  def usage(): Nothing =
    println(UsageText)
    sys.exit(0)

  /**
   * The section appended to the image's agent instructions, naming what this session may reach.
   * A named value rather than a literal at the one call site, because it states the *tag*
   * vocabulary and the proxy owns that: an agent told a tag the proxy does not define writes a
   * policy file that fails the next launch with "no treatment this proxy defines", which is a
   * confusing way to learn that these instructions drifted. A test holds the two together
   * (AgentSandboxLauncherTest, "the appended egress section names only tags the proxy defines").
   */
  def egressPolicySection(resolved: String): String =
    val indented = resolved.linesIterator.map("    " + _).mkString("\n")
    s"""
       |
       |# Egress policy in force for this session
       |
       |Resolved at launch by the proxy itself, so it is what is enforced rather than a copy
       |that can drift. `KO_AGENT_SANDBOX_EGRESS_POLICY` carries the same two lines.
       |Anything not named here is refused. The read-write hosts are opaque tunnels; the
       |read-only hosts answer only GET and HEAD, and those tagged `=git-fetch` also serve
       |`git clone`/`fetch` — `git push` is refused.
       |
       |$indented
       |""".stripMargin

  def main(args: Array[String]): Unit =
    unknownSandboxVariables(System.getenv().keySet().asScala).foreach: name =>
      System.err.println(s"warning: $name is not a variable this launcher reads; a misspelling configures nothing")
    args.toList match
      case "--help" :: _ => usage()

      case "--build" :: rest =>
        if rest.nonEmpty then fail("error: --build takes no further arguments")
        requirePodman()
        val context = unpackBuildContext()
        val fsSourceId = koAgentFsSourceId(context)
        val sandboxBundleId = contextSourceId(context, "ko-agent-sandbox")
        val proxyBundleId = contextSourceId(context, "ko-agent-egress-proxy")
        runBuilds(
          context,
          buildCommands(podman, ImgTagVersion, fsSourceId, sandboxBundleId, proxyBundleId)
        )
        verifyBuiltBundleLabels(Seq(
          "ko-agent-sandbox:latest" -> sandboxBundleId,
          "ko-agent-egress-proxy:latest" -> proxyBundleId
        ))
        installKoAgentFs(podman, currentOs, fsSourceId)
        sys.exit(0)

      case "--update" :: rest =>
        if rest.nonEmpty then fail("error: --update takes no further arguments")
        requirePodman()
        val context = unpackBuildContext()
        val sandboxBundleId = contextSourceId(context, "ko-agent-sandbox")
        runBuilds(context, updateCommands(podman, ImgTagVersion, sandboxBundleId))
        verifyBuiltBundleLabels(Seq("ko-agent-sandbox:latest" -> sandboxBundleId))
        sys.exit(0)

      case "--reset" :: rest =>
        if rest.nonEmpty then fail("error: --reset takes no further arguments")
        requirePodman()
        resetProject(currentOs)

      case "--reset-all" :: rest =>
        if rest.nonEmpty then fail("error: --reset-all takes no further arguments")
        requirePodman()
        resetAll(currentOs)

      // No requirePodman() here: with no arguments this reads host files only, and the retained
      // logs are documented as readable after every container is gone. proxyLog asks for podman on
      // the branch that needs it.
      case "--proxy-log" :: rest =>
        proxyLog(currentOs, rest)

      case "--proxy-effective" :: rest =>
        if rest.nonEmpty then fail("error: --proxy-effective takes no further arguments")
        requirePodman()
        proxyEffective(currentOs)

      case first :: _ if first.startsWith("--") =>
        fail(s"error: unknown option $first\nRun --help for the launcher verbs.")

      case _ => launch(args)

  def launch(args: Array[String]): Unit =
    val os = currentOs

    val image = env("KO_AGENT_SANDBOX_IMAGE").getOrElse("ko-agent-sandbox:latest")

    // Read before anything is created, like the egress policy below: a variable that would weaken
    // the boundary must not be discovered halfway through a launch that has already made resources.
    val guard = workspaceGuard(env(WorkspaceGuardVariable)).fold(fail(_), identity)
    val nesting = nestingMode(env(NestingVariable)).fold(fail(_), identity)
    val sessionStartMode = sessionStart(env(SessionStartVariable)).fold(fail(_), identity)

    val projectDir = resolveProjectDir()

    // -----------------------------------------------------------------------
    // Refuse obviously wrong project directories
    // -----------------------------------------------------------------------
    val homeProtection = protectedHomeDirectories(os, env).fold(fail(_), identity)
    homeProtection.warnings.foreach(warning => System.err.println(s"warning: $warning"))
    forbiddenProjectDirReason(projectDir, homeProtection).foreach: reason =>
      fail(s"error: refusing to mount $projectDir as /workspace\n\n$reason")

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
    val persistentVolume = env("KO_AGENT_SANDBOX_PERSISTENT_VOLUME")
      .getOrElse(s"ko-agent-sandbox-persistent-$projectId")

    requirePodman()

    // -----------------------------------------------------------------------
    // Podman Machine
    // -----------------------------------------------------------------------
    //
    // macOS and native Windows need podman-machine. START an existing VM; never CREATE one — sizing is a
    // workstation-provisioning decision.
    if !runOk(podman, "info") then
      os match
        case Os.Linux =>
          fail(
            "error: Podman is not usable.\nOn Linux, run rootless Podman as your normal user, without sudo."
          )
        case _ =>
          val started = run(podman, "machine", "start")
          if !started.ok then
            fail(
              s"""error: Podman Machine could not be started.
                 |${started.err}
                 |
                 |Initialize it once, for example:
                 |  podman machine init""".stripMargin
            )

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
      s"{{.Id}}\n{{with .Config.Labels}}{{index . \"$BundleLabel\"}}{{end}}\n" +
        "{{range .Config.Env}}{{println .}}{{end}}",
      image
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

    // Per run, not per project: nothing is reused, so no pre-existing object is vetted to carry the boundary, and
    // concurrent sessions cannot reach each other — a compromised proxy reaches the Internet and its own sandbox, never
    // a neighbour with a wider policy.
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
      "--format", s"{{.Id}}\n{{with .Config.Labels}}{{index . \"$BundleLabel\"}}{{end}}",
      proxyImage
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
    // The project's egress-hosts/ is read here on the host and handed to the proxy at startup; the directory is mounted
    // back read-only further down. policyGuardVolume and readPolicyFiles have the shapes, SECURITY.md the why.
    val policyDir = projectDir.resolve(".ko-agent-sandbox")
    val policyVolume = policyGuardVolume(policyDir).fold(fail(_), identity)

    val policyFiles = readPolicyFiles(policyDir.resolve("egress-hosts")).fold(fail(_), identity)

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
    val resolvedStampFile = policyCacheDir.resolve("resolved.stamp")
    // The files are multi-part, so the stamp hashes them into its one line.
    val policyStamp =
      s"$proxyImageId ${sha256Hex(policyFiles.map((name, text) => s"$name: $text").mkString("\n"))}"

    val policyResolvedText =
      readIfPresent(resolvedHostsFile)
        .filter(_.nonEmpty)
        .filter(_ => firstLine(resolvedStampFile) == policyStamp) match
        case Some(cached) => cached
        case None =>
          val resolved = resolvedPolicy(podman, proxyImage, policyFiles)
          if !resolved.ok then
            fail(s"error: this project's egress policy is not valid\n${resolved.err}")
          // content before stamp: a cut-short write mismatches and re-runs
          writeReadable(resolvedHostsFile, resolved.text + "\n")
          writeReadable(resolvedStampFile, policyStamp + "\n")
          resolved.text

    // The leaf certificate's names: the read-only line of the dry run above, tags stripped — the
    // proxy image's own answer under this project's policy — so no second copy of any list
    // exists to drift (the proxy still refuses a mismatched leaf at startup), and a policy that
    // moves a host in or out of the read-only tier reissues the leaf through leaf.sans below.
    // Empty is a policy that inspects nothing: no leaf, and no inspection material for the proxy.
    val inspectedHosts = inspectedHostsOf(policyResolvedText).fold(fail(_), identity)

    // The workspace FUSE filter, mounted before any volume is assembled (the lifecycle banner above
    // ensureKoAgentFsMounted has the shape). Every session's enforcement now, on every platform;
    // the .git pins below are what a session that opted out gets instead. The two are alternatives
    // rather than a stack: the filter's policy is a strict superset of the pins', and preparing a
    // pin's bind target means creating `.git` entries *through* the filter, which the filter denies
    // (observed as a container-start failure, not deduced).
    val sandboxContainer = sandboxRunContainer(projectId, runSuffix)

    // Derived from the guard rather than from the mount, so it exists before the mount does: the
    // mount script writes this session's marker as its first act (KoAgentFs, koAgentFsMountScript),
    // and a failure after that would otherwise leave the marker to age out of a later reap.
    val filterReap = Option.when(guard != "none")(
      koAgentFsReapScript(koAgentFsReapPodman(podman, os), projectId, sandboxContainer)
    )

    // Everything this run creates, in one place: the shutdown hook and the resident teardown both
    // run exactly this, so the two cannot drift into removing different sets.
    val removeWhatThisRunCreated = () =>
      removeRunResources(podman, proxyContainer, Seq(sandboxNetwork, egressNetwork))
      // Best effort, as on the reaper's path: this run's session marker goes now rather than
      // waiting out the launch bound, and the mount follows if no other session holds it.
      filterReap.foreach(script => runOk(koAgentFsScriptCommand(podman, os, script)*))

    // Armed before the first resource this run owns — the filter's session marker, which the mount
    // below writes. What precedes it is this project's policy cache, which outlives every run by
    // design. From here on this process is the only thing that knows what to remove, and every
    // refusal below ends the JVM rather than raising (SandboxLifecycle, armRunCleanup).
    val cleanup = armRunCleanup(removeWhatThisRunCreated)

    val filteredWorkspace = guard match
      case "none" =>
        // Said every session it happens, because this is the weaker boundary and silence about it
        // is how a user forgets which one they are running under.
        System.err.println(
          s"workspace guard: NONE by $WorkspaceGuardVariable — /workspace is bound directly, with " +
            "only .git/config and .git/hooks pinned read-only, and only until the host rewrites one"
        )
        None
      case _ => Some(ensureKoAgentFsMounted(podman, os, projectId, projectDir, sandboxContainer))

    // gitGuardVolumes has the threat and the shapes.
    val gitGuardArgs =
      if filteredWorkspace.isDefined then Vector.empty
      else
        val (emptyFile, emptyDir) = emptyMountSources(stateRoot(os))
        gitGuardVolumes(projectDir.resolve(".git"), emptyFile, emptyDir).fold(fail(_), identity)

    // -----------------------------------------------------------------------
    // This project's TLS inspection CA
    // -----------------------------------------------------------------------
    //
    // The CA the sandbox trusts for TLS inspection. Minted here; the key stays on the host, only the leaf and its own
    // key reach the proxy. SECURITY.md ("Who holds the CA key") has the reasoning.
    val tlsDir = tlsStateRoot(os).resolve(projectId)

    Files.createDirectories(tlsDir)
    if posixPermissions(tlsDir) then
      Files.setPosixFilePermissions(tlsDir, PosixFilePermissions.fromString("rwx------"))

    val caCertFile = tlsDir.resolve("ca.crt")
    val caKeyFile = tlsDir.resolve("ca.key")
    val leafCertFile = tlsDir.resolve("leaf.crt")
    val leafKeyFile = tlsDir.resolve("leaf.key")
    val leafSansFile = tlsDir.resolve("leaf.sans")
    val bundleFile = tlsDir.resolve("sandbox-ca-bundle.crt")
    val bundleStampFile = tlsDir.resolve("bundle.stamp")

    val sanList = inspectedHosts.map("DNS:" + _).mkString(",")
    val reissueDeadline = Instant.now().plusSeconds(ReissueMarginSeconds)

    if !certificateCurrent(readIfPresent(caCertFile), reissueDeadline)
      || readIfPresent(caKeyFile).forall(_.isEmpty)
    then
      Seq(caCertFile, caKeyFile, leafCertFile, leafKeyFile, leafSansFile)
        .foreach(Files.deleteIfExists)
      try
        val ca = mintCa(projectSlug)
        writePrivate(caKeyFile, ca.privateKeyPem)
        writePrivate(caCertFile, ca.certificatePem)
      catch
        case ex: Exception =>
          fail(s"error: could not create this project's inspection CA in $tlsDir\n$ex")

    // The leaf is reissued when the CA is (deleted just above), when the list of inspected names changes, and before it
    // expires — and not minted at all for a policy that inspects nothing.
    if inspectedHosts.nonEmpty
      && (!certificateCurrent(readIfPresent(leafCertFile), reissueDeadline)
        || readIfPresent(leafKeyFile).forall(_.isEmpty)
        || firstLine(leafSansFile) != sanList)
    then
      try
        val leaf = mintLeaf(
          Files.readString(caCertFile),
          Files.readString(caKeyFile),
          inspectedHosts
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
        image, "cat", "/etc/ssl/certs/ca-certificates.crt"
      )
      if !imageBundle.ok || imageBundle.out.isEmpty then
        fail(s"error: could not read the CA bundle out of $image\n${imageBundle.err}")
      val bundleText =
        String(imageBundle.out, StandardCharsets.US_ASCII).stripLineEnd + "\n" +
          Files.readString(caCertFile)
      writeReadable(bundleFile, bundleText)
      writeReadable(bundleStampFile, bundleStamp + "\n")

    // The JVM reads a `cacerts` keystore, so the bundle above cannot reach it; JdkTrust.scala is
    // that whole story, and empty means the image ships no JDK.
    val cacertsArgs = jdkTrustArgs(podman, image, imageEnv, tlsDir, bundleStamp, caCertFile)

    // The egress policy, appended to the agent instructions the image ships, so an agent starts the
    // session knowing what it can reach instead of learning it from a refused request. Same
    // technique as the CA bundle above — read the image's own file, add this project's part, mount
    // the result back over it — and the image points all three agents' instruction files at this one
    // path by symlink, so a single mount reaches every one of them. Cached on (image Id, resolved
    // policy), the only two inputs; the policy is hashed into the stamp because it is multi-line.
    val agentDocPath = "/etc/ko-agent-sandbox/AGENTS.md"
    val agentDocFile = policyCacheDir.resolve("agents.md")
    val agentDocStampFile = policyCacheDir.resolve("agents.stamp")
    val agentDocStamp = s"$imageId ${sha256Hex(policyResolvedText)}"

    if readIfPresent(agentDocFile).forall(_.isEmpty)
      || firstLine(agentDocStampFile) != agentDocStamp
    then
      val imageDoc = run(
        podman, "run", "--rm", "--pull=never", "--network=none", image, "cat", agentDocPath
      )
      if !imageDoc.ok || imageDoc.out.isEmpty then
        fail(s"error: could not read the agent instructions out of $image\n${imageDoc.err}")
      writeReadable(
        agentDocFile,
        String(imageDoc.out, StandardCharsets.UTF_8).stripLineEnd
          + egressPolicySection(policyResolvedText)
      )
      writeReadable(agentDocStampFile, agentDocStamp + "\n")

    val agentDocArgs = Vector(s"--volume=$agentDocFile:$agentDocPath:ro")

    // The leaf and its key only: the CA key sits beside them and must not be mounted. --userns makes the owner-only key
    // readable as uid 65532; without it the key would have to be world-readable on the host. (The userns flag itself
    // stays on the create call: the proxy writes its owner-only log file through the same mapping.) A policy that
    // inspects nothing gets no material — the proxy refuses material it has nothing to inspect with.
    val proxyTlsArgs =
      if inspectedHosts.isEmpty then Vector.empty
      else
        Vector(
          s"--volume=$leafCertFile:/etc/agent-egress-proxy/leaf.crt:ro",
          s"--volume=$leafKeyFile:/etc/agent-egress-proxy/leaf.key:ro",
          "--env=EGRESS_TLS_CERTIFICATE=/etc/agent-egress-proxy/leaf.crt",
          "--env=EGRESS_TLS_PRIVATE_KEY=/etc/agent-egress-proxy/leaf.key"
        )

    // The bundle replaces the image's; the variables cover tools carrying their own trust store (certifi, Node's
    // roots), and the keystore covers the JVM, which reads neither.
    val sandboxCaBundle = "/etc/ssl/certs/ca-certificates.crt"
    // The CA on its own, for sandbox-prepare-jdk: a JVM the agent installs itself is out of
    // the launcher's reach, and that script hands it this file. No new exposure — the same
    // certificate is already inside the bundle above — it just saves a script parsing one out.
    val sandboxEgressCa = "/etc/ko-agent-sandbox/egress-ca.crt"
    val sandboxTlsArgs = Vector(
      s"--volume=$bundleFile:$sandboxCaBundle:ro",
      s"--volume=$caCertFile:$sandboxEgressCa:ro",
      s"--env=SSL_CERT_FILE=$sandboxCaBundle",
      s"--env=CURL_CA_BUNDLE=$sandboxCaBundle",
      s"--env=REQUESTS_CA_BUNDLE=$sandboxCaBundle",
      s"--env=NODE_EXTRA_CA_CERTS=$sandboxCaBundle",
      s"--env=GIT_SSL_CAINFO=$sandboxCaBundle"
    ) ++ cacertsArgs

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

    // Which of this project's runs are still writing: a log names its run in the same suffix its
    // proxy container carries, so the running set is what tells a finished record from a live one.
    val proxyPrefix = proxyRunContainer(projectId, "")
    val liveRuns = run(podman, "ps", "--format", "{{.Names}}").text.linesIterator
      .map(_.trim)
      .filter(_.startsWith(proxyPrefix))
      .map(_.stripPrefix(proxyPrefix))
      .toSet

    logsToPrune(retainedLogs(logDir).map(_.getFileName.toString), RetainedProxyLogs, liveRuns)
      .foreach(name => Files.deleteIfExists(logDir.resolve(name)))

    val logStamp = DateTimeFormatter
      .ofPattern("uuuuMMdd-HHmmss")
      .withZone(ZoneOffset.UTC)
      .format(Instant.now())
    val hostLogFile = logDir.resolve(s"proxy-$logStamp-$runSuffix.log")
    writePrivate(hostLogFile, "")

    // Needed for the log-file mount here and the project bind mount below. :Z relabels privately, right for a file only
    // this run's proxy writes.
    val selinux = os == Os.Linux &&
      findOnPath("selinuxenabled", env("PATH").getOrElse(""), os)
        .exists(path => runOk(path.toString))

    val containerLogFile = "/var/log/agent-egress-proxy/proxy.log"
    val proxyLogArgs = Vector(
      s"--volume=$hostLogFile:$containerLogFile:rw${if selinux then ",Z" else ""}",
      s"--env=EGRESS_LOG_FILE=$containerLogFile"
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
        s"--userns=keep-id:uid=$ContainerUid,gid=$ContainerGid"
      ) ++ policyEnvArgs(policyFiles) ++ proxyTlsArgs ++ proxyLogArgs ++ Vector(proxyImage)*
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
      sandboxNetwork
    ).getOrElse(fail(s"error: could not determine the egress proxy's address on $sandboxNetwork"))

    // A policy that arrived with the repository never takes effect unseen: the files as written, then the dry run's
    // tier lines — the proxy's own answers, exactly what is enforced.
    if policyFiles.nonEmpty then
      policyFiles.foreach: (name, text) =>
        System.err.println(s"egress policy (.ko-agent-sandbox/egress-hosts/$name): $text")
    else System.err.println("egress policy: the proxy image's built-in lists")
    System.err.println(s"egress ${policyCounts(policyResolvedText)}")
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
    // over (JdkTrust.jdkProxyArgs). Empty when the image ships no JDK.
    val jdkProxy =
      jdkProxyArgs(podman, image, imageEnv, tlsDir, imageId, EgressProxyHost, EgressProxyPort)

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
      // it. It grants nothing: an agent can already enumerate the allowlist by probing, slowly and
      // noisily, and reading a refusal as breakage is the usual outcome of not knowing.
      s"--env=KO_AGENT_SANDBOX_EGRESS_POLICY=$policyResolvedText"
    ) ++ sandboxTlsArgs ++ jdkProxy ++ agentDocArgs ++ Vector(
      // Always mounted read-only, even with no policy shipped: without it an agent could mkdir .ko-agent-sandbox and
      // write the allowlist governing the *next* session (SECURITY.md; policyGuardVolume refused the bad shapes above).
      policyVolume
    ) ++ gitGuardArgs

    // The nested-container loosenings (NestingLoosenings has the what and why). Loud every session
    // they apply: the weaker boundary must never be the silent one. The resolved mode goes into
    // the session either way — none included — so agents read one variable with one spelling and
    // never also handle unset.
    val nestingEnv = s"--env=$NestingVariable=$nesting"
    val nestedArgs = nesting match
      case "none" => Vector(nestingEnv)
      case mode =>
        System.err.println(
          s"nested containers: $mode by $NestingVariable — /proc unmasked, SELinux label " +
            "disabled and CAP_SYS_CHROOT added, for the whole session"
        )
        NestingLoosenings :+ nestingEnv

    // -----------------------------------------------------------------------
    // Project bind mount
    // -----------------------------------------------------------------------
    //
    // With the workspace filter on — every session but one that opted out — /workspace binds the
    // filter's mountpoint, never the raw tree, and a failure anywhere in the gate aborted the launch
    // above; there is no fallback to an unfiltered bind. The .git pins were skipped in that case,
    // where the volumes were assembled.
    //
    // :Z only on native SELinux Linux, and only on the raw bind; podman-machine sources must not
    // be relabelled, and neither must a FUSE mountpoint.
    val projectVolume = filteredWorkspace match
      case Some(mountpoint) => s"$mountpoint:/workspace:rw"
      case None if selinux => s"$projectDir:/workspace:rw,Z"
      case None => s"$projectDir:/workspace:rw"

    // -----------------------------------------------------------------------
    // Optional memory ceiling
    // -----------------------------------------------------------------------
    //
    // Opt-in: a limit that is too low turns a slow build into an opaque OOM kill. Memory is the runaway this
    // environment invites (the cs java OOM in the Containerfile).
    val memoryArgs = env("KO_AGENT_SANDBOX_MEMORY").map(m => s"--memory=$m").toVector

    // -----------------------------------------------------------------------
    // The sandbox container: create, arm the reaper, then attach
    // -----------------------------------------------------------------------
    //
    // create + start --attach rather than one `podman run`, so the reaper's `podman wait` has a container to bind to
    // before anything watches it. Killed between the two, the launcher leaves a never-started stray; the reaper removes
    // it after a bounded wait, the resets sweep the rest.
    val command = Vector(
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
      "--http-proxy=false"
    ) ++ nestedArgs ++ egressArgs ++ Vector(

      // The deliberate host exposure; what the agent writes here is untrusted input to host tools (SECURITY.md, "The
      // project checkout").
      "--volume", projectVolume,

      // Anonymous, removed on exit: caches work without becoming cross-session attack state.
      "--mount", "type=volume,dst=/home/nonroot",

      // Persist auth/config; ~/.claude, ~/.codex and ~/.gemini are symlinks into this volume. This is Podman-owned
      // storage, not a bind mount into the host HOME.
      "--mount", s"type=volume,src=$persistentVolume,dst=/home/nonroot/persistent-volume",

      // Chromium treats podman's 64 MB /dev/shm default as fatal; agy's browser automation needs more. Not a host RAM
      // reservation.
      "--shm-size=512m"
    ) ++ memoryArgs ++ Vector(
      "--workdir", "/workspace",

      // No ENTRYPOINT in the image: with no arguments the command is bash, inherited from debian:*-slim.
      image
    ) ++ args.toVector

    val created = run(command*)
    if !created.ok then
      fail(s"error: could not create the sandbox container\n${created.err}")

    // A failed spawn is not fatal — it downgrades the handover to the resident path (handOver), which is the fully
    // supported Windows model, not a degraded one.
    val reaperArmed =
      os != Os.Windows &&
        spawnReaper(
          podman, sandboxContainer, proxyContainer, sandboxNetwork, egressNetwork,
          filterReap.map(_ => koAgentFsTeardownMode(os)).getOrElse("none"),
          filterReap.getOrElse("")
        )
    if os != Os.Windows && !reaperArmed then
      System.err.println(
        "note: could not spawn the proxy reaper; staying resident to remove the proxy on exit"
      )

    // Last, so the hold covers every line this launch printed. A Ctrl-C here is the documented
    // killed-between-create-and-start edge: the reaper removes the stray container it is waiting
    // on, and the proxy and networks with it.
    holdForReader(sessionStartMode, args.headOption.getOrElse("bash"))

    handOver(
      Vector(podman, "start", "--attach", "--interactive", sandboxContainer),
      viaExec = reaperArmed,
      cleanup = cleanup
    )
