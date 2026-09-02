// Run Claude Code, Codex, Antigravity, or Copilot CLI inside a rootless podman container.
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
//   BouncyCastleHelper.scala    building certificates and PEM (its header has the import rule)
//   JdkTrust.scala              making the image's JVM reach the proxy — locate, prepare, mount
//   FFMHelper.scala             the execvp downcall
//
// This file is the canonical description of what the boundary is made of:
//
//   Host
//    |
//    +-- current project -------------------> /workspace
//    |     (--write selects the mount: live — the default — is the
//    |      ko-agent-fs mountpoint, RW with git and policy control
//    |      state frozen (ensureKoAgentFsMounted; under guard=none the
//    |      .git pins of gitGuardVolumes stand in); reject is a
//    |      read-only bind of the raw tree)
//    |
//    +-- .ko-agent-sandbox: the egress policy and the project's agent
//    |      instructions, read on the host; the write mode is what keeps
//    |      a session from writing the next one's — only guard=none
//    |      mounts it back RO (policyGuardVolume)
//    |
//    +-- podman named volume -----------> ~/persistent-volume RW/persistent
//    |                                       (~/.claude, ~/.codex, ~/.gemini,
//    |                                        ~/.copilot are symlinks into it)
//    |
//    +-- --run-on-host (macOS only): sandbox-run-on-host relays a command
//    |      request to a host-side wrapper that runs sbt/mill under a
//    |      Seatbelt profile — the project (git control state and
//    |      .ko-agent-sandbox denied), per-project build caches, one
//    |      Coursier JDK, a session directory, and the build's own
//    |      loopback egress proxy; nothing else (RunOnHostSandbox.scala,
//    |      RunOnHostChannel.scala; SECURITY.md "Run on host")
//    |
//    X-- ~/.ssh                             NOT EXPOSED
//    X-- ~/.aws                             NOT EXPOSED
//    X-- ~/.config                          NOT EXPOSED
//    X-- podman/Docker socket               NOT EXPOSED
//    X-- rest of host filesystem            NOT EXPOSED
//
//   Internet
//    |
//    +-- egress proxy ------------------> the hosts --egress=<profile> admits, CONNECT :443 only
//    |                                       (EgressProxyPolicy.scala; the flags are below)
//    |                                    restricted hosts: TLS-inspected reads plus named operations;
//    |                                       git push refused
//    X-- everything else                    NO ROUTE
//
// The rest of /home/nonroot is an anonymous podman volume: build caches work, and disappear with the container.
//
// The image pre-accepts Claude Code's trust dialog for /workspace and marks it trusted for Codex and Copilot, so a
// mounted project's own agent configuration — MCP servers included — takes effect unconfirmed. The container, not
// those dialogs, is the boundary; whatever they name runs inside it, never in a host-side helper.
//
// podman arguments are not accepted: podman merges rather than replaces
// most flags, so a caller-supplied --volume or --cap-add could silently
// reopen the boundary. The launcher parses only its authority options and
// management verbs (parseCommandLine); the first non-option is the command,
// and from there everything is forwarded verbatim to the container.

package agentsandbox.launcher

import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.{FileVisitResult, Files, Path, Paths, SimpleFileVisitor, StandardCopyOption}
import java.nio.file.attribute.{BasicFileAttributes, PosixFilePermissions}
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
   * variable means — or `same-uid`, which buys the listed loosenings for the whole session,
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
   * What is deliberately not loosened names the value: no-new-privileges stays, which blocks
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
   * because a JVM wants them as two properties rather than one (JdkTrust.jdkJavaOpts).
   */
  val EgressProxyHost = "egress-proxy"
  val EgressProxyPort = 3128

  /** The proxy's own spelling (AgentEgressProxy.ReadyLine): printed once its socket is bound. */
  val EgressProxyReadyLine = s"agent-egress-proxy listening on :$EgressProxyPort"

  /** The proxy stamps every line it writes with an instant and a space; the spelling follows. */
  def isProxyReadyLine(line: String): Boolean =
    line == EgressProxyReadyLine || line.endsWith(" " + EgressProxyReadyLine)

  /** A JVM start on a loaded machine; a proxy silent past this is failed, not waited for. */
  val EgressProxyReadyBound: java.time.Duration = java.time.Duration.ofSeconds(30)

  /**
   * `podman start` returns once the process is spawned and says nothing about whether it stayed
   * up: a proxy refusing at start — a leaf naming other than its inspected set, a credential file
   * it will not honour — would otherwise leave a sandbox with no egress and the reason in a log
   * nobody was shown. Reads the run's host log, the file the proxy tees to before it does
   * anything else, until EgressProxyReadyLine, or the container is no longer running, or `bound`
   * elapses; either failure carries what the proxy wrote. The file rather than `podman logs`:
   * the container is `--rm`, and a proxy refusing at once is gone, with its output, before a
   * follower attaches — the file outlives it.
   */
  def awaitProxyReady(podman: String, container: String, log: Path, bound: java.time.Duration): Either[String, Unit] =
    val deadline = System.nanoTime() + bound.toNanos
    def said: String =
      try Files.readString(log, StandardCharsets.UTF_8) catch case _: IOException => ""
    def ready: Boolean = said.linesIterator.exists(isProxyReadyLine)
    def running: Boolean =
      val state = run(podman, "container", "inspect", "--format", "{{.State.Running}}", container)
      state.ok && state.text.trim == "true"
    var outcome: Option[Either[String, Unit]] = None
    while outcome.isEmpty do
      if ready then outcome = Some(Right(()))
      else if !running then
        // The last write may land after the liveness answer; read once more, then report.
        if ready then outcome = Some(Right(()))
        else
          val written = said
          // Only when the proxy could not even open its log does its refusal live in podman alone
          // — and `--rm` may have taken the container, and the refusal with it, before this read.
          val reason =
            if written.nonEmpty then written
            else
              val relayed = run(podman, "logs", container)
              if relayed.ok then relayed.err
              else
                s"nothing was written to $log and podman had already removed the container: the " +
                  "proxy exited before opening its log, which is that file's mount"
          outcome = Some(Left(s"the egress proxy exited before listening\n$reason"))
      else if System.nanoTime() >= deadline then
        outcome = Some(Left(s"the egress proxy did not report ready within ${bound.toSeconds}s\n$said"))
      else Thread.sleep(200)
    outcome.get

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
      "Unset it (or set it to pause) to keep the prompt, where n exits without starting;\nset it " +
        "to immediate to start the agent at once, leaving what the launch printed to be\nread " +
        "from the scrollback afterwards.",
    )

  /**
   * The decision the reader takes on the workspace and egress lines above: Enter or y starts, n
   * declines, EOF at the prompt counts as n, and any other answer asks again; Ctrl-C ends the JVM
   * through the shutdown hook, which is the same outcome as n. The full command is shown, since
   * its arguments are part of what is agreed to. With no reader — no terminal, or a mode other
   * than pause — there is nothing to hold.
   */
  def holdForReader(mode: String, command: Seq[String], reader: Option[Reader]): Boolean =
    reader.filter(_ => mode == "pause") match
      case None => true
      case Some(reader) =>
        def ask(): Boolean =
          reader.prompt(s"\nstart: ${command.map(renderArgument).mkString(" ")} [Y/n] ")
          reader.readLine() match
            case None => false
            case Some(answer) =>
              answer.trim.toLowerCase(java.util.Locale.ROOT) match
                case "" | "y" | "yes" => true
                case "n" | "no"       => false
                case _                => ask()
        ask()

  /** What a hold prompts on and reads from; readLine answers None at EOF. */
  final case class Reader(prompt: String => Unit, readLine: () => Option[String])

  /**
   * The process's terminal, if stdin is one. isTerminal, not a null check: since JDK 22
   * System.console() answers a Console for a redirected stream too, and holding a pipe open would
   * hang a scripted launch instead of skipping the hold.
   */
  def terminalReader: Option[Reader] =
    Option(System.console()).filter(_.isTerminal).map: console =>
      Reader(text => console.printf("%s", text), () => Option(console.readLine()))

  /**
   * One argument as the reader agrees to it: verbatim when it is one plain word, so that the
   * usual command reads as typed, and otherwise quoted so that `tool "a b"` and `tool a b` render
   * apart and a character that would drive or reorder the terminal's display — a control,
   * a bidi or other format character, a line or paragraph separator — is spelled out instead.
   * The spelling is the shell's: single quotes, or `$'...'` around escapes.
   */
  def renderArgument(argument: String): String =
    val plain = argument.nonEmpty && argument.forall(ch => ch.isLetterOrDigit && ch < 0x80 || "_@%+=:,./-".contains(ch))
    if plain then argument
    else if !argument.codePoints().anyMatch(invisible(_)) then s"'${argument.replace("'", "'\\''")}'"
    else
      val escaped = new StringBuilder
      argument.codePoints().forEach: cp =>
        cp match
          case '\\'                   => escaped ++= "\\\\"
          case '\''                   => escaped ++= "\\'"
          case '\n'                   => escaped ++= "\\n"
          case '\t'                   => escaped ++= "\\t"
          case '\r'                   => escaped ++= "\\r"
          case cp if cp < 0x80 && invisible(cp) => escaped ++= f"\\x$cp%02x"
          case cp if invisible(cp) && cp <= 0xffff => escaped ++= f"\\u$cp%04x"
          case cp if invisible(cp) => escaped ++= f"\\U$cp%08x"
          case cp                  => escaped.appendAll(Character.toChars(cp))
      s"$$'$escaped'"

  /** Character.getType values the terminal would act on rather than show: escaped by renderArgument. */
  val InvisibleTypes: Set[Int] = Set(
    Character.CONTROL,
    Character.FORMAT,
    Character.LINE_SEPARATOR,
    Character.PARAGRAPH_SEPARATOR,
    Character.SURROGATE,
    Character.PRIVATE_USE,
    Character.UNASSIGNED,
  ).map(_.toInt)

  private def invisible(codePoint: Int): Boolean = InvisibleTypes.contains(Character.getType(codePoint))

  /** Below this a JVM build in the sandbox does not fit; the launch says so once. */
  val SmallMachineMemory: Long = 4L << 30

  /** Bodies stream independently of their total size. Eight concurrent TLS downloads throttled to
    * 1 MiB/s peaked near 60 MB, while sequential multi-gigabyte transfers remained bounded. Even
    * if the 64 MiB heap cap were entirely additional to the measured peak, the 256 MiB ceiling
    * would retain about 135 MiB for native and workload overhead. */
  val ProxyMemoryCeiling = "256m"

  /** `podman info --format '{{.Host.MemTotal}}'`, bytes; None when podman did not answer with one. */
  def memoryTotal(answer: HostCommands.Run): Option[Long] =
    if !answer.ok then None else answer.text.trim.toLongOption.filter(_ > 0)

  /**
   * The sandbox's default memory ceiling: 1 GiB under the total of the machine podman runs on —
   * the podman machine VM, or the host on native Linux — which is what podman, the workspace
   * filter and the kernel need to keep answering while the sandbox is at its limit; and no more
   * than the machine had available at launch, where that is known (hostMemoryAvailable), since a
   * native host is already running everything else and a VM that is short is short. What one
   * ceiling cannot bound is the sum: two sessions on one machine, or a host that grows busier
   * after the launch, still add up past it — KO_AGENT_SANDBOX_MEMORY is for that.
   *
   * The one exception to the available bound is MinimumCeiling (or the total, on a machine
   * smaller than that), below which the ceiling never goes: podman reads `--memory=0` as no limit
   * at all, which a host with nothing available would otherwise get at the moment it can least
   * afford it, and a sandbox capped under what its agent needs dies before it says anything. So
   * with under 1 GiB available the sandbox may still take 1 GiB; the entrypoint's warning is what
   * tells the user the machine was that short. The same floor is what a machine under 2 GiB gets.
   */
  def memoryCeiling(machineTotal: Long, availableAtLaunch: Option[Long]): Long =
    val fromTotal = machineTotal - (1L << 30)
    val bounded = availableAtLaunch.fold(fromTotal)(Math.min(fromTotal, _))
    Math.max(bounded, Math.min(MinimumCeiling, machineTotal))

  /** What the agent CLIs and one modest build need to start at all. */
  val MinimumCeiling: Long = 1L << 30

  /**
   * MemAvailable of this host, bytes: what podman's containers can take before the host itself
   * reclaims. Only where the launcher shares the kernel with them — native Linux; on a podman
   * machine `podman info` reports MemFree, which a warm page cache makes meaningless, and the
   * VM is the sandbox's alone.
   */
  def hostMemoryAvailable(os: Os, meminfo: => String): Option[Long] =
    os match
      case Os.Linux => memoryAvailable(meminfo)
      case _        => None

  /** `MemAvailable:` out of a `/proc/meminfo`, bytes. */
  def memoryAvailable(meminfo: String): Option[Long] =
    meminfo.linesIterator
      .map(_.trim.split("\\s+"))
      .collectFirst { case Array("MemAvailable:", kb, _*) => kb.toLongOption }
      .flatten
      .map(_ * 1024)

  /**
   * Warn before the image builds when the machine has less than this available. The threshold
   * sits below the cold-build peak the warning quotes on purpose: a default 4 GiB machine idles
   * near 3.3–3.6 GiB available, and a threshold the supported default trips at idle is a
   * warning users learn to ignore. 3 GiB tells the two machine states apart — quiet on an idle
   * default machine, loud once running sessions hold real memory, the state in which a build
   * degrades every session on the machine. The answer is the user's, not the launcher's — a
   * `[y/N]` prompt, not a refusal: the builder's own heap is pinned (the proxy Containerfile),
   * so proceeding risks a slow or OOM-killed build rather than a frozen machine, a price the
   * one at the console may accept; No stays the default because the sessions at stake may not
   * be theirs to spend. With no console there is nobody to ask, and the build proceeds warned —
   * one instant of MemAvailable is too noisy to stop automation on.
   */
  val BuildMemoryWarnThreshold: Long = 3L << 30

  def buildMemoryWarning(available: Option[Long]): Option[String] =
    available.filter(_ < BuildMemoryWarnThreshold).map: bytes =>
      s"the machine has ${gib(bytes)} of memory available; a cold image build peaks near 3.3 GiB\n" +
        "  exit running sandbox sessions, or raise it with `podman machine set --memory` (machine stopped)"

  /** After requirePodman's gate, every podman verb says the machine's headroom once, beside the
    * `using:` line — the figure the memory ceiling and the build gate act on, visible before
    * they act. A figure the machine cannot give prints nothing. */
  def machineMemoryLine(os: Os, total: Option[Long], available: Option[Long]): Option[String] =
    val label = if os == Os.Linux then "memory" else "podman machine memory"
    for
      totalBytes <- total
      availableBytes <- available
    yield s"$label: ${gibNumber(availableBytes)} / ${gibNumber(totalBytes)} GiB available"

  /**
   * MemAvailable of the machine the image builds run on: this host on native Linux, the VM
   * through `podman machine ssh` elsewhere — the one route to a machine figure, since `podman
   * info` offers only MemFree (hostMemoryAvailable has why that reads meaningless). None — no
   * field, ssh refused — skips the warning rather than blocking a build.
   */
  def machineMemoryAvailable(os: Os, meminfo: => String, machineSsh: => HostCommands.Run): Option[Long] =
    os match
      case Os.Linux => memoryAvailable(meminfo)
      case _        => Some(machineSsh).filter(_.ok).flatMap(answer => memoryAvailable(answer.text))

  /**
   * `--memory-swap` equal to `--memory` forbids swap: it is the thrash a ceiling exists to
   * prevent, and podman's default of twice the memory in swap is the wrong side of that. An
   * explicit ceiling gets the same treatment, for the same reason.
   */
  def memoryArguments(
    explicit: Option[String],
    machineTotal: Option[Long],
    availableAtLaunch: Option[Long],
  ): Vector[String] =
    explicit.map(_.trim).filter(_.nonEmpty) match
      case Some(value) => Vector(s"--memory=$value", s"--memory-swap=$value")
      case None =>
        machineTotal.map(memoryCeiling(_, availableAtLaunch)).toVector.flatMap: bytes =>
          Vector(s"--memory=$bytes", s"--memory-swap=$bytes")

  def gib(bytes: Long): String = s"${gibNumber(bytes)} GiB"

  private def gibNumber(bytes: Long): String = f"${bytes.toDouble / (1L << 30)}%.1f"

  /**
   * The KO_AGENT_SANDBOX_* names this launcher reads — plus KO_AGENT_SANDBOX_EGRESS_POLICY,
   * KO_AGENT_SANDBOX_JAVA_OPTS and KO_AGENT_SANDBOX_RUN_ON_HOST, which it sets inside the sandbox
   * rather than reads, so a launcher nested in a sandbox session is not warned about the variables
   * that session legitimately carries.
   */
  val KnownSandboxVariables: Set[String] = Set(
    "KO_AGENT_SANDBOX_JAVA_OPTS",
    "KO_AGENT_SANDBOX_IMAGE",
    "KO_AGENT_SANDBOX_PROXY_IMAGE",
    "KO_AGENT_SANDBOX_PERSISTENT_VOLUME",
    "KO_AGENT_SANDBOX_MEMORY",
    WorkspaceGuardVariable,
    NestingVariable,
    SessionStartVariable,
    ClipboardVariable,
    "KO_AGENT_SANDBOX_EGRESS_POLICY",
    RunOnHostChannel.RunOnHostVariable,
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
   * the builder keeps the name pattern stated once, in the builders above.
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
            "error: podman is not usable.\nOn Linux, run rootless podman as your normal user, without sudo.",
          )
        case _ =>
          System.err.println("the podman machine is not running; starting it")
          val started = run(podman, "machine", "start")
          if !started.ok then
            fail(
              s"""error: podman Machine could not be started.
                 |${started.err}
                 |
                 |Initialize it once, for example:
                 |  podman machine init""".stripMargin
            )
    machineMemoryLine(
      os,
      memoryTotal(run(podman, "info", "--format", "{{.Host.MemTotal}}")),
      probedMachineAvailable(os),
    ).foreach(System.err.println)

  def probedMachineAvailable(os: Os): Option[Long] =
    machineMemoryAvailable(
      os,
      readIfPresent(Paths.get("/proc/meminfo")).getOrElse(""),
      run(podman, "machine", "ssh", "cat /proc/meminfo"),
    )

  /** Both build verbs run this after requirePodman: --update rebuilds the leaves through the
    * same unceilinged `podman build`, so it shares --build's gate. */
  def confirmMemoryForBuilds(os: Os): Unit =
    buildMemoryWarning(probedMachineAvailable(os)).foreach: message =>
      warn(message)
      Option(System.console()).foreach: console =>
        console.printf("Continue anyway? [y/N] ")
        if !consented(Option(console.readLine())) then fail("error: build not started")

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
   * The product images and named build caches, in dependency order. Leaf images stay on
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
   * The exit code for a self-test that failed before its behavioral checks began, as against one
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

  /**
   * Each command echoed before it runs, so what follows is what podman prints for exactly that
   * line. A build's output says where its cache hit; a --quiet pull prints only the image id, so
   * the launcher reads the id before and after and says whether the tag moved, as its own
   * `pull:` line.
   */
  def runBuilds(context: Path, commands: Vector[Vector[String]]): Unit =
    commands.foreach: command =>
      echoCommand(command)
      val pulled = if command.lift(1).contains("pull") then command.lift(2) else None
      val before = pulled.flatMap(imageId(command.head, _))
      val exit = ProcessBuilder(command*)
        .directory(context.toFile)
        .inheritIO()
        .start()
        .waitFor()
      if exit != 0 then
        if pulled.isDefined then
          deleteRecursively(context)
          fail(s"error: image refresh failed: ${command.mkString(" ")}", exit)
        else
          fail(
            s"error: build failed: ${command.mkString(" ")}\n" +
              s"build context retained at $context",
            exit,
          )
      pulled.foreach: image =>
        System.err.println("pull: " + pullVerdict(before, imageId(command.head, image)))
    deleteRecursively(context)

  private def imageId(podman: String, image: String): Option[String] =
    val inspected = run(podman, "image", "inspect", "--format", "{{.Id}}", image)
    Option.when(inspected.ok && inspected.text.nonEmpty)(inspected.text)

  def pullVerdict(before: Option[String], after: Option[String]): String =
    (before, after) match
      case (Some(old), Some(now)) if old == now => "unchanged"
      case (Some(old), Some(_)) => s"updated from ${shortId(old)}"
      case (None, Some(_)) => "new on this machine"
      case (_, None) => "no local image after the pull"

  private def buildContextReader(context: Path): String => String =
    relative => Files.readString(context.resolve(relative))

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
   * eight-hex run suffix. `--reset-all` matches whole names against these patterns rather than
   * bare prefixes: it force-removes what it matches, and a prefix alone would also take a
   * user's own `ko-agent-sandbox-persistent-backup`. A pattern is not provenance, so the patterns
   * are a reserved namespace, stated as such in SECURITY.md ("Silent changes to what you own"):
   * an object hand-named inside one is removed like the launcher's own, and the one
   * launcher-adopted name — the shared volume — is refused when it strays into it
   * (sharedVolumeNameError).
   */
  private val ProjectIdShape = "[A-Za-z0-9._-]{1,32}-[0-9a-f]{12}"
  private val RunShape = s"$ProjectIdShape-[0-9a-f]{8}"

  /**
   * Why `name` may not serve as the shared agent-state volume, or None. The generated volume
   * pattern is `--reset-all`'s to remove by name, so adopting a user-supplied name inside it
   * would hand that sweep a volume it must not own — including another project's real volume,
   * spelled out to alias its sign-ins. Refused at launch, where the volume would be created and
   * used, rather than discovered at the reset that deletes it.
   */
  def sharedVolumeNameError(name: String): Option[String] =
    Option.when(name.matches(s"ko-agent-sandbox-persistent-$ProjectIdShape"))(
      s"KO_AGENT_SANDBOX_PERSISTENT_VOLUME is '$name', which has the launcher's generated " +
        "volume-name pattern, and --reset-all removes every volume matching it\n\n" +
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
   * cannot sit inside this pattern, because such a value refuses the launch (sharedVolumeNameError).
   */
  def persistentVolumes(names: Seq[String]): Seq[String] =
    names.filter(_.matches(s"ko-agent-sandbox-persistent-$ProjectIdShape"))

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

  def projectNetworks(names: Seq[String], projectId: String): Seq[String] =
    names.filter: name =>
      isRunNamed(sandboxRunNetwork, projectId)(name)
        || isRunNamed(egressRunNetwork, projectId)(name)

  /**
   * Created fresh every run: the name carries a random run suffix, so
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
    // After the container suites, the share rows — what those suites cannot reach
    // (SelfTestShare). Skipped under a filter: it selects crate cases, and the one-case loop
    // stays fast.
    def finish(suiteExit: Int): Nothing =
      if suiteExit != 0 || filter.isDefined then sys.exit(suiteExit)
      sys.exit(SelfTestShare.shareRows(podman, os, resolveProjectDir()))

    val unprivileged = selfTestRunCommand(podman, filter, asRoot = false)
    echoCommand(unprivileged)
    val exit = ProcessBuilder(unprivileged*).inheritIO().start().waitFor()
    if exit != SelfTestVenueExit then finish(exit)

    System.err.println(
      "note: the filter's self-test failed at the venue rather than at a check; retrying as\n" +
        "  root. Its own message above is the report of what failed, and this launcher does not\n" +
        "  narrow it further. If root serves, this venue never exercises the setuid fusermount3\n" +
        "  route a session takes, which is worth recording with its venue\n" +
        "  (fuse/ko-agent-fs/doc/verification-log.md).",
    )
    val privileged = selfTestRunCommand(podman, filter, asRoot = true)
    echoCommand(privileged)
    finish(ProcessBuilder(privileged*).inheritIO().start().waitFor())

  /** The podman build the venue record names, so a run is evidence rather than an outcome. */
  def podmanVersion(): String =
    val reported = run(podman, "--version")
    if reported.ok then reported.text.trim else "podman version unknown"

  def stepOk(command: String*): Boolean =
    echoCommand(command)
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

  /** The shared front half of the egress preflights: this project's vetted policy files,
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
    resolved.err.linesIterator.filter(_.startsWith("warning:")).foreach(line => System.err.println(emphasized(line)))

    val caCert = tlsStateRoot(os).resolve(projectId).resolve("ca.crt")
    if Files.isRegularFile(caCert) then System.err.println(s"egress tls ca: $caCert")
    System.err.println(s"egress log dir: ${logStateRoot(os).resolve(projectId)}")
    sys.exit(0)

  /**
   * One host's policy decision and current resolution, through a one-shot proxy container on a
   * per-run network built like a session's egress network (AgentEgressProxy.checkHost has why the
   * two are reported apart and why the resolver must be enforcement's).
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
   * `--reset` (README has what it removes). Every other project's state and the built images are
   * left alone.
   */
  def resetProject(os: Os): Nothing =
    val projectDir = resolveProjectDir()
    // Before the deletions below: a state root inside the project directory must refuse here, not aim
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
    echoCommand(Vector("rm", "-rf", tls.toString))
    deleteRecursively(tls)

    val policyCache = policyStateRoot(os).resolve(id)
    echoCommand(Vector("rm", "-rf", policyCache.toString))
    deleteRecursively(policyCache)

    // The audit trail goes with the rest of the project's state: "reset" means "as if this project had never been
    // opened". Copy the files out first if a session's refusals still matter.
    val logs = logStateRoot(os).resolve(id)
    echoCommand(Vector("rm", "-rf", logs.toString))
    deleteRecursively(logs)

    // The project's filter daemon and mountpoint, where the feature has been used. Best effort by
    // design: with no machine running there is nothing mounted to tear down.
    System.err.println(s"unmounting the ${koAgentFsLabel(os)}, if mounted")
    if !runOk(koAgentFsScriptCommand(podman, os, koAgentFsUnmountScript(id))*) then
      System.err.println("note: filter unmount skipped (no machine running, or nothing mounted)")

    if failures > 0 then fail(s"error: $failures reset steps failed")
    sys.exit(0)

  /**
   * `--reset-all`, every project's `--reset`. It deliberately does not remove built images or
   * their valid pending-cleanup journal: image-producing verbs own both, and the images are costly
   * to rebuild (`podman image rm` removes them by hand). A malformed journal is repaired because
   * it names no image the launcher can safely remove.
   */
  def resetAll(os: Os): Nothing =
    // The workstation-wide deletions below run wherever the state and cache roots point; both
    // roots are resolved and checked against the current directory before the first of them.
    val project = resolveProjectDir()
    requireStateRootOutside(os, project)
    // The whole build-cache root, removed last: every project's host-build caches go with
    // everything else.
    val caches = buildCacheRoot(os, project)
    val imageState = stateRoot(os).resolve("image-build")
    val cleanupJournal = imageState.resolve("cleanup.ids")
    if Files.exists(cleanupJournal) then
      withFileLock(imageState.resolve("lock")):
        repairImageCleanupJournal(cleanupJournal)
    var failures = 0

    def listed(command: String*): Vector[String] =
      echoCommand(command)
      val result = run(command*)
      if !result.ok then
        failures += 1
        System.err.println(result.err)
      result.text.linesIterator.map(_.trim).filter(_.nonEmpty).toVector

    def remove(command: String*): Unit = if !stepOk(command*) then failures += 1

    val containers = listed(podman, "ps", "-a", "--format", "{{.Names}}")
    (proxyContainers(containers) ++ sandboxRunContainers(containers) ++
      SelfTestShare.probeContainers(containers))
      .foreach(name => remove(podman, "rm", "--force", name))

    persistentVolumes(listed(podman, "volume", "ls", "--format", "{{.Name}}"))
      .foreach(name => remove(podman, "volume", "rm", name))

    launcherNetworks(listed(podman, "network", "ls", "--format", "{{.Name}}"))
      .foreach(name => remove(podman, "network", "rm", name))

    val tls = tlsStateRoot(os)
    echoCommand(Vector("rm", "-rf", tls.toString))
    deleteRecursively(tls)

    val policyCache = policyStateRoot(os)
    echoCommand(Vector("rm", "-rf", policyCache.toString))
    deleteRecursively(policyCache)

    val logs = logStateRoot(os)
    echoCommand(Vector("rm", "-rf", logs.toString))
    deleteRecursively(logs)

    // Every project's filter mount. Best effort, as in the per-project reset.
    System.err.println(s"unmounting every project's ${koAgentFsLabel(os)}, if mounted")
    if !runOk(koAgentFsScriptCommand(podman, os, koAgentFsUnmountAllScript)*) then
      System.err.println("note: filter unmount skipped (no machine running, or nothing mounted)")

    echoCommand(Vector("rm", "-rf", caches.toString))
    deleteRecursively(caches)

    if failures > 0 then fail(s"error: $failures reset steps failed")
    sys.exit(0)

  /**
   * The build-cache root, refused when it would sit inside the project — the check every verb
   * that deletes under it makes, as [[requireStateRootOutside]] does for the state root and with
   * the same [[couldBeAProject]] exemption; from an exempt directory only the root's own
   * resolution can refuse. The canonical answer either way, since deletion follows it.
   */
  private def buildCacheRoot(os: Os, project: Path): Path =
    RunOnHostPolicy
      .cacheRootOf(os, env)
      .flatMap: root =>
        if couldBeAProject(os, project) then
          RunOnHostPolicy.cacheRootOutsideProject(root, project, os, canonicalizedFuturePath)
        else
          canonicalizedFuturePath(root).left.map(RunOnHostPolicy.Refusal.CacheRootUnusable(_))
      .fold(
        refusal =>
          val reason = refusal match
            case RunOnHostPolicy.Refusal.CacheRootUnusable(text) => text
            case other                                           => other.toString
          fail(s"error: cache root: $reason"),
        identity,
      )

  /**
   * This project's build caches — what its host builds resolved — removed as one directory;
   * sessions, volume and state stay. `--reset` leaves these caches alone deliberately: resetting
   * is about a stuck session, and silently discarding a warm cache would cost a full re-download
   * nobody asked for.
   */
  def resetCache(os: Os): Nothing =
    val project = resolveProjectDir()
    val caches = RunOnHostPolicy.agentCacheDir(buildCacheRoot(os, project), projectIdOf(project, os))
    echoCommand(Vector("rm", "-rf", caches.toString))
    deleteRecursively(caches)
    sys.exit(0)

  /** One project's disk use across the launcher's state and build-cache roots. */
  final case class ProjectUsage(id: String, stateBytes: Long, cacheBytes: Long)

  /**
   * A read-only report, because a size seen only while resetting is seen too late. The live
   * section is answered first and skipped when the podman machine is stopped — a report starts
   * nothing — and the directory walk is last: a real Coursier cache is millions of inodes, which
   * is why this is a verb and not a line printed at every launch.
   */
  def stats(os: Os): Nothing =
    System.out.print(liveSessionsSection(os))
    val stateDirs = Vector(tlsStateRoot(os), logStateRoot(os), policyStateRoot(os))
    val cacheDir = RunOnHostPolicy.cacheRootOf(os, env).toOption.map(_.resolve("cache"))
    val ids = (stateDirs ++ cacheDir.toVector).flatMap(childNames).distinct.sorted
    val usages = ids.toVector.map: id =>
      ProjectUsage(
        id,
        stateDirs.map(dir => directoryBytes(dir.resolve(id))).sum,
        cacheDir.map(dir => directoryBytes(dir.resolve(id))).getOrElse(0L),
      )
    System.out.print(statsReport(usages, freeSpace(cacheDir.getOrElse(stateRoot(os)))))
    sys.exit(0)

  /**
   * Pure for the tests. The flag threshold is 1% of the cache filesystem's free space, so the
   * report says which project to `--reset-cache` rather than leaving a column of numbers to
   * compare by eye.
   */
  def statsReport(usages: Vector[ProjectUsage], cacheFreeBytes: Long): String =
    val footer = s"free space where the caches live: ${humanBytes(cacheFreeBytes)}\n"
    if usages.isEmpty then "projects: none\n" + footer
    else
      val header = f"""  ${"total"}%10s  ${"state"}%10s  ${"cache"}%10s  project"""
      val rows = usages.sortBy(usage => -(usage.stateBytes + usage.cacheBytes)).map: usage =>
        val flag =
          if usage.cacheBytes * 100 > cacheFreeBytes then
            "  <- cache over 1% of free space; a --reset-cache candidate"
          else ""
        f"  ${humanBytes(usage.stateBytes + usage.cacheBytes)}%10s  ${humanBytes(usage.stateBytes)}%10s" +
          f"  ${humanBytes(usage.cacheBytes)}%10s  ${usage.id}$flag"
      ("projects by size, largest first:\n" + (header +: rows).mkString("", "\n", "\n") + footer)

  /**
   * Sizes from bytes to TiB in one column: a Coursier cache is gigabytes while a policy cache is
   * kilobytes, and one fixed unit would flatten one of them.
   */
  def humanBytes(bytes: Long): String =
    val units = Vector("B", "KiB", "MiB", "GiB", "TiB")
    var value = bytes.toDouble
    var index = 0
    while value >= 1024 && index < units.size - 1 do
      value /= 1024
      index += 1
    if index == 0 then s"$bytes B" else f"$value%.1f ${units(index)}"

  /** Sessions running now, from `podman stats`; a missing podman or a stopped machine is a note,
    * never a start. */
  private def liveSessionsSection(os: Os): String =
    findOnPath("podman", env("PATH").getOrElse(""), os).map(_.toString) match
      case None => "live sessions: not queried; podman is not on PATH\n"
      case Some(found) =>
        val machineDown = os != Os.Linux && {
          val machines = run(found, "machine", "list", "--format", "{{.Running}}")
          !machines.ok || !machines.text.linesIterator.map(_.trim).contains("true")
        }
        if machineDown then "live sessions: not queried; the podman machine is not running\n"
        else
          val result =
            run(found, "stats", "--no-stream", "--format", "{{.Name}} {{.MemUsage}} {{.CPUPerc}}")
          if !result.ok then
            val reason = result.err.linesIterator.nextOption().getOrElse("").trim
            s"live sessions: podman stats failed: $reason\n"
          else
            liveSessionRows(result.text.linesIterator.toVector) match
              case Vector() => "live sessions: none\n"
              case rows     => rows.mkString("live sessions:\n  ", "\n  ", "\n")

  /** Only this launcher's containers: another workload on the same machine is not the report's. */
  def liveSessionRows(lines: Vector[String]): Vector[String] =
    lines.filter: line =>
      val name = line.takeWhile(_ != ' ')
      proxyContainers(Seq(name)).nonEmpty || sandboxRunContainers(Seq(name)).nonEmpty

  /** Continues past races and permission holes: sizing must not fail on a tree a session is
    * changing. */
  def directoryBytes(root: Path): Long =
    if !Files.exists(root) then 0L
    else
      var total = 0L
      Files.walkFileTree(
        root,
        new SimpleFileVisitor[Path]:
          override def visitFile(file: Path, attrs: BasicFileAttributes) =
            if attrs.isRegularFile then total += attrs.size()
            FileVisitResult.CONTINUE
          override def visitFileFailed(file: Path, exc: IOException) = FileVisitResult.CONTINUE,
      )
      total

  private def childNames(dir: Path): Vector[String] =
    if !Files.isDirectory(dir) then Vector.empty
    else
      val stream = Files.list(dir)
      try stream.iterator().asScala.map(_.getFileName.toString).toVector
      finally stream.close()

  /** Of the filesystem holding `path`, read at its nearest existing ancestor: the cache root does
    * not exist before the first host build. */
  private def freeSpace(path: Path): Long =
    var probe = path.toAbsolutePath
    while !Files.exists(probe) && probe.getParent != null do probe = probe.getParent
    try Files.getFileStore(probe).getUsableSpace
    catch case _: IOException => 0L

  /**
   * Per-user state, outside any project directory: nothing in it is the
   * agent's to read or rewrite. %LOCALAPPDATA% is per user and not roamed.
   *
   * Validated, not adopted: the value must be absolute — a relative one resolves against the
   * current directory, which is the project directory, and would hand the CA signing key
   * to the sandbox (and aim `--reset-all`'s recursive deletions into the project directory). It is
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
   * Whether a launch could accept `dir` as this project — the exemption the containment checks
   * ([[requireStateRootOutside]], [[buildCacheRoot]]) share: a directory a launch itself refuses,
   * a home or a filesystem root, cannot be a project, and the default state and cache layouts
   * (`~/.local/state`, `~/.cache`) sit inside a home as the normal case, not a breach. An
   * unanswerable home discovery keeps the checks, the fail-closed side.
   */
  private def couldBeAProject(os: Os, dir: Path): Boolean =
    protectedHomeDirectories(os, env) match
      case Right(protection) => forbiddenProjectDirReason(dir, protection).isEmpty
      case Left(_)           => true

  /**
   * The containment check for the verbs run *from* a directory: refuse when the state root lies
   * inside what a launch would accept as this project. Every caller that deletes or reads under
   * the state root calls this before touching it.
   */
  def requireStateRootOutside(os: Os, projectDir: Path): Unit =
    if couldBeAProject(os, projectDir) then
      forbiddenStateRootReason(os, stateRoot(os), projectDir).foreach(fail(_))

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
   * The independent authority options, selected on every launch and never persisted by a
   * stage or an agent resume. The writable default is `live` (doc/plan-staged.md has the staged
   * mode and the default flip that follow it); no distributable build may make launches with no
   * `--write` option read-only before the staged workflow is usable.
   */
  val WriteModes = Vector("reject", "live")
  val DefaultWriteMode = "live"
  val EgressProfiles =
    Vector("deny-all", "deny-unless-model", "deny-unless-allowed", "allow-unless-denied")
  val DefaultEgressProfile = "deny-unless-allowed"

  /** The tools `--run-on-host` can name. Available on macOS only, which
    * launch() enforces: the parser stays pure over the arguments. */
  val RunOnHostTools = Vector("sbt", "mill")

  def parseRunOnHost(value: String): Either[String, Vector[String]] =
    val names = value.split(",", -1).toVector
    names.find(name => !RunOnHostTools.contains(name)) match
      case Some(bad) =>
        Left(s"error: --run-on-host=$bad; the tools are ${RunOnHostTools.mkString(", ")}, exactly")
      case None if names.distinct != names => Left(s"error: --run-on-host=$value names a tool twice")
      case None                            => Right(names)

  /** `--env=NAME` (value: the host's, read at launch) or `--env=NAME=VALUE`. */
  case class EnvForward(name: String, value: Option[String])

  val EnvironmentName = "[A-Za-z_][A-Za-z0-9_]*".r

  /**
   * The one thing `--env` refuses: the launcher's own KO_AGENT_SANDBOX_* variables, which are how
   * it tells the sandbox what is in force — the resolved egress policy, the nesting, clipboard and
   * session-start modes. Forwarded, one would make what the agent is told differ from what is
   * enforced, the drift the launcher exists to rule out. Every other variable the launcher or the
   * image sets (the proxy and CA-bundle variables, TZ, PAGER) is forwardable: the network has no
   * route but the proxy whatever the environment says, so an override can only fail, visibly,
   * under a name the launch printed — and overriding a default is what a forward is for.
   */
  val RefusedForwardPrefix = "KO_AGENT_SANDBOX_"

  /**
   * The `--env=NAME=VALUE` arguments for the forwards, or why one cannot be made. A name unset
   * on the host is an error, not an empty variable: a forward that configures nothing is the
   * silent failure the KO_AGENT_SANDBOX_* typo warning exists for. Values never reach a log or
   * the screen — a forward is how a secret gets in, and SECURITY.md ("Credential theft") is what
   * that costs.
   */
  def forwardedEnvironment(
    forwards: Vector[EnvForward],
    hostEnv: String => Option[String],
  ): Either[String, Vector[String]] =
    forwards.map(_.name).find(_.startsWith(RefusedForwardPrefix)) match
      case Some(name) =>
        Left(s"error: --env=$name; the launcher sets $RefusedForwardPrefix* itself, and a forward would replace it")
      case None => resolve(forwards, hostEnv)

  private def resolve(forwards: Vector[EnvForward], hostEnv: String => Option[String]): Either[String, Vector[String]] =
    val resolved = forwards.map: forward =>
      forward.value.orElse(hostEnv(forward.name)).toRight(forward.name)
        .map(value => s"--env=${forward.name}=$value")
    resolved.collectFirst { case Left(name) => name } match
      case Some(name) =>
        Left(s"error: --env=$name; the variable is not set on the host, so there is nothing to forward")
      case None => Right(resolved.collect { case Right(arg) => arg })

  /** Parsed launcher invocation: the authority options as given (None when defaulted), then
    * either one management verb with its operands, or the command forwarded verbatim. */
  case class ParsedCommandLine(
    write: Option[String],
    egress: Option[String],
    verb: Option[(String, List[String])],
    command: List[String],
    env: Vector[EnvForward] = Vector.empty,
    runOnHost: Option[Vector[String]] = None,
    autoShutdownForeignSbt: Boolean = false,
  ):
    def writeMode: String = write.getOrElse(DefaultWriteMode)
    def egressProfile: String = egress.getOrElse(DefaultEgressProfile)

  val ManagementVerbs: Set[String] =
    Set(
      "--help", "--build", "--update", "--reset", "--reset-cache", "--reset-all", "--stats",
      "--proxy-log", "--egress-effective", "--self-test",
    )

  /**
   * Outside a management verb's documented operands, the first non-option is the command and
   * ends launcher parsing; everything after it is passed verbatim. `--` is an optional escape
   * for a command that could look like a launcher option; no launcher option is parsed after
   * the command. An option this launcher does not parse refuses the launch rather than passing
   * through — authority is never configured by a spelling that is not read.
   */
  def parseCommandLine(args: List[String]): Either[String, ParsedCommandLine] =
    def choose(option: String, value: String, choices: Vector[String]): Either[String, String] =
      if choices.contains(value) then Right(value)
      else Left(s"error: $option=$value; the values are ${choices.mkString(", ")}, exactly")

    def loop(
      rest: List[String],
      write: Option[String],
      egress: Option[String],
      env: Vector[EnvForward],
      runOnHost: Option[Vector[String]],
      autoShutdown: Boolean,
    ): Either[String, ParsedCommandLine] =
      rest match
        case Nil =>
          Right(ParsedCommandLine(write, egress, None, Nil, env, runOnHost, autoShutdown))
        case "--" :: command =>
          Right(ParsedCommandLine(write, egress, None, command, env, runOnHost, autoShutdown))

        case arg :: tail if arg.startsWith("--write=") =>
          if write.isDefined then Left("error: --write is given twice")
          else choose("--write", arg.stripPrefix("--write="), WriteModes)
            .flatMap(value => loop(tail, Some(value), egress, env, runOnHost, autoShutdown))

        case arg :: tail if arg.startsWith("--egress=") =>
          if egress.isDefined then Left("error: --egress is given twice")
          else choose("--egress", arg.stripPrefix("--egress="), EgressProfiles)
            .flatMap(value => loop(tail, write, Some(value), env, runOnHost, autoShutdown))

        case arg :: tail if arg.startsWith("--run-on-host=") =>
          if runOnHost.isDefined then Left("error: --run-on-host is given twice")
          else parseRunOnHost(arg.stripPrefix("--run-on-host="))
            .flatMap(tools => loop(tail, write, egress, env, Some(tools), autoShutdown))

        case RunOnHostSandbox.AutoShutdownForeignSbtOption :: tail =>
          if autoShutdown then
            Left(s"error: ${RunOnHostSandbox.AutoShutdownForeignSbtOption} is given twice")
          else loop(tail, write, egress, env, runOnHost, true)

        case arg :: tail if arg.startsWith("--env=") =>
          val (name, value) = arg.stripPrefix("--env=").span(_ != '=')
          if !EnvironmentName.matches(name) then
            Left(s"error: --env=$name; a variable is named [A-Za-z_][A-Za-z0-9_]*")
          else if env.exists(_.name == name) then Left(s"error: --env=$name is given twice")
          else
            loop(
              tail, write, egress,
              env :+ EnvForward(name, Option.when(value.nonEmpty)(value.drop(1))), runOnHost,
              autoShutdown,
            )

        case ("--write" | "--egress" | "--env" | "--run-on-host") :: _ =>
          Left(
            "error: the launch options are spelled --write=<mode>, --egress=<profile>, " +
              "--env=<name>[=<value>] and --run-on-host=<tools>",
          )

        case arg :: tail if arg.startsWith("--egress-check=") =>
          Right(
            ParsedCommandLine(
              write, egress,
              Some(("--egress-check", arg.stripPrefix("--egress-check=") :: tail)),
              Nil, env, runOnHost, autoShutdown,
            ),
          )

        case verb :: tail if ManagementVerbs(verb) =>
          Right(ParsedCommandLine(write, egress, Some((verb, tail)), Nil, env, runOnHost, autoShutdown))

        case arg :: _ if arg.startsWith("--") =>
          Left(s"error: unknown option $arg\nRun --help for the launcher verbs.")

        case command =>
          Right(ParsedCommandLine(write, egress, None, command, env, runOnHost, autoShutdown))

    loop(args, None, None, Vector.empty, None, false).flatMap: parsed =>
      if parsed.autoShutdownForeignSbt && !parsed.runOnHost.exists(_.contains("sbt")) then
        Left(
          s"error: ${RunOnHostSandbox.AutoShutdownForeignSbtOption} needs --run-on-host to name sbt",
        )
      else Right(parsed)

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
   * confusing way to learn that these instructions drifted. AgentSandboxLauncherTest holds the
   * instruction vocabulary to the proxy source.
   */
  def authoritySection(
    writeMode: String,
    workspaceGuard: String,
    resolved: String,
    runOnHost: Vector[String] = Vector.empty,
    // Whether this host could serve --run-on-host at all (macOS): a session without the option
    // then gets one discovery line, and other platforms hear nothing about a command they can
    // never have. Constant per machine, so the agents.md stamp needs no part of it.
    hostBuildsAvailable: Boolean = false,
  ): String =
    val indented = resolved.linesIterator.map("    " + _).mkString("\n")
    val workspace = (writeMode, workspaceGuard) match
      // The plain reject instruction would be false under --run-on-host: a host build writes the
      // project (SECURITY.md "Run on host", the --write=reject composition).
      case ("reject", _) if runOnHost.nonEmpty =>
        """`/workspace` is read-only to this session's own writes; only builds through
          |`sandbox-run-on-host` write the project, on the host. For anything a build does not
          |write, put results under `~` or `/tmp` and tell the user, who relaunches with
          |`--write=live` for a writable session.""".stripMargin
      case ("reject", _) =>
        """`/workspace` is read-only this session. Do not attempt writes there; put results under
          |`~` or `/tmp` and tell the user, who relaunches with `--write=live` for a writable
          |session.""".stripMargin
      case ("live", "fuse") =>
        """`/workspace` is writable and shared live with the host project directory through the
          |`ko-agent-fs` filter. Git control state and `.ko-agent-sandbox` are frozen at any depth;
          |symlink targets must be relative and remain inside the workspace.""".stripMargin
      case ("live", "none") =>
        s"""`/workspace` is a raw writable bind shared live with the host project directory.
           |Raw guard: $RawWorkspaceBoundary. Nested repository control state and non-portable
           |symlinks remain writable.""".stripMargin
      case _ =>
        throw IllegalArgumentException(s"unknown workspace authority: $writeMode/$workspaceGuard")
    val hostBuilds =
      if runOnHost.nonEmpty then
        val commands = runOnHost.map(tool => s"`sandbox-run-on-host $tool …`").mkString(" or ")
        s"""
           |## Host builds
           |
           |Run this project's Scala builds with $commands: they run on the
           |host, sandboxed to the project, per-project build caches and one artifact repository,
           |and they may write the project except git control state and `.ko-agent-sandbox`.
           |Prefer them: a container build takes podman machine memory that is never returned, a
           |host build runs at host speed on memory reclaimed when it exits. Each invocation
           |starts and ends its own sbt server, so batch commands into one —
           |`sandbox-run-on-host sbt compile test`. Container `sbt` still works, over the same
           |`target/` — host and container builds compile with different JVMs against different
           |caches, so switching between them can cost a rebuild or need cleanup first ("The
           |host's own symlinks"). A host build that fails or is refused is reported to the user,
           |never re-run in the container. The environment variable
           |`${RunOnHostChannel.RunOnHostVariable}` carries this tool list.
           |""".stripMargin
      else if hostBuildsAvailable then
        s"""
           |## Host builds
           |
           |`sandbox-run-on-host` is absent from this session. If sbt or `mill` builds here are
           |slow, or the machine is short on memory, tell the user: relaunching with
           |`--run-on-host=sbt,mill` runs them on the host — memory reclaimed on exit rather than
           |left with the podman machine, at host speed, and without the symlink cleanup that
           |switching between container and host builds needs ("The host's own symlinks").
           |""".stripMargin
      else ""
    s"""
       |
       |# Authority in force for this session
       |
       |$workspace
       |$hostBuilds
       |## Egress
       |
       |Resolved at launch by the proxy itself, so it is what is enforced rather than a copy
       |that can drift. `KO_AGENT_SANDBOX_EGRESS_POLICY` carries the same lines.
       |Anything not admitted below is refused. An unrestricted host is an opaque tunnel; a
       |restricted host answers GET and HEAD plus only the named allowances shown below.
       |`allow=git-fetch` serves `clone` and `pull`; `git push` is always refused.
       |
       |$indented
       |
       |If a package registry or clone host you need is not admitted, do not look for another
       |route: name the host to the user, who adds it to `.ko-agent-sandbox/egress/allowed` on
       |the host and relaunches — under the default deny-unless-allowed profile or a broader
       |one, if this session's profile does not admit project hosts at all.
       |""".stripMargin

  def agentDocumentStamp(
    imageId: String,
    writeMode: String,
    workspaceGuard: String,
    policyResolvedText: String,
    agentInstructions: Option[String],
    runOnHost: Vector[String] = Vector.empty,
  ): String =
    s"$imageId $writeMode $workspaceGuard ${sha256Hex(policyResolvedText)} "
      + agentInstructions.fold("image")(sha256Hex)
      + (if runOnHost.isEmpty then "" else s" ${runOnHost.mkString(",")}")

  def main(args: Array[String]): Unit =
    // The private verbs, before the ordinary parse and in no usage text: they are not launch
    // surface, and nothing outside this codebase spells them. Each re-invokes the launcher's own
    // vehicle — jar or native image (RunOnHostSandbox.selfInvocation). --serve-proxy-on-host
    // hosts a build's egress proxy, configured by the EGRESS_* environment as in the container;
    // --serve-run-on-host is the session's command broker (RunOnHostChannel), and
    // --run-build-on-host one channel request as the broker's own child.
    args.headOption match
      case Some("--serve-proxy-on-host") if args.length == 1 =>
        agentsandbox.egress.AgentEgressProxy.serve()
      case Some("--serve-run-on-host")  => RunOnHostChannel.serveMain(args.toSeq.drop(1))
      case Some("--run-build-on-host")  => RunOnHostSandbox.runBuildMain(args.toSeq.drop(1))
      case _                            => launcherMain(args)

  private def launcherMain(args: Array[String]): Unit =
    unknownSandboxVariables(System.getenv().keySet().asScala).foreach: name =>
      warn(s"$name is not a variable this launcher reads; a misspelling configures nothing")

    val parsed = parseCommandLine(args.toList).fold(fail(_), identity)

    // The verbs that read no authority option refuse one rather than ignoring it: a selection
    // that configures nothing is the silent-authority failure mode the options must not have.
    def noAuthorityOptions(verb: String): Unit =
      if parsed.write.isDefined || parsed.egress.isDefined || parsed.env.nonEmpty
        || parsed.runOnHost.isDefined
      then fail(s"error: $verb reads no launch option; drop --write/--egress/--env/--run-on-host")
    def noWriteOption(verb: String): Unit =
      if parsed.write.isDefined || parsed.env.nonEmpty || parsed.runOnHost.isDefined then
        fail(s"error: $verb reads no --write, --env or --run-on-host option; drop it")

    parsed.verb match
      case Some(("--help", _)) =>
        noAuthorityOptions("--help")
        usage()

      case Some(("--build", rest)) =>
        noAuthorityOptions("--build")
        if rest.nonEmpty then fail("error: --build takes no further arguments")
        requirePodman(currentOs)
        confirmMemoryForBuilds(currentOs)
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
        confirmMemoryForBuilds(currentOs)
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

      case Some(("--reset-cache", rest)) =>
        noAuthorityOptions("--reset-cache")
        if rest.nonEmpty then fail("error: --reset-cache takes no further arguments")
        resetCache(currentOs)

      case Some(("--reset-all", rest)) =>
        noAuthorityOptions("--reset-all")
        if rest.nonEmpty then fail("error: --reset-all takes no further arguments")
        requirePodman(currentOs)
        resetAll(currentOs)

      // No requirePodman(): the report is read-only and reads host directories either way; the
      // live section degrades to a note when podman or its machine is not there to answer.
      case Some(("--stats", rest)) =>
        noAuthorityOptions("--stats")
        if rest.nonEmpty then fail("error: --stats takes no further arguments")
        stats(currentOs)

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
   * exists, and the working directory is the project directory.
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


    val image = env("KO_AGENT_SANDBOX_IMAGE").getOrElse("ko-agent-sandbox:latest")

    // Read before anything is created, like the egress policy below: a variable that would weaken
    // the boundary must not be discovered halfway through a launch that has already made resources.
    // It selects among live mode's guards only; reject binds the tree read-only and has nothing
    // for either mechanism to guard.
    val guard = workspaceGuard(env(WorkspaceGuardVariable)).fold(fail(_), identity)
    val nesting = nestingMode(env(NestingVariable)).fold(fail(_), identity)
    val sessionStartMode = sessionStart(env(SessionStartVariable)).fold(fail(_), identity)
    val clipboard = clipboardMode(env(ClipboardVariable)).fold(fail(_), identity)
    val clipboardHost =
      ClipboardBroker.hostBackend(clipboard, os, env("PATH").getOrElse("")).fold(fail(_), identity)
    // Raw, not HostCommands.env: that one reads an empty variable as unset, which is right for the
    // launcher's own settings and wrong here, where set-but-empty is a value to forward.
    val forwardedEnv = forwardedEnvironment(parsed.env, name => Option(System.getenv(name))).fold(fail(_), identity)

    // macOS only (run-on-host.md "Why only macOS"): elsewhere there is no Seatbelt backend, and a
    // container build already runs at host speed on host memory.
    val runOnHost = parsed.runOnHost.getOrElse(Vector.empty)
    if runOnHost.nonEmpty && os != Os.Mac then
      fail("error: --run-on-host is available on macOS only; on this host, run the build in the container")

    val projectDir = resolveProjectDir()

    // -----------------------------------------------------------------------
    // Refuse obviously wrong project directories
    // -----------------------------------------------------------------------
    val homeProtection = protectedHomeDirectories(os, env).fold(fail(_), identity)
    homeProtection.warnings.foreach(warn)
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
    // relabels the project directory — a recursive host-metadata write, which is exactly the authority
    // reject withholds. Refused rather than relabeled, unless the tree already carries a
    // shared container-accessible context, where a plain read-only bind needs no host write.
    if writeMode == "reject" && selinuxEnforcing && !selinuxContainerReadable(projectDir) then
      fail(
        s"""error: --write=reject cannot mount $projectDir on this SELinux-enforcing host
           |Reading a raw bind here requires relabeling the project directory (:Z), a recursive
           |host-metadata write that reject must not perform. Use --write=live — the filter's
           |mountpoint needs no relabel — or relabel the project yourself
           |(chcon -R -t container_file_t -l s0 <dir>; the level clears any categories a
           |previous :Z minted for one container) and relaunch.""".stripMargin
      )

    // -----------------------------------------------------------------------
    // Per-project identity
    // -----------------------------------------------------------------------
    //
    // Names this project directory and suffixes everything podman holds for it. The directory name alone would
    // collide — two project directories called `app` must not share credentials or a policy — so the hash covers
    // the whole path; moving a project yields new resources and new sign-ins.
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

    val imageInspect = run(
      podman, "image", "inspect",
      "--format",
      "{{.Id}}{{println}}" + // the CA-bundle and agents.md stamps below
        s"$BundleLabelTemplate{{println}}" + // the version lock
        "{{range .Config.Env}}{{println .}}{{end}}", // JdkTrust's JAVA_HOME
      image,
    ).text
    val imageId = imageInspect.linesIterator.nextOption().getOrElse("")
    val imageLabel = imageInspect.linesIterator.drop(1).nextOption().getOrElse("")
    val imageEnv = imageInspect.linesIterator.drop(2).mkString("\n")

    // A jar upgrade must never run silently against last month's images; checked before any
    // resource exists. bundleMismatch has the refuse-versus-warn reasoning.
    bundleMismatch(image, bundledSourceId("ko-agent-sandbox"), imageLabel).foreach: mismatch =>
      if env("KO_AGENT_SANDBOX_IMAGE").isDefined then warn(mismatch)
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
          warn(mismatch)
        else fail(s"error: $mismatch")

    // -----------------------------------------------------------------------
    // This project's policy
    // -----------------------------------------------------------------------
    //
    // The project's egress/ is read here on the host and handed to the proxy at startup.
    // policyDirError and readPolicyFiles have the forms, SECURITY.md the why. What keeps a
    // session from writing the next one's policy is the write mode itself: reject's read-only
    // tree, or live's FUSE reserved-name rule; only guard=none needs the read-only mount-back
    // (policyGuardArgs below).
    val policyDir = projectDir.resolve(".ko-agent-sandbox")
    policyDirError(policyDir).foreach(fail(_))

    val policyFiles = readPolicyFiles(policyDir.resolve("egress")).fold(fail(_), identity)
    // The project's replacement for the image's AGENTS-CUSTOM.md, read here for the same reason
    // the policy is: a session must not rewrite the instructions governing the next one.
    val agentInstructions = readAgentInstructions(policyDir.resolve("agent")).fold(fail(_), identity)
    agentInstructions.foreach: _ =>
      System.err.println(
        s"agent instructions: .ko-agent-sandbox/agent/$AgentInstructionsFile replaces the image's",
      )

    // The provider the launched command selects, and the one warning that is the launcher's to
    // print: the proxy never sees the command, so "this command selects no provider" cannot come
    // from its resolution.
    val provider = commandProvider(command.headOption)
    if egressProfile == "deny-unless-model" && provider.isEmpty then
      warn(
        s"'${command.headOption.getOrElse("bash")}' is not a recognized agent command, " +
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

    // The leaf's names, from the dry run (inspectedHostsOf); a policy change reissues the leaf
    // through leaf.sans below. Empty: no leaf, no inspection material.
    val inspectedHosts = inspectedHostsOf(policyResolvedText).fold(fail(_), identity)

    // The workspace FUSE filter, mounted before any volume is assembled (the lifecycle banner above
    // ensureKoAgentFsMounted has the layout). Every live session's enforcement, on every platform;
    // the .git pins below are what a guard=none session gets instead. The two are alternatives
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
      case (_, "none") => None
      case _ => Some(ensureKoAgentFsMounted(podman, os, projectId, projectDir, sandboxContainer))

    // gitGuardVolumes has the threat and the layouts. Reject mode needs no pin: the whole tree is
    // bound read-only, git control state included.
    val gitGuardArgs =
      if writeMode == "reject" || filteredWorkspace.isDefined then Vector.empty
      else
        val (emptyFile, emptyDir) = emptyMountSources(stateRoot(os))
        gitGuardVolumes(projectDir.resolve(".git"), emptyFile, emptyDir).fold(fail(_), identity)

    // guard=none is the one arrangement needing the read-only mount-back of the policy
    // directory: the raw tree is writable there, so without it a session could mkdir
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
    // the result back over it — and the image points the installed agents' instruction files at
    // this path by symlink, so a single mount reaches all of them. A project shipping its own
    // AGENTS-CUSTOM.md takes the image's AGENTS-SANDBOX.md alone and supplies the middle part
    // itself. Cached on (image Id, write mode, workspace guard, resolved policy, project
    // instructions); the
    // multi-line inputs are hashed into the stamp.
    val agentDocPath = "/etc/ko-agent-sandbox/AGENTS.md"
    val agentDocFile = policyCacheDir.resolve("agents.md")
    val agentDocStampFile = policyCacheDir.resolve("agents.stamp")
    // The profile and provider need no stamp input of their own — the resolved text's first line
    // carries both.
    val agentDocStamp =
      agentDocumentStamp(imageId, writeMode, guard, policyResolvedText, agentInstructions, runOnHost)

    val (proxyTlsArgs, sandboxTlsArgs, agentDocArgs) = withFileLock(tlsDir.resolve(".lock")):
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
        // --entrypoint=: what lands in the bundle must be cat's stdout alone, whatever ENTRYPOINT
        // the image declares (JdkTrust.jdkMounts has the argument).
        val imageBundle = run(
          podman, "run", "--rm", "--pull=never", "--network=none", "--entrypoint=",
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
      // HTTPS_PROXY family cannot reach it; JdkTrust.scala handles all of it, and empty means
      // the image ships no JDK.
      val jdkFileMounts = jdkMounts(
        podman, image, imageEnv, tlsDir, bundleStamp, caCertFile, EgressProxyHost, EgressProxyPort,
      )

      if readIfPresent(agentDocFile).forall(_.isEmpty)
        || firstLine(agentDocStampFile) != agentDocStamp
      then
        val imagePart =
          if agentInstructions.isDefined then "/etc/ko-agent-sandbox/AGENTS-SANDBOX.md" else agentDocPath
        // --entrypoint= for the same reason as the bundle read above.
        val imageDoc = run(
          podman, "run", "--rm", "--pull=never", "--network=none", "--entrypoint=",
          image, "cat", imagePart,
        )
        if !imageDoc.ok || imageDoc.out.isEmpty then
          fail(s"error: could not read the agent instructions out of $image\n${imageDoc.err}")
        writeReadable(
          agentDocFile,
          String(imageDoc.out, StandardCharsets.UTF_8).stripLineEnd
            + agentInstructions.fold("")(text => "\n\n" + text.stripLineEnd)
            + authoritySection(writeMode, guard, policyResolvedText, runOnHost, os == Os.Mac),
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
      // The CA on its own, for sandbox-jdk-use-proxy: a JVM the agent installs itself is out of
      // the launcher's reach, and that script hands it this file. No new exposure — the same
      // certificate is already inside the bundle above — it just saves a script parsing one out.
      val sandboxTls = Vector(
        s"--volume=${carried(bundleFile)}:$sandboxCaBundle:ro",
        s"--volume=${carried(caCertFile)}:$SandboxEgressCaPath:ro",
        s"--env=SSL_CERT_FILE=$sandboxCaBundle",
        s"--env=CURL_CA_BUNDLE=$sandboxCaBundle",
        s"--env=REQUESTS_CA_BUNDLE=$sandboxCaBundle",
        s"--env=NODE_EXTRA_CA_CERTS=$sandboxCaBundle",
        s"--env=GIT_SSL_CAINFO=$sandboxCaBundle",
      ) ++ jdkFileMounts.map((file, at) => s"--volume=${carried(file)}:$at:ro")
        // The same facts once more, as `-D` words, for the JVMs that read no file (JdkTrust.scala).
        ++ javaHomeOf(imageEnv).map(home =>
          s"--env=KO_AGENT_SANDBOX_JAVA_OPTS=${jdkJavaOpts(home, EgressProxyHost, EgressProxyPort)}"
        ).toVector

      (
        proxyTls,
        sandboxTls,
        Vector(s"--volume=${carried(agentDocFile)}:$agentDocPath:ro"),
      )

    // -----------------------------------------------------------------------
    // Networks
    // -----------------------------------------------------------------------
    //
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
    // only writer, so proxy liveness alone decides it, and an unreadable running set prunes
    // nothing.
    liveProxyRuns.foreach: live =>
      logsToPrune(retainedLogs(logDir).map(_.getFileName.toString), RetainedProxyLogs, live)
        .foreach(name => Files.deleteIfExists(logDir.resolve(name)))

    // The channel broker's log family, same retention — pruned by whole-run liveness, because the
    // broker lives with the sandbox container rather than the proxy.
    liveRuns.foreach: live =>
      logsToPrune(retainedLogs(logDir, "channel-").map(_.getFileName.toString), RetainedProxyLogs, live)
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
    // --rm, so a proxy whose process exits removes itself. The audit-log bind is its only writable
    // path; the native executable needs no scratch filesystem.
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
        "--read-only-tmpfs=false", // Do not add writable tmpfs mounts to the read-only root.
      ) ++
        // memoryArguments has why the equal limits disable podman's default swap allowance.
        memoryArguments(Some(ProxyMemoryCeiling), None, None) ++ Vector(
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
    awaitProxyReady(podman, proxyContainer, hostLogFile, EgressProxyReadyBound).left.foreach: reason =>
      fail(s"error: $reason")

    val networksFormat =
      "{{range $net, $conf := .NetworkSettings.Networks}}{{$net}} {{$conf.IPAddress}}{{println}}{{end}}"
    val proxyIp = addressOn(
      run(podman, "container", "inspect", "--format", networksFormat, proxyContainer).text,
      sandboxNetwork,
    ).getOrElse(fail(s"error: could not determine the egress proxy's address on $sandboxNetwork"))

    // Both authorities and their relevant state, said every launch — and a policy that arrived
    // with the repository never takes effect unseen: the files as written, then the dry run's
    // counts, the proxy's own answers to exactly what is enforced.
    // The workspace line is also where the mount step reports which branch it took, and where
    // guard=none is said every session it happens: it is the weaker boundary, and silence about
    // it is how a user forgets which one they are running under — the relabel notice included,
    // so the one raw-bind arrangement that rewrites host metadata is never a silent one.
    // Each line tints the mode it states; a branch weaker than the default is tinted whole
    // instead, in the severity hue, so no line ever carries two colours.
    System.err.println((writeMode, filteredWorkspace) match
      case ("reject", _) => s"workspace: ${statedMode("reject")}; /workspace is read-only this session"
      case (_, Some(mount)) =>
        s"workspace: ${statedMode("live")}; ${koAgentFsLabel(os)}, " +
          (if mount.joined then "reusing the mount shared by sessions in the same project directory" else "mounted")
      case (_, None) =>
        caution(
          s"workspace: live; guard none by $WorkspaceGuardVariable — /workspace bound directly, " +
            s"$RawWorkspaceBoundary; mount pins can fall through when the host replaces " +
            "their source" +
            (if selinuxEnforcing then "; the project directory is relabeled for container access (:Z)"
             else ""),
        ))
    if policyFiles.nonEmpty then
      policyFiles.foreach: (name, text) =>
        System.err.println(s"egress policy (.ko-agent-sandbox/egress/$name): ${entriesSummary(text)}")
    val egressLine = egressBanner(policyResolvedText)
    System.err.println(if permissiveProfile(policyResolvedText) then caution(egressLine) else egressLine)
    if policyWarnings.nonEmpty then System.err.println(emphasized(policyWarnings))
    if inspectedHosts.isEmpty then
      System.err.println("egress tls inspection: this policy inspects no hosts; no leaf minted")
    System.err.println(s"egress log: $hostLogFile")
    // Names only: a forwarded value may be a secret, and this line is the one place the forward
    // is said aloud, since the variable is otherwise indistinguishable from the image's own.
    if parsed.env.nonEmpty then
      System.err.println(s"forwarded environment: ${parsed.env.map(_.name).mkString(", ")}")

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
    ) ++ sandboxTlsArgs ++ agentDocArgs ++ policyGuardArgs ++ gitGuardArgs

    // The nested-container loosenings (NestingLoosenings has the what and why). Loud every session
    // they apply: the weaker boundary must never be the silent one.
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

    // Loud for the same reason: host-native execution is authority a container session alone does
    // not have. SECURITY.md "Run on host" is what bounds it.
    val runOnHostArgs =
      if runOnHost.isEmpty then Vector.empty
      else
        System.err.println(
          s"run on host: ${runOnHost.mkString(", ")} by --run-on-host; sandbox-run-on-host " +
            "relays builds to a Seatbelt-confined wrapper on this host" +
            (if parsed.autoShutdownForeignSbt
             then s"; your own live sbt server is ended when it holds the project, by ${
                 RunOnHostSandbox.AutoShutdownForeignSbtOption}"
             else ""),
        )
        Vector(s"--env=${RunOnHostChannel.RunOnHostVariable}=${runOnHost.mkString(",")}")

    // -----------------------------------------------------------------------
    // Project bind mount
    // -----------------------------------------------------------------------
    //
    // :Z only on native SELinux-enforcing Linux, and only on the raw bind; podman-machine sources
    // must not be relabelled, and neither must a FUSE mountpoint.
    val projectVolume = (writeMode, filteredWorkspace) match
      // Never :Z: the reject gate above established the tree is already container-readable, and
      // relabeling is the host write the mode withholds.
      case ("reject", _)                 => s"$projectDir:/workspace:ro"
      case (_, Some(mount))              => s"${mount.mountpoint}:/workspace:rw"
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
    // total (memoryCeiling). KO_AGENT_SANDBOX_MEMORY replaces the default for a machine shared with
    // other sessions.
    val explicitMemory = env("KO_AGENT_SANDBOX_MEMORY").map(_.trim).filter(_.nonEmpty)
    val machineMemory = memoryTotal(run(podman, "info", "--format", "{{.Host.MemTotal}}"))
    val availableMemory = hostMemoryAvailable(os, readIfPresent(Paths.get("/proc/meminfo")).getOrElse(""))
    if machineMemory.isEmpty && explicitMemory.isEmpty then
      warn("podman info reports no machine memory; the sandbox runs without a memory ceiling")
    machineMemory.filter(_ < SmallMachineMemory).foreach: total =>
      warn(
        s"podman runs on ${gib(total)} of memory; builds in the sandbox OOM below about 4 GiB\n" +
          "  on a podman machine, raise it with `podman machine set --memory` (machine stopped)",
      )
    val memoryArgs = memoryArguments(explicitMemory, machineMemory, availableMemory)

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

      "--pull=never",
      "--init",

      // Map the invoking rootless podman user to our fixed non-root user. Files created under /workspace consequently
      // remain host-user-owned.
      s"--userns=keep-id:uid=$ContainerUid,gid=$ContainerGid",
      s"--user=$ContainerUid:$ContainerGid",

      "--cap-drop=ALL",
      "--security-opt=no-new-privileges",

      // /tmp and /var/tmp stay writable through podman's --read-only-tmpfs default — the writability
      // AGENTS-SANDBOX.md promises the agents.
      "--read-only",

      // Defense against accidental or hostile fork bombs. Raise this if a particular parallel build genuinely needs
      // more.
      "--pids-limit=2048",

      // Do not inherit the host's proxy variables; egressArgs passes the sandbox's own explicitly.
      "--http-proxy=false",
    ) ++ nestedArgs ++ clipboardArgs ++ runOnHostArgs ++ egressArgs ++ Vector(

      // The host's zone, because the JVM resolves it on every platform the launcher runs on. The image
      // ships tzdata and nothing else sets a zone, so without this a commit made in the sandbox
      // carries +0000 and the agent's "today" turns over at the wrong hour.
      s"--env=TZ=${posixTz(ZoneId.systemDefault())}",
    ) ++ forwardedEnv ++ Vector(

      // The deliberate host exposure; what the agent writes here is untrusted input to host tools (SECURITY.md, "The
      // project directory").
      "--volume", projectVolume,

      // Anonymous, removed on exit: caches work without becoming cross-session attack state.
      "--mount", "type=volume,dst=/home/nonroot",

      // Persist auth/config; ~/.claude, ~/.codex, ~/.gemini and ~/.copilot are symlinks into this volume. This is
      // podman-owned storage, not a bind mount into the host HOME.
      "--mount", s"type=volume,src=$persistentVolume,dst=/home/nonroot/persistent-volume",

      // Chromium treats podman's 64 MB /dev/shm default as fatal; agy's browser automation needs more. Not a host RAM
      // reservation.
      "--shm-size=512m",
    ) ++ memoryArgs ++ Vector(
      "--workdir", "/workspace",
      image,
    ) ++ command.toVector

    // Before the container exists, and so before the reaper that waits on it: a Ctrl-C at the hold
    // is then an ordinary shutdown, the hook removing this run's proxy and networks and the launch
    // ending at once. Held after the create, it would sit inside the reaper's
    // created-but-never-started wait (SandboxLifecycle, ReaperScript) and leave it polling podman
    // for minutes after the launcher was gone. The cost is that the note below — the reaper could
    // not be spawned — prints after the release, and the TUI then clears it with the rest.
    if !holdForReader(sessionStartMode, if command.isEmpty then Vector("bash") else command, terminalReader) then
      sys.exit(0)

    // The create and the start behind it, for the reason removeWhatThisRunCreated states.
    // The blank line separates the launch's own output from the agent's.
    System.err.println("starting in sandbox\n")

    val created = run(createCommand*)
    if !created.ok then
      fail(s"error: could not create the sandbox container\n${created.err}")

    // A failed spawn is not fatal: the handover takes the resident path (handOver), the model Windows
    // always uses.
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
      // Except when the clipboard was asked for: the sandbox would wait the shim's bound
      // on every paste for a broker that never comes. The cleanup hook removes what was created,
      // the never-started sandbox included (removeRunResources).
      if clipboard != "off" then
        fail(s"error: could not spawn the proxy reaper, which serves $ClipboardVariable=$clipboard")
      System.err.println("note: could not spawn the proxy reaper; staying resident to remove the proxy on exit")
    clipboardHost.powershell.foreach(ClipboardBroker.startResident(_, podman, sandboxContainer, clipboard))

    // The command broker, detached like the reaper: it must outlive the exec below, and it ends
    // itself when the sandbox stops. A session that asked for the channel and cannot have it is a
    // failed launch, as with the clipboard above.
    if runOnHost.nonEmpty then
      val channelLogFile = logDir.resolve(s"channel-$logStamp-$runSuffix.log")
      if !RunOnHostChannel.spawnBroker(
          podman, sandboxContainer, projectDir, runOnHost, channelLogFile,
          autoShutdownForeignSbt = parsed.autoShutdownForeignSbt,
        )
      then fail("error: could not spawn the command broker, which serves --run-on-host")
      System.err.println(s"host command log: $channelLogFile")

    handOver(
      Vector(podman, "start", "--attach", "--interactive", sandboxContainer),
      viaExec = reaperArmed,
      cleanup = cleanup,
    )
