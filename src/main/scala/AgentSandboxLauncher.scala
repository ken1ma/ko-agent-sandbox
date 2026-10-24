// Run Claude Code, Codex, Antigravity, Kiro CLI, Copilot CLI or OpenCode inside a rootless podman container.
//
// One launcher for Linux, macOS, WSL and native Windows. This file records the decisions, the flags and the sequence
// of steps; the threat model is SECURITY.md. Its neighbours, each the whole of one concern:
//
//   HostCommands.scala          host executable resolution and execution, platform selection, diagnostics and
//                               the sizes they print
//   FileHelper.scala            state-file reads, replacement writes, locks, path resolution, directory scans
//   LauncherImages.scala        the images this launcher owns: names, identity, inventory, cleanup
//   ImageBuilds.scala           --build, --update and --self-test: build commands, context, lock
//   ContainerfileSources.scala  the remote images the bundled Containerfiles name, for the refresh
//   SandboxLifecycle.scala      the handover to podman, and both paths that remove a run's proxy
//   EgressRules.scala           the workspace's egress rules, their resolution, the audit log, and the
//                               --egress-* actions
//   LauncherState.scala         the state root, and the resets with the name patterns they sweep
//   CommandLine.scala           the session options, the management actions, the merge of the options
//                               file's under the command line's, and the --env forwards
//   OptionsFile.scala           the options file: location, syntax, refusals
//   AwsCredential.scala         --env-aws-cred: the AWS CLI's temporary credentials, resolved on the host
//   ClaudePlugins.scala         --claude-plugin-dir: host plugin directories run as Claude Code's managed plugins
//   LaunchMessages.scala        the weakened-boundary lines and the agent instructions' appended section
//   KoAgentFs.scala             the workspace FUSE filter: build, install, identity, mount lifecycle
//   SandboxWorkspace.scala      the workspace root: real path, refusals, identity, mount guards
//   CertificateHelper.scala     certificates as PEM: creating, parsing, checking
//   JdkTrust.scala              making the image's JVM reach the proxy — locate, prepare, mount
//   FFMHelper.scala             the downcalls into libc and kernel32
//   FileRules.scala             the file rules: defaults, the workspace's rule file, grammar, resolution
//   EgressCredentials.scala     --egress-cred: the bindings, their values, placeholders and proxies
//   ClipboardRelay.scala        the host clipboard offered to the sandbox: the protocol and both relays
//   MicrophoneRelay.scala       the host microphone under --audio=mic: the recorders, the probe and both relays
//   SandboxStats.scala          --stats: the read-only resource report
//   SelfTestShare.scala         --self-test's share rows, the host-writer/session-reader direction
//   SeatbeltProfile.scala       the Seatbelt profiles of a host command and the host proxy, as SBPL
//   RunOnHost*.scala            --run-on-host: the channel and runner (RunOnHostChannel), the
//                               supervisor (RunOnHostSandbox), the prerequisites, provisioning,
//                               session lifecycle, proxy, inspection files, sbt server and its
//                               shutdown, mill and Gradle daemons, and the runtime descriptor
//                               another launch attaches to; RunnerRuntimes.scala keeps the
//                               runtimes a launch's commands share
//
// This file is the canonical description of what the boundary is made of:
//
//   Host
//    |
//    +-- workspace root (the current directory) --> the same path (Windows: /mnt/<drive>/...)
//    |     (SandboxWorkspace.mountPathOf; --workspace selects the mount: live — the default — is the
//    |      ko-agent-fs mountpoint, RW with Git entries and launcher
//    |      configuration protected (mountKoAgentFs); read-only binds
//    |      the raw tree with podman's `ro` option)
//    |
//    +-- .ko-agent-sandbox: the egress rules, the file rules and each
//    |      run-on-host program's egress rules, read on the host; the
//    |      workspace mode is what keeps a session from writing the next one's
//    |
//    +-- podman named volume -----------> ~/persistent-volume RW/persistent
//    |                                       (~/.claude, ~/.codex, ~/.gemini, ~/.kiro,
//    |                                        ~/.copilot, ~/.local/share/kiro-cli and
//    |                                        opencode's XDG directories are symlinks
//    |                                        into it)
//    |
//    +-- --run-on-host (macOS only): ko-sandbox-run-on-host relays a command
//    |      request to a host-side supervisor that runs a build tool under a
//    |      Seatbelt profile — the workspace (`.git` and
//    |      .ko-agent-sandbox denied), per-workspace build caches, one
//    |      Coursier JDK, a session directory, and the build's own
//    |      loopback egress proxy; nothing else (RunOnHostSandbox.scala,
//    |      RunOnHostChannel.scala; SECURITY.md "Run on host")
//    |
//    X-- ~/.ssh, the SSH agent's socket     NOT EXPOSED
//    X-- ~/.aws                             NOT EXPOSED
//    X-- ~/.config                          NOT EXPOSED
//    X-- podman/Docker socket               NOT EXPOSED
//    X-- rest of host filesystem            NOT EXPOSED
//
//   Internet
//    |
//    +-- egress proxy ------------------> the hosts --egress=<profile> allows, CONNECT :443 only
//    |                                       (EgressRules.scala; the flags are below)
//    |                                    inspected hosts: TLS-inspected reads plus named grants;
//    |                                       git push refused unless a line grants POST at the repository
//    X-- everything else                    NO ROUTE
//
// The rest of /home/nonroot is an anonymous podman volume: build caches work, and disappear with the container.
//
// The entrypoint records the workspace's mount path as trusted for Claude Code, Codex, Antigravity and Copilot at
// every launch (ko-sandbox-entrypoint), so a mounted workspace's own agent configuration — MCP servers included —
// takes effect without a trust dialog. The container, not that dialog, is the boundary; whatever the configuration
// names runs inside it, never in a host-side helper.
//
// podman arguments are not accepted: podman merges rather than replaces
// most flags, so a caller-supplied --volume or --cap-add could silently
// reopen the boundary. The launcher parses only its session options and
// management actions (CommandLine.parseArguments); the first non-option is the command,
// and from there everything is forwarded verbatim to the container.

package agentsandbox.launcher

import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, Paths, StandardCopyOption}
import java.time.{Instant, ZoneId, ZoneOffset}
import java.time.format.DateTimeFormatter
import agentsandbox.egress.{AgentEgressProxy, BrokeredCredential, CredentialGrammar}
import agentsandbox.egress.LogHelper.sha256Hex

import CertificateHelper.*
import CommandLine.*
import JdkTrust.*
import EgressRules.*
import HostCommands.*
import FileHelper.*
import ImageBuilds.*
import KoAgentFs.*
import LauncherImages.*
import LauncherState.*
import LaunchMessages.*
import SandboxWorkspace.*
import SandboxLifecycle.*

object AgentSandboxLauncher:

  // Must agree with the UID/GID created in the Containerfile.
  val ContainerUid = 65532
  val ContainerGid = 65532

  // A month before expiry, so no session starts on a certificate that expires mid-run.
  val ReissueMarginSeconds = 2592000L

  // -------------------------------------------------------------------------
  // Run resource names
  //
  // Pure, and unit-tested: what this run's containers and networks are
  // called. Which podman objects the resets may touch is LauncherState.scala,
  // the workspace's own identity and guards SandboxWorkspace.scala.
  // -------------------------------------------------------------------------

  /**
   * Whether a container runtime may run inside the sandbox, as `--nesting` selects it: `none` — the
   * default — or `same-uid`, which grants the listed loosenings for the whole session,
   * at the cost SECURITY.md's "No containers inside the sandbox by default" section describes. `unmask=ALL`
   * because a nested pid namespace must mount a fresh /proc, and the kernel refuses that while
   * the masked entries remain mounted on it (measured: EPERM from a bare unshare with the masks in
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
  final val NestingVariable = "KO_AGENT_SANDBOX_NESTING"
  val NestingLoosenings =
    Vector("--security-opt=unmask=ALL", "--security-opt=label=disable", "--cap-add=SYS_CHROOT")

  /**
   * How the sandbox addresses the proxy: a name `--add-host` puts in /etc/hosts, so no resolver is
   * involved, and the port the proxy listens on. Named apart rather than only spelled into a URL,
   * because a JVM wants them as two properties rather than one (JdkTrust.jdkJavaOpts).
   */
  val EgressProxyHost = "egress-proxy"
  val EgressProxyPort = AgentEgressProxy.ListenPort

  /** The proxy variables a process behind a proxy gets, in the sandbox container and in a host
    * command alike: both spellings, since traditional programs read lowercase, and loopback exempt.
    * HTTP_PROXY is set although plain HTTP is refused, so an http:// attempt is recorded in the
    * proxy log instead of failing as an unexplained resolution error. */
  def proxyVariables(proxyUrl: String): Vector[(String, String)] =
    Vector("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy").map(_ -> proxyUrl)
      ++ Vector("NO_PROXY", "no_proxy").map(_ -> "localhost,127.0.0.1")

  /** The variables that name a PEM bundle, set in the sandbox container and in a host command
    * alike (SECURITY.md, "Who holds the CA key"); run-on-host.md, "The command's lifetime and
    * environment", lists which programs read each. */
  val CaBundleVariables: Vector[String] =
    Vector("SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "GIT_SSL_CAINFO")

  /** The proxy stamps every line it writes with an instant and a space; the spelling follows. */
  def isProxyReadyLine(line: String): Boolean =
    line == AgentEgressProxy.ReadyLine || line.endsWith(" " + AgentEgressProxy.ReadyLine)

  /** A JVM start on a loaded machine; a proxy silent past this is failed, not waited for. */
  val EgressProxyReadyBound: java.time.Duration = java.time.Duration.ofSeconds(30)

  /**
   * `podman start` returns once the process is spawned and says nothing about whether it stayed
   * up: a proxy refusing at start — a leaf naming other than its inspected set — would
   * otherwise leave a sandbox with no egress and the reason in a log
   * nobody was shown. Reads the run's host log, the file the proxy tees to before it does
   * anything else, until AgentEgressProxy.ReadyLine from a proxy still running, or the container is no
   * longer running, or `bound` elapses; each failure reports what the proxy wrote. The file rather than `podman logs`:
   * the container is `--rm`, and a proxy refusing at once is gone, with its output, before a
   * follower attaches — the file outlives it.
   *
   * Ready, it gives the proxy's networks as ProxyNetworksFormat prints them, from an inspect that
   * found it running, so the launch need not ask podman for them again.
   */
  def awaitProxyReady(podman: String, container: String, log: Path, bound: java.time.Duration): Either[String, String] =
    val deadline = System.nanoTime() + bound.toNanos
    def said: String =
      try Files.readString(log, StandardCharsets.UTF_8) catch case _: IOException => ""
    def ready: Boolean = said.linesIterator.exists(isProxyReadyLine)
    var networks: Option[String] = None
    def inspected: Boolean =
      val state = run(
        podman, "container", "inspect", "--format", s"{{.State.Running}}{{println}}$ProxyNetworksFormat", container,
      )
      val lines = state.text.linesIterator
      val running = state.ok && lines.nextOption().exists(_.trim == "true")
      if running then networks = Some(lines.mkString("\n"))
      running
    // The line, and the proxy still running: one gone after writing it is a failure with its log,
    // not an address the launch cannot find.
    def exitedAfterReady: Either[String, String] = Left(s"the egress proxy exited after reporting ready\n$said")
    def readied: Either[String, String] =
      if networks.isEmpty && !inspected then exitedAfterReady
      else Right(networks.getOrElse(""))
    var outcome: Option[Either[String, String]] = None
    while outcome.isEmpty do
      if ready then outcome = Some(readied)
      else if !inspected then
        // The last write may arrive after the liveness answer; read once more to name which exit
        // this is. Not `readied`: it would answer with the networks of an earlier inspect.
        if ready then outcome = Some(exitedAfterReady)
        else
          val written = said
          // If the proxy could not open its log, the refusal may appear only in podman's logs — and
          // `--rm` may have removed the container, and the refusal with it, before this read.
          val reason =
            if written.nonEmpty then written
            else
              val relayed = run(podman, "logs", container)
              if relayed.ok && relayed.err.nonEmpty then relayed.err
              else if relayed.ok then s"nothing was written to $log or to podman's logs of $container"
              else
                s"nothing was written to $log and podman had already removed the container: the " +
                  "proxy exited before opening its log, which is that file's mount"
          outcome = Some(Left(s"the egress proxy exited before listening\n$reason"))
      else if System.nanoTime() >= deadline then
        outcome = Some(Left(s"the egress proxy did not report ready within ${bound.toSeconds}s\n$said"))
      // Each pass asks podman once; the pause is how late a proxy that is ready can be noticed.
      else Thread.sleep(50)
    outcome.get

  /**
   * Starts the proxy container and waits for it (`awaitReady`). With bindings, the start is attached:
   * they are written to the attached `podman start`'s standard input, which podman pipes to the proxy,
   * and that client is ended once the proxy is ready or gone, while `--sig-proxy=false` keeps podman from
   * passing the signal on (SECURITY.md, "Who holds a brokered value"; src/probe/podman-attach-stdin.sh).
   * The remote client leaves `--sig-proxy` out of its help and honours it (podman's
   * `cmd/podman/containers/start.go`). The client's output is the proxy's own, which the log has.
   */
  def startProxyContainer(
    podman: String,
    container: String,
    credentials: Seq[BrokeredCredential],
  )(awaitReady: => Either[String, String]): Either[String, String] =
    if credentials.isEmpty then
      val started = run(podman, "start", container)
      if !started.ok then Left(s"could not start the egress proxy container\n${started.err}")
      else awaitReady
    else
      val client =
        try
          Right(
            ProcessBuilder(podman, "start", "--attach", "--interactive", "--sig-proxy=false", container)
              .redirectOutput(ProcessBuilder.Redirect.DISCARD)
              .start(),
          )
        catch case ex: IOException => Left(s"could not start the egress proxy container: ${ex.getMessage}")
      client.flatMap: process =>
        val bindings = CredentialGrammar.bindingBytes(credentials)
        // On its own thread: a client that never reads would hold the write, and the wait is bounded.
        val writing = Thread.startVirtualThread: () =>
          try
            process.getOutputStream.write(bindings)
            process.getOutputStream.flush()
          catch case _: IOException => ()
        // What podman says when the start itself fails; once attached it is the proxy's own output.
        val said = StringBuilder()
        val reading = Thread.startVirtualThread: () =>
          try
            val bytes = process.getErrorStream.readAllBytes()
            said.synchronized(said.append(String(bytes, StandardCharsets.UTF_8).takeRight(4096)))
          catch case _: IOException => ()
        try awaitStarted(podman, container, process, () => said.synchronized(said.toString)).flatMap(_ => awaitReady)
        finally
          process.destroy()
          process.waitFor(10, java.util.concurrent.TimeUnit.SECONDS)
          writing.join(java.time.Duration.ofSeconds(1))
          reading.join(java.time.Duration.ofSeconds(1))
          try process.getOutputStream.close() catch case _: IOException => ()

  /**
   * Waits until the attached start moves the container out of `created`. The client runs on its own, and
   * awaitProxyReady takes a container that is not running for an exited proxy, so it would misread one still
   * `created`. A container already exited has run, and awaitProxyReady reports why from its log.
   */
  private def awaitStarted(
    podman: String,
    container: String,
    client: Process,
    said: () => String,
  ): Either[String, Unit] =
    val deadline = System.nanoTime() + EgressProxyReadyBound.toNanos
    def created: Boolean =
      val state = run(podman, "container", "inspect", "--format", "{{.State.Status}}", container)
      state.ok && state.text.trim == "created"
    var outcome: Option[Either[String, Unit]] = None
    while outcome.isEmpty do
      if !created then outcome = Some(Right(()))
      else if !client.isAlive then
        outcome = Some(Left(s"could not start the egress proxy container\n${said()}"))
      else if System.nanoTime() >= deadline then
        outcome = Some(Left(s"the egress proxy container did not start within ${EgressProxyReadyBound.toSeconds}s"))
      else Thread.sleep(50)
    outcome.get

  /**
   * Everything a launch prints — the workspace mode, the egress rules, every
   * warning — is on screen for as long as it takes the agent to start, and claude's fullscreen TUI
   * and codex both clear the screen as they do. So the launcher waits for input after printing the
   * launch information and before starting the agent. `--session-start=immediate` skips that wait,
   * for whoever has read the lines enough times; without a terminal the launcher cannot wait for
   * input. The variable tells the session the mode: the entrypoint holds its own warning under it.
   */
  final val SessionStartVariable = "KO_AGENT_SANDBOX_SESSION_START"

  /** The clipboard mode inside the sandbox, which `--clipboard` selects (CommandLine.ClipboardModes). */
  final val ClipboardVariable = "KO_AGENT_SANDBOX_CLIPBOARD"

  /**
   * The variables an option replaced, with that option. A shell profile exporting one would
   * otherwise configure nothing, silently, so the launcher refuses each in its environment. Those
   * the launcher sets inside the sandbox (`inSandbox`) are refused on the host alone: a launcher run
   * in a session inherits them from it. The option names are CommandLine's `final val` constants,
   * inlined here: initializing CommandLine from this object's initializer would read
   * LauncherVariablePrefix before it is set (CommandLine.RefusedForwardPrefix).
   */
  val ReplacedVariables: Vector[(String, String, Boolean)] = Vector(
    ("KO_AGENT_SANDBOX_MEMORY", "--memory", false),
    ("KO_AGENT_SANDBOX_PERSISTENT_VOLUME", PersistentVolumeOption, false),
    ("KO_AGENT_SANDBOX_IMAGE", "--image", false),
    ("KO_AGENT_SANDBOX_PROXY_IMAGE", ProxyImageOption, false),
    (NestingVariable, "--nesting", true),
    (SessionStartVariable, "--session-start", true),
    (ClipboardVariable, "--clipboard", true),
  )

  /** Why the environment fails every invocation of the launcher, naming each replaced variable it
    * sets and the option to pass instead; a value is offered back only when the option takes it.
    * `env` is the raw environment: an exported empty variable is refused too, since it configures
    * nothing either. */
  def replacedVariablesRefusal(env: String => Option[String], inSession: Boolean): Option[String] =
    val refused = ReplacedVariables.filterNot((_, _, inSandbox) => inSession && inSandbox).flatMap:
      (variable, option, _) =>
        env(variable).map: value =>
          val valid = value.nonEmpty && parseArguments(List(s"$option=$value")).isRight && !value.contains('\n')
          val keep = if valid then s", and pass $option=$value to keep that value" else ""
          s"error: the launcher does not read $variable; $option=${ValuedOptions(option)} replaces it. Unset it$keep"
    Option.when(refused.nonEmpty)(refused.mkString("\n"))

  /** Whether this process runs inside a sandbox session: the image's `/etc/ko-agent-sandbox`, which a
    * host does not have (src/probe/machine-memory-return.sh asks the same). */
  def inSandboxSession(os: Os): Boolean = os == Os.Linux && Files.isDirectory(Paths.get("/etc/ko-agent-sandbox"))

  /**
   * The decision the reader takes on the workspace and egress lines above: Enter or y starts, n
   * declines, EOF at the prompt counts as n, and any other answer asks again; Ctrl-C ends the JVM
   * through the shutdown hook, which is the same outcome as n. The full command is shown, since
   * its arguments are part of what is agreed to. With no reader — no terminal, or a mode other
   * than pause — there is nothing to hold. When the hold returns, its line is closed: by the
   * reader's Enter, or by the hold itself at EOF, which echoes nothing.
   */
  def confirmStart(mode: String, command: Seq[String], reader: Option[Reader]): Boolean =
    startPrompt(mode, reader) match
      case None         => true
      case Some(reader) => agreed(reader, s"\nstart: ${command.map(renderArgument).mkString(" ")} [Y/n] ")

  /** The reader the start prompt asks through, if it asks at all: what a consent that rides on
    * that prompt, such as joining a mount under other file rules (KoAgentFs.joinUnderOtherRules),
    * depends on. */
  def startPrompt(mode: String, reader: Option[Reader]): Option[Reader] = reader.filter(_ => mode == "pause")

  /**
   * Whether a launch from a linked worktree shares its main worktree's agent-state volume: the
   * reader's answer, taken as confirmStart takes its own, or None where the launch holds nothing
   * and so is asked nothing (RunOnHostProvisioning follows the same rule). Asked under the lines
   * naming the two directories, before anything else is printed or created. Yes by default, unlike
   * the provisioning prompt's unconfined host run: the launch is from the repository the main
   * worktree checks out, and what is shared is the same user's logins for it.
   */
  def confirmSharedVolume(mode: String, reader: Option[Reader]): Option[Boolean] =
    reader.filter(_ => mode == "pause").map: reader =>
      reader.prompt(SharedVolumeExplained)
      agreed(reader, "\nReuse persistent volume? [Y/n] ")

  /** Said once before the question, not with each repeat of it; one line, as every launcher
    * message is, wrapped by the terminal. */
  val SharedVolumeExplained: String =
    "\nDetected a linked worktree. Reusing the main worktree's persistent volume shares agent " +
      "credentials, history, configuration and MCP state.\n"

  /** One yes-or-no question whose default is yes: Enter or y agrees, n declines, EOF declines
    * and closes the line, and any other answer asks again. */
  private def agreed(reader: Reader, prompt: String): Boolean =
    reader.prompt(prompt)
    reader.readLine() match
      case None =>
        reader.prompt("\n")
        false
      case Some(answer) =>
        answer.trim.toLowerCase(java.util.Locale.ROOT) match
          case "" | "y" | "yes" => true
          case "n" | "no"       => false
          case _                => agreed(reader, prompt)

  /** What a hold prompts on and reads from; readLine answers None at EOF. */
  final case class Reader(prompt: String => Unit, readLine: () => Option[String])

  /**
   * The process's terminal, if stdin is one, and the one way every prompt of the launcher asks.
   * isTerminal, not a null check: a console provider may answer a Console for a redirected stream
   * (which is what Console.isTerminal exists to tell), and holding a pipe open would hang a
   * scripted launch instead of skipping the hold. On Temurin 25.0.4.1's default provider,
   * System.console() is null when stdin or stdout is redirected (measured 2026-10-08), so the two
   * checks agree there.
   */
  def terminalReader: Option[Reader] =
    Option(System.console()).filter(_.isTerminal).map: console =>
      Reader(text => console.printf("%s", text), () => Option(console.readLine()))

  /** Bodies stream independently of their total size. Eight concurrent TLS downloads throttled to
    * 1 MiB/s peaked near 60 MB, while sequential multi-gigabyte transfers remained bounded. Even
    * if the 64 MiB heap cap were entirely additional to the measured peak, the 256 MiB limit
    * would retain about 135 MiB for native and workload overhead. */
  val ProxyMemoryLimit = "256m"

  /** `podman info --format '{{.Host.MemTotal}}'`, bytes; None when podman did not answer with one. */
  def memoryTotal(answer: HostCommands.Run): Option[Long] =
    if !answer.ok then None else answer.text.trim.toLongOption.filter(_ > 0)

  /**
   * The sandbox's default memory limit: 1 GiB under the total of the machine podman runs on —
   * the podman machine VM, or the host on native Linux — which is what podman, the workspace
   * filter and the kernel need to keep answering while the sandbox is at its limit; and no more
   * than the machine had available at launch, where that is known (hostMemoryAvailable), since a
   * native host is already running everything else and a VM that is short is short. What one
   * limit cannot bound is the sum: two sessions on one machine, or a host workload that increases
   * after the launch, still add up past it — `--memory` is for that.
   *
   * The one exception to the available bound is MinimumMemoryLimit (or the total, on a machine
   * smaller than that), below which the limit never goes: podman reads `--memory=0` as no limit
   * at all, which a host with nothing available would otherwise get at the moment it can least
   * afford it, and a sandbox capped under what its agent needs dies before it says anything. So
   * with under 1 GiB available the sandbox may still take 1 GiB; the entrypoint's warning is what
   * tells the user the machine was that short. The same floor is what a machine under 2 GiB gets.
   */
  def memoryLimit(machineTotal: Long, availableAtLaunch: Option[Long]): Long =
    val fromTotal = machineTotal - (1L << 30)
    val bounded = availableAtLaunch.fold(fromTotal)(Math.min(fromTotal, _))
    Math.max(bounded, Math.min(MinimumMemoryLimit, machineTotal))

  /** What the agent CLIs and one modest build need to start at all. */
  val MinimumMemoryLimit: Long = 1L << 30

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
   * is below the cold-build peak the warning quotes on purpose: a 4 GiB machine, the size the
   * threshold was chosen on, idles near 3.3–3.6 GiB available, and a threshold that size trips
   * at idle is a warning users learn to ignore. 3 GiB tells the two machine states apart — quiet
   * on an idle 4 GiB machine, loud once running sessions hold real memory, the state in which a
   * build degrades every session on the machine. The answer is the user's, not the launcher's — a
   * `[y/N]` prompt, not a refusal: the builder's own heap is limited (the proxy Containerfile),
   * so proceeding risks a slow or OOM-killed build rather than a frozen machine, a price the
   * one at the console may accept; No stays the default because the sessions at stake may not
   * be theirs to spend. With no console there is nobody to ask, and the build proceeds warned —
   * one instant of MemAvailable is too noisy to stop automation on.
   */
  val BuildMemoryWarnThreshold: Long = 3L << 30

  /**
   * A session launch does not build images, so its headroom follows the agent's minimum memory
   * allowance. Below that allowance, the entrypoint warns about the shortage (memoryLimit explains
   * the floor); below half, even starting the agent may exhaust available memory.
   */
  def launchMemoryHeadroom(available: Long): Headroom =
    if available >= MinimumMemoryLimit then Headroom.Ample
    else if available >= MinimumMemoryLimit / 2 then Headroom.Warned
    else Headroom.Short

  /**
   * Image builds and --stats share this scale so the report helps the user decide whether the
   * machine has room for an image build. BuildMemoryWarnThreshold explains the build threshold;
   * below MinimumMemoryLimit, even an agent session may exhaust available memory.
   */
  def buildMemoryHeadroom(available: Long): Headroom =
    if available >= BuildMemoryWarnThreshold then Headroom.Ample
    else if available >= MinimumMemoryLimit then Headroom.Warned
    else Headroom.Short

  def buildMemoryWarning(available: Option[Long]): Option[String] =
    available.filter(_ < BuildMemoryWarnThreshold).map: bytes =>
      s"the machine has ${humanBytes(bytes)} of memory available; a cold image build peaks near 3.3G\n" +
        "  exit running sandbox sessions, or raise it with `podman machine set --memory` (machine stopped)"

  /** After requirePodman's check, every podman action says the machine's headroom once, beside the
    * `using:` line — the figure the memory limit and the build's memory check act on, visible before
    * they act, and tinted on the action's scale (launchMemoryHeadroom, buildMemoryHeadroom). A
    * figure the machine cannot give prints nothing. */
  def machineMemoryLine(
    os: Os,
    total: Option[Long],
    available: Option[Long],
    color: Boolean = colorStderr,
    scale: Long => Headroom = launchMemoryHeadroom,
  ): Option[String] =
    val label = if os == Os.Linux then "memory" else "podman machine memory"
    for
      totalBytes <- total
      availableBytes <- available
    yield shareLine(
      label,
      availableBytes,
      totalBytes,
      "available",
      gauged(_, scale(availableBytes), color),
    )

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
   * `--memory-swap` equal to `--memory` forbids swap: it is the thrash a limit exists to
   * prevent, and podman's default of twice the memory in swap is the wrong side of that. An
   * explicit limit gets the same treatment, for the same reason.
   */
  def memoryArguments(
    explicit: Option[String],
    machineTotal: Option[Long],
    availableAtLaunch: Option[Long],
  ): Vector[String] =
    explicit.map(_.trim).filter(_.nonEmpty) match
      case Some(value) => Vector(s"--memory=$value", s"--memory-swap=$value")
      case None =>
        machineTotal.map(memoryLimit(_, availableAtLaunch)).toVector.flatMap: bytes =>
          Vector(s"--memory=$bytes", s"--memory-swap=$bytes")

  /**
   * The prefix of the variables the launcher sets inside the sandbox to say what is in force
   * (CommandLine.RefusedForwardPrefix); no variable of it configures the launcher. A variable the
   * launcher sets for one of its own components has another: `KO_AGENT_<component>_`, as
   * KO_AGENT_FS_SOURCE_ID and RunOnHostSandbox.carrierName have.
   */
  final val LauncherVariablePrefix = "KO_AGENT_SANDBOX_"

  /**
   * The proxy's address on one named network, out of the per-network listing
   * ProxyNetworksFormat prints as `<network> <ip>` lines.
   */
  val ProxyNetworksFormat =
    "{{range $net, $conf := .NetworkSettings.Networks}}{{$net}} {{$conf.IPAddress}}{{println}}{{end}}"

  def addressOn(networksOutput: String, network: String): Option[String] =
    networksOutput.linesIterator
      .find(_.startsWith(network + " "))
      .map(_.drop(network.length + 1).trim)
      .filter(_.nonEmpty)

  /**
   * The sandbox container's name: what the reaper waits on. The suffix
   * keeps concurrent sandboxes in one workspace distinct.
   */
  def sandboxRunContainer(workspaceId: String, suffix: String): String =
    s"ko-agent-sandbox-run-$workspaceId-$suffix"

  /**
   * The proxy container's name, sharing the sandbox's run suffix: each run
   * gets its own proxy, removed with its sandbox — SandboxLifecycle.scala has the
   * why.
   */
  def proxyRunContainer(workspaceId: String, suffix: String): String =
    s"ko-agent-egress-proxy-$workspaceId-$suffix"

  /**
   * This run's internal network — the one the sandbox joins, with no
   * gateway. Per run like the proxy; createNetwork has why nothing is
   * reused.
   */
  def sandboxRunNetwork(workspaceId: String, suffix: String): String =
    s"ko-agent-sandbox-$workspaceId-$suffix"

  /** This run's outbound network — the proxy's route out. Per run, as above. */
  def egressRunNetwork(workspaceId: String, suffix: String): String =
    s"ko-agent-egress-$workspaceId-$suffix"

  /** This run's disambiguator: always exactly eight hex characters (RunSuffixPattern), which
    * is what lets isRunNamed anchor on it. */
  def newRunSuffix(): String =
    java.util.UUID.randomUUID().toString.take(8)

  val RunSuffixPattern = "[0-9a-f]{8}"

  /** The run's directory of mount sources under the workspace's TLS state. */
  def tlsRunDir(suffix: String): String = s"run-$suffix"

  /**
   * The run's directory of logs under the workspace's log directory. The launch's start (logStamp)
   * comes first, so a sorted listing is chronological (runLogDirsToPrune), and the run suffix last,
   * so pruning matches a live run by the name's end, as tlsRunDirsToPrune does.
   */
  def runLogDir(stamp: String, suffix: String): String = s"run-$stamp-$suffix"

  val RunLogDirPattern: String = runLogDir("[0-9]{8}T[0-9]{6}Z", RunSuffixPattern)

  /**
   * The launch's start in its run's log directory name, in UTC: the audit lines in that directory's
   * `proxy.log` are UTC (SECURITY.md, "The audit line grammar"), and a local stamp sorts an older
   * run after a newer one across the end of daylight saving or a change of the host's zone.
   */
  def logStamp(now: Instant): String =
    DateTimeFormatter.ofPattern("uuuuMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC).format(now)

  /**
   * Whether `name` is `builder(workspaceId, <run suffix>)` — the anchored
   * form of a bare prefix check. The anchor matters because hex is
   * slug-legal and a slug may be 32 characters: a directory literally named
   * after another workspace's id yields resources that extend this workspace's
   * prefix, and a --reset here would end that workspace's live sessions.
   * With the suffix anchored, a name matches exactly one workspace. Taking
   * the builder keeps the name pattern stated once, in the builders above.
   */
  def isRunNamed(builder: (String, String) => String, workspaceId: String)(name: String): Boolean =
    val prefix = builder(workspaceId, "")
    name.startsWith(prefix) && name.drop(prefix.length).matches(RunSuffixPattern)

  /**
   * The check every podman-talking action runs first: a client that runs, and a service that
   * answers and, where `refuseRootful`, runs rootless (rootfulRefusal).
   *
   *   - On macOS and Windows the service is the podman machine, started here when stopped — never
   *     created or resized, the boundary SECURITY.md draws ("Silent changes to what you own") — so
   *     `machine init` stays the one manual step of a fresh install: the next action, usually
   *     --build, brings the machine up itself.
   *   - Gives the machine's total memory, which the launch reuses: changing it
   *     (`podman machine set --memory`) needs the machine stopped.
   *   - The available memory is asked beside `podman info`: through `podman machine ssh` on macOS
   *     and Windows, a second round trip to the machine. A machine this starts is asked again.
   */
  def requirePodman(
    os: Os,
    memoryScale: Long => Headroom = launchMemoryHeadroom,
    refuseRootful: Boolean = true,
  ): Option[Long] =
    if !podmanRuns then
      fail(
        s"""error: $podman does not run
           |
           |Reinstall it: https://podman.io/docs/installation""".stripMargin,
        127,
      )
    val awaitAvailable = inBackground("machine memory probe")(probedMachineAvailable(os, podman))
    val answered = run(podman, "info", "--format", PodmanInfoFormat)
    val (info, available) =
      if answered.ok then (answered, awaitAvailable())
      else
        os match
          case Os.Linux =>
            fail(
              "error: podman is not usable.\nOn Linux, run rootless podman as your normal user, without sudo.",
            )
          case _ =>
            // Discarded, since a stopped machine gives no answer, and settled first, so the probe
            // does not run into the start.
            awaitAvailable()
            System.err.println("the podman machine is not running; starting it")
            val started = run(podman, "machine", "start")
            if !started.ok then
              fail(
                s"""error: podman machine could not be started.
                   |${started.err}
                   |
                   |Initialize it once, for example:
                   |  podman machine init""".stripMargin,
              )
            (run(podman, "info", "--format", PodmanInfoFormat), probedMachineAvailable(os, podman))
    if refuseRootful then rootfulRefusal(os, podmanInfoField(info, 0)).foreach(fail(_))
    val total = memoryTotal(podmanInfoField(info, 1))
    machineMemoryLine(os, total, available, scale = memoryScale).foreach(System.err.println)
    total

  /** What requirePodman asks `podman info`, in one call: rootlessness, then MemTotal, a line each. */
  val PodmanInfoFormat = "{{.Host.Security.Rootless}}{{println}}{{.Host.MemTotal}}"

  /** Line `index` of a PodmanInfoFormat answer, as the answer a format of that field alone gives. */
  def podmanInfoField(answer: HostCommands.Run, index: Int): HostCommands.Run =
    val line = answer.text.linesIterator.drop(index).nextOption().getOrElse("")
    answer.copy(out = line.getBytes(StandardCharsets.UTF_8))

  /**
   * SECURITY.md's "The containers run rootless" as a condition of every podman action but the
   * ones that only read or remove. A rootful service maps `--userns=keep-id` one to one onto the
   * host's uids (podman's `GetKeepIDMapping`), so the agent's uid is the host's 65532 and the
   * container's root the host's root. An answer other than `true` refuses too: rootlessness is
   * then unknown.
   */
  def rootfulRefusal(os: Os, answer: HostCommands.Run): Option[String] =
    val reported = if answer.ok then answer.text.trim else ""
    Option.when(reported != "true"):
      val what =
        if reported == "false" then "podman runs rootful"
        else s"podman did not say whether it runs rootless: ${answer.err}"
      val fix = os match
        case Os.Linux =>
          "Run the launcher as your normal user, without sudo, and point CONTAINER_HOST or\n" +
            "`podman system connection default` at that user's podman."
        case _ =>
          "Switch the machine to rootless; what root's podman holds stays in its separate store:\n" +
            "  podman machine set --rootful=false"
      s"error: $what\nThe sandbox needs rootless podman (SECURITY.md). $fix"

  def probedMachineAvailable(os: Os, podman: String): Option[Long] =
    machineMemoryAvailable(
      os,
      readIfPresent(Paths.get("/proc/meminfo")).getOrElse(""),
      run(podman, "machine", "ssh", "cat /proc/meminfo"),
    )

  /** The sandbox and proxy images the launcher runs, and whether `--image` or `--proxy-image` chose
    * them, which is what turns a version-lock mismatch from a refusal into a warning. */
  def sandboxImageChoice(chosen: Option[String]): (String, Boolean) = imageChoice(chosen, SandboxImage)
  def proxyImageChoice(chosen: Option[String]): (String, Boolean) = imageChoice(chosen, ProxyImage)
  private def imageChoice(chosen: Option[String], default: String): (String, Boolean) =
    chosen.fold((default, false))(image => (image, true))

  /** The proxy image's Id, then its bundle label: the answer proxyImageLock reads. */
  def inspectProxyImage(proxyImage: String): Run =
    run(podman, "image", "inspect", "--format", s"{{.Id}}{{println}}$BundleLabelTemplate", proxyImage)

  /**
   * The version lock on the egress proxy image, for a launch and the egress actions alike: this
   * is the image whose --print-ruleset output and environment interface the launcher parses, so a
   * mismatched default image must not get as far as a cryptic parse failure. Left is the refusal;
   * Right is the Id to run the image by, and the warning an overridden image gets in place of the
   * refusal (bundleMismatch has the refuse-versus-warn reasoning).
   */
  def proxyImageLock(
    proxyImage: String,
    overridden: Boolean,
    inspect: String,
  ): Either[String, (String, Option[String])] =
    val proxyImageId = inspect.linesIterator.nextOption().getOrElse("")
    val label = inspect.linesIterator.drop(1).nextOption().getOrElse("")
    bundleMismatch(proxyImage, bundledSourceId("ko-agent-egress-proxy"), label) match
      case Some(mismatch) if !overridden => Left(s"error: $mismatch")
      case mismatch                      => Right((proxyImageId, mismatch))

  /** proxyImageLock's Id, after printing its warning; its refusal ends the launcher. */
  def versionLockedProxyImageId(proxyImage: String, overridden: Boolean, inspect: String): String =
    proxyImageLock(proxyImage, overridden, inspect) match
      case Left(refusal) => fail(refusal)
      case Right((proxyImageId, warning)) =>
        warning.foreach(warn)
        proxyImageId

  /**
   * The per-run TLS mount-source directories a launch may sweep: named for a run (`run-<8 hex>`)
   * that no container names. `liveRuns` is a listing taken under the workspace lock, and a launch
   * creates its proxy under that lock before releasing it, so a directory another launch can see
   * belongs to a run with a container or to a launch that died — never to one in flight. The
   * reaper deliberately does not remove these (its argument list stays fixed); the next
   * launch's sweep and the resets do.
   */
  def tlsRunDirsToPrune(names: Seq[String], liveRuns: Set[String]): Seq[String] =
    names
      .filter(_.matches(tlsRunDir(RunSuffixPattern)))
      .filterNot(name => liveRuns.contains(name.stripPrefix(tlsRunDir(""))))

  /** The run suffixes of `workspaceId` that a container in `containerNames` names, its proxy or its sandbox; None
    * when the listing failed, so that nothing is pruned (prepareRunFiles has why either container counts). */
  def liveRunsOf(workspaceId: String, containerNames: Option[Vector[String]]): Option[Set[String]] =
    containerNames.map: names =>
      Vector(proxyRunContainer, sandboxRunContainer)
        .flatMap(builder => names.filter(isRunNamed(builder, workspaceId)).map(_.stripPrefix(builder(workspaceId, ""))))
        .toSet

  /**
   * Created fresh every run: the name includes a random run suffix, so
   * nothing can already have it, nothing is ever reused, and no
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
   * The question a run of the image answers about the workspace's mount path (mountPathRefusal):
   * `entry` when the image has something at it, which the bind would cover — `/tmp`,
   * `/usr/local/bin`, a directory the image gains later — `file <path>` when the nearest
   * ancestor the image has is not a directory, `/opt/node/bin/node`, so nothing can be mounted
   * beneath it, `unreachable <dir>` when it is a directory the sandbox user cannot enter, `/root`,
   * so nothing mounted beneath it can be reached, and `absent` otherwise: podman creates the
   * missing directories of a bind target inside the read-only root, so a path the image has
   * nothing at needs no scaffolding. Asked of the image rather than of a list, so no list goes
   * stale. Only a Linux host spells such a path; `/Users/…` and `/mnt/<drive>/…` sit beside the
   * image's tree.
   */
  val MountPathProbeScript: String =
    """p=$1
      |if [ -e "$p" ] || [ -L "$p" ]; then echo entry; exit 0; fi
      |while [ "$p" != / ]; do
      |  p=${p%/*}; [ -n "$p" ] || p=/
      |  if [ -e "$p" ] || [ -L "$p" ]; then
      |    if [ ! -d "$p" ]; then echo "file $p"
      |    elif [ -x "$p" ]; then echo absent
      |    else echo "unreachable $p"; fi
      |    exit 0
      |  fi
      |done
      |echo absent""".stripMargin

  /** `--entrypoint=` and `--network=none`: the image's own program and egress are not the question
    * (readImageFiles has the same form). */
  def mountPathProbeCommand(podman: String, image: String, mountPath: String): Vector[String] =
    Vector(podman, "run", "--rm", "--pull=never", "--network=none", "--entrypoint=", image) ++
      quoteFreeSh(MountPathProbeScript, mountPath)

  /**
   * Each path's size in bytes on a line of its own and then its content, or `missing` on the line
   * for a path that is not a readable file, so one run of the image reads several files.
   */
  val ImageFilesScript: String =
    """for p; do
      |  if [ -f "$p" ] && [ -r "$p" ]; then wc -c < "$p"; cat "$p"; else echo missing; fi
      |done""".stripMargin

  /**
   * The files at `paths` read out of `imageId` in one run, by path, beside why any is missing: the
   * run's stderr, or the paths the image has no readable file at. When none are asked for, nothing
   * runs. `--entrypoint=`: the answer must be the script's stdout alone, whatever ENTRYPOINT the
   * image declares (JdkTrust.jdkMounts has the argument).
   */
  def readImageFiles(podman: String, imageId: String, paths: Vector[String]): (Map[String, Array[Byte]], String) =
    if paths.isEmpty then (Map.empty, "")
    else
      val read = run(
        Vector(podman, "run", "--rm", "--pull=never", "--network=none", "--entrypoint=", imageId)
          ++ quoteFreeSh(ImageFilesScript, paths*)*
      )
      if !read.ok then (Map.empty, read.err)
      else
        val found = imageFilesOf(read.out, paths)
        (found, paths.filterNot(found.contains).map(path => s"no readable file at $path").mkString("\n"))

  /** The files an ImageFilesScript answer holds, by path: a path answered `missing`, and every path
    * after an answer cut short, has none. */
  def imageFilesOf(out: Array[Byte], paths: Vector[String]): Map[String, Array[Byte]] =
    @scala.annotation.tailrec
    def from(at: Int, remaining: Vector[String], found: Map[String, Array[Byte]]): Map[String, Array[Byte]] =
      val lineEnd = out.indexOf('\n'.toByte, at)
      remaining.headOption.filter(_ => lineEnd >= 0) match
        case None => found
        case Some(path) =>
          val header = String(out.slice(at, lineEnd), StandardCharsets.US_ASCII).trim
          val start = lineEnd + 1
          header.toIntOption match
            case Some(size) if size >= 0 && start + size <= out.length =>
              from(start + size, remaining.tail, found + (path -> out.slice(start, start + size)))
            case None if header == "missing" => from(start, remaining.tail, found)
            case _ => found
    from(0, paths, Map.empty)

  /**
   * The stamp an image's answer about `mountPath` is cached under. The probe reads only the image,
   * so its answer holds while the image Id, the probe script and the path are the ones it was asked
   * with; the path is hashed because the stamp is one line.
   */
  def mountPathProbeStamp(imageId: String, mountPath: String): String =
    s"$imageId ${sha256Hex(MountPathProbeScript)} ${sha256Hex(mountPath)}"

  /** The probe's `absent` from `file`, when it was cached for this image and path. */
  def cachedMountPathAnswer(file: Path, imageId: String, mountPath: String): Option[HostCommands.Run] =
    stampedEntry(file, mountPathProbeStamp(imageId, mountPath))
      .filter(_ == "absent")
      .map(answer => HostCommands.Run(0, answer.getBytes(StandardCharsets.UTF_8), ""))

  /** The probe asked of `imageId`, the Id its answer is cached under, never of a name (launch's
    * `imageId` has why). */
  def probeMountPath(podman: String, imageId: String, mountPath: String): HostCommands.Run =
    run(mountPathProbeCommand(podman, imageId, mountPath)*)

  /** The image's answer about `mountPath`: cached in `file`, or probed now and cached when `absent`. */
  def mountPathAnswer(podman: String, imageId: String, mountPath: String, file: Path): HostCommands.Run =
    cachedMountPathAnswer(file, imageId, mountPath).getOrElse:
      val asked = probeMountPath(podman, imageId, mountPath)
      cacheMountPathAnswer(file, imageId, mountPath, asked)
      asked

  /** Caches `answer` in `file` when it is `absent`: every other answer refuses, and is asked again. */
  def cacheMountPathAnswer(file: Path, imageId: String, mountPath: String, answer: HostCommands.Run): Unit =
    if answer.ok && answer.text.trim == "absent" then
      writeStamped(file, mountPathProbeStamp(imageId, mountPath), "absent")

  /** Why the image cannot take the workspace root at `mountPath`, read from the probe's answer, or None. */
  def mountPathRefusal(answer: String, workspaceRoot: Path, mountPath: String): Option[String] =
    val refusing = s"error: refusing to mount $workspaceRoot at $mountPath\n\n"
    answer.trim match
      case "absent" => None
      case "entry" =>
        Some(
          refusing +
            s"The sandbox image has an entry at $mountPath, which the workspace's mount would cover, and the\n" +
            "container relies on what the image has there. Move the workspace root to a path the image has\n" +
            "nothing at (/tmp/app binds into /tmp; /tmp itself does not) and run this again.",
        )
      case s"file $path" =>
        Some(
          refusing +
            s"In the sandbox image, $path is a file, so nothing can be mounted beneath it. Move the workspace\n" +
            "root elsewhere and run this again.",
        )
      case s"unreachable $dir" =>
        Some(
          refusing +
            s"In the sandbox image, $dir cannot be entered by the sandbox user, so nothing mounted beneath\n" +
            "it is reachable. Move the workspace root elsewhere and run this again.",
        )
      case other => Some(s"error: the sandbox image gave no answer about $mountPath\n$other")

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

  def main(args: Array[String]): Unit =
    // The private actions, before the ordinary parse and in no usage text: they are not launch
    // options, and nothing outside this codebase spells them. Each re-invokes the launcher's own
    // executable — jar or native image (RunOnHostSandbox.selfInvocation). --serve-proxy-on-host
    // hosts a command's egress proxy, configured by the EGRESS_* environment as in the container;
    // --serve-run-on-host is the session's command runner (RunOnHostChannel), and
    // --run-command-on-host one channel request as the runner's own child.
    args.headOption match
      case Some("--serve-proxy-on-host") if args.length == 1 =>
        agentsandbox.egress.AgentEgressProxy.serve()
      case Some("--serve-run-on-host")  => RunOnHostChannel.serveMain(args.toSeq.drop(1))
      case Some("--run-command-on-host")  => RunOnHostSandbox.runCommandMain(args.toSeq.drop(1))
      case _                            => launcherMain(args)

  /**
   * The options an action reads, from the command line and the options file alike; it ignores the
   * file's others, and refuses the others on its command line. `--reset` leaves the shared volume
   * in place, as a launch mounts it. `--egress-check` sends no credential, so it reads no
   * `--egress-cred`.
   */
  val ResetReads: Set[String] = Set(PersistentVolumeOption)
  val EgressEffectiveReads: Set[String] = Set("--egress", ModelProviderOption, "--egress-cred", ProxyImageOption)
  val EgressCheckReads: Set[String] = EgressEffectiveReads - "--egress-cred"

  private def launcherMain(args: Array[String]): Unit =
    replacedVariablesRefusal(name => Option(System.getenv(name)), inSandboxSession(currentOs)).foreach(fail(_))

    val commandLine = parseArguments(args.toList).fold(fail(_), identity)

    // The action refusals below read the command line alone.
    def inForce(used: Set[String]): OptionsInForce =
      OptionsFile.inForce(commandLine, used)(
        OptionsFile.load(currentOs, resolveWorkspaceRoot(currentOs), name => Option(System.getenv(name))),
      ).fold(fail(_), identity)

    // The actions that read no session option refuse one rather than ignoring it: a selection
    // that configures nothing is the silent failure mode the options must not have.
    val givenOnCommandLine = givenOptions(commandLine)
    def refuseGiven(action: String, readable: Set[String] = Set.empty): Unit =
      val named = givenOnCommandLine.filterNot(readable)
      if named.nonEmpty then
        val them = if named.size == 1 then "it" else "them"
        fail(s"error: $action reads no ${named.mkString(" or ")} option; drop $them")
    def noSessionOptions(action: String): Unit = refuseGiven(action)

    commandLine.action match
      case Some(("--help", _)) =>
        noSessionOptions("--help")
        usage()

      case Some(("--build", rest)) =>
        noSessionOptions("--build")
        if rest.nonEmpty then fail("error: --build takes no further arguments")
        requirePodman(currentOs, buildMemoryHeadroom)
        confirmMemoryForBuilds(currentOs)
        build(currentOs)

      case Some(("--update", rest)) =>
        noSessionOptions("--update")
        if rest.nonEmpty then fail("error: --update takes no further arguments")
        requirePodman(currentOs, buildMemoryHeadroom)
        confirmMemoryForBuilds(currentOs)
        update(currentOs)

      case Some(("--reset", rest)) =>
        refuseGiven("--reset", ResetReads)
        val givenIds = workspaceIdOperands("--reset", rest).fold(fail(_), identity)
        val options = inForce(ResetReads)
        // The resets only remove what carries this launcher's names, so they run against a
        // rootful service too.
        requirePodman(currentOs, refuseRootful = false)
        resetWorkspace(currentOs, givenIds, options.parsed.persistentVolume, options.from(PersistentVolumeOption))

      // No id form: a gone workspace's cache goes with `--reset <id>`, and this action exists for the
      // live one, whose directory is there to run from.
      case Some(("--reset-run-on-host", rest)) =>
        noSessionOptions("--reset-run-on-host")
        if rest.nonEmpty then fail("error: --reset-run-on-host takes no further arguments")
        resetRunOnHost(currentOs)

      // No options file: the reset removes only volumes the launcher named (persistentVolumes), so
      // no shared volume is there to leave in place.
      case Some(("--reset-all", rest)) =>
        noSessionOptions("--reset-all")
        if rest.nonEmpty then fail("error: --reset-all takes no further arguments")
        requirePodman(currentOs, refuseRootful = false)
        resetAll(currentOs)

      // No requirePodman(): the report is read-only and reads host directories either way; the
      // live section degrades to a note when podman or its machine is not there to answer.
      case Some(("--stats", rest)) =>
        noSessionOptions("--stats")
        if rest.nonEmpty then fail("error: --stats takes no further arguments")
        SandboxStats.stats(currentOs)

      // No requirePodman() here: with no arguments this reads host files only, and the retained
      // logs are documented as readable after every container is gone. EgressRules.egressLog asks for podman on
      // the branch that needs it.
      case Some(("--egress-log", rest)) =>
        noSessionOptions("--egress-log")
        egressLog(currentOs, rest)

      case Some(("--self-test", rest)) =>
        noSessionOptions("--self-test")
        requirePodman(currentOs, buildMemoryHeadroom)
        selfTest(currentOs, rest)

      case Some(("--egress-effective", rest)) =>
        refuseGiven("--egress-effective", EgressEffectiveReads)
        val options = inForce(EgressEffectiveReads)
        options.fileLines().foreach(System.err.println)
        import options.parsed
        requirePodman(currentOs)
        egressEffective(
          currentOs, parsed.egressProfile, parsed.modelProviders, parsed.proxyImage, rest, parsed.credentialBindings,
        )

      case Some(("--egress-check", operands)) =>
        refuseGiven("--egress-check", EgressCheckReads)
        val host = operands.headOption.filter(_.nonEmpty).getOrElse(
          fail("error: --egress-check=<host> names the host to check"),
        )
        val options = inForce(EgressCheckReads)
        options.fileLines().foreach(System.err.println)
        import options.parsed
        requirePodman(currentOs)
        egressCheck(currentOs, parsed.egressProfile, parsed.modelProviders, parsed.proxyImage, host, operands.tail)

      // CommandLine.ManagementActions and this match drifted.
      case Some((action, _)) => fail(s"error: unhandled action $action")

      case None => launch(inForce(FileOptionNames.toSet))

  /** The TLS material a proxy mounts: the leaf and its key when the ruleset inspects a host. */
  enum ProxyTlsMaterial:
    case Leaf(certificate: Path, key: Path)
    case Uninspected

  def proxyTlsArgs(material: ProxyTlsMaterial, selinuxEnforcing: Boolean): Vector[String] =
    material match
      case ProxyTlsMaterial.Leaf(certificate, key) =>
        Vector(
          fileBind(certificate, "/etc/ko-agent-egress-proxy/leaf.crt", "ro", selinuxEnforcing),
          fileBind(key, "/etc/ko-agent-egress-proxy/leaf.key", "ro", selinuxEnforcing),
          s"--env=${AgentEgressProxy.CertificateVariable}=/etc/ko-agent-egress-proxy/leaf.crt",
          s"--env=${AgentEgressProxy.PrivateKeyVariable}=/etc/ko-agent-egress-proxy/leaf.key",
        )
      case ProxyTlsMaterial.Uninspected => Vector.empty

  /** With bindings, the container is created with `--interactive`, because `podman start` cannot open its
    * standard input later (podman-start(1)); without bindings, no arguments. */
  def proxyCredentialArgs(credentials: Seq[BrokeredCredential]): Vector[String] =
    if credentials.isEmpty then Vector.empty
    else Vector("--interactive", s"--env=${CredentialGrammar.StdinVariable}=${CredentialGrammar.StdinValue}")

  /** Each brokered name set to its placeholder in the sandbox: an explicit value, since the host's is the secret. */
  def placeholderArgs(credentials: Seq[BrokeredCredential]): Vector[String] =
    credentials.toVector.map(credential => s"--env=${credential.binding.name}=${credential.placeholder}")

  def proxyLogArgs(hostLogFile: Path, selinuxEnforcing: Boolean): Vector[String] =
    val containerLogFile = "/var/log/ko-agent-egress-proxy/proxy.log"
    Vector(
      fileBind(hostLogFile, containerLogFile, "rw", selinuxEnforcing),
      s"--env=${AgentEgressProxy.LogFileVariable}=$containerLogFile",
    )

  val AgentDocPath = "/etc/ko-agent-sandbox/AGENTS.md"

  /**
   * The files the launcher mounts over the sandbox image's own. The bundle replaces the image's;
   * the variables cover programs with a trust store of their own (certifi, Node's roots), and the
   * JDK files cover the JVM, which reads neither.
   *
   * The CA on its own is for ko-sandbox-jdk-use-proxy: a JVM the agent installs itself is out of
   * the launcher's reach, and that script hands it this file. No new exposure — the same
   * certificate is already inside the bundle — it just saves a script parsing one out.
   */
  def sandboxFileArgs(
    caBundle: Path,
    caCertificate: Path,
    jdkFiles: Vector[(Path, String)],
    agentDoc: Path,
    selinuxEnforcing: Boolean,
  ): Vector[String] =
    val sandboxCaBundle = "/etc/ssl/certs/ca-certificates.crt"
    Vector(
      fileBind(caBundle, sandboxCaBundle, "ro", selinuxEnforcing),
      fileBind(caCertificate, SandboxEgressProxyCaPath, "ro", selinuxEnforcing),
    ) ++ CaBundleVariables.map(name => s"--env=$name=$sandboxCaBundle")
      ++ jdkFiles.map((file, at) => fileBind(file, at, "ro", selinuxEnforcing))
      :+ fileBind(agentDoc, AgentDocPath, "ro", selinuxEnforcing)

  /**
   * The workspace's `--volume` value. Never relabeled: a FUSE mountpoint must not be; under
   * `--workspace=read-only`, launchWorkspace's SELinux check established that the tree is already
   * container-readable, and relabeling is the host write that mode withholds.
   */
  def workspaceBind(filteredMountpoint: Option[String], workspaceRoot: Path, mountPath: String): String =
    filteredMountpoint match
      case Some(mountpoint) => s"$mountpoint:$mountPath:rw"
      case None             => s"$workspaceRoot:$mountPath:ro"

  /**
   * Whether the directory's own SELinux context already allows container reads, so an unfiltered
   * bind mount needs no relabel: a container type with no MCS categories. A context with categories
   * — what a previous run's `:Z` leaves — is private to the container it was assigned to,
   * unreadable to a new one, so it does not count. Only the root is asked: a partially labeled tree
   * fails at runtime with EACCES on the stray files, the host's own labeling to finish. Fail closed
   * — a missing stat, an unreadable or unexpected context all answer false.
   *
   * stat resolves through findOnPath like every host executable: this runs before the sandbox
   * exists, and the working directory is the workspace root.
   */
  def selinuxContainerReadable(dir: Path): Boolean =
    findOnPath("stat", Os.Linux).exists: stat =>
      val context = run(stat.toString, "-c", "%C", dir.toString)
      val parts = if context.ok then context.text.trim.split(":") else Array.empty[String]
      parts.length == 4 && parts.lift(2).exists(Set("container_file_t", "container_share_t"))

  /**
   * The zone as a POSIX `TZ` value. A tzdata name passes through; a fixed offset — what the JVM
   * falls back to on a host it cannot map to one, as `GMT+09:00` — is spelled `UTC-9`, because
   * POSIX reads the sign the other way round from ISO: `TZ=GMT+09:00` is nine hours *behind*
   * UTC to every native program, while the JVM would read it as ahead. Seconds are dropped: glibc
   * honours `UTC-5:45:30`, but a JVM reads it as `+05:45` (measured on Java 25), so passing them on
   * would split the sandbox's own programs two ways; no zone has had one for over fifty years.
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

  /** What a launch reads and refuses before it checks the workspace root: the options and where
    * each came from, what they select on the host, and the run-on-host rule files. */
  private case class LaunchSettings(
    options: OptionsInForce,
    credentials: Vector[BrokeredCredential],
    image: String,
    imageOverridden: Boolean,
    proxyImage: String,
    proxyImageOverridden: Boolean,
    nesting: String,
    sessionStartMode: String,
    clipboard: String,
    clipboardHost: ClipboardRelay.HostBackend,
    /** The recorder candidates under --audio=mic, in probe order. */
    microphone: Option[Vector[MicrophoneRelay.Recorder]],
    forwardedEnv: Vector[String],
    awsCredential: Option[AwsCredential.Resolved],
    runOnHost: Vector[String],
    workspaceRoot: Path,
    boundaryDir: Path,
    programRules: Vector[(RunOnHostPrereqs.Program, Vector[String])],
  )

  private case class LaunchWorkspace(
    homeProtection: HomeProtection,
    mainWorktree: Option[Path],
    mountPath: String,
    selinuxEnforcing: Boolean,
    workspaceSlug: String,
    workspaceId: String,
    persistentVolume: String,
    claudePlugins: Vector[ClaudePlugins.Plugin],
  )

  private case class LaunchImages(
    imageId: String,
    imageEnv: String,
    proxyImageId: String,
    mountPathAnswerFile: Path,
    cachedMountPath: Option[HostCommands.Run],
    mountPathProbe: HostCommands.Run,
  )

  private case class LaunchRules(
    ruleFiles: Vector[(String, String)],
    workspaceFileRules: Option[(String, Vector[FileRules.Line])],
    fileRuleLines: Vector[FileRules.Line],
    fileRulesInForce: Boolean,
    fileRulesText: String,
    readOnlyFileRules: Option[FileRules.Resolved],
    provider: Option[String],
    rulesetCacheDir: Path,
    rulesetText: String,
    rulesetWarnings: String,
    inspectedHosts: Vector[String],
    egressLine: String,
    sessionCredentials: Vector[BrokeredCredential],
  )

  private case class RunNames(
    proxyContainer: String,
    sandboxContainer: String,
    sandboxNetwork: String,
    egressNetwork: String,
  )

  /** The filter's mountpoint for a live session, and the file rules the session runs under. */
  private case class LaunchMount(
    filteredWorkspace: Option[KoAgentFsPrepared],
    joinedRules: Option[RunningMount],
    sessionRuleLines: Vector[FileRules.Line],
    sessionRulesText: String,
  )

  private case class GitAccess(
    noGit: Option[NoGit],
    mountedGitdir: Option[GitdirBind],
    gitdirBindRefusal: Option[String],
    gitInstruction: Option[String],
  )

  /** The launch, phase by phase: each phase takes the earlier phases' results and imports by name the
    * values its body reads from them. The cleanup and the hold stay here: the cleanup reads
    * `heldLineClosed`, and the hold sets it. */
  def launch(options: OptionsInForce): Unit =
    val os = currentOs
    val parsed = options.parsed
    val settings = launchSettings(options, os)
    // First of the launch's lines: the options the file supplied, but those another line states
    // (ownLines), so each is printed once.
    options.fileLines(ownLines(settings, parsed), os).foreach(System.err.println)
    val workspace = launchWorkspace(parsed, settings, os)
    import parsed.{command, workspaceMode}
    import settings.{workspaceRoot, runOnHost, sessionStartMode}
    import workspace.workspaceId
    val machineMemory = requirePodman(os)

    // One suffix ties this run's containers, networks and log directory together in podman output and the retained
    // logs.
    val runSuffix = newRunSuffix()
    val logDir = logStateRoot(os).resolve(workspaceId)
    val runLogs = logDir.resolve(runLogDir(logStamp(Instant.now()), runSuffix))
    // Named before it exists: prepareRunFiles creates it after pruning, and a launch refused earlier has written
    // nothing there. Creating it here would let each refused launch's empty directory count toward the RetainedRuns
    // that pruning keeps.
    System.err.println(pathLine("log dir", runLogs, os, tint = lookedUp(_)))

    // The filter's read-only checks run beside the image and rule checks below; prepareKoAgentFs
    // reads their answer once this run's cleanup is armed.
    val startedKoAgentFsChecks = Option.when(workspaceMode == "live"):
      val sourceId = bundledKoAgentFsSourceId()
      (sourceId, inBackground("ko-agent-fs checks")(koAgentFsChecks(podman, os, sourceId)))

    val images = launchImages(settings, workspace, os)
    val rules = launchRules(parsed, settings, workspace, images, os)
    import rules.{fileRuleLines, fileRulesText, sessionCredentials}

    // -----------------------------------------------------------------------
    // This run's egress proxy
    // -----------------------------------------------------------------------
    //
    // The sandbox joins an internal network with no gateway; its peers on it are this run's proxy, whose second
    // interface has the route out, and podman's resolver, which answers only the run's names (SECURITY.md, "DNS").
    // A network boundary, not a configuration hint: removing the proxy env variables below does not restore Internet
    // access, it just makes the failure harder to diagnose. All per run (SandboxLifecycle, "Removing what the run
    // created").

    val names = RunNames(
      proxyRunContainer(workspaceId, runSuffix),
      sandboxRunContainer(workspaceId, runSuffix),
      // Per run, not per workspace, so concurrent sessions cannot reach each other — a compromised proxy reaches the
      // Internet and its own sandbox, never a neighbour with a wider ruleset.
      sandboxRunNetwork(workspaceId, runSuffix),
      egressRunNetwork(workspaceId, runSuffix),
    )
    import names.{egressNetwork, proxyContainer, sandboxContainer, sandboxNetwork}

    // The workspace FUSE filter, checked before any volume is assembled and mounted once the
    // sandbox container exists (the lifecycle banner above koAgentFsMountScript has the layout).
    // Every live session's enforcement, on every platform.
    //
    // Derived from the mode rather than from the mount, so it exists before the mount does: the
    // mount script writes this session's marker as its first act (KoAgentFs, koAgentFsMountScript),
    // and a failure after that would otherwise leave the marker to a later reap. Only live
    // sessions have a mount to reap.
    val filterReap = Option.when(workspaceMode == "live")(
      koAgentFsReapScript(koAgentFsReapPodman(podman, os), workspaceId, sandboxContainer),
    )

    // This workspace's TLS/trust state, and this run's own copies of the files podman will mount —
    // shared state is derived under the workspace lock further down, and what a container mounts is
    // the per-run copy, so a later launch's legitimate rewrite (a rebuilt image, an edited
    // rule file) cannot take a mounted file from a session already running: a bind mount does not
    // survive its source's inode being replaced, and these files have nothing behind them to fall
    // through to.
    val tlsDir = tlsStateRoot(os).resolve(workspaceId)
    createPrivateDirectories(tlsDir)
    val runFiles = tlsDir.resolve(tlsRunDir(runSuffix))

    // Everything this run creates, in one place: the shutdown hook and the resident teardown both
    // run exactly this, so the two cannot drift into removing different sets.
    //
    // The notice opens on a fresh line unless the line is known closed. The terminal echoes a
    // Ctrl-C as `^C` and stops there, a signal leaves the cursor wherever it was, a child may end
    // mid-line, and the hook cannot see any of it; the one line the launcher knows closed is the
    // hold's, ended by the reader's Enter or by the hold itself (confirmStart). Elsewhere an
    // empty line is the price, a refusal's among them.
    var heldLineClosed = false
    val removeWhatThisRunCreated = () =>
      // Podman takes about a second on cleanup, whether a launch was refused, interrupted, or ended
      // normally through the resident path. Report progress so the pause does not look like a hang.
      System.err.println((if heldLineClosed then "" else "\n") + "removing this run's containers and networks")
      removeRunResources(podman, sandboxContainer, proxyContainer, Seq(sandboxNetwork, egressNetwork))
      // This run's mount-source copies. The reaper deliberately does not remove them (its
      // argument list stays fixed); a run it cleans up leaves its copies to the next launch's
      // liveness sweep, or a reset's.
      try deleteRecursively(runFiles)
      catch case _: Exception => ()
      // Best effort, as on the reaper's path: this run's session marker goes now rather than with
      // the reap that finds its container gone, and the mount follows if no other session holds it.
      filterReap.foreach(script => runOk(koAgentFsScriptCommand(podman, os, script)*))

    // Armed before the first resource this run owns — its networks, then its files under the
    // workspace lock below. What precedes it is this workspace's ruleset cache, which outlives every
    // run by design. From here on this process is the only one that knows what to remove, and
    // every refusal below ends the JVM rather than raising (SandboxLifecycle, armRunCleanup).
    val cleanup = armRunCleanup(removeWhatThisRunCreated)

    // The filter's checks, started above, and its mountpoint now; the mount itself once the sandbox
    // container exists (mountKoAgentFs has why), which is after the proxy and the hold.
    val filteredWorkspace = startedKoAgentFsChecks.map: (sourceId, awaitChecks) =>
      prepareKoAgentFs(podman, os, workspaceId, sourceId, awaitChecks())
    // A live mount under other file rules, after an edit of file/rule, is joined under its rules,
    // which an earlier session of the workspace accepted; the start prompt below is the consent.
    val joinedRules = joinUnderOtherRules(
      filteredWorkspace.flatMap(_.running),
      fileRulesText,
      prompted = startPrompt(sessionStartMode, terminalReader).nonEmpty,
    ).fold(fail(_), identity)
    val (sessionRuleLines, sessionRulesText) = joinedRules match
      case Some(running) => (FileRules.parseDaemonText(running.rules).fold(fail(_), identity), running.rules)
      case None          => (fileRuleLines, fileRulesText)

    // -----------------------------------------------------------------------
    // Networks
    // -----------------------------------------------------------------------
    //
    createNetwork(sandboxNetwork, internal = true)
    createNetwork(egressNetwork, internal = false)

    // -----------------------------------------------------------------------
    // This run's logs
    // -----------------------------------------------------------------------
    //
    // The audit log is appended by the proxy through a bind-mounted host
    // file, so the record outlives the per-run container. Not --log-opt
    // path=: conmon interprets that inside the podman machine VM. A
    // single-file mount — the run's directory would hand the proxy this run's
    // other logs, and the workspace's log directory every previous session's
    // record — and owner-only: refusal lines carry full URLs, and a URL can
    // carry a secret.
    createPrivateDirectories(logDir)

    val hostLogFile = runLogs.resolve("proxy.log")
    val channelLogFile = runLogs.resolve("run-on-host.log")
    val microphoneLogFile = runLogs.resolve("microphone.log")

    val git = gitAccess(settings, workspace, images, rules, os)
    val sandboxFiles =
      prepareRunFiles(
        parsed, settings, workspace, images, rules, names, git, tlsDir, runFiles, logDir, runLogs, hostLogFile, os,
      )

    val proxyNetworks =
      startProxyContainer(podman, proxyContainer, sessionCredentials)(
        awaitProxyReady(podman, proxyContainer, hostLogFile, EgressProxyReadyBound),
      ).fold(reason => fail(s"error: $reason"), identity)
    val proxyIp = addressOn(proxyNetworks, sandboxNetwork)
      .getOrElse(fail(s"error: could not determine the egress proxy's address on $sandboxNetwork"))

    val mount = LaunchMount(filteredWorkspace, joinedRules, sessionRuleLines, sessionRulesText)
    printLaunchLines(parsed, settings, workspace, rules, mount, git, hostLogFile, os)
    val createCommand = sandboxCreateCommand(
      parsed, settings, workspace, images, rules, names, mount, git, proxyIp, sandboxFiles, machineMemory, os,
    )

    // Before the hold, what the first mill, gradle or mvn command would refuse for want of an
    // executable the user provisions, offered as that run now (RunOnHostProvisioning): the reader
    // is the hold's, so a launch that holds nothing is told and asked nothing.
    if runOnHost.nonEmpty then
      RunOnHostProvisioning.run(
        workspaceRoot,
        RunOnHostPrereqs.Program.values.filter(program => runOnHost.contains(program.name)).toSet,
        name => Option(System.getenv(name)),
        terminalReader.filter(_ => sessionStartMode == "pause"),
      )

    // The hold, then the create, the reaper, the mount, and the start. The hold before the
    // container exists: a Ctrl-C there is then an ordinary shutdown, the hook removing this run's
    // proxy and networks and the launch ending at once, and a launcher killed outright at the
    // prompt leaves no created container behind. The reaper right after the create, so a
    // created-but-never-started sandbox has its remover (SandboxLifecycle, ReaperScript) from the
    // first instant — where a reaper runs. Where none does — Windows, and a POSIX spawn that
    // failed — the launcher stays resident, and one killed outright leaves the created container,
    // and with it the marker and the mount, to a reset, as it leaves the proxy. The mount after
    // both, because the container is what names this session to the filter's reap, which asks
    // podman for it by name (KoAgentFs, koAgentFsReapScript):
    // written after the create, the session marker is never on disk without it, and a launcher
    // that dies during the mount leaves the marker to the reap that follows the reaper's removal
    // of the container. The cost is that the notes below — the reaper could not be spawned, which
    // branch the mount took — print after the release, and the TUI then clears them with the rest.
    if !confirmStart(sessionStartMode, if command.isEmpty then Vector("bash") else command, terminalReader) then
      heldLineClosed = true
      sys.exit(0)

    startSandbox(
      parsed, settings, workspace, rules, names, mount, createCommand, filterReap, runFiles, channelLogFile,
      microphoneLogFile, cleanup, os,
    )

  /** The options another launch line states when in force, which names the options file when the
    * option came from it: the grants' orange lines, the shared agent-state volume's line, the
    * workspace and egress lines, and the forwarded names and credentials. */
  private def ownLines(settings: LaunchSettings, parsed: ParsedCommandLine): Set[String] =
    Set(
      Some("--workspace"),
      Some("--egress"),
      Some(ModelProviderOption),
      Option.when(parsed.env.nonEmpty)("--env"),
      Option.when(settings.credentials.nonEmpty)("--egress-cred"),
      Option.when(settings.awsCredential.nonEmpty)(AwsCredential.OptionName),
      Option.when(settings.clipboard != "off")("--clipboard"),
      Option.when(settings.microphone.nonEmpty)(AudioOption),
      Option.when(settings.nesting != "none")("--nesting"),
      Option.when(settings.runOnHost.nonEmpty)("--run-on-host"),
      Option.when(parsed.persistentVolume.nonEmpty)(PersistentVolumeOption),
      Option.when(parsed.claudePlugins.nonEmpty)(ClaudePlugins.OptionName),
    ).flatten

  private def launchSettings(options: OptionsInForce, os: Os): LaunchSettings =
    val parsed = options.parsed
    // First, before any check that starts a process (the clipboard's `ps` below): from here the values
    // are in this process's memory, and no process it starts inherits them (EgressCredentials.withhold).
    val credentials =
      EgressCredentials.resolve(parsed.credentialBindings, name => Option(System.getenv(name))).fold(fail(_), identity)
    EgressCredentials.withhold(credentials.map(_.binding.name), os)

    val (image, imageOverridden) = sandboxImageChoice(parsed.image)
    val (proxyImage, proxyImageOverridden) = proxyImageChoice(parsed.proxyImage)

    val nesting = parsed.nestingMode
    val sessionStartMode = parsed.sessionStartMode
    val clipboard = parsed.clipboardMode
    val pathValue = env("PATH").getOrElse("")
    val microphone = Option.when(parsed.microphone)(MicrophoneRelay.recorders(os, pathValue).fold(fail(_), identity))
    // The reaper ends the microphone relay's tree with the same proven ps as the clipboard's.
    val clipboardHost =
      ClipboardRelay.hostBackend(clipboard, os, pathValue).fold(fail(_), identity) match
        case backend if microphone.nonEmpty && os != Os.Windows && backend.ps.isEmpty =>
          backend.copy(ps = ClipboardRelay.probedPs(MicOption, os, pathValue).fold(fail(_), identity))
        case backend => backend
    // Raw, not HostCommands.env: that one reads an empty variable as unset, which is right for the
    // launcher's own settings and wrong here, where set-but-empty is a value to forward.
    val forwardedEnv = forwardedEnvironment(parsed.env, name => Option(System.getenv(name))).fold(fail(_), identity)
    // The values stay in this process's memory and reach podman and the runner as a host value does
    // (forwardedEnvironment, RunOnHostChannel.spawnRunner): in an environment, never an argument.
    val awsCredential = parsed.awsCredential.map: request =>
      AwsCredential.resolve(
        request, name => Option(System.getenv(name)), name => findOnPath(name, os),
        command => run(command*), Instant.now(),
        forwardRegion = !parsed.env.exists(_.name == AwsCredential.RegionName),
      ).fold(fail(_), identity)

    // macOS only (run-on-host.md "Why only macOS"): elsewhere there is no Seatbelt backend, and a
    // container build already runs at host speed on host memory.
    val runOnHost = parsed.runOnHost.getOrElse(Vector.empty)
    if runOnHost.nonEmpty && os != Os.Mac then
      fail("error: --run-on-host is available on macOS only; on this host, run those programs in the container")

    val workspaceRoot = resolveWorkspaceRoot(os)
    // Before any read of the boundary configuration: boundaryDirRefusal has the forms, SECURITY.md the why.
    val boundaryDir = boundaryDirOf(workspaceRoot)
    boundaryDirRefusal(boundaryDir).foreach(fail(_))

    // The selected programs' rule files, read before anything is created: a binding is checked against
    // them below, and the launch's widening report prints them (LaunchMessages.runOnHostWideningLines).
    // The runner reads them again at a program's first command.
    val programRules = RunOnHostPrereqs.Program.values.toVector.filter(program => runOnHost.contains(program.name))
      .map: program =>
        RunOnHostPrereqs.readProgramRules(workspaceRoot, program).fold(fail(_), program -> _)
    LaunchSettings(
      options, credentials, image, imageOverridden, proxyImage, proxyImageOverridden, nesting, sessionStartMode,
      clipboard, clipboardHost, microphone,
      forwardedEnv, awsCredential, runOnHost, workspaceRoot, boundaryDir, programRules,
    )

  private def launchWorkspace(parsed: ParsedCommandLine, settings: LaunchSettings, os: Os): LaunchWorkspace =
    import parsed.workspaceMode
    import settings.{workspaceRoot, sessionStartMode}
    // -----------------------------------------------------------------------
    // Refuse obviously wrong workspace roots
    // -----------------------------------------------------------------------
    val homeProtection = protectedHomeDirectories(os, env).fold(fail(_), identity)
    homeProtection.warnings.foreach(warn)
    forbiddenWorkspaceRootReason(workspaceRoot, homeProtection).foreach: reason =>
      fail(s"error: refusing to mount ${pathInline(workspaceRoot, os)}\n\n$reason")
    forbiddenStateRootReason(os, stateRoot(os), workspaceRoot).foreach(fail(_))

    // -----------------------------------------------------------------------
    // Shared agent state
    // -----------------------------------------------------------------------
    //
    // Separate volumes keep settings and MCP commands written by one workspace out of another workspace's sessions
    // (SECURITY.md, "What the persistent volume holds"). This requires signing in separately for each workspace.
    // --persistent-volume opts into sharing that state across workspaces using the named volume, and
    // says so on a line of its own, whichever source gave it.
    // A linked worktree may instead share its main worktree's volume, which the reader agrees to
    // right here, under the two lines naming both directories and before podman announces
    // itself: the question is about those two lines and nothing that follows. A launch that
    // holds nothing keeps this worktree's own volume and says so, naming the option a launch
    // without the prompt shares through: after a launch that agreed, a scripted one would
    // otherwise seem to have lost the main worktree's logins.
    val sharedVolume = parsed.persistentVolume.map: shared =>
      sharedVolumeNameRefusal(shared).foreach(reason => fail(s"error: $reason"))
      shared
    // Named under the option too, where nothing is asked: the read-only git mount reads it.
    val mainWorktree = SandboxWorkspace.mainWorktreeOf(workspaceRoot, homeProtection, os)
    // Where the container has the workspace: the same path, so nothing on either side translates
    // (SandboxWorkspace.mountPathOf). What the image has there is asked, or read from the cache of
    // an earlier answer, once the image is known, below, still before any per-workspace resource
    // exists.
    val mountPath = mountPathOf(os, workspaceRoot).fold(fail(_), identity)
    System.err.println(
      pathLine("workspace root", workspaceRoot, os, tint = chosen(_)) +
        workspaceModeClause(workspaceMode, settings.options.from("--workspace", os), mountPath, os),
    )
    mainWorktree.foreach(main => System.err.println(pathLine("main git worktree", main, os)))
    sharedVolume.foreach: shared =>
      System.err.println(sharedVolumeLine(shared, settings.options.from(PersistentVolumeOption, os)))
    // The answer said back as the workspace root and egress lines say their modes: an answer is a
    // choice, and either continues the launch.
    val sharedWithMain: Option[Path] = mainWorktree.filter(_ => sharedVolume.isEmpty).filter: _ =>
      confirmSharedVolume(sessionStartMode, terminalReader) match
        case Some(true) =>
          System.err.println(s"agent state: ${chosen("shared")} with the main git worktree")
          true
        case Some(false) =>
          System.err.println(s"agent state: this worktree's ${chosen("own")}")
          false
        case None =>
          System.err.println(
            "agent state: this worktree's own; a launch without the prompt shares agent state " +
              s"through $PersistentVolumeOption",
          )
          false

    // Detected this early because the read-only mode's refusal below must come before any resource exists;
    // every fileBind reads it again further down. Enforcing specifically:
    // permissive and disabled hosts read every mount unrelabeled, so relabeling there would be
    // a host-metadata write with no benefit.
    val selinuxEnforcing = os == Os.Linux &&
      findOnPath("getenforce", os)
        .exists(path => run(path.toString).text.trim == "Enforcing")

    // An unfiltered bind mount on an SELinux-enforcing host is readable to the container only after
    // :Z relabels the workspace — a recursive host-metadata write, which is exactly the authority the
    // read-only mode withholds. Refused rather than relabeled, unless the tree already has a shared
    // container-accessible context, where a plain read-only bind needs no host write.
    if workspaceMode == "read-only" && selinuxEnforcing && !selinuxContainerReadable(workspaceRoot) then
      fail(
        s"""error: --workspace=read-only cannot mount $workspaceRoot on this SELinux-enforcing host
           |Reading an unfiltered bind mount here requires relabeling the workspace (:Z), a recursive
           |host-metadata write that --workspace=read-only never makes. Use --workspace=live — the filter's
           |mountpoint needs no relabel — or relabel the workspace yourself
           |(chcon -R -t container_file_t -l s0 <dir>; the level clears any categories a
           |previous :Z assigned to one container) and relaunch.""".stripMargin,
      )

    // -----------------------------------------------------------------------
    // Per-workspace identity
    // -----------------------------------------------------------------------
    //
    // Names this workspace root and suffixes everything podman holds for it. The directory name alone would
    // collide — two workspace roots called `app` must not share credentials or a ruleset — so the hash covers
    // the whole path; moving a workspace yields new resources and new sign-ins.
    val workspaceSlug = slugOf(workspaceRoot.getFileName.toString)
    val workspaceId = workspaceIdOf(workspaceRoot, os)
    // -----------------------------------------------------------------------
    // Persistent volume
    // -----------------------------------------------------------------------
    //
    // The volume this session mounts ("Shared agent state", above).
    val persistentVolume = sharedVolume
      .orElse(sharedWithMain.map(mainWorktreeVolume(_, os)))
      .getOrElse(persistentVolumeName(workspaceId))
    // Read against the host here, before anything is created, like the rule files: the directories
    // are bound into the sandbox unrelabeled, so an enforcing host is asked whether the container
    // can read them, as it is about the workspace.
    val claudePlugins =
      if parsed.claudePlugins.isEmpty then Vector.empty
      else
        ClaudePlugins.resolve(
          parsed.claudePlugins,
          ClaudePlugins.SessionWritten(workspaceRoot, "the workspace, which the session writes")
            +: hostCommandWrites(os).fold(fail(_), identity),
          os,
          directory => !selinuxEnforcing || selinuxContainerReadable(directory),
        ).fold(fail(_), identity)
    LaunchWorkspace(
      homeProtection, mainWorktree, mountPath, selinuxEnforcing, workspaceSlug, workspaceId, persistentVolume,
      claudePlugins,
    )

  /**
   * The directories outside the workspace that `--run-on-host` commands write (SeatbeltProfile.render's
   * grants): the caches under the launcher's cache root, where each lies once a symlink is
   * followed (RunOnHostPrereqs.writtenCacheDirectories), and every session's `tmp/` under the host
   * commands' root. The cache root and the host commands' root are named whole, as a reset removes
   * the cache tree and the root holds every session's directory. Named whether or not the launch
   * runs host commands: a plugin there is also under a reset's removal. The Left, where the caches
   * cannot be found, refuses every plugin: none can be shown to lie outside them.
   */
  private def hostCommandWrites(os: Os): Either[String, Vector[ClaudePlugins.SessionWritten]] =
    val caches = RunOnHostPrereqs.cacheRootOf(os, env).toOption match
      case None => Right(Vector.empty)
      case Some(cacheRoot) =>
        RunOnHostPrereqs.writtenCacheDirectories(cacheRoot)
          .left.map: reason =>
            s"error: ${ClaudePlugins.OptionName}; $reason, so no plugin can be shown to lie outside them"
          .map: written =>
            ClaudePlugins.SessionWritten(
              cacheRoot, s"the launcher's cache directory $cacheRoot, which --run-on-host commands write",
            ) +: written.map: cache =>
              ClaudePlugins.SessionWritten(cache, s"the --run-on-host cache $cache, which host commands write")
    val sessions = Option.when(os == Os.Mac):
      val root = RunOnHostSession.root(com.sun.security.auth.module.UnixSystem().getUid.toInt)
      ClaudePlugins.SessionWritten(root, s"the host commands' directory $root, which --run-on-host commands write")
    caches.map(_ ++ sessions)

  private def launchImages(settings: LaunchSettings, workspace: LaunchWorkspace, os: Os): LaunchImages =
    import settings.{image, imageOverridden, workspaceRoot}
    import workspace.{mountPath, workspaceId}
    // -----------------------------------------------------------------------
    // Sandbox image
    // -----------------------------------------------------------------------
    //
    // No implicit pull: image rollout is separate from running an agent.
    val imageInspected = run(
      podman, "image", "inspect",
      "--format",
      "{{.Id}}{{println}}" + // imageId: every run of the image and every cache stamp below
        s"$BundleLabelTemplate{{println}}" + // the version lock
        "{{range .Config.Env}}{{println .}}{{end}}", // JdkTrust's JAVA_HOME
      image,
    )
    if !imageInspected.ok then
      fail(
        s"""error: sandbox image not found: $image
           |
           |Build it first: run this launcher with --build.""".stripMargin,
      )
    val imageInspect = imageInspected.text
    // Every later run of the image names this Id rather than `image`: a build or a retag can move
    // the name after this inspect, and this Id is what the version lock checks and what the caches
    // below are stamped with. The proxy image's Id is used the same way.
    val imageId = imageInspect.linesIterator.nextOption().getOrElse("")
    val imageLabel = imageInspect.linesIterator.drop(1).nextOption().getOrElse("")
    val imageEnv = imageInspect.linesIterator.drop(2).mkString("\n")

    // A mount path the image has an entry at, or that the sandbox user cannot reach, is refused
    // before the filter's preparation, the networks and the TLS state, so a refusal writes
    // nothing (mountPathRefusal has the cases).
    //   - The probe is a run of the image, 0.2 s on a macOS podman machine (2026-09-18), so its
    //     `absent` is cached per image Id, written once the workspace's cache directory exists below.
    //   - A miss runs beside the sandbox image's version lock and the proxy image's inspect; its
    //     refusals come between theirs.
    val mountPathAnswerFile = rulesetStateRoot(os).resolve(workspaceId).resolve("mount-path.answer")
    val cachedMountPath = cachedMountPathAnswer(mountPathAnswerFile, imageId, mountPath)
    val awaitMountPathProbe = cachedMountPath.fold(
      inBackground("mount path probe")(probeMountPath(podman, imageId, mountPath)),
    )(answer => () => answer)

    // A jar upgrade must never run silently against images an earlier jar built; checked before
    // any resource exists. bundleMismatch has the refuse-versus-warn reasoning.
    bundleMismatch(image, bundledSourceId("ko-agent-sandbox"), imageLabel).foreach: mismatch =>
      if imageOverridden then warn(mismatch)
      else fail(s"error: $mismatch")

    import settings.{proxyImage, proxyImageOverridden}

    // The proxy side of the version lock above (proxyImageLock).
    val proxyInspected = inspectProxyImage(proxyImage)

    val mountPathProbe = awaitMountPathProbe()
    if !mountPathProbe.ok then
      fail(s"error: could not ask $image about $mountPath\n${mountPathProbe.err}")
    mountPathRefusal(mountPathProbe.text, workspaceRoot, mountPath).foreach(fail(_))

    if !proxyInspected.ok then
      fail(
        s"""error: egress proxy image not found: $proxyImage
           |
           |The sandbox has no route to the Internet of its own; this proxy is
           |what it reaches instead. Build it first: run this launcher with
           |--build.""".stripMargin,
      )
    val proxyImageId = versionLockedProxyImageId(proxyImage, proxyImageOverridden, proxyInspected.text)
    LaunchImages(imageId, imageEnv, proxyImageId, mountPathAnswerFile, cachedMountPath, mountPathProbe)

  private def launchRules(
    parsed: ParsedCommandLine,
    settings: LaunchSettings,
    workspace: LaunchWorkspace,
    images: LaunchImages,
    os: Os,
  ): LaunchRules =
    import parsed.{command, egressProfile, workspaceMode}
    import settings.{boundaryDir, credentials, programRules, workspaceRoot, runOnHost}
    import workspace.{mountPath, workspaceId}
    import images.{cachedMountPath, imageId, mountPathAnswerFile, mountPathProbe, proxyImageId}
    // -----------------------------------------------------------------------
    // This workspace's boundary configuration
    // -----------------------------------------------------------------------
    //
    // The workspace's egress/ is read here on the host and handed to the proxy at startup.
    // readRuleFiles has the forms, SECURITY.md the why. What keeps a session from writing the
    // next one's rules is the workspace mode itself: the read-only mode's `ro` bind of the raw tree, or
    // the live mode's FUSE reserved-name rule.
    val ruleFiles = readRuleFiles(boundaryDir.resolve("egress")).fold(fail(_), identity)

    // The workspace files a host program executes on an event (FileRules), read as the egress rules
    // are and resolved to what the filter and the Seatbelt profile enforce. The filter's guard adds
    // to them at the mount; under --workspace=read-only with --run-on-host, where no daemon runs,
    // `ko-agent-fs --resolve` does.
    val workspaceFileRules = FileRules.readRuleFile(boundaryDir.resolve("file")).fold(fail(_), identity)
    val fileRuleLines = FileRules.resolve(workspaceFileRules.fold(Vector.empty[FileRules.Line])(_(1)))
    val fileRulesInForce = workspaceMode == "live" || runOnHost.nonEmpty
    val fileRulesText = FileRules.daemonText(fileRuleLines, FileRules.hostView(os, mountPath))
    val readOnlyFileRules = Option.when(workspaceMode == "read-only" && runOnHost.nonEmpty)(
      resolveFileRules(podman, os, workspaceId, mountPath, fileRulesText),
    )

    // The providers the launch selects (EgressRules.selectedProvider), and the one warning that is
    // the launcher's to print.
    val provider = selectedProvider(parsed.modelProviders, command.headOption, egressProfile).fold(fail(_), identity)
    if provider.isEmpty then noProviderLine(command.headOption.orElse(Some("bash")), egressProfile).foreach(warn)

    // Validated before anything is created: invalid rules would otherwise appear as "could not determine the
    // egress proxy's address" after the --rm proxy died, the reason buried in its log. Cached like the CA bundle below,
    // under the stamp below, and only success is written.
    // Enforcement never reads this cache: the proxy re-resolves the same variables at startup, so corruption can at
    // worst misprint the banner, never widen what is enforced.
    val rulesetCacheDir = rulesetStateRoot(os).resolve(workspaceId)
    createPrivateDirectories(rulesetCacheDir)
    recordWorkspaceRoot(workspacesStateRoot(os), workspaceId, workspaceRoot)
    if cachedMountPath.isEmpty then cacheMountPathAnswer(mountPathAnswerFile, imageId, mountPath, mountPathProbe)

    val resolvedHostsFile = rulesetCacheDir.resolve("resolved.hosts")
    val resolvedWarningsFile = rulesetCacheDir.resolve("resolved.warnings")
    // The stamp covers everything the dry run reads: the image, the selected options — the
    // profile and the provider variable's value as the proxy receives it, so no selection and a
    // value the proxy would refuse never share a stamp — and the files,
    // hashed into its one line because they are multi-part. It is the first line of each cached
    // file rather than a file of its own, and a hit needs both to hold it: concurrent launches of
    // one workspace under different session options write here without a lock, and a stamp
    // beside the content can end up describing the other launch's (FileHelper.stampedEntry).
    val rulesetStamp =
      s"$proxyImageId $egressProfile ${provider.getOrElse("")} " +
        sha256Hex(ruleFiles.map((name, text) => s"$name: $text").mkString("\n"))

    // The dry run's warnings are cached beside the hosts, so an idle denial or an unreachable
    // provider is said at every launch, not only the one that missed the cache.
    // stampedEntry gives back exactly what was cached, trailing newline and all removed, so a hit
    // and a miss are one string. This one is hashed into the agent instructions' stamp: two
    // spellings of the same ruleset would make every launch after a re-resolve rewrite the shared
    // agents.md for nothing (FileHelper.writeWithMode).
    val cachedRuleset =
      (stampedEntry(resolvedHostsFile, rulesetStamp).filter(_.nonEmpty),
        stampedEntry(resolvedWarningsFile, rulesetStamp))
    val (rulesetText, rulesetWarnings) =
      cachedRuleset match
        case (Some(hosts), Some(warnings)) => (hosts, warnings)
        case _ =>
          val resolved = resolvedRuleset(podman, proxyImageId, egressProfile, provider, ruleFiles)
          if !resolved.ok then
            fail(rulesetRefusal(resolved.err))
          val warnings = resolved.err.linesIterator.filter(_.startsWith("warning:")).mkString("\n")
          writeStamped(resolvedHostsFile, rulesetStamp, resolved.text)
          writeStamped(resolvedWarningsFile, rulesetStamp, warnings)
          (resolved.text, warnings)

    // The leaf's names, from the dry run (inspectedHostsOf); a ruleset change reissues the leaf
    // through leaf.sans below. Empty: no leaf, no inspection material.
    val inspectedHosts = inspectedHostsOf(rulesetText).fold(fail(_), identity)
    // Read now, so a dry run the banner cannot state fails the launch before its proxy starts.
    val egressLine = egressBanner(
      rulesetText, settings.options.from("--egress", os),
      settings.options.providersFrom(provider.toVector.flatMap(_.split(",")), os),
    ).fold(fail(_), identity)

    // Each binding must reach a proxy that inspects its host: the session's, or a selected
    // program's, whose proxy inspects every host of its rules (RunOnHostSandbox.credentialHosts).
    EgressCredentials.checkHosts(
      parsed.credentialBindings, inspectedHosts.toSet, tunnelHostsOf(rulesetText).toSet,
      programRules.map((program, hosts) => program.name -> RunOnHostSandbox.credentialHosts(program, hosts)).toMap,
    ).fold(fail(_), identity)
    val sessionCredentials = EgressCredentials.bindingsFor(credentials, inspectedHosts.toSet)
    LaunchRules(
      ruleFiles, workspaceFileRules, fileRuleLines, fileRulesInForce, fileRulesText, readOnlyFileRules, provider,
      rulesetCacheDir, rulesetText, rulesetWarnings, inspectedHosts, egressLine, sessionCredentials,
    )

  private def gitAccess(
    settings: LaunchSettings,
    workspace: LaunchWorkspace,
    images: LaunchImages,
    rules: LaunchRules,
    os: Os,
  ): GitAccess =
    import settings.workspaceRoot
    import workspace.{homeProtection, mainWorktree, mountPath, selinuxEnforcing}
    import images.imageId
    import rules.rulesetCacheDir
    val noGit = SandboxWorkspace.noGit(workspaceRoot, homeProtection, os)
    // A linked worktree's main Git directory, bound read-only where the container can follow the
    // pointer there (SandboxWorkspace.linkedGitdirBind) and can read it once bound: the image must
    // have nothing at the target (the workspace root's probe, asked again of this path); on an
    // SELinux-enforcing host, the directory must carry a container-readable label, which the
    // launcher never gives a workspace (SECURITY.md, "the workspace's SELinux labels"); and
    // the repository must not set the extension the image's git refuses
    // (SandboxWorkspace.setsRelativeWorktrees). Each refusal is said with the git warning, since
    // the warning alone would read as a linked worktree this launcher does not recognize.
    val gitdirBind = noGit.collect { case NoGit.Gitdir(_, _, _) => () }
      .flatMap(_ => mainWorktree.flatMap(main => SandboxWorkspace.linkedGitdirBind(workspaceRoot, main, os)))
    val gitdirBindRefusal: Option[String] = gitdirBind.flatMap: bind =>
      if SandboxWorkspace.setsRelativeWorktrees(bind.source) then
        Some(
          "the repository sets extensions.relativeWorktrees, which the sandbox image's git does not know; " +
            "git there would refuse the repository",
        )
      else if selinuxEnforcing && !selinuxContainerReadable(bind.source) then
        Some(
          s"${pathInline(bind.source, os)} has no container-readable SELinux label; " +
            s"chcon -R -t container_file_t -l s0 ${pathInline(bind.source, os)} gives it one for the next launch",
        )
      else
        val probe = mountPathAnswer(podman, imageId, bind.target, rulesetCacheDir.resolve("gitdir-mount-path.answer"))
        Option.when(!probe.ok || probe.text.trim != "absent"):
          s"the sandbox image cannot take a mount at ${bind.target}"
    val mountedGitdir = gitdirBind.filter(_ => gitdirBindRefusal.isEmpty)
    val gitInstruction = mountedGitdir
      .map(SandboxWorkspace.readOnlyGitInstruction(_, mountPath))
      .orElse(noGit.map(SandboxWorkspace.noGitInstruction(_, mountPath)))
    GitAccess(noGit, mountedGitdir, gitdirBindRefusal, gitInstruction)

  /** This workspace's TLS state and agent instructions, this run's copies of what the containers mount,
    * and the proxy container, all under the workspace lock: the sandbox container's file arguments. */
  private def prepareRunFiles(
    parsed: ParsedCommandLine,
    settings: LaunchSettings,
    workspace: LaunchWorkspace,
    images: LaunchImages,
    rules: LaunchRules,
    names: RunNames,
    git: GitAccess,
    tlsDir: Path,
    runFiles: Path,
    logDir: Path,
    runLogs: Path,
    hostLogFile: Path,
    os: Os,
  ): Vector[String] =
    import parsed.{egressProfile, workspaceMode}
    import settings.{image, runOnHost}
    import workspace.{claudePlugins, mountPath, workspaceId, workspaceSlug, selinuxEnforcing}
    import images.{imageEnv, imageId, proxyImageId}
    import rules.{inspectedHosts, provider, ruleFiles, rulesetCacheDir, rulesetText, sessionCredentials}
    import names.{egressNetwork, proxyContainer, sandboxNetwork}
    import git.gitInstruction
    // -----------------------------------------------------------------------
    // This workspace's TLS inspection CA, and this run's mount sources
    // -----------------------------------------------------------------------
    //
    // The CA the sandbox trusts for TLS inspection. Created here; the key stays on the host, only the leaf and its own
    // key reach the proxy. SECURITY.md ("Who holds the CA key") has the reasoning.
    //
    // Under the workspace lock, because every step is check-then-act over shared files: two first
    // launches that both find no usable CA would otherwise interleave their writes and leave one
    // launch's ca.key beside the other's ca.crt. The lock spans the checks through the per-run
    // copies and the proxy's create, so what this run mounts is one launch's consistent set; it
    // cannot span further — podman resolves bind sources at container *start*, past the
    // interactive hold — and the per-run copies are what close that remainder. What the lock
    // cannot cover is a launch that
    // *died* between two writes, which is the coherence checks' job below: they test that key and
    // certificate match each other, not merely that both look fine.
    val caCertFile = tlsDir.resolve("ca.crt")
    val caKeyFile = tlsDir.resolve("ca.key")
    val leafCertFile = tlsDir.resolve("leaf.crt")
    val leafKeyFile = tlsDir.resolve("leaf.key")
    val leafSansFile = tlsDir.resolve("leaf.sans")
    val bundleFile = tlsDir.resolve("sandbox-ca-bundle.crt")
    val bundleStampFile = tlsDir.resolve("bundle.stamp")

    val sanList = inspectedHosts.map("DNS:" + _).mkString(",")
    val reissueDeadline = Instant.now().plusSeconds(ReissueMarginSeconds)

    // Session-specific instructions point to the ruleset environment variable rather than embed
    // the host list in every prompt. Read the image's file, append the session's instructions, and
    // mount the result over it. All installed agents' instruction files link to this path, so one
    // mount reaches all of them. LaunchMessages.agentDocumentStamp keys the cached assembly.
    val agentDocFile = rulesetCacheDir.resolve("agents.md")
    val agentDocStampFile = rulesetCacheDir.resolve("agents.stamp")
    // The profile and provider need no stamp input of their own — the resolved text's first line
    // names both.
    val agentDocStamp = agentDocumentStamp(
      imageId, workspaceMode, rulesetText, runOnHost, gitInstruction, parsed.credentialBindings,
    )

    withFileLock(tlsDir.resolve(".lock")):
      // Which of this workspace's runs a container still names, for every pruning decision this
      // launch makes. Listed under the lock and in every state, because a run's directories — of
      // logs, of mount copies — are created under this lock and its proxy created before the
      // lock is released: a run whose files another launch can see has a container in that
      // launch's listing, or died before creating one. A launcher dead between its create and
      // start left a created container, which keeps the files until a reset removes it. A failed
      // listing prunes nothing — unknown liveness must not read as "no live runs" and delete a
      // running session's files out from under it. A run is live while either of its containers
      // exists: the proxy writes its logs, and so do the runner and the relay, which serve the
      // sandbox container; the mount copies serve both containers. A run whose proxy crashed
      // while its sandbox lives on must keep them.
      val containers = run(podman, "ps", "--all", "--format", "{{.Names}}")
      val containerNames: Option[Vector[String]] =
        Option.when(containers.ok)(containers.text.linesIterator.map(_.trim).toVector)
      val liveRuns = liveRunsOf(workspaceId, containerNames)
      if containerNames.isEmpty then
        System.err.println(
          "note: could not list this workspace's containers; keeping every retained log and run file\n"
            + containers.err,
        )

      // A run's log directory names its run in the same suffix as its containers.
      liveRuns.foreach: live =>
        val entries = directoryEntries(logDir).map(_.getFileName.toString)
        runLogDirsToPrune(entries, RetainedRuns, live).foreach(name => deleteRecursively(logDir.resolve(name)))

      // Run copies whose runs are gone leave with this launch rather than accumulating; the resets
      // take the rest.
      liveRuns.foreach: live =>
        val entries = directoryEntries(tlsDir).map(_.getFileName.toString)
        tlsRunDirsToPrune(entries, live).foreach(name => deleteRecursively(tlsDir.resolve(name)))

      // After the pruning, which keeps one fewer than RetainedRuns: this run's directory brings the count to
      // RetainedRuns.
      createPrivateDirectories(runLogs)
      writePrivate(hostLogFile, "")

      // Coherence, not just expiry: a launch that died between writing the key and the
      // certificate leaves a pair that is unexpired, non-empty and useless — every handshake fails
      // while both files look fine — and only a correspondence test re-issues it.
      def coherentPair(certFile: Path, keyFile: Path): Boolean =
        (readIfPresent(certFile), readIfPresent(keyFile)) match
          case (Some(cert), Some(key)) => keyMatchesCertificate(cert, key)
          case _                       => false

      // This run's directory first: the copies below are written into it.
      createPrivateDirectories(runFiles)

      if !certificateExpiresAfter(readIfPresent(caCertFile), reissueDeadline)
        || !coherentPair(caCertFile, caKeyFile)
      then
        try
          val ca = createCa(workspaceSlug)
          // The leaf this CA no longer signs is retired by emptying it, not by deleting it: the
          // names stay stable for the copies below and for anything still reading them
          // (FileHelper.writeWithMode). Empty fails every expiry test below, so the leaf is
          // reissued in this same launch — and it is emptied before the CA is written, so a
          // launch that dies here leaves a leaf that the next one reissues rather than one
          // silently signed by the old CA.
          Seq(leafCertFile, leafKeyFile).foreach(writePrivate(_, ""))
          writeReadable(leafSansFile, "")
          writePrivate(caKeyFile, ca.privateKeyPem)
          writePrivate(caCertFile, ca.certificatePem)
        catch
          case ex: Exception =>
            fail(s"error: could not create this workspace's inspection CA in $tlsDir\n$ex")

      // The leaf is reissued when the CA is (emptied just above), when the list of inspected names changes, and before
      // it expires — and not issued at all for a ruleset that inspects nothing. Its own coherence
      // check, plus the chain to this CA: a leaf another launch issued under a CA since replaced
      // is internally consistent and still fails every handshake.
      if inspectedHosts.nonEmpty
        && (!certificateExpiresAfter(readIfPresent(leafCertFile), reissueDeadline)
          || firstLine(leafSansFile) != sanList
          || !coherentPair(leafCertFile, leafKeyFile)
          || !readIfPresent(leafCertFile).exists(signedBy(_, Files.readString(caCertFile))))
      then
        try
          val leaf = issueLeaf(
            Files.readString(caCertFile),
            Files.readString(caKeyFile),
            inspectedHosts,
          )
          writePrivate(leafKeyFile, leaf.privateKeyPem)
          writePrivate(leafCertFile, leaf.certificatePem)
          writeReadable(leafSansFile, sanList + "\n")
        catch
          case ex: Exception =>
            fail(s"error: could not issue this workspace's inspection certificate\n$ex")

      // The sandbox's trust: the image's own CA bundle — not the workstation's, a different set
      // entirely — plus the CA this run trusts. Re-read when image or CA changes; the stamp records
      // both (imageId comes from the sandbox image's inspect).
      val caFingerprint = certificateFingerprint(pemBody(Files.readString(caCertFile)))
      val bundleStamp = s"$imageId $caFingerprint"

      // The image's files both caches below are made from, read in one run of the image when both
      // are stale, as after a rebuild.
      val bundleStale = readIfPresent(bundleFile).forall(_.isEmpty) || firstLine(bundleStampFile) != bundleStamp
      val agentDocStale =
        readIfPresent(agentDocFile).forall(_.isEmpty) || firstLine(agentDocStampFile) != agentDocStamp
      val imageBundlePath = "/etc/ssl/certs/ca-certificates.crt"
      val (imageFiles, imageFilesMissing) = readImageFiles(
        podman, imageId,
        Vector(imageBundlePath).filter(_ => bundleStale) ++ Vector(AgentDocPath).filter(_ => agentDocStale),
      )

      if bundleStale then
        val imageBundle = imageFiles.get(imageBundlePath).filter(_.nonEmpty)
          .getOrElse(fail(s"error: could not read the CA bundle out of $image\n$imageFilesMissing"))
        val bundleText =
          String(imageBundle, StandardCharsets.US_ASCII).stripLineEnd + "\n" +
            Files.readString(caCertFile)
        writeReadable(bundleFile, bundleText)
        writeReadable(bundleStampFile, bundleStamp + "\n")

      // The JVM reads a `cacerts` keystore and no proxy variable, so the bundle above and the
      // HTTPS_PROXY family cannot reach it; JdkTrust.scala handles all of it, and empty means
      // the image ships no JDK.
      val jdkFileMounts = jdkMounts(
        podman, imageId, imageEnv, tlsDir, bundleStamp, caCertFile, EgressProxyHost, EgressProxyPort,
        selinuxEnforcing,
      )

      if agentDocStale then
        val imageDoc = imageFiles.get(AgentDocPath).filter(_.nonEmpty)
          .getOrElse(fail(s"error: could not read the agent instructions out of $image\n$imageFilesMissing"))
        writeReadable(
          agentDocFile,
          String(imageDoc, StandardCharsets.UTF_8).stripLineEnd
            + appendedSection(
              mountPath, workspaceMode, rulesetText, runOnHost, os == Os.Mac, gitInstruction, parsed.credentialBindings,
            ),
        )
        writeReadable(agentDocStampFile, agentDocStamp + "\n")

      // This run's copies, made while the lock still holds so no concurrent launch's rewrite can
      // happen between an expiry check above and a copy below; a file this run wrote into its own
      // directory is mounted where it is. Modes travel with the copy: the leaf key stays
      // owner-only, and the run directory itself allows only this user.
      def carried(source: Path): Path =
        if source.startsWith(runFiles) then source
        else
          val target = runFiles.resolve(source.getFileName)
          Files.copy(
            source, target,
            StandardCopyOption.COPY_ATTRIBUTES, StandardCopyOption.REPLACE_EXISTING,
          )
          target

      // The leaf and its key only: the CA key is stored beside them and is never copied or
      // mounted, and a ruleset that inspects nothing gets no material — the proxy refuses material
      // it has nothing to inspect with. --userns makes an owner-only key readable as uid 65532;
      // without it the key would have to be world-readable on the host. (The userns flag itself
      // stays on the create call: the proxy writes its owner-only log file through the same
      // mapping.)
      val proxyTls = proxyTlsArgs(
        if inspectedHosts.isEmpty then ProxyTlsMaterial.Uninspected
        else ProxyTlsMaterial.Leaf(carried(leafCertFile), carried(leafKeyFile)),
        selinuxEnforcing,
      )

      // The host plugins' marketplace manifest and managed drop-in, this run's own files
      // (ClaudePlugins.scala has the layout); the plugin directories are bound where they are.
      val marketplaceRoot = runFiles.resolve(ClaudePlugins.RunFilesDirectory)
      val pluginDropIn = runFiles.resolve(ClaudePlugins.DropInFile)
      if claudePlugins.nonEmpty then
        val manifest = marketplaceRoot.resolve(ClaudePlugins.MarketplaceFile)
        Files.createDirectories(manifest.getParent)
        writeReadable(manifest, ClaudePlugins.marketplaceText(claudePlugins))
        writeReadable(pluginDropIn, ClaudePlugins.dropInText(claudePlugins))

      val preparedSandboxFiles = sandboxFileArgs(
        carried(bundleFile), carried(caCertFile),
        jdkFileMounts.map((file, at) => (carried(file), at)), carried(agentDocFile),
        selinuxEnforcing,
      )
        ++ ClaudePlugins.mountArgs(marketplaceRoot, pluginDropIn, claudePlugins, selinuxEnforcing)
        // The JDK files' facts once more, as `-D` words, for the JVMs that read no file (JdkTrust.scala).
        ++ javaHomeOf(imageEnv).map(home =>
          s"--env=KO_AGENT_SANDBOX_JAVA_OPTS=${jdkJavaOpts(home, EgressProxyHost, EgressProxyPort)}"
        ).toVector

      // -----------------------------------------------------------------------
      // Proxy container
      // -----------------------------------------------------------------------
      //
      // A session keeps the ruleset it started with; the next launch re-reads.
      // --rm, so a proxy whose process exits removes itself. The audit-log bind is its only writable
      // path; the native executable needs no scratch filesystem. Created here, still under the lock,
      // so no sweep that lists under it (the top of this block) sees this run's files above without
      // a container naming the run; a launch that dies before this create leaves files no
      // container names, which is what that sweep is for. Started once the lock is released.
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
          memoryArguments(Some(ProxyMemoryLimit), None, None) ++ Vector(
            "--pids-limit=512",
            "--http-proxy=false",
            s"--userns=keep-id:uid=$ContainerUid,gid=$ContainerGid",
          ) ++ rulesetEnvArgs(egressProfile, provider, ruleFiles) ++ upstreamProxyArgs(env)
          ++ proxyCredentialArgs(sessionCredentials)
          ++ proxyTls ++ proxyLogArgs(hostLogFile, selinuxEnforcing) ++ Vector(proxyImageId)*
      )
      if !proxyCreated.ok then
        fail(s"error: could not create the egress proxy container\n${proxyCreated.err}")

      preparedSandboxFiles

  /** `git --version` on the host, or None where no git answers on PATH. */
  private def hostGitVersionLine(): Option[String] =
    try
      val run = HostCommands.run("git", "--version")
      Option.when(run.exit == 0)(String(run.out, StandardCharsets.UTF_8).trim)
    catch case _: IOException => None

  /**
   * The warning for a host git older than 2.34, whose `git bisect` is a shell script that runs `eval`
   * over `.git/BISECT_NAMES`, a file the filter lets a session write since 2.34 reads it as data
   * (`fuse/ko-agent-fs/src/policy.rs`, `classify_within_gitdir`). For every live workspace: a session
   * writes the gitdir of any repository below the root, whether or not the root's own git works or its
   * main gitdir is mounted read-only. `versionLine` is read only then.
   */
  def oldGitBisectWarning(workspaceMode: String, versionLine: => Option[String]): Option[String] =
    if workspaceMode != "live" then None
    else
      versionLine.flatMap: line =>
        raw"git version (\d+)\.(\d+)".r
          .findFirstMatchIn(line)
          .map(found => (found.group(1).toInt, found.group(2).toInt))
          .collect:
            case (major, minor) if major < 2 || (major == 2 && minor < 34) =>
              s"host git $major.$minor is older than 2.34: its `git bisect` evaluates .git/BISECT_NAMES as " +
                "shell code, a file a session may write. Do not run git bisect on the host in this workspace, " +
                "or upgrade git."

  private def printLaunchLines(
    parsed: ParsedCommandLine,
    settings: LaunchSettings,
    workspace: LaunchWorkspace,
    rules: LaunchRules,
    mount: LaunchMount,
    git: GitAccess,
    hostLogFile: Path,
    os: Os,
  ): Unit =
    import settings.{awsCredential, credentials}
    import rules.{
      egressLine, fileRulesInForce, inspectedHosts, workspaceFileRules, ruleFiles, rulesetText, rulesetWarnings,
    }
    import mount.{joinedRules, sessionRuleLines}
    import git.{gitdirBindRefusal, mountedGitdir, noGit}
    // The egress profile with its relevant state, said every launch, as the workspace root line
    // says the workspace mode: first the dry run's counts, the proxy's own answers to exactly what is
    // enforced, then each line of the egress rule file once (HostCommands.ruleFileReport), so rules
    // that arrived with the repository never take effect unseen.
    // Each line tints what the user chose; a line stating a boundary weaker than the default tints
    // its grant instead (HostCommands.weakened).
    val options = settings.options
    // Qualifies the workspace root line's mode: the mount is sound, and git is not there, or reads
    // the main worktree's Git directory and writes nothing. Every mode, since what git needs is
    // absent from the container under each.
    mountedGitdir match
      case Some(bind) => warn(readOnlyGitWarning(bind, os))
      case None       => noGit.foreach(cause => warn(noGitWarning(cause, os)))
    gitdirBindRefusal.foreach: reason =>
      System.err.println(s"note: the main worktree's Git directory is not mounted; $reason")
    oldGitBisectWarning(parsed.workspaceMode, hostGitVersionLine()).foreach(warn)
    joinedRules match
      case Some(running) =>
        warn(joinWarning(running))
        FileRules.runningLaunchLines(sessionRuleLines).foreach(System.err.println)
      case None => if fileRulesInForce then FileRules.launchLines(workspaceFileRules).foreach(System.err.println)
    System.err.println(egressLine)
    EgressRules.launchLines(ruleFiles, rulesetText).foreach(System.err.println)
    // The transport, when this launch passed HTTPS_PROXY: the proxy's own line, from its own
    // parse, so what is on the screen is what is used — never a launcher-side reading of the
    // variable.
    if upstreamProxyArgs(env).nonEmpty then
      val said =
        try Files.readString(hostLogFile)
        catch case ex: IOException => fail(s"error: cannot read $hostLogFile: ${ex.getMessage}")
      val transport = transportLineOf(said).getOrElse(
        fail("error: the egress proxy reported no transport line before listening; the image is not this launcher's"),
      )
      System.err.println(transport.replace("upstream proxy", chosen("upstream proxy")))
    if rulesetWarnings.nonEmpty then System.err.println(emphasized(rulesetWarnings))
    if inspectedHosts.isEmpty then
      System.err.println("egress tls inspection: this ruleset inspects no hosts; no leaf issued")
    // Names only: a forwarded value may be a secret, and this line is the one place the forward
    // is said aloud, since the variable is otherwise indistinguishable from the image's own.
    if parsed.env.nonEmpty then
      val fromFile = options.fileValues("--env").toSet
      val source = options.from("--env", os)
      System.err.println(forwardedEnvironmentLine(parsed.env.map(_.name), fromFile, source))
    awsCredential.foreach: resolved =>
      System.err.println(AwsCredential.bannerLine(resolved, Instant.now()) + options.from(AwsCredential.OptionName, os))
    // Loud as a loosening: code that runs in the session without a tool call, which the image's
    // allowManagedHooksOnly otherwise keeps out, chosen on the host (SECURITY.md).
    // A plugin is the file's when the file names its directory: a directory both sources spell alike
    // the command line supplies (CommandLine.merge), and one spelled otherwise is a second plugin of
    // that name, which ClaudePlugins.resolve refuses.
    if workspace.claudePlugins.nonEmpty then
      val fromFile =
        options.fileValues(ClaudePlugins.OptionName).flatMap(spelled => realPath(Path.of(spelled))).toSet
      val source = options.from(ClaudePlugins.OptionName, os)
      val sourceOf = (plugin: ClaudePlugins.Plugin) => if fromFile(plugin.directory) then source else ""
      System.err.println(ClaudePlugins.bannerLine(workspace.claudePlugins, sourceOf))
    if credentials.nonEmpty then
      val fromFile = options.fileValues("--egress-cred").toSet
      val source = options.from("--egress-cred", os)
      val sourceOf = (credential: BrokeredCredential) => if fromFile(credential.binding.spelled) then source else ""
      EgressCredentials.bannerLines(credentials, sourceOf).foreach(System.err.println)
      System.err.println(s"note: ${EgressCredentials.SubstitutionNote}")

  /** The sandbox container's `podman create`, saying aloud each loosening it carries. */
  private def sandboxCreateCommand(
    parsed: ParsedCommandLine,
    settings: LaunchSettings,
    workspace: LaunchWorkspace,
    images: LaunchImages,
    rules: LaunchRules,
    names: RunNames,
    mount: LaunchMount,
    git: GitAccess,
    proxyIp: String,
    sandboxFiles: Vector[String],
    machineMemory: Option[Long],
    os: Os,
  ): Vector[String] =
    import parsed.{command, workspaceMode}
    import settings.{
      awsCredential, clipboard, credentials, forwardedEnv, microphone, nesting, programRules, workspaceRoot, runOnHost,
      sessionStartMode,
    }
    import workspace.{mountPath, persistentVolume}
    import images.imageId
    import rules.{fileRulesInForce, rulesetText}
    import names.{sandboxContainer, sandboxNetwork}
    import mount.{filteredWorkspace, sessionRuleLines}
    import git.mountedGitdir
    // -----------------------------------------------------------------------
    // How the sandbox reaches it
    // -----------------------------------------------------------------------
    //
    // --dns=none: proxied programs CONNECT by name and never resolve; the
    // effective no-external-DNS property comes from the internal network.
    // Defence in depth, not a fix for a known hole — SECURITY.md has the
    // measurement; do not remove this believing it closes one. --add-host
    // supplies the one name that must work, read back from podman so no
    // subnet is reserved. proxyVariables has the variables.
    val egressProxyUrl = s"http://$EgressProxyHost:$EgressProxyPort"

    val egressArgs = Vector(
      s"--network=$sandboxNetwork",
      "--dns=none",
      s"--add-host=$EgressProxyHost:$proxyIp",
    ) ++ proxyVariables(egressProxyUrl).map((name, value) => s"--env=$name=$value") ++ Vector(

      // Keep the proxy's resolved rules available on demand. Metadata about the workspace's rule
      // file stays with the terminal; the agent needs the grants actually in force (rulesetLinesOf).
      // Revealing the rules grants no access: an agent could discover them by probing, slowly
      // and noisily, and mistake refusals for a broken environment in the meantime.
      s"--env=KO_AGENT_SANDBOX_EGRESS_RULESET=${rulesetLinesOf(rulesetText)}",

      // The entrypoint holds its machine-health warning on screen under the same setting as
      // confirmStart, for the same reason: the TUI clears it otherwise.
      s"--env=$SessionStartVariable=$sessionStartMode",
    ) ++ sandboxFiles

    // The rule lines the session's writes are held to, for the agent to consult on a refusal; what
    // the filter's guard adds at the mount comes after the container exists and is not among them.
    val fileRuleArgs = Option.when(fileRulesInForce)(
      s"--env=KO_AGENT_SANDBOX_FILE_RULES=${sessionRuleLines.map(_.text).mkString("\n")}",
    ).toVector

    // The nested-container loosenings (NestingLoosenings has the what and why). Loud every session
    // they apply: the weaker boundary must never be the silent one.
    val nestingEnv = s"--env=$NestingVariable=$nesting"
    val nestedArgs = nesting match
      case "none" => Vector(nestingEnv)
      case mode =>
        System.err.println(nestingLine(mode, settings.options.from("--nesting", os)))
        NestingLoosenings :+ nestingEnv

    // Loud for the same reason. WAYLAND_DISPLAY, because Claude Code and Copilot copy through
    // wl-copy only when they see a display, and otherwise through OSC 52, which Terminal.app
    // ignores; the value names the shim so nothing mistakes it for a compositor.
    val clipboardArgs = clipboard match
      case "off" => Vector.empty
      case mode =>
        System.err.println(clipboardLine(mode, settings.options.from("--clipboard", os)))
        Vector(s"--env=$ClipboardVariable=$mode") ++
          (if mode == "bidirectional" then Vector("--env=WAYLAND_DISPLAY=ko-sandbox-clipboard") else Vector.empty)

    // Loud for the same reason; the entrypoint starts the daemon these variables name.
    val microphoneArgs =
      if microphone.isEmpty then Vector.empty
      else
        System.err.println(micLine(settings.options.from(AudioOption, os)))
        MicrophoneRelay.sandboxEnvironment().map((name, value) => s"--env=$name=$value")

    // Loud for the same reason: host-native execution is authority a container session alone does
    // not have. SECURITY.md "Run on host" is what bounds it.
    val runOnHostArgs =
      if runOnHost.isEmpty then Vector.empty
      else
        runOnHostLines(runOnHost, workspaceMode, settings.options.from("--run-on-host", os)).foreach(System.err.println)
        runOnHostWideningLines(programRules.map((program, hosts) => program.name -> hosts)).foreach(System.err.println)
        Vector(s"--env=${RunOnHostChannel.RunOnHostVariable}=${runOnHost.mkString(",")}")

    // -----------------------------------------------------------------------
    // Workspace bind mount
    // -----------------------------------------------------------------------
    val workspaceVolume = workspaceBind(filteredWorkspace.map(_.mountpoint), workspaceRoot, mountPath)

    // -----------------------------------------------------------------------
    // Memory limit
    // -----------------------------------------------------------------------
    //
    // The Coursier OOM in container/debian-coursier/Containerfile demonstrates why memoryLimit
    // reserves memory for Podman's service, which every session needs. For diagnosis, see
    // "The whole machine degrades" in fuse/ko-agent-fs/doc/troubleshooting.md.
    val explicitMemory = parsed.memory.map(_.trim).filter(_.nonEmpty)
    val availableMemory = hostMemoryAvailable(os, readIfPresent(Paths.get("/proc/meminfo")).getOrElse(""))
    if machineMemory.isEmpty && explicitMemory.isEmpty then
      warn("podman info reports no machine memory; the sandbox runs without a memory limit")
    val memoryArgs = memoryArguments(explicitMemory, machineMemory, availableMemory)

    // -----------------------------------------------------------------------
    // The sandbox container: create, arm the reaper, then attach
    // -----------------------------------------------------------------------
    //
    // create + start --attach rather than one `podman run`, so the reaper's `podman wait` has a container to bind to
    // before anything watches it. Killed between the two, the launcher leaves a never-started stray; the reaper removes
    // it after a bounded wait, the resets sweep the rest.
    Vector(
      podman, "create",

      // What the reaper waits on; --rm, so a session normally leaves nothing behind with this name.
      s"--name=$sandboxContainer",
      "--rm",
      "-it",

      "--pull=never",
      "--init",

      // Map the invoking rootless podman user to our fixed non-root user. Files created in the workspace consequently
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
    ) ++ nestedArgs ++ clipboardArgs ++ microphoneArgs ++ runOnHostArgs ++ egressArgs ++ fileRuleArgs ++ Vector(

      // The host's zone, because the JVM resolves it on every platform the launcher runs on. The image
      // ships tzdata and nothing else sets a zone, so without this a commit made in the sandbox
      // carries +0000 and the agent's "today" turns over at the wrong hour.
      s"--env=TZ=${posixTz(ZoneId.systemDefault())}",
    ) ++ forwardedEnv ++ awsCredential.toVector.flatMap(_.names.map(name => s"--env=$name"))
      ++ placeholderArgs(credentials) ++ Vector(

      // The deliberate host exposure; what the agent writes here is untrusted input to host programs (SECURITY.md, "The
      // workspace").
      "--volume", workspaceVolume,
    ) ++ mountedGitdir.toVector.flatMap(bind => Vector("--volume", s"${bind.source}:${bind.target}:ro")) ++ Vector(

      // Anonymous, removed on exit: caches work without becoming cross-session attack state.
      "--mount", s"type=volume,dst=$ContainerHome",

      // Persist auth/config; ~/.claude, ~/.codex, ~/.gemini, ~/.kiro, ~/.copilot, ~/.local/share/kiro-cli and
      // opencode's XDG directories are symlinks into this volume. This is podman-owned storage, not a bind mount
      // into the host HOME.
      "--mount", s"type=volume,src=$persistentVolume,dst=$ContainerHome/persistent-volume",

      // Chromium treats podman's 64 MB /dev/shm default as fatal; agy's browser automation needs more. Not a host RAM
      // reservation.
      "--shm-size=512m",
    ) ++ memoryArgs ++ Vector(
      "--workdir", mountPath,
      imageId,
    ) ++ command.toVector

  /** The create, the reaper, the filter's mount and the command runner, then the handover to the
    * sandbox: what follows the hold. */
  private def startSandbox(
    parsed: ParsedCommandLine,
    settings: LaunchSettings,
    workspace: LaunchWorkspace,
    rules: LaunchRules,
    names: RunNames,
    mount: LaunchMount,
    createCommand: Vector[String],
    filterReap: Option[String],
    runFiles: Path,
    channelLogFile: Path,
    microphoneLogFile: Path,
    cleanup: RunCleanup,
    os: Os,
  ): Nothing =
    import settings.{awsCredential, clipboard, clipboardHost, credentials, microphone, workspaceRoot, runOnHost}
    import workspace.{mountPath, workspaceId}
    import rules.readOnlyFileRules
    import names.{egressNetwork, proxyContainer, sandboxContainer, sandboxNetwork}
    import mount.{filteredWorkspace, sessionRulesText}
    // The AWS values in the create's own environment, where its value-less `--env=NAME` reads them;
    // checked again here, since the hold above may have outlasted them.
    awsCredential.flatMap(AwsCredential.expiredSince(_, Instant.now())).foreach(message => fail(message))
    val created = runWithEnvironment(awsCredential.map(_.environment).getOrElse(Map.empty), createCommand*)
    if !created.ok then
      fail(s"error: could not create the sandbox container\n${created.err}")

    // In this run's own directory: the reaper's microphone job reports its probe here.
    val microphoneJob = microphone.filter(_ => os != Os.Windows).map: recorders =>
      MicrophoneJob(runFiles.resolve("microphone.status"), microphoneLogFile, recorders)

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
          microphoneJob,
        )
    if os != Os.Windows && !reaperArmed then
      // Except when a relay was asked for: the sandbox would wait the clipboard shim's bound on
      // every paste, or dictate nothing, for a relay that never comes. The cleanup hook removes
      // what was created, the never-started sandbox included (removeRunResources).
      if clipboard != "off" then
        fail(
          s"error: could not spawn the proxy reaper, which serves --clipboard=$clipboard; launch again, or without it",
        )
      if microphone.nonEmpty then
        fail(s"error: could not spawn the proxy reaper, which serves $MicOption; launch again, or without it")
      System.err.println("note: could not spawn the proxy reaper; staying resident to remove the proxy on exit")
    clipboardHost.powershell.foreach(ClipboardRelay.startResident(_, podman, sandboxContainer, clipboard))

    // The launch probe, before the sandbox starts: the recorder that delivers is the session's.
    // A launch whose microphone cannot record fails here, its cleanup hook removing what was made.
    microphone.foreach: recorders =>
      val notice = () =>
        System.err.println("microphone: answer macOS's microphone permission prompt; the launch waits up to a minute")
      def recording(label: String, silent: Boolean): Unit =
        System.err.println(s"microphone: recording with $label")
        if silent then warn(MicrophoneRelay.silenceWarning(os))
      microphoneJob match
        case Some(job) =>
          MicrophoneRelay.awaitProbe(job.status, os, notice) match
            case MicrophoneRelay.ProbeOutcome.Recording(label, silent) => recording(label, silent)
            case MicrophoneRelay.ProbeOutcome.Failed(reasons) => fail(MicrophoneRelay.failureMessage(reasons, os))
        case None =>
          MicrophoneRelay.probeResident(recorders, MicrophoneRelay.probeBoundSeconds(os), microphoneLogFile) match
            case Right(kept) =>
              recording(kept.recorder.label, kept.silent)
              MicrophoneRelay.startResident(kept, podman, sandboxContainer, microphoneLogFile)
            case Left(reasons) =>
              val diagnosis = findOnPath("powershell", os)
                .map(MicrophoneRelay.windowsDiagnostics).getOrElse(Vector.empty)
              fail(MicrophoneRelay.failureMessage(reasons, os, diagnosis))

    // Said here, not on the workspace line above: the user should not have to infer "joined" from
    // silence, and which branch the mount took is known only now.
    val mountedFileRules = filteredWorkspace.map: prepared =>
      val (joined, resolved) =
        mountKoAgentFs(podman, os, prepared, workspaceId, mountPath, sandboxContainer, sessionRulesText)
      System.err.println(
        if joined then "ko-agent-fs filter: joined the existing mount for this workspace"
        else "ko-agent-fs filter: mounted",
      )
      resolved
    val resolvedFileRules = mountedFileRules.orElse(readOnlyFileRules)
    resolvedFileRules.map(FileRules.guardLines).getOrElse(Vector.empty).foreach(System.err.println)

    // The command runner, detached like the reaper: it must outlive the exec below, and it ends
    // itself when the sandbox stops. A session that asked for the channel and cannot have it is a
    // failed launch, as with the clipboard above.
    if runOnHost.nonEmpty then
      // In this run's own directory, removed with it, where the runner and each command read it.
      val runnerFileRules = runFiles.resolve("file-rules.resolved")
      resolvedFileRules.foreach(resolved => writePrivate(runnerFileRules, resolved.text))
      if !RunOnHostChannel.spawnRunner(
          podman, sandboxContainer, workspaceRoot, runOnHost, channelLogFile, mountPath,
          // A brokered name reaches a host command as the sandbox has it: its placeholder.
          forwards = parsed.env ++ awsCredential.toVector.flatMap(_.forwards) ++ credentials.map(credential =>
            EnvForward(credential.binding.name, Some(credential.placeholder)),
          ),
          fileRules = resolvedFileRules.map(_ => runnerFileRules),
          credentials = credentials,
        )
      then fail("error: could not spawn the command runner, which serves --run-on-host")

    // Separate the launch diagnostics from the agent's terminal UI.
    System.err.println()

    handOver(
      Vector(podman, "start", "--attach", "--interactive", sandboxContainer),
      viaExec = reaperArmed,
      cleanup = cleanup,
    )
