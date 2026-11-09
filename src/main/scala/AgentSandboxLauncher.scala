// Run Claude Code, Codex, Antigravity, Kiro CLI, Copilot CLI or OpenCode inside a rootless podman container.
//
// One launcher serves Linux, macOS, WSL and native Windows. This file records the decisions, the flags and the
// sequence of steps, and SECURITY.md holds the threat model. Each neighbouring file holds the whole of one concern:
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
//   KoAgentFs.scala             the FUSE backend: build, install, identity, mount lifecycle
//   KoAgentBpf.scala            the BPF cgroup-LSM backend of --workspace=...,bpf: build, install, the
//                               probe, the launch's attach and proof, the teardown and the reconcile
//   SandboxWorkspace.scala      the workspace root: real path, refusals, identity, mount guards
//   InspectionCa.scala          the CAs the launcher creates; the proxy's CertificateHelper checks them
//   JdkTrust.scala              making the image's JVM reach the proxy: locate, prepare, mount
//   FFMHelper.scala             the downcalls into libc and kernel32
//   FileRules.scala             the file rules: defaults, the workspace's rule file, grammar, resolution
//   EgressCredentials.scala     --egress-cred: the bindings, their values, placeholders and proxies
//   ClipboardRelay.scala        the host clipboard offered to the sandbox: the protocol and both relays
//   MicRelay.scala              the host microphone under --audio=mic: the recorders, the probe and both relays
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
//    |     (SandboxWorkspace.mountPathOf). --workspace selects the mount:
//    |      - live, the default, mounts the ko-agent-fs mountpoint RW, with Git
//    |        entries and launcher configuration protected (mountKoAgentFs).
//    |        Under the bpf backend, live mounts the raw tree RW, and a BPF
//    |        policy on the container's cgroup holds the same protections
//    |        (KoAgentBpf).
//    |      - read-only binds the raw tree with podman's `ro` option. Under the
//    |        bpf backend, a policy also refuses every write on the share.
//    |
//    +-- .ko-agent-sandbox: the egress rules, the file rules and each
//    |      run-on-host program's egress rules, read on the host. The
//    |      workspace mode keeps a session from writing the next session's
//    |      rules.
//    |
//    +-- podman named volume -----------> ~/persistent-volume RW/persistent
//    |                                       (~/.claude, ~/.codex, ~/.gemini, ~/.kiro,
//    |                                        ~/.copilot, ~/.local/share/kiro-cli and
//    |                                        opencode's XDG directories are symlinks
//    |                                        into it)
//    |
//    +-- --run-on-host (macOS only): ko-sandbox-run-on-host relays a command
//    |      request to a host-side supervisor, which runs a build tool under a
//    |      Seatbelt profile. The profile grants the workspace (`.git` and
//    |      .ko-agent-sandbox denied), per-workspace build caches, one
//    |      Coursier JDK, a session directory, and the build's own loopback
//    |      egress proxy, and nothing else (RunOnHostSandbox.scala,
//    |      RunOnHostChannel.scala; SECURITY.md, "Run on host")
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
// The rest of /home/nonroot is an anonymous podman volume: build caches work, and they disappear with the container.
//
// The entrypoint records the workspace's mount path as trusted for Claude Code, Codex, Antigravity and Copilot at
// every launch (ko-sandbox-entrypoint). A mounted workspace's own agent configuration, MCP servers included, therefore
// takes effect without a trust dialog. The container, not that dialog, is the boundary: whatever the configuration
// names runs inside the container, never in a host-side helper.
//
// The launcher accepts no podman arguments. Podman merges most flags rather than replacing them, so a caller-supplied
// --volume or --cap-add could silently reopen the boundary. The launcher parses only its session options and
// management actions (CommandLine.parseArguments). The first non-option is the command, and the launcher forwards
// everything from there verbatim to the container.

package agentsandbox.launcher

import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, Paths, StandardCopyOption}
import java.time.{Instant, ZoneId, ZoneOffset}
import java.time.format.DateTimeFormatter
import agentsandbox.egress.{AgentEgressProxy, BrokeredCredential, CredentialGrammar, X509Helper}
import agentsandbox.egress.CertificateHelper.*
import agentsandbox.egress.LogHelper.sha256Hex

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

  // These values must agree with the UID and GID that the Containerfile creates.
  val ContainerUid = 65532
  val ContainerGid = 65532

  // The launcher reissues a certificate a month before expiry, so no session starts on a certificate that expires
  // mid-run.
  val ReissueMarginSeconds = 2592000L

  // -------------------------------------------------------------------------
  // Run resource names
  //
  // These functions are pure and unit-tested: they name this run's containers and networks. LauncherState.scala
  // decides which podman objects the resets may touch, and SandboxWorkspace.scala holds the workspace's own identity
  // and guards.
  // -------------------------------------------------------------------------

  /**
   * What a session may nest inside itself, as `--nesting` selects it:
   * - `none`, the default, runs under the launcher's seccomp profile (SeccompProfile), which refuses creating a user
   *   namespace and every mount syscall.
   * - `user-namespace` runs under podman's default profile, which allows both.
   * - `same-uid` also grants the listed loosenings for the whole session, so a rootless container runtime runs, at
   *   the cost that SECURITY.md describes ("No containers inside the sandbox by default").
   *
   * Each loosening of `same-uid` has a measured reason:
   * - `unmask=ALL`: a nested pid namespace must mount a fresh /proc, and the kernel refuses that mount while the
   *   masked entries remain mounted on /proc. Measured: a bare unshare fails with EPERM with the masks in place, with
   *   SELinux permitting the mount and SYS_CHROOT granted.
   * - `label=disable`: SELinux denies that mount for plain container_t (EACCES, reproduced by a bare unshare with no
   *   runtime involved).
   *   - The narrower candidate is container_engine_t, container-selinux's type for containers that run containers.
   *     That type permits the mount but cannot exec the `--init` that podman injects. Measured: "exec
   *     /run/podman-init: Permission denied" at session start.
   *   - Any future candidate must therefore be probed with --init in the run.
   * - `SYS_CHROOT`: layer unpack chroots, and the seccomp profile compiled for a no-capability container answers
   *   chroot with EPERM, even for root in a nested user namespace. The measured failure is every pull's "after
   *   fallback to chroot: operation not permitted".
   *   - Inner podman 6.0.2 behaves identically to the 5.4.2 that the recipe installs: the vendored unpack is the same
   *     code, and this outer container's filter decides.
   * - /dev/fuse is deliberately absent: nested storage runs on kernel-native overlay in the user namespace. Measured:
   *   the container rootfs mounts as `overlay`, and the matrix passes with the fuse-overlayfs binary removed.
   *
   * The session's environment always holds the resolved mode, `none` included, so an agent reads one variable with
   * one spelling instead of also handling an unset variable.
   *
   * The value `same-uid` is named for what is deliberately not loosened: no-new-privileges stays. That flag blocks
   * setuid newuidmap, so a nested runtime maps only the uid that this session already runs as. Images that switch
   * USER or chown to a second uid fail by design, and this repository's own images are among them.
   */
  final val NestingVariable = "KO_AGENT_SANDBOX_NESTING"
  val NestingLoosenings =
    Vector("--security-opt=unmask=ALL", "--security-opt=label=disable", "--cap-add=SYS_CHROOT")

  /**
   * How the sandbox addresses the proxy: a name that `--add-host` puts in /etc/hosts, so no resolver is involved, and
   * the port that the proxy listens on. The host and the port are named apart rather than only spelled into a URL,
   * because a JVM wants them as two properties rather than one (JdkTrust.jdkJavaOpts).
   */
  val EgressProxyHost = "egress-proxy"
  val EgressProxyPort = AgentEgressProxy.ListenPort

  /** The proxy variables that a process behind a proxy gets, in the sandbox container and in a host command alike.
    * - Both spellings are set, since traditional programs read lowercase, and loopback is exempt.
    * - HTTP_PROXY is set although plain HTTP is refused, so the proxy log records an http:// attempt, instead of the
    *   attempt failing as an unexplained resolution error. */
  def proxyVariables(proxyUrl: String): Vector[(String, String)] =
    Vector("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy").map(_ -> proxyUrl)
      ++ Vector("NO_PROXY", "no_proxy").map(_ -> "localhost,127.0.0.1")

  /** The variables that name a PEM bundle, set in the sandbox container and in a host command alike (SECURITY.md,
    * "Who holds the CA key"). run-on-host-internals.md lists which programs read each variable ("The command's lifetime
    * and environment"). */
  val CaBundleVariables: Vector[String] =
    Vector("SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "GIT_SSL_CAINFO")

  def isProxyReadyLine(line: String): Boolean = AgentEgressProxy.readyPort(line).contains(AgentEgressProxy.ListenPort)

  /** The bound covers a JVM start on a loaded machine. The launch fails a proxy that stays silent past the bound,
    * rather than waiting for it. */
  val EgressProxyReadyBound: java.time.Duration = java.time.Duration.ofSeconds(30)

  /**
   * Waits for the proxy to report ready, or fails with what the proxy wrote.
   * - `podman start` returns once the process is spawned, and says nothing about whether the process stayed up. A
   *   proxy that refuses at start, such as for a leaf naming other than its inspected set, would otherwise leave a
   *   sandbox with no egress and the reason in a log that nobody was shown.
   * - The method reads the run's host log, the file that the proxy tees to before the proxy does anything else. The
   *   method reads until AgentEgressProxy.ReadyLine comes from a proxy that is still running, or the container stops
   *   running, or `bound` elapses. Each failure reports what the proxy wrote.
   * - The method reads the file rather than `podman logs`, because the container is `--rm`. A proxy that refuses at
   *   once is gone, with its output, before a follower attaches, and the file outlives the container.
   *
   * When the proxy is ready, the method gives the proxy's networks as ProxyNetworksFormat prints them, from an
   * inspect that found the proxy running, so the launch need not ask podman for the networks again.
   */
  def awaitProxyReady(podman: String, container: String, log: Path, bound: java.time.Duration): Either[String, String] =
    val deadline = System.nanoTime() + bound.toNanos
    def said: String = readIfReadable(log).getOrElse("")
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
    // The ready line must come from a proxy that is still running. A proxy that is gone after writing the line is a
    // failure with its log, not an address that the launch cannot find.
    def exitedAfterReady: Either[String, String] = Left(s"the egress proxy exited after reporting ready\n$said")
    def readied: Either[String, String] =
      if networks.isEmpty && !inspected then exitedAfterReady
      else Right(networks.getOrElse(""))
    var outcome: Option[Either[String, String]] = None
    while outcome.isEmpty do
      if ready then outcome = Some(readied)
      else if !inspected then
        // The last write may arrive after the liveness answer, so the loop reads once more to name which exit this is.
        // The loop does not call `readied`, which would answer with the networks of an earlier inspect.
        if ready then outcome = Some(exitedAfterReady)
        else
          val written = said
          // If the proxy could not open its log, the refusal may appear only in podman's logs. `--rm` may also have
          // removed the container, and the refusal with it, before this read.
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
      // Each pass asks podman once, and the pause bounds how late the launch notices a proxy that is ready.
      else Thread.sleep(50)
    outcome.get

  /**
   * Starts the proxy container and waits for the proxy (`awaitReady`).
   * - With bindings, the start is attached. The bindings are written to the attached `podman start`'s standard input,
   *   which podman pipes to the proxy. The launch ends that client once the proxy is ready or gone, and
   *   `--sig-proxy=false` keeps podman from passing the signal on (SECURITY.md, "Who holds a brokered value";
   *   src/probe/podman-attach-stdin.sh).
   * - The remote client leaves `--sig-proxy` out of its help but honours the flag (podman's
   *   `cmd/podman/containers/start.go`).
   * - The client's output is the proxy's own output, which the log has.
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
        // The write runs on its own thread, because a client that never reads would hold the write, and the wait is
        // bounded.
        val writing = Thread.startVirtualThread: () =>
          try
            process.getOutputStream.write(bindings)
            process.getOutputStream.flush()
          catch case _: IOException => ()
        // What podman says when the start itself fails. Once the client is attached, the output is the proxy's own.
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
   * awaitProxyReady takes a container that is not running for an exited proxy, so awaitProxyReady would misread a
   * container that is still `created`. A container that already exited has run, and awaitProxyReady reports why from
   * its log.
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
   * Everything a launch prints, such as the workspace mode, the egress rules and every warning, stays on screen only
   * until the agent starts, because claude's fullscreen TUI and codex both clear the screen as they start.
   * - The launcher therefore waits for input after printing the launch information and before starting the agent.
   * - `--session-start=immediate` skips that wait, for whoever has read the lines enough times. Without a terminal,
   *   the launcher cannot wait for input.
   * - The variable tells the session the mode, and the entrypoint holds its own warning under the mode.
   */
  final val SessionStartVariable = "KO_AGENT_SANDBOX_SESSION_START"

  /** The clipboard mode inside the sandbox, which `--clipboard` selects (CommandLine.ClipboardModes). */
  final val ClipboardVariable = "KO_AGENT_SANDBOX_CLIPBOARD"

  /**
   * The variables that an option replaced, each with that option.
   * - A shell profile that exported such a variable would otherwise configure nothing, silently, so the launcher
   *   refuses each variable in its environment.
   * - The launcher refuses the variables that it sets inside the sandbox (`inSandbox`) on the host alone, because a
   *   launcher run in a session inherits them from the session.
   * - The option names are CommandLine's `final val` constants, inlined here. Initializing CommandLine from this
   *   object's initializer would read LauncherVariablePrefix before it is set (CommandLine.RefusedForwardPrefix).
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

  /** Why the environment fails every invocation of the launcher. The reason names each replaced variable that the
    * environment sets, and the option to pass instead. The reason offers a value back only when the option takes it.
    * `env` is the raw environment, so an exported empty variable is refused too, since it configures nothing either. */
  def replacedVariablesRefusal(env: String => Option[String], inSession: Boolean): Option[String] =
    val refused = ReplacedVariables.filterNot((_, _, inSandbox) => inSession && inSandbox).flatMap:
      (variable, option, _) =>
        env(variable).map: value =>
          val valid = value.nonEmpty && parseArguments(List(s"$option=$value")).isRight && !value.contains('\n')
          val keep = if valid then s", and pass $option=$value to keep that value" else ""
          s"error: the launcher does not read $variable; $option=${ValuedOptions(option)} replaces it. Unset it$keep"
    Option.when(refused.nonEmpty)(refused.mkString("\n"))

  /** Whether this process runs inside a sandbox session, which the image's `/etc/ko-agent-sandbox` shows. A host does
    * not have that directory (src/probe/PodmanMachineMemoryReclaim.scala asks the same). */
  def inSandboxSession(os: Os): Boolean = os == Os.Linux && Files.isDirectory(Paths.get("/etc/ko-agent-sandbox"))

  /**
   * The decision that the reader takes on the workspace and egress lines above.
   * - Enter or y starts, n declines, EOF at the prompt counts as n, and any other answer asks again.
   * - Ctrl-C ends the JVM through the shutdown hook, which is the same outcome as n.
   * - The prompt shows the full command, since the command's arguments are part of what the reader agrees to.
   * - With no reader, because there is no terminal or the mode is not pause, there is nothing to hold.
   * - When the hold returns, the hold's line is closed: by the reader's Enter, or by the hold itself at EOF, which
   *   echoes nothing.
   */
  def confirmStart(mode: String, command: Seq[String], reader: Option[Reader]): Boolean =
    startPrompt(mode, reader) match
      case None         => true
      case Some(reader) => agreed(reader, s"\nstart: ${command.map(renderArgument).mkString(" ")} [Y/n] ")

  /** The reader that the start prompt asks through, if the prompt asks at all. A consent that rides on that prompt
    * depends on this reader, such as joining a mount under other file rules (KoAgentFs.joinUnderOtherRules). */
  def startPrompt(mode: String, reader: Option[Reader]): Option[Reader] = reader.filter(_ => mode == "pause")

  /**
   * Whether a launch from a linked worktree shares its main worktree's agent-state volume.
   * - The answer is the reader's, taken as confirmStart takes its own. The answer is None where the launch holds
   *   nothing and so asks nothing (RunOnHostProvisioning follows the same rule).
   * - The launch asks under the lines that name the two directories, before anything else is printed or created.
   * - The default is yes, unlike the provisioning prompt's unconfined host run. The launch is from the repository that
   *   the main worktree checks out, and the volume shares the same user's logins for that repository.
   */
  def confirmSharedVolume(mode: String, reader: Option[Reader]): Option[Boolean] =
    reader.filter(_ => mode == "pause").map: reader =>
      reader.prompt(SharedVolumeExplained)
      agreed(reader, "\nReuse persistent volume? [Y/n] ")

  /** The launch prints this text once before the question, not with each repeat of the question. The text is one
    * line, as every launcher message is, and the terminal wraps it. */
  val SharedVolumeExplained: String =
    "\nDetected a linked worktree. Reusing the main worktree's persistent volume shares agent " +
      "credentials, history, configuration and MCP state.\n"

  /** One yes-or-no question whose default is yes. Enter or y agrees, n declines, EOF declines and closes the line, and
    * any other answer asks again. */
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

  /** What a hold prompts on and reads from. readLine answers None at EOF. */
  final case class Reader(prompt: String => Unit, readLine: () => Option[String])

  /**
   * The process's terminal, if stdin is one. Every prompt of the launcher asks through this reader.
   * - The method checks isTerminal, not only null. A console provider may answer a Console for a redirected stream,
   *   which is what Console.isTerminal exists to tell. Holding a pipe open would hang a scripted launch instead of
   *   skipping the hold.
   * - On Temurin 25.0.4.1's default provider, System.console() is null when stdin or stdout is redirected (measured
   *   2026-10-08), so the two checks agree there.
   */
  def terminalReader: Option[Reader] =
    Option(System.console()).filter(_.isTerminal).map: console =>
      Reader(text => console.printf("%s", text), () => Option(console.readLine()))

  /** The proxy streams bodies independently of their total size. Eight concurrent TLS downloads throttled to 1 MiB/s
    * peaked near 60 MB, while sequential multi-gigabyte transfers remained bounded. Even if the 64 MiB heap cap were
    * entirely additional to the measured peak, the 256 MiB limit would retain about 135 MiB for native and workload
    * overhead. */
  val ProxyMemoryLimit = "256m"

  /** `podman info --format '{{.Host.MemTotal}}'`, in bytes, or None when podman did not answer with a total. */
  def memoryTotal(answer: HostCommands.Run): Option[Long] =
    if !answer.ok then None else answer.text.trim.toLongOption.filter(_ > 0)

  /**
   * The sandbox's default memory limit.
   * - The limit is 1 GiB under the total of the machine that podman runs on: the podman machine VM, or the host on
   *   native Linux. Podman, the FUSE backend's daemon and the kernel need that 1 GiB to keep answering while the
   *   sandbox is at its limit.
   * - The limit is no more than the machine had available at launch, where that figure is known
   *   (hostMemoryAvailable). A native host is already running everything else, and a VM that is short is short.
   * - One limit cannot bound the sum: two sessions on one machine, or a host workload that increases after the
   *   launch, still add up past the limit. `--memory` is for that case.
   *
   * The one exception to the available bound is MinimumMemoryLimit, or the total on a machine smaller than that. The
   * limit never goes below that floor:
   * - Podman reads `--memory=0` as no limit at all. A host with nothing available would otherwise get no limit at the
   *   moment it can least afford it.
   * - A sandbox capped under what its agent needs dies before the agent says anything.
   * - With under 1 GiB available, the sandbox may therefore still take 1 GiB. The entrypoint's warning tells the user
   *   that the machine was that short.
   * - A machine under 2 GiB gets the same floor.
   */
  def memoryLimit(machineTotal: Long, availableAtLaunch: Option[Long]): Long =
    val fromTotal = machineTotal - (1L << 30)
    val bounded = availableAtLaunch.fold(fromTotal)(Math.min(fromTotal, _))
    Math.max(bounded, Math.min(MinimumMemoryLimit, machineTotal))

  /** What the agent CLIs and one modest build need to start at all. */
  val MinimumMemoryLimit: Long = 1L << 30

  /**
   * MemAvailable of this host, in bytes: what podman's containers can take before the host itself reclaims.
   * - The figure exists only where the launcher shares the kernel with the containers, on native Linux.
   * - On a podman machine, `podman info` reports MemFree, which a warm page cache makes meaningless, and the VM
   *   belongs to the sandbox alone.
   */
  def hostMemoryAvailable(os: Os, meminfo: => String): Option[Long] =
    os match
      case Os.Linux => memoryAvailable(meminfo)
      case _        => None

  /** `MemAvailable:` out of a `/proc/meminfo`, in bytes. */
  def memoryAvailable(meminfo: String): Option[Long] =
    meminfo.linesIterator
      .map(_.trim.split("\\s+"))
      .collectFirst { case Array("MemAvailable:", kb, _*) => kb.toLongOption }
      .flatten
      .map(_ * 1024)

  /**
   * Warn before the image builds when the machine has less than this amount available.
   * - The threshold lies below the cold-build peak that the warning quotes, on purpose. A 4 GiB machine, the size on
   *   which the threshold was chosen, idles near 3.3–3.6 GiB available. A threshold of that size trips at idle, and
   *   users learn to ignore such a warning.
   * - 3 GiB tells the two machine states apart. The warning stays quiet on an idle 4 GiB machine and speaks once
   *   running sessions hold real memory, the state in which a build degrades every session on the machine.
   * - The user answers, not the launcher, through a `[y/N]` prompt rather than a refusal. The builder's own heap is
   *   limited (the proxy Containerfile), so proceeding risks a slow or OOM-killed build rather than a frozen machine.
   *   The user at the console may accept that price. No stays the default, because the sessions at stake may not be
   *   that user's to spend.
   * - With no console, nobody can be asked, and the build proceeds with the warning. One instant of MemAvailable is
   *   too noisy to stop automation on.
   */
  val BuildMemoryWarnThreshold: Long = 3L << 30

  /**
   * A session launch does not build images, so the launch's headroom follows the agent's minimum memory allowance.
   * Below that allowance, the entrypoint warns about the shortage (memoryLimit explains the floor). Below half the
   * allowance, even starting the agent may exhaust available memory.
   */
  def launchMemoryHeadroom(available: Long): Headroom =
    if available >= MinimumMemoryLimit then Headroom.Ample
    else if available >= MinimumMemoryLimit / 2 then Headroom.Warned
    else Headroom.Short

  /**
   * Image builds and --stats share this scale, so the report helps the user decide whether the machine has room for
   * an image build. BuildMemoryWarnThreshold explains the build threshold. Below MinimumMemoryLimit, even an agent
   * session may exhaust available memory.
   */
  def buildMemoryHeadroom(available: Long): Headroom =
    if available >= BuildMemoryWarnThreshold then Headroom.Ample
    else if available >= MinimumMemoryLimit then Headroom.Warned
    else Headroom.Short

  def buildMemoryWarning(available: Option[Long]): Option[String] =
    available.filter(_ < BuildMemoryWarnThreshold).map: bytes =>
      s"the machine has ${humanBytes(bytes)} of memory available; a cold image build peaks near 3.3G\n" +
        "  exit running sandbox sessions, or raise it with `podman machine set --memory` (machine stopped)"

  /** After requirePodman's check, every podman action prints the machine's headroom once, beside the `using:` line.
    * - The figure is what the memory limit and the build's memory check act on, and the line shows the figure before
    *   they act.
    * - The line tints the figure on the action's scale (launchMemoryHeadroom, buildMemoryHeadroom).
    * - A figure that the machine cannot give prints nothing. */
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
   * MemAvailable of the machine that the image builds run on: this host on native Linux, and elsewhere the VM through
   * `podman machine ssh`.
   * - `podman machine ssh` is the one route to a machine figure, since `podman info` offers only MemFree
   *   (hostMemoryAvailable says why MemFree reads meaningless).
   * - None, for a missing field or a refused ssh, skips the warning rather than blocking a build.
   */
  def machineMemoryAvailable(os: Os, meminfo: => String, machineSsh: => HostCommands.Run): Option[Long] =
    os match
      case Os.Linux => memoryAvailable(meminfo)
      case _        => Some(machineSsh).filter(_.ok).flatMap(answer => memoryAvailable(answer.text))

  /**
   * `--memory-swap` equal to `--memory` forbids swap. Swap is the thrash that a limit exists to prevent, and podman's
   * default of twice the memory in swap is on the wrong side of that. An explicit limit gets the same treatment, for
   * the same reason.
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
   * The prefix of the variables that the launcher sets inside the sandbox to say what is in force
   * (CommandLine.RefusedForwardPrefix). No variable with this prefix configures the launcher. A variable that the
   * launcher sets for one of its own components has another prefix, `KO_AGENT_<component>_`, as KO_AGENT_FS_SOURCE_ID
   * and RunOnHostSandbox.carrierName have.
   */
  final val LauncherVariablePrefix = "KO_AGENT_SANDBOX_"

  /**
   * The proxy's address on one named network, out of the per-network listing that ProxyNetworksFormat prints as
   * `<network> <ip>` lines.
   */
  val ProxyNetworksFormat =
    "{{range $net, $conf := .NetworkSettings.Networks}}{{$net}} {{$conf.IPAddress}}{{println}}{{end}}"

  def addressOn(networksOutput: String, network: String): Option[String] =
    networksOutput.linesIterator
      .find(_.startsWith(network + " "))
      .map(_.drop(network.length + 1).trim)
      .filter(_.nonEmpty)

  /**
   * The sandbox container's name, which the reaper waits on. The suffix keeps concurrent sandboxes in one workspace
   * distinct.
   */
  def sandboxRunContainer(workspaceId: String, suffix: String): String =
    s"ko-agent-sandbox-run-$workspaceId-$suffix"

  /**
   * The proxy container's name, which shares the sandbox's run suffix. Each run gets its own proxy, which is removed
   * with its sandbox (SandboxLifecycle.scala has the reason).
   */
  def proxyRunContainer(workspaceId: String, suffix: String): String =
    s"ko-agent-egress-proxy-$workspaceId-$suffix"

  /**
   * This run's internal network, which the sandbox joins, with no gateway. The network is per run like the proxy
   * (createNetwork says why nothing is reused).
   */
  def sandboxRunNetwork(workspaceId: String, suffix: String): String =
    s"ko-agent-sandbox-$workspaceId-$suffix"

  /** This run's outbound network, the proxy's route out. The network is per run, as above. */
  def egressRunNetwork(workspaceId: String, suffix: String): String =
    s"ko-agent-egress-$workspaceId-$suffix"

  /** This run's disambiguator: always exactly eight hex characters (RunSuffixPattern), which lets isRunNamed anchor
    * on the suffix. */
  def newRunSuffix(): String =
    java.util.UUID.randomUUID().toString.take(8)

  val RunSuffixPattern = "[0-9a-f]{8}"

  /** The run's directory of mount sources under the workspace's TLS state. */
  def tlsRunDir(suffix: String): String = s"run-$suffix"

  /**
   * The run's directory of logs under the workspace's log directory.
   * - The launch's start (logStamp) comes first, so a sorted listing is chronological (runLogDirsToPrune).
   * - The run suffix comes last, so pruning matches a live run by the name's end, as tlsRunDirsToPrune does.
   */
  def runLogDir(stamp: String, suffix: String): String = s"run-$stamp-$suffix"

  val RunLogDirPattern: String = runLogDir("[0-9]{8}T[0-9]{6}Z", RunSuffixPattern)

  /**
   * The launch's start in its run's log directory name, in UTC. The audit lines in that directory's `proxy.log` are
   * UTC (SECURITY.md, "The audit line grammar"), and a local stamp would sort an older run after a newer one across
   * the end of daylight saving or a change of the host's zone.
   */
  def logStamp(now: Instant): String =
    DateTimeFormatter.ofPattern("uuuuMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC).format(now)

  /**
   * Whether `name` is `builder(workspaceId, <run suffix>)`, the anchored form of a bare prefix check.
   * - The anchor matters because hex is slug-legal, and a slug may be 32 characters. A directory literally named after
   *   another workspace's id yields resources that extend this workspace's prefix, and a --reset here would end that
   *   other workspace's live sessions.
   * - With the suffix anchored, a name matches exactly one workspace.
   * - The method takes the builder, so the builders above state the name pattern once.
   */
  def isRunNamed(builder: (String, String) => String, workspaceId: String)(name: String): Boolean =
    val prefix = builder(workspaceId, "")
    name.startsWith(prefix) && name.drop(prefix.length).matches(RunSuffixPattern)

  /**
   * The check that every podman-talking action runs first: a client that runs, and a service that answers and, where
   * `refuseRootful`, runs rootless (rootfulRefusal).
   *
   *   - On macOS and Windows the service is the podman machine. This check starts a stopped machine but never creates
   *     or resizes one, which is the boundary that SECURITY.md draws ("Silent changes to what you own"). `machine
   *     init` therefore stays the one manual step of a fresh install, and the next action, usually --build, brings the
   *     machine up itself.
   *   - The check gives the machine's total memory, which the launch reuses. Changing the total
   *     (`podman machine set --memory`) needs the machine stopped.
   *   - The check asks for the available memory beside `podman info`. On macOS and Windows the question goes through
   *     `podman machine ssh`, a second round trip to the machine. The check asks a machine that it starts again.
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
            // The probe's answer is discarded, since a stopped machine gives no answer. The probe is settled first, so
            // the probe does not run into the start.
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

  /** What requirePodman asks `podman info`, in one call: rootlessness, then MemTotal, one line each. */
  val PodmanInfoFormat = "{{.Host.Security.Rootless}}{{println}}{{.Host.MemTotal}}"

  /** Line `index` of a PodmanInfoFormat answer, as the answer that a format of that field alone would give. */
  def podmanInfoField(answer: HostCommands.Run, index: Int): HostCommands.Run =
    val line = answer.text.linesIterator.drop(index).nextOption().getOrElse("")
    answer.copy(out = line.getBytes(StandardCharsets.UTF_8))

  /**
   * SECURITY.md's "The containers run rootless" as a condition of every podman action except the actions that only
   * read or remove.
   * - A rootful service maps `--userns=keep-id` one to one onto the host's uids (podman's `GetKeepIDMapping`). The
   *   agent's uid is then the host's 65532, and the container's root is the host's root.
   * - An answer other than `true` refuses too, because rootlessness is then unknown.
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

  /** The sandbox and proxy images that the launcher runs, and whether `--image` or `--proxy-image` chose them. That
    * choice turns a version-lock mismatch from a refusal into a warning. */
  def sandboxImageChoice(chosen: Option[String]): (String, Boolean) = imageChoice(chosen, SandboxImage)
  def proxyImageChoice(chosen: Option[String]): (String, Boolean) = imageChoice(chosen, ProxyImage)
  private def imageChoice(chosen: Option[String], default: String): (String, Boolean) =
    chosen.fold((default, false))(image => (image, true))

  /** The proxy image's Id, then its bundle label: the answer that proxyImageLock reads. */
  def inspectProxyImage(proxyImage: String): Run =
    run(podman, "image", "inspect", "--format", s"{{.Id}}{{println}}$BundleLabelTemplate", proxyImage)

  /**
   * The version lock on the egress proxy image, for a launch and the egress actions alike. The launcher parses this
   * image's --print-ruleset output and environment interface, so a mismatched default image must not get as far as a
   * cryptic parse failure.
   * - Left is the refusal.
   * - Right is the Id to run the image by, and the warning that an overridden image gets in place of the refusal
   *   (bundleMismatch has the refuse-versus-warn reasoning).
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

  /** proxyImageLock's Id, after printing its warning. proxyImageLock's refusal ends the launcher. */
  def versionLockedProxyImageId(proxyImage: String, overridden: Boolean, inspect: String): String =
    proxyImageLock(proxyImage, overridden, inspect) match
      case Left(refusal) => fail(refusal)
      case Right((proxyImageId, warning)) =>
        warning.foreach(warn)
        proxyImageId

  /**
   * The per-run TLS mount-source directories that a launch may sweep: the directories named for a run
   * (`run-<8 hex>`) that no container names.
   * - `liveRuns` is a listing taken under the workspace lock, and a launch creates its proxy under that lock before
   *   releasing the lock. A directory that another launch can see therefore belongs to a run with a container, or to
   *   a launch that died, and never to a launch in flight.
   * - The reaper deliberately does not remove these directories, so the reaper's argument list stays fixed. The next
   *   launch's sweep and the resets remove them.
   */
  def tlsRunDirsToPrune(names: Seq[String], liveRuns: Set[String]): Seq[String] =
    names
      .filter(_.matches(tlsRunDir(RunSuffixPattern)))
      .filterNot(name => liveRuns.contains(name.stripPrefix(tlsRunDir(""))))

  /** The run suffixes of `workspaceId` that a container in `containerNames` names, the run's proxy or its sandbox.
    * None when the listing failed, so that nothing is pruned (prepareRunFiles says why either container counts). */
  def liveRunsOf(workspaceId: String, containerNames: Option[Vector[String]]): Option[Set[String]] =
    containerNames.map: names =>
      Vector(proxyRunContainer, sandboxRunContainer)
        .flatMap(builder => names.filter(isRunNamed(builder, workspaceId)).map(_.stripPrefix(builder(workspaceId, ""))))
        .toSet

  /**
   * Creates the network fresh every run. The name includes a random run suffix, so nothing can already have the name,
   * nothing is ever reused, and no pre-existing object's properties need vetting before the boundary rests on them. A
   * creation failure is a failed launch, stated with podman's own reason.
   */
  def createNetwork(network: String, internal: Boolean): Unit =
    val created =
      if internal then run(podman, "network", "create", "--internal", network)
      else run(podman, "network", "create", network)
    if !created.ok then
      fail(s"error: could not create the network $network\n${created.err}")

  /**
   * The question that a run of the image answers about the workspace's mount path (mountPathRefusal):
   * - `entry` when the image has something at the path, which the bind would cover: `/tmp`, `/usr/local/bin`, or a
   *   directory that the image gains later;
   * - `file <path>` when the nearest ancestor that the image has is not a directory, such as `/opt/node/bin/node`, so
   *   nothing can be mounted beneath it;
   * - `unreachable <dir>` when that ancestor is a directory that the sandbox user cannot enter, such as `/root`, so
   *   nothing mounted beneath it can be reached;
   * - `absent` otherwise. Podman creates the missing directories of a bind target inside the read-only root, so a
   *   path that the image has nothing at needs no scaffolding.
   * The launcher asks the image rather than a list, so no list goes stale. Only a Linux host spells such a path:
   * `/Users/…` and `/mnt/<drive>/…` sit beside the image's tree.
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

  /** The command passes `--entrypoint=` and `--network=none`, because the image's own program and egress are not the
    * question (readImageFiles has the same form). */
  def mountPathProbeCommand(podman: String, image: String, mountPath: String): Vector[String] =
    Vector(podman, "run", "--rm", "--pull=never", "--network=none", "--entrypoint=", image) ++
      quoteFreeSh(MountPathProbeScript, mountPath)

  /**
   * Each path's size in bytes on a line of its own and then the path's content, or `missing` on that line for a path
   * that is not a readable file. One run of the image thus reads several files.
   */
  val ImageFilesScript: String =
    """for p; do
      |  if [ -f "$p" ] && [ -r "$p" ]; then wc -c < "$p"; cat "$p"; else echo missing; fi
      |done""".stripMargin

  /**
   * The files at `paths`, read out of `imageId` in one run, by path, beside the reason any file is missing: the run's
   * stderr, or the paths at which the image has no readable file.
   * - When no path is asked for, nothing runs.
   * - The run passes `--entrypoint=`, because the answer must be the script's stdout alone, whatever ENTRYPOINT the
   *   image declares (JdkTrust.jdkMounts has the argument).
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

  /** The files that an ImageFilesScript answer holds, by path. A path answered `missing` has no file, and neither has
    * every path after an answer cut short. */
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
   * The stamp under which an image's answer about `mountPath` is cached. The probe reads only the image, so the answer
   * holds while the image Id, the probe script and the path are the ones the probe was asked with. The path is hashed,
   * because the stamp is one line.
   */
  def mountPathProbeStamp(imageId: String, mountPath: String): String =
    s"$imageId ${sha256Hex(MountPathProbeScript)} ${sha256Hex(mountPath)}"

  /** The probe's `absent` from `file`, when `absent` was cached for this image and path. */
  def cachedMountPathAnswer(file: Path, imageId: String, mountPath: String): Option[HostCommands.Run] =
    stampedEntry(file, mountPathProbeStamp(imageId, mountPath))
      .filter(_ == "absent")
      .map(answer => HostCommands.Run(0, answer.getBytes(StandardCharsets.UTF_8), ""))

  /** The probe, asked of `imageId`, the Id under which the answer is cached, and never of a name (launch's `imageId`
    * says why). */
  def probeMountPath(podman: String, imageId: String, mountPath: String): HostCommands.Run =
    run(mountPathProbeCommand(podman, imageId, mountPath)*)

  /** The image's answer about `mountPath`: cached in `file`, or probed now and cached when `absent`. */
  def mountPathAnswer(podman: String, imageId: String, mountPath: String, file: Path): HostCommands.Run =
    cachedMountPathAnswer(file, imageId, mountPath).getOrElse:
      val asked = probeMountPath(podman, imageId, mountPath)
      cacheMountPathAnswer(file, imageId, mountPath, asked)
      asked

  /** Caches `answer` in `file` when the answer is `absent`. Every other answer refuses, and the next launch asks
    * again. */
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
    // The private actions come before the ordinary parse and appear in no usage text, because they are not launch
    // options, and nothing outside this codebase spells them. Each private action re-invokes the launcher's own
    // executable, jar or native image (RunOnHostSandbox.selfInvocation).
    // - --serve-proxy-on-host hosts a command's egress proxy, configured by the EGRESS_* environment as in the
    //   container.
    // - --serve-run-on-host is the session's command runner (RunOnHostChannel).
    // - --run-command-on-host runs one channel request as the runner's own child.
    args.headOption match
      case Some("--serve-proxy-on-host") if args.length == 1 =>
        agentsandbox.egress.AgentEgressProxy.serve()
      case Some("--serve-run-on-host")  => RunOnHostChannel.serveMain(args.toSeq.drop(1))
      case Some("--run-command-on-host")  => RunOnHostSandbox.runCommandMain(args.toSeq.drop(1))
      case _                            => launcherMain(args)

  /**
   * The options that an action reads, from the command line and the options file alike. The action ignores the file's
   * other options, and refuses other options on its command line.
   * - `--reset` leaves the shared volume in place, as a launch mounts it.
   * - `--egress-check` sends no credential, so it reads no `--egress-cred`.
   */
  val ResetReads: Set[String] = Set(PersistentVolumeOption)
  val EgressEffectiveReads: Set[String] = Set("--egress", ModelProviderOption, "--egress-cred", ProxyImageOption)
  val EgressCheckReads: Set[String] = EgressEffectiveReads - "--egress-cred"

  /**
   * Whether KoAgentBpf.NoBpfOption is among an action's operands, which take nothing else. Native Linux refuses the
   * option, since it has only the FUSE backend and the option would select nothing.
   */
  def noBpfOperand(action: String, operands: List[String], os: Os): Either[String, Boolean] =
    val (stated, others) = operands.partition(_ == KoAgentBpf.NoBpfOption)
    if stated.sizeIs > 1 then Left(s"error: $action: ${KoAgentBpf.NoBpfOption} is given twice")
    else if stated.nonEmpty && os == Os.Linux then
      Left(
        s"error: $action: native Linux has only the FUSE backend, so ${KoAgentBpf.NoBpfOption} selects nothing; " +
          "drop it",
      )
    else if others.nonEmpty && os == Os.Linux then Left(s"error: $action takes no argument")
    else if others.nonEmpty then Left(s"error: $action takes no argument other than ${KoAgentBpf.NoBpfOption}")
    else Right(stated.nonEmpty)

  private def launcherMain(args: Array[String]): Unit =
    replacedVariablesRefusal(name => Option(System.getenv(name)), inSandboxSession(currentOs)).foreach(fail(_))

    val commandLine = parseArguments(args.toList).fold(fail(_), identity)

    // The action refusals below read the command line alone.
    def inForce(used: Set[String]): OptionsInForce =
      OptionsFile.inForce(commandLine, used)(
        OptionsFile.load(currentOs, resolveWorkspaceRoot(currentOs), name => Option(System.getenv(name))),
      ).fold(fail(_), identity)

    // The actions that read no session option refuse such an option rather than ignoring it, because a selection that
    // configures nothing is the silent failure mode that the options must not have.
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
        val noBpf = noBpfOperand("--build", rest, currentOs).fold(fail(_), identity)
        requirePodman(currentOs, buildMemoryHeadroom)
        confirmMemoryForBuilds(currentOs)
        build(currentOs, noBpf)

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
        // The resets only remove what carries this launcher's names, so the resets run against a rootful service too.
        requirePodman(currentOs, refuseRootful = false)
        resetWorkspace(currentOs, givenIds, options.parsed.persistentVolume, options.from(PersistentVolumeOption))

      // This action has no id form. A gone workspace's cache goes with `--reset <id>`, and this action exists for the
      // live workspace, whose directory is there to run from.
      case Some(("--reset-run-on-host", rest)) =>
        noSessionOptions("--reset-run-on-host")
        if rest.nonEmpty then fail("error: --reset-run-on-host takes no further arguments")
        resetRunOnHost(currentOs)

      // This action reads no options file. The reset removes only volumes that the launcher named (persistentVolumes),
      // so no shared volume is there to leave in place.
      case Some(("--reset-all", rest)) =>
        noSessionOptions("--reset-all")
        if rest.nonEmpty then fail("error: --reset-all takes no further arguments")
        requirePodman(currentOs, refuseRootful = false)
        resetAll(currentOs)

      // This action calls no requirePodman(). The report is read-only and reads host directories either way, and the
      // live section degrades to a note when podman or its machine is not there to answer.
      case Some(("--stats", rest)) =>
        noSessionOptions("--stats")
        if rest.nonEmpty then fail("error: --stats takes no further arguments")
        SandboxStats.stats(currentOs)

      // This action calls no requirePodman() here. With no arguments, the action reads host files only, and the
      // retained logs are documented as readable after every container is gone. EgressRules.egressLog asks for podman
      // on the branch that needs it.
      case Some(("--egress-log", rest)) =>
        noSessionOptions("--egress-log")
        egressLog(currentOs, rest)

      case Some(("--self-test", rest)) =>
        noSessionOptions("--self-test")
        val noBpf = noBpfOperand("--self-test", rest, currentOs).fold(fail(_), identity)
        requirePodman(currentOs, buildMemoryHeadroom)
        selfTest(currentOs, noBpf)

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

      // Reaching this case means that CommandLine.ManagementActions and this match drifted.
      case Some((action, _)) => fail(s"error: unhandled action $action")

      case None => launch(inForce(FileOptionNames.toSet))

  /** The TLS material that a proxy mounts: the leaf and its key, when the ruleset inspects a host. */
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

  /** With bindings, the container is created with `--interactive`, because `podman start` cannot open the container's
    * standard input later (podman-start(1)). Without bindings, the answer holds no arguments. */
  def proxyCredentialArgs(credentials: Seq[BrokeredCredential]): Vector[String] =
    if credentials.isEmpty then Vector.empty
    else Vector("--interactive", s"--env=${CredentialGrammar.StdinVariable}=${CredentialGrammar.StdinValue}")

  /** Each brokered name, set to its placeholder in the sandbox as an explicit value, since the host's value is the
    * secret. */
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
   * The files that the launcher mounts over the sandbox image's own.
   * - The bundle replaces the image's bundle.
   * - The variables cover programs with a trust store of their own (certifi, Node's roots).
   * - The JDK files cover the JVM, which reads neither.
   *
   * The CA on its own is for ko-sandbox-jdk-use-proxy. A JVM that the agent installs itself is out of the launcher's
   * reach, and that script hands the JVM this file. The file adds no exposure, because the same certificate is already
   * inside the bundle. The file only saves a script from parsing the certificate out.
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
   * The workspace's `--volume` value, which is never relabeled.
   * - A FUSE mountpoint must not be relabeled.
   * - Under `--workspace=read-only`, launchWorkspace's SELinux check established that the tree is already
   *   container-readable, and relabeling is the host write that this mode withholds.
   */
  def workspaceBind(fuseMountpoint: Option[String], workspaceRoot: Path, mountPath: String): String =
    fuseMountpoint match
      case Some(mountpoint) => s"$mountpoint:$mountPath:rw"
      case None             => s"$workspaceRoot:$mountPath:ro"

  /**
   * Whether the directory's own SELinux context already allows container reads, so a plain bind mount needs no
   * relabel. Such a context has a container type with no MCS categories.
   * - A context with categories, as a previous run's `:Z` leaves, is private to the container it was assigned to and
   *   unreadable to a new container, so the context does not count.
   * - The method asks only about the root. A partially labeled tree fails at runtime with EACCES on the stray files,
   *   and the host's own labeling must finish the tree.
   * - The method fails closed: a missing stat, an unreadable context or an unexpected context all answer false.
   *
   * stat resolves through findOnPath like every host executable, because this method runs before the sandbox exists,
   * and the working directory is the workspace root.
   */
  def selinuxContainerReadable(dir: Path): Boolean =
    findOnPath("stat", Os.Linux).exists: stat =>
      val context = run(stat.toString, "-c", "%C", dir.toString)
      val parts = if context.ok then context.text.trim.split(":") else Array.empty[String]
      parts.length == 4 && parts.lift(2).exists(Set("container_file_t", "container_share_t"))

  /**
   * The zone as a POSIX `TZ` value.
   * - A tzdata name passes through.
   * - A fixed offset is spelled `UTC-9`. The JVM falls back to a fixed offset, such as `GMT+09:00`, on a host whose
   *   zone the JVM cannot map to a name. POSIX reads the sign the other way round from ISO: `TZ=GMT+09:00` is nine
   *   hours *behind* UTC to every native program, while the JVM would read the value as ahead.
   * - Seconds are dropped. glibc honours `UTC-5:45:30`, but a JVM reads the value as `+05:45` (measured on Java 25), so
   *   passing seconds on would split the sandbox's own programs two ways. No zone has had a seconds offset for over
   *   fifty years.
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

  /** What a launch reads and refuses before it checks the workspace root: the options and where each option came
    * from, what the options select on the host, and the run-on-host rule files. */
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
    mic: Option[Vector[MicRelay.Recorder]],
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

  /** The FUSE backend's mountpoint for a live session, the probe's answer where the BPF backend serves this run
    * (KoAgentBpf), and the file rules that the session runs under. */
  private case class LaunchMount(
    fuseWorkspace: Option[KoAgentFsPrepared],
    bpf: Option[KoAgentBpf.Facts],
    /** The settings that this run runs under. They differ from the asked settings where the probe left a read-only
      * session without a policy. */
    settings: CommandLine.WorkspaceSettings,
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

  /** The launch, phase by phase. Each phase takes the earlier phases' results and imports by name the values that its
    * body reads from them. The cleanup and the hold stay here, because the cleanup reads `heldLineClosed`, and the hold
    * sets it. */
  def launch(options: OptionsInForce): Unit =
    val os = currentOs
    val parsed = options.parsed
    val settings = launchSettings(options, os)
    // The launch's first lines: the options that the file supplied, except those that another line states (ownLines),
    // so each option is printed once.
    options.fileLines(ownLines(settings, parsed), os).foreach(System.err.println)
    val workspace = launchWorkspace(parsed, settings, os)
    import parsed.command
    import settings.{workspaceRoot, runOnHost, sessionStartMode}
    import workspace.{mountPath, workspaceId}
    val workspaceSettings = parsed.workspaceSettings
    val machineMemory = requirePodman(os)

    // One suffix ties this run's containers, networks and log directory together in podman output and the retained
    // logs.
    val runSuffix = newRunSuffix()
    val logDir = logStateRoot(os).resolve(workspaceId)
    val runLogs = logDir.resolve(runLogDir(logStamp(Instant.now()), runSuffix))
    // The launch names the log directory before the directory exists. prepareRunFiles creates the directory after
    // pruning, and a launch refused earlier has written nothing there. Creating the directory here would let each
    // refused launch's empty directory count toward the RetainedRuns that pruning keeps.
    System.err.println(pathLine("log dir", runLogs, os, tint = lookedUp(_)))

    // The FUSE backend's read-only checks run beside the image and rule checks below. prepareKoAgentFs reads the
    // checks' answer once this run's cleanup is armed.
    val startedKoAgentFsChecks = Option.when(workspaceSettings.fuseMounted):
      val sourceId = bundledKoAgentFsSourceId()
      (sourceId, inBackground("ko-agent-fs checks")(koAgentFsChecks(podman, os, sourceId)))
    // The BPF backend's capability probe runs the same way (KoAgentBpf.checksScript). The launch reads the probe's
    // answer below, before anything of the run exists.
    val startedBpfChecks = Option.when(workspaceSettings.bpf):
      inBackground("ko-agent-bpf checks")(run(koAgentFsScriptCommand(podman, os, KoAgentBpf.checksScript(mountPath))*))

    val images = launchImages(settings, workspace, os)
    val rules = launchRules(parsed, settings, workspace, images, os)
    import rules.{fileRuleLines, fileRulesText, sessionCredentials}

    // -----------------------------------------------------------------------
    // This run's egress proxy
    // -----------------------------------------------------------------------
    //
    // The sandbox joins an internal network with no gateway. The sandbox's peers on that network are this run's proxy,
    // whose second interface has the route out, and podman's resolver, which answers only the run's names
    // (SECURITY.md, "DNS").
    // - The network is a boundary, not a configuration hint. Removing the proxy env variables below does not restore
    //   Internet access. The removal only makes the failure harder to diagnose.
    // - Every resource here is per run (SandboxLifecycle, "Removing what the run created").

    val names = RunNames(
      proxyRunContainer(workspaceId, runSuffix),
      sandboxRunContainer(workspaceId, runSuffix),
      // The network is per run, not per workspace, so concurrent sessions cannot reach each other. A compromised proxy
      // reaches the Internet and its own sandbox, never a neighbour with a wider ruleset.
      sandboxRunNetwork(workspaceId, runSuffix),
      egressRunNetwork(workspaceId, runSuffix),
    )
    import names.{egressNetwork, proxyContainer, sandboxContainer, sandboxNetwork}

    // The launch reads the BPF backend's probe now.
    // - A live session that the backend cannot serve is refused with what the machine lacks, each line with its
    //   remedy.
    // - A read-only session keeps the raw `ro` bind alone and says so. The no-root policy is the read-only mode's
    //   defence against a descriptor that a live session passes, and the bind refuses the session's own writes either
    //   way (ko-agent-fs/bpf/doc/architecture.md, "The hooks", `file_receive`).
    val bpfFacts: Option[KoAgentBpf.Facts] = startedBpfChecks.flatMap: awaitChecks =>
      val checks = awaitChecks()
      if !checks.ok then fail(s"error: the BPF backend's probe did not run in the podman machine:\n${checks.err}")
      val facts = KoAgentBpf.parseFacts(checks.text)
      val missing = KoAgentBpf.requirementFailures(facts, os, KoAgentBpf.bundledSourceId(), bundledKoAgentFsSourceId())
      if missing.isEmpty then Some(facts)
      else if workspaceSettings.live then
        val heading = s"error: --workspace=${workspaceSettings.spelled} cannot run on this podman machine:"
        val reasons = missing.map(line => s"  - $line")
        fail(((heading +: reasons) :+ KoAgentBpf.fuseRemedy(workspaceSettings)).mkString("\n"))
      else
        System.err.println(
          ("note: the read-only session runs under podman's `ro` bind alone; the BPF backend needs:" +:
            missing.map(line => s"  - $line")).mkString("\n"),
        )
        None
    // What this run is, for its labels and for the comparison with the live sessions. A read-only session that the
    // probe left without a policy is a FUSE backend session with no socket setting, whatever was asked. A live `bpf`
    // session beside it is therefore refused, as it would be beside any other FUSE backend session.
    val effectiveSettings =
      if workspaceSettings.bpf && bpfFacts.isEmpty then
        workspaceSettings.copy(backend = "fuse", unixSocket = false)
      else workspaceSettings

    // The launch checks the FUSE backend before any volume is assembled, and mounts the FUSE backend once the
    // sandbox container exists (the lifecycle banner above koAgentFsMountScript has the layout).
    // - The FUSE backend enforces every live session that selects `fuse`, on every platform.
    // - Under the bpf backend, the policy's teardown takes the reap's place (KoAgentBpf.teardownScript).
    //
    // The reap is derived from the mode rather than from the mount, so the reap exists before the mount does. The
    // mount script writes this session's marker as its first act (KoAgentFs, koAgentFsMountScript), and a failure after
    // that would otherwise leave the marker to a later reap. Only live sessions have a mount to reap.
    val fuseReap =
      if workspaceSettings.fuseMounted then
        Some(koAgentFsReapScript(koAgentFsReapPodman(podman, os), workspaceId, sandboxContainer))
      else bpfFacts.map(facts => KoAgentBpf.teardownScript(sandboxContainer, facts.manager))

    // This workspace's TLS and trust state, and this run's own copies of the files that podman will mount.
    // - The launch derives the shared state under the workspace lock further down.
    // - A container mounts the per-run copy. A later launch's legitimate rewrite, such as for a rebuilt image or an
    //   edited rule file, therefore cannot take a mounted file from a session that is already running.
    // - A bind mount does not survive its source's inode being replaced, and these files have nothing behind them to
    //   fall through to.
    val tlsDir = tlsStateRoot(os).resolve(workspaceId)
    createPrivateDirectories(tlsDir)
    val runFiles = tlsDir.resolve(tlsRunDir(runSuffix))

    // Everything this run creates, in one place. The shutdown hook and the resident teardown both run exactly this
    // function, so the two cannot drift into removing different sets.
    //
    // The notice opens on a fresh line unless the line is known to be closed.
    // - The terminal echoes a Ctrl-C as `^C` and stops there, a signal leaves the cursor wherever it was, and a child
    //   may end mid-line. The hook cannot see any of these.
    // - The one line that the launcher knows to be closed is the hold's line, which the reader's Enter or the hold
    //   itself ends (confirmStart).
    // - Elsewhere an empty line is the price, after a refusal too.
    var heldLineClosed = false
    val removeWhatThisRunCreated = () =>
      // Podman takes about a second on cleanup, whether a launch was refused, interrupted, or ended normally through
      // the resident path. The notice reports progress, so the pause does not look like a hang.
      System.err.println((if heldLineClosed then "" else "\n") + "removing this run's containers and networks")
      removeRunResources(podman, sandboxContainer, proxyContainer, Seq(sandboxNetwork, egressNetwork))
      // This run's mount-source copies. The reaper deliberately does not remove them, so the reaper's argument list
      // stays fixed. A run that the reaper cleans up leaves its copies to the next launch's liveness sweep, or to a
      // reset.
      try deleteRecursively(runFiles)
      catch case _: Exception => ()
      // Best effort, as on the reaper's path. This run's session marker goes now rather than with the reap that finds
      // the run's container gone, and the mount follows if no other session holds the mount.
      fuseReap.foreach(script => runOk(koAgentFsScriptCommand(podman, os, script)*))

    // The launch arms the cleanup before the first resource that this run owns: the run's networks, then its files
    // under the workspace lock below.
    // - What precedes the cleanup is this workspace's ruleset cache, which outlives every run by design.
    // - From here on, this process is the only one that knows what to remove, and every refusal below ends the JVM
    //   rather than raising (SandboxLifecycle, armRunCleanup).
    val cleanup = armRunCleanup(removeWhatThisRunCreated)

    // The launch reads the FUSE backend's checks, started above, and prepares its mountpoint now. The mount itself
    // happens once the sandbox container exists (mountKoAgentFs has the reason), which is after the proxy and the hold.
    val fuseWorkspace = startedKoAgentFsChecks.map: (sourceId, awaitChecks) =>
      prepareKoAgentFs(podman, os, workspaceId, sourceId, awaitChecks(), startPrompt(sessionStartMode, terminalReader))
    // The backend's reconcile runs at this launcher's start (ko-agent-fs/bpf/doc/architecture.md, "Lifecycle", step
    // 7), under the launch lock, so the reconcile does not take a launch in flight's pins for an orphan's.
    bpfFacts.foreach: facts =>
      val reconciled = withFileLock(KoAgentBpf.launchLockFile(stateRoot(os))):
        run(koAgentFsScriptCommand(podman, os, KoAgentBpf.reconcileScript(facts.manager))*)
      if !reconciled.ok then
        System.err.println(
          s"note: the BPF backend's reconcile did not run; stale sessions stay until the next\n${reconciled.err}",
        )
      reconciled.text.linesIterator.filter(line => line.contains("action=refused") || line.contains("action=removed"))
        .foreach(line => System.err.println(s"  $line"))
      KoAgentBpf.reconcileNote(reconciled.text).foreach(System.err.println)
    // After an edit of file/rule, the launch joins a live mount under other file rules under the mount's rules, which
    // an earlier session of the workspace accepted. The start prompt below is the consent.
    val joinedRules = joinUnderOtherRules(
      fuseWorkspace.flatMap(_.running),
      fileRulesText,
      prompted = startPrompt(sessionStartMode, terminalReader).nonEmpty,
    ).fold(fail(_), identity)
    val (sessionRuleLines, sessionRulesText) = joinedRules match
      case Some(running) => (FileRules.parseRuleFileText(running.rules).fold(fail(_), identity), running.rules)
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
    // The proxy appends the audit log through a bind-mounted host file, so the record outlives the per-run container.
    // - The launch does not use --log-opt path=, because conmon interprets that path inside the podman machine VM.
    // - The mount is a single file. The run's directory would hand the proxy this run's other logs, and the
    //   workspace's log directory would hand the proxy every previous session's record.
    // - The file is owner-only, because refusal lines carry full URLs, and a URL can carry a secret.
    createPrivateDirectories(logDir)

    val hostLogFile = runLogs.resolve("proxy.log")
    val channelLogFile = runLogs.resolve("run-on-host.log")
    val micLogFile = runLogs.resolve("mic.log")
    val backendLogFile = runLogs.resolve("ko-agent-bpf.log")

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

    val mount =
      LaunchMount(fuseWorkspace, bpfFacts, effectiveSettings, joinedRules, sessionRuleLines, sessionRulesText)
    printLaunchLines(parsed, settings, workspace, rules, mount, git, hostLogFile, os)
    val createCommand = sandboxCreateCommand(
      parsed, settings, workspace, images, rules, names, mount, git, proxyIp, sandboxFiles, machineMemory, os,
    )

    // Before the hold, the launch offers the run that provisions each executable whose absence would make the first
    // mill, gradle or mvn command refuse (RunOnHostProvisioning). The reader is the hold's reader, so a launch that
    // holds nothing tells and asks nothing.
    if runOnHost.nonEmpty then
      RunOnHostProvisioning.run(
        workspaceRoot,
        RunOnHostPrereqs.Program.values.filter(program => runOnHost.contains(program.name)).toSet,
        name => Option(System.getenv(name)),
        terminalReader.filter(_ => sessionStartMode == "pause"),
      )

    // The hold comes first, then the create, the reaper, the mount, and the start.
    // - The hold comes before the container exists. A Ctrl-C there is then an ordinary shutdown: the hook removes this
    //   run's proxy and networks, and the launch ends at once. A launcher killed outright at the prompt leaves no
    //   created container behind.
    // - The reaper comes right after the create, so a created-but-never-started sandbox has its remover
    //   (SandboxLifecycle, ReaperScript) from the first instant, where a reaper runs.
    //   - Where no reaper runs, on Windows or after a failed POSIX spawn, the launcher stays resident. A resident
    //     launcher killed outright leaves the created container, and with it the marker and the mount, to a reset, as
    //     it leaves the proxy.
    // - The mount comes after both, because the container names this session to the FUSE backend's reap, which asks
    //   podman for the container by name (KoAgentFs, koAgentFsReapScript).
    //   - Written after the create, the session marker is never on disk without the container.
    //   - A launcher that dies during the mount leaves the marker to the reap that follows the reaper's removal of the
    //     container.
    // - The cost: the notes below print after the release, and the TUI then clears them with the rest. The notes say
    //   that the reaper could not be spawned, or which branch the mount took.
    if !confirmStart(sessionStartMode, if command.isEmpty then Vector("bash") else command, terminalReader) then
      heldLineClosed = true
      sys.exit(0)

    startSandbox(
      parsed, settings, workspace, rules, names, mount, git, createCommand, fuseReap, runFiles, channelLogFile,
      micLogFile, backendLogFile, cleanup, os,
    )

  /** The options that another launch line states when in force. That line names the options file when the option came
    * from the file. The lines are the grants' orange lines, the shared agent-state volume's line, the workspace and
    * egress lines, and the forwarded names and credentials. */
  private def ownLines(settings: LaunchSettings, parsed: ParsedCommandLine): Set[String] =
    Set(
      Some("--workspace"),
      Some("--egress"),
      Some(ModelProviderOption),
      Option.when(parsed.env.nonEmpty)("--env"),
      Option.when(settings.credentials.nonEmpty)("--egress-cred"),
      Option.when(settings.awsCredential.nonEmpty)(AwsCredential.OptionName),
      Option.when(settings.clipboard != "off")("--clipboard"),
      Option.when(settings.mic.nonEmpty)(AudioOption),
      Option.when(settings.nesting != "none")("--nesting"),
      Option.when(settings.runOnHost.nonEmpty)("--run-on-host"),
      Option.when(parsed.persistentVolume.nonEmpty)(PersistentVolumeOption),
      Option.when(parsed.claudePlugins.nonEmpty)(ClaudePlugins.OptionName),
    ).flatten

  /** The `podman create` arguments of a nesting mode: the profile for `none`, and the loosenings for `same-uid`.
    * NestingVariable says what each mode allows, and why the variable is set for `none` too. */
  def nestingArguments(nesting: String, stateRoot: Path): Vector[String] =
    val variable = s"--env=$NestingVariable=$nesting"
    nesting match
      case "none"     => Vector(SeccompProfile.createArgument(stateRoot), variable)
      case "same-uid" => NestingLoosenings :+ variable
      case _          => Vector(variable)

  private def launchSettings(options: OptionsInForce, os: Os): LaunchSettings =
    val parsed = options.parsed
    // The credentials resolve first, before any check that starts a process (the clipboard's `ps` below). From here
    // the values are in this process's memory, and no process that it starts inherits them
    // (EgressCredentials.withhold).
    val credentials =
      EgressCredentials.resolve(parsed.credentialBindings, name => Option(System.getenv(name))).fold(fail(_), identity)
    EgressCredentials.withhold(credentials.map(_.binding.name), os)

    val (image, imageOverridden) = sandboxImageChoice(parsed.image)
    val (proxyImage, proxyImageOverridden) = proxyImageChoice(parsed.proxyImage)

    val nesting = parsed.nestingMode
    // This check runs before anything is created, because a launch under podman's default profile is the weaker
    // boundary.
    if nesting == "none" then SeccompProfile.missingReason(stateRoot(os)).foreach(fail(_))
    val sessionStartMode = parsed.sessionStartMode
    val clipboard = parsed.clipboardMode
    val pathValue = env("PATH").getOrElse("")
    val mic = Option.when(parsed.mic)(MicRelay.recorders(os, pathValue).fold(fail(_), identity))
    // The reaper ends the microphone relay's tree with the same proven ps as the clipboard relay's tree.
    val clipboardHost =
      ClipboardRelay.hostBackend(clipboard, os, pathValue).fold(fail(_), identity) match
        case backend if mic.nonEmpty && os != Os.Windows && backend.ps.isEmpty =>
          backend.copy(ps = ClipboardRelay.probedPs(MicOption, os, pathValue).fold(fail(_), identity))
        case backend => backend
    // The launch reads the raw environment, not HostCommands.env. HostCommands.env reads an empty variable as unset,
    // which is right for the launcher's own settings and wrong here, where set-but-empty is a value to forward.
    val forwardedEnv = forwardedEnvironment(parsed.env, name => Option(System.getenv(name))).fold(fail(_), identity)
    // The values stay in this process's memory and reach podman and the runner as a host value does: in an
    // environment, never in an argument (forwardedEnvironment, RunOnHostChannel.spawnRunner).
    val awsCredential = parsed.awsCredential.map: request =>
      AwsCredential.resolve(
        request, name => Option(System.getenv(name)), name => findOnPath(name, os),
        command => run(command*), Instant.now(),
        forwardRegion = !parsed.env.exists(_.name == AwsCredential.RegionName),
      ).fold(fail(_), identity)

    KoAgentBpf.placementRefusal(parsed.workspaceSettings, os, parsed.nestingMode).foreach(fail(_))

    // --run-on-host is macOS only (run-on-host-internals.md, "Why only macOS"). Elsewhere there is no Seatbelt backend,
    // and a container build already runs at host speed on host memory.
    val runOnHost = parsed.runOnHost.getOrElse(Vector.empty)
    if runOnHost.nonEmpty && os != Os.Mac then
      fail("error: --run-on-host is available on macOS only; on this host, run those programs in the container")

    val workspaceRoot = resolveWorkspaceRoot(os)
    // This check runs before any read of the boundary configuration. boundaryDirRefusal has the refused forms, and
    // SECURITY.md has the reason.
    val boundaryDir = boundaryDirOf(workspaceRoot)
    boundaryDirRefusal(boundaryDir).foreach(fail(_))

    // The launch reads the selected programs' rule files before anything is created. A binding is checked against the
    // files below, and the launch's widening report prints them (LaunchMessages.runOnHostWideningLines). The runner
    // reads the files again at a program's first command.
    val programRules = RunOnHostPrereqs.Program.values.toVector.filter(program => runOnHost.contains(program.name))
      .map: program =>
        RunOnHostPrereqs.readProgramRules(workspaceRoot, program).fold(fail(_), program -> _)
    LaunchSettings(
      options, credentials, image, imageOverridden, proxyImage, proxyImageOverridden, nesting, sessionStartMode,
      clipboard, clipboardHost, mic,
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
    // (SECURITY.md, "What the persistent volume holds"). The user therefore signs in separately for each workspace.
    // - --persistent-volume opts into sharing that state across workspaces through the named volume. The launch says
    //   so on a line of its own, whichever source gave the option.
    // - A linked worktree may instead share its main worktree's volume. The reader agrees to that right here, under
    //   the two lines that name both directories, and before podman announces itself, because the question is about
    //   those two lines and nothing that follows.
    // - A launch that holds nothing keeps this worktree's own volume and says so. The line names the option through
    //   which a launch without the prompt shares. After a launch that agreed, a scripted launch would otherwise seem to
    //   have lost the main worktree's logins.
    val sharedVolume = parsed.persistentVolume.map: shared =>
      sharedVolumeNameRefusal(shared).foreach(reason => fail(s"error: $reason"))
      shared
    // The launch finds the main worktree under the option too, where nothing is asked, because the read-only git mount
    // reads the main worktree.
    val mainWorktree = SandboxWorkspace.mainWorktreeOf(workspaceRoot, homeProtection, os)
    // The container has the workspace at the same path, so nothing on either side translates
    // (SandboxWorkspace.mountPathOf). Once the image is known, below, the launch asks what the image has at that path,
    // or reads the cache of an earlier answer, still before any per-workspace resource exists.
    val mountPath = mountPathOf(os, workspaceRoot).fold(fail(_), identity)
    System.err.println(
      pathLine("workspace root", workspaceRoot, os, tint = chosen(_)) +
        workspaceModeClause(
          parsed.workspaceSettings.spelled, settings.options.from("--workspace", os), mountPath, os,
          sourceOf = settings.options.workspacePartSource,
        ),
    )
    mainWorktree.foreach(main => System.err.println(pathLine("main git worktree", main, os)))
    sharedVolume.foreach: shared =>
      System.err.println(sharedVolumeLine(shared, settings.options.from(PersistentVolumeOption, os)))
    // The launch says the answer back, as the workspace root and egress lines say their modes, because an answer is a
    // choice, and either answer continues the launch.
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

    // The launch detects SELinux this early, because the read-only mode's refusal below must come before any resource
    // exists. Every fileBind reads the value again further down. The check asks for Enforcing specifically, because
    // permissive and disabled hosts read every mount unrelabeled, and relabeling there would be a host-metadata write
    // with no benefit.
    val selinuxEnforcing = os == Os.Linux &&
      findOnPath("getenforce", os)
        .exists(path => run(path.toString).text.trim == "Enforcing")

    // A plain bind mount on an SELinux-enforcing host is readable to the container only after :Z relabels the
    // workspace. The relabel is a recursive host-metadata write, which is exactly the authority that the read-only mode
    // withholds. The launch refuses rather than relabels, unless the tree already has a shared container-accessible
    // context, where a plain read-only bind needs no host write.
    if workspaceMode == "read-only" && selinuxEnforcing && !selinuxContainerReadable(workspaceRoot) then
      fail(
        s"""error: --workspace=read-only cannot mount $workspaceRoot on this SELinux-enforcing host
           |Reading a plain bind mount here requires relabeling the workspace (:Z), a recursive
           |host-metadata write that --workspace=read-only never makes. Use --workspace=live,fuse, whose FUSE
           |mount needs no relabel, or relabel the workspace yourself
           |(chcon -R -t container_file_t -l s0 <dir>; the level clears any categories a
           |previous :Z assigned to one container) and relaunch.""".stripMargin,
      )

    // -----------------------------------------------------------------------
    // Per-workspace identity
    // -----------------------------------------------------------------------
    //
    // The identity names this workspace root and suffixes everything that podman holds for the workspace. The
    // directory name alone would collide, and two workspace roots called `app` must not share credentials or a
    // ruleset, so the hash covers the whole path. Moving a workspace yields new resources and new sign-ins.
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
    // The launch reads the plugin directories against the host here, before anything is created, like the rule files.
    // The directories are bound into the sandbox unrelabeled, so the launch asks an enforcing host whether the
    // container can read them, as it asks about the workspace.
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
   * The directories outside the workspace that `--run-on-host` commands write (SeatbeltProfile.render's grants):
   * - the caches under the launcher's cache root, where each cache lies once a symlink is followed
   *   (RunOnHostPrereqs.writtenCacheDirectories);
   * - every session's `tmp/` under the host commands' root.
   * The method names the cache root and the host commands' root whole, because a reset removes the cache tree, and
   * the host commands' root holds every session's directory. The method names them whether or not the launch runs
   * host commands, because a plugin there is also under a reset's removal. The Left, where the caches cannot be found,
   * refuses every plugin, because no plugin can be shown to lie outside the caches.
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
    // The launch pulls no image implicitly, because image rollout is separate from running an agent.
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
    // Every later run of the image names this Id rather than `image`. A build or a retag can move the name after this
    // inspect, and the version lock checks this Id, and the caches below are stamped with it. The launch uses the
    // proxy image's Id the same way.
    val imageId = imageInspect.linesIterator.nextOption().getOrElse("")
    val imageLabel = imageInspect.linesIterator.drop(1).nextOption().getOrElse("")
    val imageEnv = imageInspect.linesIterator.drop(2).mkString("\n")

    // The launch refuses a mount path at which the image has an entry, or which the sandbox user cannot reach, before
    // the FUSE backend's preparation, the networks and the TLS state, so a refusal writes nothing (mountPathRefusal has
    // the cases).
    //   - The probe is a run of the image, 0.2 s on a macOS podman machine (2026-09-18). The probe's `absent` is
    //     therefore cached per image Id, and written once the workspace's cache directory exists below.
    //   - On a cache miss, the probe runs beside the sandbox image's version lock and the proxy image's inspect. The
    //     probe's refusals come between theirs.
    val mountPathAnswerFile = rulesetStateRoot(os).resolve(workspaceId).resolve("mount-path.answer")
    val cachedMountPath = cachedMountPathAnswer(mountPathAnswerFile, imageId, mountPath)
    val awaitMountPathProbe = cachedMountPath.fold(
      inBackground("mount path probe")(probeMountPath(podman, imageId, mountPath)),
    )(answer => () => answer)

    // A jar upgrade must never run silently against images that an earlier jar built. The launch checks before any
    // resource exists, and bundleMismatch has the refuse-versus-warn reasoning.
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
    // The launch reads the workspace's egress/ here on the host, and hands the rules to the proxy at startup.
    // readRuleFiles has the forms, and SECURITY.md has the reason. The workspace mode itself keeps a session from
    // writing the next session's rules: the read-only mode's `ro` bind of the raw tree, or the live mode's backend,
    // which refuses writes under `.ko-agent-sandbox`.
    val ruleFiles = readRuleFiles(boundaryDir.resolve("egress")).fold(fail(_), identity)

    // The workspace files that a host program executes on an event (FileRules). The launch reads them as it reads the
    // egress rules, and resolves them to what the workspace policy and the Seatbelt profile enforce. The workspace
    // policy's guard adds to the rules at the FUSE backend's mount, or in the BPF backend's launch script. Under
    // --workspace=read-only with --run-on-host, where no daemon runs, `ko-agent-fs --resolve` adds to them.
    val workspaceFileRules = FileRules.readRuleFile(boundaryDir.resolve("file")).fold(fail(_), identity)
    val fileRuleLines = FileRules.resolve(workspaceFileRules.fold(Vector.empty[FileRules.Line])(_(1)))
    val fileRulesInForce = workspaceMode == "live" || runOnHost.nonEmpty
    val fileRulesText = FileRules.ruleFileText(fileRuleLines, FileRules.hostView(os, mountPath))
    val readOnlyFileRules = Option.when(workspaceMode == "read-only" && runOnHost.nonEmpty)(
      resolveFileRules(podman, os, workspaceId, mountPath, fileRulesText),
    )

    // The providers that the launch selects (EgressRules.selectedProvider), and the one warning that the launcher
    // prints itself.
    val provider = selectedProvider(parsed.modelProviders, command.headOption, egressProfile).fold(fail(_), identity)
    if provider.isEmpty then noProviderLine(command.headOption.orElse(Some("bash")), egressProfile).foreach(warn)

    // The launch validates the rules before anything is created. Invalid rules would otherwise appear as "could not
    // determine the egress proxy's address" after the --rm proxy died, with the reason buried in the proxy's log.
    // - The launch caches the result like the CA bundle below, under the stamp below, and writes only a success.
    // - Enforcement never reads this cache. The proxy re-resolves the same variables at startup, so corruption can at
    //   worst misprint the banner, never widen what is enforced.
    val rulesetCacheDir = rulesetStateRoot(os).resolve(workspaceId)
    createPrivateDirectories(rulesetCacheDir)
    recordWorkspaceRoot(workspacesStateRoot(os), workspaceId, workspaceRoot)
    if cachedMountPath.isEmpty then cacheMountPathAnswer(mountPathAnswerFile, imageId, mountPath, mountPathProbe)

    val resolvedHostsFile = rulesetCacheDir.resolve("resolved.hosts")
    val resolvedWarningsFile = rulesetCacheDir.resolve("resolved.warnings")
    // The stamp covers everything that the dry run reads:
    // - the image;
    // - the selected options: the profile, and the provider variable's value as the proxy receives it, so no selection
    //   and a value that the proxy would refuse never share a stamp;
    // - the files, hashed into the stamp's one line because they are multi-part.
    // The stamp is the first line of each cached file rather than a file of its own, and a hit needs both files to
    // hold the stamp. Concurrent launches of one workspace under different session options write here without a lock,
    // and a stamp beside the content could end up describing the other launch's content (FileHelper.stampedEntry).
    val rulesetStamp =
      s"$proxyImageId $egressProfile ${provider.getOrElse("")} " +
        sha256Hex(ruleFiles.map((name, text) => s"$name: $text").mkString("\n"))

    // The launch caches the dry run's warnings beside the hosts, so every launch reports an idle denial or an
    // unreachable provider, not only the launch that missed the cache.
    // - stampedEntry gives back exactly what was cached, with the trailing newline removed, so a hit and a miss yield
    //   one string.
    // - The hosts text is hashed into the agent instructions' stamp. Two spellings of the same ruleset would make every
    //   launch after a re-resolve rewrite the shared agents.md for nothing (FileHelper.writeWithMode).
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

    // The leaf's names, from the dry run (inspectedHostsOf). A ruleset change reissues the leaf (prepareRunFiles). An
    // empty list means no leaf and no inspection material.
    val inspectedHosts = inspectedHostsOf(rulesetText).fold(fail(_), identity)
    // The launch builds the banner now, so a dry run that the banner cannot state fails the launch before its proxy
    // starts.
    val egressLine = egressBanner(
      rulesetText, settings.options.from("--egress", os),
      settings.options.providersFrom(provider.toVector.flatMap(_.split(",")), os),
      providersFromFile = settings.options.fileValues(ModelProviderOption).toSet,
      profileFrom = settings.options.egressProfileSource,
    ).fold(fail(_), identity)

    // Each binding must reach a proxy that inspects the binding's host: the session's proxy, or a selected program's
    // proxy, which inspects every host of the program's rules (RunOnHostSandbox.credentialHosts).
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
    // A linked worktree's main Git directory, bound read-only where the container can follow the pointer there
    // (SandboxWorkspace.linkedGitdirBind) and can read the directory once bound:
    // - the image must have nothing at the target, which the workspace root's probe, asked again of this path, checks;
    // - on an SELinux-enforcing host, the directory must carry a container-readable label, which the launcher never
    //   gives a workspace (SECURITY.md, "the workspace's SELinux labels");
    // - the repository must not set the extension that the image's git refuses
    //   (SandboxWorkspace.setsRelativeWorktrees).
    // The launch prints each refusal with the git warning, since the warning alone would read as a linked worktree that
    // this launcher does not recognize.
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

  /** Prepares this workspace's TLS state and agent instructions, this run's copies of what the containers mount, and
    * the proxy container, all under the workspace lock. The answer is the sandbox container's file arguments. */
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
    // The CA that the sandbox trusts for TLS inspection is created here. The CA key stays on the host, and only the
    // leaf and the leaf's own key reach the proxy (SECURITY.md, "Who holds the CA key", has the reasoning).
    //
    // The steps run under the workspace lock, because every step is check-then-act over shared files. Two first
    // launches that both find no usable CA would otherwise interleave their writes, and leave one launch's ca.key
    // beside the other launch's ca.crt.
    // - The lock spans the checks through the per-run copies and the proxy's create, so what this run mounts is one
    //   launch's consistent set.
    // - The lock cannot span further, because podman resolves bind sources at container *start*, past the interactive
    //   hold. The per-run copies close that remainder.
    // - The lock cannot cover a launch that *died* between two writes. The coherence checks below cover that case:
    //   they test that key and certificate match each other, not merely that both look fine.
    val caCertFile = tlsDir.resolve("ca.crt")
    val caKeyFile = tlsDir.resolve("ca.key")
    val leafCertFile = tlsDir.resolve("leaf.crt")
    val leafKeyFile = tlsDir.resolve("leaf.key")
    val bundleFile = tlsDir.resolve("sandbox-ca-bundle.crt")
    val bundleStampFile = tlsDir.resolve("bundle.stamp")

    val reissueDeadline = Instant.now().plusSeconds(ReissueMarginSeconds)

    // The session-specific instructions point to the ruleset environment variable rather than embed the host list in
    // every prompt. The launch reads the image's file, appends the session's instructions, and mounts the result over
    // the image's file. All installed agents' instruction files link to this path, so one mount reaches all of them.
    // LaunchMessages.agentDocumentStamp keys the cached assembly.
    val agentDocFile = rulesetCacheDir.resolve("agents.md")
    val agentDocStampFile = rulesetCacheDir.resolve("agents.stamp")
    // The profile and provider need no stamp input of their own, because the resolved text's first line names both.
    val agentDocStamp = agentDocumentStamp(
      imageId, parsed.workspaceSettings.spelled, rulesetText, runOnHost, gitInstruction, parsed.credentialBindings,
    )

    withFileLock(tlsDir.resolve(".lock")):
      // Which of this workspace's runs a container still names, for every pruning decision that this launch makes.
      // - The launch lists the containers under the lock and in every state. A run's directories, of logs and of mount
      //   copies, are created under this lock, and the run's proxy is created before the lock is released. A run whose
      //   files another launch can see therefore has a container in that launch's listing, or died before creating
      //   one.
      // - A launcher that died between its create and start left a created container, which keeps the files until a
      //   reset removes it.
      // - A failed listing prunes nothing. Unknown liveness must not read as "no live runs" and delete a running
      //   session's files out from under it.
      // - A run is live while either of its containers exists. The proxy writes the run's logs, and so do the runner
      //   and the relay, which serve the sandbox container. The mount copies serve both containers. A run whose proxy
      //   crashed while its sandbox lives on must keep its files.
      val containers = listedNames(podman, "ps", "--all", "--format", "{{.Names}}")
      val liveRuns = liveRunsOf(workspaceId, containers.toOption)
      containers.left.foreach: err =>
        System.err.println(
          "note: could not list this workspace's containers; keeping every retained log and run file\n" + err,
        )

      // A run's log directory names its run in the same suffix as its containers.
      liveRuns.foreach: live =>
        val entries = directoryEntries(logDir).map(_.getFileName.toString)
        runLogDirsToPrune(entries, RetainedRuns, live).foreach(name => deleteRecursively(logDir.resolve(name)))

      // This launch removes the run copies whose runs are gone, rather than letting them accumulate. The resets remove
      // the rest.
      liveRuns.foreach: live =>
        val entries = directoryEntries(tlsDir).map(_.getFileName.toString)
        tlsRunDirsToPrune(entries, live).foreach(name => deleteRecursively(tlsDir.resolve(name)))

      // This directory comes after the pruning, which keeps one fewer than RetainedRuns, so this run's directory brings
      // the count to RetainedRuns.
      createPrivateDirectories(runLogs)
      writePrivate(hostLogFile, "")

      // This run's directory comes first, because the copies below are written into it.
      createPrivateDirectories(runFiles)

      // The CA check tests coherence, not just expiry (CertificateHelper.keyMatchesCertificate).
      val caServes = (readIfPresent(caCertFile), readIfPresent(caKeyFile)) match
        case (Some(cert), Some(key)) =>
          certificateExpiresAfter(Some(cert), reissueDeadline) && keyMatchesCertificate(cert, key)
        case _ => false
      if !caServes then
        try
          val ca = InspectionCa.create(workspaceSlug)
          // The launch retires the leaf that this CA no longer signs by emptying the leaf, not by deleting it.
          // - The names stay stable for the copies below and for anything still reading the files
          //   (FileHelper.writeWithMode).
          // - An empty leaf fails every expiry test below, so this same launch reissues the leaf.
          // - The launch empties the leaf before writing the CA. A launch that dies here leaves a leaf that the next
          //   launch reissues, rather than a leaf silently signed by the old CA.
          Seq(leafCertFile, leafKeyFile).foreach(writePrivate(_, ""))
          writePrivate(caKeyFile, ca.privateKeyPem)
          writePrivate(caCertFile, ca.certificatePem)
        catch
          case ex: Exception =>
            fail(s"error: could not create this workspace's inspection CA in $tlsDir\n$ex")

      // The leaf is reissued when the CA is reissued (the leaf is emptied just above), and whenever the leaf stops
      // serving the inspected names (CertificateHelper.leafServes). A ruleset that inspects nothing gets no leaf.
      if inspectedHosts.nonEmpty
        && !leafServes(
          readIfPresent(leafCertFile), readIfPresent(leafKeyFile), inspectedHosts.toSet, Files.readString(caCertFile),
          reissueDeadline,
        )
      then
        try
          val leaf = X509Helper.issueLeaf(
            inspectedHosts,
            parseCertificate(Files.readString(caCertFile)),
            parsePrivateKey(Files.readString(caKeyFile), caKeyFile.toString),
          )
          writePrivate(leafKeyFile, leaf.privateKeyPem)
          writePrivate(leafCertFile, leaf.certificatePem)
        catch
          case ex: Exception =>
            fail(s"error: could not issue this workspace's inspection certificate\n$ex")

      // The sandbox's trust is the image's own CA bundle, plus the CA that this run trusts. The workstation's bundle is
      // a different set entirely. The launch re-reads the image's bundle when the image or the CA changes, and the
      // stamp records both (imageId comes from the sandbox image's inspect).
      val caFingerprint = certificateFingerprint(parseCertificate(Files.readString(caCertFile)))
      val bundleStamp = s"$imageId $caFingerprint"

      // The image's files from which both caches below are made. The launch reads both files in one run of the image
      // when both caches are stale, as after a rebuild.
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

      // The JVM reads a `cacerts` keystore and no proxy variable, so the bundle above and the HTTPS_PROXY family cannot
      // reach the JVM. JdkTrust.scala handles the JVM's trust and proxy, and an empty answer means that the image ships
      // no JDK.
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
              backend = parsed.workspaceSettings.backend,
              unixSocket = parsed.workspaceSettings.unixSocket,
              windowsShare = os == Os.Windows,
            ),
        )
        writeReadable(agentDocStampFile, agentDocStamp + "\n")

      // This run's copies, made while the lock still holds, so no concurrent launch's rewrite can happen between an
      // expiry check above and a copy below.
      // - A file that this run wrote into its own directory is mounted where it is.
      // - Modes travel with the copy: the leaf key stays owner-only, and the run directory itself allows only this
      //   user.
      def carried(source: Path): Path =
        if source.startsWith(runFiles) then source
        else
          val target = runFiles.resolve(source.getFileName)
          Files.copy(
            source, target,
            StandardCopyOption.COPY_ATTRIBUTES, StandardCopyOption.REPLACE_EXISTING,
          )
          target

      // The proxy gets the leaf and its key only.
      // - The CA key is stored beside them and is never copied or mounted.
      // - A ruleset that inspects nothing gets no material, because the proxy refuses material that it has nothing to
      //   inspect with.
      // - --userns makes an owner-only key readable as uid 65532. Without --userns, the key would have to be
      //   world-readable on the host. The userns flag itself stays on the create call, because the proxy writes its
      //   owner-only log file through the same mapping.
      val proxyTls = proxyTlsArgs(
        if inspectedHosts.isEmpty then ProxyTlsMaterial.Uninspected
        else ProxyTlsMaterial.Leaf(carried(leafCertFile), carried(leafKeyFile)),
        selinuxEnforcing,
      )

      // The host plugins' marketplace manifest and managed drop-in are this run's own files (ClaudePlugins.scala has
      // the layout). The plugin directories are bound where they are.
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
      // A session keeps the ruleset that it started with, and the next launch re-reads the rules.
      // - The proxy is --rm, so a proxy whose process exits removes itself.
      // - The audit-log bind is the proxy's only writable path, because the native executable needs no scratch
      //   filesystem.
      // - The launch creates the proxy here, still under the lock. No sweep that lists under the lock (the top of this
      //   block) then sees this run's files above without a container that names the run. A launch that dies before
      //   this create leaves files that no container names, and that sweep exists for those files.
      // - The launch starts the proxy once the lock is released.
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
          // memoryArguments says why the equal limits disable podman's default swap allowance.
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
   * The warning for a host git older than 2.34, whose `git bisect` is a shell script that runs `eval` over
   * `.git/BISECT_NAMES`. The workspace policy lets a session write that file, since git 2.34 and later read the file
   * as data (`ko-agent-fs/policy/src/policy.rs`, `classify_within_gitdir`).
   * - The warning applies to every live workspace. A session writes the gitdir of any repository below the root,
   *   whether or not the root's own git works, and whether or not the root's main gitdir is mounted read-only.
   * - `versionLine` is read only for a live workspace.
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
    // Every launch prints the egress profile with its relevant state, as the workspace root line prints the workspace
    // mode.
    // - First come the dry run's counts, which are the proxy's own answers to exactly what is enforced.
    // - Then come the lines of the egress rule file, each once (HostCommands.ruleFileReport), so rules that arrived
    //   with the repository never take effect unseen.
    // - Each line tints what the user chose. A line that states a boundary weaker than the default tints its grant
    //   instead (HostCommands.weakened).
    val options = settings.options
    // The git warning qualifies the workspace root line's mode: the mount is sound, and git either is not there, or
    // reads the main worktree's Git directory and writes nothing. The warning applies to every mode, since what git
    // needs is absent from the container under each mode.
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
    // The transport, when this launch passed HTTPS_PROXY. The line is the proxy's own line, from the proxy's own parse,
    // so what is on the screen is what is used, never a launcher-side reading of the variable.
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
    // The line prints names only, because a forwarded value may be a secret. This line is the one place that states
    // the forward aloud, since the variable is otherwise indistinguishable from the image's own variables.
    if parsed.env.nonEmpty then
      val fromFile = options.fileValues("--env").toSet
      val source = options.from("--env", os)
      System.err.println(forwardedEnvironmentLine(parsed.env.map(_.name), fromFile, source))
    awsCredential.foreach: resolved =>
      val source = options.from(AwsCredential.OptionName, os)
      System.err.println(AwsCredential.bannerLine(resolved, Instant.now(), fromFile = source.nonEmpty) + source)
    // The line is loud as a loosening. The plugins are code that runs in the session without a tool call, chosen on
    // the host, which the image's allowManagedHooksOnly otherwise keeps out (SECURITY.md).
    // - A plugin counts as the file's when the file names the plugin's directory.
    // - The command line supplies a directory that both sources spell alike (CommandLine.merge).
    // - A directory spelled otherwise is a second plugin of that name, which ClaudePlugins.resolve refuses.
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

  /** The sandbox container's `podman create`: the options, then the image and the command. The split lets the start
    * add the options that are known only once the backend's steps ran (KoAgentBpf). */
  final case class CreateCommand(options: Vector[String], imageAndCommand: Vector[String]):
    def withOptions(more: Vector[String]): Vector[String] = options ++ more ++ imageAndCommand

  /** The sandbox container's `podman create`. The method prints each loosening that the command carries. */
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
  ): CreateCommand =
    import parsed.{command, workspaceMode}
    import settings.{
      awsCredential, clipboard, credentials, forwardedEnv, mic, nesting, programRules, workspaceRoot, runOnHost,
      sessionStartMode,
    }
    import workspace.{mountPath, persistentVolume}
    import images.imageId
    import rules.{fileRulesInForce, rulesetText}
    import names.{sandboxContainer, sandboxNetwork}
    import mount.{bpf, fuseWorkspace, sessionRuleLines}
    import git.mountedGitdir
    // -----------------------------------------------------------------------
    // How the sandbox reaches it
    // -----------------------------------------------------------------------
    //
    // --dns=none: proxied programs CONNECT by name and never resolve. The effective no-external-DNS property comes from
    // the internal network.
    // - --dns=none is defence in depth, not a fix for a known hole. SECURITY.md has the measurement. Do not remove the
    //   flag in the belief that it closes a hole.
    // - --add-host supplies the one name that must work. The address is read back from podman, so no subnet is
    //   reserved.
    // - proxyVariables has the variables.
    val egressProxyUrl = s"http://$EgressProxyHost:$EgressProxyPort"

    val egressArgs = Vector(
      s"--network=$sandboxNetwork",
      "--dns=none",
      s"--add-host=$EgressProxyHost:$proxyIp",
    ) ++ proxyVariables(egressProxyUrl).map((name, value) => s"--env=$name=$value") ++ Vector(

      // Keep the proxy's resolved rules available on demand.
      // - Metadata about the workspace's rule file stays with the terminal. The agent needs the grants actually in
      //   force (rulesetLinesOf).
      // - Revealing the rules grants no access. An agent could discover the rules by probing, slowly and noisily, and
      //   mistake refusals for a broken environment in the meantime.
      s"--env=KO_AGENT_SANDBOX_EGRESS_RULESET=${rulesetLinesOf(rulesetText)}",

      // The entrypoint holds its machine-health warning on screen under the same setting as confirmStart, for the same
      // reason: the TUI clears the warning otherwise.
      s"--env=$SessionStartVariable=$sessionStartMode",
    ) ++ sandboxFiles

    // The rule lines that the session's writes are held to, for the agent to consult on a refusal. What the workspace
    // policy's guard adds comes later, at the FUSE backend's mount or in the BPF backend's launch script, and is not
    // among these lines.
    val fileRuleArgs = Option.when(fileRulesInForce)(
      s"--env=KO_AGENT_SANDBOX_FILE_RULES=${sessionRuleLines.map(_.text).mkString("\n")}",
    ).toVector

    // The launch prints the nesting line in every session to which a nesting loosening applies, because the weaker
    // boundary must never be the silent one.
    if nesting != "none" then System.err.println(nestingLine(nesting, settings.options.from("--nesting", os)))
    val nestedArgs = nestingArguments(nesting, stateRoot(os))

    // The clipboard line is loud for the same reason.
    // - The launch sets WAYLAND_DISPLAY, because Claude Code and Copilot copy through wl-copy only when they see a
    //   display. Otherwise they copy through OSC 52, which Terminal.app ignores.
    // - The value names the shim, so nothing mistakes the value for a compositor.
    val clipboardArgs = clipboard match
      case "off" => Vector.empty
      case mode =>
        System.err.println(clipboardLine(mode, settings.options.from("--clipboard", os)))
        Vector(s"--env=$ClipboardVariable=$mode") ++
          (if mode == "bidirectional" then Vector("--env=WAYLAND_DISPLAY=ko-sandbox-clipboard") else Vector.empty)

    // The microphone line is loud for the same reason. The entrypoint starts the daemon that these variables name.
    val micArgs =
      if mic.isEmpty then Vector.empty
      else
        System.err.println(micLine(settings.options.from(AudioOption, os)))
        MicRelay.sandboxEnvironment().map((name, value) => s"--env=$name=$value")

    // The run-on-host lines are loud for the same reason: host-native execution is authority that a container session
    // alone does not have. SECURITY.md, "Run on host", bounds that authority.
    val runOnHostArgs =
      if runOnHost.isEmpty then Vector.empty
      else
        runOnHostLines(runOnHost, workspaceMode, settings.options.from("--run-on-host", os)).foreach(System.err.println)
        runOnHostWideningLines(programRules.map((program, hosts) => program.name -> hosts)).foreach(System.err.println)
        Vector(s"--env=${RunOnHostChannel.RunOnHostVariable}=${runOnHost.mkString(",")}")

    // -----------------------------------------------------------------------
    // Workspace bind mount
    // -----------------------------------------------------------------------
    //
    // Under the bpf backend, a live session binds the raw tree writable. The policy attached to the container's cgroup
    // holds the protections that the FUSE backend holds elsewhere (KoAgentBpf). No launch binds the tree so without the
    // policy attached and verified (startSandbox's order).
    val workspaceVolume =
      if bpf.isDefined && workspaceMode == "live" then s"$workspaceRoot:$mountPath:rw"
      else workspaceBind(fuseWorkspace.map(_.mountpoint), workspaceRoot, mountPath)

    // -----------------------------------------------------------------------
    // Memory limit
    // -----------------------------------------------------------------------
    //
    // The Coursier OOM in container/debian-coursier/Containerfile demonstrates why memoryLimit
    // reserves memory for Podman's service, which every session needs. For diagnosis, see
    // "The whole machine degrades" in ko-agent-fs/fuse/doc/troubleshooting.md.
    val explicitMemory = parsed.memory.map(_.trim).filter(_.nonEmpty)
    val availableMemory = hostMemoryAvailable(os, readIfPresent(Paths.get("/proc/meminfo")).getOrElse(""))
    if machineMemory.isEmpty && explicitMemory.isEmpty then
      warn("podman info reports no machine memory; the sandbox runs without a memory limit")
    val memoryArgs = memoryArguments(explicitMemory, machineMemory, availableMemory)

    // -----------------------------------------------------------------------
    // The sandbox container: create, arm the reaper, then attach
    // -----------------------------------------------------------------------
    //
    // The launch runs create and then start --attach rather than one `podman run`, so the reaper's `podman wait` has a
    // container to bind to before anything watches the container. A launcher killed between the two leaves a
    // never-started stray. The reaper removes the stray after a bounded wait, and the resets sweep the rest.
    val options = Vector(
      podman, "create",

      // What the reaper waits on. The container is --rm, so a session normally leaves nothing behind with this name.
      s"--name=$sandboxContainer",
      "--rm",
      "-it",

      "--pull=never",
      "--init",

      // Map the invoking rootless podman user to our fixed non-root user, so files created in the workspace remain
      // owned by the host user.
      s"--userns=keep-id:uid=$ContainerUid,gid=$ContainerGid",
      s"--user=$ContainerUid:$ContainerGid",

      "--cap-drop=ALL",
      "--security-opt=no-new-privileges",

      // /tmp and /var/tmp stay writable through podman's --read-only-tmpfs default, which is the writability that
      // AGENTS-SANDBOX.md promises the agents.
      "--read-only",

      // The limit defends against accidental or hostile fork bombs. Raise the limit if a particular parallel build
      // genuinely needs more.
      "--pids-limit=2048",

      // Do not inherit the host's proxy variables, because egressArgs passes the sandbox's own explicitly.
      "--http-proxy=false",
    ) ++ nestedArgs ++ clipboardArgs ++ micArgs ++ runOnHostArgs ++ egressArgs ++ fileRuleArgs ++ Vector(

      // The host's zone, because the JVM resolves the zone on every platform that the launcher runs on. The image
      // ships tzdata, and nothing else sets a zone. Without this variable, a commit made in the sandbox carries +0000,
      // and the agent's "today" turns over at the wrong hour.
      s"--env=TZ=${posixTz(ZoneId.systemDefault())}",
    ) ++ forwardedEnv ++ awsCredential.toVector.flatMap(_.names.map(name => s"--env=$name"))
      ++ placeholderArgs(credentials) ++ Vector(

      // The deliberate host exposure. What the agent writes here is untrusted input to host programs (SECURITY.md, "The
      // workspace").
      "--volume", workspaceVolume,
    ) ++ mountedGitdir.toVector.flatMap(bind => Vector("--volume", s"${bind.source}:${bind.target}:ro")) ++ Vector(

      // The home volume is anonymous and removed on exit, so caches work without becoming cross-session attack state.
      "--mount", s"type=volume,dst=$ContainerHome",

      // This volume persists auth and config: ~/.claude, ~/.codex, ~/.gemini, ~/.kiro, ~/.copilot,
      // ~/.local/share/kiro-cli and opencode's XDG directories are symlinks into it. The volume is podman-owned
      // storage, not a bind mount into the host HOME.
      "--mount", s"type=volume,src=$persistentVolume,dst=$ContainerHome/persistent-volume",

      // Chromium treats podman's 64 MB /dev/shm default as fatal, and agy's browser automation needs more. The size is
      // not a host RAM reservation.
      "--shm-size=512m",
    ) ++ memoryArgs ++ Vector("--workdir", mountPath)
    CreateCommand(options, imageId +: command.toVector)

  /**
   * The backend's steps, then the settings that every sandbox container carries as labels (KoAgentBpf.labelArguments),
   * and the comparison with the live sessions.
   * - The comparison runs under the launch lock, from the listing until this run's container exists. The backend and
   *   the socket setting must equal those of every live session that shares the volume or a raw mount
   *   (ko-agent-fs/bpf/doc/architecture.md, "The hooks", `file_receive`).
   * - `prepare` runs the backend's steps 1 to 3 where the backend serves this run, under the lock too. Another
   *   launcher's reconcile takes a session with pins and no container for an orphan
   *   (ko-agent-fs/bpf/doc/architecture.md, "Lifecycle", step 7).
   * - `identities` gives each path's identity in the machine, as the labels record it.
   * - On native Linux no backend but the FUSE backend runs, so no identity is read, and no live session is compared.
   */
  private def createUnderLaunchLock(
    createCommand: CreateCommand,
    settings: CommandLine.WorkspaceSettings,
    persistentVolume: String,
    mountPaths: Vector[String],
    prepare: () => Option[KoAgentBpf.Launched],
    identities: Option[KoAgentBpf.Launched] => Vector[String] => Map[String, String],
    environment: Map[String, String],
    os: Os,
  ): (Option[KoAgentBpf.Launched], HostCommands.Run) =
    def bpfOptions(launched: Option[KoAgentBpf.Launched]): Vector[String] =
      launched.toVector.flatMap: done =>
        Vector(s"--cgroup-parent=${done.parent}", "--restart=no", s"--label=${KoAgentBpf.CgroupLabel}=${done.cgroup}")
    if os == Os.Linux then
      val labels = KoAgentBpf.labelArguments(settings, persistentVolume, Vector.empty, None)
      return (None, runWithEnvironment(environment, createCommand.withOptions(labels)*))
    withFileLock(KoAgentBpf.launchLockFile(stateRoot(os))):
      val launched = prepare()
      val names = listedNames(podman, "ps", "--all", "--filter", "name=ko-agent-sandbox-run-", "--format", "{{.Names}}")
        .fold(
          err => fail(s"error: could not list the live sessions, which the backend's launch compares with\n$err"),
          identity,
        )
      val live = names.map: name =>
        val inspected = run(podman, "inspect", "--format", KoAgentBpf.LabelsFormat, name)
        if !inspected.ok then fail(s"error: could not read the labels of the live session $name\n${inspected.err}")
        KoAgentBpf.liveSessionOf(name, inspected.text)
      val paths = (mountPaths ++ live.flatMap(_.mounts.map(_.path))).distinct
      val known = identities(launched)(paths)
      val mine = mountPaths.map: path =>
        val identity = known.getOrElse(path, fail(s"error: the machine answered no identity for $path"))
        if identity == "gone" then fail(s"error: the machine finds nothing at $path, which this launch mounts")
        KoAgentBpf.RawMount(path, identity)
      KoAgentBpf.refusalBeside(settings, persistentVolume, mine, live, path => known.get(path).filter(_ != "gone"))
        .foreach(reason => fail(reason))
      val labels = KoAgentBpf.labelArguments(settings, persistentVolume, mine, None)
      (launched, runWithEnvironment(environment, createCommand.withOptions(labels ++ bpfOptions(launched))*))

  /** What follows the hold: the create, the reaper, the FUSE backend's mount and the command runner, then the handover
    * to the sandbox. */
  private def startSandbox(
    parsed: ParsedCommandLine,
    settings: LaunchSettings,
    workspace: LaunchWorkspace,
    rules: LaunchRules,
    names: RunNames,
    mount: LaunchMount,
    git: GitAccess,
    createCommand: CreateCommand,
    fuseReap: Option[String],
    runFiles: Path,
    channelLogFile: Path,
    micLogFile: Path,
    backendLogFile: Path,
    cleanup: RunCleanup,
    os: Os,
  ): Nothing =
    import settings.{awsCredential, clipboard, clipboardHost, credentials, mic, workspaceRoot, runOnHost}
    import workspace.{mountPath, persistentVolume, workspaceId}
    import rules.readOnlyFileRules
    import names.{egressNetwork, proxyContainer, sandboxContainer, sandboxNetwork}
    import mount.{bpf, fuseWorkspace, sessionRulesText}
    val workspaceSettings = mount.settings
    // The AWS values go into the create's own environment, where the create's value-less `--env=NAME` reads them. The
    // launch checks the values again here, since the hold above may have outlasted them.
    awsCredential.flatMap(AwsCredential.expiredSince(_, Instant.now())).foreach(message => fail(message))

    // The backend's steps 1 to 3 (ko-agent-fs/bpf/doc/architecture.md, "Lifecycle") run before the container exists:
    // the attach cgroup, the policy attached from the preloaded set or loaded, the read-back and the proof.
    // - The steps run in one script in the machine. A failure names the step, and the launch ends with nothing bound
    //   writable.
    // - The script runs under the image-build lock, as the FUSE backend's mount does, so a --build that replaces the
    //   binaries waits.
    // The gitdir bind's source is spelled as the machine spells it, as the workspace root is (mountPathOf).
    val gitdirSource = git.mountedGitdir.map(bind => mountPathOf(os, bind.source).fold(fail(_), identity))
    val mountPaths = mountPath +: gitdirSource.toVector
    def backendSteps(facts: KoAgentBpf.Facts): KoAgentBpf.Launched =
      val fixture = mountPathOf(os, KoAgentBpf.fixtureRoot(stateRoot(os), workspaceId)).fold(fail(_), identity)
      val placement =
        mountPathOf(os, KoAgentBpf.placementFile(stateRoot(os), sandboxContainer)).fold(fail(_), identity)
      val script = KoAgentBpf.launchScript(
        sandboxContainer, workspaceSettings, facts, mountPath, fixture, placement, sessionRulesText, persistentVolume,
        gitdirSource, Vector.empty, bundledKoAgentFsSourceId(), KoAgentBpf.bundledSourceId(), os,
      )
      val ran = withFileLock(ImageBuilds.imageBuildLockFile(os)):
        run(koAgentFsScriptCommand(podman, os, script)*)
      if !ran.ok then
        fail(
          s"error: the BPF backend's launch failed at its ${KoAgentBpf.stepReached(ran.text)} step; nothing is bound " +
            s"writable\n${ran.text.linesIterator.filter(_.contains("mismatch")).mkString("\n")}${ran.err}",
          ran.exit,
        )
      KoAgentBpf.parseLaunched(ran.text).fold(reason => fail(s"error: $reason\n${ran.text}"), identity)
    // The identities that the labels record: the launch script's identities where the backend ran, else identities
    // read now.
    val identities: Option[KoAgentBpf.Launched] => Vector[String] => Map[String, String] = launched =>
      paths =>
        launched.map(_.identities).filter(known => paths.forall(known.contains)).getOrElse:
          val asked = run(koAgentFsScriptCommand(podman, os, KoAgentBpf.identScript(paths))*)
          if !asked.ok then fail(s"error: the machine did not answer the mounts' identities\n${asked.err}")
          KoAgentBpf.parseIdentities(asked.text)
    val (launched, created) = createUnderLaunchLock(
      createCommand, workspaceSettings, persistentVolume, mountPaths, () => bpf.map(backendSteps), identities,
      awsCredential.map(_.environment).getOrElse(Map.empty), os,
    )
    if !created.ok then
      fail(
        s"error: could not create the sandbox container\n${created.err}" +
          KoAgentBpf.createFailureNote(os, created.err).filter(_ => bpf.isDefined).fold("")(note => s"\n$note"),
      )
    launched.foreach: done =>
      System.err.println(KoAgentBpf.LaunchLine)
      KoAgentBpf.appendLog(backendLogFile, KoAgentBpf.stepsLogLine(done))
      if done.preloaded then
        KoAgentBpf.appendLog(backendLogFile, "a program set for the next launch is being verified behind this one")
    // Step 4's placement check (ko-agent-fs/bpf/doc/architecture.md, "Lifecycle", step 4). `podman init` makes the
    // container now, so the machine's watcher reads the container's cgroup while the launch goes on. The start below
    // waits for the verdict.
    val initializing = launched.map: _ =>
      val task = java.util.concurrent.FutureTask(() => run(podman, "init", sandboxContainer))
      Thread.startVirtualThread(task)
      task

    // The status file lies in this run's own directory, where the reaper's microphone job reports its probe.
    val micJob = mic.filter(_ => os != Os.Windows).map: recorders =>
      MicJob(runFiles.resolve("mic.status"), micLogFile, recorders)

    // A failed spawn is not fatal. The handover takes the resident path (handOver), which is the model that Windows
    // always uses.
    val reaperArmed =
      os != Os.Windows &&
        spawnReaper(
          podman, sandboxContainer, proxyContainer, sandboxNetwork, egressNetwork,
          fuseReap.map(_ => koAgentFsTeardownMode(os)).getOrElse("none"),
          fuseReap.getOrElse(""),
          clipboard,
          clipboardHost,
          micJob,
        )
    if os != Os.Windows && !reaperArmed then
      // A failed spawn is fatal when a relay was asked for. The sandbox would otherwise wait the clipboard shim's bound
      // on every paste, or dictate nothing, for a relay that never comes. The cleanup hook removes what was created,
      // the never-started sandbox included (removeRunResources).
      if clipboard != "off" then
        fail(
          s"error: could not spawn the proxy reaper, which serves --clipboard=$clipboard; launch again, or without it",
        )
      if mic.nonEmpty then
        fail(s"error: could not spawn the proxy reaper, which serves $MicOption; launch again, or without it")
      System.err.println("note: could not spawn the proxy reaper; staying resident to remove the proxy on exit")
    clipboardHost.powershell.foreach(ClipboardRelay.startResident(_, podman, sandboxContainer, clipboard))

    // The launch probe runs before the sandbox starts, and the recorder that delivers becomes the session's recorder.
    // A launch whose microphone cannot record fails here, and its cleanup hook removes what was made.
    mic.foreach: recorders =>
      val notice = () =>
        System.err.println("mic: answer macOS's microphone permission prompt; the launch waits up to a minute")
      def recording(label: String, silent: Boolean): Unit =
        System.err.println(s"mic: recording with $label")
        if silent then warn(MicRelay.silenceWarning(os))
      micJob match
        case Some(job) =>
          MicRelay.awaitProbe(job.status, os, notice) match
            case MicRelay.ProbeOutcome.Recording(label, silent) => recording(label, silent)
            case MicRelay.ProbeOutcome.Failed(reasons) => fail(MicRelay.failureMessage(reasons, os))
        case None =>
          MicRelay.probeResident(recorders, MicRelay.probeBoundSeconds(os), micLogFile) match
            case Right(kept) =>
              recording(kept.recorder.label, kept.silent)
              MicRelay.startResident(kept, podman, sandboxContainer, micLogFile)
            case Left(reasons) =>
              val diagnosis = findOnPath("powershell", os)
                .map(MicRelay.windowsDiagnostics).getOrElse(Vector.empty)
              fail(MicRelay.failureMessage(reasons, os, diagnosis))

    // The launch prints the mount's branch here, not on the workspace line above. The user should not have to infer
    // "joined" from silence, and which branch the mount took is known only now.
    val mountedFileRules = fuseWorkspace.map: prepared =>
      val (joined, resolved) =
        mountKoAgentFs(podman, os, prepared, workspaceId, mountPath, sandboxContainer, sessionRulesText)
      System.err.println(
        if joined then "FUSE backend: joined the existing mount for this workspace"
        else "FUSE backend: mounted",
      )
      resolved
    val resolvedFileRules = mountedFileRules.orElse(launched.filter(_ => workspaceSettings.live).map(_.resolved))
      .orElse(readOnlyFileRules)
    resolvedFileRules.map(FileRules.guardLines).getOrElse(Vector.empty).foreach(System.err.println)

    // The command runner starts detached like the reaper, because the runner must outlive the exec below. The runner
    // ends itself when the sandbox stops. A session that asked for the channel and cannot have it is a failed launch,
    // as with the clipboard above.
    if runOnHost.nonEmpty then
      // The file lies in this run's own directory and is removed with it. The runner and each command read the file
      // there.
      val runnerFileRules = runFiles.resolve("file-rules.resolved")
      resolvedFileRules.foreach(resolved => writePrivate(runnerFileRules, resolved.text))
      if !RunOnHostChannel.spawnRunner(
          podman, sandboxContainer, workspaceRoot, runOnHost, channelLogFile, mountPath,
          // A brokered name reaches a host command as the sandbox has the name: with its placeholder.
          forwards = parsed.env ++ awsCredential.toVector.flatMap(_.forwards) ++ credentials.map(credential =>
            EnvForward(credential.binding.name, Some(credential.placeholder)),
          ),
          fileRules = resolvedFileRules.map(_ => runnerFileRules),
          credentials = credentials,
        )
      then fail("error: could not spawn the command runner, which serves --run-on-host")

    launched.zip(initializing).foreach: (done, task) =>
      val initialized = task.get()
      val waiting = System.nanoTime()
      val report = KoAgentBpf.placementFile(stateRoot(os), sandboxContainer)
      KoAgentBpf.confirmPlacement(initialized, KoAgentBpf.awaitPlacement(report), done.cgroup) match
        case Right(_) =>
          KoAgentBpf.appendLog(
            backendLogFile,
            s"the container lies below the attach cgroup, confirmed after " +
              s"${(System.nanoTime() - waiting) / 1_000_000} ms of waiting",
          )
        case Left(reason) =>
          fail(s"error: $reason; the container has not started. Launch with --workspace=live,fuse meanwhile")

    // Separate the launch diagnostics from the agent's terminal UI.
    System.err.println()

    handOver(
      Vector(podman, "start", "--attach", "--interactive", sandboxContainer),
      viaExec = reaperArmed,
      cleanup = cleanup,
    )
