// The BPF cgroup-LSM backend of doc/plan-bpf-lsm-cgroup.md as the launcher drives it, on the podman
// machines: the build and install of its binaries (bpf/ko-agent-bpf/), the capability probe, the
// launch's steps 1 to 3 ("Lifecycle": the attach cgroup, the controller, the read-back and the proof),
// the teardown, the reconcile at every launcher start, and the labels and the launch lock by which
// a launch is refused beside a live session of the other backend or socket setting ("The hooks",
// `file_receive`). The filter's module, KoAgentFs.scala, is the model: the same install directory,
// the same `podman machine ssh` channel, the same base64 transport for user-controlled values.

package agentsandbox.launcher

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path}
import java.util.Base64
import scala.jdk.CollectionConverters.*
import scala.util.Using

import CommandLine.WorkspaceSettings
import HostCommands.*
import KoAgentFs.{koAgentFsScriptCommand, KoAgentFsBinary, KoAgentFsInstallDir}
import LauncherImages.{bundleIndex, bundleResource, bundleSourceId, KoAgentBpfBuildImage, KoAgentBpfImage}

object KoAgentBpf:

  /** Where the backend is installed, relative to the machine user's home, beside the filter. */
  val InstallDir = s"$KoAgentFsInstallDir/bpf"

  /** Where the sessions' links and programs are pinned, and the spare set ("Lifecycle"). */
  val PinRoot = "/sys/fs/bpf/ko-agent-bpf"
  val SparePinDir = s"$PinRoot/spare"

  /** A session's pin directory: bpffs refuses a name holding a `.` (`EPERM` at the lookup), and a
    * container name carries the workspace directory's, so the dot becomes `_` here and in the
    * controller's reconcile (`pin_name`); the session's record, cgroup and unit keep the name. */
  def pinDir(session: String): String = s"$PinRoot/${session.replace('.', '_')}"

  /** The eight hooks of every session, and the ninth under `unix-socket` ("The hooks"). */
  val Hooks: Vector[String] = Vector(
    "file_open", "inode_create", "inode_mknod", "inode_symlink", "inode_link", "inode_rename", "inode_unlink",
    "inode_setattr",
  )
  val ReceiveHook = "file_receive"
  def hooks(unixSocket: Boolean): Vector[String] = if unixSocket then Hooks :+ ReceiveHook else Hooks

  /** Why a launch under the backend is refused for its nesting mode, or None: the first version runs
    * under `--nesting=none` alone, since the other modes keep podman's default profile, under which
    * a session mounts and creates user namespaces, routes the hooks do not judge yet ("Mounts",
    * "Later versions"). */
  def nestingRefusal(settings: WorkspaceSettings, nesting: String): Option[String] =
    Option.when(settings.bpf && nesting != CommandLine.DefaultNestingMode)(
      s"error: --workspace=${settings.spelled} needs --nesting=none; under --nesting=$nesting the session can mount " +
        "and create user namespaces, which the BPF policy does not judge yet, so the ko-agent-fs filter holds the " +
        "workspace's protections there (SECURITY.md, \"The BPF backend\")",
    )

  /** The share types the plan measured; another refuses the launch ("Phases", 6). */
  val MeasuredShareTypes: Set[String] = Set("virtiofs", "9p")

  // ---------------------------------------------------------------------------
  // Labels: what every sandbox container says about itself, for the next launch's comparison
  // ---------------------------------------------------------------------------

  /** The workspace settings, in WorkspaceSettings.spelled's spelling. */
  val SettingsLabel = "ko-agent-sandbox.workspace"
  /** The persistent volume the container mounts. */
  val VolumeLabel = "ko-agent-sandbox.volume"
  /** The raw mounts: the workspace tree and a linked worktree's main gitdir, each as `identity:base64(path)`,
    * separated by spaces; the identity is `stat -c %d:%i` in the machine (identScript). */
  val MountsLabel = "ko-agent-sandbox.raw-mounts"
  /** The attach cgroup's path in the machine, for the reconcile; absent on a filter-backed session. */
  val CgroupLabel = "ko-agent-sandbox.bpf-cgroup"

  final case class RawMount(path: String, identity: String):
    def encoded: String = s"$identity:${Base64.getEncoder.encodeToString(path.getBytes(StandardCharsets.UTF_8))}"

  object RawMount:
    def decode(entry: String): Option[RawMount] =
      entry.split(":", 3) match
        case Array(dev, ino, path) =>
          try Some(RawMount(String(Base64.getDecoder.decode(path), StandardCharsets.UTF_8), s"$dev:$ino"))
          catch case _: IllegalArgumentException => None
        case _ => None

  def labelArguments(
    settings: WorkspaceSettings,
    volume: String,
    mounts: Vector[RawMount],
    cgroup: Option[String],
  ): Vector[String] =
    Vector(
      s"--label=$SettingsLabel=${settings.spelled}",
      s"--label=$VolumeLabel=$volume",
      s"--label=$MountsLabel=${mounts.map(_.encoded).mkString(" ")}",
    ) ++ cgroup.map(path => s"--label=$CgroupLabel=$path")

  /** What a listed sandbox container says of itself; `settings` is None for a container of a launcher
    * before the labels, which the comparison refuses beside. */
  final case class LiveSession(
    name: String,
    settings: Option[WorkspaceSettings],
    volume: String,
    mounts: Vector[RawMount],
    cgroup: Option[String],
  )

  /**
   * The inspect format reading the four labels, one per line; a host argument, so free of double
   * quotes (LauncherImages.labelTemplate).
   */
  val LabelsFormat: String =
    Vector(SettingsLabel, VolumeLabel, MountsLabel, CgroupLabel)
      .map(LauncherImages.labelTemplate).mkString("{{println}}")

  /** A container's labels out of its LabelsFormat answer. */
  def liveSessionOf(name: String, inspected: String): LiveSession =
    val lines = inspected.linesIterator.toVector.padTo(4, "")
    LiveSession(
      name,
      Option(lines(0)).filter(_.nonEmpty).flatMap(CommandLine.parseWorkspace(_).toOption),
      lines(1),
      lines(2).split(" ").toVector.filter(_.nonEmpty).flatMap(RawMount.decode),
      Option(lines(3)).filter(_.nonEmpty),
    )

  /**
   * Why this launch is refused beside the live sessions, or None ("The hooks", `file_receive`).
   * `reread` is each recorded path's identity in the machine now, None where the path is gone.
   * Two sessions share when their volumes are equal, when a raw mount of each has the same
   * identity, or when a path of one is the other's or lies below it; a session whose recorded path
   * no longer names its recorded identity is refused beside, since a host rename happened in
   * between and the paths cannot be compared. A container without the labels is an earlier
   * launcher's, which ran the filter and no socket setting, and whose volume and mounts are
   * unknown: refused beside a launch under any other backend or setting, and no concern to a
   * filter launch, which it equals.
   */
  def refusalBeside(
    mine: WorkspaceSettings,
    myVolume: String,
    myMounts: Vector[RawMount],
    live: Vector[LiveSession],
    reread: String => Option[String],
  ): Option[String] =
    def beneath(above: String, below: String): Boolean =
      below == above || below.startsWith(above.stripSuffix("/") + "/")
    def shares(other: LiveSession): Boolean =
      other.volume == myVolume ||
        other.mounts.exists(theirs => myMounts.exists(_.identity == theirs.identity)) ||
        other.mounts.exists(theirs =>
          myMounts.exists(ours => beneath(theirs.path, ours.path) || beneath(ours.path, theirs.path)),
        )
    live.iterator.map { other =>
      other.settings match
        case None if mine.bpf || mine.unixSocket =>
          Some(
            s"error: ${other.name} is a live session of an earlier launcher, which ran the ko-agent-fs filter, and " +
              "whether it shares this workspace's volume or tree cannot be told without its labels; end it first",
          )
        case None => None
        case Some(theirs) =>
          val renamed = other.mounts.filter(mount => !reread(mount.path).contains(mount.identity))
          if renamed.nonEmpty && (theirs.backend != mine.backend || theirs.unixSocket != mine.unixSocket) then
            Some(
              s"error: ${other.name} runs under --workspace=${theirs.spelled}, and its recorded path " +
                s"${renamed.head.path} no longer names the directory it was launched on, so whether it shares " +
                "this workspace's tree cannot be told; end it first, or launch with the same backend and socket " +
                "setting",
            )
          else if (theirs.backend != mine.backend || theirs.unixSocket != mine.unixSocket) && shares(other) then
            Some(
              s"error: ${other.name} runs under --workspace=${theirs.spelled} and shares this workspace's volume or " +
                s"tree; a session under --workspace=${mine.spelled} beside it would judge the shared files by " +
                "another policy. End it first, or launch with the same backend and socket setting",
            )
          else None
    }.collectFirst { case Some(reason) => reason }

  // ---------------------------------------------------------------------------
  // Build and install
  // ---------------------------------------------------------------------------

  /** The bundled files the backend is built from: the directory, the classifier and the records header. */
  val SourcePaths: Vector[String] = Vector("bpf/ko-agent-bpf/policy.bpf.c", "ko-agent-fs/include/records.h")
  val SourceDir = "bpf/ko-agent-bpf"

  /** The source id of the backend out of an unpacked context, over exactly what the Containerfile copies. */
  def sourceId(context: Path): String =
    val dir = context.resolve(SourceDir)
    val own = Using.resource(Files.list(dir))(_.iterator().asScala.toVector)
      .filter(Files.isRegularFile(_))
      .map(file => s"$SourceDir/${file.getFileName}" -> Files.readAllBytes(file))
    val shared = SourcePaths.map(path => path -> Files.readAllBytes(context.resolve(path)))
    bundleSourceId(own ++ shared)

  /** The same id out of the jar, for a launch's check of the installation: the directory's own files, not
    * `host/`, the classifier's host build the self-test image compiles (its id is the self-test's). */
  def bundledSourceId(): String =
    val own = bundleIndex()
      .filter(entry => entry.startsWith(s"$SourceDir/") && !entry.drop(SourceDir.length + 1).contains('/'))
      .map(entry => entry -> bundleResource(entry))
    bundleSourceId(own ++ SourcePaths.map(path => path -> bundleResource(path)))

  /** The build, from the unpacked bundle's root (bpf/ko-agent-bpf/Containerfile has why): the compile
    * stage under its cache tag, then the image the install extracts. `kernel` is the machine's. */
  def buildCommands(podman: String, kernel: String, sourceId: String): Vector[Vector[String]] =
    Vector(
      Vector(
        podman, "build", ImageBuilds.NoRegistryLookup, "--target", "build",
        "--build-arg", s"BUILD_KERNEL=$kernel", "--build-arg", s"KO_AGENT_BPF_SOURCE_ID=$sourceId",
        "-f", s"$SourceDir/Containerfile", "-t", KoAgentBpfBuildImage, ".",
      ),
      Vector(
        podman, "build", ImageBuilds.NoRegistryLookup,
        "--build-arg", s"BUILD_KERNEL=$kernel", "--build-arg", s"KO_AGENT_BPF_SOURCE_ID=$sourceId",
        "-f", s"$SourceDir/Containerfile", "-t", KoAgentBpfImage, ".",
      ),
    )

  /** `podman info`'s kernel: the machine's, since the server answers. */
  def machineKernel(podman: String): String =
    val answered = run(podman, "info", "--format", "{{.Host.Kernel}}")
    if !answered.ok || answered.text.trim.isEmpty then
      fail(s"error: podman info did not answer the machine's kernel release\n${answered.err}")
    answered.text.trim

  /** The pseudo filesystems the controller and the read-back need, mounted where the machine does
    * not (the WSL machine mounts neither, "Environment evidence"). */
  val MountPseudoFilesystems: String =
    """sudo -n sh -c 'findmnt -n /sys/kernel/security >/dev/null || mount -t securityfs securityfs /sys/kernel/security
      |  findmnt -n /sys/fs/bpf >/dev/null || mount -t bpf bpf /sys/fs/bpf'""".stripMargin

  /**
   * The install, in the machine: the image's /out into the install directory, the source id checked,
   * the installed object's tags recorded under the running kernel ("Lifecycle", 3), and the spare
   * set prepared afresh, since the one of an earlier build fails the tag check.
   */
  def installScript(sourceId: String): String =
    withScriptPath(
      s"""set -eu
         |dir="$$HOME/$InstallDir"
         |mkdir -p "$$dir"
         |podman create --replace --name ko-agent-bpf-extract $KoAgentBpfImage >/dev/null
         |podman cp ko-agent-bpf-extract:/out/. "$$dir/"
         |podman rm ko-agent-bpf-extract >/dev/null
         |installed="$$(cat "$$dir/source-id")"
         |if [ "$$installed" != "$sourceId" ]; then
         |  echo "the extracted backend reports source $$installed, expected $sourceId" >&2
         |  exit 1
         |fi
         |$MountPseudoFilesystems
         |sudo -n "$$dir/readback" tags policy.bpf.o "$$dir/tags.txt"
         |sudo -n "$$dir/controller" unpin $SparePinDir >/dev/null 2>&1 || true
         |sudo -n "$$dir/controller" prepare-spare $SparePinDir
         |cat "$$dir/clang-version.txt" "$$dir/build-kernel.txt" "$$dir/objects.sha256\"""".stripMargin,
    )

  def installedLine(installOutput: String): String =
    val lines = installOutput.linesIterator.toVector
    val tags = lines.find(_.startsWith("tags ")).map(line => field("programs", line).getOrElse("?")).getOrElse("?")
    val spare = lines.find(_.startsWith("spare ")).map(line => field("load_ms", line).getOrElse("?")).getOrElse("?")
    s"ko-agent-bpf installed: $tags programs verified; a program set for the next launch loaded in $spare ms"

  /** Install the freshly built backend into the machine and prepare its spare. Linux has no machine
    * and keeps the filter ("Later versions"), so the caller does not come here. */
  def installKoAgentBpf(podman: String, os: Os, sourceId: String): Either[String, Unit] =
    val command = koAgentFsScriptCommand(podman, os, installScript(sourceId))
    echoCommand(command)
    val installed = run(command*)
    if !installed.ok then Left(s"install failed:\n${installed.err.trim}")
    else
      System.err.println(installedLine(installed.text))
      System.err.println(
        s"  to remove it: podman machine ssh rm -r $InstallDir, and the unit below as its comment says",
      )
      Right(ensureSpareUnit(podman, os))

  // ---------------------------------------------------------------------------
  // The boot-time unit that prepares the first spare
  // ---------------------------------------------------------------------------

  val SpareUnit = "ko-agent-bpf-spare.service"
  val SpareUnitPath = s"/etc/systemd/system/$SpareUnit"

  /** The unit's text; `home` is the machine user's home, where the controller is installed. */
  def spareUnitText(home: String): String =
    s"""[Unit]
       |Description=ko-agent-sandbox: load and verify the workspace policy's BPF programs ahead of the first launch
       |# Written by ko-agent-sandbox --build with your consent (KoAgentBpf.scala); remove with
       |# `sudo systemctl disable --now $SpareUnit && sudo rm $SpareUnitPath`.
       |
       |[Service]
       |Type=oneshot
       |ExecStartPre=/bin/sh -c 'findmnt -n /sys/kernel/security >/dev/null \\
       |  || mount -t securityfs securityfs /sys/kernel/security'
       |ExecStartPre=/bin/sh -c 'findmnt -n /sys/fs/bpf >/dev/null || mount -t bpf bpf /sys/fs/bpf'
       |ExecStart=$home/$InstallDir/controller prepare-spare $SparePinDir
       |
       |[Install]
       |WantedBy=multi-user.target
       |""".stripMargin

  /** Whether the installed unit is the expected text and enabled; the text is compared in the machine,
    * where the home is known. */
  def spareUnitCheckScript: String =
    s"""set -u
       |expected="$$(${printingCommand(spareUnitText("@HOME@"))} | sed "s|@HOME@|$$HOME|g")"
       |[ "$$(cat $SpareUnitPath 2>/dev/null)" = "$$expected" ] || exit 1
       |systemctl is-enabled $SpareUnit >/dev/null 2>&1""".stripMargin

  def spareUnitInstallScript: String =
    s"""set -eu
       |${printingCommand(spareUnitText("@HOME@"))} | sed "s|@HOME@|$$HOME|g" | sudo -n tee $SpareUnitPath >/dev/null
       |sudo -n systemctl daemon-reload
       |sudo -n systemctl enable $SpareUnit >/dev/null 2>&1""".stripMargin

  /** The two scripts hold double quotes, so they cross the machine's ssh as koAgentFsScriptCommand
    * sends them: Windows passes a quote through unescaped (KoAgentFs.koAgentFsScriptCommand). */
  def spareUnitCheckCommand(podman: String, os: Os): Vector[String] =
    koAgentFsScriptCommand(podman, os, spareUnitCheckScript)

  def spareUnitInstallCommand(podman: String, os: Os): Vector[String] =
    koAgentFsScriptCommand(podman, os, spareUnitInstallScript)

  /**
   * The boot-time unit, installed with the user's consent: a system unit is the machine's
   * configuration (SECURITY.md, "Silent changes to what you own"), as /etc/fuse.conf is for the
   * filter. Declined, the first launch after each boot loads its programs itself, once.
   */
  /** The consent prompt's text. The unit is joined after `stripMargin`, which would otherwise take the
    * leading spaces and the first `|` of its `|| mount` continuation line, showing text the file does not
    * hold. */
  def spareUnitPrompt: String =
    val indentedUnit = spareUnitText("$HOME").linesIterator.map(line => s"  $line").mkString("\n")
    s"""Each launch of --workspace=live,bpf attaches BPF programs the kernel must verify first, a wait
       |of up to a few seconds that depends on the machine's kernel. The launcher keeps one program set
       |loaded and verified ahead of the next launch, so no launch waits for that (SECURITY.md, "The BPF
       |backend").
       |After a machine boot the first such set comes from a system unit, $SpareUnitPath,
       |run as root at boot. Your machine's configuration is not changed without asking. The unit, with
       |$$HOME the machine user's home:
       |""".stripMargin + "\n" + indentedUnit + "\n" +
      """
        |Without it, the first launch after each boot loads and verifies its programs itself and waits
        |that time; every later launch finds the set the launch before it left ready.""".stripMargin

  def ensureSpareUnit(podman: String, os: Os): Unit =
    if run(spareUnitCheckCommand(podman, os)*).ok then return
    System.err.println(spareUnitPrompt)
    val reader = AgentSandboxLauncher.terminalReader
    val answer = reader.flatMap: console =>
      console.prompt("Install the unit now? [y/N] ")
      console.readLine()
    if !consented(answer) then
      System.err.println(
        "note: the unit is not installed; the first launch after each machine boot verifies its programs itself",
      )
      return
    val installed = run(spareUnitInstallCommand(podman, os)*)
    if !installed.ok then fail(s"error: installing $SpareUnit failed: ${installed.err}", installed.exit)
    if !run(spareUnitCheckCommand(podman, os)*).ok then
      fail(s"error: $SpareUnit is not installed as expected after enabling; check the machine's $SpareUnitPath")
    System.err.println(s"unit installed: $SpareUnitPath")

  // ---------------------------------------------------------------------------
  // The capability probe, at every launch
  // ---------------------------------------------------------------------------

  /** What the probe reads in the machine, one `key=value` line each (parseFacts). */
  def checksScript(backing: String): String =
    withScriptPath(
      s"""set -u
         |backing="$$(${printingCommand(backing)})"
         |dir="$$HOME/$InstallDir"
         |echo "home=$$HOME"
         |echo "uid=$$(id -u)"
         |echo "kernel=$$(uname -r)"
         |echo "manager=$$(podman info --format '{{.Host.CgroupManager}}' 2>/dev/null || echo unknown)"
         |echo "cgroup2=$$(stat -f -c %T /sys/fs/cgroup 2>/dev/null || echo none)"
         |echo "user_manager=$$(systemctl --user is-system-running 2>/dev/null || echo none)"
         |if sudo -n true 2>/dev/null; then echo sudo=1; else echo sudo=0; fi
         |if $MountPseudoFilesystems
         |then echo mounted=1; else echo mounted=0; fi
         |echo "lsm=$$(sudo -n cat /sys/kernel/security/lsm 2>/dev/null || echo unknown)"
         |if [ -r /sys/kernel/btf/vmlinux ]; then echo btf=1; else echo btf=0; fi
         |echo "share_type=$$(findmnt -n -o FSTYPE -T "$$backing" 2>/dev/null || echo unknown)"
         |echo "installed_source=$$(cat "$$dir/source-id" 2>/dev/null || echo none)"
         |if [ -x "$$dir/controller" ] && [ -x "$$dir/readback" ] && [ -x "$$dir/fixture" ] \\
         |    && [ -r "$$dir/policy.bpf.o" ] && [ -r "$$dir/tags.txt" ]; then echo binaries=1; else echo binaries=0; fi
         |echo "tags_kernel=$$(sed -n 's/^kernel=\\([^ ]*\\).*/\\1/p' "$$dir/tags.txt" 2>/dev/null)"
         |echo "fs_version=$$("$$HOME/$KoAgentFsBinary" --version 2>/dev/null || true)"""".stripMargin,
    )

  /** The probe's answer. */
  final case class Facts(values: Map[String, String]):
    def apply(key: String): String = values.getOrElse(key, "")
    def home: String = apply("home")
    def uid: String = apply("uid")
    def manager: String = apply("manager")
    def shareType: String = apply("share_type")

  def parseFacts(text: String): Facts =
    Facts(text.linesIterator.flatMap { line =>
      line.indexOf('=') match
        case -1 => None
        case at => Some(line.take(at) -> line.drop(at + 1).trim)
    }.toMap)

  /** The upgrade that brings the machine's kernel and podman forward, per provider (doc/TODO.md,
    * "A stale podman machine OS"); the Windows machine's kernel is WSL's. */
  def upgradeRemedy(os: Os): String =
    os match
      case Os.Windows => "update WSL, whose kernel the podman machine runs: `wsl --update`, then `wsl --shutdown`"
      case _ => "upgrade the podman machine's OS: `podman machine os upgrade --restart`"

  /**
   * What the machine lacks for the backend, each with what to do, or nothing. `bpfSourceId` and
   * `fsSourceId` are this launcher's bundled builds: the installed backend and the guard must be
   * them.
   */
  def requirementFailures(facts: Facts, os: Os, bpfSourceId: String, fsSourceId: String): Vector[String] =
    val checks: Vector[(Boolean, String)] = kernelChecks(facts, os) ++ Vector(
      (
        Set("running", "degraded").contains(facts("user_manager")),
        s"the machine user's systemd manager is ${facts("user_manager")}; the attach cgroup is made under it",
      ),
      (
        MeasuredShareTypes.contains(facts.shareType),
        s"the workspace's share is ${facts.shareType}, not one the policy was measured on " +
          s"(${MeasuredShareTypes.mkString(", ")})",
      ),
      (
        facts("binaries") == "1" && facts("installed_source") == bpfSourceId,
        "the BPF backend is not installed from this launcher's build; run --build",
      ),
      (
        facts("tags_kernel").nonEmpty && facts("tags_kernel") == facts("kernel"),
        s"the installed policy's tags were recorded under kernel ${facts("tags_kernel")}, the machine runs " +
          s"${facts("kernel")}; run --build",
      ),
      (
        KoAgentFs.koAgentFsReportedSourceId(facts("fs_version")).contains(fsSourceId),
        "the installed ko-agent-fs, whose guard compiles the policy's records, is not this launcher's build; " +
          "run --build",
      ),
    )
    checks.collect { case (false, reason) => reason }

  /** The machine's own prerequisites, which the build needs as a launch does. */
  private def kernelChecks(facts: Facts, os: Os): Vector[(Boolean, String)] =
    val remedy = upgradeRemedy(os)
    Vector(
      (
        facts("sudo") == "1",
        "the machine's `sudo -n` fails; the controller loads the policy as root (`podman machine ssh sudo -n true`)",
      ),
      (
        facts("lsm").split(",").contains("bpf"),
        s"the machine's kernel lists no `bpf` LSM (/sys/kernel/security/lsm: ${facts("lsm")}); $remedy",
      ),
      (facts("cgroup2") == "cgroup2fs", s"the machine's /sys/fs/cgroup is ${facts("cgroup2")}, not cgroup v2; $remedy"),
      (facts("mounted") == "1", "bpffs or securityfs could not be mounted in the machine"),
    )

  /**
   * What keeps `--build` from building the backend on this machine: the kernel prerequisites and the
   * kernel's BTF, which the compile reads. On any, the build skips the backend and the filter's build
   * goes on, `fuse` being the default; on none, a failure of the backend's build fails the build.
   */
  def buildFailures(facts: Facts, os: Os): Vector[String] =
    (kernelChecks(facts, os) :+ (facts("btf") == "1", s"the machine's kernel has no BTF (/sys/kernel/btf/vmlinux), " +
      s"which the policy is compiled against; ${upgradeRemedy(os)}")).collect { case (false, reason) => reason }

  /** The build's warning when the backend's build or install failed on a machine that passed the checks. */
  def buildFailedNote(reason: String, os: Os): String =
    "the BPF backend could not be built on this machine, so `--workspace=...,bpf` is refused until a later " +
      "`--build` succeeds; the rest of the build is complete. The machine's kernel may lack a BPF feature the " +
      s"policy uses, which is measured on kernels 6.18 and 7.2: ${upgradeRemedy(os)}. The backend's $reason"

  /** The build's note when it skipped the backend. */
  def buildSkippedNote(failures: Vector[String]): String =
    val heading = "note: the BPF backend is not built on this machine, so `--workspace=...,bpf` is refused until " +
      "a `--build` after these are resolved:"
    (heading +: failures.map(reason => s"  - $reason")).mkString("\n")

  // ---------------------------------------------------------------------------
  // The launch: steps 1 to 3, in one script in the machine
  // ---------------------------------------------------------------------------

  /** The attach cgroup's names for a session under each manager ("Lifecycle", 1). */
  def holdUnit(session: String): String = s"ko-agent-bpf-hold-$session"
  def slice(session: String): String = s"ko-agent-bpf-$session.slice"
  def cgroupfsParent(uid: String, session: String): String =
    s"/user.slice/user-$uid.slice/user@$uid.service/app.slice/ko-agent-bpf-$session"

  /** `--cgroup-parent`'s value: the slice's name under systemd, the absolute path under cgroupfs. */
  def cgroupParent(facts: Facts, session: String): String =
    if facts.manager == "systemd" then slice(session) else cgroupfsParent(facts.uid, session)

  /** The policy's flags: `short-names` on Windows, where the share is NTFS and a generated short name
    * such as `VSCODE~1` is a second name of a guarded entry ("The policy"); `unix-socket` when set. */
  def policyFlags(settings: WorkspaceSettings, os: Os): String =
    val names = Vector(Option.when(os == Os.Windows)("short-names"), Option.when(settings.unixSocket)("unix-socket"))
      .flatten
    if names.isEmpty then "" else s"--flags ${names.mkString(",")}"

  val StepMarker = "step="
  val IdentMarker = "ident "

  /**
   * Steps 1 to 3 of "Lifecycle" for one session, and the readings the labels need. Fixed text
   * except the names (podman-safe by construction), with the backing path, the fixture root, the
   * rule text and the other sessions' paths travelling base64-encoded. Each step prints a
   * `step=<name>` line before it runs, so a failure names the step reached; the proof's mismatches
   * end the script with status 4 after `rm` of the fixture's stamp, so the next launch lays the
   * fixture out again ("Lifecycle", 3). The caller holds the launch lock across this script and its
   * `podman create`: the reconcile of another launcher, under the same lock, would otherwise take
   * the session's record without its container for an orphan's ("Lifecycle", 7). The file rules the
   * guard resolved follow FileRules.ResolvedMarker; the identities of `backing`, the gitdir bind and
   * the other sessions' recorded paths follow IdentMarker, `stat -c %d:%i` or `gone`. Once the proof
   * passed, PlacementWatcher waits in the background for the session's container, whose name is
   * `session`, and reports at `placement` (placementVerdict).
   */
  def launchScript(
    session: String,
    settings: WorkspaceSettings,
    facts: Facts,
    backing: String,
    fixture: String,
    placement: String,
    fileRules: String,
    volume: String,
    gitdirSource: Option[String],
    otherPaths: Vector[String],
    fsSourceId: String,
    bpfSourceId: String,
    os: Os,
  ): String =
    val noRoot = settings.readOnly
    val hookList = hooks(settings.unixSocket).mkString(" ")
    val flags = policyFlags(settings, os)
    val noRootFlag = if noRoot then "--no-root" else ""
    val proofFlags = Vector(Option.when(settings.unixSocket)("--unix-socket"), Option.when(noRoot)("--no-root"))
      .flatten.mkString(" ")
    val recordsOption = if noRoot then "" else "--records \"$sess/records.bin\""
    // A read-only session's proof expects every write refused, whatever the rules: an empty rule
    // file lays out the fixture's fixed entries alone.
    val proofRules = if noRoot then "\"$sess/proof-rules\"" else "\"$sess/records.bin\""
    val parent = cgroupParent(facts, session)
    val cgroupStep =
      if facts.manager == "systemd" then
        s"""systemctl --user stop ${holdUnit(session)} >/dev/null 2>&1 || true
           |systemctl --user reset-failed >/dev/null 2>&1 || true
           |systemd-run --user --unit=${holdUnit(session)} --slice=${slice(session)} \\
           |  /usr/bin/sleep infinity >/dev/null 2>&1
           |cg="$$(find /sys/fs/cgroup/user.slice -type d -name ${slice(session)} 2>/dev/null | head -1)"
           |[ -n "$$cg" ] || { echo "the attach slice ${slice(session)} was not created" >&2; exit 1; }""".stripMargin
      else
        s"""cg=/sys/fs/cgroup$parent
           |mkdir -p "$$cg\"""".stripMargin
    val proofStep =
      if facts.manager == "systemd" then
        s"""systemd-run --user --scope --slice=$parent -q "$$dir/fixture" run "$$fixture" $proofRules $proofFlags"""
      else
        s"""mkdir -p "$$cg/proof"
           |systemd-run --user --scope -q "$$dir/fixture" join "$$cg/proof" \\
           |  "$$dir/fixture" run "$$fixture" $proofRules $proofFlags
           |rmdir "$$cg/proof" 2>/dev/null || true""".stripMargin
    val identities = (Vector(backing) ++ gitdirSource ++ otherPaths).map(identLine)
    withScriptPath(
      s"""set -eu
         |dir="$$HOME/$InstallDir"
         |sess="$$dir/sessions/$session"
         |backing="$$(${printingCommand(backing)})"
         |fixture="$$(${printingCommand(fixture)})"
         |mkdir -p "$$sess" "$$fixture"
         |echo "${StepMarker}checks"
         |case "$$("$$HOME/$KoAgentFsBinary" --version 2>/dev/null || true)" in
         |  *" source $fsSourceId") ;;
         |  *) echo "the installed ko-agent-fs is not this launcher's build; run --build" >&2; exit 1 ;;
         |esac
         |[ "$$(cat "$$dir/source-id" 2>/dev/null || true)" = "$bpfSourceId" ] \\
         |  || { echo "the installed BPF backend is not this launcher's build; run --build" >&2; exit 1; }
         |podman volume exists $volume >/dev/null 2>&1 || podman volume create $volume >/dev/null
         |volmp="$$(podman volume inspect --format '{{.Mountpoint}}' $volume)"
         |echo "${StepMarker}records"
         |${printingCommand(fileRules)} > "$$sess/rules"
         |${if noRoot then ": > \"$sess/resolved\"; : > \"$sess/proof-rules\""
         else "\"$HOME/" + KoAgentFsBinary + "\" --source \"$backing\" --resolve --file-rules \"$sess/rules\" " +
           "--bpf-records \"$sess/records.bin\" > \"$sess/resolved\""}
         |echo "${StepMarker}fixture"
         |stamp="$$({ echo $bpfSourceId; cat "$$sess/rules" $proofRules 2>/dev/null; } | sha256sum | cut -d' ' -f1)"
         |if [ "$$(cat "$$fixture/.laid" 2>/dev/null || true)" != "$$stamp" ]; then
         |  find "$$fixture" -mindepth 1 -delete
         |  "$$dir/fixture" make "$$fixture" $proofRules >/dev/null
         |  printf %s "$$stamp" > "$$fixture/.laid"
         |fi
         |echo "${StepMarker}cgroup"
         |$cgroupStep
         |echo "cgroup=$$cg cgroup_id=$$(stat -c %i "$$cg")" > "$$sess/cgroup"
         |echo "cgroup path=$$cg id=$$(stat -c %i "$$cg") parent=$parent"
         |echo "${StepMarker}attach"
         |pins=${pinDir(session)}
         |spare=""
         |if sudo -n "$$dir/readback" check-spare $SparePinDir --tags "$$dir/tags.txt" ${hooks(true).mkString(" ")} \\
         |    2>/dev/null | grep -q ' ok=1'; then spare="--spare $SparePinDir"
         |else sudo -n "$$dir/controller" unpin $SparePinDir >/dev/null 2>&1 || true; fi
         |sudo -n "$$dir/controller" attach "$$cg" "$$pins" $recordsOption --workspace "$$backing" \\
         |  --fixture "$$fixture" --volume "$$volmp" --bind-source "$$backing" $flags $noRootFlag $$spare $hookList
         |echo "${StepMarker}verify"
         |sudo -n "$$dir/readback" verify "$$cg" --tags "$$dir/tags.txt" $recordsOption --workspace "$$backing" \\
         |  --fixture "$$fixture" --volume "$$volmp" $flags $noRootFlag $hookList
         |echo "${StepMarker}proof"
         |proof="$$($proofStep)" || true
         |printf '%s\\n' "$$proof" | grep -e mismatch -e '^fixture ops' || true
         |case "$$proof" in
         |  *" mismatches=0 "*) ;;
         |  *) rm -f "$$fixture/.laid"; echo "the proof fixture found a mismatch or did not run" >&2; exit 4 ;;
         |esac
         |echo "${StepMarker}placement"
         |placement="$$(${printingCommand(placement)})"
         |mkdir -p "$$(dirname "$$placement")"
         |rm -f "$$placement"
         |${printingCommand(PlacementWatcher)} > "$$sess/watch-placement"
         |(nohup sh "$$sess/watch-placement" "$$placement" $session >/dev/null 2>&1 &)
         |if [ -n "$$spare" ]; then
         |  (nohup sudo -n "$$dir/controller" prepare-spare $SparePinDir >/dev/null 2>&1 &)
         |fi
         |echo "${StepMarker}done"
         |${identities.mkString("\n")}
         |echo "${FileRules.ResolvedMarker}"
         |cat "$$sess/resolved\"""".stripMargin,
    )

  /** How long PlacementWatcher waits for the container to be initialized, in its 0.2 s polls. */
  val PlacementPolls = 300

  /**
   * Step 4's check of "Lifecycle": once the launcher's `podman init` has made the container, the
   * cgroup of the process `State.Pid` names, `crun` waiting to start the command, as `/proc` gives
   * it. `podman inspect`'s `State.CgroupPath` stays empty until the container runs (podman's
   * `cGroupPath`), and `HostConfig.CgroupParent` is the request, not the placement. Reported, not
   * judged: placementVerdict decides on the host. Written aside, then renamed, so the launcher never
   * reads half a report. Arguments: the report's path and the container's name.
   */
  val PlacementWatcher: String =
    s"""out=$$1 name=$$2 i=0 state=
       |while [ "$$i" -lt $PlacementPolls ]; do
       |  state=$$(podman inspect --format '{{.State.Status}} {{.State.Pid}}' "$$name" 2>/dev/null || true)
       |  case $$state in "initialized "*) break ;; esac
       |  i=$$((i + 1))
       |  sleep 0.2
       |done
       |case $$state in
       |  "initialized "*) pid=$${state#* }
       |    line=$$(sed -n 's/^0:://p' "/proc/$$pid/cgroup" 2>/dev/null || true)
       |    report="status=initialized pid=$$pid cgroup=$$line" ;;
       |  *) report="status=timeout" ;;
       |esac
       |printf '%s waited_ms=%s\n' "$$report" "$$((i * 200))" > "$$out.tmp"
       |mv "$$out.tmp" "$$out"
       |""".stripMargin

  /** Where PlacementWatcher reports for a session, under the state root the machine shares. */
  def placementFile(stateRoot: Path, session: String): Path =
    stateRoot.resolve("bpf").resolve("placement").resolve(session)

  /**
   * PlacementWatcher's report once it is there, removed as it is read; None after `seconds`, which
   * outlast the watcher's own wait.
   */
  def awaitPlacement(file: Path, seconds: Int = PlacementPolls / 5 + 10): Option[String] =
    val deadline = System.nanoTime() + seconds * 1_000_000_000L
    while !Files.exists(file) && System.nanoTime() < deadline do Thread.sleep(50)
    Option.when(Files.exists(file)):
      val report = Files.readString(file)
      Files.deleteIfExists(file)
      report

  /**
   * The container's placement out of PlacementWatcher's report: Right when the cgroup lies below the
   * attach cgroup, Left naming what was found otherwise, a missing or unreadable cgroup included.
   */
  def placementVerdict(attachCgroup: String, report: String): Either[String, String] =
    val reported = (key: String) => field(key, report.linesIterator.nextOption().getOrElse(""))
    reported("status") match
      case Some("initialized") =>
        reported("cgroup").filter(_.nonEmpty).map(path => s"/sys/fs/cgroup$path") match
          case Some(found) if found.startsWith(attachCgroup.stripSuffix("/") + "/") => Right(found)
          case Some(found) => Left(s"the container lies in $found, not below the attach cgroup $attachCgroup")
          case None => Left(s"the machine could not read the cgroup of the container's process (${report.trim})")
      case Some("timeout") => Left("the container was not initialized within the machine's wait")
      case _ => Left(s"the machine's placement report is unreadable: ${report.trim}")

  /**
   * Step 4's decision of "Lifecycle": the launcher's own `podman init` succeeded, then the watcher's
   * report places the container below the attach cgroup. The report is not awaited after a failed
   * init.
   */
  def confirmPlacement(initialized: Run, report: => Option[String], attachCgroup: String): Either[String, String] =
    if !initialized.ok then Left(s"could not initialize the sandbox container: ${initialized.err.trim}")
    else report.toRight("the machine reported no placement").flatMap(placementVerdict(attachCgroup, _))

  /** What the launch script established. */
  final case class Launched(
    cgroup: String,
    cgroupId: String,
    parent: String,
    identities: Map[String, String],
    resolved: FileRules.Resolved,
    spare: Boolean,
    attachLine: String,
    verifyLine: String,
    proofLine: String,
  )

  /** A `key=value` field of one line. */
  def field(key: String, line: String): Option[String] =
    s"(?:^| )$key=(\\S*)".r.findFirstMatchIn(line).map(_.group(1))

  /** The step the script reached, out of its output: the last `step=` line. */
  def stepReached(output: String): String =
    output.linesIterator.filter(_.startsWith(StepMarker)).map(_.stripPrefix(StepMarker)).toVector.lastOption
      .getOrElse("start")

  def parseLaunched(output: String): Either[String, Launched] =
    val lines = output.linesIterator.toVector
    val cgroupLine = lines.find(_.startsWith("cgroup path=")).toRight("the launch script printed no cgroup line")
    val identities = lines.filter(_.startsWith(IdentMarker)).flatMap { line =>
      line.stripPrefix(IdentMarker).split(" ", 2) match
        case Array(identity, encoded) =>
          try Some(String(Base64.getDecoder.decode(encoded.trim), StandardCharsets.UTF_8) -> identity)
          catch case _: IllegalArgumentException => None
        case _ => None
    }.toMap
    val marker = lines.indexOf(FileRules.ResolvedMarker)
    for
      cgroup <- cgroupLine
      resolved <-
        if marker < 0 then Left("the launch script printed no resolved file rules")
        else FileRules.parseResolved(lines.drop(marker + 1).mkString("\n"))
      attach <- lines.find(_.startsWith("attach ")).toRight("the controller printed no attach line")
    yield Launched(
      field("path", cgroup).getOrElse(""),
      field("id", cgroup).getOrElse(""),
      field("parent", cgroup).getOrElse(""),
      identities,
      resolved,
      field("spare", attach).contains("1"),
      attach,
      lines.find(_.startsWith("verify ")).getOrElse(""),
      lines.find(_.startsWith("fixture ops")).getOrElse(""),
    )

  /** The launch line. A check that fails ends the launch, so what each step cost goes to the run's
    * log (stepsLogLine) rather than the terminal. */
  val LaunchLine = "ko-agent-bpf backend: the policy attached and tested"

  /** What each of steps 1 to 3 cost, for the run's log. */
  def stepsLogLine(launched: Launched): String =
    val hooksAttached = field("hooks", launched.attachLine).getOrElse("?")
    val load = field("load_ms", launched.attachLine).getOrElse("?")
    val verify = field("ms", launched.verifyLine).getOrElse("?")
    val proof = field("ms", launched.proofLine).getOrElse("?")
    val how = if launched.spare then "the program set verified ahead" else "programs verified now"
    s"attached $hooksAttached hooks in $load ms from $how; read back in $verify ms; tested in $proof ms"

  /** The run's log of the backend's steps, which `log dir` names; a failed write costs the line alone. */
  def appendLog(file: Path, line: String): Unit =
    try
      Files.writeString(
        file, s"$line\n", StandardCharsets.UTF_8,
        java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND,
      )
    catch case _: java.io.IOException => ()

  // ---------------------------------------------------------------------------
  // Teardown and the reconcile
  // ---------------------------------------------------------------------------

  /**
   * Step 6 of "Lifecycle" for one session: the pins, the cgroup and the session's record, once
   * podman's own answer says the container is gone (exit 1 of `container exists`, as the filter's
   * reap prunes a marker). A container still there, or a podman that cannot answer, keeps all three:
   * unpinning would detach the policy from a live session, and stopping the slice would end it;
   * the reconcile at the next launch removes an orphan ("Lifecycle", 7). Each step after the
   * check on its own, so one that fails costs none of the others.
   */
  def teardownScript(session: String, manager: String): String =
    val cgroup =
      if manager == "systemd" then
        s"systemctl --user stop ${holdUnit(session)} ${slice(session)} >/dev/null 2>&1 || true"
      else
        s"""cg="$$(sed -n 's/^cgroup=\\([^ ]*\\).*/\\1/p' "$$HOME/$InstallDir/sessions/$session/cgroup" 2>/dev/null)"
           |[ -n "$$cg" ] && { rmdir "$$cg/proof" 2>/dev/null; rmdir "$$cg" 2>/dev/null; } || true""".stripMargin
    withScriptPath(
      s"""dir="$$HOME/$InstallDir"
         |gone=0
         |podman container exists $session >/dev/null 2>&1 || gone=$$?
         |if [ "$$gone" -ne 1 ]; then
         |  echo "session $session is not gone (podman container exists: $$gone); its policy, pins and record stay"
         |  exit 0
         |fi
         |sudo -n "$$dir/controller" unpin ${pinDir(session)} >/dev/null 2>&1 || true
         |$cgroup
         |rm -rf "$$dir/sessions/$session\"""".stripMargin,
    )

  /**
   * Step 7 of "Lifecycle": the recorded sessions beside podman's containers, then the controller
   * decides, under the launch lock the caller holds. A session's record names its cgroup and the
   * cgroup's identity; a container's label names the cgroup it was created under. A listing or a
   * label that cannot be read tells the controller so, which then removes nothing. Under systemd a
   * session without a container has its hold unit stopped first, so that the hold does not count
   * as populated, and the slices the controller names are stopped after it. The spare is kept
   * while its tags are the installed object's, unpinned otherwise, and prepared in the background
   * where there is none; a preparer's staging directory, `spare-<pid>`, is unpinned once that
   * process is gone, as after a failed pin or a killed preparation. Every test of the pin root runs
   * as root: the controller makes it 0700.
   */
  def reconcileScript(manager: String): String =
    val release =
      if manager == "systemd" then "systemctl --user stop ko-agent-bpf-hold-$name >/dev/null 2>&1 || true" else ":"
    withScriptPath(
      s"""set -u
         |dir="$$HOME/$InstallDir"
         |[ -d "$$dir/sessions" ] || mkdir -p "$$dir/sessions"
         |listing_failed=no
         |labels="$$(ids=$$(podman ps -aq --filter name=ko-agent-sandbox-run- 2>/dev/null) || exit 9
         |  for id in $$ids; do
         |    podman inspect --format '{{.Name}} {{index .Config.Labels "$CgroupLabel"}}' "$$id" || exit 9
         |  done
         |  echo LISTING_OK)" || listing_failed=yes
         |case "$$labels" in *LISTING_OK*) ;; *) listing_failed=yes ;; esac
         |args="--manager $manager"
         |[ "$$listing_failed" = yes ] && args="$$args --listing-failed"
         |for record in "$$dir/sessions"/*/cgroup; do
         |  [ -f "$$record" ] || continue
         |  name="$$(basename "$$(dirname "$$record")")"
         |  cg="$$(sed -n 's/^cgroup=\\([^ ]*\\).*/\\1/p' "$$record")"
         |  id="$$(sed -n 's/.*cgroup_id=\\([^ ]*\\).*/\\1/p' "$$record")"
         |  named="$$(printf '%s\\n' "$$labels" \\
         |    | awk -v n="$$name" -v m="/$$name" '$$1 == n || $$1 == m { print $$2 }')"
         |  if [ -z "$$named" ]; then
         |    [ "$$listing_failed" = no ] && $release
         |  elif [ "$$named" = "$$cg" ]; then args="$$args --named $$name"
         |  else args="$$args --hold $$name"; fi
         |  args="$$args --session $$name $$cg $$id"
         |done
         |sleep 1
         |out="$$(sudo -n "$$dir/controller" reconcile $PinRoot $$args 2>&1)" || true
         |printf '%s\\n' "$$out"
         |printf '%s\\n' "$$out" | sed -n 's/.*cgroup=stop-slice slice=\\(.*\\)/\\1/p' | while read -r s; do
         |  systemctl --user stop "$$s" >/dev/null 2>&1 || true
         |done
         |printf '%s\\n' "$$out" | sed -n 's/^reconcile session=\\([^ ]*\\) action=removed.*/\\1/p' \\
         |    | while read -r n; do
         |  rm -rf "$$dir/sessions/$$n"
         |done
         |if sudo -n test -d $SparePinDir; then
         |  sudo -n "$$dir/readback" check-spare $SparePinDir --tags "$$dir/tags.txt" ${hooks(true).mkString(" ")} \\
         |    2>/dev/null | grep -q ' ok=1' \\
         |    || { sudo -n "$$dir/controller" unpin $SparePinDir >/dev/null 2>&1; echo "spare stale=1"; }
         |fi
         |sudo -n sh -c 'for d in $SparePinDir-*; do [ -d "$$d" ] || continue; \\
         |  kill -0 "$${d##*-}" 2>/dev/null && continue; \\
         |  "$$1" unpin "$$d" >/dev/null 2>&1; echo "spare abandoned=$$d"; done' sh "$$dir/controller"
         |sudo -n test -d $SparePinDir \\
         |  || (nohup sudo -n "$$dir/controller" prepare-spare $SparePinDir >/dev/null 2>&1 &)
         |exit 0""".stripMargin,
    )

  /** The reconcile's summary for the launch lines, or None when nothing was removed or refused. */
  def reconcileNote(output: String): Option[String] =
    output.linesIterator.find(_.startsWith("reconcile sessions=")).flatMap: line =>
      val removed = field("removed", line).getOrElse("0")
      val refused = field("refused", line).getOrElse("0")
      Option.when(removed != "0" || refused != "0")(
        s"ko-agent-bpf reconcile: $removed orphaned session(s) removed, $refused refused" +
          (if refused != "0" then "; the lines above name each" else ""),
      )

  /** The identities of paths in the machine, for a filter-backed session's labels (identScript's
    * output parses as the launch script's IdentMarker lines). */
  def identScript(paths: Vector[String]): String =
    withScriptPath(paths.map(identLine).mkString("set -u\n", "\n", ""))

  /** One path's identity line: `stat`'s device and inode, or `gone`, then the path encoded. */
  private def identLine(path: String): String =
    s"""p="$$(${printingCommand(path)})"; echo "$IdentMarker$$(stat -c %d:%i "$$p" 2>/dev/null || echo gone) """ +
      s"""$$(printf %s "$$p" | base64 | tr -d '\\n')\""""

  def parseIdentities(output: String): Map[String, String] =
    output.linesIterator.filter(_.startsWith(IdentMarker)).flatMap { line =>
      line.stripPrefix(IdentMarker).split(" ", 2) match
        case Array(identity, encoded) =>
          try Some(String(Base64.getDecoder.decode(encoded.trim), StandardCharsets.UTF_8) -> identity)
          catch case _: IllegalArgumentException => None
        case _ => None
    }.toMap

  /** The lock every launch holds from its listing of the live sessions until its container exists. */
  def launchLockFile(stateRoot: Path): Path = stateRoot.resolve("bpf").resolve("launch.lock")

  /** The proof fixture's root for a workspace, under the launcher's state root, which the machine
    * shares ("Lifecycle", 3). */
  def fixtureRoot(stateRoot: Path, workspaceId: String): Path =
    stateRoot.resolve("bpf").resolve("proof").resolve(workspaceId)

  /** The note after a `podman create` that failed under the backend on Windows: the placement below
    * the attach cgroup needs a WSL setting ("Environment evidence"). */
  def createFailureNote(os: Os, error: String): Option[String] =
    Option.when(os == Os.Windows && (error.contains("controller pids") || error.contains("cgroup")))(
      "The podman machine on Windows places a container below the attach cgroup only with " +
        "`isolateDistroCgroup=false` under `[wsl2]` in %UserProfile%\\.wslconfig, after `wsl --shutdown`.",
    )
