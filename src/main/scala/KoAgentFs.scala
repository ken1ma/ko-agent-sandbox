// Everything the launcher does about ko-agent-fs, the workspace FUSE filter: digesting the source it
// bundles, building and installing the binary, proving the installed one is that source's build, and
// the per-project mount lifecycle every session that mounts it runs through.
//
// It is a separate program with its own source tree, docs, tests and version contract
// (fuse/ko-agent-fs/), and it reaches the launch through workspaceGuard, prepareKoAgentFs and
// mountKoAgentFs. That is why it is a file rather than a section.

package agentsandbox.launcher

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, Paths}
import java.security.MessageDigest
import scala.jdk.CollectionConverters.*

import HostCommands.*

object KoAgentFs:

  /**
   * The one source-identity digest, for the filter binary and the image bundle labels alike:
   * SHA-256 over (path, content) pairs in path order, each entry framed by its path, a NUL and its
   * big-endian length — the sort makes bundling order irrelevant, the length keeps file boundaries
   * unambiguous, and the path makes a rename a new identity. The algorithm lives only here,
   * deliberately: a build is told the answer and repeats it, so there is no second implementation
   * to drift from this one.
   */
  def bundleSourceId(entries: Seq[(String, Array[Byte])]): String =
    val digest = MessageDigest.getInstance("SHA-256")
    entries.sortBy(_._1).foreach: (path, content) =>
      digest.update(path.getBytes(StandardCharsets.UTF_8))
      digest.update(0.toByte)
      digest.update(java.nio.ByteBuffer.allocate(8).putLong(content.length.toLong).array())
      digest.update(content)
    digest.digest().map(b => f"$b%02x").mkString

  /**
   * Digest one directory of the unpacked context — the literal build input,
   * so the id describes exactly what podman build is about to see.
   */
  def contextSourceId(context: Path, dir: String): String =
    val root = context.resolve(dir)
    val entries = Files
      .walk(root)
      .iterator()
      .asScala
      .filter(Files.isRegularFile(_))
      .map(file => (root.relativize(file).toString.replace('\\', '/'), Files.readAllBytes(file)))
      .toVector
    bundleSourceId(entries)

  /**
   * The bundled filter source's identity, passed to the image build as KO_AGENT_FS_SOURCE_ID and
   * reported back by the installed binary's `--version`, so a binary that is not the one this
   * launcher would build is detected rather than trusted (fuse/ko-agent-fs/doc/architecture.md,
   * "Build and install").
   *
   * Every bundled file counts, tests included: the digest names the source a binary was built
   * from, which is also the source its suites covered (the developer's run and `--self-test`),
   * and picking out which of the bundled files "really" affect it is a judgement that can rot.
   * The exclusions are drawn where they cannot rot into a second opinion: ko-agent-fs/doc and
   * ko-agent-fs/probe are not bundled at all (build.sbt), so they are neither distributed nor
   * digested, and editing a design document or a platform probe does not invalidate every
   * installed binary.
   */
  def koAgentFsSourceId(context: Path): String = contextSourceId(context, "ko-agent-fs")

  /**
   * Where the filter binary lives, relative to the home of the user the
   * daemon runs as — the VM user's home on podman machine, the host user's
   * on native Linux. Relative on purpose: `podman machine ssh` lands in the
   * VM user's home whoever that is (core on macOS, the WSL user on
   * Windows), so no per-platform absolute path needs to be known here.
   */
  val KoAgentFsInstallDir = ".local/share/ko-agent-sandbox"
  val KoAgentFsBinary = s"$KoAgentFsInstallDir/ko-agent-fs"

  /**
   * Steps 3–4 of the filter pipeline (fuse/ko-agent-fs/doc/architecture.md,
   * "Build and install"): take /ko-agent-fs out of the image's scratch stage
   * and put it where the daemon must run. On podman machine both the image
   * storage and the daemon live inside the VM, so the whole extraction runs
   * there through `machine ssh` — a host-side `podman cp` would land the
   * binary on the wrong side of the boundary. The ssh script is fixed text;
   * nothing user-controlled is interpolated into it. `--replace` clears a
   * leftover extract container from a crashed earlier run.
   */
  def koAgentFsInstallCommands(podman: String, os: Os, home: String): Vector[Vector[String]] =
    os match
      case Os.Linux =>
        Vector(
          Vector(podman, "create", "--replace", "--name", "ko-agent-fs-extract", "ko-agent-fs:latest"),
          Vector(podman, "cp", "ko-agent-fs-extract:/ko-agent-fs", s"$home/$KoAgentFsBinary"),
          Vector(podman, "rm", "ko-agent-fs-extract"),
        )
      case Os.Mac | Os.Windows =>
        val script =
          s"""set -eu
             |mkdir -p $KoAgentFsInstallDir
             |podman create --replace --name ko-agent-fs-extract ko-agent-fs:latest >/dev/null
             |podman cp ko-agent-fs-extract:/ko-agent-fs $KoAgentFsBinary
             |podman rm ko-agent-fs-extract >/dev/null""".stripMargin
        Vector(Vector(podman, "machine", "ssh", script))

  /**
   * The filter mounts with `allow_other`, which fusermount3 refuses for an
   * unprivileged user until `user_allow_other` is set in the machine's
   * /etc/fuse.conf. That file is the user's configuration, VM or not, so it
   * is never changed silently: `--build` detects the missing line, shows
   * the change *as a diff of the actual file* plus the exact script, and
   * asks; only a "y" runs it, and every other path — declined, or no
   * console to ask on — fails with the same script for the user to run
   * themselves. One-time until the machine is recreated. A native Linux
   * *host* is never even offered: there the self-test's message is the
   * user's remedy.
   *
   * The script saves the original beside the file first. The backup name
   * is the tool's name, not `.dist`: `.dist` would claim
   * as-distributed pristineness nobody verified, while this says who saved
   * it and when it is safe to delete. Saved only if no backup exists yet,
   * so a re-run cannot overwrite the true original with a modified copy.
   */
  val KoAgentFsFuseConfBackup = "/etc/fuse.conf.ko-agent-sandbox.orig"

  val KoAgentFsFuseConfEnable: String =
    s"""test ! -f /etc/fuse.conf || test -e $KoAgentFsFuseConfBackup ||
       |  sudo cp /etc/fuse.conf $KoAgentFsFuseConfBackup
       |sudo sh -c 'echo user_allow_other >> /etc/fuse.conf'""".stripMargin

  def koAgentFsFuseConfCheckCommand(podman: String): Vector[String] =
    Vector(podman, "machine", "ssh", "grep -qx user_allow_other /etc/fuse.conf")

  def koAgentFsFuseConfEnableCommand(podman: String): Vector[String] =
    Vector(podman, "machine", "ssh", KoAgentFsFuseConfEnable)

  /**
   * The change as a diff over the file's actual content: every current line
   * as context, the one addition marked `+`. Consent is then over exact
   * bytes, not a description of them.
   */
  def fuseConfDiff(current: String): String =
    val context =
      if current.isEmpty then Vector("  (/etc/fuse.conf does not exist yet; it will be created)")
      else current.linesIterator.map(line => s"  $line").toVector
    (context :+ "+ user_allow_other").mkString("\n")

  def ensureUserAllowOther(podman: String): Unit =
    if run(koAgentFsFuseConfCheckCommand(podman)*).ok then return
    val current = run(podman, "machine", "ssh", "cat /etc/fuse.conf 2>/dev/null || true").text
    System.err.println(
      s"""The workspace FUSE filter mounts with allow_other, so the sandbox (a different uid) can use
         |it, and fusermount3 refuses that until user_allow_other is set in the podman machine's
         |/etc/fuse.conf. Your machine's configuration is not changed without asking. The change:
         |
         |${fuseConfDiff(current)}
         |
         |applied inside the machine by (the original is saved to $KoAgentFsFuseConfBackup first):
         |
         |${KoAgentFsFuseConfEnable.linesIterator.map(line => s"  $line").mkString("\n")}
         |
         |It persists until the machine is recreated (podman machine rm + init); to undo, restore
         |the saved original.""".stripMargin
    )
    val console = System.console()
    if console == null then
      fail(
        s"error: no console to ask on; run the script above via `podman machine ssh` yourself, " +
          "then re-run --build",
      )
    console.printf("Apply it now? [y/N] ")
    if !consented(Option(console.readLine())) then
      fail("error: not applied; run the script above via `podman machine ssh` yourself, then re-run --build")
    val enable = run(koAgentFsFuseConfEnableCommand(podman)*)
    if !enable.ok then fail(s"error: enabling user_allow_other failed: ${enable.err}", enable.exit)
    if !run(koAgentFsFuseConfCheckCommand(podman)*).ok then
      fail("error: user_allow_other still not set after enabling; check the machine's /etc/fuse.conf")

  private def koAgentFsInvocation(podman: String, os: Os, home: String, flag: String): Vector[String] =
    os match
      case Os.Linux => Vector(s"$home/$KoAgentFsBinary", flag)
      case Os.Mac | Os.Windows => Vector(podman, "machine", "ssh", s"./$KoAgentFsBinary $flag")

  def koAgentFsVersionCommand(podman: String, os: Os, home: String): Vector[String] =
    koAgentFsInvocation(podman, os, home, "--version")

  def koAgentFsSelfTestCommand(podman: String, os: Os, home: String): Vector[String] =
    koAgentFsInvocation(podman, os, home, "--self-test")

  /** "ko-agent-fs <version> source <id>" → the id; None for anything else. */
  def koAgentFsReportedSourceId(versionLine: String): Option[String] =
    versionLine.trim.split("\\s+") match
      case Array("ko-agent-fs", _, "source", id) => Some(id)
      case _ => None

  /**
   * Step 5: install the freshly built filter and prove the installed binary
   * is the one this launcher's bundled source builds — its --version must
   * echo the digest that was passed to the image build. A mismatch after a
   * fresh install means the image tagged ko-agent-fs:latest is not the one
   * --build just produced, and the launch pipeline must not trust it.
   */
  def installKoAgentFs(podman: String, os: Os, expectedId: String): Unit =
    val home = sys.props("user.home")
    if os == Os.Linux then Files.createDirectories(Paths.get(home, KoAgentFsInstallDir))
    else ensureUserAllowOther(podman)
    koAgentFsInstallCommands(podman, os, home).foreach: command =>
      echoCommand(command)
      val result = run(command*)
      if !result.ok then
        fail(s"error: ko-agent-fs install failed: ${command.mkString(" ")}\n${result.err}", result.exit)
    val version = run(koAgentFsVersionCommand(podman, os, home)*)
    if !version.ok then
      fail(s"error: the installed ko-agent-fs does not run: ${version.err}", version.exit)
    koAgentFsReportedSourceId(version.text) match
      case Some(id) if id == expectedId =>
        System.err.println(s"ko-agent-fs installed: ${version.text}")
      case Some(id) =>
        fail(
          s"""error: the installed ko-agent-fs reports source $id, expected $expectedId
             |
             |The image tagged ko-agent-fs:latest is not the one this --build produced.""".stripMargin
        )
      case None =>
        fail(s"error: unrecognized ko-agent-fs --version output: ${version.text}")
    // The whole stack, proven where it will run: an unprivileged mount over a scratch tree, with
    // the policy shown to refuse. Its failure text names the environment fix.
    val selfTest = run(koAgentFsSelfTestCommand(podman, os, home)*)
    if !selfTest.ok then
      fail(s"error: ko-agent-fs self-test failed after install:\n${selfTest.err}", selfTest.exit)
    System.err.println(selfTest.text)

  // ---------------------------------------------------------------------------
  // The workspace FUSE filter's mount lifecycle (every live session's under guard=fuse)
  //
  // One daemon per project, alive while the project has sessions: started on
  // demand, reused by concurrent sessions, restarted when the
  // mountpoint is stale or the installed binary is not the one this launcher's
  // source builds, and unmounted when the project's last session ends. The
  // reference count is the session markers under <mountdir>/sessions/, written
  // by the mount script *before* it touches the mount, once the session's
  // container exists, and collected by the reaper (or the resident path) after
  // `podman wait`. The two orderings and the project lock shared by the scripts
  // keep a concurrent reap off a live session; koAgentFsReapScript has what each
  // covers. The resets remain the sweep for whatever a crashed launcher leaves.
  // A daemon dying mid-session leaves
  // the container's bind on a dead FUSE superblock — every access fails
  // ENOTCONN, never a fallthrough to the unfiltered tree.
  // ---------------------------------------------------------------------------

  /**
   * Which mechanism guards the workspace's git control state: `fuse` — the default, what an
   * unset variable means — mounts /workspace through the FUSE filter; `none` binds it directly
   * with only the mount pins, the weaker boundary. The variable names the effect and the value
   * names the mechanism, so a better guard someday is a new value here, not a new variable.
   * This variable can weaken the boundary, so "security
   * configuration must fail closed: unknown, malformed, or ambiguously interpreted policy must
   * not silently weaken the effective boundary" (design.md's principles) applies to it
   * exactly: any other value is a refused launch, never a guard quietly switched off
   * (HostCommands.closedChoice).
   */
  val WorkspaceGuardVariable = "KO_AGENT_SANDBOX_WORKSPACE_GUARD"
  val RawWorkspaceBoundary =
    "workspace-root .git/config and .git/hooks are pinned when .git is a directory; the whole " +
      ".git file is pinned in a linked worktree; an empty .git mount is pinned when no repository " +
      "exists; the workspace-root .ko-agent-sandbox is also pinned"

  def workspaceGuard(value: Option[String]): Either[String, String] =
    closedChoice(
      WorkspaceGuardVariable,
      value,
      Vector("fuse", "none"),
      "fuse",
      "Unset it (or set it to fuse) to keep the workspace filter; set it to none\nto bind " +
        s"/workspace directly; $RawWorkspaceBoundary.",
    )

  /**
   * The digest of one bundle directory as this jar bundles it — the same
   * bytes unpackBuildContext writes and contextSourceId hashes, read
   * straight from the jar so no unpack is needed. What the filter binary's
   * `--version` must report, and what --build stamps into the sandbox and
   * proxy images as their bundle label (AgentSandboxLauncher.bundleMismatch).
   */
  def bundledSourceId(dir: String): String =
    def resource(name: String): Array[Byte] =
      val stream = getClass.getResourceAsStream(s"/sandbox-build/$name")
      if stream == null then fail(s"error: the launcher jar has no bundled entry '$name'")
      try stream.readAllBytes()
      finally stream.close()
    val entries =
      String(resource("INDEX"), StandardCharsets.UTF_8).linesIterator
        .filter(_.startsWith(s"$dir/"))
        .map(entry => entry.stripPrefix(s"$dir/") -> resource(entry))
        .toVector
    bundleSourceId(entries)

  def bundledKoAgentFsSourceId(): String = bundledSourceId("ko-agent-fs")

  def koAgentFsMountDir(projectId: String): String = s"$KoAgentFsInstallDir/mounts/$projectId"

  /**
   * Start (or reuse) the project's filter daemon and leave the mountpoint
   * serving. Fixed text except three safe-charset values: the project id
   * (podman-safe by construction), the source id (hex), and the backing
   * path — which is user-controlled and therefore travels base64-encoded,
   * never spliced into shell text.
   *
   * Each step fails closed. The project lock is `lock` in koAgentFsReapScript. A non-empty
   * mountpoint is refused because a vanished mount must expose nothing. The `fuse*` match on
   * statfs is because fuse/fuseblk naming varies by stat version.
   */
  def koAgentFsMountScript(
    backing: String,
    projectId: String,
    sourceId: String,
    sandboxContainer: String,
  ): String =
    val encoded =
      java.util.Base64.getEncoder.encodeToString(backing.getBytes(StandardCharsets.UTF_8))
    withScriptPath(
      s"""set -eu
       |backing="$$(printf %s $encoded | base64 -d)"
       |dir="$$HOME/${koAgentFsMountDir(projectId)}"
       |mnt="$$dir/workspace"
       |mkdir -p "$$mnt" "$$dir/sessions"
       |: > "$$dir/sessions/$sandboxContainer"
       |exec 9>"$$dir/lock"
       |flock 9 2>/dev/null || true
       |if mountpoint -q "$$mnt"; then
       |  if [ "$$(cat "$$dir/source-id" 2>/dev/null || true)" = "$sourceId" ] \\
       |      && ls "$$mnt" >/dev/null 2>&1; then
       |    echo "reusing the existing mount"
       |    exit 0
       |  fi
       |  fusermount3 -uz "$$mnt"
       |fi
       |ls "$$mnt" >/dev/null 2>&1 || fusermount3 -uz "$$mnt" || true
       |if [ -n "$$(ls -A "$$mnt")" ]; then
       |  echo "mountpoint $$mnt is not empty; refusing" >&2
       |  exit 1
       |fi
       |# The binary prepareKoAgentFs verified can be replaced by a --build between that check and
       |# here — the start prompt sits between them. Checked again beside the start, under the
       |# image-build lock the launcher holds across this script and the installer holds while it
       |# replaces the binary (mountKoAgentFs), so the daemon started is the build source-id names.
       |case "$$("$$HOME/$KoAgentFsBinary" --version 2>/dev/null || true)" in
       |  *" source $sourceId") ;;
       |  *) echo "the installed ko-agent-fs is no longer this launcher's build; launch again" >&2; exit 1 ;;
       |esac
       |printf %s "$sourceId" > "$$dir/source-id"
       |mv -f "$$dir/daemon.log" "$$dir/daemon.log.1" 2>/dev/null || true
       |# 9>&- so the daemon does not inherit the project lock and hold it for the session's
       |# whole life, which would block every later reap forever.
       |nohup "$$HOME/$KoAgentFsBinary" --source "$$backing" --mount "$$mnt" --foreground \\
       |  9>&- >>"$$dir/daemon.log" 2>&1 &
       |i=0
       |while [ $$i -lt 100 ]; do
       |  case "$$(stat -f -c %T "$$mnt" 2>/dev/null || true)" in
       |    fuse*) echo "mounted"; exit 0 ;;
       |  esac
       |  i=$$((i+1))
       |  sleep 0.1
       |done
       |echo "the filter did not become a FUSE mount; daemon log:" >&2
       |cat "$$dir/daemon.log" >&2 || true
       |exit 1""".stripMargin
    )

  /**
   * The last-session teardown, run where the daemon lives after a sandbox
   * container exits. The session markers are the reference count: remove
   * this run's, prune the dead ones (a crashed launcher leaks its marker;
   * pruning self-heals it), and unmount only when none remain.
   *
   * Dead is container-gone, and nothing more: a session creates its container
   * before it mounts, so its marker is never there without a container podman
   * can name. A launcher that died between its `create` and `start` left the
   * container, which keeps the marker until the reaper's bounded wait removes
   * the stray (SandboxLifecycle.ReaperScript) or a reset does.
   *
   * The safeguards below keep a reap off a live session, and none is sufficient
   * alone. The container before the marker covers a launch still on its way to
   * starting. The marker is written before the mount, so a reap that starts
   * later must see it. And `lock` — held here across counting the markers and
   * unmounting, and by the mount script across its reuse decision — covers
   * what the ordering alone does not: a reap that counted zero markers, then
   * a launch that writes its marker and reuses the still-live mount, then the
   * unmount landing under it. Serialized, that launch either takes the lock
   * first and is counted, or finds the mount gone and starts a fresh daemon.
   * A machine without flock degrades to the orderings, which is why the marker
   * is written outside the lock and first.
   *
   * Which podman the script calls is the caller's to decide:
   * koAgentFsReapPodman.
   */
  def koAgentFsReapScript(podman: String, projectId: String, sandboxContainer: String): String =
    withScriptPath(
      s"""dir="$$HOME/${koAgentFsMountDir(projectId)}"
       |rm -f "$$dir/sessions/$sandboxContainer"
       |# The project lock (see above). A shell that cannot even open it exits here, which leaves
       |# the mount up — the same direction every other open edge in this script fails toward.
       |mkdir -p "$$dir" 2>/dev/null || true
       |exec 9>"$$dir/lock"
       |flock 9 2>/dev/null || true
       |for marker in "$$dir/sessions"/*; do
       |  [ -e "$$marker" ] || continue
       |  gone=0
       |  "$podman" container exists "$$(basename "$$marker")" >/dev/null 2>&1 || gone=$$?
       |  # Only podman's own "no such container" answer (exit 1) prunes. Anything else — a broken
       |  # podman is exit 125 — is unknown liveness, and pruning on unknown is how the last-session
       |  # unmount below lands under a live session; the marker leaks toward a later reap instead.
       |  [ "$$gone" -eq 1 ] && rm -f "$$marker"
       |done
       |if [ -z "$$(ls -A "$$dir/sessions" 2>/dev/null)" ]; then
       |  fusermount3 -uz "$$dir/workspace" 2>/dev/null || true
       |fi""".stripMargin
    )

  /**
   * The podman the reap script calls. Inside the VM the bare name is the only
   * right answer — it is the machine's own podman, the owner of those
   * containers, and its path is not the host's to know; ScriptPath is what
   * puts it in reach.
   *
   * On native Linux the script runs on this host, and a host's podman need not
   * be in ScriptPath's system directories at all (/opt/podman/bin is a real
   * layout). The path findOnPath resolved is the one this run created those
   * containers with, so it is the one that can answer for them; the reap's
   * own exit-code gate (only podman's not-exists answer prunes) is the
   * backstop for a podman that fails rather than answers.
   */
  def koAgentFsReapPodman(podman: String, os: Os): String =
    os match
      case Os.Linux => podman
      case Os.Mac | Os.Windows => "podman"

  /**
   * How launcher output names the filter: its binary name, which is also what `findmnt` shows,
   * with what it is and where its daemon runs — which is not the host on macOS and Windows.
   */
  def koAgentFsLabel(os: Os): String =
    val where = os match
      case Os.Linux => "on the host"
      case Os.Mac | Os.Windows => "in the podman machine"
    s"ko-agent-fs filter $where"

  def koAgentFsTeardownMode(os: Os): String =
    os match
      case Os.Linux => "local"
      case Os.Mac | Os.Windows => "machine"

  /** Unmount and remove one project's filter state; `-z` because a bind may still hold it. */
  def koAgentFsUnmountScript(projectId: String): String =
    withScriptPath(
      s"""dir="$$HOME/${koAgentFsMountDir(projectId)}"
       |fusermount3 -uz "$$dir/workspace" 2>/dev/null || true
       |rm -rf "$$dir"""".stripMargin
    )

  def koAgentFsUnmountAllScript: String =
    withScriptPath(
      s"""for mnt in "$$HOME"/$KoAgentFsInstallDir/mounts/*/workspace; do
       |  fusermount3 -uz "$$mnt" 2>/dev/null || true
       |done
       |rm -rf "$$HOME/$KoAgentFsInstallDir/mounts"""".stripMargin
    )

  def koAgentFsScriptCommand(podman: String, os: Os, script: String): Vector[String] =
    os match
      // /bin/sh, not a PATH-resolved `sh`, for the reason findOnPath states; ReaperScript spells it
      // the same way.
      case Os.Linux => Vector("/bin/sh", "-c", script)
      // The script crosses base64-encoded. Windows needs it: the script is full of double quotes,
      // which Windows argument encoding passes through unescaped, handing the VM a mangled
      // command line (LauncherImages.BundleLabelTemplate is the same wall). macOS does not
      // need it and gets it anyway: macOS is the platform running daily, so sharing the path is
      // what keeps a broken wrapper from surviving unnoticed until someone sits at a Windows
      // machine.
      case Os.Mac | Os.Windows =>
        val encoded =
          java.util.Base64.getEncoder.encodeToString(script.getBytes(StandardCharsets.UTF_8))
        Vector(podman, "machine", "ssh", s"printf %s $encoded | base64 -d | sh")

  /**
   * The backing path as the daemon resolves it, in the filesystem the daemon runs in. This is the
   * one host path that bypasses podman: every `--volume` source is translated by podman's own
   * client, but the backing travels to the daemon in the mount script. On Linux the daemon is on
   * this host, and the macOS machine mounts the host shares at their host paths — the Windows
   * machine is a WSL distro, which serves host drives at `/mnt/<drive>`, the same translation
   * podman's client applies to volume sources. A path with no drive letter (UNC) has no `/mnt`
   * spelling and refuses the launch.
   */
  def koAgentFsBackingPath(os: Os, projectDir: Path): Either[String, String] =
    val text = projectDir.toString
    os match
      case Os.Linux | Os.Mac => Right(text)
      case Os.Windows =>
        if text.length >= 3 && text(0).isLetter && text(1) == ':'
          && (text(2) == '\\' || text(2) == '/')
        then Right(s"/mnt/${text(0).toLower}/${text.drop(3).replace('\\', '/')}")
        else
          Left(
            s"error: cannot map $text into the podman machine\n" +
              "The workspace filter serves the project from inside the machine, which reaches " +
              "host drives at /mnt/<drive>; only drive-letter paths (C:\\...) have that spelling.",
          )

  /** The daemon user's home — the base every relative lifecycle path resolves against, and the
    * prefix that turns the mountpoint into an absolute `--volume` source. */
  def koAgentFsHome(podman: String, os: Os): String =
    val home =
      if os == Os.Linux then sys.props("user.home")
      else run(podman, "machine", "ssh", "pwd").text
    if home.isEmpty then fail("error: cannot determine the filter daemon's home directory")
    home

  /**
   * The mountpoint made ready for a `podman create` that binds it: a directory, so podman's
   * statfs of every bind source at create finds one, and not a dead mount — a daemon gone
   * mid-session leaves a mountpoint every access of which fails ENOTCONN, statfs included, which
   * the mount script would repair too late, after the create. Under the project lock like every
   * decision about the mount; a live mount answers `ls` and is left alone.
   */
  def koAgentFsPrepareScript(projectId: String): String =
    withScriptPath(
      s"""dir="$$HOME/${koAgentFsMountDir(projectId)}"
       |mnt="$$dir/workspace"
       |mkdir -p "$$mnt" "$$dir/sessions"
       |exec 9>"$$dir/lock"
       |flock 9 2>/dev/null || true
       |ls "$$mnt" >/dev/null 2>&1 || fusermount3 -uz "$$mnt" || true""".stripMargin
    )

  /**
   * The per-session gate, before anything of the run exists: prove the installed binary is this
   * launcher's build, prove it can mount and the policy refuses (self-test), and make the
   * mountpoint one a `podman create` can bind (koAgentFsPrepareScript). Every failure aborts the
   * launch — there is no fallback to an unfiltered bind mount. The mount itself is
   * mountKoAgentFs, once the sandbox container exists; its script repeats the build check beside
   * the daemon start, so this early one is the friendly refusal, not the binding one.
   */
  def prepareKoAgentFs(podman: String, os: Os, projectId: String): KoAgentFsPrepared =
    val home = koAgentFsHome(podman, os)
    val expected = bundledKoAgentFsSourceId()
    val version = run(koAgentFsVersionCommand(podman, os, home)*)
    if !version.ok || !koAgentFsReportedSourceId(version.text).contains(expected) then
      fail(
        s"""error: the installed ko-agent-fs is not this launcher's build
           |  (${if version.ok then version.text else version.err})
           |
           |Run --build first.""".stripMargin
      )
    val selfTest = run(koAgentFsSelfTestCommand(podman, os, home)*)
    if !selfTest.ok then
      fail(s"error: ko-agent-fs self-test failed; not launching:\n${selfTest.err}", selfTest.exit)
    val prepared = run(koAgentFsScriptCommand(podman, os, koAgentFsPrepareScript(projectId))*)
    if !prepared.ok then
      fail(s"error: preparing the ${koAgentFsLabel(os)} mountpoint failed:\n${prepared.err}", prepared.exit)
    KoAgentFsPrepared(expected, s"$home/${koAgentFsMountDir(projectId)}/workspace")

  /** What prepareKoAgentFs proved and where: the installed build's source id, and the absolute
    * mountpoint to bind at /workspace. */
  final case class KoAgentFsPrepared(sourceId: String, mountpoint: String)

  /**
   * Mount the project, or join its mount, and say which: true when this session reused a mount
   * another session holds. Run once `sandboxContainer` exists, so the marker the script writes
   * first is never found without its container (koAgentFsReapScript). Under the image-build lock,
   * which installKoAgentFs holds while it replaces the binary: the script's build check and its
   * daemon start are then one step against a concurrent --build, and a build in progress makes
   * the mount wait for it.
   */
  def mountKoAgentFs(
    podman: String,
    os: Os,
    prepared: KoAgentFsPrepared,
    projectId: String,
    projectDir: Path,
    sandboxContainer: String,
  ): Boolean =
    val backing = koAgentFsBackingPath(os, projectDir).fold(fail(_), identity)
    val script = koAgentFsMountScript(backing, projectId, prepared.sourceId, sandboxContainer)
    val mount = withFileLock(AgentSandboxLauncher.imageBuildLockFile(os)):
      run(koAgentFsScriptCommand(podman, os, script)*)
    if !mount.ok then
      fail(s"error: mounting the ${koAgentFsLabel(os)} failed:\n${mount.err}", mount.exit)
    mount.text.contains("reusing")

  /** Both steps at once, for a mount no session's reap counts: the share self-test's scratch
    * project (SelfTestShare). The mountpoint to bind. */
  def ensureKoAgentFsMounted(
    podman: String,
    os: Os,
    projectId: String,
    projectDir: Path,
    sandboxContainer: String,
  ): String =
    val prepared = prepareKoAgentFs(podman, os, projectId)
    mountKoAgentFs(podman, os, prepared, projectId, projectDir, sandboxContainer)
    prepared.mountpoint
