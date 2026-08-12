// Everything the launcher does about ko-agent-fs, the workspace FUSE filter: digesting the source it
// bundles, building and installing the binary, proving the installed one is that source's build, and
// the per-project mount lifecycle every session now runs through.
//
// It is a separate program with its own source tree, docs, tests and version contract
// (fuse/ko-agent-fs/), and it reaches the launch through exactly two calls — fuseFilterDisabled and
// ensureKoAgentFsMounted. That is why it is a file rather than a section.

package agentsandbox.launcher

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, Paths}
import java.security.MessageDigest
import scala.jdk.CollectionConverters.*

import HostCommands.*

object KoAgentFs:

  /**
   * The identity of the bundled ko-agent-fs source: SHA-256 over every file
   * under the build context's ko-agent-fs/, hashed sorted by path, each as
   * path + NUL + big-endian length + content — the sort makes bundling order
   * irrelevant, the length keeps file boundaries unambiguous, and the path
   * makes a rename a new identity. Passed to the image build as
   * KO_AGENT_FS_SOURCE_ID and reported back by the installed binary's
   * --version, so a binary that is not the one this launcher would build is
   * detected rather than trusted (fuse/ko-agent-fs/docs/architecture.md,
   * "Build and install"). The algorithm lives only here, deliberately: the
   * build is told the answer and repeats it, so there is no second
   * implementation to drift from this one.
   *
   * Every bundled file counts, tests included: `cargo deny` and `cargo test`
   * run before `cargo build`, so they decide whether a binary exists at all,
   * and picking out which of the remaining files "really" affect it is a
   * judgement that can rot. The exclusions are drawn where they cannot rot
   * into a second opinion: ko-agent-fs/docs and ko-agent-fs/probes are not
   * bundled at all (build.sbt), so they are neither distributed nor digested,
   * and editing a design document or a platform probe does not invalidate
   * every installed binary.
   */
  def koAgentFsSourceId(entries: Seq[(String, Array[Byte])]): String =
    val digest = MessageDigest.getInstance("SHA-256")
    entries.sortBy(_._1).foreach: (path, content) =>
      digest.update(path.getBytes(StandardCharsets.UTF_8))
      digest.update(0.toByte)
      digest.update(java.nio.ByteBuffer.allocate(8).putLong(content.length.toLong).array())
      digest.update(content)
    digest.digest().map(b => f"$b%02x").mkString

  /**
   * Digest the unpacked context's ko-agent-fs/ tree — the literal build
   * input, so the id describes exactly what podman build is about to see.
   */
  def koAgentFsSourceId(context: Path): String =
    val root = context.resolve("ko-agent-fs")
    val entries = Files
      .walk(root)
      .iterator()
      .asScala
      .filter(Files.isRegularFile(_))
      .map(file => (root.relativize(file).toString.replace('\\', '/'), Files.readAllBytes(file)))
      .toVector
    koAgentFsSourceId(entries)

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
   * Steps 3–4 of the filter pipeline (fuse/ko-agent-fs/docs/architecture.md,
   * "Build and install"): take /ko-agent-fs out of the image's scratch stage
   * and put it where the daemon must run. On podman machine both the image
   * storage and the daemon live inside the VM, so the whole extraction runs
   * there through `machine ssh` — a host-side `podman cp` would land the
   * binary on the wrong side of the boundary. The ssh script is fixed text;
   * nothing user-controlled is interpolated into it. `--replace` clears a
   * leftover extract container from a crashed earlier run.
   *
   */
  def koAgentFsInstallCommands(podman: String, os: Os, home: String): Vector[Vector[String]] =
    os match
      case Os.Linux =>
        Vector(
          Vector(podman, "create", "--replace", "--name", "ko-agent-fs-extract", "ko-agent-fs:latest"),
          Vector(podman, "cp", "ko-agent-fs-extract:/ko-agent-fs", s"$home/$KoAgentFsBinary"),
          Vector(podman, "rm", "ko-agent-fs-extract")
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
   * carries the tool's name, not `.dist`: `.dist` would claim
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
         |it — and fusermount3 refuses that until user_allow_other is set in the Podman machine's
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
          "then re-run --build"
      )
    console.printf("Apply it now? [y/N] ")
    val answer = Option(console.readLine()).map(_.trim.toLowerCase(java.util.Locale.ROOT)).getOrElse("")
    if answer != "y" && answer != "yes" then
      fail("error: not applied; run the script above via `podman machine ssh` yourself, then re-run --build")
    val enable = run(koAgentFsFuseConfEnableCommand(podman)*)
    if !enable.ok then fail(s"error: enabling user_allow_other failed: ${enable.err}", enable.exit)
    if !run(koAgentFsFuseConfCheckCommand(podman)*).ok then
      fail("error: user_allow_other still not set after enabling; check the machine's /etc/fuse.conf")

  /** Run the installed binary with one flag, wherever the daemon lives. */
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
      System.err.println(command.mkString(" "))
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
    // the policy shown to bite. Its failure text names the environment fix (e.g. a native Linux
    // host missing user_allow_other, which the launcher must not sudo into place).
    val selfTest = run(koAgentFsSelfTestCommand(podman, os, home)*)
    if !selfTest.ok then
      fail(s"error: ko-agent-fs self-test failed after install:\n${selfTest.err}", selfTest.exit)
    System.err.println(selfTest.text)

  // ---------------------------------------------------------------------------
  // The workspace FUSE filter's mount lifecycle (every session's, unless opted out)
  //
  // One daemon per project, alive while the project has sessions: started on
  // demand, reused by concurrent sessions, restarted when the
  // mountpoint is stale or the installed binary is not the one this launcher's
  // source builds, and unmounted when the project's last session ends. The
  // reference count is the session markers under <mountdir>/sessions/, written
  // by the mount script *before* it touches the mount and collected by the
  // reaper (or the resident path) after `podman wait` — the write-marker-first
  // ordering is what closes the race with a concurrent reap
  // (koAgentFsReapScript). The resets remain the sweep for whatever a crashed
  // launcher leaves. A daemon dying mid-session leaves the container's bind on
  // a dead FUSE superblock — every access fails ENOTCONN, never a fallthrough
  // to the unfiltered tree.
  // ---------------------------------------------------------------------------

  /**
   * The one escape hatch out of the workspace FUSE filter, which is otherwise every session's
   * enforcement. Named for what it does rather than for what it configures: presence is what
   * disables, so it cannot be reached by accident and there is no value to misread as "keep the
   * filter".
   *
   * Which is why the values are enumerated rather than taken as a bare presence test, the way
   * the opt-in variable it replaces did. This is the only variable in the launcher that *weakens* the
   * boundary, and "security configuration must fail closed: unknown, malformed, or ambiguously
   * interpreted policy must not silently weaken the effective boundary" (TODO.md's design
   * principles) applies to it exactly. So `=false` — which a reader could well write meaning "do
   * not disable" — is a refused launch, never a filter quietly switched off.
   */
  val NoFuseFilterVariable = "KO_AGENT_SANDBOX_NO_FUSE_FILTER"
  val NoFuseFilterValues = Vector("1", "true", "yes", "on")

  def fuseFilterDisabled(value: Option[String]): Either[String, Boolean] =
    value.map(_.trim.toLowerCase(java.util.Locale.ROOT)) match
      case None | Some("")                                => Right(false)
      case Some(text) if NoFuseFilterValues.contains(text) => Right(true)
      case Some(text) =>
        Left(
          s"""error: $NoFuseFilterVariable is set to '$text', which is not one of ${NoFuseFilterValues.mkString(", ")}
             |
             |This variable only ever weakens the boundary, so an unrecognized value is refused
             |rather than guessed at. Unset it to keep the filter; set it to 1 to bind /workspace
             |directly, with only .git/config and .git/hooks pinned read-only.""".stripMargin
        )

  /** The digest of the ko-agent-fs source bundled in this jar — what an installed binary's
    * `--version` must report before a session may mount through it. */
  def bundledKoAgentFsSourceId(): String =
    def resource(name: String): Array[Byte] =
      val stream = getClass.getResourceAsStream(s"/sandbox-build/$name")
      if stream == null then fail(s"error: the launcher jar has no bundled entry '$name'")
      try stream.readAllBytes()
      finally stream.close()
    val entries =
      String(resource("INDEX"), StandardCharsets.UTF_8).linesIterator
        .filter(_.startsWith("ko-agent-fs/"))
        .map(entry => entry.stripPrefix("ko-agent-fs/") -> resource(entry))
        .toVector
    koAgentFsSourceId(entries)

  def koAgentFsMountDir(projectId: String): String = s"$KoAgentFsInstallDir/mounts/$projectId"

  /**
   * Start (or reuse) the project's filter daemon and leave the mountpoint
   * serving. Fixed text except three safe-charset values: the project id
   * (podman-safe by construction), the source id (hex), and the backing
   * path — which is user-controlled and therefore travels base64-encoded,
   * never spliced into shell text.
   *
   * The steps, each fail-closed: reuse an existing healthy mount of the
   * same source id; lazily unmount a stale or version-skewed one; refuse a
   * non-empty mountpoint (a vanished mount must expose nothing); start the
   * daemon detached with its log beside the mount; wait until statfs
   * reports FUSE (fuse/fuseblk naming varies by stat version, hence the
   * prefix match).
   */
  def koAgentFsMountScript(
    backing: String,
    projectId: String,
    sourceId: String,
    sandboxContainer: String
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
       |if mountpoint -q "$$mnt"; then
       |  if [ "$$(cat "$$dir/source-id" 2>/dev/null || true)" = "$sourceId" ] \\
       |      && ls "$$mnt" >/dev/null 2>&1; then
       |    echo "workspace FUSE filter: reusing the existing mount"
       |    exit 0
       |  fi
       |  fusermount3 -uz "$$mnt"
       |fi
       |ls "$$mnt" >/dev/null 2>&1 || fusermount3 -uz "$$mnt" || true
       |if [ -n "$$(ls -A "$$mnt")" ]; then
       |  echo "mountpoint $$mnt is not empty; refusing" >&2
       |  exit 1
       |fi
       |printf %s "$sourceId" > "$$dir/source-id"
       |mv -f "$$dir/daemon.log" "$$dir/daemon.log.1" 2>/dev/null || true
       |nohup "$$HOME/$KoAgentFsBinary" --source "$$backing" --mount "$$mnt" --foreground \\
       |  >>"$$dir/daemon.log" 2>&1 &
       |i=0
       |while [ $$i -lt 100 ]; do
       |  case "$$(stat -f -c %T "$$mnt" 2>/dev/null || true)" in
       |    fuse*) echo "workspace FUSE filter: mounted"; exit 0 ;;
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
   * this run's, prune any whose container no longer exists (a crashed
   * launcher leaks its marker; pruning self-heals it), and unmount only
   * when none remain. The ordering closes the race with a concurrent
   * launch: a new session writes its marker *before* touching the mount,
   * so either this script sees the marker and leaves the daemon alone, or
   * the newcomer finds the mount gone and starts a fresh one. Which podman
   * the script calls is the caller's to decide: koAgentFsReapPodman.
   */
  def koAgentFsReapScript(podman: String, projectId: String, sandboxContainer: String): String =
    withScriptPath(
      s"""dir="$$HOME/${koAgentFsMountDir(projectId)}"
       |rm -f "$$dir/sessions/$sandboxContainer"
       |for marker in "$$dir/sessions"/*; do
       |  [ -e "$$marker" ] || continue
       |  "$podman" container exists "$$(basename "$$marker")" 2>/dev/null || rm -f "$$marker"
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
   * layout). A miss there does not fail cleanly: `container exists` returning
   * 127 takes the `|| rm -f` branch below, so every session marker is pruned
   * as though its container had gone, and the last-session unmount then pulls
   * the mount out from under a live concurrent session. The path findOnPath
   * resolved is the one this run created those containers with, so it is the
   * one that can answer for them.
   */
  def koAgentFsReapPodman(podman: String, os: Os): String =
    os match
      case Os.Linux => podman
      case Os.Mac | Os.Windows => "podman"

  /** Where the reaper must run the reap script: inside the VM, or on this host. */
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

  /** Run a lifecycle script where the daemon lives: the VM on podman machine, the host on Linux. */
  def koAgentFsScriptCommand(podman: String, os: Os, script: String): Vector[String] =
    os match
      // /bin/sh, not a PATH-resolved `sh`, for the reason findOnPath states; ReaperScript spells it
      // the same way.
      case Os.Linux => Vector("/bin/sh", "-c", script)
      case Os.Mac | Os.Windows => Vector(podman, "machine", "ssh", script)

  /** The daemon user's home — the base every relative lifecycle path resolves against, and the
    * prefix that turns the mountpoint into an absolute `--volume` source. */
  def koAgentFsHome(podman: String, os: Os): String =
    val home =
      if os == Os.Linux then sys.props("user.home")
      else run(podman, "machine", "ssh", "pwd").text
    if home.isEmpty then fail("error: cannot determine the filter daemon's home directory")
    home

  /**
   * The per-session gate and mount: prove the installed binary is this
   * launcher's build, prove it can mount and the policy bites (self-test),
   * then mount the project and return the absolute mountpoint to bind at
   * /workspace. Every failure aborts the launch — there is no fallback to
   * an unfiltered bind mount.
   */
  def ensureKoAgentFsMounted(
    podman: String,
    os: Os,
    projectId: String,
    projectDir: Path,
    sandboxContainer: String
  ): String =
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
    val script = koAgentFsMountScript(projectDir.toString, projectId, expected, sandboxContainer)
    val mount = run(koAgentFsScriptCommand(podman, os, script)*)
    if !mount.ok then
      fail(s"error: mounting the workspace FUSE filter failed:\n${mount.err}", mount.exit)
    // Which branch the script took — the user should not have to infer "reused" from silence.
    System.err.println(mount.text)
    s"$home/${koAgentFsMountDir(projectId)}/workspace"
