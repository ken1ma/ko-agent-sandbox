// Everything the launcher does about ko-agent-fs, the workspace FUSE filter: digesting the source it
// bundles, building and installing the binary, proving the installed one is that source's build, and
// the per-project mount lifecycle every session that mounts it runs through.
//
// It is a separate program with its own source tree, docs, tests and version check
// (fuse/ko-agent-fs/), and it reaches the launch through prepareKoAgentFs and
// mountKoAgentFs. That is why it is a file rather than a section.

package agentsandbox.launcher

import java.io.IOException
import java.nio.file.{Files, Path, Paths}

import HostCommands.*
import FileHelper.*
import LauncherImages.{bundledSourceId, contextSourceId}

object KoAgentFs:

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
   * Where the filter binary is installed, relative to the home of the user the
   * daemon runs as — the VM user's home on podman machine, the host user's
   * on native Linux. Relative on purpose: `podman machine ssh` starts in the
   * VM user's home whoever that is (core on macOS, the WSL user on
   * Windows), so no per-platform absolute path needs to be known here.
   */
  val KoAgentFsInstallDir = ".local/share/ko-agent-sandbox"
  val KoAgentFsBinary = s"$KoAgentFsInstallDir/ko-agent-fs"

  /**
   * Steps 3–4 of the filter pipeline (fuse/ko-agent-fs/doc/architecture.md,
   * "Build and install"): take /ko-agent-fs out of the image's scratch stage
   * and put it where the daemon must run. On podman machine both the image
   * storage and the daemon are inside the VM, so the whole extraction runs
   * there through `machine ssh` — a host-side `podman cp` would put the
   * binary on the wrong side of the boundary. The ssh script is fixed text;
   * nothing user-controlled is interpolated into it. `--replace` clears a
   * leftover extract container from a crashed earlier run.
   */
  def koAgentFsInstallCommands(podman: String, os: Os, home: String): Vector[Vector[String]] =
    os match
      case Os.Linux =>
        Vector(
          Vector(podman, "create", "--replace", "--name", "ko-agent-fs-extract", LauncherImages.KoAgentFsImage),
          Vector(podman, "cp", "ko-agent-fs-extract:/ko-agent-fs", s"$home/$KoAgentFsBinary"),
          Vector(podman, "rm", "ko-agent-fs-extract"),
        )
      case Os.Mac | Os.Windows =>
        val script =
          s"""set -eu
             |mkdir -p $KoAgentFsInstallDir
             |podman create --replace --name ko-agent-fs-extract ${LauncherImages.KoAgentFsImage} >/dev/null
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
   * is the program's name, not `.dist`: `.dist` would claim
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
      s"""The workspace FUSE filter mounts with allow_other, which the container runtime needs to bind
         |the mount into the sandbox, and fusermount3 refuses that until user_allow_other is set in the
         |podman machine's /etc/fuse.conf. Your machine's configuration is not changed without asking.
         |The change:
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
  // The workspace FUSE filter's mount lifecycle (every live session's)
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

  def bundledKoAgentFsSourceId(): String = bundledSourceId("ko-agent-fs")

  /** Runs an unmount script and prints its [[unmountReport]]; true when the script acted on any filter state. */
  def unmountKoAgentFs(os: Os, script: String): Boolean =
    val result =
      try Some(run(koAgentFsScriptCommand(podman, os, script)*))
      catch case _: IOException => None
    val lines = unmountReport(koAgentFsLabel(os), result)
    lines.foreach(System.err.println)
    result.exists(_.text.nonEmpty)

  /** The lines reporting an unmount script's run, None when it could not start: every action it
    * printed, even when a later one failed, then a note if the run failed. */
  def unmountReport(label: String, result: Option[Run]): Vector[String] =
    val done = result.toVector.flatMap(_.text.linesIterator).map(line => s"$label: $line")
    if result.exists(_.ok) then done
    else if done.isEmpty then Vector("note: filter unmount skipped (no machine running, or the unmount script failed)")
    else done :+ "note: the filter unmount script failed after the actions above"

  def koAgentFsMountDir(projectId: String): String = s"$KoAgentFsInstallDir/mounts/$projectId"

  /**
   * Start (or reuse) the project's filter daemon and leave the mountpoint
   * serving. Fixed text except five values: the project id and the sandbox container's name
   * (podman-safe by construction), the source id (hex), and the backing path and file rules —
   * user-controlled, and therefore travelling base64-encoded, never spliced into shell text.
   *
   * Each step fails closed. The project lock is `lock` in koAgentFsReapScript. A non-empty
   * mountpoint is refused because a vanished mount must expose nothing. The `fuse*` match on
   * statfs is because fuse/fuseblk naming varies by stat version.
   *
   * The file rules (FileRules.daemonText) are the mount's, as its source id is: a launch joins a
   * live mount only under the same rules, since every session on one mount runs under the set its
   * first launch resolved. A launch after an edit passes the running mount's rules it was shown
   * (joinUnderOtherRules), so a refusal here, naming the sessions holding the mount, means the
   * running mount's rules changed after the start prompt. Either way the script ends with the resolved set after
   * FileRules.ResolvedMarker.
   */
  def koAgentFsMountScript(
    backing: String,
    projectId: String,
    sourceId: String,
    sandboxContainer: String,
    fileRules: String,
  ): String =
    withScriptPath(
      s"""set -eu
       |backing="$$(${printingCommand(backing)})"
       |dir="$$HOME/${koAgentFsMountDir(projectId)}"
       |mnt="$$dir/workspace"
       |mkdir -p "$$mnt" "$$dir/sessions"
       |: > "$$dir/sessions/$sandboxContainer"
       |exec 9>"$$dir/lock"
       |flock 9 2>/dev/null || true
       |${printingCommand(fileRules)} > "$$dir/file-rules.new"
       |if mountpoint -q "$$mnt"; then
       |  if [ "$$(cat "$$dir/source-id" 2>/dev/null || true)" = "$sourceId" ] \\
       |      && ls "$$mnt" >/dev/null 2>&1; then
       |    if [ "$$(cat "$$dir/file-rules.new")" != "$$(cat "$$dir/file-rules" 2>/dev/null || true)" ]; then
       |      rm -f "$$dir/file-rules.new"
       |      others=""
       |      for marker in "$$dir/sessions"/*; do
       |        [ "$$(basename "$$marker")" = "$sandboxContainer" ] || others="$$others $$(basename "$$marker")"
       |      done
       |      echo "this project is mounted for sessions under other file rules:$$others" >&2
       |      echo "launch again: the start prompt then shows the rules they run under" >&2
       |      exit 1
       |    fi
       |    rm -f "$$dir/file-rules.new"
       |    echo "reusing the existing mount"
       |    echo "${FileRules.ResolvedMarker}"
       |    cat "$$dir/file-rules.resolved"
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
       |# here — execution pauses at the start prompt. Checked again beside the start, under the
       |# image-build lock the launcher holds across this script and the installer holds while it
       |# replaces the binary (mountKoAgentFs), so the daemon started is the build source-id names.
       |case "$$("$$HOME/$KoAgentFsBinary" --version 2>/dev/null || true)" in
       |  *" source $sourceId") ;;
       |  *) echo "the installed ko-agent-fs is no longer this launcher's build; launch again" >&2; exit 1 ;;
       |esac
       |printf %s "$sourceId" > "$$dir/source-id"
       |mv -f "$$dir/file-rules.new" "$$dir/file-rules"
       |rm -f "$$dir/file-rules.resolved"
       |mv -f "$$dir/daemon.log" "$$dir/daemon.log.1" 2>/dev/null || true
       |# 9>&- so the daemon does not inherit the project lock and hold it for the session's
       |# whole life, which would block every later reap forever.
       |nohup "$$HOME/$KoAgentFsBinary" --source "$$backing" --mount "$$mnt" \\
       |  --file-rules "$$dir/file-rules" --foreground 9>&- >>"$$dir/daemon.log" 2>&1 &
       |i=0
       |while [ $$i -lt 100 ]; do
       |  case "$$(stat -f -c %T "$$mnt" 2>/dev/null || true)" in
       |    fuse*)
       |      echo "mounted"
       |      echo "${FileRules.ResolvedMarker}"
       |      cat "$$dir/file-rules.resolved"
       |      exit 0 ;;
       |  esac
       |  i=$$((i+1))
       |  sleep 0.1
       |done
       |echo "the filter did not become a FUSE mount; daemon log:" >&2
       |cat "$$dir/daemon.log" >&2 || true
       |exit 1""".stripMargin
    )

  /**
   * The last-session teardown, run where the daemon runs after a sandbox
   * container exits. The session markers are the reference count: remove
   * this run's, prune the dead ones (a crashed launcher leaves its marker
   * behind), and unmount only when none remain.
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
   * unmount running under it. Serialized, that launch either takes the lock
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
       |# A directory a reset removed took the markers and the mount with it, so there is nothing to
       |# reap; recreated to take the lock in, it would name the project to the next reset again.
       |[ -d "$$dir" ] || exit 0
       |# The project lock (see above). A shell that cannot even open it exits here, which leaves
       |# the mount up — as every other failure in this script does.
       |exec 9>"$$dir/lock"
       |flock 9 2>/dev/null || true
       |for marker in "$$dir/sessions"/*; do
       |  [ -e "$$marker" ] || continue
       |  gone=0
       |  "$podman" container exists "$$(basename "$$marker")" >/dev/null 2>&1 || gone=$$?
       |  # Only podman's own "no such container" answer (exit 1) prunes. Anything else — a broken
       |  # podman is exit 125 — is unknown liveness, and pruning on unknown is how the last-session
       |  # unmount below runs under a live session; the marker leaks toward a later reap instead.
       |  [ "$$gone" -eq 1 ] && rm -f "$$marker"
       |done
       |# A sessions directory that exists but cannot be listed is unknown liveness too, and keeps
       |# the mount; one that does not exist never held a marker.
       |if sessions="$$(ls -A "$$dir/sessions" 2>/dev/null)" || [ ! -e "$$dir/sessions" ]; then
       |  [ -z "$$sessions" ] && fusermount3 -uz "$$dir/workspace" 2>/dev/null || true
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
   * containers with, so it is the one that can answer for them; the reap
   * prunes a marker only on podman's not-exists answer, so a podman that
   * fails rather than answers prunes nothing.
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

  /** Unmount and remove one project's filter state; `-z` because a bind may still hold it. Prints a
    * line for each unmount and removal it made, and nothing where there is no state. An unmount is
    * reported only when fusermount3 made one: a resolve (koAgentFsResolveScript) leaves the state
    * directory without a mount. */
  def koAgentFsUnmountScript(projectId: String): String =
    withScriptPath(
      s"""dir="$$HOME/${koAgentFsMountDir(projectId)}"
       |[ -e "$$dir" ] || [ -L "$$dir" ] || exit 0
       |fusermount3 -uz "$$dir/workspace" 2>/dev/null && echo "unmounted $$dir/workspace"
       |rm -rf "$$dir" && echo "removed $$dir"""".stripMargin
    )

  /** [[koAgentFsUnmountScript]] for every project. */
  def koAgentFsUnmountAllScript: String =
    withScriptPath(
      s"""mounts="$$HOME/$KoAgentFsInstallDir/mounts"
       |[ -e "$$mounts" ] || [ -L "$$mounts" ] || exit 0
       |for mnt in "$$mounts"/*/workspace; do
       |  fusermount3 -uz "$$mnt" 2>/dev/null && echo "unmounted $$mnt"
       |done
       |rm -rf "$$mounts" && echo "removed $$mounts"""".stripMargin
    )

  def koAgentFsScriptCommand(podman: String, os: Os, script: String): Vector[String] =
    os match
      // /bin/sh, not a PATH-resolved `sh`, for the reason findOnPath states; ReaperScript spells it
      // the same way.
      case Os.Linux => Vector("/bin/sh", "-c", script)
      // The script crosses base64-encoded. Windows needs it: the script is full of double quotes,
      // which Windows argument encoding passes through unescaped, handing the VM a mangled
      // command line (LauncherImages.BundleLabelTemplate has the same problem). macOS does not need it
      // but uses the same encoding, so daily macOS runs detect a broken wrapper before it is used on
      // Windows.
      case Os.Mac | Os.Windows =>
        Vector(podman, "machine", "ssh", s"${printingCommand(script)} | sh")

  /**
   * The mountpoint made ready for a `podman create` that binds it: a directory, so podman's
   * statfs of every bind source at create finds one, and not a dead mount — a daemon gone
   * mid-session leaves a mountpoint every access of which fails ENOTCONN, statfs included, which
   * the mount script would repair too late, after the create. Under the project lock like every
   * decision about the mount; a live mount answers `ls` and is left alone. A live mount the
   * mount script would join, one the build `sourceId` names serves, is described after
   * RunningMountMarker: its sessions and its file rules (runningMountOf).
   */
  def koAgentFsPrepareScript(projectId: String, sourceId: String): String =
    withScriptPath(
      s"""dir="$$HOME/${koAgentFsMountDir(projectId)}"
       |mnt="$$dir/workspace"
       |mkdir -p "$$mnt" "$$dir/sessions"
       |exec 9>"$$dir/lock"
       |flock 9 2>/dev/null || true
       |ls "$$mnt" >/dev/null 2>&1 || fusermount3 -uz "$$mnt" || true
       |if mountpoint -q "$$mnt" && [ "$$(cat "$$dir/source-id" 2>/dev/null || true)" = "$sourceId" ] \\
       |    && [ -f "$$dir/file-rules" ]; then
       |  echo "$RunningMountMarker"
       |  for marker in "$$dir/sessions"/*; do
       |    [ -e "$$marker" ] && echo "session $$(basename "$$marker")"
       |  done
       |  echo "$RunningRulesMarker"
       |  cat "$$dir/file-rules"
       |fi""".stripMargin
    )

  /** The lines before a running mount's sessions and before its file rules (koAgentFsPrepareScript). */
  val RunningMountMarker = "running mount:"
  val RunningRulesMarker = "running mount's file rules:"

  /** A live mount of the project a launch would join: the sessions holding it, as their containers
    * are named, and the file rules it serves, as FileRules.daemonText wrote them. */
  final case class RunningMount(sessions: Vector[String], rules: String)

  def runningMountOf(output: String): Option[RunningMount] =
    val lines = output.linesIterator.toVector
    val start = lines.indexOf(RunningMountMarker)
    val rules = lines.indexOf(RunningRulesMarker)
    Option.when(start >= 0 && rules > start)(
      RunningMount(
        lines.slice(start + 1, rules).collect { case s"session $name" => name },
        lines.drop(rules + 1).map(_ + "\n").mkString,
      ),
    )

  /**
   * The mount a launch whose file rules are `wanted` joins under rules other than its own, with
   * the start prompt as the consent (doc/file-rules.md, "One mount per project"), or the refusal
   * when no prompt will ask: the running rules may be weaker than the edit.
   */
  def joinUnderOtherRules(
    running: Option[RunningMount],
    wanted: String,
    prompted: Boolean,
  ): Either[String, Option[RunningMount]] =
    running.filter(_.rules != wanted) match
      case Some(other) if !prompted =>
        Left(
          s"error: this project's concurrent sessions (${other.sessions.mkString(", ")}) run under other " +
            "file rules than .ko-agent-sandbox/file/rule gives, and joining them needs the start " +
            "prompt's consent. Launch from a terminal with " +
            s"${AgentSandboxLauncher.SessionStartVariable} unset or pause, or once they end.",
        )
      case joined => Right(joined)

  /** The warning a joining launch prints, on one line the launcher does not wrap. */
  def joinWarning(running: RunningMount): String =
    "your edits to .ko-agent-sandbox/file/rule do not take effect until this project's concurrent sessions end " +
      s"(${running.sessions.mkString(", ")}); this session runs under the file rules they started with"

  /**
   * prepareKoAgentFs's read-only checks as one script: one `podman machine ssh` where the filter
   * runs in the machine, and a step the launch can start before its own checks finish. It prints:
   *
   *   - the daemon user's home: the base every relative lifecycle path resolves against, and the
   *     prefix that turns the mountpoint into an absolute `--volume` source. On native Linux it is
   *     `home`, the JVM's `user.home` as installKoAgentFs uses it; the working directory there is
   *     the project;
   *   - the installed binary's `--version`;
   *   - only when that names `sourceId`, ChecksSelfTestMarker and then the self-test, whose status
   *     is the script's.
   */
  def koAgentFsChecksScript(home: Option[String], sourceId: String): String =
    val homeLine = home match
      case Some(path) =>
        s"""home="$$(${printingCommand(path)})""""
      case None => """home="$(pwd)""""
    withScriptPath(
      s"""set -u
       |$homeLine
       |printf '%s\\n' "$$home"
       |version="$$("$$home/$KoAgentFsBinary" --version)"
       |printf '%s\\n' "$$version"
       |case "$$version" in
       |  *" source $sourceId") ;;
       |  *) exit 0 ;;
       |esac
       |echo "$ChecksSelfTestMarker"
       |exec "$$home/$KoAgentFsBinary" --self-test""".stripMargin
    )

  /** The line koAgentFsChecksScript prints once the version matched, before the self-test runs. */
  val ChecksSelfTestMarker = "self-test:"

  /** Runs koAgentFsChecksScript where the filter runs; on native Linux, with the JVM's home. */
  def koAgentFsChecks(podman: String, os: Os, sourceId: String): HostCommands.Run =
    val home = Option.when(os == Os.Linux)(sys.props("user.home"))
    run(koAgentFsScriptCommand(podman, os, koAgentFsChecksScript(home, sourceId))*)

  /**
   * The checks before each session, before anything of the run exists. Every failure aborts the
   * launch — there is no fallback to an unfiltered bind mount.
   *
   *   - `checks`, koAgentFsChecks's answer, which the caller runs: the installed binary is this
   *     launcher's build, and it can mount and the policy refuses (self-test).
   *   - koAgentFsPrepareScript makes the mountpoint one a `podman create` can bind.
   *
   * The mount itself is mountKoAgentFs, once the sandbox container exists; its script repeats the
   * build check beside the daemon start, so this early one is the friendly refusal, not the binding
   * one.
   */
  def prepareKoAgentFs(
    podman: String,
    os: Os,
    projectId: String,
    expected: String,
    checks: HostCommands.Run,
  ): KoAgentFsPrepared =
    val home = checkedKoAgentFsHome(checks, expected).fold(fail(_, _), identity)
    val prepared = run(koAgentFsScriptCommand(podman, os, koAgentFsPrepareScript(projectId, expected))*)
    if !prepared.ok then
      fail(s"error: preparing the ${koAgentFsLabel(os)} mountpoint failed:\n${prepared.err}", prepared.exit)
    KoAgentFsPrepared(expected, s"$home/${koAgentFsMountDir(projectId)}/workspace", runningMountOf(prepared.text))

  /** The home a koAgentFsChecks answer reports, or the refusal and exit status the answer calls for. */
  def checkedKoAgentFsHome(checks: HostCommands.Run, expected: String): Either[(String, Int), String] =
    val lines = checks.text.linesIterator.toVector
    val home = lines.headOption.getOrElse("")
    val marker = lines.indexOf(ChecksSelfTestMarker)
    val version = lines.slice(1, if marker < 0 then lines.length else marker).mkString("\n")
    if home.isEmpty then Left(("error: cannot determine the filter daemon's home directory", 1))
    else if marker < 0 || !koAgentFsReportedSourceId(version).contains(expected) then
      Left(
        (
          s"""error: the installed ko-agent-fs is not this launcher's build
             |  (${if version.nonEmpty then version else checks.err})
             |
             |Run --build first.""".stripMargin,
          1,
        ),
      )
    else if !checks.ok then Left((s"error: ko-agent-fs self-test failed; not launching:\n${checks.err}", checks.exit))
    else Right(home)

  /** What prepareKoAgentFs proved and where: the installed build's source id, the absolute
    * mountpoint to bind at the project's mount path, and the live mount there a launch would join. */
  final case class KoAgentFsPrepared(sourceId: String, mountpoint: String, running: Option[RunningMount])

  /**
   * Mount the project, or join its mount: whether this session reused a mount another session
   * holds, and the resolved file rules the script printed. `backing` is the project as the
   * daemon's filesystem spells it (SandboxProject.mountPathOf). Run once `sandboxContainer`
   * exists, so the marker the script writes first is never found without its container
   * (koAgentFsReapScript). Under the image-build lock, which installKoAgentFs holds while it
   * replaces the binary: the script's build check and its daemon start are then one step against
   * a concurrent --build, and a build in progress makes the mount wait for it.
   */
  def mountKoAgentFs(
    podman: String,
    os: Os,
    prepared: KoAgentFsPrepared,
    projectId: String,
    backing: String,
    sandboxContainer: String,
    fileRules: String,
  ): (Boolean, FileRules.Resolved) =
    val script = koAgentFsMountScript(backing, projectId, prepared.sourceId, sandboxContainer, fileRules)
    val mount = withFileLock(ImageBuilds.imageBuildLockFile(os)):
      run(koAgentFsScriptCommand(podman, os, script)*)
    if !mount.ok then
      fail(s"error: mounting the ${koAgentFsLabel(os)} failed:\n${mount.err}", mount.exit)
    (mount.text.linesIterator.contains("reusing the existing mount"), resolvedAfterMarker(mount.text))

  /** The resolved file rules a script printed after FileRules.ResolvedMarker. */
  def resolvedAfterMarker(output: String): FileRules.Resolved =
    val lines = output.linesIterator.toVector
    lines.indexOf(FileRules.ResolvedMarker) match
      case -1 =>
        fail(
          "error: the filter printed no resolved file rules; the installed ko-agent-fs is not this " +
            "launcher's. Run --build.",
        )
      case at => FileRules.parseResolved(lines.drop(at + 1).mkString("\n")).fold(fail(_), identity)

  /**
   * The resolved file rules without a mount, for `--write=reject` with `--run-on-host`, where host
   * commands write the project while no daemon runs: `ko-agent-fs --resolve` over the project as
   * the daemon's filesystem spells it, through the channel the mount uses, under the same build
   * check.
   */
  def koAgentFsResolveScript(backing: String, projectId: String, sourceId: String, fileRules: String): String =
    withScriptPath(
      s"""set -eu
       |backing="$$(${printingCommand(backing)})"
       |dir="$$HOME/${koAgentFsMountDir(projectId)}"
       |mkdir -p "$$dir"
       |rules="$$dir/file-rules.resolve.$$$$"
       |${printingCommand(fileRules)} > "$$rules"
       |case "$$("$$HOME/$KoAgentFsBinary" --version 2>/dev/null || true)" in
       |  *" source $sourceId") ;;
       |  *) rm -f "$$rules"; echo "the installed ko-agent-fs is not this launcher's build; run --build" >&2; exit 1 ;;
       |esac
       |echo "${FileRules.ResolvedMarker}"
       |status=0
       |"$$HOME/$KoAgentFsBinary" --source "$$backing" --resolve --file-rules "$$rules" || status=$$?
       |rm -f "$$rules"
       |exit $$status""".stripMargin
    )

  def resolveFileRules(
    podman: String,
    os: Os,
    projectId: String,
    backing: String,
    fileRules: String,
  ): FileRules.Resolved =
    val script = koAgentFsResolveScript(backing, projectId, bundledKoAgentFsSourceId(), fileRules)
    val resolved = withFileLock(ImageBuilds.imageBuildLockFile(os)):
      run(koAgentFsScriptCommand(podman, os, script)*)
    if !resolved.ok then
      fail(s"error: resolving the file rules with the ${koAgentFsLabel(os)} failed:\n${resolved.err}", resolved.exit)
    resolvedAfterMarker(resolved.text)

  /** Both steps at once, for a mount no session's reap counts: the share self-test's scratch
    * project (SelfTestShare). The mountpoint to bind. */
  def ensureKoAgentFsMounted(
    podman: String,
    os: Os,
    projectId: String,
    backing: String,
    sandboxContainer: String,
  ): String =
    val expected = bundledKoAgentFsSourceId()
    val prepared = prepareKoAgentFs(podman, os, projectId, expected, koAgentFsChecks(podman, os, expected))
    val noRules = FileRules.daemonText(Vector.empty, Vector("/"))
    mountKoAgentFs(podman, os, prepared, projectId, backing, sandboxContainer, noRules)
    prepared.mountpoint
