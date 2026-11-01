// --self-test's share rows: the host-writer/session-reader direction that the ko-agent-fs suites cannot
// reach, because their backing tree is the container's own storage (ko-agent-fs/doc/testing.md).
//
// A scratch lower created inside the current directory puts the real share in the path: host filesystem
// -> share -> ko-agent-fs -> container. The launcher performs the host-side steps.
//
// The rows meet the standard of doc/TODO.md, "Deferred — `--self-test`'s remaining share rows":
// - the launcher drives the rows, and the run records the machine;
// - the scratch is gone on success and kept on failure;
// - a killed run leaves nothing that the reset sweep does not match:
//   - the mount lies under the same mounts/ root that the unmount-all sweep clears;
//   - the container's name pattern is in --reset-all's container sweep;
//   - the scratch's name says what left it behind.

package agentsandbox.launcher

import java.io.{BufferedReader, InputStreamReader}
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path}
import java.util.concurrent.TimeUnit

import HostCommands.*
import FileHelper.*
import KoAgentFs.*

object SelfTestShare:

  /** The mount id lies under the FUSE backend's mounts/ root, so `--reset-all` and the unmount-all sweep cover
    * a killed run's mount exactly as they cover a session's mount. */
  def shareMountId(suffix: String): String = s"self-test-share-$suffix"

  def probeContainerName(suffix: String): String = s"ko-agent-self-test-share-$suffix"

  /** `--reset-all`'s sweep for the probe container a killed launcher leaves. `--rm` and the removal in
    * [[shareRows]]' finally are the primary cleanup. This method is the fallback match, anchored on the
    * eight-hex run suffix like the launcher's own reserved patterns. */
  def probeContainers(names: Seq[String]): Seq[String] =
    names.filter(_.matches(probeContainerName(AgentSandboxLauncher.RunSuffixPattern)))

  val SeedName = "share-probe-data"
  val OldBytes = "AAAA"
  val NewBytes = "BBBB" // Same length as OldBytes: the probe compares the mapped page in place, with no size change.

  // The line protocol between the container half and the orchestrator. The probe programs below
  // interpolate these values, so the two sides cannot drift.
  private val StackPrefix = "stack "
  private val Ready = "READY"
  private val ReadVisible = "read-visible"
  private val MmapVisible = "mmap-visible"
  private val Abort = "abort: "

  /** Where the probe container has the scratch workspace. The path is fixed and the probe's own, not the
    * scratch's host path that a session would use: the probe is not a session, and no agent sees it. */
  val ProbeMount = "/mnt/share-probe"

  /**
   * The probe container, run as a session's container would be where it matters:
   * - keep-id maps the image uid onto the daemon user, which makes the allow_other mount writable
   *   through the bind;
   * - the volume is mounted unlabelled, like every FUSE mountpoint;
   * - `--entrypoint=` is empty because the probe is the stdin program, not an agent session;
   * - `--network=none` because the rows need no egress.
   */
  def probeRunCommand(podman: String, mountpoint: String, container: String): Vector[String] =
    Vector(
      podman, "run", "--rm", "-i", "--name", container, "--network=none", "--entrypoint=",
      s"--userns=keep-id:uid=${AgentSandboxLauncher.ContainerUid},gid=${AgentSandboxLauncher.ContainerGid}",
      s"--user=${AgentSandboxLauncher.ContainerUid}:${AgentSandboxLauncher.ContainerGid}",
      s"--volume=$mountpoint:$ProbeMount:rw",
      LauncherImages.SandboxImage, "python3", "-",
    )

  /** The stack check the program opens with. `.git` refused at *any* depth is a property a bind mount
    * does not have, and probing in a fresh subdirectory makes the check answer in a tree that already
    * has a `.git`. */
  private val ProbePrelude: String =
    s"""import mmap, os, shutil, sys, tempfile, time
       |os.chdir("$ProbeMount")
       |probe = tempfile.mkdtemp(prefix=".stack-", dir=".")
       |try:
       |    os.mkdir(os.path.join(probe, ".git"))
       |    print("${StackPrefix}plain", flush=True)
       |except PermissionError:
       |    print("${StackPrefix}fuse", flush=True)
       |finally:
       |    shutil.rmtree(probe, ignore_errors=True)
       |""".stripMargin

  /**
   * The container half, fed on stdin. After the prelude, the program makes the coherency measurements
   * the hand-run probe made: a host write visible through read(), and through an already-established
   * mmap. The mmap measurement takes the AUTO_INVAL_DATA path, which nothing else exercises.
   * - Both waits are bounded, so a broken share is a failed row rather than a hung action.
   * - The mmap wait starts at the moment read() saw the write, so its figure is the lag between the
   *   two views.
   */
  val SessionProbe: String = ProbePrelude +
    s"""with open("$SeedName", "rb") as handle:
       |    page = mmap.mmap(handle.fileno(), ${OldBytes.length}, prot=mmap.PROT_READ)
       |    if bytes(page) != b"$OldBytes":
       |        print("${Abort}the seed reads %r" % bytes(page), flush=True)
       |        sys.exit(3)
       |    print("$Ready", flush=True)
       |    deadline = time.monotonic() + 120
       |    seen = None
       |    while time.monotonic() < deadline:
       |        with open("$SeedName", "rb") as reader:
       |            if reader.read() == b"$NewBytes":
       |                seen = time.monotonic()
       |                break
       |        time.sleep(0.01)
       |    if seen is None:
       |        print("$ReadVisible never", flush=True)
       |        sys.exit(1)
       |    print("$ReadVisible", flush=True)
       |    while time.monotonic() < seen + 120:
       |        if bytes(page) == b"$NewBytes":
       |            print("$MmapVisible %d" % int((time.monotonic() - seen) * 1000), flush=True)
       |            sys.exit(0)
       |        time.sleep(0.01)
       |    print("$MmapVisible never", flush=True)
       |    sys.exit(1)
       |""".stripMargin

  /** What one probe line means to the orchestrator. Noise is any unrecognized line, printed so that a
    * failed run's transcript is whole. */
  enum ProbeEvent:
    case Stack(fuse: Boolean)
    case ReadySeen
    case ReadSeen(ok: Boolean)
    case MmapSeen(lagMillis: Option[Long])
    case Aborted(reason: String)
    case Noise(text: String)

  def interpret(line: String): ProbeEvent =
    if line.startsWith(StackPrefix) then ProbeEvent.Stack(line.stripPrefix(StackPrefix) == "fuse")
    else if line == Ready then ProbeEvent.ReadySeen
    else if line == ReadVisible then ProbeEvent.ReadSeen(true)
    else if line == s"$ReadVisible never" then ProbeEvent.ReadSeen(false)
    else if line == s"$MmapVisible never" then ProbeEvent.MmapSeen(None)
    else if line.startsWith(s"$MmapVisible ") then
      line.stripPrefix(s"$MmapVisible ").toLongOption
        .fold(ProbeEvent.Noise(line))(lag => ProbeEvent.MmapSeen(Some(lag)))
    else if line.startsWith(Abort) then ProbeEvent.Aborted(line.stripPrefix(Abort))
    else ProbeEvent.Noise(line)

  /** The machine's own view, for the machine record: its kernel, and what filesystem serves the backing
    * path there. virtiofs is the answer that says the real share is in the path. The script uses findmnt
    * because virtiofs registers under FUSE's own statfs magic: `stat -f` answers "fuse" for virtiofs,
    * indistinguishable from the FUSE backend's mounts. */
  def machineViewScript(backing: String): String =
    withScriptPath(
      s"""backing="$$(${printingCommand(backing)})"
         |printf 'kernel %s, share %s' "$$(uname -r)" \\
         |  "$$(findmnt -no FSTYPE --target "$$backing" 2>/dev/null || echo unknown)"""".stripMargin,
    )

  def daemonLogScript(mountId: String): String =
    withScriptPath(s"""cat "$$HOME/${koAgentFsMountDir(mountId)}/daemon.log" 2>/dev/null""")

  /**
   * Runs the rows and returns 0 when every row passed. On failure, the scratch stays: its files tell a
   * row that measured a refusal apart from a row where the probe broke. The daemon log is printed
   * before the mount directory goes.
   */
  def shareRows(podman: String, os: Os, baseDir: Path): Int =
    var failed = false
    def row(ok: Boolean, label: String, detail: String): Unit =
      if !ok then failed = true
      System.err.println(f"  ${if ok then "PASS" else "FAIL"}%-4s  $label%-46s $detail")

    System.err.println("share rows: host filesystem -> share -> ko-agent-fs -> container")
    val scratch = Files.createTempDirectory(baseDir, "self-test-share.")
    val suffix = AgentSandboxLauncher.newRunSuffix()
    val mountId = shareMountId(suffix)
    val container = probeContainerName(suffix)
    try
      Files.write(scratch.resolve(SeedName), OldBytes.getBytes(UTF_8))

      // The run records the machine before any row, because a run with no machine recorded is not evidence.
      val lowerType =
        try Files.getFileStore(scratch).`type`()
        catch case _: java.io.IOException => "unknown"
      Files.write(scratch.resolve("case-probe"), Array.emptyByteArray)
      val lowerCase = if Files.exists(scratch.resolve("CASE-PROBE")) then "folding" else "sensitive"
      Files.delete(scratch.resolve("case-probe"))
      val backing = SandboxWorkspace.mountPathOf(os, scratch).fold(fail(_), identity)
      val machineView = os match
        case Os.Linux => s"kernel ${sys.props("os.version")}, share local"
        case _ =>
          val provider = run(podman, "machine", "info", "--format", "{{.Host.VMType}}")
          run(koAgentFsScriptCommand(podman, os, machineViewScript(backing))*).text.trim +
            s", provider ${if provider.ok then provider.text.trim else "unknown"}"
      System.err.println(s"share: lower $lowerType case-$lowerCase; machine: $machineView")

      val mountpoint = ensureKoAgentFsMounted(podman, os, mountId, backing, container)
      try
        val command = probeRunCommand(podman, mountpoint, container)
        echoCommand(command)
        val process = ProcessBuilder(command*).redirectErrorStream(true).start()
        // The hard bound over both 120 s probe waits plus the container's start. The kill ends an
        // unresponsive probe. The rows already printed remain, and the non-zero exit below adds a failure
        // row only when none of them failed.
        val watchdog = Thread(() =>
          if !process.waitFor(300, TimeUnit.SECONDS) then { process.destroyForcibly(); () },
        )
        watchdog.setDaemon(true)
        watchdog.start()
        process.getOutputStream.write(SessionProbe.getBytes(UTF_8))
        process.getOutputStream.close()

        val reader = BufferedReader(InputStreamReader(process.getInputStream, UTF_8))
        var writeAt = 0L
        var line = reader.readLine()
        while line != null do
          interpret(line) match
            case ProbeEvent.Stack(fuse) =>
              row(fuse, "the guard refuses through the whole stack",
                if fuse then "" else "mkdir .git succeeded")
            case ProbeEvent.ReadySeen =>
              writeAt = System.nanoTime()
              // A refused write is retried within a bound. On Windows, the machine's 9p server opens the
              // seed under Windows sharing rules, which refuse some writers while the server holds the seed
              // (ko-agent-fs/fuse/doc/verification-log.md, "Measured: coherency on Windows — fresh when
              // unheld; a hold refuses some writers (Server 24H2)"). A refusal that outlasts the bound
              // fails the row. The kill turns the container's own wait into an exit.
              var refusal: Option[String] = None
              var written = false
              while !written && System.nanoTime() - writeAt < 10L * 1000 * 1000 * 1000 do
                try
                  Files.write(scratch.resolve(SeedName), NewBytes.getBytes(UTF_8))
                  written = true
                catch
                  case ex: java.io.IOException =>
                    refusal = Some(ex.toString)
                    Thread.sleep(50)
              if !written then
                row(false, "a host rewrite of the mapped seed", refusal.getOrElse(""))
                process.destroyForcibly(); ()
            case ProbeEvent.ReadSeen(ok) =>
              val millis = (System.nanoTime() - writeAt) / 1000000
              val detail = if ok then s"$millis ms after the write" else "not within 120 s"
              row(ok, "a host write becomes visible to read()", detail)
            case ProbeEvent.MmapSeen(Some(lag)) =>
              val marginal = if lag > 2000 then " (MARGINAL: git mmaps .git/index and packfiles)" else ""
              row(true, "the write reaches an established mmap", s"$lag ms behind read()$marginal")
            case ProbeEvent.MmapSeen(None) =>
              row(false, "the write reaches an established mmap", "AUTO_INVAL_DATA is not invalidating")
            case ProbeEvent.Aborted(reason) =>
              row(false, "share probe", reason)
            case ProbeEvent.Noise(text) =>
              System.err.println(s"  probe: $text")
          line = reader.readLine()
        val exit = process.waitFor()
        if exit != 0 && !failed then row(false, "share probe", s"exit $exit with no failing row")
      finally
        // The watchdog kills only the attached client. The container, its process blocked on the share,
        // outlives the client, because --rm removes a container only when the container exits. This
        // finally therefore removes the container explicitly. If the launcher is killed before this
        // finally runs, --reset-all removes the container by name pattern.
        run(podman, "rm", "--force", "--ignore", container)
        if failed then
          val log = run(koAgentFsScriptCommand(podman, os, daemonLogScript(mountId))*)
          if log.text.nonEmpty then System.err.println(s"daemon log:\n${log.text}")
        run(koAgentFsScriptCommand(podman, os, koAgentFsUnmountScript(mountId))*)
    finally
      if failed then System.err.println(s"kept for inspection: $scratch")
      else deleteRecursively(scratch)
    if failed then 1 else 0
