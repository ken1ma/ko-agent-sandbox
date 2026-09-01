// --self-test's share rows: the host-writer/session-reader axis the crate's suites cannot reach,
// because their backing tree is the container's own storage (fuse/ko-agent-fs/doc/testing.md). A
// scratch lower created inside the current directory puts the real share in the path — host
// filesystem -> share -> ko-agent-fs -> container — and the launcher plays the host half the
// hand-run probes needed a person for. fuse/ko-agent-fs/doc/TODO.md is the standard: driven by the
// launcher, venue recorded, the scratch gone on success and kept on failure, and nothing a killed
// run leaves that the reset sweep does not match — the mount lives under the same mounts/ root the
// unmount-all sweep clears, the container's name shape is in --reset-all's container sweep, and
// the scratch's name says what left it behind.

package agentsandbox.launcher

import java.io.{BufferedReader, InputStreamReader}
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path}
import java.util.concurrent.TimeUnit

import HostCommands.*
import KoAgentFs.*

object SelfTestShare:

  /** Under the filter's mounts/ root, so `--reset-all` and the unmount-all sweep cover a killed
    * run's mount exactly as they cover a session's. */
  def shareMountId(suffix: String): String = s"self-test-share-$suffix"

  def probeContainerName(suffix: String): String = s"ko-agent-self-test-share-$suffix"

  /** `--reset-all`'s sweep for the probe container a killed launcher leaves. `--rm` and the
    * removal in [[shareRows]]' finally are the primary cleanup; this is the belt-and-braces
    * match, anchored on the eight-hex run suffix like the launcher's own reserved shapes. */
  def probeContainers(names: Seq[String]): Seq[String] =
    names.filter(_.matches(probeContainerName("[0-9a-f]{8}")))

  val SeedName = "share-probe-data"
  val OldBytes = "AAAA"
  val NewBytes = "BBBB" // same length: the mapped page is compared in place, no size change

  /** The orchestrator's answer to `HELD` (the Windows program), whichever way its write attempt
    * went: the file whose appearance tells the container to release the seed and exit. */
  val ReleaseName = "share-probe-release"

  // The line protocol between the container half and the orchestrator. Interpolated into the
  // probe programs below, so the two sides cannot drift.
  private val StackPrefix = "stack "
  private val Ready = "READY"
  private val ReadVisible = "read-visible"
  private val MmapVisible = "mmap-visible"
  private val Held = "HELD"
  private val Abort = "abort: "

  /**
   * The probe container, run as a session's would be where it matters: keep-id maps the image uid
   * onto the daemon user, which is what makes the allow_other mount writable through the bind,
   * and the volume rides unlabelled like every FUSE mountpoint. `--entrypoint=` because the probe
   * is the stdin program, not an agent session; `--network=none` because the rows need no egress.
   */
  def probeRunCommand(podman: String, mountpoint: String, container: String): Vector[String] =
    Vector(
      podman, "run", "--rm", "-i", "--name", container, "--network=none", "--entrypoint=",
      s"--userns=keep-id:uid=${AgentSandboxLauncher.ContainerUid},gid=${AgentSandboxLauncher.ContainerGid}",
      s"--user=${AgentSandboxLauncher.ContainerUid}:${AgentSandboxLauncher.ContainerGid}",
      s"--volume=$mountpoint:/workspace:rw",
      "ko-agent-sandbox:latest", "python3", "-",
    )

  /** The stack check both programs open with — `.git` refused at *any* depth is the property that
    * separates the filter from the launcher's mount pins, and probing in a fresh subdirectory is
    * what makes it answer in a tree that already has a `.git`. */
  private val ProbePrelude: String =
    s"""import mmap, os, shutil, sys, tempfile, time
       |os.chdir("/workspace")
       |probe = tempfile.mkdtemp(prefix=".stack-", dir=".")
       |try:
       |    os.mkdir(os.path.join(probe, ".git"))
       |    print("${StackPrefix}unfiltered", flush=True)
       |except PermissionError:
       |    print("${StackPrefix}filtered", flush=True)
       |finally:
       |    shutil.rmtree(probe, ignore_errors=True)
       |""".stripMargin

  /**
   * The container half, fed on stdin. After the prelude, the coherency measurements the hand-run
   * probe made: a host write visible through read(), and through an already-established mmap —
   * the AUTO_INVAL_DATA path nothing else exercises. Both waits are bounded, so a broken share is
   * a failed row rather than a hung verb; the mmap wait starts at the moment read() saw the
   * write, which makes its figure the lag between the two views.
   */
  val PosixSessionProbe: String = ProbePrelude +
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

  /**
   * The Windows program (verification-log.md, "coherency on Windows"): the podman machine reaches
   * the host's NTFS through its 9p server, whose handles carry Windows sharing semantics, so the
   * POSIX program's opening mmap would turn the orchestrator's own rewrite into the failure. Here
   * nothing holds the seed when READY asks for the rewrite — the unheld half of the documented
   * result — and the file is opened and mapped only afterwards: HELD asks the orchestrator to
   * write against the hold and expect the refusal, which is what closes the mmap question on that
   * venue — a mapped file cannot go stale, because the write is refused while the mapping holds.
   * The release file is the orchestrator's answer either way, and waiting for it is bounded like
   * every other wait.
   */
  val WindowsSessionProbe: String = ProbePrelude +
    s"""with open("$SeedName", "rb") as handle:
       |    seed = handle.read()
       |if seed != b"$OldBytes":
       |    print("${Abort}the seed reads %r" % seed, flush=True)
       |    sys.exit(3)
       |print("$Ready", flush=True)
       |deadline = time.monotonic() + 120
       |seen = False
       |while time.monotonic() < deadline:
       |    with open("$SeedName", "rb") as reader:
       |        if reader.read() == b"$NewBytes":
       |            seen = True
       |            break
       |    time.sleep(0.01)
       |if not seen:
       |    print("$ReadVisible never", flush=True)
       |    sys.exit(1)
       |print("$ReadVisible", flush=True)
       |handle = open("$SeedName", "rb")
       |page = mmap.mmap(handle.fileno(), ${OldBytes.length}, prot=mmap.PROT_READ)
       |print("$Held", flush=True)
       |while time.monotonic() < deadline + 120:
       |    if os.path.exists("$ReleaseName"):
       |        sys.exit(0)
       |    time.sleep(0.01)
       |print("${Abort}never released", flush=True)
       |sys.exit(1)
       |""".stripMargin

  /** What one probe line means to the orchestrator; Noise is the build of suspicion a failed run
    * prints whole. */
  enum ProbeEvent:
    case Stack(filtered: Boolean)
    case ReadySeen
    case ReadSeen(ok: Boolean)
    case MmapSeen(lagMillis: Option[Long])
    case HeldSeen
    case Aborted(reason: String)
    case Noise(text: String)

  def interpret(line: String): ProbeEvent =
    if line.startsWith(StackPrefix) then ProbeEvent.Stack(line.stripPrefix(StackPrefix) == "filtered")
    else if line == Ready then ProbeEvent.ReadySeen
    else if line == Held then ProbeEvent.HeldSeen
    else if line == ReadVisible then ProbeEvent.ReadSeen(true)
    else if line == s"$ReadVisible never" then ProbeEvent.ReadSeen(false)
    else if line == s"$MmapVisible never" then ProbeEvent.MmapSeen(None)
    else if line.startsWith(s"$MmapVisible ") then
      line.stripPrefix(s"$MmapVisible ").toLongOption
        .fold(ProbeEvent.Noise(line))(lag => ProbeEvent.MmapSeen(Some(lag)))
    else if line.startsWith(Abort) then ProbeEvent.Aborted(line.stripPrefix(Abort))
    else ProbeEvent.Noise(line)

  /** The machine's own view, for the venue record: its kernel, and what filesystem serves the
    * backing path there — virtiofs is the answer that says the real share is in the path. findmnt,
    * because virtiofs registers under FUSE's own statfs magic: `stat -f` answers "fuse" for it,
    * indistinguishable from the filter's mounts. */
  def machineVenueScript(backing: String): String =
    val encoded = java.util.Base64.getEncoder.encodeToString(backing.getBytes(UTF_8))
    withScriptPath(
      s"""backing="$$(printf %s $encoded | base64 -d)"
         |printf 'kernel %s, share %s' "$$(uname -r)" \\
         |  "$$(findmnt -no FSTYPE --target "$$backing" 2>/dev/null || echo unknown)"""".stripMargin,
    )

  def daemonLogScript(mountId: String): String =
    withScriptPath(s"""cat "$$HOME/${koAgentFsMountDir(mountId)}/daemon.log" 2>/dev/null""")

  /**
   * Run the rows; 0 when every row passed. On failure the scratch stays — its files are how a row
   * that measured a refusal is told apart from a row where the probe broke — and the daemon log is
   * printed before the mount directory goes.
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

      // The venue, before any row: a run with no venue recorded is not evidence.
      val lowerType =
        try Files.getFileStore(scratch).`type`()
        catch case _: java.io.IOException => "unknown"
      Files.write(scratch.resolve("case-probe"), Array.emptyByteArray)
      val lowerCase = if Files.exists(scratch.resolve("CASE-PROBE")) then "folding" else "sensitive"
      Files.delete(scratch.resolve("case-probe"))
      val backing = koAgentFsBackingPath(os, scratch).fold(fail(_), identity)
      val machineView = os match
        case Os.Linux => s"kernel ${run("uname", "-r").text.trim}, share local"
        case _ =>
          val provider = run(podman, "machine", "info", "--format", "{{.Host.VMType}}")
          run(koAgentFsScriptCommand(podman, os, machineVenueScript(backing))*).text.trim +
            s", provider ${if provider.ok then provider.text.trim else "unknown"}"
      System.err.println(s"share venue: lower $lowerType case-$lowerCase; machine: $machineView")

      val mount = ensureKoAgentFsMounted(podman, os, mountId, scratch, container)
      try
        val command = probeRunCommand(podman, mount.mountpoint, container)
        echoCommand(command)
        val process = ProcessBuilder(command*).redirectErrorStream(true).start()
        // The hard bound over both 120 s probe waits plus container start; the kill turns a wedged
        // share into a failed row with the lines so far as the report.
        val watchdog = Thread(() =>
          if !process.waitFor(300, TimeUnit.SECONDS) then { process.destroyForcibly(); () },
        )
        watchdog.setDaemon(true)
        watchdog.start()
        val program = if os == Os.Windows then WindowsSessionProbe else PosixSessionProbe
        process.getOutputStream.write(program.getBytes(UTF_8))
        process.getOutputStream.close()

        val reader = BufferedReader(InputStreamReader(process.getInputStream, UTF_8))
        var writeAt = 0L
        var line = reader.readLine()
        while line != null do
          interpret(line) match
            case ProbeEvent.Stack(filtered) =>
              row(filtered, "the guard bites through the whole stack", if filtered then "" else "mkdir .git succeeded")
            case ProbeEvent.ReadySeen =>
              writeAt = System.nanoTime()
              // A refused write is retried within a bound: on Windows the program's read poll
              // itself holds the seed through the 9p server for an instant, and a genuine hold
              // outlasts the bound. The kill turns the container's own wait into an exit.
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
                row(false, "a host rewrite of the unheld seed", refusal.getOrElse(""))
                process.destroyForcibly(); ()
            case ProbeEvent.ReadSeen(ok) =>
              val millis = (System.nanoTime() - writeAt) / 1000000
              val detail = if ok then s"$millis ms after the write" else "not within 120 s"
              row(ok, "a host write becomes visible to read()", detail)
            case ProbeEvent.MmapSeen(Some(lag)) =>
              val marginal = if lag > 2000 then " — MARGINAL: git mmaps .git/index and packfiles" else ""
              row(true, "the write reaches an established mmap", s"$lag ms behind read()$marginal")
            case ProbeEvent.MmapSeen(None) =>
              row(false, "the write reaches an established mmap", "AUTO_INVAL_DATA is not invalidating")
            case ProbeEvent.HeldSeen =>
              val refused =
                try
                  Files.write(scratch.resolve(SeedName), OldBytes.getBytes(UTF_8))
                  false
                catch case _: java.io.IOException => true
              row(
                refused,
                "a host write is refused while the seed is held",
                if refused then "the sharing lock, so the mapping can never go stale"
                else "the write succeeded — the lock premise fell; re-measure the mmap row (verification-log.md)",
              )
              Files.write(scratch.resolve(ReleaseName), Array.emptyByteArray)
            case ProbeEvent.Aborted(reason) =>
              row(false, "share probe", reason)
            case ProbeEvent.Noise(text) =>
              System.err.println(s"  probe: $text")
          line = reader.readLine()
        val exit = process.waitFor()
        if exit != 0 && !failed then row(false, "share probe", s"exit $exit with no failing row")
      finally
        // The watchdog kills only the attached client; a container wedged in the share outlives
        // it, --rm firing on container exit alone. Removed here directly — and by name shape in
        // --reset-all's sweep, for the killed launcher no finally survives.
        run(podman, "rm", "--force", "--ignore", container)
        if failed then
          val log = run(koAgentFsScriptCommand(podman, os, daemonLogScript(mountId))*)
          if log.text.nonEmpty then System.err.println(s"daemon log:\n${log.text}")
        run(koAgentFsScriptCommand(podman, os, koAgentFsUnmountScript(mountId))*)
    finally
      if failed then System.err.println(s"kept for inspection: $scratch")
      else deleteRecursively(scratch)
    if failed then 1 else 0
