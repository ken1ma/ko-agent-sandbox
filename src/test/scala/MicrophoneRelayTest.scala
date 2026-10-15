// The microphone's POSIX and Windows relays, run for real against the same scripts in place of podman, the
// recorders and the sandbox's writer: the reaper's shell functions under /bin/sh with its tree
// functions, and the resident launcher's threads, which Windows runs. What they hold is the probe's
// report to the launcher and the forwarding's contract with the writer: nothing before `ready`, the
// audio of the round trip first, no gap, and nothing one request left behind reaching the next.
// Last, the Windows relay's recorders, which end with the launcher.

package agentsandbox.launcher

import java.nio.file.{Files, Path, Paths}
import java.nio.file.attribute.PosixFilePermissions

import scala.jdk.CollectionConverters.*
import scala.jdk.OptionConverters.*
import scala.util.Using

class MicrophoneRelayTest extends munit.FunSuite:

  private val programs = Vector("sh", "mkfifo", "dd", "head", "tr", "wc", "base64")
  private def onPath(program: String): Boolean =
    sys.env.getOrElse("PATH", "").split(":").exists(dir => Files.isExecutable(Paths.get(dir, program)))

  /** The distinct periods in `pcm`, each 320 samples of its index, so a capture reads as a sequence of indices. */
  private val Periods = 1000

  private def executable(path: Path, body: String): Unit =
    Files.writeString(path, body)
    Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"))

  /** The relay under test: the reaper's shell functions on POSIX, or the resident launcher's threads,
    * which Windows runs and which run here against the same fakes. */
  private enum Relay(val label: String):
    case Posix extends Relay("POSIX")
    case Windows extends Relay("Windows")

  /** One run of the relay: its directories, the fakes' records under `host`, and whether it runs. */
  private final class Harness(
    val relay: Relay,
    val host: Path,
    val sandbox: Path,
    val status: Path,
    val log: Path,
    val alive: () => Boolean,
  ):
    def statusLines: Vector[String] =
      if Files.exists(status) then Files.readAllLines(status).asScala.toVector else Vector.empty
    def logText: String = if Files.exists(log) then Files.readString(log) else ""
    /** What a failure shows: the relay's stderr, its log and its status. */
    def diagnostics: String =
      val err = status.resolveSibling("relay.err")
      s"\nstderr:\n${if Files.exists(err) then Files.readString(err) else ""}\nlog:\n$logText\nstatus:\n" +
        statusLines.mkString("\n")
    def count(name: String): Int =
      val file = host.resolve(name)
      if Files.exists(file) then Files.readString(file).trim.toIntOption.getOrElse(0) else 0
    /** The recorder's latest period, as it last wrote it, read again while a rewrite has emptied it. */
    def latestPeriod: Int =
      val file = host.resolve("at")
      Iterator
        .continually(if Files.exists(file) then Files.readString(file).trim else "0")
        .take(100)
        .find(_.nonEmpty)
        .flatMap(_.toIntOption)
        .getOrElse(0)
    def capture(exec: Int): Array[Byte] =
      val file = host.resolve(s"exec-$exec.raw")
      if Files.exists(file) then Files.readAllBytes(file) else Array.empty
    /** What the writer's stand-in had read of its stdin when it answered `ready`. */
    def beforeReady(exec: Int): Option[Long] =
      val file = host.resolve(s"exec-$exec.before-ready")
      Option.when(Files.exists(file))(Files.readString(file).trim.toLong)

    def awaitStatus(): Vector[String] =
      awaitTrue(s"the probe's outcome$diagnostics")(MicrophoneRelay.probeOutcome(statusLines).nonEmpty)
      statusLines

    /** A `start`, as the controller writes it: to a reader of `req`, which the relay's exec makes. */
    def request(line: String = "start"): Unit =
      val req = sandbox.resolve("req")
      awaitTrue("the relay's request FIFO")(Files.exists(req))
      // The reader exec may be between two requests; the controller retries the same way.
      awaitTrue(s"a reader of req for `$line`"):
        val writer = ProcessBuilder("sh", "-c", s"""printf '%s\\n' '$line' > "$req"""").start()
        writer.waitFor(2, java.util.concurrent.TimeUnit.SECONDS) && writer.exitValue() == 0 || {
          writer.destroyForcibly()
          false
        }

    /** The controller's SIGTERM, which a real writer obeys; the stand-in is KILLed, as podman's exec is. */
    def endWriter(): Unit =
      val pid = Files.readString(host.resolve("writer.pid")).trim
      ProcessBuilder("kill", "-KILL", pid).start().waitFor()

  private def awaitTrue(what: => String, seconds: Int = 20)(condition: => Boolean): Unit =
    val deadline = System.nanoTime() + seconds * 1_000_000_000L
    while !condition do
      assert(System.nanoTime() < deadline, s"timed out waiting for $what")
      Thread.sleep(50)

  /** The period indices of a capture, which must be whole periods. */
  private def indices(capture: Array[Byte]): Vector[Int] =
    assertEquals(capture.length % 640, 0, "a capture holds part of a period")
    capture.grouped(640).map(period => (period(0) & 0xff) | ((period(1) & 0xff) << 8)).toVector

  private def consecutive(found: Vector[Int]): Boolean =
    found.sliding(2).forall:
      case Vector(a, b) => b == (a + 1) % Periods
      case _            => true

  /**
   * Recorders by label: `good` paces indexed periods at 20 ms, `late` paces 100 periods of zeros
   * and then as `good` does, `silent` paces zeros, `failing`
   * exits at once with SoX's warning then its failure on stderr, `mute` never writes, `stalling`
   * writes the probe's periods and 30 more, then nothing. Each counts its starts in
   * `starts-<label>`.
   */
  private def recorder(host: Path, label: String): String =
    val path = host.resolve(label)
    val body = label match
      case "good" =>
        s"""i=0
           |while :; do
           |  echo "$$i" > "$host/at"
           |  dd if="$host/pcm" bs=640 skip=$$((i % $Periods)) count=1 2>/dev/null || exit
           |  i=$$((i + 1))
           |  sleep 0.02
           |done""".stripMargin
      case "late" =>
        s"""i=0
           |while [ "$$i" -lt 100 ]; do
           |  dd if="$host/zeros" bs=640 count=1 2>/dev/null || exit
           |  sleep 0.02
           |  i=$$((i + 1))
           |done
           |i=0
           |while :; do
           |  dd if="$host/pcm" bs=640 skip=$$((i % $Periods)) count=1 2>/dev/null || exit
           |  i=$$((i + 1))
           |  sleep 0.02
           |done""".stripMargin
      case "silent" => s"while :; do dd if=\"$host/zeros\" bs=640 count=1 2>/dev/null || exit; sleep 0.02; done"
      case "failing" =>
        "echo \"rec WARN formats: can't set sample rate 16000; using 48000\" >&2\n" +
          "echo \"rec FAIL formats: can't open input\" >&2\nexit 2"
      case "mute" => "exec sleep 3600"
      case "stalling" =>
        s"dd if=\"$host/pcm\" bs=640 count=${MicrophoneRelay.ProbeReads + 30} 2>/dev/null\nexec sleep 3600"
    executable(
      path,
      s"""#!/bin/sh
         |n=$$(cat "$host/starts-$label" 2>/dev/null || echo 0)
         |echo $$((n + 1)) > "$host/starts-$label"
         |""".stripMargin + body + "\n",
    )
    path.toString

  /** A scenario run against both relays, under one name each. */
  private def bothRelays(name: String, labels: String*)(check: Harness => Unit): Unit =
    Relay.values.foreach: relay =>
      test(s"$name (${relay.label} relay)")(run(relay, labels)(check))

  /** `jobWritable = false` takes the write permission off the POSIX relay's directory. */
  private def run(relay: Relay, labels: Seq[String], jobWritable: Boolean = true)(check: Harness => Unit): Unit =
    assume(programs.forall(onPath), s"needs ${programs.mkString(", ")} on PATH")
    val ps = HostPs.answering()
    // Never under the project: on a podman machine served by libkrun, a FIFO there whose times
    // change hangs the machine's whole /Users share (doc/upstream-issues.md).
    val root = Files.createTempDirectory("microphone-relay").toRealPath()
    val host = Files.createDirectory(root.resolve("host"))
    val sandbox = Files.createDirectory(root.resolve("sandbox"))
    val job = Files.createDirectory(root.resolve("job"))
    if !jobWritable then job.toFile.setWritable(false)
    Files.write(host.resolve("zeros"), new Array[Byte](640))
    Files.write(
      host.resolve("pcm"),
      (0 until Periods).toArray.flatMap: index =>
        Array.fill(320)(Array((index & 0xff).toByte, (index >> 8).toByte)).flatten,
    )
    // "exec C sh -c S" runs S here, against the test's sandbox directory; the writer's command
    // runs the stand-in below, and an exec -i that leaves the detach keys on fails. `stopped` is the
    // container stopping.
    executable(
      host.resolve("podman"),
      s"""#!/bin/sh
         |case "$$1 $$2" in
         |  "container inspect") if [ -e "$host/stopped" ]; then echo false; else echo true; fi; exit 0 ;;
         |  "container exists") [ -e "$host/stopped" ] && exit 1; exit 0 ;;
         |esac
         |shift
         |if [ "$$1" = -i ]; then
         |  [ "$$2" = --detach-keys= ] || { echo "exec -i with the detach keys on" >&2; exit 125; }
         |  shift 2
         |fi
         |shift
         |[ "$$1" = ko-sandbox-mic ] && exec "$host/writer"
         |exec "$$@"
         |""".stripMargin,
    )
    // The writer's stand-in reads its stdin from its start, as podman does whether or not the
    // process inside reads it, and records how much it had read when it answered `ready`. It reads
    // in its own process, the one the relay ends, so a `SIGSTOP` of its pid is a daemon that stopped
    // reading. `stale`: the stream closed before it looked; `ready-delay`: a slow round trip.
    executable(
      host.resolve("writer"),
      s"""#!/bin/sh
         |n=$$(( $$(cat "$host/execs" 2>/dev/null || echo 0) + 1 ))
         |echo "$$n" > "$host/execs"
         |echo "$$$$" > "$host/writer.pid"
         |[ -e "$host/stale" ] && exit 0
         |: > "$host/exec-$$n.raw"
         |{
         |  sleep "$$(cat "$host/ready-delay" 2>/dev/null || echo 0)"
         |  wc -c < "$host/exec-$$n.raw" | tr -d ' ' > "$host/exec-$$n.before-ready"
         |  echo ready
         |} &
         |exec cat > "$host/exec-$$n.raw"
         |""".stripMargin,
    )
    val recorders = labels.toVector.map(label => MicrophoneRelay.Recorder(label, Vector(recorder(host, label))))
    val podman = host.resolve("podman").toString
    val (status, log) = (root.resolve("status"), root.resolve("microphone.log"))
    // Every process the run starts is this JVM's descendant, the relay and its recorders alike; suites
    // run one at a time (build.sbt), so those absent before the start are the run's. Collected while it
    // runs, since a process whose parent ended leaves the tree.
    val before = ProcessHandle.current().descendants().map(_.pid).toList.asScala.toSet
    val owned = scala.collection.mutable.Map.empty[Long, ProcessHandle]
    @volatile var ended = false
    val watcher = Thread(() =>
      while !ended do
        ProcessHandle.current().descendants().filter(handle => !before(handle.pid)).forEach: handle =>
          owned.synchronized(owned.getOrElseUpdate(handle.pid, handle))
        Thread.sleep(20),
    )
    watcher.setDaemon(true)
    watcher.start()
    var alive: () => Boolean = () => false
    // The relay starts processes until it finds the container stopped, a request reader among them that
    // waits on `req` for a writer: ended until the relay ends, for at most ten seconds.
    def endAll(): Unit =
      Files.writeString(host.resolve("stopped"), "")
      val deadline = System.nanoTime() + 10_000_000_000L
      while alive() && System.nanoTime() < deadline do
        owned.synchronized(owned.values.foreach(_.destroyForcibly()))
        Thread.sleep(50)
      ended = true
      watcher.join()
      owned.synchronized(owned.values.foreach(_.destroyForcibly()))
      // A subshell forked as its parent died leaves the tree before the watcher sees it; every process the
      // scripts start names the run's directory, or descends from one that does.
      ProcessHandle.allProcesses()
        .filter(_.info.commandLine.toScala.exists(_.contains(root.toString)))
        .forEach: handle =>
          handle.descendants().forEach(_.destroyForcibly())
          handle.destroyForcibly()
    try
      alive = relay match
        case Relay.Posix =>
          val script =
            s"trap '' INT HUP TERM\nps_command='$ps'\n" + SandboxLifecycle.TreeFunctions +
              MicrophoneRelay.hostShellFunctions(sandbox.toString, probeBound = Some(3)) +
              "microphone_relay \"$@\"\n"
          Files.writeString(root.resolve("relay.sh"), script)
          val process = ProcessBuilder(
            (Vector("sh", "-c", script, "relay", podman, "sandbox", job.toString, status.toString, log.toString)
              ++ recorders.map(MicrophoneRelay.encodedCandidate))*,
          ).redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(root.resolve("relay.err").toFile).start()
          () => process.isAlive
        case Relay.Windows =>
          // The launcher's own steps (AgentSandboxLauncher.startSandbox), its outcome written as the POSIX
          // relay's status lines.
          MicrophoneRelay.probeResident(recorders, 3, log) match
            case Right(kept) =>
              Files.write(
                status,
                (Option.when(kept.silent)("silent").toVector :+ s"recording ${kept.recorder.label}").asJava,
              )
              val thread = MicrophoneRelay.startResident(kept, podman, "sandbox", log, sandbox.toString)
              () => thread.isAlive
            case Left(reasons) =>
              Files.write(status, (reasons.map("failed " + _) :+ "none").asJava)
              () => false
      check(Harness(relay, host, sandbox, status, log, () => alive()))
      // Kept after a failure, for its records.
      endAll()
      Using.resource(Files.walk(root))(_.iterator().asScala.toVector.reverse.foreach(Files.deleteIfExists))
    finally if !ended then endAll()

  bothRelays(
    "the probe keeps the first candidate that records and reports each that did not",
    "failing",
    "mute",
    "good",
  ): harness =>
    val lines = harness.awaitStatus()
    assertEquals(lines.last, "recording good", lines.mkString("\n"))
    // The Windows relay's probe returns the candidates' reasons only when none records (probeResident).
    if harness.relay == Relay.Posix then
      assertEquals(
        lines.filter(_.startsWith("failed ")),
        Vector(
          "failed failing: exited with status 2 (rec FAIL formats: can't open input)",
          "failed mute: delivered no audio within 3 s",
        ),
      )
    assert(!lines.contains("silent"))
    // The probe keeps a count, never the audio: no file of the job's holds a period.
    val kept = Using.resource(Files.list(harness.status.resolveSibling("job")))(
      _.iterator().asScala.filter(Files.isRegularFile(_)).toVector,
    )
    assert(kept.forall(Files.size(_) < 640), kept.map(file => s"$file ${Files.size(file)}").mkString("\n"))

  bothRelays(
    "a probe whose first moment is exact silence warns and keeps the recorder",
    "silent",
  ): harness =>
    assertEquals(
      MicrophoneRelay.probeOutcome(harness.awaitStatus()),
      Some(MicrophoneRelay.ProbeOutcome.Recording("silent", silent = true)),
    )

  bothRelays(
    "no candidate that records ends the probe with none",
    "failing",
  ): harness =>
    val outcome = MicrophoneRelay.probeOutcome(harness.awaitStatus())
    assertEquals(
      outcome,
      Some(
        MicrophoneRelay.ProbeOutcome.Failed(
          Vector("failing: exited with status 2 (rec FAIL formats: can't open input)"),
        ),
      ),
    )

  bothRelays(
    "a request's capture starts at the request, reaches the exec only from ready, and leaves nothing for the next",
    "good",
  ): harness =>
    assertEquals(harness.awaitStatus().last, "recording good")
    // While idle the drain keeps nothing: the capture begins at the request, not at the launch.
    Thread.sleep(1500)
    Files.writeString(harness.host.resolve("ready-delay"), "0.6")
    val requestedAt = harness.latestPeriod
    harness.request()
    awaitTrue("forwarded audio")(harness.capture(1).length >= 640 * 60)
    assertEquals(harness.beforeReady(1), Some(0L), "audio reached the exec before its ready")
    val first = indices(harness.capture(1))
    assert(consecutive(first), s"a gap or repeat: ${first.take(80)}")
    // The 0.6 s before `ready` are 30 periods: the capture starts at the request, not after them.
    assert((first.head - requestedAt + Periods) % Periods <= 8, s"requested at $requestedAt, began at ${first.head}")

    // The controller ends the writer; the next request's capture begins at its own request,
    // with no byte the first exec left behind.
    harness.endWriter()
    Files.writeString(harness.host.resolve("ready-delay"), "0")
    Thread.sleep(1500)
    val secondAt = harness.latestPeriod
    harness.request()
    awaitTrue("the second request's audio")(harness.capture(2).length >= 640 * 20)
    val second = indices(harness.capture(2))
    assert(consecutive(second), s"a gap or repeat: ${second.take(80)}")
    assert((second.head - secondAt + Periods) % Periods <= 8, s"requested at $secondAt, began at ${second.head}")
    assertEquals(harness.count("starts-good"), 1, "the recorder was started again")

  bothRelays(
    "a stale start costs one exec and forwards nothing, and a refused line is logged and skipped",
    "good",
  ): harness =>
    harness.awaitStatus()
    Files.writeString(harness.host.resolve("stale"), "")
    harness.request()
    awaitTrue("the stale exec")(harness.count("execs") == 1)
    Thread.sleep(500)
    assertEquals(harness.capture(1).length, 0)
    harness.request("junk")
    awaitTrue("the refusal in the log")(harness.logText.contains("refused a request other than start"))
    Files.delete(harness.host.resolve("stale"))
    harness.request()
    awaitTrue("the next request's audio")(harness.capture(2).length >= 640 * 10)
    assert(consecutive(indices(harness.capture(2))))

  bothRelays(
    "a recorder that stops delivering is ended and logged, and the next request starts it again",
    "stalling",
  ): harness =>
    assertEquals(harness.awaitStatus().last, "recording stalling")
    awaitTrue("the stall in the log", seconds = 15)(harness.logText.contains("delivered no audio for 5 s"))
    harness.request()
    awaitTrue("a second start")(harness.count("starts-stalling") == 2)
    awaitTrue("the restarted recorder's audio")(harness.capture(1).length >= 640 * 10)

  bothRelays(
    "the relay ends when the container stops, its log naming the recorder and the first sound",
    "good",
  ): harness =>
    harness.awaitStatus()
    harness.request()
    awaitTrue("forwarded audio")(harness.capture(1).length > 0)
    // The forwarding ends with the container's exec, and the relay finds the container stopped.
    Files.writeString(harness.host.resolve("stopped"), "")
    harness.endWriter()
    awaitTrue("the relay's end")(!harness.alive())
    assert(harness.logText.contains("recording with good"), harness.logText)
    // The indexed periods begin with one of zeros.
    assert(harness.logText.contains(MicrophoneRelay.firstSoundLine(640)), harness.logText)

  bothRelays(
    "a writer slower than the bound forwards nothing, is logged, and the next request records",
    "good",
  ): harness =>
    harness.awaitStatus()
    // Past the two seconds the recorder's FIFO holds and past the relay's bound.
    Files.writeString(harness.host.resolve("ready-delay"), "12")
    harness.request()
    // The POSIX relay's recorder blocks on its full FIFO, and its supervisor ends it; the Windows
    // relay keeps the audio in memory and gives up at the bound.
    val failure = harness.relay match
      case Relay.Posix   => "delivered no audio for 5 s"
      case Relay.Windows => "the writer did not answer within 10 s"
    awaitTrue(s"`$failure` in the log", seconds = 20)(harness.logText.contains(failure))
    assertEquals(harness.capture(1).length, 0, "audio reached a writer that never answered")
    Files.writeString(harness.host.resolve("ready-delay"), "0")
    harness.request()
    awaitTrue("the next request's audio")(harness.capture(2).length >= 640 * 10)
    assert(consecutive(indices(harness.capture(2))))

  bothRelays(
    "a daemon that stops reading ends the recorder and the forwarding, and the next request records",
    "good",
  ): harness =>
    harness.awaitStatus()
    harness.request()
    awaitTrue("forwarded audio")(harness.capture(1).length >= 640 * 10)
    val writer = Files.readString(harness.host.resolve("writer.pid")).trim
    ProcessBuilder("kill", "-STOP", writer).start().waitFor()
    awaitTrue("the stall in the log", seconds = 20)(harness.logText.contains("delivered no audio for 5 s"))
    // Reading again: a TERM the stopped writer holds pending ends it now.
    ProcessBuilder("kill", "-CONT", writer).start().waitFor()
    harness.request()
    awaitTrue("a second start")(harness.count("starts-good") == 2)
    awaitTrue("the next request's audio")(harness.capture(2).length >= 640 * 10)
    assert(consecutive(indices(harness.capture(2))))

  bothRelays(
    "the launch recorder's first sound is logged as audio time, after a silent start too",
    "late",
  ): harness =>
    assertEquals(
      MicrophoneRelay.probeOutcome(harness.awaitStatus()),
      Some(MicrophoneRelay.ProbeOutcome.Recording("late", silent = true)),
    )
    // 100 periods of zeros, then the indexed periods, whose first is zeros too: 101 periods, 2020 ms.
    awaitTrue("the first sound in the log")(harness.logText.contains(MicrophoneRelay.firstSoundLine(101 * 640)))

  test("a relay directory the POSIX relay cannot write fails the probe, naming the directory"):
    run(Relay.Posix, Vector("good"), jobWritable = false): harness =>
      val lines = harness.awaitStatus()
      assert(lines.exists(_.startsWith("failed relay: could not make a FIFO in ")), lines.mkString("\n"))
      assertEquals(lines.last, "none")

  test("the Windows relay's recorders end with the launcher, and none starts after"):
    assume(onPath("sleep"), "needs sleep on PATH")
    // The run-on-host Seatbelt profile grants no `signal`, so there this JVM cannot end its child.
    val probe = ProcessBuilder("sleep", "10").start()
    probe.destroyForcibly()
    assume(probe.waitFor(2, java.util.concurrent.TimeUnit.SECONDS), "needs to end its own child process")
    val hooks = Vector.newBuilder[Thread]
    val owner = MicrophoneRelay.Recorders(register = hooks += _)
    val running = owner.start(Vector("sleep", "60")).getOrElse(fail("the recorder did not start"))
    val registered = hooks.result()
    assertEquals(registered.length, 1, "the hook, registered by the first start")
    registered.head.run()
    assert(running.waitFor(5, java.util.concurrent.TimeUnit.SECONDS), "the recorder outlived the hook")
    assertEquals(owner.start(Vector("sleep", "60")), None, "a recorder started after the hook ran")

  test("a resident recorder the shutdown overtakes never starts"):
    val marker = Files.createTempDirectory("microphone-recorders").resolve("started")
    val owner = MicrophoneRelay.Recorders(register = _ => throw IllegalStateException("Shutdown in progress"))
    assertEquals(owner.start(Vector("sh", "-c", s"touch '$marker'")), None)
    Thread.sleep(200)
    assert(!Files.exists(marker), "a recorder started during the shutdown")
    Files.delete(marker.getParent)

  test("the launch probe's candidates on each OS, in order, a refusal naming the package, and a failure naming " +
    "each reason and its next step"):
    val bin = Files.createTempDirectory("microphone-candidates").toRealPath()
    Vector("rec", "sox_ng.exe", "arecord", "parecord").foreach(name => executable(bin.resolve(name), "#!/bin/sh\n"))
    def commands(os: HostCommands.Os): Vector[Vector[String]] =
      MicrophoneRelay.recorders(os, bin.toString).fold(fail(_), _.map(_.command))
    // Each command names its mode, since the path resolved is the canonical file.
    assertEquals(commands(HostCommands.Os.Mac).map(_.head), Vector(bin.resolve("rec").toString))
    assertEquals(commands(HostCommands.Os.Windows).map(_.head), Vector(bin.resolve("sox_ng.exe").toString))
    assert(commands(HostCommands.Os.Windows).head.contains("-d"), "sox_ng without its default device")
    assertEquals(
      commands(HostCommands.Os.Linux).map(command => command.take(2)),
      Vector(Vector(bin.resolve("arecord").toString, "-C"), Vector(bin.resolve("parecord").toString, "--record")),
    )
    Files.delete(bin.resolve("arecord"))
    assertEquals(commands(HostCommands.Os.Linux).map(_.head), Vector(bin.resolve("parecord").toString))
    val packages = Map(
      HostCommands.Os.Mac     -> "brew install sox_ng",
      HostCommands.Os.Windows -> "winget install --id sox_ng.sox_ng -e",
      HostCommands.Os.Linux   -> "pulseaudio-utils",
    )
    // A recorder that failed is installed: its next step is the cause's, never installing it again.
    val nextSteps = Map(
      HostCommands.Os.Mac     -> "Privacy & Security > Microphone",
      HostCommands.Os.Windows -> "change what the lines above name",
      HostCommands.Os.Linux   -> "pulseaudio-utils",
    )
    val empty = Files.createTempDirectory("microphone-no-candidates").toRealPath()
    packages.foreach: (os, name) =>
      val refusal = MicrophoneRelay.recorders(os, empty.toString).left.getOrElse(fail(s"$os found a recorder"))
      assert(refusal.contains(name), refusal)
      val message = MicrophoneRelay.failureMessage(
        Vector("first: exited with status 1 (its last word)", "second: delivered no audio within 10 s"),
        os,
        Vector("a diagnosis"),
      )
      Vector("first: exited with status 1 (its last word)", "second: delivered no audio", "a diagnosis", nextSteps(os))
        .foreach(part => assert(message.contains(part), s"$os: $message"))
      if os != HostCommands.Os.Linux then assert(!message.contains(name), s"$os: $message")
    assert(
      MicrophoneRelay.failureMessage(Vector("sox_ng: exited with status 2"), HostCommands.Os.Windows)
        .contains("Settings > System > Sound > Input"),
      "a Windows failure the diagnosis cannot explain",
    )
    Using.resource(Files.walk(bin))(_.iterator().asScala.toVector.reverse.foreach(Files.deleteIfExists))
    Files.delete(empty)

  test("a failed Windows probe is explained by the endpoint count, the default device and the permission values"):
    def diagnosis(endpoints: String, permissions: String): Vector[String] =
      MicrophoneRelay.windowsDiagnosis(s"endpoints $endpoints\npermissions $permissions\n")
    assert(diagnosis("0 nodefault", "Allow Allow Allow").head.contains("no active capture device"))
    assert(diagnosis("1 nodefault", "Allow Allow Allow").head.contains("no default communications capture device"))
    assertEquals(diagnosis("1 default", "Allow Allow Allow"), Vector.empty)
    // A Deny in any value, and an absent per-user value, stop the recorder; the first such names its switch.
    assert(diagnosis("1 default", "Deny Allow Allow").head.contains("Microphone access is off"))
    assert(diagnosis("1 default", "absent Allow Allow").head.contains("Microphone access is off"))
    assert(diagnosis("1 default", "Allow Deny Deny").head.contains("Let desktop apps access your microphone"))
    assert(diagnosis("1 default", "Allow Allow Deny").head.contains("machine-wide microphone policy"))
    // An absent NonPackaged or machine-wide value leaves the recorder recording.
    assertEquals(diagnosis("1 default", "Allow absent absent"), Vector.empty)
    assertEquals(diagnosis("0 nodefault", "Deny Allow Allow").length, 2, "the endpoints, then the permission")
    // Through the script's runner, with a stand-in that answers as the script prints.
    val dir = Files.createTempDirectory("microphone-diagnostics").toRealPath()
    val powershell = dir.resolve("powershell")
    executable(powershell, "#!/bin/sh\nprintf 'endpoints 0 nodefault\\npermissions Allow Allow Allow\\n'\n")
    assertEquals(MicrophoneRelay.windowsDiagnostics(powershell), diagnosis("0 nodefault", "Allow Allow Allow"))
    executable(powershell, "#!/bin/sh\nexit 1\n")
    assertEquals(MicrophoneRelay.windowsDiagnostics(powershell), Vector.empty, "a script that failed explains nothing")
    Files.delete(powershell)
    Files.delete(dir)
