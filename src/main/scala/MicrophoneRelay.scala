// The host microphone under --mic: the recorder programs each host runs, the launch probe, the
// POSIX relay's shell (a job of the reaper, SandboxLifecycle), and the Windows relay (threads of the
// resident launcher). The sandbox side is the image's ko-sandbox-mic and its PulseAudio daemon;
// SECURITY.md "Microphone" has what the channel grants, doc/microphone.md the design.

package agentsandbox.launcher

import java.io.{IOException, InputStream, OutputStream}
import java.nio.charset.StandardCharsets.{UTF_16LE, UTF_8}
import java.nio.file.{Files, Path, StandardOpenOption}
import java.time.Instant
import java.util.concurrent.TimeUnit

import HostCommands.{ExecWithInput, Os, findOnPath, quoteFreeSh, run}

object MicrophoneRelay:

  /**
   * The channel's directory under the sandbox's /tmp: the daemon's FIFO `mic` (the image's
   * microphone.pa spells it), the request FIFO `req` the relay's first exec makes, the writer's pid
   * file, and the daemon's three configuration directories, its socket in `pulse-runtime`.
   */
  val SandboxDir = "/tmp/ko-agent-sandbox/microphone"

  val MicVariable = "KO_AGENT_SANDBOX_MIC"

  /**
   * The variables the sandbox gets under --mic; doc/microphone.md, "The daemon", has why the
   * PULSE_* ones. No SOX_OPTS: the CLI's `rec` overrides its `--buffer`, and the image's SoX writes
   * 4096 bytes at a time either way (doc/microphone.md, "Latency").
   */
  def sandboxEnvironment(sandboxDir: String = SandboxDir): Vector[(String, String)] =
    Vector(
      MicVariable -> "on",
      "PULSE_SERVER" -> s"unix:$sandboxDir/pulse-runtime/native",
      "PULSE_CONFIG_PATH" -> s"$sandboxDir/pulse-config",
      "PULSE_STATE_PATH" -> s"$sandboxDir/pulse-state",
      "PULSE_RUNTIME_PATH" -> s"$sandboxDir/pulse-runtime",
      "PULSE_COOKIE" -> s"$sandboxDir/pulse-config/cookie",
    )

  /** One request per exec: the first line written to `req`, whatever a writer adds after it. */
  def sandboxRequestReader(sandboxDir: String = SandboxDir): String =
    s"trap \"\" INT HUP TERM; d=$sandboxDir; mkdir -p -m 700 $$d; " +
      s"[ -p $$d/req ] || mkfifo -m 600 $$d/req; head -n 1 $$d/req"

  /** The writer's command line inside the sandbox, run with [[HostCommands.ExecWithInput]] and no shell. */
  def writerCommand(sandboxDir: String = SandboxDir): Vector[String] =
    Vector("ko-sandbox-mic", "write", s"$sandboxDir/mic")

  /** What the host reads of one request exec's output: `start` and its newline, with room. */
  val MaxRequestBytes = 64

  // -------------------------------------------------------------------------
  // The recorders
  // -------------------------------------------------------------------------

  /**
   * A recorder program writing raw signed 16-bit little-endian mono at 16000 Hz to stdout, by the
   * path findOnPath resolved. Each command names its mode, since findOnPath canonicalizes:
   * `arecord` is a link to `aplay`, `parecord` to `pacat`, Homebrew's `rec` to `sox`, and each of
   * those decides by its name what it does.
   */
  final case class Recorder(label: String, command: Vector[String])

  /**
   * SoX writes its output in `--buffer`-sized blocks, 8192 bytes by default, which is 256 ms of
   * this stream; 640 bytes is one 20 ms period. `-D`: SoX dithers its 16-bit output by default,
   * which turns a silent input into samples of plus and minus one; the probe's silence warning
   * reads exact zeros.
   */
  private val SoxOutput = Vector("-q", "-D", "--buffer", "640")
  private val RawStream = Vector("-t", "raw", "-r", "16000", "-e", "signed", "-b", "16", "-c", "1", "-")

  /** What the launch error names when no candidate is on PATH, or none records. */
  def packageHint(os: Os): String = os match
    case Os.Mac => "install sox_ng (`brew install sox_ng`, or sox), which provides rec"
    case Os.Windows =>
      "put sox_ng.exe on PATH, from https://codeberg.org/sox_ng/sox_ng/releases or " +
        "`winget install --id sox_ng.sox_ng -e`"
    case _ => "install alsa-utils, which provides arecord, or pulseaudio-utils, which provides parecord"

  /**
   * The candidates on this host's PATH, in probe order. On Linux `arecord` on ALSA's `default`
   * PCM first, one command whichever server owns the microphone where the desktop routes
   * `default` to it, then `parecord` for a host where it does not, as on WSLg.
   */
  def recorders(os: Os, pathValue: String): Either[String, Vector[Recorder]] =
    def found(name: String): Option[Path] = findOnPath(name, pathValue, os)
    val candidates = os match
      case Os.Mac =>
        found("rec").map: path =>
          // A file named rec records from the default device itself; any other name needs -d.
          val device = if path.getFileName.toString == "rec" then Vector.empty else Vector("-d")
          Recorder("rec", (path.toString +: SoxOutput) ++ device ++ RawStream)
        .toVector
      case Os.Windows =>
        found("sox_ng").map(path => Recorder("sox_ng", ((path.toString +: SoxOutput) :+ "-d") ++ RawStream)).toVector
      case _ =>
        found("arecord").map: path =>
          Recorder(
            "arecord",
            Vector(
              path.toString, "-C", "-q", "-D", "default", "-t", "raw", "-f", "S16_LE", "-r", "16000", "-c", "1",
              "-B", "80000", "-F", "20000",
            ),
          )
        .toVector ++ found("parecord").map: path =>
          Recorder(
            "parecord",
            Vector(
              path.toString, "--record", "--raw", "--format=s16le", "--rate=16000", "--channels=1",
              "--latency-msec=20",
            ),
          )
        .toVector
    if candidates.isEmpty then Left(s"error: --mic needs a recorder on this host; ${packageHint(os)}")
    else
      candidates.find(_.command.exists(word => word.contains(WordSeparator) || word.contains('\n'))) match
        case Some(recorder) =>
          Left(
            s"error: --mic cannot run ${recorder.command.head}: its path holds a control character; " +
              "move or link the recorder to a path without one, ahead on PATH",
          )
        case None           => Right(candidates)

  // The POSIX relay receives each command as one argument split at this separator.
  private val WordSeparator = '\u001f'

  def encodedCandidate(recorder: Recorder): String = recorder.command.mkString(WordSeparator.toString)

  // -------------------------------------------------------------------------
  // The launch probe, read by the launcher
  // -------------------------------------------------------------------------

  /** How long a candidate may take to deliver its first bytes; on macOS this spans the
    * microphone permission prompt the first recording raises. */
  def probeBoundSeconds(os: Os): Int = if os == Os.Mac then 60 else 10

  /** On macOS, how long without bytes before the launch says it waits for the prompt. */
  val PromptNoticeSeconds = 3

  /**
   * The probe's moment, in reads of at most one 20 ms period: about a second. A macOS launch can
   * warn of exact silence and then dictate, at ten reads and at fifty (doc/microphone.md, "The
   * launch").
   */
  val ProbeReads = 50

  /**
   * How far into the launch recorder's audio its first sound came, which both relays log once: the
   * launches that warn of a silent start and then dictate are measured by it (doc/microphone.md,
   * "The launch"). Audio time, 32 bytes a millisecond, from the recorder's first byte; the watch
   * ends at the bound or the first request.
   */
  val FirstSoundPrefix = "the recorder's first sound came after"
  val FirstSoundBoundBytes: Long = 30 * 32_000
  val NoSoundLine = s"the recorder delivered no sound in its first ${FirstSoundBoundBytes / 32_000} s of audio"

  def firstSoundLine(offset: Long): String = s"$FirstSoundPrefix ${offset / 32} ms of its audio"

  enum ProbeOutcome:
    /** The recorder kept for the session; `silent` when its first moment was all zero samples. */
    case Recording(label: String, silent: Boolean)
    case Failed(reasons: Vector[String])

  /**
   * The probe's status lines as the POSIX relay writes them, in order: `waiting` once on macOS,
   * `failed <label>: <reason>` per candidate that did not record, `silent` before the
   * `recording <label>` of the one kept, or `none` after the last failure. None while undecided.
   */
  def probeOutcome(lines: Vector[String]): Option[ProbeOutcome] =
    val failures = lines.collect { case line if line.startsWith("failed ") => line.stripPrefix("failed ") }
    lines.collectFirst {
      case line if line.startsWith("recording ") =>
        ProbeOutcome.Recording(line.stripPrefix("recording "), lines.contains("silent"))
      case "none" => ProbeOutcome.Failed(failures)
    }

  /**
   * Waits for the POSIX relay's probe through its status file, printing the prompt notice when it
   * appears. The bound is the relay's own plus room for its exec and polling; past it the job is
   * taken for dead.
   */
  def awaitProbe(status: Path, os: Os, notice: () => Unit): ProbeOutcome =
    val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(probeBoundSeconds(os) * 2L + 10)
    var noticed = false
    var outcome = Option.empty[ProbeOutcome]
    while outcome.isEmpty do
      val lines =
        try Files.readAllLines(status, UTF_8).toArray.toVector.map(_.toString)
        catch case _: IOException => Vector.empty
      if !noticed && lines.contains("waiting") then
        noticed = true
        notice()
      outcome = probeOutcome(lines)
      if outcome.isEmpty then
        if System.nanoTime() > deadline then
          outcome = Some(ProbeOutcome.Failed(Vector("the relay reported nothing; it may not have started")))
        else Thread.sleep(50)
    outcome.get

  /**
   * The launch error when every candidate on PATH failed, so installing it again is not the step:
   * on macOS the terminal's permission, which an unanswered prompt leaves undecided until the bound;
   * on Windows what the diagnosis names; on Linux the device, or the other recorder.
   */
  def failureMessage(reasons: Vector[String], os: Os, diagnosis: Vector[String] = Vector.empty): String =
    val next = os match
      case Os.Mac =>
        "To record, allow this terminal under System Settings > Privacy & Security > Microphone, answering " +
          "macOS's prompt when it shows, and launch again."
      case Os.Windows =>
        if diagnosis.nonEmpty then "To record, change what the lines above name, and launch again."
        else "To record, check the recording device under Settings > System > Sound > Input, and launch again."
      case Os.Linux =>
        "To record, check that the desktop's microphone works, or install the other of alsa-utils (arecord) " +
          "and pulseaudio-utils (parecord), and launch again."
    (Vector("error: --mic found no recorder that records on this host:") ++ reasons.map(reason => s"  $reason")
      ++ diagnosis.map(line => s"  $line") :+ s"  $next").mkString("\n")

  def silenceWarning(os: Os): String =
    val causes = os match
      case Os.Mac =>
        "a denied permission (System Settings > Privacy & Security > Microphone, for this terminal) and a " +
          "muted input (System Settings > Sound > Input) cause this"
      case Os.Windows => "a muted or disabled input (Settings > System > Sound > Input) causes this"
      case _          => "a muted input or a monitor source causes this"
    s"the microphone delivered exact silence at launch; $causes, and an input with a noise gate is silent " +
      "until spoken into. The first dictation shows which"

  // -------------------------------------------------------------------------
  // The POSIX relay
  // -------------------------------------------------------------------------

  /**
   * `microphone_relay <engine> <sandbox> <dir> <status> <log> <candidate>...`, the engine being the
   * resolved podman, for the reaper to run as a job from before the sandbox starts to its end.
   * `dir` is the job's own directory, mode 0700, which the reaper makes and removes; `status` is
   * the file the launcher reads the probe from ([[awaitProbe]]); `log` is the microphone log; each
   * candidate is [[encodedCandidate]]. Everything it runs is the user's own on the host.
   *
   * The recorder's FIFO is held read-write for the session, so the recorder never meets a closed
   * pipe and no open waits for the other end; Linux and macOS allow that where POSIX leaves it
   * undefined (fifo(7)). Between requests a pump drains it to /dev/null; from a `start` the pump
   * stops and the FIFO keeps what the recorder writes, up to its capacity (64 KiB, 2 s, on Linux),
   * until the writer's `ready`, when the pump copies it into the exec's stdin FIFO, oldest first.
   *
   * The pump copies with dd in batches of 50 reads of at most one period, about a second, and marks
   * each batch: the recorder's supervisor ends a recorder that leaves five seconds unmarked, as one
   * that ended. Children of the reaper inherit its ignored TERM, which a program resets only by
   * installing a handler of its own, so ending a child is TERM, then the tree KILLed after a
   * second ([[SandboxLifecycle.TreeFunctions]]' stop_tree and end_tree).
   */
  def hostShellFunctions(sandboxDir: String = SandboxDir, probeBound: Option[Int] = None): String =
    """# The host microphone, recorded for the session and forwarded while an agent records.
      |microphone_relay() {
      |  mic_engine=$1
      |  mic_sandbox=$2
      |  mic_dir=$3
      |  mic_status=$4
      |  mic_log=$5
      |  shift 5
      |  mic_separator=$(printf '\037')
      |  # For parecord: the probe starts no PulseAudio daemon of its own.
      |  printf 'autospawn = no\n' > "$mic_dir/client.conf"
      |  if ! mkfifo -m 600 "$mic_dir/recorded"; then
      |    printf 'failed relay: could not make a FIFO in %s\nnone\n' "$mic_dir" >> "$mic_status"
      |    return 1
      |  fi
      |  exec 7<> "$mic_dir/recorded"
      |  # In tenths of a second: the poll's unit.
      |  case "$(uname -s)" in
      |    Darwin) mic_bound=""".stripMargin + probeBound.getOrElse(probeBoundSeconds(Os.Mac)) * 10 + """ ;;
      |    *) mic_bound=""".stripMargin + probeBound.getOrElse(probeBoundSeconds(Os.Linux)) * 10 + """ ;;
      |  esac
      |  mic_kept=
      |  for mic_candidate in "$@"; do
      |    mic_record "$mic_candidate"
      |    if mic_probe; then mic_kept=$mic_candidate; break; fi
      |    mic_end "$mic_supervisor"
      |  done
      |  if [ -z "$mic_kept" ]; then echo none >> "$mic_status"; return 1; fi
      |  mic_say "recording with $mic_label"
      |  # Where the launch recorder's first sound came: an exactly silent start, which the probe warns
      |  # of, can end after the launch.
      |  printf '0\n' > "$mic_dir/listening"
      |  mic_heard "$(cat "$mic_dir/probe")"
      |  : > "$mic_dir/watching"
      |  mic_pump drain
      |  mic_running() {
      |    [ "$("$mic_engine" container inspect --format '{{.State.Running}}' "$mic_sandbox" 2>/dev/null)" = true ]
      |  }
      |  until mic_running; do
      |    "$mic_engine" container exists "$mic_sandbox" 2>/dev/null || return 0
      |    sleep 1
      |  done
      |  while mic_running; do
      |    mic_request=$("$mic_engine" exec "$mic_sandbox" sh -c '""".stripMargin + sandboxRequestReader(sandboxDir) +
      s"""' </dev/null 2>/dev/null | head -c $MaxRequestBytes)
      |    case "$$mic_request" in
      |      start) mic_forward ;;
      |      # An exec that failed, or a writer that wrote nothing: a second's pause, not a spin.
      |      '') sleep 1 ;;
      |      *) mic_say "refused a request other than start"; sleep 1 ;;
      |    esac
      |  done
      |}
      |
      |mic_say() { printf '%s %s\\n' "$$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$$*" >> "$$mic_log"; }
      |
      |# TERM, and the tree KILLed if it outlives a second. A pid that is gone is never signalled again.
      |mic_end() {
      |  kill -0 "$$1" 2>/dev/null || return 0
      |  kill -TERM "$$1" 2>/dev/null
      |  mic_i=0
      |  while kill -0 "$$1" 2>/dev/null && [ "$$mic_i" -lt 10 ]; do sleep 0.1; mic_i=$$((mic_i + 1)); done
      |  kill -0 "$$1" 2>/dev/null || return 0
      |  stop_tree "$$1"
      |  end_tree "$$1"
      |}
      |
      |# A recorder and its supervisor, which ends it when it delivers nothing for five seconds once
      |# the probe has passed, and at its end leaves its reason in recorder.ended and ends the
      |# forwarding in progress.
      |mic_record() {
      |  rm -f "$$mic_dir/recorder.ended" "$$mic_dir/flowing"
      |  mic_program=$${1%%"$$mic_separator"*}
      |  mic_label=$${mic_program##*/}
      |  (
      |    IFS=$$mic_separator
      |    set -f
      |    set -- $$1
      |    unset IFS
      |    set +f
      |    PULSE_CLIENTCONFIG="$$mic_dir/client.conf" "$$@" >&7 2>"$$mic_dir/recorder.err" </dev/null 7>&- 8>&- &
      |    recorder=$$!
      |    idle=0
      |    reason=
      |    while kill -0 "$$recorder" 2>/dev/null; do
      |      sleep 1
      |      [ -e "$$mic_dir/watching" ] || continue
      |      if [ -e "$$mic_dir/flowing" ]; then rm -f "$$mic_dir/flowing"; idle=0; else idle=$$((idle + 1)); fi
      |      if [ "$$idle" -ge 5 ]; then reason="delivered no audio for 5 s"; mic_end "$$recorder"; break; fi
      |    done
      |    wait "$$recorder"
      |    status=$$?
      |    # The last line: SoX warns on stderr before it fails, under -q too.
      |    stderr_line=$$(grep . "$$mic_dir/recorder.err" 2>/dev/null | tail -n 1 | tr -cd '[:print:]' | head -c 200)
      |    reason="$${reason:-exited with status $$status}$${stderr_line:+ ($$stderr_line)}"
      |    [ -e "$$mic_dir/watching" ] && mic_say "the recorder $$mic_label $$reason; the next request starts it again"
      |    printf '%s\\n' "$$reason" > "$$mic_dir/recorder.ended"
      |    forwarding=$$(cat "$$mic_dir/exec.pid" 2>/dev/null)
      |    if [ -n "$$forwarding" ]; then mic_end "$$forwarding"; fi
      |  ) &
      |  mic_supervisor=$$!
      |}
      |
      |# The first bytes within the bound, read as ProbeReads reads of at most one period: success,
      |# a warning when they are all zero, or the candidate's failure. What it keeps is where the first
      |# sound came, never the audio.
      |mic_probe() {
      |  (dd bs=640 count=$ProbeReads <&7 2>/dev/null | mic_sound 0 >"$$mic_dir/probe") &
      |  mic_reader=$$!
      |  mic_i=0
      |  while kill -0 "$$mic_reader" 2>/dev/null; do
      |    if [ -e "$$mic_dir/recorder.ended" ] || [ "$$mic_i" -ge "$$mic_bound" ]; then
      |      stop_tree "$$mic_reader"
      |      end_tree "$$mic_reader"
      |      wait "$$mic_reader" 2>/dev/null
      |      if [ -e "$$mic_dir/recorder.ended" ]; then mic_reason=$$(cat "$$mic_dir/recorder.ended")
      |      else mic_reason="delivered no audio within $$((mic_bound / 10)) s"; fi
      |      echo "failed $$mic_label: $$mic_reason" >> "$$mic_status"
      |      return 1
      |    fi
      |    # On macOS only, the one host whose bound exceeds Linux's.
      |    if [ "$$mic_i" -eq ${PromptNoticeSeconds * 10} ] && [ "$$mic_bound" -gt ${probeBoundSeconds(Os.Linux) * 10} ]
      |    then echo waiting >> "$$mic_status"; fi
      |    sleep 0.1
      |    mic_i=$$((mic_i + 1))
      |  done
      |  wait "$$mic_reader"
      |  case "$$(cat "$$mic_dir/probe")" in silence*) echo silent >> "$$mic_status" ;; esac
      |  echo "recording $$mic_label" >> "$$mic_status"
      |  return 0
      |}
      |
      |# drain: to /dev/null; forward: into the exec's stdin FIFO, held as fd 8. While `listening`
      |# holds the bytes the launch recorder has delivered without a sound, a drained batch is read
      |# for the first one instead.
      |mic_pump() {
      |  (
      |    while :; do
      |      if [ "$$1" = forward ]; then dd bs=640 count=50 <&7 >&8 2>/dev/null || exit
      |      elif [ -e "$$mic_dir/listening" ]; then
      |        mic_seen=$$(cat "$$mic_dir/listening")
      |        mic_heard "$$(dd bs=640 count=50 <&7 2>/dev/null | mic_sound "$$mic_seen")" || exit
      |      else dd bs=640 count=50 <&7 >/dev/null 2>/dev/null || exit; fi
      |      : > "$$mic_dir/flowing"
      |    done
      |  ) &
      |  mic_pump_pid=$$!
      |}
      |
      |# `sound <offset>` of the first nonzero byte on stdin, counted from the recorder's first byte
      |# with $$1 bytes before it, or `silence <bytes>` with stdin's added.
      |mic_sound() {
      |  od -An -v -tu1 | awk -v seen="$$1" '
      |    { for (i = 1; i <= NF; i++) { if ($$i != 0) { print "sound", seen + n; found = 1; exit } n++ } }
      |    END { if (!found) print "silence", seen + n }'
      |}
      |
      |# What mic_sound found, logged once: the first sound, or none within the bound. Fails on a
      |# batch that read nothing.
      |mic_heard() {
      |  case "$$1" in
      |    "sound "*)
      |      rm -f "$$mic_dir/listening"
      |      mic_say "$FirstSoundPrefix $$((($${1#sound }) / 32)) ms of its audio" ;;
      |    "silence "*)
      |      [ "$${1#silence }" = "$$(cat "$$mic_dir/listening" 2>/dev/null)" ] && return 1
      |      if [ "$${1#silence }" -ge $FirstSoundBoundBytes ]; then
      |        rm -f "$$mic_dir/listening"
      |        mic_say "$NoSoundLine"
      |      else printf '%s\\n' "$${1#silence }" > "$$mic_dir/listening"; fi ;;
      |    *) return 1 ;;
      |  esac
      |}
      |
      |mic_stop_pump() {
      |  stop_tree "$$mic_pump_pid"
      |  end_tree "$$mic_pump_pid"
      |  wait "$$mic_pump_pid" 2>/dev/null
      |}
      |
      |# One request: the writer's exec, its stdin a FIFO nothing writes until its `ready`, since
      |# podman reads the stdin it is given whether or not the process reads it; a stale start's
      |# exec ends without `ready` and forwards nothing. A new FIFO per request, so a byte one exec
      |# left unread never reaches the next.
      |mic_forward() {
      |  rm -f "$$mic_dir/listening"
      |  [ -e "$$mic_dir/recorder.ended" ] && mic_record "$$mic_kept"
      |  mic_stop_pump
      |  rm -f "$$mic_dir/exec-in" "$$mic_dir/exec.out"
      |  mkfifo -m 600 "$$mic_dir/exec-in"
      |  exec 8<> "$$mic_dir/exec-in"
      |  "$$mic_engine" ${ExecWithInput.mkString(" ")} "$$mic_sandbox" ${writerCommand(sandboxDir).mkString(" ")} \\
      |    <"$$mic_dir/exec-in" >"$$mic_dir/exec.out" 2>>"$$mic_log" 7>&- &
      |  mic_exec=$$!
      |  echo "$$mic_exec" > "$$mic_dir/exec.pid"
      |  mic_i=0
      |  mic_ready=
      |  while :; do
      |    mic_out=$$(head -c 16 "$$mic_dir/exec.out" 2>/dev/null)
      |    case "$$mic_out" in
      |      ready) mic_ready=yes; break ;;
      |      ''|r|re|rea|read) ;;
      |      *) mic_say "the writer answered other than ready"; break ;;
      |    esac
      |    # Ended before `ready`: a stale start, whose stream had closed.
      |    kill -0 "$$mic_exec" 2>/dev/null || break
      |    if [ "$$mic_i" -ge 200 ]; then mic_say "the writer did not answer within 10 s"; break; fi
      |    sleep 0.05
      |    mic_i=$$((mic_i + 1))
      |  done
      |  if [ -n "$$mic_ready" ]; then
      |    mic_pump forward
      |    wait "$$mic_exec"
      |    rm -f "$$mic_dir/exec.pid"
      |    mic_stop_pump
      |  else
      |    # Only an exec still alive: one this shell has reaped may have handed its pid on.
      |    kill -0 "$$mic_exec" 2>/dev/null && mic_end "$$mic_exec"
      |    wait "$$mic_exec" 2>/dev/null
      |    rm -f "$$mic_dir/exec.pid"
      |  fi
      |  exec 8<&-
      |  rm -f "$$mic_dir/exec-in" "$$mic_dir/exec.out"
      |  mic_pump drain
      |}
      |
      |""".stripMargin

  // -------------------------------------------------------------------------
  // The Windows relay
  // -------------------------------------------------------------------------
  //
  // Windows has no reaper — the launcher stays resident — so the relay is threads of the launcher:
  // the recorder its child for the session, a pump reading the recorder's output, a request loop,
  // and a watchdog. Windows has no SIGTERM: Process.destroy() is TerminateProcess.

  /** The recorder's output, read for the session: dropped while idle, kept from a request on, and
    * forwarded from the writer's `ready`, what was kept first. */
  private[launcher] final class Pump(val process: Process, val label: String):
    private var kept: Option[java.io.ByteArrayOutputStream] = None
    private var target: Option[OutputStream] = None
    @volatile var lastBytes: Long = System.nanoTime()
    @volatile private var latestStderrLine: String = ""
    private var probeNonzero = 0L
    private var probeReads = 0
    // The first-sound watch: bytes delivered, and where the first nonzero one came; a request ends it.
    @volatile private var listening = true
    @volatile private var delivered = 0L
    @volatile var firstSound: Option[Long] = None

    private val firstSoundLogged = java.util.concurrent.atomic.AtomicBoolean(false)

    /** Logs what the watch found, once it has: the first sound, or none within the bound. Not under
      * this pump's monitor, which a write blocked on a stopped writer holds. */
    def logFirstSound(log: Path): Unit =
      firstSound.map(firstSoundLine).orElse(Option.when(delivered >= FirstSoundBoundBytes)(NoSoundLine)).foreach:
        line => if firstSoundLogged.compareAndSet(false, true) then say(log, line)
    private val probed = java.util.concurrent.CompletableFuture[Boolean]()

    private val stderrReader = Thread(() => readStderr(process.getErrorStream), "ko-agent-sandbox-microphone-stderr")

    def start(): Unit =
      val reading = Thread(() => pump(process.getInputStream), "ko-agent-sandbox-microphone-pump")
      reading.setDaemon(true)
      reading.start()
      stderrReader.setDaemon(true)
      stderrReader.start()

    /** Whether the recorder's output ended before the probe's last read. */
    def endedEarly: Boolean = probed.isCompletedExceptionally

    /** The recorder's last stderr line once the recorder has ended, and its stderr with it. */
    def lastStderrLine(): String =
      stderrReader.join(1000)
      latestStderrLine

    /** Whether the first [[ProbeReads]] reads, as the POSIX relay's probe reads them, were all zero
      * bytes; None if the recorder ended or the bound passed first. Like the POSIX relay, it keeps
      * the count of nonzero bytes, never the audio. */
    def firstMomentSilent(seconds: Int): Option[Boolean] =
      try Some(probed.get(seconds.toLong, TimeUnit.SECONDS))
      catch case _: Exception => None

    def keep(): Unit = synchronized {
      listening = false
      kept = Some(java.io.ByteArrayOutputStream())
      target = None
    }

    /** From `ready`: what was kept, then the live stream. */
    def forward(out: OutputStream): Unit = synchronized {
      try
        kept.foreach(_.writeTo(out))
        out.flush()
        target = Some(out)
      catch case _: IOException => target = None
      kept = None
    }

    def idle(): Unit = synchronized { kept = None; target = None }

    private def pump(in: InputStream): Unit =
      val buffer = new Array[Byte](640)
      try
        var count = in.read(buffer)
        while count >= 0 do
          lastBytes = System.nanoTime()
          if listening && firstSound.isEmpty && delivered < FirstSoundBoundBytes then
            val index = buffer.indexWhere(_ != 0)
            if index >= 0 && index < count then firstSound = Some(delivered + index)
            delivered += count
          if !probed.isDone then
            probeNonzero += buffer.iterator.take(count).count(_ != 0)
            probeReads += 1
            if probeReads >= ProbeReads then probed.complete(probeNonzero == 0)
          synchronized {
            kept.foreach(_.write(buffer, 0, count))
            target.foreach: out =>
              try
                out.write(buffer, 0, count)
                out.flush()
              catch case _: IOException => target = None
          }
          count = in.read(buffer)
      catch case _: IOException => ()
      // Ended before its last probe read: the POSIX relay's probe fails such a recorder too.
      probed.completeExceptionally(IOException("the recorder ended"))

    private def readStderr(err: InputStream): Unit =
      try
        val reader = java.io.BufferedReader(java.io.InputStreamReader(err, UTF_8))
        var line = reader.readLine()
        while line != null do
          if line.trim.nonEmpty then latestStderrLine = line.trim.filter(c => c >= ' ' && c != 127).take(200)
          line = reader.readLine()
      catch case _: IOException => ()

  def say(log: Path, message: String): Unit =
    try
      Files.writeString(
        log, s"${Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS)} $message\n", UTF_8,
        StandardOpenOption.CREATE, StandardOpenOption.APPEND,
      )
    catch case _: IOException => ()

  /**
   * The recorders this launcher started, ended by one shutdown hook whichever way the launcher
   * ends: during the probe, on a failed launch, or with the session. Windows ends no child with
   * its parent, and a recorder waiting on its device need not notice its reader is gone.
   *   - The hook is registered before the first recorder starts. A start during the shutdown
   *     starts nothing once the JDK refuses the registration or the hook has run; a recorder
   *     started before the hook runs is ended by it.
   *   - `register` adds the hook; a test passes its own to run it.
   */
  private[launcher] final class Recorders(register: Thread => Unit = Runtime.getRuntime.addShutdownHook(_)):
    private val live = java.util.concurrent.ConcurrentHashMap.newKeySet[Process]()
    private var registered = false
    private var ended = false

    def start(command: Seq[String]): Option[Process] = synchronized {
      try
        if !registered then
          register(Thread(() => endAll(), "ko-agent-sandbox-microphone-recorders"))
          registered = true
        Option.unless(ended):
          val process = ProcessBuilder(command*).start()
          live.add(process)
          process.getOutputStream.close()
          process.onExit().thenRun(() => live.remove(process))
          process
      catch case _: IOException | _: IllegalStateException => None
    }

    def endAll(): Unit = synchronized {
      ended = true
      live.forEach(_.destroyForcibly())
    }

  private val liveRecorders = Recorders()

  private def startRecorder(recorder: Recorder): Option[Pump] =
    liveRecorders.start(recorder.command).map: process =>
      val pump = Pump(process, recorder.label)
      pump.start()
      pump

  /** The recorder the resident probe kept, running for the session; `silent` when its first moment
    * was all zero samples. */
  final class Kept private[launcher] (val recorder: Recorder, val silent: Boolean, private[launcher] val pump: Pump)

  /** The resident probe: the first candidate whose recorder delivers bytes within the bound, else
    * each candidate's reason. */
  def probeResident(candidates: Vector[Recorder], boundSeconds: Int, log: Path): Either[Vector[String], Kept] =
    var reasons = Vector.empty[String]
    var kept = Option.empty[Kept]
    val remaining = candidates.iterator
    while kept.isEmpty && remaining.hasNext do
      val recorder = remaining.next()
      startRecorder(recorder) match
        case None => reasons :+= s"${recorder.label}: could not be started"
        case Some(pump) =>
          pump.firstMomentSilent(boundSeconds) match
            case Some(silent) =>
              say(log, s"recording with ${recorder.label}")
              pump.logFirstSound(log)
              kept = Some(Kept(recorder, silent, pump))
            case None =>
              // The output's end can arrive before the process's: an ended output waits for its status.
              val ended = pump.endedEarly && pump.process.waitFor(5, TimeUnit.SECONDS)
              pump.process.destroyForcibly()
              pump.process.waitFor(5, TimeUnit.SECONDS)
              val stderrSuffix = Option(pump.lastStderrLine()).filter(_.nonEmpty).fold("")(line => s" ($line)")
              val reason =
                if ended then s"exited with status ${pump.process.exitValue()}$stderrSuffix"
                else s"delivered no audio within $boundSeconds s$stderrSuffix"
              reasons :+= s"${recorder.label}: $reason"
    kept.toRight(reasons)

  /**
   * The Windows relay for the session, from the probe's recorder: the request loop and the
   * watchdog, both daemon threads ending when the sandbox stops. The first wait is bounded like the
   * reaper's, for a launcher that never reaches the start.
   */
  def startResident(
    kept: Kept,
    podman: String,
    sandboxContainer: String,
    log: Path,
    sandboxDir: String = SandboxDir,
    stallSeconds: Int = 5,
  ): Thread =
    val relay = Resident(kept.recorder, kept.pump, podman, sandboxContainer, log, sandboxDir, stallSeconds)
    val thread = Thread(() => relay.serve(), "ko-agent-sandbox-microphone")
    thread.setDaemon(true)
    thread.start()
    thread

  private final class Resident(
    recorder: Recorder,
    firstPump: Pump,
    podman: String,
    sandboxContainer: String,
    log: Path,
    sandboxDir: String,
    stallSeconds: Int,
  ):
    @volatile private var pump: Option[Pump] = Some(firstPump)
    @volatile private var exec: Option[Process] = None
    @volatile private var stopped = false

    private def running(): Boolean =
      try run(podman, "container", "inspect", "--format", "{{.State.Running}}", sandboxContainer).text == "true"
      catch case _: IOException => false

    def serve(): Unit =
      val watchdog = Thread(() => watch(), "ko-agent-sandbox-microphone-watchdog")
      watchdog.setDaemon(true)
      watchdog.start()
      var waited = 0
      while !running() && waited < 600 do
        Thread.sleep(1000)
        waited += 1
      while running() do
        val request =
          try readRequest()
          catch case _: IOException => ""
        request match
          case "start\n" | "start" => forward()
          case ""                  => Thread.sleep(1000)
          case _ =>
            say(log, "refused a request other than start")
            Thread.sleep(1000)
      stopped = true
      pump.foreach(_.process.destroyForcibly())

    private def readRequest(): String =
      val command = Seq(podman, "exec", sandboxContainer) ++ quoteFreeSh(sandboxRequestReader(sandboxDir))
      val reader = ProcessBuilder(command*)
        .redirectError(ProcessBuilder.Redirect.DISCARD)
        .start()
      reader.getOutputStream.close()
      val bytes = reader.getInputStream.readNBytes(MaxRequestBytes)
      if bytes.length == MaxRequestBytes then reader.destroy()
      reader.waitFor()
      String(bytes, UTF_8)

    /** Logs, once, where the launch recorder's first sound came. Ends a recorder that ended or went
      * silent, and the forwarding with it; the next request starts a new one. Silence is bytes too:
      * only no bytes at all counts. */
    private def watch(): Unit =
      while !stopped do
        Thread.sleep(1000)
        firstPump.logFirstSound(log)
        pump.foreach: current =>
          val silentFor = (System.nanoTime() - current.lastBytes) / 1_000_000_000L
          val reason =
            if !current.process.isAlive then Some(s"exited with status ${current.process.exitValue()}")
            else Option.when(silentFor >= stallSeconds)(s"delivered no audio for $stallSeconds s")
          reason.foreach: why =>
            current.process.destroyForcibly()
            pump = None
            val stderrSuffix = Option(current.lastStderrLine()).filter(_.nonEmpty).fold("")(line => s" ($line)")
            say(log, s"the recorder ${current.label} $why$stderrSuffix; the next request starts it again")
            exec.foreach(_.destroy())

    private def forward(): Unit =
      if pump.isEmpty then pump = startRecorder(recorder)
      pump match
        case None => say(log, s"could not start the recorder ${recorder.label}")
        case Some(current) =>
          current.keep()
          val process =
            try
              Some(
                ProcessBuilder(((podman +: ExecWithInput :+ sandboxContainer) ++ writerCommand(sandboxDir))*)
                  .redirectError(ProcessBuilder.Redirect.appendTo(log.toFile))
                  .start(),
              )
            catch case _: IOException => None
          process.foreach: started =>
            exec = Some(started)
            try
              readyLine(started) match
                case Some("ready") =>
                  current.forward(started.getOutputStream)
                  started.waitFor()
                case Some(other) if other.nonEmpty => say(log, "the writer answered other than ready")
                case Some(_)                       => ()
                case None                          => say(log, "the writer did not answer within 10 s")
            finally
              current.idle()
              exec = None
              started.destroy()
              if !started.waitFor(5, TimeUnit.SECONDS) then started.destroyForcibly()
              try started.getOutputStream.close()
              catch case _: IOException => ()
          if process.isEmpty then current.idle()

    /** The exec's first line within the bound: Some("") for an exec that ended without one, a
      * stale start; None when the bound passed. */
    private def readyLine(process: Process): Option[String] =
      val line = java.util.concurrent.CompletableFuture.supplyAsync: () =>
        val in = process.getInputStream
        val bytes = java.io.ByteArrayOutputStream()
        var next = in.read()
        while next >= 0 && next != '\n' && bytes.size < 16 do
          bytes.write(next)
          next = in.read()
        String(bytes.toByteArray, UTF_8)
      try Some(line.get(10, TimeUnit.SECONDS))
      catch case _: Exception => None

  // -------------------------------------------------------------------------
  // Windows diagnostics
  // -------------------------------------------------------------------------

  private val ConsentStore = "Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore"

  /**
   * Read only after sox_ng failed, whose message names neither cause: the capture endpoints
   * Windows shows this session, through IMMDeviceEnumerator, and the three microphone permission
   * values. A Remote Desktop session can see no endpoint while the device store still lists the
   * machine's own, so the store is not read.
   */
  val DiagnosticsScript: String =
    s"""$$ErrorActionPreference = 'Stop'
       |Add-Type -TypeDefinition @'
       |using System;
       |using System.Runtime.InteropServices;
       |[ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")] class MMDeviceEnumerator {}
       |[Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
       |interface IMMDeviceEnumerator {
       |  [PreserveSig] int EnumAudioEndpoints(int dataFlow, int stateMask, out IMMDeviceCollection devices);
       |  [PreserveSig] int GetDefaultAudioEndpoint(int dataFlow, int role, out IntPtr endpoint);
       |}
       |[Guid("0BD7A1BE-7A1A-44DB-8397-CC5392387B5E"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
       |interface IMMDeviceCollection {
       |  [PreserveSig] int GetCount(out uint count);
       |}
       |public static class KoSandboxCaptureEndpoints {
       |  public static string Describe() {
       |    var enumerator = (IMMDeviceEnumerator)new MMDeviceEnumerator();
       |    IMMDeviceCollection devices;
       |    Marshal.ThrowExceptionForHR(enumerator.EnumAudioEndpoints(1, 1, out devices));
       |    uint count;
       |    Marshal.ThrowExceptionForHR(devices.GetCount(out count));
       |    IntPtr endpoint;
       |    int found = enumerator.GetDefaultAudioEndpoint(1, 2, out endpoint);
       |    if (found == 0) Marshal.Release(endpoint);
       |    return count + " " + (found == 0 ? "default" : "nodefault");
       |  }
       |}
       |'@
       |"endpoints " + [KoSandboxCaptureEndpoints]::Describe()
       |$$values = foreach ($$key in 'HKCU:\\$ConsentStore\\microphone',
       |    'HKCU:\\$ConsentStore\\microphone\\NonPackaged', 'HKLM:\\$ConsentStore\\microphone') {
       |  $$value = (Get-ItemProperty -Path $$key -Name Value -ErrorAction SilentlyContinue).Value
       |  if ($$value) { $$value } else { 'absent' }
       |}
       |"permissions " + ($$values -join ' ')
       |""".stripMargin

  /**
   * What the diagnostics' answer explains, first the endpoints, then the first permission value
   * that stops sox_ng: a Deny in any of the three, or an absent per-user value (measured on
   * Windows Server 2025; an absent NonPackaged or machine-wide value records). The values explain
   * a failure and decide nothing: what they mean on other Windows builds is unmeasured.
   */
  def windowsDiagnosis(answer: String): Vector[String] =
    val fields = answer.linesIterator.map(_.trim.split("\\s+").toVector).toVector
    val endpoints = fields.collectFirst { case "endpoints" +: count +: default +: _ => (count, default) }
    val permissions = fields.collectFirst { case "permissions" +: values if values.size == 3 => values }
    val endpointLine = endpoints.flatMap:
      case ("0", _) =>
        Some(
          "Windows shows this session no active capture device: connect or enable one (Settings > System > " +
            "Sound > Input); a Remote Desktop session sees only the devices its client redirects",
        )
      case (_, "nodefault") => Some("Windows has no default communications capture device (Sound control panel)")
      case _                => None
    val switches = Vector(
      "Settings > Privacy & security > Microphone > Microphone access is off",
      "Settings > Privacy & security > Microphone > Let desktop apps access your microphone is off",
      "the machine-wide microphone policy denies access (Settings > Privacy & security > Microphone, " +
        "set by an administrator)",
    )
    val permissionLine = permissions.flatMap: values =>
      values.indices.collectFirst:
        case index if values(index).equalsIgnoreCase("Deny") || (index == 0 && values(index) == "absent") =>
          switches(index)
    endpointLine.toVector ++ permissionLine.toVector

  /** The diagnostics run in Windows PowerShell; empty when it could not run. */
  def windowsDiagnostics(powershell: Path): Vector[String] =
    val encoded = java.util.Base64.getEncoder.encodeToString(DiagnosticsScript.getBytes(UTF_16LE))
    try
      val answer = run(powershell.toString, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded)
      if answer.ok then windowsDiagnosis(answer.text) else Vector.empty
    catch case _: IOException => Vector.empty
