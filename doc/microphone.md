# The host microphone — `--mic` for the agents' voice dictation

The sandbox has no audio capture device: no `/dev/snd`, no `/proc/asound`, and the launcher passes
no `--device`. Under `--mic` a host relay records the host microphone and streams it into a
PulseAudio daemon inside the sandbox, and the agents record from the daemon as they do on any
Linux desktop. Without `--mic`, nothing in the sandbox can record.

- README's Reference names what each host needs; SECURITY.md, "Microphone", states what the grant
  allows and when the microphone is open.
- Claude Code dictates through `/voice` in hold and tap mode, tap mode sending the prompt itself
  and stopping a silent recording after about 15 s with "No speech detected"; agy dictates through
  its `/voice` (measured on macOS on 2026-10-13 and 2026-10-14). Codex's `/voice` cannot connect
  ("Codex").
- The open checks are in `doc/TODO.md`, "The host microphone for voice dictation".

```
    ┌─ host ─────────────────────────────────────────────────────────────────┐
    │ recorder (rec, sox_ng, arecord or parecord), running all session       │
    │     │ PCM                                                              │
    │     ↓                                                                  │
    │ relay: drops the audio while idle; per `start`, one `podman exec`      │
    └─────│──────────────────────────────────────────↑───────────────────────┘
          │ PCM, on the exec's stdin                 │ `start`, read from `req`
          ↓                                          │
    ┌─ sandbox ──────────────────────────────────────│───────────────────────┐
    │ ko-sandbox-mic write → FIFO `mic`              │                       │
    │     → PulseAudio daemon → an agent's stream    │                       │
    │ ko-sandbox-mic control: a stream and no writer → `start`               │
    └────────────────────────────────────────────────────────────────────────┘
```

## Decisions

- **An option, not an environment variable**, as for every grant of a host resource
  (design.md, "Host resources are granted by launch options, not variables").
- **No device passthrough.** `/dev/snd` would give every process in the sandbox the microphone
  with no host-side gate, and the macOS and Windows podman machines offer no microphone to pass
  (measured for Windows, "Windows, measured"; unverified for macOS; on Linux the missing host-side
  gate decides it alone).
- **A host recorder program on every OS**, read by a relay that runs where the launcher lives: a
  shell job of the reaper on macOS and Linux, as the clipboard relay is, since the launcher hands
  over to the agent and no JVM stays for the session; threads of the resident launcher on
  Windows.
  - On Windows the program is `sox_ng`, the maintained SoX, through its `waveaudio` driver; its
    first period arrives about 125 ms after the start and then every 20 to 30 ms ("Windows,
    measured").
  - Java Sound (`javax.sound.sampled`), in the launcher thread on Windows or as a session job on
    macOS, is not used: it is a second capture implementation to own, a native-image launcher
    cannot carry it (doc/TODO.md), and its measurements show nothing a program on `PATH` lacks.
  - WSLg's PulseAudio server, which the podman machine on the WSL provider mounts, is not used: it
    needs a helper container beside the socket, serves no Hyper-V machine, hangs 30 s when Windows
    has no capture device, and delivers audio at twice its level ("Windows, measured").
- **The host recorder runs for the whole session; the relay forwards only while a process in the
  sandbox records.** A recorder started per dictation loses its own start on top of the relay's
  round trip, 660 to 810 ms of each dictation on macOS ("Latency"); a running recorder loses nothing
  of its own, and the relay keeps what arrives during the round trip and forwards it first.
  - The cost is a microphone open all session, macOS's indicator lit with it; SECURITY.md says so.
- **Linux hosts: the latest stable Debian, Fedora and Ubuntu.** Each gets a check of the recorder
  program and its package, recording the version it ran on (open in doc/TODO.md); another host may
  work and is not claimed.
- **A PulseAudio daemon in the sandbox, not a recorder shim.** Claude Code records through SoX's
  PulseAudio backend, the path the CLI's own documentation prescribes for WSL; agy through
  `parec`; Codex's helper through ALSA's PulseAudio plugin, the path it takes on WSLg. A stock
  daemon and a configuration file serve all three where a shim would answer one agent's command
  lines. The daemon's microphone is a FIFO the relay writes; the daemon needs no device.
  - A null sink's monitor as the microphone, fed by `pacat --playback` from the writer, is the
    alternative if a boundary measurement ever finds samples crossing between dictations ("The
    daemon"): it has no FIFO and no loopback, and a client's unrendered audio dies with its
    stream, but its delay is the sink's, where the pipe source adds none.
- **PulseAudio, not PipeWire**, for two reasons: its pipe source adds no delay, and the server is
  one daemon and one file. The clients speak the PulseAudio protocol (SoX, `parec`) or ALSA
  (Codex's helper), and either server speaks both and offers a pipe source and a null sink; Debian
  13 packages both. Read in both projects' `master` on 2026-10-09:
  - PulseAudio's `module-pipe-source` posts each chunk it reads. PipeWire's `module-pipe-tunnel`
    keeps a ring whose read index it sets 8192 frames behind the write index at every resync, and
    it resyncs at every underrun, which is the state at every recording's start: a dictation at
    16000 Hz begins 512 ms late, hard-coded, and fills with silence while the FIFO is dry. The
    relay cannot recover a delay inside the module.
  - PipeWire is a core daemon, `pipewire-pulse` for the protocol and a session manager or a
    hand-written routing policy to link streams to the source, with nothing the sandbox's
    device-free graph needs from them.
  - The two agree on what "The daemon" is built around, so the loopback that keeps the source
    running transfers unchanged either way: each makes its FIFO and opens it read-write and
    non-blocking, so a writer's close is never an EOF, and each reads the FIFO only while its
    stream is running (PulseAudio: `thread_func`'s `PA_SOURCE_RUNNING` test; PipeWire:
    `stream_state_changed` enabling `SPA_IO_IN` only in `STREAMING`, `tunnel.may-pause` off).
  - The choice is revisited if Codex's helper fails on alsa-plugins' pulse PCM and works on
    `pipewire-alsa`, at the delay above ("Codex").
- **No playback to the host.** Codex's helper must open a speaker; the daemon's is a null sink.
  - Codex's spoken replies would reach nothing, and its reply would be read in the transcript the
    TUI shows (unverified).
  - One direction keeps the relay as it is; playback would be a pipe sink and a second relay
    direction, added without changing the first.
  - Playback would be its own option, never a default: sound a sandbox process puts on the host
    can imitate the user's tools or a person in the room, and reaches any microphone nearby,
    another device's included; with the microphone it also closes a loop from the host's speaker
    back into the sandbox.

### Codex

Codex is served only once its helper is shown to accept the daemon; the README says what its
`/voice` does. Its helper lists ALSA cards, and the sandbox has none; openai/codex#47370 shows it
failing without an ALSA-to-PulseAudio bridge (its exit code 25) and later with one (code 37).
Claude Code and agy justify the daemon on their own.

- Blocked by the network, before the audio: Codex 0.162.1's `/voice` reports "voice transport
  could not connect". Its log shows the helper, a WebRTC client (`codex_realtime_webrtc`), exiting
  with code 24 in its `Transport` phase, one second after the proxy allowed its 14 CONNECTs to
  `chatgpt.com` (2026-10-14). The call's setup passed the proxy; the likely cause, unverified, is
  its media connection, which WebRTC opens to the server directly rather than through an HTTP
  proxy, and the sandbox has no direct route. Whether the helper would accept the daemon is
  unmeasured; doc/TODO.md, "Codex's `/voice`", has what serving it needs.
- `-c 'realtime.transport="websocket"'`, a key Codex's binary defines (`RealtimeToml`'s
  `transport`, `webrtc` or `websocket`) and its config reference does not list, leaves `/voice` on
  the same WebRTC client, failing the same way.

## How the agents record

### Claude Code

On macOS and Windows the CLI records with its built-in module, and `arecord` and SoX are its
Linux fallbacks (the voice dictation page, "Requirements"). On Linux, `/voice` runs these checks in
order (`checkRecordingAvailability`, `checkVoiceDependencies`, read from the image's
`/usr/bin/claude` 2.1.295 on 2026-10-09):

- `CLAUDE_CODE_REMOTE` set: "no audio device is available in this environment". The launcher sets
  nothing of the kind.
- The bundled `audio-capture.node` loads `libasound.so.2`, which the image has, and the CLI then
  requires a non-empty `/proc/asound/cards` not reading "no soundcards". Absent in the sandbox.
- `arecord --version` exits 0, and `arecord -f S16_LE -r 16000 -c 1 -t raw /dev/null` exits 0 or
  is still running 150 ms later: `arecord` is the recorder.
- Else `sox --version` and `rec --version` both exit 0: SoX `rec` is the recorder.
- Else: without SoX, "Voice mode requires SoX for audio recording. Install it with: sudo apt-get
  install sox"; with it, "Voice mode requires a microphone, but SoX could not open an audio
  capture device".

The image installs SoX and its PulseAudio backend, so under `--mic` `rec --version` exits 0 and
the CLI takes its SoX branch (the Containerfile says why `alsa-utils` stays out). Without the
backend, `rec --version` fails with "Sorry, there is no default audio device configured" (measured
in the sandbox).

Without `--mic`, the CLI 2.1.296 answers `/voice tap` with the last check's "Voice mode requires a
microphone, but SoX could not open an audio capture device", adding that the host may have none
(measured on macOS). A bare `/voice` toggles: with voice on in the settings, it answers "Voice mode
disabled." before any check.

- Recording through `rec`: `rec -q --buffer 1024 -t raw -r 16000 -e signed -b 16 -c 1 -`, from the
  default device, stdout read as audio, `SIGTERM` to stop, with a SoX `silence` effect appended when
  silence detection is on (read from 2.1.296 on 2026-10-14). `ko_sandbox_mic_test.py`'s
  `ClaudeCodeRecorderContractTest` fails when a release changes the order or these arguments.
- Recording through `arecord` would be `arecord -f S16_LE -r 16000 -c 1 -t raw -q -`, with no
  silence detection.
- The stream: a WebSocket to `wss://api.anthropic.com/api/ws/speech_to_text/voice_stream`
  (`linear16`, 16000 Hz, one channel) with the claude.ai OAuth token as bearer.
  - A `GET /api/hello` probe precedes it on the same host. The CLI passes its proxy setting to the
    WebSocket, and the ruleset's `allow https://api.anthropic.com/ tunnel` covers both.
  - A profile without that host fails `/voice` with "Voice stream error" after the recorder starts
    (read from the CLI).
- An API key, Bedrock, Vertex or Foundry session is refused before recording: "Voice mode requires
  a Claude.ai account".

### The other agents

Read from the image's binaries on 2026-10-09.

- Codex 0.162.0: `/voice` is a two-way realtime conversation, microphone and speaker, through its
  bundled helper `codex-resources/voice/bin/codex-voice-host`, a glibc build with its own GStreamer
  (`manifest.json`: `voiceTarget` gnu beside the musl `appTarget`).
  - The helper opens ALSA PCMs itself — it carries libasound, lists cards through
    `/dev/snd/controlC%i`, names `hw` and `plughw` — and `[realtime] audio` takes device names.
  - openai/codex#47370 reports the same helper failing on WSLg through the ALSA PulseAudio plugin,
    on its playback stream.
- agy 1.3.2: `/voice` dictates into the prompt, under a permission the sign-in must carry. On Linux
  it records with `parec --raw` when `PULSE_SERVER` is set, or reads a microphone served by
  `agy mic-serve` on another machine at `127.0.0.1:4713`, agy's own protocol over an SSH forward.
  It transcribes at `aicode.googleapis.com`, which `model-provider/google` tunnels.
- Copilot 1.0.94, kiro-cli 2.28.0 and OpenCode 1.18.35 dictate nothing.

## The launch

- Without `--mic` no daemon or relay runs, and no `PULSE_SERVER` is set.
- Before the container starts, the relay starts each candidate recorder in order ("The recorder")
  and keeps the first that delivers bytes within a bound; that process is the session's recorder,
  so the probe and the recorder are one start.
  - No candidate on `PATH`: the launch fails naming the package to install.
  - None that records: the launch fails with each candidate's reason and the step for the cause,
    since the program is installed: the terminal's permission on macOS, what the diagnostics name
    on Windows, the device or the other recorder on Linux.
  - A recorder's environment — `XDG_RUNTIME_DIR`, a WSLg session's preset `PULSE_SERVER` — is the
    launcher's own, and is checked by that recording, not by name.
  - The probe keeps only the count of nonzero bytes, never the audio.
- On macOS the probe raises the microphone permission prompt at launch rather than at the first
  dictation: after a few seconds without bytes it asks for an answer, and gives up after a minute.
  - Observed on 2026-10-14 in Ghostty after `tccutil reset Microphone`: the prompt appeared at
    launch for the recorder the reaper's job starts, reading "Ghostty.app would like to access the
    Microphone. A program running within Ghostty would like to use your microphone".
  - With the prompt unanswered, the launch failed after the minute.
- A denied permission on macOS records exact digital silence ("macOS, measured"), and so do a muted
  input and a microphone with a noise gate before anyone speaks: the recorder cannot tell them
  apart.
  - The probe reads its moment with dither off, so silence is exact zeros.
  - All-zero samples print a warning naming the permission and the input setting, and do not fail
    the launch: in Ghostty, whose permission was denied, a `--mic` launch raised no prompt, warned,
    and started the agent (2026-10-14).
  - A launch can warn and then dictate: on macOS, at ten reads and again at fifty, some launches'
    first moment was exact silence while the microphone worked (2026-10-14). The cause is
    unmeasured.
    - Sharing the device is not the cause: one launch beside another `--mic` session warned and
      the next did not, and a `rec` run from the shell beside that session delivered sound in its
      first piece, at 137 to 141 ms, in three runs.
    - Each launch's microphone log says how far into the recorder's audio its first sound came,
      or that none came in its first 30 s.
- On Windows the recorder decides and two diagnostics explain. In a session without a capture
  endpoint, and under each permission value that stops it, the recorder fails within about 350 ms
  with a message that names neither cause ("Windows, measured"). A recorder that fails ends the
  launch with the diagnostics' reading; one that records proceeds.
  - Capture endpoints: a PowerShell script calls
    `IMMDeviceEnumerator::EnumAudioEndpoints(eCapture, DEVICE_STATE_ACTIVE)` and
    `GetDefaultAudioEndpoint(eCapture, eCommunications)` through `Add-Type` COM interop, and prints
    the count and whether a default exists (`E_NOTFOUND` when none).
    - The API filters by direction and state itself; an endpoint's instance id is a string whose
      format Microsoft leaves undefined.
    - It answers for the session: a Remote Desktop session with sound on the client shows its
      programs no capture endpoint, while the device store under
      `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture` holds the
      machine's own at `DeviceState` 1. So the store is not the check.
  - Permissions: the three `Value`s under `CapabilityAccessManager\ConsentStore` in
    `Software\Microsoft\Windows\CurrentVersion`, each `Allow`, `Deny` or absent:
    - `microphone` under `HKCU` ("Microphone access");
    - `microphone\NonPackaged` under `HKCU` ("Let desktop apps access your microphone");
    - `microphone` under `HKLM` (the machine-wide policy).
    - The diagnosis names the switch, under Settings > Privacy & security > Microphone, of the
      first value that stops the recorder ("Windows, measured" has which do). The values explain a
      failure and decide nothing: what they mean on other Windows builds is unmeasured.
- Inside the sandbox the launcher sets `KO_AGENT_SANDBOX_MIC=on`, `PULSE_SERVER`, the three
  `PULSE_*_PATH` variables and `PULSE_COOKIE` ("The daemon"), and no `SOX_OPTS` ("Latency").

## The daemon

Under `--mic`, `ko-sandbox-entrypoint` starts PulseAudio before the agent from the image's
`microphone.pa` alone, whose comments give each module's reason.

- `-n` skips the default script, and `--disallow-module-loading` applies once the script's
  modules are loaded. No D-Bus and no TCP module.
- `PULSE_CONFIG_PATH`, `PULSE_STATE_PATH` and `PULSE_RUNTIME_PATH` point the daemon and every
  client at three directories under the session's `/tmp`, `pulse-config`, `pulse-state` and
  `pulse-runtime`, so no `daemon.conf`, `client.conf` or state is read from or written to
  `~/.config/pulse`.
  - Three and not one, because `pa_get_state_dir` (`core-util.c`, read at `master` on
    2026-10-09) breaks when the state and runtime paths are the same directory.

The script's modules:

- `module-pipe-source` on `/tmp/ko-agent-sandbox/microphone/mic`, the default source.
- `module-null-sink`, the default sink, for Codex's speaker.
- `module-loopback` from the pipe source to the null sink, with `adjust_time=0`: a permanent
  output that keeps the source running, and a running pipe source reads its FIFO as bytes arrive.
  - The module makes its stream variable-rate whatever the specs (`PA_SINK_INPUT_VARIABLE_RATE`,
    `module-loopback.c`), so its resampler runs even at matching rates, at a ratio of one;
    `adjust_time=0` stops the rate readjustment it runs every second by default toward a latency
    target a drop path has no use for (both read at `v17.0` on 2026-10-11).
  - So audio written while no agent records is read and dropped into the null sink as the source's
    thread gets to it, and a stream an agent opens later gets what the source posts after it
    opened. What could cross from one dictation to the next is a period the writer delivered that
    the thread had not yet read when the next stream opened.
  - Measured with PulseAudio 17.0 on 2026-10-14 (`ko_sandbox_mic_test.py`, `DaemonTest`): no
    sample written before a stream opened, or before one stream closed and the next opened,
    reached the new stream, under CPU load, through a one-page FIFO and with the daemon
    `SIGSTOP`ped across the switch too. A count above zero would be the design's limit to record,
    not a timing to tune.
  - Without the loopback the source idles between recordings, stops reading, and delivers the end
    of one dictation at the start of the next; draining the FIFO from outside instead would race
    the source's own reads.
  - Under `adjust_time=0` the loopback's buffer takes up any difference between the writer's
    clock and the null sink's; the growth lasts one forwarding. Measured with PulseAudio 17.0 on
    2026-10-14:
    - A feed 0.1 % faster than its rate for an hour, beyond a real clock's difference: the source
      stayed `RUNNING`, the buffer grew with the excess from 0.20 s to 3.78 s and the daemon's
      memory by 240 kB.
    - A stream opened at that hour's end received a marker within a millisecond and every sample
      of it, as one at the start did.
    - With the feed stopped, after three minutes 1 % fast, the buffer fell from 2.09 s to under a
      millisecond within 15 s.
- `module-native-protocol-unix` on its default socket, `native` in `pulse-runtime`, which
  `PULSE_SERVER` names, with no cookie.
  - A client makes a cookie file where it finds none, `~/.config/pulse/cookie` by default whatever
    `PULSE_CONFIG_PATH` says (measured with Debian 13's PulseAudio 17.0), so the launcher also sets
    `PULSE_COOKIE` to a path in `pulse-config`: the file the clients make lands in the session's
    `/tmp`, and nothing checks its contents.
- No `module-suspend-on-idle`: a suspended source or sink would stop the loopback, and resuming
  one is a delay the first syllables pay.

The daemon and the controller end with the agent. The launcher creates the session container with
podman's `--init`, which is catatonit unless containers.conf's `init_path` names another; the
entrypoint `exec`s the agent, so the agent is catatonit's child; catatonit exits when that child
does (`catatonit.c`'s reaping of its pid1); and when a PID namespace's init exits, the kernel
`SIGKILL`s every process in it (pid_namespaces(7)).

The Containerfile installs each agent's client path to the daemon, and a client configuration
that turns autospawn off.

## The controller and the writer

`ko-sandbox-mic`, a Python program (the image runs its status line with `python3 -I` already), in
two roles.

**The controller**, started by the entrypoint beside the daemon, is the one holder of the recording
state inside the sandbox. It keeps two facts current and acts on their difference, on every stream
event and when its timer is due, five seconds after its last check.

- It writes its own pid file, pid and start time as the writer's below, for the writer's watch.
- The entrypoint starts it again while the daemon runs, so a controller that dies costs the
  dictation in flight, not the session's microphone.

- *Demand*: whether an agent has a stream open on the microphone.
  - It subscribes with `pactl subscribe` first, then lists `pactl list short source-outputs`, and
    reconciles on each `source-output` event and on the timer, and on no other kind: `pactl
    subscribe` also reports clients, and each listing is a client, so a listing on every event
    would list forever.
  - `pactl subscribe` registers after its start and says nothing when it does (`pactl.c`, read at
    `v17.0` on 2026-10-14), so the controller lists until the subscription reports a listing's
    client, and only then takes the first listing: no stream opens unseen between the two.
  - It counts outputs on the pipe source whose driver is the native protocol's, which leaves out
    the loopback's own output and anything on the null sink's monitor.
  - Corked outputs count: an agent that corks its stream keeps the host recording, which none of
    the three does, and the short listing has no cork column.
- *Supply*: whether a writer is alive, by the pid file the writer makes, which holds its pid and
  its start time from `/proc/<pid>/stat`. The process is the writer only when both match, since a
  pid outlives its process in a file and is reused; the controller holds the writer as a pidfd and
  signals through it, so a pid reused between the check and the signal is not signalled.
- Demand and no supply: it writes `start` to the channel's `req` FIFO.
  - The FIFO is opened for writing non-blocking, so a FIFO the relay has not made yet (`ENOENT`) or
    is not reading (`ENXIO`) is a relay unavailable, retried every 0.2 s while demand persists: the
    relay reads `req` through one exec per request, so between two execs nobody reads it, and a
    retry at the next five-second tick would cost the dictation's first seconds.
  - A delivered `start` begins a wait of up to three seconds for a writer before the next `start`,
    so a slow exec gets one request, and a recorder that died while a stream is open gets a new
    one; a `start` not delivered begins no wait.
  - Requests the relay has not read yet queue in the FIFO, so a `start` can be read after its
    stream has closed, or several can: the writer's first step settles what a stale one costs.
  - A request stale when the writer checks forwards nothing. If the stream closes between that
    step and `ready`, the relay forwards for at most one round trip, until the controller sees no
    demand and ends the writer.
- Supply and no demand: it sends the writer `SIGTERM`, which ends the exec; the host does the rest.
- A subscription that ends — the daemon gone — is no demand, and the controller exits with the
  daemon.

**The writer**, `ko-sandbox-mic write`, is what the relay's exec runs, in these steps:

- It lists the source outputs once, as the controller counts them: with no demand it exits without
  a word, so a `start` read after its stream closed costs one exec and no microphone.
- It writes its pid file, and requires a live controller, by the controller's pid file and the same
  start-time check: the controller alone ends a forwarding on the last stream's close, so without
  it the writer would forward the host microphone with no stream open until the session's end.
- It checks that the pipe source's path is a FIFO (`S_ISFIFO`, no following of links) and opens it
  for writing, non-blocking.
- Only then does it write `ready` to its stdout with `os.write`, the host's signal to forward: after
  the FIFO is open, so the host never forwards into a writer that cannot take PCM, and never through
  Python's stdout, which a non-interactive process block-buffers.
- It copies its stdin to the FIFO until its stdin ends, `SIGTERM` arrives, or the controller is
  gone, waiting in `select` on the controller's pidfd as well, so neither a full FIFO nor an idle
  stdin hides the controller's death. The daemon reads the FIFO continuously, so the FIFO is full
  only when the daemon has stopped reading; the writer then stops reading its stdin, and once the
  recorder's write blocks, five seconds without bytes end the recorder and the forwarding.
  - Whole frames only: it writes an even number of bytes, keeping an odd trailing byte for the next
    read, in writes of at most `PIPE_BUF`, which pipe(7) keeps atomic, so the daemon's reads return
    whole frames too. Read at `master` on 2026-10-13:
    - The exec transport hands the writer chunks of any length, while `module-pipe-source` reads
      up to `PIPE_BUF` bytes at a time and posts each read's length as a chunk.
    - `pa_source_output_push` (`source-output.c`) asserts that a chunk is frame-aligned:
      `pa_assert` (`macro.h`) aborts the daemon unless the build defines `NDEBUG`, and with it off
      a half frame shifts every later sample.

`timeout` is not used around a stream: it bounds a whole command, which would cut a dictation at
the bound; the clipboard's `timeout 10 sh -c "cat > rsp"` fits a reply read whole, not this.

## The relay

The channel is `/tmp/ko-agent-sandbox/microphone/req`, made by the relay's first exec, with the
daemon's FIFO `mic` beside it. The clipboard relay's request and reply each read whole; a
recording is a stream that runs until a stop, so this relay's forwarding is an exec that lasts the
recording.

- POSIX relay: a job of the reaper beside the clipboard's, with the candidate recorders in probe
  order and the launcher's environment. It runs the launch probe, and the recorder it keeps is the
  job's child for the session, writing into a FIFO of the job's own. The job accepts only the line
  `start`, and logs and skips any other.
  - The job's FIFOs live in a directory it makes with mode 0700 and are made with mode 0600, since
    the microphone's audio flows through them all session; the job removes the directory when it
    ends, and the reaper removes it after a `KILL`.
  - The job holds its FIFOs open read-write, since a read-only open of a FIFO blocks until a writer
    exists. It holds the recorder's for the session, so the recorder never meets a closed pipe.
    It holds each exec's stdin FIFO for one request: made and opened before the exec starts, and
    closed and removed once the exec and the copy have ended, so a byte the exec left unread dies
    with its request.
    - Linux allows the read-write open where POSIX leaves it undefined (fifo(7)), and so does
      macOS: the relay forwarded live dictation there (2026-10-14).
  - While no agent records, the job drains the recorder's FIFO into `/dev/null`.
  - Per `start` it ends the drain, so the recorder's FIFO keeps what the recorder writes from then
    on, and runs `podman exec -i --detach-keys= <sandbox> ko-sandbox-mic write <mic>` with its
    stdin FIFO, which nothing writes yet, waiting, bounded, for `ready` on the exec's stdout.
    - An exec that ends before `ready` was a stale `start`; anything else before it, or the bound
      passing, is a failure logged with what arrived; in both cases the drain resumes.
    - The recorder's FIFO is never the exec's stdin: podman reads the stdin it is given as soon as
      bytes arrive, whether or not the contained process reads them (podman-exec(1),
      `--interactive`), so audio handed to it before `ready` would reach the sandbox on a stale
      `start`, into a pipe any process of the one uid can open through `/proc`.
    - Without `--detach-keys=`, PCM bytes could detach the exec (`HostCommands.ExecWithInput`).
  - On `ready` the job copies the recorder's FIFO into the exec's stdin, beginning with what the
    pipe kept during the round trip, so the audio of the round trip reaches the agent too; it reads
    the next request only when the exec and the copy have ended, since the recording's end arrives
    as the exec's end, not as a line.
  - The recorder FIFO's capacity bounds what a slow exec keeps: 64 KiB, 2 s of this stream, by
    default on Linux, which pipe(7) says applications must not rely on; unmeasured on macOS. A full
    pipe blocks the recorder's write until the exec's bound ends the request as a logged failure.
  - Every path on both sides is absolute: an exec's working directory is the container's, not the
    channel's.
- A forwarding ends, and the exec and the copy with it, when any of these happens:
  - the exec ends: the controller ended the writer, or the writer or the controller died, or the
    daemon is gone;
  - the recorder ends, or delivers no bytes for five seconds, silence being bytes too: it is logged
    with its exit status and its stderr's last line to the launcher's log, where a permission
    refusal or a device that disappeared is read, and started again at the next request, which then
    pays its start;
  - the container stops, as the clipboard's loop ends;
  - the session ends: the reaper `KILL`s the job's tree, recorder included.

  The drain resumes after each; ending a child is `SIGTERM`, then `SIGKILL` after a bound.
- Windows relay: threads of the resident launcher running the same loop, the recorder their child
  for the session, the exec their child per request. A reading thread discards the recorder's
  output while idle, holds it in memory from the request on, and writes nothing to the exec's stdin
  before `ready`, for the reason the POSIX relay gives; from `ready` it forwards.
  - Windows has no `SIGTERM`: the thread ends the exec with `Process.destroy()`
    (`TerminateProcess`). Windows ends no child with its parent, so a shutdown hook ends every
    recorder the launcher started.
- Between a request and `ready` the host holds the audio in the recorder's FIFO (POSIX) or in
  memory (Windows); nothing is written to a file. The stream's rate is 32 kB/s.

### The recorder

Raw signed 16-bit little-endian mono at 16000 Hz. `MicrophoneRelay.recorders` holds the candidates'
command lines in probe order, and the reasons for SoX's `--buffer 640` and `-D` ("Windows,
measured" and "macOS, measured" have the measurements).

- macOS: SoX `rec`. `brew install sox_ng` installs the `rec` name; `brew install sox` serves too,
  and Homebrew refuses to install both. macOS has no built-in recorder command.
- Windows: `sox_ng` with `-d`, the Sound control panel's default recording device through the
  `waveaudio` driver. winget's manifests trail the release (14.7.1.2 against 14.8.1 on
  2026-10-11).
- Linux: `arecord` on ALSA's `default` PCM first, one command whichever server owns the
  microphone, if each host's desktop edition routes `default` to it (unmeasured); then `parecord`
  for a host where it does not, as on WSLg.
  - `parecord` runs with a `PULSE_CLIENTCONFIG` that sets `autospawn = no`, so the probe starts no
    daemon of its own; a server the host's systemd starts on its socket is the host's
    configuration, not the probe's.
- A probe that delivers bytes shows a source that records, not that it is a microphone: a monitor
  or null source records silence. The first dictation shows the rest.

## Latency

A client's stream opens at the key press, and the relay keeps the audio from the request on, so
what the agent never hears is what is said between the key press and the request: the
controller's event and one FIFO write.

- The round trip, one `podman exec` of 100 to 120 ms on the Mac's podman machine ("macOS,
  measured"), delays the first bytes and loses none; the daemon and SoX add their own buffers; the
  source itself is already running, so no resume is paid.
- A recorder started per dictation would pay its own start first, 550 to 700 ms on macOS, of which
  about 450 is its device setup after the process start and is paid on every start, and 125 ms on
  Windows; with the round trip, a per-dictation relay would lose about 660 to 810 ms of each
  dictation on macOS.
- Measured on macOS on 2026-10-14: `rec` in the sandbox recorded room audio through the relay, its
  first bytes after 386 ms.

At the key's release the CLI sends `rec` `SIGTERM` and, in the same step, closes its stream to the
transcription server; chunks arriving after that are dropped (`[voice_stream] Dropping audio chunk
after CloseStream`), so nothing after the key reaches the transcript.

- What is lost of the last word is the audio in flight between the host's microphone and the CLI at
  that moment: the recorder's period, the exec, the daemon and the CLI's `rec`. The relay's part is
  kept short (a 20 ms period, no buffering).
- The CLI's `rec` delivers 4096-byte pieces, 128 ms, against the daemon, so up to 128 ms can be in
  its output at `SIGTERM`. Nothing the sandbox sets shortens them, so the launcher sets no
  `SOX_OPTS`:
  - the CLI's own `--buffer 1024` overrides `SOX_OPTS`, which supplies SoX's defaults (sox(1));
  - Debian 13's SoX 14.4.2 writes 4096 bytes at a time to the pipe even under `--buffer 640` on
    its command line (measured 2026-10-14: the CLI's arguments with and without
    `SOX_OPTS=--buffer 640`, and `--buffer 640` in place of its own).

## Windows, measured

Measured on 2026-10-11 on Windows Server 2025 (10.0.26100.32522) reached over Remote Desktop, WSL
3.0.1.0 with WSLg 1.0.79 (PulseAudio 17.0), a podman machine on the WSL provider, Oracle JDK
25.0.2, sox_ng 14.8.1 (win64 release zip) and VB-CABLE 3.3.1.7 as the capture device, since the
instance has no microphone (below). A 440 Hz tone at 0.3 of full scale played into the cable stood
for speech, so the timings include the cable's buffer and are not a microphone's.

- `sox_ng -q --buffer 640 -d -t raw -r 16000 -e signed -b 16 -c 1 -` records the default recording
  device at the tone's exact level (RMS 0.211, 128000 bytes for 4 s). Its process start takes
  17 ms; the first 640-byte period reaches the pipe about 125 ms after the start and the next ones
  every 20 to 30 ms, in exact 640-byte pieces.
  - Without `--buffer`, SoX writes its output in 8192-byte blocks, 256 ms of this stream, the first
    about 490 ms after the start; `--buffer 1280` gives 1280-byte pieces at 40 ms. The option sizes
    the output write, not the driver's period.
  - Under each permission value at `Deny` ("The launch"), and with the per-user `microphone` value
    absent, it exits after about 330 ms with
    `sox_ng FAIL formats: can't open input 'default': waveInOpen failed with code 1` and the
    system's text for that code, which names neither the microphone nor the permission.
  - With `NonPackaged` absent, or the machine-wide value absent, it records normally. On this image
    as installed, the per-user value is `Deny`, `NonPackaged` is `Allow` and the machine-wide value
    is `Allow`.
  - In one run after `Disable-PnpDevice` on the only capture endpoint it did not fail: the Wave
    Mapper opened and delivered silence at one LSB of noise (peak 0.00003) for as long as it ran,
    so neither exit status nor byte count showed the missing microphone, and a level test cannot
    tell that from a quiet room.
  - In a later run of the same command the endpoint again showed `Error` in `Get-PnpDevice` while
    the audio API still counted it active and sox_ng recorded the tone at full level: the PnP
    status is not the audio API's state.
  - In the Remote Desktop session that hides every endpoint (below) it fails after about 350 ms
    with `sox_ng FAIL formats: can't open input 'default': sample format negotiation failed with
    code 2` and the system's text for a file not found: a session with no capture endpoint fails
    fast, where the silent run above did not.
  - `EnumAudioEndpoints(eCapture, DEVICE_STATE_ACTIVE)`, called from PowerShell through `Add-Type`
    COM interop, counts 1 in a session that sees the cable and 0 in the Remote Desktop session that
    hides it; `Add-Type` compiles the script in 150 ms and a count takes 7 ms. The count and the
    recorder agreed in every run where both were measured.
- The podman machine has no ALSA capture device (`/dev/snd` holds `timer`), and WSLg mounts its
  PulseAudio server at `/mnt/wslg/PulseServer` into it, with `RDPSource` (s16le, mono, 44100 Hz) as
  the default source and `RDPSink` as the default sink. A rootless container with `/mnt/wslg`
  mounted reaches it with no cookie.
  - `parecord --raw --format=s16le --rate=16000 --channels=1 --latency-msec=20` on it delivers
    Windows's default capture device, resampled by WSLg's server, at twice the tone's level (RMS
    0.42); the first 20 ms period arrived 47, 57 and 68 ms after the start, with the source idle and
    the container already running.
  - With no capture device on Windows the source stays suspended, and a stream on it fails after
    30 s with "Connection failure: Timeout".
- Java Sound lists each capture endpoint as a DirectSound mixer, grants the 16000 Hz, 16-bit mono
  line directly, grants the requested 640-byte (20 ms) buffer, returns one period per `read`,
  delivered the tone at its level, and a `close()` from another thread returned a blocked `read`
  after 506 ms.
  - With "Microphone access" off the mixers are still listed and `open` fails with
    `LineUnavailableException: line with format ... not supported`, which names the format, not the
    cause.
- A Remote Desktop session with sound played on the client sees only the redirected "Remote Audio"
  playback endpoint; the machine's own endpoints, active in the device store, are hidden from every
  program in that session. Windows App on macOS redirected no microphone to this server, although
  the server's capture policy allowed it.
- The podman machine stops at sign-out; `podman machine start` brings it back.

## macOS, measured

Measured on 2026-10-11 on an Apple silicon Mac (Homebrew's `arm64_tahoe` bottles) with sox_ng
14.8.1 from Homebrew and the Mac's microphone, speaking.

- `brew install sox_ng` installs the `rec` and `sox` names, with `coreaudio` as the one audio device
  driver. Claude Code's own `/voice` on the Mac dictates with the `sox` formula uninstalled, which
  says nothing about sox_ng: on macOS the CLI records with its built-in module.
- The first `rec` run from a shell raised macOS's microphone permission prompt, naming the terminal
  application.
- With the permission denied, in a newly installed terminal whose prompt was answered "Don't
  Allow", `rec` neither fails nor hangs: it ran until killed at 20 s and wrote 428036 bytes with a
  peak of 1 LSB, SoX's dither on zeros, and its first bytes came about 6.6 s after the start, once
  the prompt was answered. With dither off (`-D`) at the device's 48000 Hz, 3 s of recording were
  144000 samples all exactly 0, where the dithered output had left none at 0.
- The device runs at 48000 Hz and refuses 16000, so SoX resamples and prints `rec WARN formats:
  can't set sample rate 16000; using 48000` on stderr even under `-q`; the output is 16000 Hz
  (128106 bytes for 4.003 s). The relay treats stderr as a log, not as failure. Speech arrived at
  RMS 0.0089, peak 0.068.
- Timing, from the process start to the first bytes on the pipe, then between pieces:
  - `rec --version` alone takes 100 ms.
  - 48000 Hz with `--buffer 1920`, one 20 ms period: first bytes at 540 to 570 ms, then exactly
    every 20 ms.
  - 16000 Hz with `--buffer 640`: 560 to 710 ms, then 1280 and 640-byte pieces alternating every
    30 ms; with `--buffer 1280`, 720 ms; with the default 8192, 1000 ms, then every 256 ms.
  - So about 450 ms lies between the process start and the first period: SoX's CoreAudio driver
    querying the device and trying to set its format, creating the I/O proc, starting the device
    and filling the first buffer, and macOS's microphone permission check for the new process, in
    unmeasured proportion; the resampler adds up to 150 ms and the output buffer the rest. Runs
    back to back all paid it, so it is not a hardware wake-up.
- `podman exec <sandbox> true` on the Mac's podman machine takes 100 to 120 ms, which is the relay's
  round trip before the writer starts.

## Excluded

- Patches to the agents; device passthrough and playback to the host are under "Decisions".
- Live checks whose result would change no code or message: what agy's `/voice` says without its
  permission, `--egress=deny-all`, a real microphone on Windows and a disabled capture endpoint, and
  the first word and word endings against the CLI's own path.
- agy's `mic-serve` protocol: its `parec` path is served instead.
- Sessions whose profile excludes an agent's transcription host: the agent's stream, not the relay,
  fails.

## Sources

- https://code.claude.com/docs/en/voice-dictation.md
- https://code.claude.com/docs/en/settings-reference.md (`voice`, `voiceEnabled`)
- The image's `/usr/bin/claude` 2.1.295, and 2.1.296 for `rec`'s arguments: the recorder
  selection, the `arecord` and `rec` command lines, and the stream URL
- The image's `/opt/codex/bin/codex` 0.162.0 and `codex-resources/voice/`, `/usr/local/bin/agy`,
  `copilot`, `kiro-cli` and `opencode`: the other agents' voice paths
- https://github.com/openai/codex/issues/47370
- https://github.com/pulseaudio/pulseaudio/blob/master/src/modules/module-pipe-source.c and
  https://github.com/PipeWire/pipewire/blob/master/src/modules/module-pipe-tunnel.c, both read at
  `master` on 2026-10-09
- PulseAudio's `src/pulsecore/core-util.c` (`pa_get_state_dir`), `src/pulsecore/protocol-native.c`
  (`pa_native_options_parse`) and `src/utils/pactl.c` (the subscription mask), read the same day;
  `pactl.c` again at `v17.0` on 2026-10-14 (when `subscribe` registers)
- PulseAudio's `src/pulsecore/source-output.c` (`pa_source_output_push`), `src/pulsecore/macro.h`
  (`pa_assert`) and `core-util.c` (`pa_pipe_buf`), read at `master` on 2026-10-13
- https://manpages.debian.org/trixie/pulseaudio-utils/pacat.1.en.html (`parec`, `parecord`) and
  https://manpages.debian.org/trixie/sox/soxformat.7.en.html (`waveaudio`), read on 2026-10-11
- https://codeberg.org/sox_ng/sox_ng/releases (14.8.1, its `README.win32` and `sox_ng.txt` for `-d`
  and `--buffer`), Homebrew's `sox_ng` formula (`--enable-replace`) and the sox_ng wiki's "Distros"
  page (Debian testing ships sox_ng as `sox`), read on 2026-10-11
- https://manpages.debian.org/trixie/sox/sox.1.en.html (`SOX_OPTS`, `--buffer`), read on 2026-10-14
- https://man7.org/linux/man-pages/man7/pid_namespaces.7.html, openSUSE/catatonit `catatonit.c` at
  `main` and containers/common `docs/containers.conf.5.md` (`init_path`), read on 2026-10-14
- containers/podman v6.1.2 `libpod/oci_conmon_attach_common.go` (`setupStdioChannels`) and
  containers/common `pkg/detach/copy.go`: an exec's stdin through the detach keys, read on
  2026-10-14
