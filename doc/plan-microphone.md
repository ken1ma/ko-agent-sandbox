# Plan: the host microphone for voice dictation

Claude Code's `/voice` dictates through a recorder it spawns, Codex's `/voice` and agy's
`/voice` through an audio server or device they open, and the sandbox has no audio capture
device: no `/dev/snd`, no `/proc/asound`, and the launcher passes no `--device`. This plan adds a
`--mic` session option, under which a host relay records the host microphone and streams it
into a PulseAudio daemon inside the sandbox, on the channel pattern of the clipboard relay. The
agents record from the daemon as they do on any Linux desktop.

The requirement: with `--mic`, an unmodified Claude Code dictates through `/voice` in hold
and tap mode; agy dictates and Codex converses once their own gates allow, with Codex's replies
as transcript only; without `--mic`, nothing in the sandbox can record. Under `--mic` the host
microphone is open for the whole session, and its audio reaches the sandbox only while an agent
is recording.

The CLI's paths below are read from the image's `/usr/bin/claude` (2.1.295) and the other agents'
binaries on 2026-10-09, and from the voice dictation page on 2026-10-09 and 2026-10-11; "Tests"
lists what is unmeasured.

## Decisions

- **An option, not an environment variable.** A microphone grant is a per-launch choice the user
  makes in the launch command, like `--write` and `--egress`; a variable in a shell profile would
  hand every session the microphone unnoticed. The clipboard moves with it:
  `--clipboard=off|paste|bidirectional` replaces `KO_AGENT_SANDBOX_CLIPBOARD`, same grammar and
  default, so every grant of a host resource is spelled in the launch command.
- **No device passthrough.** `/dev/snd` would give every process in the sandbox the microphone
  with no host-side gate, and the macOS and Windows podman machines offer no microphone to pass
  (measured for Windows under "Windows, measured", unverified for macOS; the Linux case decides
  alone).
- **A host recorder program on every OS**, read by a relay that runs where the launcher lives:
  a shell job of the reaper on macOS and Linux, as the clipboard relay is, since the launcher
  hands over to the agent and no JVM stays for the session; a thread of the resident launcher on
  Windows. The launch names the package when the host has none.
  - On Windows the program is `sox_ng`, the maintained SoX
    (https://codeberg.org/sox_ng/sox_ng/releases, a single static `sox_ng.exe`), through its
    `waveaudio` driver; its first period arrives about 125 ms after the start and then every
    20 ms ("Windows, measured").
  - Java Sound (`javax.sound.sampled`), in the launcher thread on Windows or as a session job on
    macOS, is not used: it is a second capture implementation to own, a native-image launcher
    cannot carry it (doc/TODO.md), and its measurements ("Windows, measured") show nothing a
    program on `PATH` lacks.
  - WSLg's PulseAudio server, which the podman machine on the WSL provider mounts, is not used:
    it needs a helper container beside the socket, serves no Hyper-V machine, hangs 30 s when
    Windows has no capture device, and delivers audio at twice its level ("Windows, measured").
- **The host recorder runs for the whole session; the relay forwards only while an agent
  records.** A recorder started per dictation loses its own start on top of the relay's round
  trip, 660 to 810 ms of each dictation on macOS ("Latency"); a running recorder loses nothing
  of its own, and the relay keeps what arrives during the round trip and forwards it first, so
  the first word survives the round trip too.
  - The cost is a microphone open all session, macOS's indicator lit with it; SECURITY.md says
    so.
- **Linux hosts: the latest stable Debian, Fedora and Ubuntu.** The recorder program and its
  package are checked on those three; another host may work and is not claimed. The plan records
  the versions each check ran on.
- **A PulseAudio daemon in the sandbox, not a recorder shim.** Claude Code records through SoX's
  PulseAudio backend, the path the CLI's own documentation prescribes for WSL; agy through
  `parec`; Codex's helper through ALSA's PulseAudio plugin, the path it takes on WSLg. A stock
  daemon and a configuration file serve all three where a shim would have answered one agent's
  command lines. The daemon's microphone is a FIFO the relay writes; the daemon needs no device.
  - A null sink's monitor as the microphone, fed by `pacat --playback` from the writer, is the
    fallback if the boundary test ("Tests") finds samples crossing between dictations: it has no
    FIFO and no loopback, and a client's unrendered audio dies with its stream, but its delay is
    the sink's, where the pipe source adds none (the PulseAudio decision below).
- **PulseAudio, not PipeWire**, for two reasons: its pipe source adds no delay, and the server
  is one daemon and one file. The clients speak the PulseAudio protocol (SoX, `parec`) or ALSA
  (Codex's helper), and either server offers both, a pipe source and a null sink; Debian 13
  packages both. Read in both projects' `master` on 2026-10-09:
  - PulseAudio's `module-pipe-source` posts each chunk it reads. PipeWire's
    `module-pipe-tunnel` keeps a ring whose read index it sets 8192 frames behind the write
    index at every resync, and it resyncs at every underrun, which is the state at every
    recording's start: a dictation at 16000 Hz begins 512 ms late, hard-coded, and fills with
    silence while the FIFO is dry. The relay cannot recover a delay inside the module.
  - PipeWire is a core daemon, `pipewire-pulse` for the protocol and a session manager or a
    hand-written routing policy to link streams to the source, with nothing the sandbox's
    device-free graph needs from them.
  - The two agree on what "The daemon" below is built around, so the loopback that keeps the
    source running transfers unchanged either way: each makes its FIFO and opens it read-write
    and non-blocking, so a writer's close is never an EOF, and each reads the FIFO only while
    its stream is running (PulseAudio: `thread_func`'s `PA_SOURCE_RUNNING` test; PipeWire:
    `stream_state_changed` enabling `SPA_IO_IN` only in `STREAMING`, `tunnel.may-pause` off).
  - The choice is revisited if the Codex feasibility test fails on alsa-plugins' pulse PCM and
    passes on `pipewire-alsa`, which the test then tries second, at the delay above.
- **Codex is served if its helper accepts the daemon, which is measured, not assumed.** Its
  helper lists ALSA cards, and the sandbox has none; openai/codex#47370 shows it failing without
  an ALSA-to-PulseAudio bridge (its exit code 25) and later with one (code 37). Claude Code and
  agy justify the daemon on their own; Codex support is claimed in the README only after the
  feasibility test under "Tests" passes, and is otherwise recorded as blocked with the reason.
- **No playback to the host.** Codex's helper must open a speaker; the daemon's is a null sink.
  - Codex's spoken replies reach nothing, and the reply is read in the realtime transcript the
    TUI shows (unverified, "Tests").
  - One direction keeps the relay as it is; playback would be a pipe sink and a second relay
    direction, added without changing what is built first.
  - Playback would be its own option, never a default: sound a sandbox process puts on the
    host can imitate the user's tools or a person in the room, and reaches any microphone
    nearby, another device's included; with the microphone it also closes a loop from the
    host's speaker back into the sandbox.

## Today

### The CLI

On macOS and Windows the CLI records with its built-in module, and `arecord` and SoX are its
Linux fallbacks (the voice dictation page, "Requirements"). On Linux, `/voice` runs these checks
in order (`checkRecordingAvailability`, `checkVoiceDependencies`):

- `CLAUDE_CODE_REMOTE` set: "no audio device is available in this environment". The launcher
  sets nothing of the kind.
- The bundled `audio-capture.node` loads `libasound.so.2`, which the image has, and the CLI then
  requires a non-empty `/proc/asound/cards` not reading "no soundcards". Absent in the sandbox.
- `arecord --version` exits 0, and `arecord -f S16_LE -r 16000 -c 1 -t raw /dev/null` exits 0 or
  is still running 150 ms later: `arecord` is the recorder.
- Else `sox --version` and `rec --version` both exit 0: SoX `rec` is the recorder.
- Else: without SoX, "Voice mode requires SoX for audio recording. Install it with: sudo apt-get
  install sox"; with it, "Voice mode requires a microphone, but SoX could not open an audio
  capture device".

The image installs SoX (Containerfile, the Claude Code block) so the second message is the one a
session sees. Measured in the sandbox: `rec --version` itself fails with "Sorry, there is no
default audio device configured", so the SoX branch is never taken.

Recording through `arecord`: `arecord -f S16_LE -r 16000 -c 1 -t raw -q -`, stdout read as audio,
`SIGTERM` to stop. No silence detection is applied on this path (it is a SoX `silence` effect on
the `rec` path), so a hold-mode recording ends with the key and a tap-mode one with the second
tap.

The stream: a WebSocket to `wss://api.anthropic.com/api/ws/speech_to_text/voice_stream`
(`linear16`, 16000 Hz, one channel) with the claude.ai OAuth token as bearer, and a
`GET /api/hello` probe on the same host. The CLI passes its proxy setting to the WebSocket. The
ruleset's `allow https://api.anthropic.com/ tunnel` covers both; a profile without that host
fails `/voice` with "Voice stream error" after the recorder starts. An API key, Bedrock, Vertex or
Foundry session is refused before recording: "Voice mode requires a Claude.ai account".

### Other agents

Read from the image's binaries; each is a client of an audio server or a device, and none
spawns a recorder command as Claude Code does.

- Codex 0.162.0: `/voice` is a two-way realtime conversation, microphone and speaker, through
  its bundled helper `codex-resources/voice/bin/codex-voice-host`, a glibc build with its own
  GStreamer (`manifest.json`: `voiceTarget` gnu beside the musl `appTarget`).
  - The helper opens ALSA PCMs itself — it carries libasound, lists cards through
    `/dev/snd/controlC%i`, names `hw` and `plughw` — and `[realtime] audio` takes device
    names. In the sandbox it has no card to list.
  - openai/codex#47370 reports the same helper failing on WSLg through the ALSA PulseAudio
    plugin, on its playback stream.
- agy 1.3.2: `/voice` dictates into the prompt, under a permission the sign-in must carry.
  On Linux it records with `parec --raw` when `PULSE_SERVER` is set (its message names the
  package to install), or reads a microphone served by `agy mic-serve` on another machine at
  `127.0.0.1:4713`, agy's own protocol over an SSH forward.
- Copilot 1.0.94, kiro-cli 2.28.0 and OpenCode 1.18.35 dictate nothing.

### Windows, measured

Measured on 2026-10-11 on Windows Server 2025 (10.0.26100.32522) reached over Remote Desktop, WSL
3.0.1.0 with WSLg 1.0.79 (PulseAudio 17.0), a podman machine on the WSL provider, Oracle JDK
25.0.2, sox_ng 14.8.1 (win64 release zip) and VB-CABLE 3.3.1.7 as the capture device, since the
instance has no microphone (below). A 440 Hz tone at 0.3 of full scale played into the cable
stood for speech, so the timings include the cable's buffer and are not a microphone's.

- `sox_ng -q --buffer 640 -d -t raw -r 16000 -e signed -b 16 -c 1 -` records the default
  recording device at the tone's exact level (RMS 0.211, 128000 bytes for 4 s). Its process start
  takes 17 ms; the first 640-byte period reaches the pipe about 125 ms after the start and the
  next ones every 20 to 30 ms, in exact 640-byte pieces.
  - Without `--buffer`, SoX writes its output in 8192-byte blocks, 256 ms of this stream, the
    first about 490 ms after the start; `--buffer 1280` gives 1280-byte pieces at 40 ms. The
    option sizes the output write, not the driver's period.
  - Under each permission value at `Deny` ("The option"), and with the per-user `microphone`
    value absent, it exits after about 330 ms with
    `sox_ng FAIL formats: can't open input 'default': waveInOpen failed with code 1` and the
    system's text for that code, which names neither the microphone nor the permission.
  - With `NonPackaged` absent, or the machine-wide value absent, it records normally. On this
    image as installed, the per-user value is `Deny`, `NonPackaged` is `Allow` and the
    machine-wide value is `Allow`.
  - In one run after `Disable-PnpDevice` on the only capture endpoint it did not fail: the Wave
    Mapper opened and delivered silence at one LSB of noise (peak 0.00003) for as long as it ran,
    so neither exit status nor byte count showed the missing microphone, and a level test cannot
    tell that from a quiet room.
  - In a later run of the same command the endpoint again showed `Error` in `Get-PnpDevice`
    while the audio API still counted it active (below) and sox_ng recorded the tone at full
    level: the PnP status is not the audio API's state.
  - In the Remote Desktop session that hides every endpoint (below) it fails after about 350 ms
    with `sox_ng FAIL formats: can't open input 'default': sample format negotiation failed with
    code 2` and the system's text for a file not found: a session with no capture endpoint fails
    fast, where the silent run above did not.
  - `EnumAudioEndpoints(eCapture, DEVICE_STATE_ACTIVE)`, called from PowerShell through
    `Add-Type` COM interop ("The option"), counts 1 in a session that sees the cable and 0 in
    the Remote Desktop session that hides it; `Add-Type` compiles the script in 150 ms and a
    count takes 7 ms. The count and the recorder agreed in every run where both were measured.
- The podman machine has no ALSA capture device (`/dev/snd` holds `timer`), and WSLg mounts its
  PulseAudio server at `/mnt/wslg/PulseServer` into it, with `RDPSource` (s16le, mono, 44100 Hz)
  as the default source and `RDPSink` as the default sink. A rootless container with `/mnt/wslg`
  mounted reaches it with no cookie.
  - `parecord --raw --format=s16le --rate=16000 --channels=1 --latency-msec=20` on it delivers
    Windows's default capture device, resampled by WSLg's server, at twice the tone's level (RMS
    0.42); the first 20 ms period arrived 47, 57 and 68 ms after the start, with the source idle
    and the container already running.
  - With no capture device on Windows the source stays suspended, and a stream on it fails after
    30 s with "Connection failure: Timeout"; a launch probe needs its own bound.
- Java Sound (`javax.sound.sampled`) lists each capture endpoint as a DirectSound mixer, grants
  the 16000 Hz, 16-bit mono line directly, grants the requested 640-byte (20 ms) buffer, returns
  one period per `read`, delivered the tone at its level, and a `close()` from another thread
  returned a blocked `read` after 506 ms.
  - With "Microphone access" off the mixers are still listed and `open` fails with
    `LineUnavailableException: line with format ... not supported`, which names the format, not
    the cause. That value is `Deny` on this image as installed.
- A Remote Desktop session with sound played on the client sees only the redirected "Remote
  Audio" playback endpoint; the machine's own endpoints, active in the device store, are hidden
  from every program in that session. Windows App on macOS redirected no microphone to this
  server with the server's capture policy allowing it.
- The podman machine stops at sign-out; `podman machine start` brings it back.
- What signals a recording on Windows, the latencies against a real microphone, and the endpoint
  count with the only endpoint disabled in the audio API's state remain "Tests".

### macOS, measured

Measured on 2026-10-11 on an Apple silicon Mac (Homebrew's `arm64_tahoe` bottles) with sox_ng
14.8.1 from Homebrew and the Mac's microphone, speaking.

- `brew install sox_ng` installs the `rec` and `sox` names, with `coreaudio` as the one audio
  device driver. Claude Code's own `/voice` on the Mac dictates with the `sox` formula
  uninstalled, which says nothing about sox_ng: on macOS the CLI records with its built-in
  module ("The CLI").
- The first `rec` run from a shell raised macOS's microphone permission prompt, naming the
  terminal application.
- With the permission denied, in a newly installed terminal whose prompt was answered "Don't
  Allow", `rec` neither fails nor hangs: it ran until killed at 20 s and wrote 428036 bytes with
  a peak of 1 LSB, SoX's dither on zeros, and its first bytes came about 6.6 s after the start,
  once the prompt was answered. With dither off (`-D`) at the device's 48000 Hz, 3 s of recording
  were 144000 samples all exactly 0, where the dithered output had left none at 0.
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
  - So about 450 ms lies between the process start and the first period: SoX's CoreAudio
    driver querying the device and trying to set its format, creating the I/O proc, starting
    the device and filling the first buffer, and macOS's microphone permission check for the new
    process, in unmeasured proportion; the resampler adds up to 150 ms and the output buffer the
    rest. Runs back to back all paid it, so it is not a hardware wake-up.
- `podman exec <sandbox> true` on the Mac's podman machine takes 100 to 120 ms, which is the
  relay's round trip before the writer starts.

### The channel pattern

The clipboard relay (`ClipboardRelay`, SECURITY.md "Clipboard"): the sandbox writes a request to
a FIFO the host reads through `podman exec`, and the host answers through another exec; no host
listener, no port, nothing the host did not start. Its response is bounded, read whole and
returned once. A recording is a stream that runs until a stop, which that relay has no form for.

## After the change

### The option

- `--mic`, a session option like `--write`, never persisted. Absent, no daemon runs, no relay
  runs, and no `PULSE_SERVER` is set.
- At launch, before the container starts, the relay starts each candidate recorder in order
  ("The relay") and keeps the first that delivers bytes within a bound; that process is the
  session's recorder, so the probe and the recorder are one start.
  - None: the launch fails with each candidate's reason, and the package to install, as
    `hostBackend` fails a Linux launch with the clipboard and no xclip.
  - A recorder's environment — `XDG_RUNTIME_DIR`, a WSLg session's preset `PULSE_SERVER` — is
    the launcher's own, and is checked by that recording, not by name.
  - On macOS the probe is where the microphone permission prompt appears, at launch rather than
    at the first dictation, so its wait for the first bytes spans a prompt: after a few seconds
    without bytes it says it is waiting for the prompt, and gives up after a minute.
  - On macOS a denied permission records exact digital silence ("macOS, measured"), and so do
    a muted input and a microphone with a noise gate before anyone speaks; the recorder cannot
    tell them apart, so the probe reads its bounded moment with dither off.
    - All-zero samples print a warning and do not fail the launch: that the microphone delivered
      silence, that a denied permission (Privacy & Security > Microphone, for the terminal) and
      a muted input (Sound > Input) look like this, and that a gated input is silent until spoken
      into. The first dictation shows the rest, as for any probe that delivers bytes ("The
      relay").
  - On Windows the recorder decides and two diagnostics explain: in a session without a capture
    endpoint, and under each denied or absent permission value that stops it, the recorder fails
    within about 350 ms with a message that names neither cause ("Windows, measured"), so a
    recorder that fails ends the launch with the diagnostics' reading, and one that records
    proceeds, its all-zero window warning as on macOS.
    - Capture endpoints: a `powershell` child runs a script of the launcher's that calls
      `IMMDeviceEnumerator::EnumAudioEndpoints(eCapture, DEVICE_STATE_ACTIVE)` and
      `GetDefaultAudioEndpoint(eCapture, eCommunications)` through `Add-Type` COM interop and
      prints the count and whether a default exists (`E_NOTFOUND` when none).
      - The API filters by direction and state itself; an endpoint's instance id is a string
        whose format Microsoft leaves undefined, not a thing to parse.
      - It answers for the session: a Remote Desktop session with sound on the client shows its
        programs no capture endpoint while the device store under
        `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture` still holds the
        machine's own at `DeviceState` 1 ("Windows, measured"), so the store is not the check.
      - The script's count is measured with the cable visible and in the Remote Desktop session
        ("Windows, measured"); with the only endpoint disabled in the audio API's own state, which
        `Disable-PnpDevice` does not reliably produce, it is "Tests".
    - Permissions, the three `Value`s under `CapabilityAccessManager\ConsentStore` in
      `Software\Microsoft\Windows\CurrentVersion`: `microphone` under `HKCU` ("Microphone
      access"), `microphone\NonPackaged` under `HKCU` ("Let desktop apps access your
      microphone") and `microphone` under `HKLM` (the machine-wide policy), each `Allow`, `Deny`
      or absent.
      - A `Deny` in any of them, and an absent per-user `microphone` value, stop the recorder,
        while an absent `NonPackaged` or machine-wide value leaves it recording ("Windows,
        measured"); the diagnosis names the first such value's switch under Settings > Privacy &
        security > Microphone. The values explain a failure and decide nothing: what they mean
        on other Windows builds is unmeasured, and the recorder's failure is what is known.
- `--clipboard=<mode>` parses as `--write` does. The launcher no longer reads the variable from
  its own environment, and a set one fails the launch naming the option, so a profile that still
  exports it is not silently ignored. Inside the sandbox the launcher keeps setting
  `KO_AGENT_SANDBOX_CLIPBOARD`, and sets `KO_AGENT_SANDBOX_MIC=on` and
  `PULSE_SERVER=unix:/tmp/ko-agent-sandbox/microphone/pulse` alike.
- Under `--mic` the agent's environment also carries `SOX_OPTS=--buffer 640`, which SoX reads as
  its default global options (sox(1)): the CLI's own `rec` in the sandbox then writes 20 ms
  blocks where its default is 256 ms, which is audio in flight at the key's release ("Latency").
  sox(1) warns that the variable reaches every SoX run in that environment; under `--mic` that
  is what it is for.
- `--env` keeps refusing `KO_AGENT_SANDBOX_*`; no variable is added.

### The daemon

Under `--mic`, `ko-sandbox-entrypoint` starts a PulseAudio daemon before the agent, in the
foreground of a job it ends with the agent, from a script of the image and nothing else:
`pulseaudio -n --file=<the image's script> --daemonize=no --disallow-module-loading=yes
--disallow-exit=yes --exit-idle-time=-1`, where `-n` skips the default script and the module
restriction applies once the script's modules are loaded. `PULSE_CONFIG_PATH`,
`PULSE_STATE_PATH` and `PULSE_RUNTIME_PATH` point the daemon and every client at three
directories under the session's `/tmp` — `pulse-config`, `pulse-state`, `pulse-runtime` — so
no `daemon.conf`, `client.conf` or state is read from or written to `~/.config/pulse`; three
and not one, because `pa_get_state_dir` (`core-util.c`, read at `master` on 2026-10-09) breaks
when the state and runtime paths are the same directory. No D-Bus and no TCP module. The
script loads:

- `module-pipe-source` on `/tmp/ko-agent-sandbox/microphone/mic`, `s16le`, 16000 Hz, one
  channel, the default source. The module makes the FIFO and holds it open for reading and
  writing, so the relay's writer opens it without waiting and its closing is not an EOF.
- `module-null-sink` at the pipe source's sample spec (`format=s16le rate=16000 channels=1`),
  the default sink, for Codex's speaker; the loopback below then has no rate, format or channel
  difference to convert on its way to it.
- `module-loopback` from the pipe source to the null sink, with `adjust_time=0`. Its stream is a
  permanent output on the source, which keeps the source running, and a running pipe source
  reads its FIFO as bytes arrive.
  - The module makes its stream variable-rate whatever the specs (`PA_SINK_INPUT_VARIABLE_RATE`,
    `module-loopback.c`), so its resampler runs even at matching rates, at a ratio of one;
    `adjust_time=0` stops the rate readjustment it runs every second by default toward a latency
    target a drop path has no use for (both read at `v17.0` on 2026-10-11).
  - So audio written while no agent records is read and dropped into the null sink as the
    source's thread gets to it, and a stream an agent opens later gets what the source posts
    after it opened.
  - What can still cross from one dictation to the next is a period the writer delivered that
    the thread had not yet read when the next stream opened: a scheduling gap, not a buffer,
    and "Tests" measures it as zero under load rather than assuming it.
  - Without the loopback the source idles between recordings, stops reading, and delivers the
    end of one dictation at the start of the next; draining the FIFO from outside instead
    would race the source's own reads.
- `module-native-protocol-unix` on `/tmp/ko-agent-sandbox/microphone/pulse`, the socket
  `PULSE_SERVER` names, with `auth-anonymous=1 auth-cookie-enabled=0`.
  - Every process in the container is one uid and the socket reaches nothing outside it, so a
    cookie would authenticate the daemon to itself and leave a file to place.
  - The second option is what stops the module from making one: anonymous access alone leaves
    cookie handling on (`protocol-native.c`, `pa_native_options_parse`).
- No `module-suspend-on-idle`: a suspended source or sink would stop the loopback, and
  resuming one is a delay the first syllables pay.

What the image adds for the daemon's clients: `pulseaudio` and `pulseaudio-utils` (`parec`,
`pactl`); `libsox-fmt-pulse`, SoX's PulseAudio backend, which `/voice` records through: with it
`rec --version` exits 0, so the CLI takes its SoX branch, and `rec -t raw -r 16000 -e signed
-b 16 -c 1 -` reads the default source; `libasound2-plugins` and `/etc/asound.conf` making
ALSA's `default` PCM and control the PulseAudio ones, for Codex's helper. `alsa-utils` stays
out: the CLI probes `arecord` before SoX, and one path is enough.

Without `--mic` the packages are present and no daemon runs. What `/voice` then says — the
CLI's SoX branch is taken and `rec` fails to connect — is "Tests"; the requirement is that
nothing records.

### The controller and the writer

`ko-sandbox-mic`, a Python program (the image runs its status line with `python3 -I` already),
in two roles.

**The controller**, started by the entrypoint beside the daemon, is the one holder of the
recording state inside the sandbox, level-triggered: it keeps two facts current and acts on
their difference, on every event and every five seconds besides.

- *Demand*: whether an agent has a stream open on the microphone.
  - It subscribes with `pactl subscribe` first, then lists `pactl list short source-outputs`,
    and reconciles the list on each `source-output` event and on the timer, and on no other
    kind: `pactl subscribe` also reports clients, and each listing is a client, so a listing
    on every event would list forever.
  - It counts outputs on the pipe source whose driver is the native protocol's, which leaves
    out the loopback's own output and anything on the null sink's monitor.
  - Corked outputs count: an agent that corks its stream keeps the host recording, which none
    of the three does, and the short listing has no cork column.
- *Supply*: whether a writer is alive, by the pid file the writer makes under the channel's
  directory, which holds its pid and its start time from `/proc/<pid>/stat`.
  - The process is the writer only when both match, since a pid outlives its process in a
    file and is reused.
  - The controller holds the writer as a pidfd (`os.pidfd_open`, then the start-time check on
    that process) and signals through it (`signal.pidfd_send_signal`), so a pid reused between
    the check and the signal is not signalled.
- Demand and no supply: it writes `start` to the channel's `req` FIFO, one line under a bound,
  as the clipboard shim's.
  - The FIFO is opened for writing non-blocking, so a FIFO the relay has not made yet
    (`ENOENT`) or is not reading (`ENXIO`: the relay has not opened it, or is dead) is a relay
    unavailable, retried on the timer while demand persists and never a wait on the open.
  - A delivered `start` begins a wait of up to three seconds for a writer before the next
    `start`, so a slow exec gets one request, and a recorder that died while a stream is open
    gets a new one; a `start` not delivered begins no wait.
  - Requests the relay has not read yet queue in the FIFO, so a `start` can be read after its
    stream has closed, or several can: what a stale one costs is settled by the writer's first
    step, below, not by the controller.
  - A stream that closes between that step and `ready` forwards audio for one round trip until
    the controller sees no demand and ends the writer; so the claim is that a request stale
    when the writer checks forwards nothing, and a later closing ends the forwarding within the
    bound.
- Supply and no demand: it sends the writer `SIGTERM`, which ends the exec; the host does the
  rest ("The relay").
- A subscription that ends — the daemon gone — is no demand, and the controller exits with
  the daemon.

**The writer**, `ko-sandbox-mic write`, is what the relay's exec runs, in these steps:

- It lists the source outputs once, as the controller counts them: no demand, and it exits
  without a word, so a `start` read after its stream closed costs one exec and no microphone.
- It writes its pid file — pid and start time, written whole to a temporary name and renamed,
  and removed by the writer alone.
- It checks that the pipe source's path is a FIFO (`S_ISFIFO`, no following of links) and
  opens it for writing.
- Only then it writes `ready` and a newline to its stdout with `os.write`, the host's signal
  to start recording: after the FIFO is open, so the host never records into a writer that
  cannot take PCM, and never through Python's stdout, which a non-interactive process
  block-buffers and would hold while the writer waits on stdin.
- It copies its stdin to the FIFO with `os.read` and `os.write`, blocking, until its stdin
  ends or `SIGTERM` arrives. It watches nothing: the daemon reads the FIFO continuously, so a
  write never waits longer than the pipe's capacity, and a signal is the one interruption a
  blocking copy needs. Python's buffered streams would hold up to their buffer of audio,
  4 KiB being 128 ms, and `-I` ignores `PYTHONUNBUFFERED`.
`timeout` is not used around a stream: it bounds a whole command, which would cut a dictation
at the bound; the clipboard's `timeout 10 sh -c "cat > rsp"` fits a reply read whole, not
this.

### The relay

The channel: `/tmp/ko-agent-sandbox/microphone/req`, made by the relay's first exec; the
daemon's FIFO `mic` beside it.

- POSIX twin: a job of the reaper beside the clipboard's, `microphone_relay <podman> <sandbox>
  <recorder>...`, with the candidate recorders in probe order and the launcher's environment. It
  runs the launch probe ("The option"), and the recorder it keeps is the job's child for the
  session, writing into a FIFO of the job's own. The job reads `start`, and nothing else, or the
  line is refused.
  - The job's FIFOs live in a directory it makes with mode 0700 and are made with `mkfifo -m 600`,
    since the microphone's audio flows through them all session; the job removes the directory
    when it ends, and the reaper removes it after a `KILL`.
  - The job holds its FIFOs open read-write, since a read-only open of a FIFO blocks until a
    writer exists: the recorder's for the session, so the recorder never meets a closed pipe;
    the exec's stdin FIFO below per request, made and opened before the exec starts and closed
    and removed once the exec and the copy have ended, so a byte the exec left unread dies with
    its request and never reaches the next exec before its `ready`.
    - Linux allows the read-write open where POSIX leaves it undefined (fifo(7)); macOS is
      "Tests".
  - While no agent records, a `cat` drains the FIFO into `/dev/null`, so nothing accumulates.
  - Per `start` it ends the drain, so the recorder's FIFO keeps what the recorder writes from
    then on, and runs
    `podman exec -i <sandbox> ko-sandbox-mic write /tmp/ko-agent-sandbox/microphone/mic` with a
    second FIFO of the job's as its stdin, which nothing writes yet, waiting, bounded, for the
    line `ready` on the exec's stdout.
    - An exec that ends before `ready` was a stale `start`; anything else before it, or the
      bound passing, is a failure logged with what arrived; in both cases the drain resumes.
    - The recorder's FIFO is never the exec's stdin: podman reads the stdin it is given as soon
      as bytes arrive, whether or not the contained process reads them (podman-exec(1),
      `--interactive`), so audio handed to it before `ready` would reach the sandbox on a stale
      `start`, into a pipe any process of the one uid can open through `/proc`.
  - On `ready` a `cat` copies the recorder's FIFO into the exec's stdin FIFO, beginning with
    what the pipe kept during the round trip, so the audio of the round trip reaches the agent
    too; the job reads the next request only when the exec and the copy have ended: the loop is
    sequential, as the clipboard's is, because the recording's end arrives as the exec's end,
    not as a line.
  - The recorder FIFO's capacity bounds what a slow exec keeps: 64 KiB, 2 s of this stream, by
    default on Linux, and pipe(7) fixes none. A full pipe blocks the recorder's write and the
    driver drops audio until the exec's bound ends the request as a logged failure; "Tests" fills
    the pipe on purpose and watches the recorder recover.
  - Every path on both sides is absolute: an exec's working directory is the container's, not
    the channel's.
- A forwarding ends, and the exec and the copy with it, when any of these happens:
  - the exec ends: the controller ended the writer, or it died, or the daemon is gone;
  - the recorder ends, or delivers no bytes for five seconds, silence being bytes too: it is
    logged with its exit status and its stderr's first line to the launcher's log, where a
    permission refusal or a device that disappeared is read, and started again at the next
    request, which then pays its start;
  - the container stops, as the clipboard's loop ends;
  - the session ends: the reaper `KILL`s the job's tree, recorder included.
  The drain resumes after each; ending a child is `SIGTERM`, then `SIGKILL` after a bound.
- Windows twin: a thread of the resident launcher running the same loop, the recorder its child
  for the session, the exec its child per request. A reading thread discards the recorder's
  output while idle, holds it in memory from the request on, and writes nothing to the exec's
  stdin before `ready`, for the reason the POSIX twin gives; from `ready` it forwards.
  - Windows has no `SIGTERM`: the thread ends the exec with `Process.destroy()`
    (`TerminateProcess`), and the recorder ends with the launcher.
- The recorder program, writing raw signed 16-bit little-endian mono at 16000 Hz, the
  candidates in launch-probe order:
  - Every SoX command carries `--buffer 640` and `-D`. SoX writes its output in `--buffer`-sized
    blocks, 8192 bytes by default, which is 256 ms of this stream and arrives as such ("Windows,
    measured"); 640 bytes is one 20 ms period. SoX dithers its 16-bit output by default, which
    turns a silent input into samples of plus and minus one; `-D` keeps silence exact, which the
    probe's warning reads ("macOS, measured").
  - macOS: SoX `rec -q -D --buffer 640 -t raw -r 16000 -e signed -b 16 -c 1 -`. The launch error
    names `brew install sox_ng`, whose formula installs the `rec` name; `brew install sox` serves
    too, and Homebrew refuses to install both. sox_ng's CoreAudio driver and its timing are
    measured ("macOS, measured"). macOS has no built-in recorder command.
  - Windows: `sox_ng -q -D --buffer 640 -d -t raw -r 16000 -e signed -b 16 -c 1 -`, `-d` being the
    Sound control panel's default recording device through the `waveaudio` driver, from the
    release zip's `sox_ng.exe` on `PATH` or from `winget install --id sox_ng.sox_ng -e`, whose
    manifests trail the release (14.7.1.2 against 14.8.1 on 2026-10-11); the launch error names
    both.
  - Linux, first: `arecord -q -D default -t raw -f S16_LE -r 16000 -c 1 -B 80000 -F 20000`
    (`alsa-utils`), one command whichever server owns the microphone, if each host's desktop
    edition routes ALSA's `default` PCM to it ("Tests").
  - Linux, then: `parecord --raw --format=s16le --rate=16000 --channels=1 --latency-msec=20`
    (`pulseaudio-utils`) for a host where `default` is not routed, as on WSLg. It runs with a
    `PULSE_CLIENTCONFIG` that sets `autospawn = no`, so the probe starts no daemon of its own;
    a server the host's systemd starts on its socket is the host's configuration, not the
    probe's.
  - The package names are what the launch error names.
  - A probe that delivers bytes shows a source that records, not that it is a microphone: a
    monitor or null source records silence. The launch prints which device the recorder
    opened, when the program can say, and the first dictation shows the rest.
- What the host holds is one pipe and, between a request and `ready`, its contents; nothing is
  buffered to a file. The stream's rate is 32 kB/s.

### Latency

A client's stream opens at the key press, and the relay keeps the audio from the request on, so
what the agent never hears is what is said between the key press and the request: the
controller's event and one FIFO write, within the controller's timer resolution.

- The round trip, one `podman exec` of 100 to 120 ms on the Mac's podman machine ("macOS,
  measured"), delays the first bytes and loses none; the daemon and SoX add their own buffers;
  the source itself is already running, so no resume is paid.
- The numbers behind the session-long recorder ("Decisions"): a recorder started per dictation
  pays its own start first, 550 to 700 ms on macOS, of which about 450 is its device setup after
  the process start and is paid on every start, and 125 ms on Windows; with the round trip, a
  per-dictation relay would lose about 660 to 810 ms of each dictation on macOS. What the CLI's
  own path loses on the same host, its built-in module's start, is "Tests".

At the key's release the CLI sends `rec` `SIGTERM` and, in the same step, closes its stream to
the transcription server; chunks arriving after that are dropped (`[voice_stream] Dropping
audio chunk after CloseStream`), so nothing after the key reaches the transcript.

- The word ending lost is the audio in flight between the host's microphone and the CLI at that
  moment: the recorder's period, the exec, the daemon and SoX's buffer. The pipeline is kept
  short (a 20 ms period, no buffering in the relay) and the loss is measured.
- The CLI's own `rec` in the sandbox would hold up to 8192 bytes, 256 ms, when `SIGTERM`
  arrives; `SOX_OPTS` ("The option") makes that 640 bytes, and "Tests" measures the word ending
  with and without it.

### Security

SECURITY.md gains "Microphone", with the clipboard section's form, and keeps these apart:

- **The grant is to the container, for the session.** Under `--mic`, any process in the
  sandbox can open a stream on the daemon's microphone, as often and as long as it likes, with
  no per-recording consent; an open stream is a process recording, which need not be the user
  dictating. The sandbox asks; the host answers: no host listener, no port, no proxy rule, and
  the daemon's socket reaches nothing outside the container.
- **What an agent transcribes is not shown to be the host microphone.** The pipe source's FIFO
  is a file in the container (the module makes it mode 0666, and the container is one uid), so
  any process in the sandbox can write PCM into the microphone source, and an agent dictating
  then transcribes that.
  - The channel guards the host microphone's confidentiality, not the authenticity of audio
    inside the sandbox, where every process already shares the agent's files and trust;
    SECURITY.md says so beside the grant.
- **When the host microphone is open.** From the launch probe to the session's end, whether or
  not an agent records; the relay discards the audio as it arrives, buffering none, except
  between a request and the writer's `ready`, and the pipes it flows through on the host are the
  user's alone ("The relay").
  - Audio reaches the sandbox from a request until the controller sees the last stream close,
    or until the writer's death, the exec's end, the container or the session. There is no
    bound on how long a process keeps a stream open.
  - macOS shows its microphone indicator for the whole session; nothing else signals the grant,
    and nothing signals a forwarding.
- What leaves the host is the agent's doing: Claude Code streams the audio to Anthropic, agy to
  Google and Codex to OpenAI, under the egress rules the session already has.
- Without `--mic`, no daemon runs and no FIFO exists; the image has no other capture path.

## Documentation

- README's Reference block (which `--help` prints): `--mic` and `--clipboard` under the
  session options, the former with the host program each OS needs and the sentence that the
  microphone stays open for the session, and the variable gone from the environment table; the
  `claude` section: `/voice` needs `--mic`; the `codex` and `agy` sections: what their `/voice`
  does under it, as measured.
- SECURITY.md "Clipboard", `doc/plan-clipboard.md`, `doc/design.md` and the clipboard shim's
  comment: the option's name where the variable's was.
- SECURITY.md "Microphone", above.
- `doc/design.md`, the relay list: the microphone relay beside the clipboard relay and the
  runner.
- The Containerfile: the audio packages' comment names the daemon and the three clients; SoX's
  says it is `/voice`'s recorder under `--mic`.

## Tests

### Unit

- The controller, against a fake daemon (a `pactl` stand-in for `subscribe` and `list`) and
  a fake writer:
  - demand is built from the list after subscribing and reconciled on each `source-output`
    event and on the timer; the loopback's output and outputs on the monitor do not count;
  - `start` is sent on demand without supply and not again within three seconds; a writer
    that dies under demand gets a new `start`;
  - a writer alive without demand gets `SIGTERM`, a writer arriving after its stream closed
    too;
  - a stream that closes and another that opens between two observations is handled as the
    events say; the controller exits when the subscription ends.
- Boundaries, on the real daemon: identifiable sequence A is written to the FIFO while no
  stream is open, then a stream opens and sequence B is written, and the stream reads no
  sample of A; the same with A's stream closing and B's opening in quick succession.
  - Both repeated under CPU load and with the daemon's reading delayed on purpose (`SIGSTOP`
    on the daemon around the boundary), recording how many samples of A reach B.
  - A count above zero is evidence that a FIFO fed by a separate process cannot promise a
    strict boundary under those conditions, to be recorded as the design's limit, not a
    timing to tune.
- Stale `start`: the exec's start is delayed past several resend intervals, then the stream
  closes; each queued `start` costs one exec that ends without `ready`, and nothing is
  forwarded; a stream closed between the writer's demand check and `ready` sees the forwarding
  end within the bound; a writer whose pid a later process reuses is not taken for supply, and a
  pid reused after the check is not signalled.
- `ready` is read by the host when the writer waits on stdin, which is a test that it is
  written unbuffered and after the FIFO is open; `ready` after a FIFO that fails to open
  never appears; the exec starts with its stdin FIFO as yet unwritten, which is a test that the
  job holds that FIFO open.
- Saturation: `ready` is delayed until the recorder's FIFO is full; the recorder's write blocks,
  the request ends as a logged failure at the bound, the drain resumes, the recorder is running
  or restarted, and the next request records.
- The relay's grammar: `start` and nothing else; a refused line ends the stream's reading; a
  `start` read during a recording is read after it; forwarding begins only on `ready`, and an
  exec that ends without it within the bound forwards nothing and resumes the drain.
- Integrity: a known PCM sequence fed to a fake recorder on the host is read back from the
  daemon by `parec` at the same sample spec, sample for sample.
- Forwarding, against a fake recorder and an exec stand-in that reads its stdin as eagerly as
  podman does:
  - while idle, nothing the recorder writes reaches the sandbox and nothing accumulates; from
    `start`, what it writes is kept, and the stand-in receives no byte before `ready`;
  - on `ready` the kept audio arrives first and whole, followed by the live stream with no gap
    or repeat; a stale `start` discards what was kept;
  - across two requests, identifiable audio the first exec left unread in its stdin at its end
    reaches the second exec in no byte, before or after its `ready`;
  - a chunk written during forwarding reaches the daemon's FIFO before the next one, so the
    writer holds no audio; the elapsed time from a client's stream to its first byte is recorded
    as a distribution under "Live", not asserted here.
- Ending:
  - the last stream's close ends the exec and the forwarding within the bound while PCM is
    flowing, the recorder keeps running and the drain resumes, and the writer's `SIGTERM`
    interrupts a copy blocked in `os.write`;
  - a recorder that writes nothing for five seconds, idle or forwarding, is ended and logged,
    and the next request starts a new one; a recorder that fails at launch fails the launch;
  - the container's stop ends the relay; the session's end `KILL`s the recorder and a
    forwarding in progress;
  - the writer refuses a path that is not a FIFO.
- The daemon: it starts from the image's script with no device, no D-Bus and no home
  directory, reads and writes nothing under `~/.config/pulse` with the three `PULSE_*_PATH`
  variables set to their three directories, makes no cookie file anywhere, serves `pactl info`
  on the socket `PULSE_SERVER` names, refuses `pactl load-module`, and ends with the agent.
- The controller's own listings: the client events its `pactl list` runs cause trigger no
  further listing, so an event-driven reconciliation settles after one listing.
- Stability, an hour of the recorder running with `adjust_time=0` and the clocks of the host's
  audio and the null sink's timer uncompensated: the pipe source stays `RUNNING`, the loopback's
  output stays on it with its latency bounded, and a stream opened at the end records as one did
  at the start.
- The controller against the relay's absence: demand before the relay's first exec made `req`
  (`ENOENT`), a `req` nobody reads (`ENXIO`), and a relay that dies while demand persists: no
  blocked open, a retry on each timer tick, no three-second wait after an undelivered `start`,
  and `start` delivered on the first tick after the relay is back.
- The launch probe: each OS's candidate order, the first that delivers bytes is kept, and the
  launch failure names every candidate's reason and the package to install.
  - On Windows, against a stand-in for the endpoint script: a recorder stand-in that fails ends
    the launch with the message for a count of zero, a missing default endpoint, a `Deny` in any
    of the three permission values or an absent per-user `microphone` value, whichever the
    diagnostics show, and a recorder stand-in that records proceeds whatever they show.
  - On macOS, a fake recorder delivering zeros prints the silence warning and the launch
    proceeds.
- The Windows twin's ending: `destroy()` ends the exec, the forwarding ends with it within the
  bound, and the recorder keeps running with its output discarded again.
- The CLI contract: a test reads the image's `/usr/bin/claude` for the recorder order, the
  `rec --version` probe and the exact `rec` argument vector, and fails the build when a Claude
  Code release changes them, as `doc/plan-clipboard.md` rechecks each agent's clipboard
  commands; the paths served are a contract with one CLI version, not a guarantee.

### Live

- macOS: the microphone permission prompt appears at the launch probe and names the terminal
  when the recorder is the launcher's and the reaper's child, as it does for a shell's child
  ("macOS, measured"); the probe waits through the prompt and says so; a denied permission and
  a muted input each print the silence warning and the launch proceeds; a microphone with a
  noise gate, silent at launch, dictates once spoken into.
- macOS, the job's FIFOs: the read-write opens succeed with no other process at either end, the
  exec starts with its stdin FIFO unwritten, and a per-request FIFO is closed and removed
  without blocking ("The relay").
- Claude Code: hold and tap mode dictation end to end; what `/voice` says without `--mic`.
- agy: `/voice` records through `parec` under `--mic`, with a sign-in that carries its
  permission; what it says without one.
- Codex, the feasibility test its support waits on, with the bundled helper:
  - whether it lists and opens ALSA's `default` through the PulseAudio plugin with no card to
    list, and whether the null sink satisfies its speaker;
  - whether capture and playback then run together for minutes without either stream failing
    (openai/codex#47370's code 37 is that failure, and the image would then carry
    alsa-plugins' fix); a failure in alsa-plugins' pulse PCM is retried on PipeWire with
    `pipewire-alsa` ("Decisions");
  - whether the reply appears as transcript;
  - whether its feature gate ("Voice conversations are not enabled") opens for this sign-in.
    A closed gate blocks the test, and the README then says so; the others are the daemon's
    to pass.
- `--egress=deny-all`: the recording starts and each agent reports its own stream error.
- Windows: the endpoint script's count with the only capture endpoint disabled in the audio API's
  state, through the Sound control panel's Disable, and whether `sox_ng -D` then records exact
  zeros, as `rec -D` does on macOS; on a real microphone, what signals a recording, and the two
  latencies below.
  - Measured already ("Windows, measured"): the recorder's output timing, its behavior in a
    session without an endpoint and under each permission value present or absent, and the
    script's count in both sessions.
- The latest stable Debian, Fedora and Ubuntu, desktop editions: which recorder programs their
  default installs carry, whether ALSA's `default` PCM reaches the desktop's microphone, the
  package to name when none is found, and the environment the reaper's job needs to find the
  audio server's socket (`XDG_RUNTIME_DIR`, `PULSE_SERVER`).
- The first word of a dictation: with the recorder running all session and the round trip's
  audio kept, whether it arrives whole, against the CLI's own path on the same host, whose
  built-in module's start is unmeasured; and the delay from the key press to the first forwarded
  byte.
- Word endings on `SIGTERM`: how much audio is in flight at the key's release, with and without
  `SOX_OPTS` in the agent's environment, against the CLI's own path on the same host.

## Excluded

- Device passthrough, patches to the agents, and playback to the host: Codex's spoken replies
  are not heard.
- agy's `mic-serve` protocol: its `parec` path is served instead.
- Sessions whose profile excludes an agent's transcription host: the agent's stream, not the
  relay, fails.

## Sources

- https://code.claude.com/docs/en/voice-dictation.md
- https://code.claude.com/docs/en/settings-reference.md (`voice`, `voiceEnabled`)
- The image's `/usr/bin/claude` 2.1.295: the recorder selection, the `arecord` and `rec`
  command lines, and the stream URL
- The image's `/opt/codex/bin/codex` 0.162.0 and `codex-resources/voice/`, `/usr/local/bin/agy`,
  `copilot`, `kiro-cli` and `opencode`: the other agents' voice paths
- https://github.com/openai/codex/issues/47370
- https://github.com/pulseaudio/pulseaudio/blob/master/src/modules/module-pipe-source.c and
  https://github.com/PipeWire/pipewire/blob/master/src/modules/module-pipe-tunnel.c, both read
  at `master` on 2026-10-09
- PulseAudio's `src/pulsecore/core-util.c` (`pa_get_state_dir`), `src/pulsecore/protocol-native.c`
  (`pa_native_options_parse`) and `src/utils/pactl.c` (the subscription mask), read the same day
- https://manpages.debian.org/trixie/pulseaudio-utils/pacat.1.en.html (`parec`, `parecord`) and
  https://manpages.debian.org/trixie/sox/soxformat.7.en.html (`waveaudio`), read on 2026-10-11
- https://codeberg.org/sox_ng/sox_ng/releases (14.8.1, its `README.win32` and `sox_ng.txt` for
  `-d` and `--buffer`), Homebrew's `sox_ng` formula (`--enable-replace`) and the sox_ng wiki's
  "Distros" page (Debian testing ships sox_ng as `sox`), read on 2026-10-11
