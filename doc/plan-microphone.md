# Plan: the host microphone for voice dictation

Claude Code's `/voice` dictates through a recorder it spawns, Codex's `/voice` and agy's
`/voice` through an audio server or device they open, and the sandbox has no audio capture
device: no `/dev/snd`, no `/proc/asound`, and the launcher passes no `--device`. This plan adds a
`--mic` session option, under which a host relay records the host microphone and streams it
into a PulseAudio daemon inside the sandbox, on the channel pattern of the clipboard relay. The
agents record from the daemon as they do on any Linux desktop.

The requirement: with `--mic`, an unmodified Claude Code dictates through `/voice` in hold
and tap mode; agy dictates and Codex converses once their own gates allow, with Codex's replies
as transcript only; without `--mic`, nothing in the sandbox can record. The host records only
while an agent is recording.

The CLI's paths below are read from the image's `/usr/bin/claude` (2.1.295), the other agents'
binaries and the voice dictation page on 2026-10-09; "Tests" lists what is unmeasured.

## Decisions

- **An option, not an environment variable.** A microphone grant is a per-launch choice the user
  makes in the launch command, like `--write` and `--egress`; a variable in a shell profile would
  hand every session the microphone unnoticed. The clipboard moves with it:
  `--clipboard=off|paste|bidirectional` replaces `KO_AGENT_SANDBOX_CLIPBOARD`, same grammar and
  default, so every grant of a host resource is spelled in the launch command.
- **No device passthrough.** `/dev/snd` would give every process in the sandbox the microphone
  with no host-side gate, and the macOS and Windows podman machines offer no microphone to pass
  (unverified for the machines; the Linux case decides alone).
- **A host recorder program on macOS and Linux, Java Sound on Windows.**
  - On macOS and Linux the launcher hands over to the agent and no JVM stays for the session,
    so the relay is a shell job of the reaper, as the clipboard relay is, and the microphone
    is read by a program the host has; the launch names the package when it has none.
  - On Windows the launcher is resident, so its thread records with the JDK's
    `javax.sound.sampled` and the host installs nothing. Java Sound is not available in a
    native-image launcher; doc/TODO.md's native-image item records why and what the Windows
    relay needs there instead.
  - A per-session JVM job recording with Java Sound on macOS too, sparing the SoX install, was
    weighed and set aside: it trades one Homebrew package for a process alive all session and
    a second capture implementation to own. It is reopened only if, after the Windows twin is
    measured, the SoX dependency still matters and Java Sound's capture on macOS is tested on
    its own, permission prompt included.
- **Linux hosts: the latest stable Debian, Fedora and Ubuntu.** The recorder program and its
  package are checked on those three; another host may work and is not claimed. The plan records
  the versions each check ran on.
- **A PulseAudio daemon in the sandbox, not a recorder shim.** Claude Code records through SoX's
  PulseAudio backend, the path the CLI's own documentation prescribes for WSL; agy through
  `parec`; Codex's helper through ALSA's PulseAudio plugin, the path it takes on WSLg. A stock
  daemon and a configuration file serve all three where a shim would have answered one agent's
  command lines. The daemon's microphone is a FIFO the relay writes; the daemon needs no device.
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

`/voice` runs these checks in order (`checkRecordingAvailability`, `checkVoiceDependencies`):

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

### The channel pattern

The clipboard relay (`ClipboardRelay`, SECURITY.md "Clipboard"): the sandbox writes a request to
a FIFO the host reads through `podman exec`, and the host answers through another exec; no host
listener, no port, nothing the host did not start. Its response is bounded, read whole and
returned once. A recording is a stream that runs until a stop, which that relay has no form for.

## After the change

### The option

- `--mic`, a session option like `--write`, never persisted. Absent, no daemon runs, no relay
  runs, and no `PULSE_SERVER` is set.
- At launch, before the container starts, the launcher records on the host into nothing for a
  bounded moment with each candidate recorder in order ("The relay") and keeps the first that
  delivers bytes; on Windows it opens the Java Sound line instead.
  - None: the launch fails with each candidate's reason, and the package to install, as
    `hostBackend` fails a Linux launch with the clipboard and no xclip.
  - A recorder's environment — `XDG_RUNTIME_DIR`, a WSLg session's preset `PULSE_SERVER` — is
    the launcher's own, and is checked by that recording, not by name.
  - On macOS the probe is where the microphone permission prompt appears, at launch rather than
    at the first dictation.
- `--clipboard=<mode>` parses as `--write` does. The launcher no longer reads the variable from
  its own environment, and a set one fails the launch naming the option, so a profile that still
  exports it is not silently ignored. Inside the sandbox the launcher keeps setting
  `KO_AGENT_SANDBOX_CLIPBOARD`, and sets `KO_AGENT_SANDBOX_MIC=on` and
  `PULSE_SERVER=unix:/tmp/ko-agent-sandbox/microphone/pulse` alike.
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
- `module-null-sink`, the default sink, for Codex's speaker.
- `module-loopback` from the pipe source to the null sink. Its stream is a permanent output
  on the source, which keeps the source running, and a running pipe source reads its FIFO as
  bytes arrive.
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
  - A stream that closes between that step and `ready` opens the microphone for one round trip
    until the controller sees no demand and ends the writer; so the claim is that a request
    stale when the writer checks opens no microphone, and a later closing ends it within the
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
  <recorder>`, with the recorder the launch probe selected and the launcher's environment. It
  reads `start`, and nothing else, or the line is refused.
  - Per `start` it runs
    `podman exec -i <sandbox> ko-sandbox-mic write /tmp/ko-agent-sandbox/microphone/mic` and
    waits, bounded, for the line `ready` on its stdout. An exec that ends before it was a
    stale `start`; anything else before it, or the bound passing, is a failure logged with
    what arrived; in neither case does a recorder start.
  - On `ready` it starts the recorder, both as tracked children, copies the recorder's stdout
    into the exec's stdin, and reads the next request only when both have ended: the loop is
    sequential, as the clipboard's is, because the recording's end arrives as the exec's end,
    not as a line.
  - Every path on both sides is absolute: an exec's working directory is the container's, not
    the channel's.
  - A recorder that ends without bytes, or at all, is logged with its exit status and its
    stderr's first line to the launcher's log, which is where a permission refusal or a device
    that disappeared is read.
- The recording ends, and both children with it, when any of these happens:
  - the exec ends: the controller ended the writer, or it died, or the daemon is gone;
  - the recorder ends, or delivers no bytes for five seconds: a recorder whose backend hung
    writes nothing;
  - the container stops, as the clipboard's loop ends;
  - the session ends: the reaper `KILL`s the job's tree.
  Ending is `SIGTERM`, then `SIGKILL` after a bound; the relay waits for both children before
  it reads the next request.
- Windows twin: a thread of the resident launcher running the same loop, the recorder a Java
  Sound line in place of a program; unmeasured.
  - `AudioSystem.getTargetDataLine` for 16000 Hz, 16-bit signed, mono, little-endian, opened,
    then `start()`, without which a line delivers nothing.
  - A mixer that offers no such line refuses it with `IllegalArgumentException`, and the
    thread then opens the line in a format the mixer offers and converts to the required one
    itself, resampling and mixing channels included.
  - The line's buffer is the smallest the mixer grants, so a period is read as soon as it is
    captured.
  - The copy runs in its own thread, and the loop's thread closes the line when the exec ends
    or the five-second deadline passes, which returns a `read` blocked on it; the capture
    thread never has to notice on its own.
- The recorder program, writing raw signed 16-bit little-endian mono at 16000 Hz, the
  candidates in launch-probe order:
  - macOS: SoX `rec -q -t raw -r 16000 -e signed -b 16 -c 1 -`, which `brew install sox`
    provides and the CLI's own documentation names for macOS. macOS has no built-in recorder
    command.
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
- What the host holds is one pipe; nothing is buffered to a file. The stream's rate is 32 kB/s.

### Latency

A client's stream opens at the key press; the controller's event, the request, one `podman
exec` round trip on the machine and the recorder's own start come before the first audio bytes
reach the daemon, and the daemon and SoX add their own buffers; the source itself is already
running, so no resume is paid. Whether that loses the first syllables
is "Tests"; the mitigation, if needed, is a relay that keeps the recorder running between
requests and gates only the copy, which changes "The host records only while an agent is
recording" above and is not planned until measured.

At the key's release the CLI sends `rec` `SIGTERM` and, in the same step, closes its stream to
the transcription server; chunks arriving after that are dropped (`[voice_stream] Dropping
audio chunk after CloseStream`). So nothing after the key reaches the transcript, and the word
ending lost is the audio in flight between the host's microphone and the CLI at that moment:
the recorder's period, the exec, the daemon and SoX's buffer. The pipeline is kept short (a
20 ms period, no buffering in the relay) and the loss is measured.

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
- **When the host microphone is open.** At launch, for the probe's bounded moment, with no
  agent running; then only while a stream is open on the daemon's microphone.
  - A recording ends when the controller sees the last stream close, and also with the
    writer's death, the exec's end, the container or the session. There is no bound on how
    long a process keeps a stream open.
  - macOS shows its microphone indicator while the host records; nothing else signals a
    recording.
- What leaves the host is the agent's doing: Claude Code streams the audio to Anthropic, agy to
  Google and Codex to OpenAI, under the egress rules the session already has.
- Without `--mic`, no daemon runs and no FIFO exists; the image has no other capture path.

## Documentation

- README's Reference block (which `--help` prints): `--mic` and `--clipboard` under the
  session options, the former with the host program each OS needs, and the variable gone from
  the environment table; the `claude` section: `/voice` needs `--mic`; the `codex` and `agy`
  sections: what their `/voice` does under it, as measured.
- doc/TODO.md, the native-image item: Java Sound's absence there and the recorder program the
  Windows relay needs instead.
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
  closes; each queued `start` costs one exec that ends without `ready`, and the host recorder
  never starts; a stream closed between the writer's demand check and `ready` sees the
  recorder end within the bound; a writer whose pid a later process reuses is not taken for
  supply, and a pid reused after the check is not signalled.
- `ready` is read by the host when the writer waits on stdin, which is a test that it is
  written unbuffered and after the FIFO is open; `ready` after a FIFO that fails to open
  never appears.
- The relay's grammar: `start` and nothing else; a refused line ends the stream's reading; a
  `start` read during a recording is read after it; the recorder starts only on `ready`, and an
  exec that ends without it within the bound starts none.
- Integrity: a known PCM sequence fed to a fake recorder on the host is read back from the
  daemon by `parec` at the same sample spec, sample for sample.
- Forwarding: with the recorder running, a chunk it writes reaches the daemon's FIFO before it
  writes the next one, so the writer holds no audio; the elapsed time from a client's stream to
  its first byte is recorded as a distribution under "Live", not asserted here.
- Ending:
  - the last stream's close ends the host recorder within the bound while PCM is flowing, and
    the writer's `SIGTERM` interrupts a copy blocked in `os.write`;
  - a recorder that writes nothing is ended after five seconds; a recorder that fails to start
    leaves the daemon's microphone silent and the launcher's log its reason;
  - the container's stop ends the relay; the session's end `KILL`s a recording in progress;
  - the writer refuses a path that is not a FIFO.
- The daemon: it starts from the image's script with no device, no D-Bus and no home
  directory, reads and writes nothing under `~/.config/pulse` with the three `PULSE_*_PATH`
  variables set to their three directories, makes no cookie file anywhere, serves `pactl info`
  on the socket `PULSE_SERVER` names, refuses `pactl load-module`, and ends with the agent.
- The controller's own listings: the client events its `pactl list` runs cause trigger no
  further listing, so an event-driven reconciliation settles after one listing.
- The controller against the relay's absence: demand before the relay's first exec made `req`
  (`ENOENT`), a `req` nobody reads (`ENXIO`), and a relay that dies while demand persists: no
  blocked open, a retry on each timer tick, no three-second wait after an undelivered `start`,
  and `start` delivered on the first tick after the relay is back.
- The launch probe: each OS's candidate order, the first that delivers bytes is kept, and the
  launch failure names every candidate's reason and the package to install; on Windows, a
  line that opens and delivers bytes passes, and a mixer with no line fails the launch with
  the exception's message.
- The Windows line's format: a fake mixer refusing 16000 Hz mono is opened in its own format
  and the thread's conversion yields the required rate, channel count and duration, and a
  known tone's frequency and amplitude within a tolerance, since resampling preserves no
  sample for sample; a close from the loop's thread returns a `read` blocked on the line.
- The CLI contract: a test reads the image's `/usr/bin/claude` for the recorder order, the
  `rec --version` probe and the exact `rec` argument vector, and fails the build when a Claude
  Code release changes them, as `doc/plan-clipboard.md` rechecks each agent's clipboard
  commands; the paths served are a contract with one CLI version, not a guarantee.

### Live

- macOS: the microphone permission prompt appears at the launch probe, and which application
  it names (the terminal, as the responsible process of the launcher and of the reaper's job;
  unverified); a denied permission fails the launch with the message, not a hang.
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
- Windows: the resident twin's line opens, and what signals a recording there.
- The latest stable Debian, Fedora and Ubuntu, desktop editions: which recorder programs their
  default installs carry, whether ALSA's `default` PCM reaches the desktop's microphone, the
  package to name when none is found, and the environment the reaper's job needs to find the
  audio server's socket (`XDG_RUNTIME_DIR`, `PULSE_SERVER`).
- The first-byte latency from a key press, with the microphone idle, which the host's server
  may have suspended. Whether `/voice` loses the first syllables on this path more than on
  the CLI's native one on the same host decides whether the relay keeps the recorder running.
- Word endings on `SIGTERM`: how much audio is in flight at the key's release, against the
  CLI's native path on the same host.

## Excluded

- Device passthrough, patches to the agents, and playback to the host: Codex's spoken replies
  are not heard.
- A native-image launcher's Windows relay: Java Sound is not available there (doc/TODO.md),
  and the recorder program it needs instead is that item's.
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
