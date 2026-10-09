# Plan: the host microphone for Claude Code's `/voice`

Claude Code's `/voice` dictates through a recorder it spawns, and the sandbox has no audio capture
device: no `/dev/snd`, no `/proc/asound`, and the launcher passes no `--device`. This plan adds a
`--mic` session option, under which a host relay records the host microphone and streams
it into the sandbox through an `arecord` shim, on the channel pattern of the clipboard relay.

The requirement: with `--mic`, an unmodified Claude Code dictates through `/voice` in hold
and tap mode; without it, nothing in the sandbox can record, and `/voice` says why.

The CLI's paths below are read from the image's `/usr/bin/claude` (2.1.295) and the voice
dictation page on 2026-10-09; "Tests" lists what is unmeasured.

## Decisions

- **An option, not an environment variable.** A microphone grant is a per-launch choice the user
  makes in the launch command, like `--write` and `--egress`; a variable in a shell profile would
  hand every session the microphone unnoticed. The clipboard moves with it:
  `--clipboard=off|paste|bidirectional` replaces `KO_AGENT_SANDBOX_CLIPBOARD`, same grammar and
  default, so every grant of a host resource is spelled in the launch command.
- **No device passthrough.** `/dev/snd` would give every process in the sandbox the microphone
  with no host-side gate, and the macOS and Windows podman machines offer no microphone to pass
  (unverified for the machines; the Linux case decides alone).
- **Linux hosts: the latest stable Debian, Fedora and Ubuntu.** The recorder program and its
  package are checked on those three; another host may work and is not claimed. The plan records
  the versions each check ran on.
- **The `arecord` path, not SoX or the native module.** The CLI's native module requires a card in
  `/proc/asound/cards`, and SoX a device; `arecord` is a program whose stdout the CLI reads, so a
  shim serves it without any audio stack in the image.

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

Read from the image's binaries; none runs a recorder command the shim could answer.

- Codex 0.162.0: `/voice` is a two-way realtime conversation, microphone and speaker, through
  its bundled helper `codex-resources/voice/bin/codex-voice-host`, a glibc build with its own
  GStreamer (`manifest.json`: `voiceTarget` gnu beside the musl `appTarget`). The helper
  opens ALSA PCMs itself — it carries libasound, lists cards through `/dev/snd/controlC%i`,
  names `hw` and `plughw` — and `[realtime] audio` takes device names. In the sandbox it has
  no card to list. openai/codex#47370 reports the same helper failing on WSLg through the ALSA
  PulseAudio plugin. Serving it would take a virtual ALSA capture and playback device, not a
  command.
- agy 1.3.2: `/voice` dictates into the prompt, under a permission the sign-in must carry.
  On Linux it records with `parec --raw` when `PULSE_SERVER` is set (its message names the
  package to install), or reads a microphone served by `agy mic-serve` on another machine at
  `127.0.0.1:4713`, agy's own protocol over an SSH forward. Either is a server the sandbox
  would have to offer, not a command.
- Copilot 1.0.94, kiro-cli 2.28.0 and OpenCode 1.18.35 dictate nothing.

### The channel pattern

The clipboard relay (`ClipboardRelay`, SECURITY.md "Clipboard"): the sandbox writes a request to
a FIFO the host reads through `podman exec`, and the host answers through another exec; no host
listener, no port, nothing the host did not start. Its response is bounded, read whole and
returned once. A recording is a stream that ends when the reader goes away, which that relay has
no form for.

## After the change

### The option

- `--mic`, a session option like `--write`, never persisted. Absent, no relay runs and the
  shim fails at once.
- At launch, before the container starts, the launcher records on the host into nothing for a
  bounded moment with each candidate recorder in order ("The relay") and keeps the first that
  delivers bytes. None: the launch fails with each candidate's reason, and the package to
  install, as `hostBackend` fails a Linux launch with the clipboard and no xclip. A recorder's
  environment — `XDG_RUNTIME_DIR`, a WSLg session's preset `PULSE_SERVER` — is the launcher's
  own, and is checked by that recording, not by name.
  - On macOS the probe is where the microphone permission prompt appears, at launch rather than
    at the first dictation.
- `--clipboard=<mode>` parses as `--write` does. The launcher no longer reads the variable from
  its own environment, and a set one fails the launch naming the option, so a profile that still
  exports it is not silently ignored. Inside the sandbox the launcher keeps setting
  `KO_AGENT_SANDBOX_CLIPBOARD`, and sets `KO_AGENT_SANDBOX_MIC=on` alike: the shims read
  them to know whether to wait for a FIFO the relay has not yet made.
- `--env` keeps refusing `KO_AGENT_SANDBOX_*`; no variable is added.

### The shim

`ko-sandbox-mic`, a Python program (the image runs its status line with `python3 -I` already),
installed as `/usr/local/bin/arecord` and answering exactly the CLI's forms:

- `arecord --version` and `arecord -f S16_LE -r 16000 -c 1 -t raw /dev/null`: exit 0 when
  the channel's `req` FIFO exists, else 1. No recording: the CLI gives its probe 150 ms, which
  a host round trip from a suspended microphone need not meet, and it counts a probe still
  running at 150 ms as success anyway. Whether the host records is settled at launch ("The
  option"); so without `--mic` the CLI never selects `arecord` and reports SoX's device
  message, and with it the probe says only that a relay is there.
- `arecord -f S16_LE -r 16000 -c 1 -t raw -q -`: take the channel's lock (`flock`, five
  seconds, as the clipboard shim); draw a request id from `os.urandom`; `mkfifo rsp.<id>`,
  which fails rather than replaces an existing one; write `record <id>` to `req` within a
  bound; open the FIFO non-blocking for reading, and poll it until the first byte arrives, a
  deadline of ten seconds after the request passes, or the relay's writer connects and ends
  with nothing; then copy to stdout, blocking, until EOF.
  - One process from start to end: the CLI's `SIGTERM` ends it and closes the only read
    descriptor and the lock; nothing is trapped, forked or left behind. A deadline passed is
    exit 1 with the reason on stderr, which the CLI ignores and the launcher's log carries
    from its side; the FIFO is the writer's to remove, and a shim removes an orphan of its
    own id only.
  - The FIFO carries PCM only, from the first byte: no status line, nothing parsed from the
    stream, nothing read ahead of the audio. A recorder that did not start gives an empty
    stream, which to the CLI is a recorder that ended at once.
  - Waiting is `poll` on the descriptor, which tells a FIFO no writer has opened (no event,
    and a read of nothing) from one whose writer connected and closed (`POLLHUP`): the first
    keeps waiting until the deadline, the second ends the shim. The bytes a poll delivers
    are the stream's first, kept.
  - The copy, on both sides, is `os.read` and `os.write` on descriptors switched back to
    blocking (`os.set_blocking`) once connected: Python's buffered streams would hold up to
    their buffer of audio, 4 KiB being 128 ms, and `-I` ignores `PYTHONUNBUFFERED`.
- Any other form: usage error, exit 64, as the clipboard shim.

The same program, as `ko-sandbox-mic write <fifo>`, is the relay's writer inside the sandbox:
it checks that the path is a FIFO (`S_ISFIFO`, no following of links), opens it for writing
non-blocking, retrying on `ENXIO` until a reader is there or five seconds pass, then copies its
stdin to the FIFO, blocking, until EOF or `EPIPE`, and removes the FIFO. The deadline is on the
open; the copy has none, since the recording's length is the user's. `timeout` cannot express
that: it bounds a whole command, which for a stream would cut a dictation at the bound — the
clipboard's `timeout 10 sh -c "cat > rsp"` fits a reply read whole, not this.

A response FIFO is one request's: a reply to a shim that died — killed by the CLI, or gone at
its deadline — goes to a FIFO no later request reads, since ids are not reused; the writer's
open deadline passes without a reader, and it removes the FIFO.

### The relay

The channel: `/tmp/ko-agent-sandbox/microphone/req`, made by the relay's first exec, and the
shims' `rsp.<id>`.

- POSIX twin: a job of the reaper beside the clipboard's, `microphone_relay <podman> <sandbox>
  <recorder>`, with the recorder the launch probe selected and the launcher's environment. Per
  `record <id>` — `id` is sixteen hex digits and nothing else, or the request is refused — it
  starts the recorder and `podman exec -i <sandbox> ko-sandbox-mic write
  /tmp/ko-agent-sandbox/microphone/rsp.<id>`, both as tracked children, and copies the
  recorder's stdout into the exec's stdin. Every path on both sides is absolute: an exec's
  working directory is the container's, not the channel's. A recorder that ends without
  bytes, or at all, is logged with its exit status and its stderr's first line to the
  launcher's log, which is where a permission refusal or a device that disappeared is read;
  the stream itself carries no status.
- The recording ends, and both children with it, when any of these happens:
  - the exec ends: the shim closed its FIFO, so the writer ended on `EPIPE` at the next
    write, or no reader came within the writer's open deadline;
  - the recorder ends, or delivers no bytes for five seconds: a recorder whose backend hung
    writes nothing, so a closed reader would never reach it through `SIGPIPE`;
  - the container stops, as the clipboard's loop ends;
  - the session ends: the reaper `KILL`s the job's tree.
  Ending is `SIGTERM`, then `SIGKILL` after a bound; the relay waits for both children before
  it takes the next request. A closed reader is not a signal to the writer, only a failure of
  its next write, so the relay never relies on it alone.
- Windows twin: a thread of the resident launcher, capturing with Java Sound into the same
  exec. `AudioSystem.getTargetDataLine` refuses a format no mixer offers, so the twin asks for
  16000 Hz, 16-bit signed, mono, little-endian, and when refused opens the line in a format
  the mixer offers and converts from that to the required one in the relay; unmeasured.
- The recorder program, writing raw signed 16-bit little-endian mono at 16000 Hz, the
  candidates in launch-probe order:
  - macOS: SoX `rec -q -t raw -r 16000 -e signed -b 16 -c 1 -`, which `brew install sox`
    provides and the CLI's own documentation names for macOS. macOS has no built-in recorder
    command.
  - Linux: `arecord -q -D default -t raw -f S16_LE -r 16000 -c 1 -B 80000 -F 20000`
    (`alsa-utils`), one command whichever server owns the microphone, if each host's desktop
    edition routes ALSA's `default` PCM to it ("Tests"); then `parecord --raw --format=s16le
    --rate=16000 --channels=1 --latency-msec=20` (`pulseaudio-utils`) for a host where
    `default` is not routed, as on WSLg. The fallback runs with a `PULSE_CLIENTCONFIG` that
    sets `autospawn = no`, so the probe starts no daemon of its own; a server the host's
    systemd starts on its socket is the host's configuration, not the probe's. The package
    names are what the launch error names.
  - A probe that delivers bytes shows a source that records, not that it is a microphone: a
    monitor or null source records silence. The launch prints which device the recorder
    opened, when the program can say, and the first dictation shows the rest.
- What the host holds is one pipe; nothing is buffered to a file. The stream's rate is 32 kB/s.

### Latency

The shim is spawned at the key press, and the first audio bytes arrive after one `podman exec`
round trip on the machine, plus the recorder's own start. Whether that loses the first syllables
is "Tests"; the mitigation, if needed, is a relay that keeps the recorder running between
requests and gates only the copy, which changes "what the host holds" above and is not planned
until measured.

At the key's release the CLI sends the recorder `SIGTERM` and, in the same step, closes its
stream to the transcription server; chunks arriving after that are dropped
(`[voice_stream] Dropping audio chunk after CloseStream`). So no post-roll in the shim can
reach the transcript, and the word ending lost is the audio in flight between the host's
microphone and the CLI at that moment: the recorder's period, the exec and the FIFO. The
pipeline is kept short (a 20 ms period, no buffering in the relay) and the loss is measured.

### Security

SECURITY.md gains "Microphone", with the clipboard section's form:

- The sandbox asks; the host answers. No listener, no port, no proxy rule.
- The grant is to the container: any process in the session can record, as often and as long as
  it likes, for the whole session, with no per-recording consent. macOS shows its microphone
  indicator while the host records; nothing else signals a recording.
- One recording at a time; the stream ends with its reader, the session or the container.
- What leaves the host is the agent's doing: Claude Code streams the audio to Anthropic, under the
  egress rules the session already has.
- Without `--mic`, no FIFO exists and the shim fails at once; the image has no other
  capture path.

## Documentation

- README's Reference block (which `--help` prints): `--mic` and `--clipboard` under the
  session options, the former with the host program each OS needs, and the variable gone from
  the environment table; the `claude` section: `/voice` needs `--mic`.
- SECURITY.md "Clipboard", `doc/plan-clipboard.md`, `doc/design.md` and the clipboard shim's
  comment: the option's name where the variable's was.
- SECURITY.md "Microphone", above.
- `doc/design.md`, the relay list: the microphone relay beside the clipboard relay and the
  runner.
- The Containerfile's SoX comment: SoX now names only the message a session without the option
  sees.

## Tests

### Unit

- The shim's four forms, with and without the FIFO: exit codes, and that only the recording form
  touches `req`; the recording form's `rsp.<id>` is made before the request, is never one that
  exists, and is gone after the relay's writer ends, whether the shim read it or died first.
- After `SIGTERM` to the shim, no process in the sandbox holds the FIFO open (`fuser`), and the
  lock is free.
- Integrity: a known PCM sequence fed to a fake recorder on the host arrives at the shim's
  stdout sample for sample.
- Forwarding: with both ends connected, a chunk the fake recorder writes reaches the shim's
  stdout before the recorder writes the next one, so neither program holds audio; the
  elapsed time from the shim's start to its first byte is recorded as a distribution under
  "Live", not asserted here, since the exec and the scheduler are in it.
- Deadlines: a relay that dies after reading `record <id>` and before its writer opens ends
  the shim at its first-byte deadline, exit 1; a shim killed before the writer opens ends the
  writer at its open deadline, the FIFO removed; a recording longer than both deadlines
  streams whole, since neither bounds the copy; the writer refuses a path that is not a FIFO.
- The relay's grammar: `record <id>` with sixteen hex digits and nothing else; a refused line
  ends the stream's reading; a reply to a dead shim ends at the writer's bound and the next
  request is served.
- Ending: `SIGTERM` to the shim ends the host recorder within the bound; a recorder that writes
  nothing is ended after five seconds; a recorder that fails to start gives the shim an empty
  stream and the launcher's log its reason; the container's stop ends the relay; the session's
  end `KILL`s a recording in progress.
- Two recorders: the second shim fails at the lock's bound (`flock -w 5`), and the CLI sees its
  recorder end; the first keeps streaming.
- The launch probe: each OS's candidate order, the first that delivers bytes is kept, and the
  launch failure names every candidate's reason and the package to install.
- The CLI contract: a test reads the image's `/usr/bin/claude` for the exact `arecord`
  argument vectors the shim answers and the probe's deadline, and fails the build when a
  Claude Code release changes them, as `doc/plan-clipboard.md` rechecks each agent's clipboard
  commands; the accepted forms are a contract with one CLI version, not a guarantee.

### Live

- macOS: the microphone permission prompt appears, and which application it names (the terminal,
  as the reaper's responsible process; unverified); a denied permission reaches the CLI as a
  stream's end, not a hang.
- Hold and tap mode dictation end to end; how many milliseconds of speech the first exec costs,
  on a podman machine.
- `--egress=deny-all`: the recorder starts and the CLI reports the stream error.
- Windows: the resident twin's capture and the same prompt.
- The latest stable Debian, Fedora and Ubuntu, desktop editions: which
  recorder programs their default installs carry, whether ALSA's `default` PCM reaches the
  desktop's microphone, the package to name when none is found, and the environment the
  reaper's job needs to find the audio server's socket (`XDG_RUNTIME_DIR`, `PULSE_SERVER`).
- The first-byte latency of the chosen recorder from an idle microphone, which the server may
  have suspended. Whether `/voice` loses the first syllables on this path more than on the
  CLI's native one on the same host decides whether the relay keeps the stream open.
- Word endings on `SIGTERM`: how much audio is in flight at the key's release, against the
  CLI's native path on the same host.

## Excluded

- Device passthrough, an audio server in the sandbox, patches to Claude Code, and speakers.
- Codex's and agy's voice features ("Other agents"): each needs a device or a server, which this
  channel is not. A PulseAudio-protocol server in the sandbox backed by the same relay would
  serve agy's `parec` path and is the increment to consider if agy's dictation is wanted;
  Codex's conversation needs playback as well, which the relay does not carry.
- Sessions whose profile excludes `api.anthropic.com`: the CLI's stream, not the relay, fails.

## Sources

- https://code.claude.com/docs/en/voice-dictation.md
- https://code.claude.com/docs/en/settings-reference.md (`voice`, `voiceEnabled`)
- The image's `/usr/bin/claude` 2.1.295: the recorder selection, the `arecord` and `rec`
  command lines, and the stream URL
- The image's `/opt/codex/bin/codex` 0.162.0 and `codex-resources/voice/`, `/usr/local/bin/agy`,
  `copilot`, `kiro-cli` and `opencode`: the other agents' voice paths
- https://github.com/openai/codex/issues/47370
