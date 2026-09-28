# Plan: a Wayland clipboard service for native clipboard readers

Codex and Copilot read clipboard images through a Wayland library, never through the command
shims, so image paste reaches neither of them in any mode. This plan adds a Wayland service inside
the sandbox that offers only the clipboard, backed by the existing host relay, and keeps the four
command shims for the agents that run clipboard commands.

The requirement: unmodified installed agents paste host images under `paste` and
`bidirectional`, and copy text to the host under `bidirectional`, with only the host access
SECURITY.md "Clipboard" grants, which this plan extends by primary-selection writes on Linux hosts
under `bidirectional` ("Documentation").

The agents' paths below are read from the installed binaries and upstream source on 2026-09-28.
What a terminal or a live agent does with them is unmeasured; "Tests" lists each check.

## Permissions, today and after the change

| Mode            | Host reads through the channel | Host writes through the channel             |
| --------------- | ------------------------------ | ------------------------------------------- |
| `off`           | none; call fails               | none; call fails                            |
| `paste`         | the current image as PNG       | none; call reports `ok`                     |
| `bidirectional` | the current image as PNG       | text; on Linux, also the primary selection  |

OSC 52 requests bypass the channel and this table (SECURITY.md, "Terminal clipboard requests
(OSC 52)"). Under `off` no relay runs, so every call fails. Under the other modes the relay
enforces the table: it never serves the host's text or file lists. Which images it serves depends
on the host (`ClipboardRelay`):

- macOS: an image the pasteboard offers as PNG (`«class PNGf»`).
- Linux: an image the selection offers as `image/png`.
- Windows: any image `Clipboard.ContainsImage()` reports, converted to PNG.

The service's socket is one more way into the same relay. The change widens one cell: under
`bidirectional` a Linux host's primary selection, which middle-click pastes and which is separate
from the clipboard, can also be set ("Copies to the primary selection"). Today the shim's
`wl-copy --primary` sets the clipboard instead.

## Today

### The channel

- The host relay answers `types`, `get image/png` and `set <bytes>` on two FIFOs in the sandbox
  (`ClipboardRelay`); SECURITY.md "Clipboard" has what each mode grants.
- `ko-sandbox-clipboard` is installed as `xclip`, `xsel`, `wl-paste` and `wl-copy`, answers only
  the argument patterns in its `case`, and exits 64 on any other.
- The launcher sets `WAYLAND_DISPLAY=ko-sandbox-clipboard` only under `bidirectional`, a name with
  no socket behind it, so that agents copying with `wl-copy` only when they see a display use it
  there and OSC 52 otherwise (`AgentSandboxLauncher.scala`, `clipboardArgs`).
- OSC 52 is an escape sequence the agent writes to its terminal to ask the terminal to set the
  clipboard; the sandbox neither sees nor restricts it, in any mode.
- Cmd+V is the terminal typing the clipboard's text into the session. No clipboard tool is
  involved, so text paste works in every mode.

### Agents

The copy paths below hold for a launch that forwards no SSH or tmux variable with `--env`; Claude
Code, Codex and Copilot choose other paths when one is set, Copilot also on `CODESPACES` and
`REMOTE_CONTAINERS`.

Claude Code 2.1.283:

- Image paste (Ctrl+V) runs `xclip -selection clipboard -t TARGETS -o`, then `wl-paste -l`, to
  find an image, then `xclip … -t image/png -o`, `wl-paste --type image/png` and the same for
  `image/bmp`. The shim serves the PNG forms, so image paste works under `paste` and
  `bidirectional`.
- Copy writes OSC 52 and also runs a native copy: `wl-copy` when `WAYLAND_DISPLAY`
  is set, `xclip` or `xsel` on both selections when `DISPLAY` is set, otherwise its
  `clipboard-napi` addon when either variable is set.
  - Under `off` and `paste`: OSC 52 alone.
  - Under `bidirectional`: OSC 52 and `wl-copy`, which reaches the host through the shim.

Codex 0.157.1 (`codex-rs/tui/src/clipboard_paste.rs`, `clipboard_copy.rs`):

- Uses arboard 3.6.1 built with `wayland-data-control` (`codex-rs/Cargo.toml`), which uses
  wl-clipboard-rs 0.9.3 when `WAYLAND_DISPLAY` is set and its connection succeeds, and X11
  otherwise. The sandbox has no X server, so every arboard call fails in every mode.
- Image paste (Ctrl+V) asks arboard for a file list, then for an image: fails in every mode.
- `/copy` and Ctrl+O write text and HTML through arboard and write OSC 52 only when that fails.
  In the sandbox it always fails, so every mode copies through OSC 52 alone.

Copilot 1.0.88 (`app.js` and `prebuilds/linux-arm64/cli-native.node` of its package):

- Image paste goes only through its native module: clipboard-rs 0.3.5 over wl-clipboard-rs 0.9.3
  when `WAYLAND_DISPLAY` is set, X11 otherwise. It fails in every mode.
  - clipboard-rs prints `Wayland clipboard init failed, falling back to X11` to stderr when the
    Wayland connection fails, as under `bidirectional`'s socketless display.
- Copy writes OSC 52 (`]52;c;`), then `wl-copy --type text/plain` when `WAYLAND_DISPLAY` is set,
  then its native module: for every copy without a display, only for HTML with one.
  - Under `off` and `paste`: OSC 52; the native module fails.
  - Under `bidirectional`: OSC 52 and `wl-copy`, which reaches the host.
- Selecting text with the mouse writes OSC 52 to the primary selection (`]52;p!;`, `]52;p;` for
  Alacritty) and runs `wl-copy --primary --type text/plain` when `WAYLAND_DISPLAY` is set, or
  `xclip -selection primary` when only `DISPLAY` is. The shim refuses that `wl-copy` form.
  Copilot skips this on macOS and Windows; inside the sandbox it sees Linux.
- Text reads run `wl-paste --no-newline --type text/plain`, which the shim refuses, then the
  native module.

OpenCode 1.18.32:

- Image paste runs `wl-paste -t image/png`, which the shim refuses, then
  `xclip -selection clipboard -t image/png -o`, which it serves: works under `paste` and
  `bidirectional`.
- Copy writes OSC 52, then `wl-copy` when `WAYLAND_DISPLAY` is set, else
  `xclip -selection clipboard`, else `xsel --clipboard --input`.
  - Under `paste`: OSC 52, and `xclip`, which the relay drops.
  - Under `bidirectional`: OSC 52 and `wl-copy`, which reaches the host.

agy 1.2.12:

- A Go binary whose functions `readWayland`, `wlListTypes`, `wlReadType`, `readX11`,
  `xclipListTypes` and `xclipReadType` read the clipboard, and whose copy contains OSC 52 and
  `wl-copy`. Its exact arguments are not recoverable from the binary.

kiro-cli 2.24.1:

- `kiro-cli-chat`, which serves `/paste` (an image) and `/copy`, links arboard 3.6.1 without the
  Wayland feature and runs no clipboard command or OSC 52, so both fail in every mode, before and
  after this plan.
- `kiro-cli` links arboard with the Wayland feature and has a "Copy to clipboard" action; what it
  copies is under "Tests".

### Terminals

- kitty (`clipboard_control`), Ghostty (`clipboard-write`) and WezTerm (its escape-sequence
  table) allow OSC 52 writes by default. Codex's source also names iTerm2, whose default is not
  read here.
- The launcher's comment records that Terminal.app ignores it.

On that reading, copying out of an agent under `off` and `paste` works on kitty, Ghostty and
WezTerm and not on Terminal.app, and under `bidirectional` works everywhere for the agents that
run `wl-copy`.

## After the change

### The service

- A Rust program on Smithay's `wayland-server`, built in the image for both architectures, as
  `ko-agent-fs` is. It advertises `wl_seat` at version 2 and `ext-data-control-v1`, and nothing
  else.
  - wl-clipboard-rs binds only a seat of version 2 or later, at version 2, and otherwise reports no
    seats (`src/common.rs`). The seat sends its capabilities and its name on binding.
  - wl-clipboard-rs 0.9.3 binds `ext-data-control-v1` first and falls back to the wlroots
    protocol (`src/common.rs`), so the wlroots protocol is added only if agy needs it.
- The entrypoint starts it under `paste` and `bidirectional`, waits for its socket, and then
  starts the agent, keeping the agent's signals and exit status.
- The launcher sets `WAYLAND_DISPLAY` to the socket's absolute path under both modes.
  `XDG_RUNTIME_DIR` is unset in the container, and wayland-client 0.31 connects to an absolute
  `WAYLAND_DISPLAY` without it (`src/conn.rs`).
- It talks to the relay through the FIFOs under the shims' lock, as one more caller. The relay
  gains one request, `primary` ("Copies to the primary selection"), in both twins and on each host;
  its other requests and its limits are unchanged.

### Offers without polling

- wl-clipboard-rs opens a connection per read, creates the data device, makes one round trip, and
  reports an empty clipboard if no offer arrived by then (`src/paste.rs`, `get_offer`).
- So the service asks the relay for `types` while creating the device and holds that
  connection until the answer, within the shims' bounds.
- ext-data-control-v1 requires the first `selection` event, and `primary_selection` from a
  compositor that supports it, on binding the device. The service sends, in order:
  - with an image on the host: `data_offer`, `offer` `image/png`, and `selection` with that offer;
  - otherwise, or without the relay's answer: `selection` with NULL, which the client reports as
    an empty clipboard;
  - then `primary_selection` with NULL, since it accepts primary copies.
- The relay serves one request at a time under the shims' lock, so a stalled relay delays every
  native client and shim up to those bounds; threads in the service cannot remove that.
- The offer lists `image/png` when the host has an image, and never text or `text/uri-list`.
- A `receive` for `image/png` is one `get image/png`. The service reads the whole answer, up to a
  cap, releases the lock, and writes it to the client's descriptor apart from the connection's
  handling, until a deadline.
  - wl-clipboard-rs sends `receive`, makes a round trip, drops the connection, and only then reads
    the pipe (`src/paste.rs`, `get_contents_internal`). A write inside the handling would block on
    a full pipe and the round trip would never complete, and the write must outlive the
    connection.

### Copies

- A client's `set_selection` names a source; the service reads its `text/plain` and sends one
  `set`. Under `paste`, the relay drops it as it drops a shim's.
- A source is read to its end, for `set_selection` and `set_primary_selection` alike, and sent
  only whole, as the relay copies a body.
  - Passing `MaxRequestBytes`, a deadline, the source's cancellation, the client's disconnect and
    the session's end abort the read, and nothing is sent.
- A native copy reports success without waiting for the service or the host to accept it:
  wl-clipboard-rs returns once the source exists, makes no round trip after `set_selection`, and
  drops errors from serving it (`src/copy.rs`, `copy_internal`, `prepare_copy_internal`).
  - So a copy the host refuses or fails — over `MaxRequestBytes`, a failed host program, a relay
    gone — reads as done to Codex and Copilot's native module, and Codex writes no OSC 52 for it.
  - "Documentation" has what the README says. The shims keep reporting such a copy as failed.
- When a new source replaces it, the service cancels the old one, which ends the copying client's
  serving thread (arboard and clipboard-rs serve a copy from a thread until cancelled).
- The copied text is not offered back to clients in the sandbox.

### Shims

- All four names stay and keep calling the relay directly.
- New forms: `wl-paste -t image/png` (OpenCode), Copilot's `wl-copy --primary --type text/plain`,
  and agy's once measured.

### Copies to the primary selection

- Copilot's copy on mouse selection runs `wl-copy --primary --type text/plain`. The shim sends it,
  and the existing `wl-copy --primary` form, as a new relay request `primary <bytes>` instead of
  `set`; the service does the same for a native client's `set_primary_selection`. Its count is
  read and bounded as a `set`'s.
- On macOS and Windows hosts the relay reads and drops it and answers `ok`, as `paste` drops a
  `set`: Copilot's own macOS and Windows builds do not copy on selection, and forwarding it would
  replace the host clipboard at every selection.
- On Linux hosts under `bidirectional`, it sets the host's primary selection, following Copilot's
  own Linux build: `xclip -selection primary -i`, falling back to `wl-copy --primary` when xclip
  is absent or fails, as the relay's `copy` falls back for a `set`. The host clipboard is
  untouched. A host that cannot set it fails the request, as a failed `set` does.

### Agents

- Claude Code: unchanged under `bidirectional`. Under `paste`, it now sees a display and copies
  through `wl-copy`, which the relay drops, and OSC 52 as before.
  - Reconsider the image's `claude-code/managed-settings.d/tui.json`, which keeps the classic
    renderer so that the terminal can select text.
- Codex: image paste works under `paste` and `bidirectional`. Copy reaches the host under
  `bidirectional`; under `paste`, arboard succeeds against the service, so Codex no longer writes
  OSC 52 and its copies reach no clipboard on any terminal. Under `off` it keeps OSC 52.
  - Decided: this is `paste` mode's intent, no copy through the sandbox ("Documentation").
  - Reconsider `fullscreen_transcript = false` in the image's `codex/config.toml`: Codex's own
    copies then reach the host under `bidirectional`, but under `paste` only the terminal's
    selection copies.
- Copilot: image paste works under `paste` and `bidirectional`. Copy is unchanged under
  `bidirectional` except that an HTML copy reaches the host twice, through `wl-copy` and the
  native module; under `paste`, OSC 52 as before.
- OpenCode: image paste answers at the first command. Copy under `paste` runs `wl-copy` instead of
  `xclip`; both are dropped.
- agy: depends on the measured invocations.
- kiro-cli: `/paste` and `/copy` still fail; serving them needs an X server, which this plan
  excludes.

## Documentation

- README, `codex`: under `paste`, Codex's copies reach no clipboard; under `bidirectional`, a copy
  the host refuses or fails still reads as done, and the text can be selected in the terminal,
  since the image's `codex/config.toml` turns off Codex's fullscreen transcript.
- README, `copilot`: selecting text behaves as in Copilot's own build for the host, under
  `bidirectional`.
  - On Linux hosts it sets the host's primary selection, for middle-click paste.
  - On macOS and Windows hosts it copies nothing, since each selection would replace the
    clipboard; use `/copy`.
- README's Reference block, which `--help` prints, and `clipboardMode`'s error message
  (`AgentSandboxLauncher.scala`): `paste` "lets the agent read a copied image" names the agents it
  holds for — Claude Code, Codex, Copilot and OpenCode, agy as measured — and not kiro-cli.
- SECURITY.md "Clipboard": the service's socket beside the FIFOs, and that `bidirectional` also
  sets the primary selection on Linux hosts.
- The relay's code records that `primary` follows Copilot's own build for each host.

## Tests

### Before building: today's behavior

For each agent, under each mode, on Terminal.app, iTerm2, Ghostty, kitty and WezTerm with their
default settings, and then with any clipboard setting they have turned on:

- Does the agent's copy reach the host clipboard, and through which path?
- Does Ctrl+V paste a copied image?

Specific checks:

- Terminal.app ignores OSC 52 for `c` and `p`.
- The four OSC 52 terminals: `c` sets the clipboard, and which iTerm2 setting that needs; what
  `p` and `p!` do on macOS.
- Codex's and Copilot's image paste fails in every mode, and what each shows the user.
- Copilot's clipboard-rs stderr line appears on screen under `bidirectional`.
- OpenCode's image paste works under `paste` through its `xclip` fallback.
- agy: its exact clipboard invocations, recorded by a logging shim, and whether it chooses the
  Wayland or X11 commands by `WAYLAND_DISPLAY`.
- kiro-cli: `/paste` and `/copy` fail in every mode; what `kiro-cli`'s "Copy to clipboard" is.

### The prototype, against a fake relay

- arboard `get_image` and clipboard-rs `get_image` read the PNG; a changed image between two
  pastes is read fresh.
- arboard `set_html` and clipboard-rs `setClipboardContents` reach the fake relay as one `set`
  of the plain text.
- A PNG larger than the capacity `F_GETPIPE_SZ` reports for the client's pipe arrives whole,
  though the client drops its connection before reading; pipe(7) fixes no capacity.
- A client slow to read its pipe holds no relay lock: a shim and another native client are served
  meanwhile.
- A stalled relay ends a native client's `types` wait with an empty clipboard, and a shim's
  request with a failure, each within its bound.
- Replacing a copy cancels the previous source, and the copying client's thread ends.
- On binding: the seat at version 2, then `selection` with the PNG offer or with NULL, then
  `primary_selection` with NULL; a stalled relay still yields `selection` with NULL.
- A source that neither writes nor closes its descriptor is abandoned at the deadline, and at once
  when the client disconnects.

### The implementation

- Integration under `paste` and `bidirectional`, for the native clients and the shims:
  - concurrent requests, a changing image, a client that disconnects mid-transfer;
  - a stalled relay, and one that dies: bounded failure;
  - the session's end: the service exits, and the agent's exit status and signals pass through.
- Copies, by mode:
  - `off`: no service runs; native copies fail, and the shims fail at once.
  - `paste`: a copy reaches no clipboard and reports success, through the shim and natively; one
    over `MaxRequestBytes` fails the shim and still reports success natively.
  - `bidirectional`: a copy over `MaxRequestBytes`, and one the host program fails, fail the shim
    and report success natively, with nothing on the host.
- A `primary` request, from the shim and from a native client, leaves the host clipboard unchanged
  on macOS and Windows hosts and under `paste`, and answers `ok`; on a Linux host under
  `bidirectional` it sets the primary selection through xclip, through wl-copy on a Wayland-only
  host, and through wl-copy when both are installed and xclip fails, and leaves the clipboard
  unchanged.
- `ClipboardRelayTest` covers `primary` in both twins' grammar and, on a Linux host, through xclip,
  through wl-copy on a Wayland-only host, and through wl-copy when an installed xclip fails; its
  existing cases keep covering the other requests.
- Live: the "Before building" matrix again, on macOS first, then one Linux and one Windows host;
  on the macOS and Windows hosts, also that `primary` leaves the clipboard unchanged.

## Excluded

- Patches to agents, an X11 server, a desktop compositor, intercepting the terminal, and host
  clipboard access beyond the table.
- Compatibility with later agent releases is something the tests recheck, not a guarantee.

## Sources

- https://github.com/openai/codex/tree/rust-v0.157.1/codex-rs (`Cargo.toml`,
  `tui/src/clipboard_paste.rs`, `tui/src/clipboard_copy.rs`)
- Terminals' OSC 52 defaults:
  - https://github.com/kovidgoyal/kitty/blob/master/kitty/options/definition.py
  - https://github.com/ghostty-org/ghostty/blob/main/src/config/Config.zig
  - https://github.com/wezterm/wezterm/blob/main/docs/escape-sequences.md
- Crates from crates.io: arboard 3.6.1 (`src/platform/linux/`), wl-clipboard-rs 0.9.3
  (`src/paste.rs`, `src/copy.rs`, `src/common.rs`, `src/utils.rs`), clipboard-rs 0.3.5
  (`src/platform/`), wayland-client 0.31.12 (`src/conn.rs`)
- The image's binaries: `/usr/bin/claude`, `/opt/codex/bin/codex`, Copilot's package under
  `~/.cache/copilot/pkg/linux-arm64/1.0.88`, `/usr/local/bin/opencode`, `/usr/local/bin/agy`,
  `/usr/local/bin/kiro-cli` and `kiro-cli-chat`
