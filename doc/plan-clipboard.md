# Plan: a Wayland clipboard service for native clipboard readers

Codex and Copilot read clipboard images through a Wayland library, never through the command
shims. So image paste reaches neither agent in any mode.

- This plan adds a Wayland service inside the sandbox. The service offers only the clipboard, and
  the existing host relay backs it.
- The plan keeps the four command shims for the agents that run clipboard commands.

The requirement: the installed agents, unmodified, paste host images under `paste` and
`bidirectional`, and copy text to the host under `bidirectional`. The agents get only the host
access that SECURITY.md grants ("Clipboard"). This plan extends that access by one item: writes to
the primary selection on Linux hosts under `bidirectional` ("Documentation").

The agents' clipboard paths below were read from the installed binaries and the upstream source on
2026-09-28. What a terminal or a live agent does with them is unmeasured. "Tests" lists each check.

## Permissions, today and after the change

| Mode            | Host reads through the channel | Host writes through the channel             |
| --------------- | ------------------------------ | ------------------------------------------- |
| `off`           | none; call fails               | none; call fails                            |
| `paste`         | the current image as PNG       | none; call reports `ok`                     |
| `bidirectional` | the current image as PNG       | text; on Linux, also the primary selection  |

- OSC 52 requests bypass the channel and this table (SECURITY.md, "Terminal clipboard requests
  (OSC 52)").
- Under `off` no relay runs, so every call fails.
- Under the other modes the relay enforces the table, and it never serves the host's text or file
  lists. The images the relay serves depend on the host (`ClipboardRelay`):
  - macOS: an image the pasteboard offers as PNG (`«class PNGf»`).
  - Linux: an image the selection offers as `image/png`.
  - Windows: any image `Clipboard.ContainsImage()` reports, converted to PNG.

The service's socket is one more way into the same relay. The change widens one cell of the table:
under `bidirectional`, a session can also set a Linux host's primary selection ("Copies to the
primary selection").

- The primary selection is what middle-click pastes, and it is separate from the clipboard.
- Today, the shim's `wl-copy --primary` sets the clipboard instead.

## Today

### The channel

- The host relay answers `types`, `get image/png` and `set <bytes>` on two FIFOs in the sandbox
  (`ClipboardRelay`). SECURITY.md has what each mode grants ("Clipboard").
- `ko-sandbox-clipboard` is installed as `xclip`, `xsel`, `wl-paste` and `wl-copy`. The shim answers
  only the argument patterns in its `case`, and exits 64 on any other.
- The launcher sets `WAYLAND_DISPLAY=ko-sandbox-clipboard` only under `bidirectional`
  (`AgentSandboxLauncher.scala`, `clipboardArgs`).
  - No socket stands behind that name.
  - Some agents copy with `wl-copy` only when they see a display, and through OSC 52 otherwise.
    The variable makes those agents use `wl-copy` under `bidirectional`.
- OSC 52 is an escape sequence that the agent writes to its terminal, asking the terminal to set
  the clipboard. The sandbox neither sees nor restricts OSC 52, in any mode.
- On Cmd+V, the terminal types the clipboard's text into the session. No clipboard tool is
  involved, so text paste works in every mode.

### Agents

The copy paths below hold for a launch that forwards no SSH or tmux variable with `--env`. Claude
Code, Codex and Copilot choose other paths when such a variable is set. Copilot also chooses other
paths on `CODESPACES` and `REMOTE_CONTAINERS`.

Claude Code 2.1.283:

- Image paste (Ctrl+V) runs `xclip -selection clipboard -t TARGETS -o`, then `wl-paste -l`, to find
  an image. Image paste then runs `xclip … -t image/png -o`, `wl-paste --type image/png`, and the
  same for `image/bmp`.
  - The shim serves the PNG forms, so image paste works under `paste` and `bidirectional`.
- Copy writes OSC 52 and also runs a native copy. The native copy is `wl-copy` when
  `WAYLAND_DISPLAY` is set, `xclip` or `xsel` on both selections when `DISPLAY` is set, and
  otherwise the `clipboard-napi` addon when either variable is set.
  - Under `off` and `paste`: OSC 52 alone.
  - Under `bidirectional`: OSC 52 and `wl-copy`, which reaches the host through the shim.

Codex 0.157.1 (`codex-rs/tui/src/clipboard_paste.rs`, `clipboard_copy.rs`):

- Codex uses arboard 3.6.1, built with `wayland-data-control` (`codex-rs/Cargo.toml`).
  - arboard uses wl-clipboard-rs 0.9.3 when `WAYLAND_DISPLAY` is set and the connection succeeds,
    and X11 otherwise.
  - The sandbox has no X server, so every arboard call fails in every mode.
- Image paste (Ctrl+V) asks arboard for a file list, then for an image. Image paste fails in every
  mode.
- `/copy` and Ctrl+O write text and HTML through arboard, and write OSC 52 only when arboard fails.
  In the sandbox arboard always fails, so every mode copies through OSC 52 alone.

agy 1.2.12:

- agy is a Go binary. agy's functions `readWayland`, `wlListTypes`, `wlReadType`, `readX11`,
  `xclipListTypes` and `xclipReadType` read the clipboard, and its copy contains OSC 52 and
  `wl-copy`. The exact arguments are not recoverable from the binary.

kiro-cli 2.24.1:

- `kiro-cli-chat` serves `/paste` (an image) and `/copy`. `kiro-cli-chat` links arboard 3.6.1
  without the Wayland feature, and it runs no clipboard command and writes no OSC 52. So both
  commands fail in every mode, before and after this plan.
- `kiro-cli` links arboard with the Wayland feature and has a "Copy to clipboard" action. What that
  action copies is under "Tests".

Copilot 1.0.88 (`app.js` and `prebuilds/linux-arm64/cli-native.node` of its package):

- Image paste goes only through Copilot's native module. The module uses clipboard-rs 0.3.5 over
  wl-clipboard-rs 0.9.3 when `WAYLAND_DISPLAY` is set, and X11 otherwise. Image paste fails in
  every mode.
  - clipboard-rs prints `Wayland clipboard init failed, falling back to X11` to stderr when the
    Wayland connection fails. The connection fails under `bidirectional`'s socketless display.
- Copy writes OSC 52 (`]52;c;`), then runs `wl-copy --type text/plain` when `WAYLAND_DISPLAY` is
  set. Copilot then calls its native module: for every copy without a display, and only for HTML
  with one.
  - Under `off` and `paste`: OSC 52, and the native module fails.
  - Under `bidirectional`: OSC 52 and `wl-copy`, which reaches the host.
- Selecting text with the mouse writes OSC 52 to the primary selection (`]52;p!;`, and `]52;p;`
  for Alacritty).
  - The selection also runs `wl-copy --primary --type text/plain` when `WAYLAND_DISPLAY` is set, or
    `xclip -selection primary` when only `DISPLAY` is set. The shim refuses that `wl-copy` form.
  - Copilot skips the selection copy on macOS and Windows. Inside the sandbox, Copilot sees Linux.
- A text read runs `wl-paste --no-newline --type text/plain`, which the shim refuses, and then
  calls the native module.

OpenCode 1.18.32:

- Image paste runs `wl-paste -t image/png`, which the shim refuses, then
  `xclip -selection clipboard -t image/png -o`, which the shim serves. Image paste works under
  `paste` and `bidirectional`.
- Copy writes OSC 52, then runs `wl-copy` when `WAYLAND_DISPLAY` is set, else
  `xclip -selection clipboard`, else `xsel --clipboard --input`.
  - Under `paste`: OSC 52, and `xclip`, which the relay drops.
  - Under `bidirectional`: OSC 52 and `wl-copy`, which reaches the host.

### Terminals

- kitty (`clipboard_control`), Ghostty (`clipboard-write`) and WezTerm (its escape-sequence
  table) allow OSC 52 writes by default.
- Codex's source also names iTerm2, whose default is not read here.
- The launcher's comment records that Terminal.app ignores OSC 52.

On that reading:

- under `off` and `paste`, copying out of an agent works on kitty, Ghostty and WezTerm, and not on
  Terminal.app;
- under `bidirectional`, copying works on every terminal for the agents that run `wl-copy`.

## After the change

### The service

- The service is a Rust program on Smithay's `wayland-server`. The image builds it for both
  architectures, as the image builds `ko-agent-fs`.
- The service advertises `wl_seat` at version 2 and `ext-data-control-v1`, and nothing else.
  - wl-clipboard-rs binds only a seat of version 2 or later, at version 2, and otherwise reports no
    seats (`src/common.rs`). The seat sends its capabilities and its name on binding.
  - wl-clipboard-rs 0.9.3 binds `ext-data-control-v1` first and falls back to the wlroots
    protocol (`src/common.rs`). So the service adds the wlroots protocol only if agy needs it.
- Under `paste` and `bidirectional`, the entrypoint starts the service, waits for its socket, and
  then starts the agent. The entrypoint keeps the agent's signals and exit status.
- The launcher sets `WAYLAND_DISPLAY` to the socket's absolute path under both modes.
  - `XDG_RUNTIME_DIR` is unset in the container. wayland-client 0.31 connects to an absolute
    `WAYLAND_DISPLAY` without that variable (`src/conn.rs`).
- The service talks to the relay through the FIFOs under the shims' lock, as one more caller.
- The relay gains one request, `primary`, in both relays and on each host ("Copies to the primary
  selection"). The relay's other requests and its limits stay as they are.

### Offers without polling

- wl-clipboard-rs opens a connection per read, creates the data device, and makes one round trip.
  wl-clipboard-rs reports an empty clipboard if no offer arrived by then (`src/paste.rs`,
  `get_offer`).
- So the service asks the relay for `types` while it creates the client's data device. The service
  holds the client's connection until the relay answers, within the shims' bounds.
- ext-data-control-v1 requires the first `selection` event when the client binds the device. A
  compositor that supports the primary selection must also send the first `primary_selection`
  event. The service sends, in order:
  - with an image on the host: `data_offer`, `offer` `image/png`, and `selection` with that offer;
  - otherwise, or without the relay's answer: `selection` with NULL, which the client reports as
    an empty clipboard;
  - then `primary_selection` with NULL, since the service accepts primary copies.
- The relay serves one request at a time under the shims' lock. So a stalled relay delays every
  native client and shim up to those bounds, and threads in the service cannot remove that delay.
- The offer lists `image/png` when the host has an image, and never lists text or `text/uri-list`.
- A `receive` for `image/png` is one `get image/png`.
  - The service reads the whole answer, up to a cap, and releases the lock.
  - The service then writes the answer to the client's descriptor until a deadline, apart from the
    connection's handling.
  - wl-clipboard-rs sends `receive`, makes a round trip, drops the connection, and only then reads
    the pipe (`src/paste.rs`, `get_contents_internal`). A write inside the connection's handling
    would block on a full pipe, and the round trip would never complete. The write must also
    outlive the connection.

### Copies

- A client's `set_selection` names a source. The service reads the source's `text/plain` and sends
  one `set`. Under `paste`, the relay drops that `set` as it drops a shim's.
- The service reads a source to its end, for `set_selection` and `set_primary_selection` alike. The
  service sends the text only whole, as the relay copies a body.
  - These events abort the read, and then nothing is sent: passing `MaxRequestBytes`, a deadline,
    the source's cancellation, the client's disconnect, and the session's end.
- A native copy reports success without waiting for the service or the host to accept it.
  wl-clipboard-rs returns once the source exists, makes no round trip after `set_selection`, and
  drops errors from serving the source (`src/copy.rs`, `copy_internal`, `prepare_copy_internal`).
  - So a copy that the host refuses or fails reads as done to Codex and to Copilot's native
    module, and Codex writes no OSC 52 for it. Such a copy is one over `MaxRequestBytes`, one whose
    host program fails, or one whose relay is gone.
  - "Documentation" has what the README says about such a copy. The shims keep reporting such a copy
    as failed.
- When a new source replaces the old one, the service cancels the old source. The cancellation ends
  the copying client's serving thread: arboard and clipboard-rs serve a copy from a thread until
  the copy is cancelled.
- The service does not offer the copied text back to clients in the sandbox.

### Shims

- All four names stay, and they keep calling the relay directly.
- The shim gains these forms: agy's forms once they are measured, Copilot's
  `wl-copy --primary --type text/plain`, and `wl-paste -t image/png` (OpenCode).

### Copies to the primary selection

- Copilot's copy on mouse selection runs `wl-copy --primary --type text/plain`.
  - The shim sends that form, and the existing `wl-copy --primary` form, as a new relay request
    `primary <bytes>` instead of `set`.
  - The service does the same for a native client's `set_primary_selection`.
  - The relay reads and bounds the request's byte count as it does for a `set`.
- On macOS and Windows hosts, the relay reads and drops a `primary` request and answers `ok`, as
  `paste` drops a `set`.
  - Copilot's own macOS and Windows builds do not copy on selection.
  - Forwarding the request would replace the host clipboard at every selection.
- On Linux hosts under `bidirectional`, the request sets the host's primary selection, following
  Copilot's own Linux build.
  - The relay runs `xclip -selection primary -i`. It falls back to `wl-copy --primary` when xclip
    is absent or fails, as the relay's `copy` falls back for a `set`.
  - The host clipboard stays untouched.
  - A host that cannot set the primary selection fails the request, as a failed `set` does.

### Agents

- Claude Code behaves as today under `bidirectional`. Under `paste`, Claude Code sees a display,
  so it copies through `wl-copy`, which the relay drops, and through OSC 52 as today.
  - Reconsider the image's `claude-code/managed-settings.d/tui.json`, which keeps the classic
    renderer so that the terminal can select text.
- Codex: image paste works under `paste` and `bidirectional`.
  - Copy reaches the host under `bidirectional`.
  - Under `paste`, arboard succeeds against the service. So Codex writes no OSC 52, and its copies
    reach no clipboard on any terminal.
    - Decided: this is `paste` mode's intent, no copy through the sandbox ("Documentation").
  - Under `off`, Codex keeps copying through OSC 52.
  - Reconsider `fullscreen_transcript = false` in the image's `codex/config.toml`. With the
    service, Codex's own copies reach the host under `bidirectional`, but under `paste` only the
    terminal's selection copies.
- agy: the result depends on the measured invocations.
- kiro-cli: `/paste` and `/copy` still fail. Serving those commands needs an X server, which this
  plan excludes.
- Copilot: image paste works under `paste` and `bidirectional`.
  - Under `bidirectional`, copy behaves as today, except that an HTML copy reaches the host twice:
    through `wl-copy` and through the native module.
  - Under `paste`, copy writes OSC 52 as today.
- OpenCode: image paste succeeds at the first command. Under `paste`, copy runs `wl-copy` instead
  of `xclip`, and the relay drops both.

## Documentation

- README, `codex`:
  - under `paste`, Codex's copies reach no clipboard;
  - under `bidirectional`, a copy that the host refuses or fails still reads as done. The text can
    be selected in the terminal, since the image's `codex/config.toml` turns off Codex's fullscreen
    transcript.
- README, `copilot`: under `bidirectional`, selecting text behaves as in Copilot's own build for
  the host.
  - On Linux hosts, a selection sets the host's primary selection, for middle-click paste.
  - On macOS and Windows hosts, a selection copies nothing, since each selection would replace the
    clipboard. Use `/copy` instead.
- README's Reference block, which `--help` prints: the `--clipboard=paste` text "lets the agent
  read a copied image" names the agents the claim holds for. Those are Claude Code, Codex, agy as
  measured, Copilot and OpenCode, but not kiro-cli.
- SECURITY.md, "Clipboard": the service's socket beside the FIFOs, and that `bidirectional` also
  sets the primary selection on Linux hosts.
- The relay's code records that `primary` follows Copilot's own build for each host.

## Tests

### Before building: today's behavior

For each agent, under each mode, on Terminal.app, iTerm2, Ghostty, kitty and WezTerm, first with
their default settings and then with any clipboard setting they have turned on:

- Does the agent's copy reach the host clipboard, and through which path?
- Does Ctrl+V paste a copied image?

Specific checks:

- Terminal.app ignores OSC 52 for `c` and `p`.
- On the four OSC 52 terminals, `c` sets the clipboard. Record which iTerm2 setting that needs, and
  what `p` and `p!` do on macOS.
- Codex's and Copilot's image paste fails in every mode. Record what each agent shows the user.
- agy: record its exact clipboard invocations with a logging shim, and whether agy chooses the
  Wayland or X11 commands by `WAYLAND_DISPLAY`.
- kiro-cli: `/paste` and `/copy` fail in every mode. Record what `kiro-cli`'s "Copy to clipboard"
  is.
- Copilot's clipboard-rs stderr line appears on screen under `bidirectional`.
- OpenCode's image paste works under `paste` through its `xclip` fallback.

### The prototype, against a fake relay

- arboard `get_image` and clipboard-rs `get_image` read the PNG. When the image changes between two
  pastes, the second paste reads the new image.
- arboard `set_html` and clipboard-rs `setClipboardContents` reach the fake relay as one `set` of
  the plain text.
- A PNG larger than the capacity that `F_GETPIPE_SZ` reports for the client's pipe arrives whole,
  though the client drops its connection before reading. pipe(7) fixes no capacity.
- A client slow to read its pipe holds no relay lock: a shim and another native client are served
  meanwhile.
- A stalled relay ends a native client's `types` wait with an empty clipboard, and a shim's request
  with a failure, each within its bound.
- Replacing a copy cancels the previous source, and the copying client's thread ends.
- On binding, the service sends the seat at version 2, then `selection` with the PNG offer or with
  NULL, then `primary_selection` with NULL. A stalled relay still yields `selection` with NULL.
- A source that neither writes nor closes its descriptor is abandoned at the deadline, and at once
  when the client disconnects.

### The implementation

- Integration under `paste` and `bidirectional`, for the native clients and the shims:
  - concurrent requests, a changing image, and a client that disconnects mid-transfer;
  - a stalled relay, and a relay that dies: each fails within a bound;
  - the session's end: the service exits, and the agent's exit status and signals pass through.
- Copies, by mode:
  - `off`: no service runs. Native copies fail, and the shims fail at once.
  - `paste`: a copy reaches no clipboard and reports success, through the shim and natively. A copy
    over `MaxRequestBytes` fails the shim and still reports success natively.
  - `bidirectional`: a copy over `MaxRequestBytes`, and a copy whose host program fails, fail the
    shim and report success natively. Nothing reaches the host.
- A `primary` request, from the shim and from a native client:
  - on macOS and Windows hosts and under `paste`, leaves the host clipboard unchanged and answers
    `ok`;
  - on a Linux host under `bidirectional`, sets the primary selection and leaves the clipboard
    unchanged. The request goes through xclip, through wl-copy on a Wayland-only host, and through
    wl-copy when both are installed and xclip fails.
- `ClipboardRelayTest` covers `primary` in both relays' grammar. On a Linux host it covers
  `primary` through xclip, through wl-copy on a Wayland-only host, and through wl-copy when an
  installed xclip fails. The test's existing cases keep covering the other requests.
- Live: run the "Before building" matrix again, on macOS first, then on one Linux and one Windows
  host. On the macOS and Windows hosts, also check that `primary` leaves the clipboard unchanged.

## Excluded

- Patches to agents, an X11 server, a desktop compositor, intercepting the terminal, and host
  clipboard access beyond the table.
- A guarantee of compatibility with later agent releases. The tests recheck compatibility instead.

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
- The image's binaries: `/usr/bin/claude`, `/opt/codex/bin/codex`, `/usr/local/bin/agy`,
  `/usr/local/bin/kiro-cli` and `kiro-cli-chat`, Copilot's package under
  `~/.cache/copilot/pkg/linux-arm64/1.0.88`, and `/usr/local/bin/opencode`
