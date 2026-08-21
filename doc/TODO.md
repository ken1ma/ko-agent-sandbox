# TODO

Remaining work that buys real security or maintainability for the actual threat model. Ideas
without a concrete gain live in DESIGN.md as Non-TODOs so they stop resurfacing.

## Deferred — inspected-relay keep-alive

- [ ] Client-side keep-alive in the inspected relay, only if the per-request TLS handshake ever
  measurably hurts (a 104-archive install's 104 handshakes cost seconds today). Both legs' framing
  is parsed and enforced, so the shape is a request loop per client connection with a fresh
  upstream connection per request; the price is a larger state machine at the enforcement point and
  the one-request stance's smuggling argument re-argued in SECURITY.md.

## Deferred — Git LFS batch downloads

No implementation now.

If `git lfs pull` becomes important:

- inspect the LFS batch request body;
- allow only `operation=download`;
- continue refusing upload;
- add end-to-end tests before enabling it.

Do not blindly allow the batch `POST` endpoint merely because downloads use it.

## Deferred — staged-workspace extensions and hardening

These are separate increments after the staged workspace in `PLAN-STAGED.md`, not reasons to put
all of its lifecycle into one change. The initial one-stage-per-project sharing unit and its failure
semantics are defined in `../fuse/ko-agent-fs/doc/architecture.md` ("Who may reach the mount").

- [ ] Detect project-directory replacement before attaching a persistent stage. Record a host-only
  root identity, an optional resolved-gitdir identity and a small secondary fingerprint; ordinary
  branch switches and host edits must remain live. An uncertain or different origin preserves the
  stage and requires explicit reattachment. Reattachment must not rewrite the per-path baselines
  that detect apply conflicts.
- [ ] Create a host-only rollback bundle before applying a sealed generation. It records the
  original contents and metadata, absence of new paths, and the sealed-plan identity, making a
  partial multi-file apply recoverable. Preflight its storage cost and require an explicit override
  when a bundle cannot be made.
- [ ] Treat stage and apply disk exhaustion as a boundary condition: preflight upper-layer,
  temporary-replacement, rollback and staged-control-journal space; fail writes or apply closed;
  retain a precise partial result; and never spill into the host project directory, discard pending
  state, or fall back to live write. The live mutation journal's bounded, fail-closed storage
  behavior is defined in the initial increment and is not deferred here.
- [ ] Add a tested host-side migration when a persistent stage representation first changes. The
  staged-workspace increment versions upper layers and whiteouts, lower baselines, sealed
  generations and apply plans and refuses an unknown version; extend the manifest to rollback
  bundles when those are implemented. A migration never silently reinterprets or deletes an older
  stage.
- [ ] Attribute mutations in shared live and staged workspaces to attached sessions where the
  request supplies reliable identity. Keep this diagnostic and best-effort: journal entries may
  report an unknown session and status may report multiple or unknown sessions, while the
  workspace-wide journal or trusted upper-layer delta remains authoritative.
- [ ] Add non-interactive plan/apply only with a concrete automation use case. `--stage plan` seals
  the current generation and returns a digest; `--stage apply --plan=<digest> --yes` applies the
  whole conflict-free plan. The digest binds the project identity, representation version,
  generation, complete operation groups, content and metadata hashes, lower baselines, and rename
  and hardlink relationships. A mismatch changes nothing; path selection remains interactive and
  rewrites the residual plan under a new digest.
- [ ] Add `--stage-name=<name>` only when one project needs concurrent independent staged change
  sets. Each name selects a separate upper layer, merged mount, cache and failure domain over the
  same project directory; sessions sharing a name still share those resources. Define safe name
  encoding, resource limits, management-command selection, project-wide apply serialization and
  migration from the sole unnamed stage before exposing it.

## Deferred — keep the host awake during long sandbox work (caffeinate)

The design is recorded here so it can be adopted or rejected deliberately rather than redesigned
from scratch.

**Problem.** A host that idle-sleeps mid-build suspends the podman machine: builds stall, API
connections break. Claude Code solves this on macOS by wrapping long commands in `caffeinate`, but
the agent here runs inside a Linux container — it cannot reach the host's power manager, and the
launcher execs away on POSIX, so neither side has an obvious place to stand.

**The lease design:**

- A `caffeinate` shim in the sandbox image — the macOS name, so agents' trained habit transfers.
  It accepts the familiar flags (`-t`, `-w`), execs the wrapped command with its exit status passed
  through, and refreshes a lease file under a dedicated mount every 15 s while the command runs.
- The launcher mounts a launcher-owned lease directory there and starts a host-side watcher that
  reads lease **freshness, never content** — no injection surface; the channel is one bit whose
  worst misuse drains a battery (it belongs in SECURITY.md's low-bandwidth list when it returns).
- The watcher per host: macOS, a detached sh loop (reaper pattern) running
  `/usr/bin/caffeinate -i -t 20` while fresh — the assertion doubling as the poll interval, so no
  child pid to manage; Linux, the same loop with `/usr/bin/systemd-inhibit --what=idle:sleep`,
  keyed on that absolute path existing; Windows, a daemon thread in the resident launcher calling
  kernel32 `SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)` via FFM — per-thread
  state that clears when the thread dies, so no teardown path. WSL is a documented gap: the Linux
  mechanism cannot reach the Windows power manager.
- Two simpler halves that come with it: `--build`/`--update` wrapped in `caffeinate -i`
  unconditionally on macOS (finite work, no reason to ask), and *not* a session-wide env-var wrap —
  the launcher's only scope is the whole session, so an idle open agent would pin the laptop awake,
  which is the reason the lease is scoped to a command at all.

**Open questions:** whether the feature carries its weight at all, and whether a container→host
channel — however narrow — should exist for a convenience. One constraint on any implementation:
command builders must take the podman path as a parameter, never read the global, which fails fast
on podman-less machines and kills the test JVM.

## Before the first release — continuous integration

There is none, which is why both image builds run their own suites on every user's `--build`:
`ko-agent-fs`'s Containerfile runs `cargo deny` and `cargo test` before it produces a binary, and
the proxy's runs `sbt testFull` before it packages a jar. That is the right arrangement while it is
the only automated gate in existence — removing it would not move those suites anywhere, it would
leave them running when a developer remembers.

- [ ] Add CI, then trim each image build to what belongs on the user's machine rather than on ours:
  - `cargo deny check licenses bans sources` stays. It gates the licences of what actually ships,
    and an image whose licences were never checked should not exist. Its fourth check, `advisories`,
    is what CI adds rather than moves: nothing runs it today, and the image build is the wrong home
    for it — `deny.toml` records why a moving external input must not gate the command a user
    installs with.
  - `tests/binary.rs` stays. It spawns the built artifact for the shipping musl triple on the
    user's own architecture, which is the one thing our machine cannot cover for theirs
    (`fuse/ko-agent-fs/doc/testing.md` has why the triple is not cosmetic).
  - The pure suites — policy, inode, guard, the git corpus, the proxy's parsers — move to CI, where
    they run once per change instead of once per user.

  What that buys is build time. What it costs is that a user who edits the source they were handed
  to read no longer has its tests run against what they built, which is not nothing in a design
  that ships source rather than a binary. Weigh it when the time comes.

## Before the first release — the published identity

- [ ] One decision, several names that must fall out of it together: the jar's artifact name and
  publication coordinates; the Scala package names (`agentsandbox.*` today, carrying neither the
  `ko-` prefix nor an organization); and the image label key (`ko-agent-sandbox.bundle` today —
  OCI convention wants a reverse-DNS key, and the right prefix is this same identity, so deciding
  the key alone would decide the identity by accident). Until then a changed key self-heals
  through the "rebuild with --build" refusal, so the exposure is bounded.
