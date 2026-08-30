# TODO

Remaining work that buys real security or maintainability for the actual threat model. Ideas
without a concrete gain live in DESIGN.md as Non-TODOs so they stop resurfacing.

## Deferred — inspected-relay keep-alive

- [ ] Client-side keep-alive in the inspected relay, only if the per-request TLS handshake ever
  measurably hurts (104 handshakes added seconds to the recorded 104-archive install). Both legs'
  framing is parsed and enforced, so the shape is a request loop per client connection with a
  fresh upstream connection per request; the price is a larger state machine at the enforcement
  point and the one-request stance's smuggling argument re-argued in SECURITY.md.

## Deferred — Git LFS batch downloads

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

## Deferred — `--self-test`'s share rows

`--self-test` builds the self-test image and runs the crate's suites in it
(`../fuse/ko-agent-fs/doc/testing.md`). Those settle the code's own logic and the kernel; the share
is the axis they cannot reach, because their backing tree is the container's own storage
(`DESIGN.md`). The rows that do reach it are hand-run probes with a host terminal beside them, and
they are the same host-writer/session-reader shape the verb would have to take.

`PLAN-SBT-ON-HOST.md` §14.7 schedules this work, because a host-native build makes that axis
routine rather than occasional. The two rows below stay here as the standard it must meet.

- [ ] Fold `probe/coherency-probe.py` and `probe/lower-probe.py` into `--self-test`: a scratch lower
  in the host project directory so the share is in the path, the host side driven by the launcher
  rather than by a person, and the full venue record — OS, podman version, machine provider, kernel,
  the lower's filesystem type and case behaviour, the upper volume's filesystem. A run with no venue
  recorded is not evidence for the next release (`../fuse/ko-agent-fs/doc/TODO.md`, "P1").
- [ ] Keep those rows non-destructive, which the container run gets for free and a share row does
  not: the work directory goes away on success and survives a failure, since its files are how a row
  that measured a refusal is told apart from a row where the probe broke; `.git` and
  `.ko-agent-sandbox` stay untouched at any depth; Podman machine configuration is unchanged. Test
  that a second run rebuilds no image, creates no second container or volume, and leaves the
  project directory byte-identical, and that a killed run leaves nothing the reset sweep does not
  match.

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
- Simpler work that comes with it: `--build`/`--update` wrapped in `caffeinate -i`
  unconditionally on macOS (finite work, no reason to ask), and *not* a session-wide env-var wrap —
  the launcher's only scope is the whole session, so an idle open agent would pin the laptop awake,
  which is the reason the lease is scoped to a command at all.

**Open questions:** whether the feature carries its weight at all, and whether a container→host
channel — however narrow — should exist for a convenience. One constraint on any implementation:
command builders must take the podman path as a parameter, never read the global, which fails fast
on podman-less machines and kills the test JVM.

## Before the first release — continuous integration

There is no CI. The README's developer commands run the launcher, proxy and filter suites;
`--self-test` runs the filter suites on demand. A user's `--build` instead performs the gates whose
answers belong to that artifact and machine: `cargo deny check licenses bans sources`, compilation,
binary identity, and the installed filter's mount self-test.

- [ ] Add CI for the launcher's and proxy's `sbt testFull`, and the filter's pure and binary suites
  on both shipping architectures. Add `cargo deny check advisories` there: `deny.toml` records why
  its moving external database must not gate installation.
- [ ] Keep the artifact-local gates above in `--build`, and keep the mounted filter suites in
  `--self-test`; CI does not prove a user's FUSE venue.

## Before the first release — the published identity

- [ ] One decision, several names that must fall out of it together: the jar's artifact name and
  publication coordinates; the Scala package names (`agentsandbox.*`, carrying neither the
  `ko-` prefix nor an organization); and the image label key (`ko-agent-sandbox.bundle` —
  OCI convention wants a reverse-DNS key, and the right prefix is this same identity, so deciding
  the key alone would decide the identity by accident). Until then a changed key self-heals
  through the "rebuild with --build" refusal, so the exposure is bounded.
