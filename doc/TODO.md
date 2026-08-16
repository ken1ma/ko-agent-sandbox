# TODO

Remaining work that buys real security or maintainability for the actual threat model. Ideas
without a concrete gain live in DESIGN.md as Non-TODOs so they stop resurfacing.

## P1 — Black-box security integration tests: what is still out of reach

The launcher and proxy unit tests cover many trust-critical pure functions. What they cannot show is
that the **effective Podman topology, mounts, and runtime behavior** have the properties the source
intends — and prior art has had real regressions where a network-sandbox option meant for one
purpose reopened arbitrary outbound traffic, and where DNS stayed an exfiltration path despite
network restrictions:

- Anthropic Sandbox Runtime #225:
  https://github.com/anthropic-experimental/sandbox-runtime/issues/225
- Anthropic Sandbox Runtime #88: https://github.com/anthropic-experimental/sandbox-runtime/issues/88

Six suites settle most of it, each gated on the venue its evidence lives in.
`SessionBoundaryTest` runs **inside** a session: uid, capabilities, mounts, routes and cgroup
limits; that unsetting the proxy variables restores nothing; the CONNECT gate's refusals; which
tier a host is in, told apart by the certificate it presents; what an inspected tunnel permits; and
that the filter freezes git control state at any depth. On the **host**, under
`KO_AGENT_SANDBOX_INTEGRATION=1` so an ordinary run never starts a container:
`MountLifecycleTest` drives the workspace filter's mount lifecycle, `ProxyContainerTest` inspects
the proxy's own container, `RunTopologyTest` covers a run's networks, the isolation between
concurrent sessions and projects, and `--reset` sweeping a run that outlived its reaper,
`WorkspaceGuardOffTest` drives the opted-out mode's `.git` pins against host-side mutation, and
`EgressPolicyTest` launches one session per project-supplied policy — including the proxy's
upstream certificate check, which no session can demonstrate about itself.

What is left needs a fixture nobody here owns. The five host suites share `IntegrationSession`,
which makes its own scratch project and launches through the launcher's own name builders, so the
remaining rows extend a shape that exists rather than one still to be built.

- [ ] **The resident teardown path**, which removes a run's resources from the launcher process
  instead of the reaper. Native Windows always takes it; a POSIX launch falls back to it only when
  the reaper's spawn fails, and nothing outside the process can make that happen — DESIGN.md
  declines the test hook that would. So: verified on a Windows host, or not at all.
- [ ] **An absent or pointer-file `.git` in the opted-out mode**: `WorkspaceGuardOffTest` drives an
  ordinary repository, and the whole-directory pin the other two shapes get is a different mount.
- [ ] **The bundle version lock** end to end: a default-named image whose label mismatches this
  jar's digest refuses the launch with the rebuild hint, while an explicitly overridden image only
  warns. Needs a deliberately mislabelled image.
- [ ] **`storage.googleapis.com` with a signed upload URL** — the case the read-only tier exists
  for. The session probe refuses a plain `PUT` there; the signed form needs a URL only the bucket's
  owner can mint.
- [ ] Client-side keep-alive in the inspected relay, only if the per-request TLS handshake ever
  measurably hurts (a 104-archive install's 104 handshakes cost seconds today). Both legs' framing
  is parsed and enforced, so the shape is a request loop per client connection with a fresh
  upstream connection per request; the price is a larger state machine at the enforcement point and
  the one-request stance's smuggling argument re-argued in SECURITY.md.

### Nested read-only mount stability under host-side mutation

Docker Sandboxes #388 (https://github.com/docker/sbx-releases/issues/388) reports a nested read-only
mount disappearing after host-side mutation, access falling through to the writable parent. The
opted-out mode's `.git` pins are that shape, and **Podman does the same within about two seconds of
the host replacing either pinned path's inode** — which is how `git config` and most editors write.
`WorkspaceGuardOffTest` measures it and SECURITY.md ("The opted-out mode's `.git` pins") states what
it costs; there is no fix inside a mode whose enforcement is a mount over a path. The default
session's filter is not affected — it has no nested mounts to lose.

- [ ] Re-measure on the other host families: Linux rootless Podman, and Windows if it is supported
  by then. The suite runs unchanged; only the row of results is missing.

## Deferred — Git LFS batch downloads

No implementation now.

If `git lfs pull` becomes important:

- inspect the LFS batch request body;
- allow only `operation=download`;
- continue refusing upload;
- add end-to-end tests before enabling it.

Do not blindly allow the batch `POST` endpoint merely because downloads use it.

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
