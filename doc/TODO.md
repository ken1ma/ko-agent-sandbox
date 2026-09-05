# TODO

Remaining work that buys real security or maintainability for the actual threat model. Ideas
without a concrete gain live in design.md as standing design decisions so they stop resurfacing.

## Deferred — GREASE ECH on inspected hosts

- [ ] Admit an ECH extension on an inspected host, only if a client that sends GREASE ECH —
  a browser, a BoringSSL-based tool — enters the image. The proxy is the TLS server there, so
  ignoring an extension it cannot decrypt is what every non-ECH server does: a GREASE client
  continues, a real-ECH client aborts on its own when the rejection is not confirmed, and the
  origin never sees the client's hello. On a `tunnel` host the refusal stays: GREASE and real ECH
  are indistinguishable by design (RFC 9849, 6.2), and real ECH under a passing outer SNI is
  domain fronting through the allowed host (`TLSHelper`, the extension constant). The price is a
  second ECH step in SECURITY.md's handshake list and its tests.

## Deferred — inspected-relay keep-alive

- [ ] Client-side keep-alive in the inspected relay, only if the per-request TLS handshake ever
  measurably hurts (104 handshakes added seconds to the recorded 104-archive install). Both legs'
  framing is parsed and enforced, so the design is a request loop per client connection with a
  fresh origin connection per request; the price is a larger state machine at the enforcement
  point and the one-request rule's smuggling argument re-argued in SECURITY.md.

## Deferred — Git LFS batch downloads

If `git lfs pull` becomes important:

- inspect the LFS batch request body;
- allow only `operation=download`;
- continue refusing upload;
- add end-to-end tests before enabling it.

Do not blindly allow the batch `POST` endpoint merely because downloads use it.

## Deferred — LAN destinations, as launch-time authority

The proxy refuses every private, loopback, link-local and CGNAT address after resolution, and the
rule grammar refuses an IP literal, so a corporate site on the LAN without a public name is
unreachable from a session. If that is ever needed, the shape that keeps the security model:

- [ ] A launch option naming exact addresses — never a range, never a line in
  `.ko-agent-sandbox/egress/`: an address is local to whoever runs the sandbox, so a committed
  line would name a different machine on every clone, and a reviewer could not say what it
  reaches. Authority typed at launch, like `--egress=allow-unless-denied`, and tinted in the
  banner the same way.
- [ ] The vetting admits those addresses and nothing else of the private space, and only when
  the CONNECT names the address itself: a public name resolving to a private address stays
  refused, or a name whose answer changes, or has one public and one private record, reaches
  the LAN through the name.
- [ ] An exception to the lifecycle's step 10 for the listed addresses, and only those: a
  ClientHello with no SNI is the form a client sends to an address and is admitted there, one
  naming any host stays refused. Opaque, as the simplest form; an inspected address is
  possible — the leaf can include an `iPAddress` name — and is its own further decision. Opaque,
  the consequence is stated with it: nothing binds the tunnel to a name, so the origin's
  identity rests on the client's own certificate check, which the client may skip, and the
  grant reaches every application endpoint selectable at the address — by `Host`, by HTTP/2's
  `:authority`, by whatever protocol the client speaks after the handshake — since the proxy
  sees none of it.
- [ ] Stated cost, in SECURITY.md when it lands: the traffic is a tunnel by construction — the
  hello admitted at step 10 is opaque at step 11 — so nothing past the CONNECT is seen or
  logged; and the sandbox then holds
  the host's network position against services that authenticate by location — router and NAS
  pages, dev servers, dashboards, registries, CI runners — with the cloud metadata endpoint in
  the same class. Port 443 and the one-client network bound the surface, not the trust.

## Deferred — the upstream proxy's interception CA, explicit resolvers, the container matrix

- [ ] Trust an upstream proxy's interception CA, so a TLS-terminating one stops failing closed
  with certificate errors (`egress-proxy.md`, "Through an upstream proxy"). Its inclusion is
  authority — it lets that proxy read and change opaque model traffic — so it needs a
  launch-time selection and a banner line of its own, and four stores extended: the proxy's
  origin trust, the sandbox PEM bundle, the image JDK's `cacerts`, and `sandbox-jdk-use-proxy`'s
  certificate. An endpoint CA, for an `https` endpoint under a private CA, is carried the same
  way but extends one store only, the trust the proxy verifies the endpoint against: in any of
  the four it would be interception authority.
- [ ] Explicit resolvers for the proxy container, only when podman's resolver — which follows the
  host's on Linux and the host's through the machine elsewhere — stops answering for someone.
  Any resolver keeps the all-answers-public check for origins: an internal mirror for a public
  name is a refusal naming the non-public answer, never a private address admitted.
- [ ] Run `ProxyContainerTest`'s upstream case on native Linux and in the macOS and Windows
  podman machines, and record whether each can route to a private endpoint; one that cannot must
  fail the launch, never bypass the upstream proxy. Whether an address the host has on its network
  reaches a loopback helper such as cntlm under rootless podman is part of the same run.

## Deferred — `--explain-request`, the ordered rules traced for one request

The rule file's order being its meaning (`egress-proxy.md`, "The rule file"), the question an
operator
asks is no longer "is this host admitted" — `--egress-check` answers that — but "which line
decided this request". doas answers it with `doas -C`, which evaluates a hypothetical command
against the file through the same code that would run it; the equivalent here is a trace:

- [ ] `--explain-request METHOD URL`, printing the request's classification, each applicable
  line with the grant state it leaves, the boundary the longest match selects, and the
  decision. The trace comes from the proxy's own resolver and authorizer emitting it as they
  decide, run through the launcher's dry run — never a second evaluator in production: the
  tests' plain ordered evaluator stays the oracle the fold is checked against, and a trace
  that could disagree with enforcement would be worse than none.

## Deferred — staged-workspace extensions and hardening

These are separate increments after the staged workspace in `plan-staged.md`, not reasons to put
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

## Deferred — `--self-test`'s remaining share rows

`--self-test` runs share rows after the crate's suites (`SelfTestShare.scala`,
`../fuse/ko-agent-fs/doc/testing.md`): the share is what the container suites cannot reach,
and the coherency rows cross it launcher-driven and machine-recorded, the scratch gone on
success and kept on failure — its files are how a row that measured a refusal is told apart from a
row where the probe broke — with a killed run leaving nothing outside the mounts/ sweep,
`--reset-all`'s container sweep and the named scratch. Still to fold, to that same standard:

- [ ] The `probe/lower-probe.py` rows — hardlink identity, rename flags, symlink creation, case
  folding, open-file holds — with the launcher playing `lower-probe-host.py`'s part; both probe
  halves are deleted when their rows land. Their machine record adds the upper volume's filesystem,
  which is what the staged design needs the answers for (`plan-staged.md`).
- [ ] The `--run-on-host`-gated row: a build through the channel, then `target/` read back from
  the container — a host-native build turns host writes from an occasional human edit into
  every build.

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

## Deferred — extra hardening, low value

- [ ] A Seatbelt profile for the proxy the launcher serves on the host (`--serve-proxy-on-host`),
  which runs unconfined while parsing hostile bytes as the user's uid
  (`run-on-host.md` "The build's egress proxy", where the acceptance argument binds:
  loopback-only listener, a JVM parse bug as the failure mode, `HostileInputTest` over the
  surface). The profile, if it ever earns its cost: read-only JDK and launcher jar, writes to its
  log alone, no `process-exec*`, unrestricted `network-outbound` — host filtering is the proxy's
  own job, and SBPL cannot filter by name — plus its loopback listener.
- [ ] Filter `mach-lookup` in the host build profile. It is granted unfiltered, and the system tool
  directories are executable (a build's scripts need `find`, `mount` and whatever else;
  `runtime-authority.txt`); together those let a build reach any Mach service — `open` through
  LaunchServices would start an application outside the profile. Measure the services a build
  actually needs, as `ops` measures operation families, and filter to them
  (`(allow mach-lookup (global-name …))`, the pattern Apple's profiles use); the gate's
  forked-process rows are where the answer is checked.

## Deferred — same-path workspace mounting under `--run-on-host`

Its own launch option, when it arrives. It aligns source paths and nothing else — the host build's
JVM is a macOS binary and the container's is Linux, and their Coursier cache roots differ — so it
does not establish compatibility between the two builds' state. That leaves legible paths in
build output as the benefit, which did not justify the change. The host path reaches the
container regardless: the build's streamed output names it (`SECURITY.md`, "Run on host"). Prior
art, both mounting the project at its host path for path legibility rather than shared state:

- Gemini CLI sandboxing: https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/sandbox.md
- Docker Sandboxes, whose parent directories are empty scaffolding so only the workspace is real:
  https://www.docker.com/blog/building-ai-teams-docker-sandboxes-agent/

## Before the first release — continuous integration

There is no CI. The README's developer commands run the launcher, proxy and filter suites;
`--self-test` runs the filter suites on demand. A user's `--build` instead performs the gates whose
answers belong to that artifact and machine: `cargo deny check licenses bans sources`, compilation,
binary identity, and the installed filter's mount self-test.

- [ ] Add CI for the launcher's and proxy's `sbt testFull`, and the filter's pure and binary suites
  on both shipping architectures. Add `cargo deny check advisories` there: `deny.toml` records why
  its moving external database must not gate installation.
- [ ] Keep the artifact-local gates above in `--build`, and keep the mounted filter suites in
  `--self-test`; CI does not prove the filter on a user's own machine.

## Before the first release — the published identity

- [ ] One decision, several names that must fall out of it together: the jar's artifact name and
  publication coordinates; the Scala package names (`agentsandbox.*`, containing neither the
  `ko-` prefix nor an organization); and the image label key (`ko-agent-sandbox.bundle` —
  OCI convention wants a reverse-DNS key, and the right prefix is this same identity, so deciding
  the key alone would decide the identity by accident). Until then a changed key self-heals
  through the "rebuild with --build" refusal, so the exposure is bounded.
