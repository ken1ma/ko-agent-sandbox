# TODO

Remaining work that adds real security or maintainability for the actual threat model, and ideas
whose benefit is uncertain, each with the condition that decides whether to build it. An idea
examined and found without benefit is recorded in design.md with its reason, so it is not proposed
again.

## Credential brokering — its two plans, in order

- [ ] `plan-credential-broker-proxy.md` whole, through its acceptance checklist.
- [ ] Real sessions on it before `plan-provider-credential-proxy.md`, whose steps are taken one
  at a time, each on a use case those sessions produced, never as the broker's automatic second
  half: what that plan adds — storage, generations, refresh, removal — is where the field
  failures are (docker/sbx-releases #492, a removed credential still injected after a restart),
  and none of it is needed for a per-run static value.
- AWS is in neither: the broker plan's "Deliberate exclusions" has why, and what a session
  forwards instead.

## Deferred — GREASE ECH on inspected hosts

- [ ] Allow an ECH extension on an inspected host, only if a client that sends GREASE ECH —
  a browser, a BoringSSL-based program — enters the image. The proxy is the TLS server there, so
  ignoring an extension it cannot decrypt is what every non-ECH server does: a GREASE client
  continues, a real-ECH client aborts on its own when the rejection is not confirmed, and the
  origin never sees the client's hello. On a `tunnel` host the refusal stays: GREASE and real ECH
  are indistinguishable by design (RFC 9849, 6.2), and real ECH under a passing outer SNI is
  domain fronting through the allowed host (`TLSHelper`, the extension constant). This adds a
  second ECH step to SECURITY.md's handshake list and its tests.

## Deferred — inspected-relay keep-alive

- [ ] Client-side keep-alive in the inspected relay, only if the per-request TLS handshake ever
  measurably hurts (104 handshakes added seconds to the recorded 104-archive install). Both legs'
  framing is parsed and enforced, so the design is a request loop per client connection with a
  fresh origin connection per request; this needs a larger state machine at the enforcement
  point and the one-request rule's smuggling argument re-argued in SECURITY.md.

## Deferred — Git LFS batch downloads

If `git lfs pull` becomes important:

- inspect the LFS batch request body;
- allow only `operation=download`;
- continue refusing upload;
- add end-to-end tests before enabling it.

Do not blindly allow the batch `POST` endpoint merely because downloads use it.

## Deferred — LAN destinations, as a session option

The proxy refuses every private, loopback, link-local and CGNAT address after resolution, and the
rule grammar refuses an IP literal, so a corporate site on the LAN without a public name is
unreachable from a session. If that is ever needed, the design that keeps the security model:

- [ ] A launch option naming exact addresses — never a range, never a line in
  `.ko-agent-sandbox/egress/`: an address is local to whoever runs the sandbox, so a committed
  line would name a different machine on every clone, and a reviewer could not say what it
  reaches. Selected at launch, like `--egress=allow-unless-denied`, and tinted in the
  banner the same way.
- [ ] The vetting allows those addresses and nothing else of the private space, and only when
  the CONNECT names the address itself: a public name resolving to a private address stays
  refused, or a name whose answer changes, or has one public and one private record, reaches
  the LAN through the name.
- [ ] An exception to the lifecycle's step 10 for the listed addresses, and only those: a
  ClientHello with no SNI is the form a client sends to an address and is allowed there, one
  naming any host stays refused. Opaque, as the simplest form; an inspected address is
  possible — the leaf can include an `iPAddress` name — and is its own further decision. Opaque,
  the consequence is stated with it: nothing binds the tunnel to a name, so the origin's
  identity rests on the client's own certificate check, which the client may skip, and the
  grant reaches every application endpoint selectable at the address — by `Host`, by HTTP/2's
  `:authority`, by whatever protocol the client speaks after the handshake — since the proxy
  sees none of it.
- [ ] Stated cost, in SECURITY.md when it is implemented: the traffic is a tunnel by construction —
  the hello allowed at step 10 is opaque at step 11 — so nothing past the CONNECT is seen or
  logged; and the sandbox then reaches, from the host's own address, services that authenticate by
  location — router and NAS pages, dev servers, dashboards, registries, CI runners — with the cloud
  metadata endpoint in the same class. Port 443 and the one-client network bound the attack surface,
  not the trust.

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
  name is a refusal naming the non-public answer, never a private address allowed.
- [ ] Run `ProxyContainerTest`'s upstream case on native Linux and in the macOS and Windows
  podman machines, and record whether each can route to a private endpoint; one that cannot must
  fail the launch, never bypass the upstream proxy. Whether an address the host has on its network
  reaches a loopback helper such as cntlm under rootless podman is part of the same run.

## Deferred — `--explain-request`, the ordered rules traced for one request

The rule file's order being its meaning (`egress-proxy.md`, "The rule file"), the question an
operator
asks is no longer "is this host allowed" — `--egress-check` answers that — but "which line
decided this request". doas answers it with `doas -C`, which evaluates a hypothetical command
against the file through the same code that would run it; the equivalent here is a trace:

- [ ] `--explain-request METHOD URL`, printing the request's classification, each applicable
  line with the grant state it leaves, the boundary the longest match selects, and the
  decision. The trace comes from the proxy's own resolver and authorizer emitting it as they
  decide, run through the launcher's dry run — never a second evaluator in production: the
  tests' plain ordered evaluator stays the oracle the fold is checked against, and a trace
  that could disagree with enforcement would be worse than none.

## Deferred — staged-workspace extensions and hardening

These are separate increments after the staged workspace in `plan-staged.md`, not reasons to put all
of its lifecycle into one change. The initial one-stage-per-project sharing unit and what happens
when it fails are defined in `../fuse/ko-agent-fs/doc/architecture.md` ("Who may reach the mount").

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
  rewrites the remaining plan under a new digest.
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
  folding, open-file holds — with the launcher in place of `lower-probe-host.py`; both probe
  halves are deleted when their rows are added. Their machine record adds the upper volume's
  filesystem, which is what the staged design needs the answers for (`plan-staged.md`).
- [ ] The `--run-on-host`-gated row: a command through the channel, then `target/` read back from
  the container — a host-native build turns host writes from an occasional human edit into
  every build.

## Deferred — keep the host awake during long sandbox work (caffeinate)

The design is recorded here so it can be adopted or rejected deliberately rather than redesigned
from scratch.

**Problem.** A host that idle-sleeps mid-build suspends the podman machine: builds stall, API
connections break. Claude Code solves this on macOS by wrapping long commands in `caffeinate`, but
the agent here runs inside a Linux container — it cannot reach the host's power manager, and the
launcher execs away on POSIX, so neither side has an obvious place to run it.

**The lease design:**

- A `caffeinate` shim in the sandbox image — the macOS name, so agents' trained habit transfers.
  It accepts the familiar flags (`-t`, `-w`), execs the wrapped command with its exit status passed
  through, and refreshes a lease file under a dedicated mount every 15 s while the command runs.
- The launcher mounts a launcher-owned lease directory there and starts a host-side watcher that
  reads lease **freshness, never content** — nothing to inject into; the channel is one bit whose
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
  the launcher's only scope is the whole session, so an idle open agent would keep the laptop awake,
  which is the reason the lease is scoped to a command at all.

**Open questions:** whether the feature is worth building at all, and whether a container→host
channel — however narrow — should exist for a convenience. One constraint on any implementation:
command builders must take the podman path as a parameter, never read the global, which fails fast
on podman-less machines and kills the test JVM.

## Deferred — extra hardening, low value

- [ ] Fold case in the host command profile's guard pattern (`SeatbeltProfile.anyDepth`), so a
  `.GIT` or `.KO-AGENT-SANDBOX` the command creates where no lowercase entry exists is denied on a
  case-insensitive volume (`run-on-host.md`, "The host command's filesystem rules"), with a gate
  row creating one. Until then the workspace filter is the stricter of the two guards there.

- [ ] A Seatbelt profile for the proxy the launcher serves on the host (`--serve-proxy-on-host`),
  which runs unconfined while parsing hostile bytes as the user's uid
  (`run-on-host.md` "The command's egress proxy", where the acceptance argument binds).
  Designed: `plan-host-build-daemons-and-gradle.md`, "The proxy's own profile", step 7.
- [ ] Filter `mach-lookup` in the host command profile. It is granted unfiltered, and the system
  program directories are executable (a command's scripts need `find`, `mount` and whatever else;
  `runtime-authority.txt`); together those let a command reach any Mach service — `open` through
  LaunchServices would start an application outside the profile. Measure the services a command
  actually needs, as `ops` measures operation families, and filter to them (`(allow mach-lookup
  (global-name …))`, the pattern Apple's profiles use); the gate's forked-process rows are where the
  answer is checked.

## Deferred — a bound on a silent host command

An sbt server's and a mill daemon's start are bounded by the broker's progress bound
(`run-on-host.md`, "The channel and the command", "`mill`"). A command that stalls after its
server or daemon is up — or a Maven command at any point — is silent until the agent gives up:
nothing bounds it, not the wrapper, not the
broker, whose writers die only with their requester, and not the shim, which reads output to EOF.
One form would, and it waits on a measurement:

- [ ] Generic, in the broker: no output for N seconds ends the command through the same SIGTERM,
  so the command's logs are kept, with a stderr line naming the bound and the host command log.
  Silence is measured where the command's bytes are read, and time the pump spends blocked on a
  slow requester does not count. N must exceed a healthy silence — a module compiling, a large
  download, which the proxy logs once at its start, a slow test — because a value below one is not
  a one-off failure: the rerun hits the same silence, and the project cannot build on the host
  until the constant changes. Five minutes is the smallest value defensible without measurement.

Not a form: a bound on the time to first output. Every JVM prints its `JAVA_TOOL_OPTIONS` banner
within a second, so every host command has written something before it can stall.

## Deferred — an idle bound for the sbt server

The broker's sbt server has no idle bound of the broker's: it lives until the launch ends,
`sandbox-run-on-host sbt shutdown`, or sbt's own `serverIdleTimeout`, seven days
(`run-on-host.md`, the startup-cost paragraph). A warm server is what a terminal user keeps on
purpose, so its heap is the price chosen; Mill's daemon exits on Mill's own thirty minutes.

The form, if a launch ever wants one: a broker-kept bound selected by a launch option — never an
environment variable, since the command's environment is closed by design — with thirty minutes,
Mill's default, as the value to start from. Idle counts from the end of the last sbt command,
never from the server's start. The broker's serve loop blocks in the handshake reader between
requests, so the bound needs a timer thread, the one thread retiring runtimes outside the serial
dispatch, fenced thus: one lock covers the broker's runtime state; a request takes it, marks the
runtime busy and cancels its pending expiry before the command receives the runtime, and re-arms
the expiry when the command ends; each re-arming increments an idle generation kept with the
runtime; an expiry carries the generation it was armed with and, under the lock, retires the
runtime only if that instance is idle and its generation is still the expiry's own — so a
cancelled callback that had left its sleep before a request re-armed the timer does nothing, and
a timer outliving a retired runtime is a no-op on its replacement. Its tests: a request arriving
as the timer fires, that late callback, and a stale timer after replacement, each leaving one
consistent runtime.

## Deferred — a rule-file edit taking effect at the next command

A program's rule file, and the distribution `cs install sbt` execs, are read when the broker
creates a runtime, and an edit to either leaves a running one as it is: the edit takes effect at
the runtime's next creation (`run-on-host.md`, "The command's egress proxy"). Until then a host
removed from the file stays reachable from that runtime's proxy, and one added is not. The form:
the broker compares, before each command, the file's lines and the distribution's home with those
the runtime was created from, and retires the runtime on a difference — the proxy with its server
or daemon, whose JVM options carry the proxy's port from their start — so the edit takes effect
at the next command, at the cost of a start. The comparison the broker makes before each `mill`
command for Mill's own inputs (`RunOnHostPrereqs.millDaemonConfig`) is the shape.

## Deferred — ending the mill starter once the daemon listens

The broker starts Mill's daemon by running the build directory's `./mill version` under the
daemon profile, which denies the launcher's own connect, so the launcher retries for ten seconds
before it exits (`run-on-host.md`, "`mill`"); every daemon start pays that retry. Ending the
starter as soon as `lsof` shows the daemon listening would save it. That must signal the
starter's own pid alone — the daemon lives in the same registered group, so ending the group
would end it — and it needs the process topology the gate's daemon rows record first: which pid
is the launcher and which the daemon, and that the daemon survives its starter's TERM as it
survives the starter's own exit (`destroyOnExit = false`, `MillServerLauncher.scala`).

## Deferred — cross-launch server takeover

Two `ko-agent-sandbox` launches on one project share nothing: each broker keeps its own sbt
servers, and one launch's command for a build directory another launch's broker still owns is
refused rather than served (`SECURITY.md` "Run on host"; `RunOnHostSandbox.BrokerRuntimes`). The
build lock already serializes the *commands* of one directory across launches, so a running
command never overlaps; what is deferred is a launch *ending or adopting another live launch's
warm server* so the second need not wait for the first launch to end. This is separate from
sharing one server between two launches ("two launches sharing one server or daemon", below):
takeover ends the other launch's server and starts its own; sharing runs both launches' clients
against one server.

Ending a process another party owns is implemented for Mill, for the user's own daemon
(`MillDaemons.endForeign`): the daemon is found in the process table, its idleness observed on its
own TCP table, and its pid and start time proved again immediately before each signal. Another
launch's daemon is refused, as another launch's sbt server is, and for the same reason.

The reason it is deferred, not done: a broker ending another broker's server means one process
signalling another's recorded process group, and `endRecordedGroup` validates the leader's pid and
start time and then signals — so a peer ending the same group, and the pid being recycled between
the check and the signal, would send the signal to an unrelated group. Making that safe needs a
shared exclusion held from the identity check through the signal, across:

- **cancellation** — the owner retiring its own server after a cancel,
- **replacement** — the owner replacing a server whose proxy or portfile changed,
- **teardown** — the owner ending all its servers at the launch's end, including on `SIGTERM`,
- **scavenging** — a start collecting a *dead* owner's leftover server (this one already has its
  exclusion: the scavenger condemns the dead session by rename under a lock, so no live broker
  races it; a live owner is what the takeover must coordinate with).

The build lock, held per program and build directory, is the natural exclusion, but every one of
those paths must take it around the whole validate-and-signal, and teardown taking build locks on
`SIGTERM` is the hard part. When built, this needs deterministic concurrency tests that pause one
retirement between the identity check and the signal while another retires and recycles the group
(through the injected `Processes` seam, without real OS pids), covering all four paths.

## Deferred — two launches sharing one server or daemon

Two launches on one project could share one sbt server or mill daemon when everything the
runtime was created from is equal — JDK home, executable and distribution, cache root, rule
lines, and the forwarded name/value pairs, the one that decides it for security, since a launch
forwarding a secret must not serve a launch that does not. The egress profile is never part of
it: every host command's proxy gets `deny defaults`, Maven Central and the rule file. The second
launch is refused the directory while the first lives; "cross-launch server takeover", above, is
the other way past that refusal, ending the first launch's runtime.

The design: the broker writes that set as a descriptor into its session, out of the confined
command's reach since the profile grants `tmp/` alone; a second launch finding a server whose
socket, or a daemon whose group, belongs to a live broker session compares descriptors and, when
equal, attaches with that session's socket directory or daemon port and proxy port in its client
profile, Mill's own fingerprint check agreeing by construction; when different, the refusal
stays. Its costs, documented with it: a cancel across launches is the tool's own, since the
server is not the canceller's to retire, so a test that ignores interruption runs on until the
next command queues behind it; and the owning launch's end takes the shared server with it, a
build of the other launch included, whose next command starts its own.

## Deferred — fetching mill's JVM launcher for the user

A `mill` command whose pinned version the user has not provisioned is refused with the command
to run, `MILL_VERSION=<v>-jvm ./mill version` in a host terminal (`run-on-host.md`, "`mill`").
The sandbox does not fetch the launcher itself because of where the bootstrap keeps it:
`~/.cache/mill/download` is the folder the user's own unconfined `./mill` runs launchers from,
so an executable the sandbox chose there would later run outside any sandbox. The refusal is
clear, and once per version per user it is a tolerable cost.

A way to remove the step while keeping the rule that the user provisions executables and the
sandbox fetches only artifacts: the JVM launcher is the Maven Central artifact
`com.lihaoyi:mill-dist:<v>` (its `-assembly` jar, the file the bootstrap downloads), on the host
every `mill` command's proxy already allows. The wrapper would resolve it through the proxy into
the project's run-on-host cache like any other jar, and start it as
`java -cp <jar> mill.launcher.MillLauncherMain` instead of through the bootstrap script.

- Benefits: no host step for the user, for a first project and for every version bump; nothing
  written where the user's own `./mill` looks; the file is never executed directly, since the
  profile grants caches no process-exec and the JVM only loads them, so the pin in the project
  selects a version, never a file the user runs.
- Costs: the wrapper runs Mill's launcher class rather than the stock `./mill` script, so the
  script's own resolution — the version pin, `MILL_FINAL_DOWNLOAD_FOLDER`, the `-jvm` and
  `-native` cases — is replaced by the wrapper's, which already reads the same pins; the first
  command from a project downloads the launcher, tens of megabytes, through the proxy; and the
  plan's decision to start the daemon with the stock executable (section 7.2) would be revised,
  with the daemon start and the gate's Mill rows measured again.

## Deferred — Gradle under `--run-on-host`

Gradle does not fit the host command profile: its daemon, workers and file-lock socket bind TCP
and UDP ports of the kernel's choosing and connect to each other's, and the profile grants no
listener and no connect but the proxy's port (`run-on-host.md`, "Network"). Designed and decided:
`plan-host-build-daemons-and-gradle.md`, Phase 2 and "Revision — Phase 2 scope" — Gradle runs
under Mill's daemon grant plus outbound to any port of this host, the cost stated in
`SECURITY.md`'s per-program table. Removed when Phase 2 lands.

## Deferred — same-path workspace mounting under `--run-on-host`

Its own launch option, when it arrives. It aligns source paths and nothing else — the host command's
JVM is a macOS binary and the container's is Linux, and their Coursier cache roots differ — so it
does not establish compatibility between the two builds' state. That leaves readable paths in
build output as the benefit, which did not justify the change. The host path is already in
the container: the command's streamed output names it (`SECURITY.md`, "Run on host"). Prior
art, both mounting the project at its host path for path legibility rather than shared state:

- Gemini CLI sandboxing: https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/sandbox.md
- Docker Sandboxes, whose parent directories are empty scaffolding so only the workspace is real:
  https://www.docker.com/blog/building-ai-teams-docker-sandboxes-agent/

## Deferred — readable session directory names under `--run-on-host`

- [ ] Name the sessions `broker-<random>` and `command-<random>` instead of `b<random>` and
  `s<random>` (`RunOnHostSession.Kind`), once the path length allows it: the session's `tmp/` hosts
  sbt's boot socket, and `RunOnHostPrereqs.SessionTmpMaxLength` leaves that path 53 characters,
  of which the root and Java's 20-digit temp-directory name take 51. Either sbt's boot socket
  comes to need fewer than its 50 characters past the directory (`sbt-issues.md`, the thin-client
  entry — its fix as requested only turns the crash into a message, and lifts no length), or the
  session names get a shorter random part of their own, with the collision retry
  `Files.createTempDirectory` does today.

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

- [ ] One decision that must settle several names together: the jar's artifact name and
  publication coordinates; the Scala package names (`agentsandbox.*`, containing neither the
  `ko-` prefix nor an organization); and the image label key (`ko-agent-sandbox.bundle` —
  OCI convention wants a reverse-DNS key, and the right prefix is this same identity, so deciding
  the key alone would decide the identity by accident). Until then a changed key ends in
  the "rebuild with --build" refusal, so the exposure is bounded.
