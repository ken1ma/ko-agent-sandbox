# TODO

Remaining work that adds real security or maintainability for the actual threat model, and ideas
whose benefit is uncertain, each with the condition that decides whether to build it. An idea
examined and found without benefit is recorded in design.md with its reason, so it is not proposed
again.

## Remove `KO_AGENT_SANDBOX_WORKSPACE_GUARD`

- [ ] Remove the variable and the read-only mounts of its `none` mode, so that the workspace
  filter is the one guard of a `--write=live` session.
  - The mounts protect the paths they are mounted at, and that is not enough: on a Windows volume
    with 8.3 short names a session goes around every one of them, a host-side replacement defeats
    them on macOS, and they cover the workspace root alone (SECURITY.md, "The read-only `.git`
    mounts under `WORKSPACE_GUARD=none`").
  - `plan-staged.md`, step 5, lists what the removal takes out and which documents change with
    it, and schedules it after staged mode. This row does not wait for that plan.
  - The mode is still the unfiltered control of `probe/perf-probe.py`, and the Windows
    performance row is unmeasured (`../fuse/ko-agent-fs/doc/TODO.md`, "Performance"): run that
    row first, or give the probe a control that needs no launcher mode.

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
  a browser, a BoringSSL-based program — enters the image.
  - The proxy is the TLS server there, so ignoring an extension it cannot decrypt is what every
    non-ECH server does: a GREASE client continues, a real-ECH client aborts on its own when the
    rejection is not confirmed, and the origin never sees the client's hello.
  - On a `tunnel` host the refusal stays: GREASE and real ECH are indistinguishable by design
    (RFC 9849, 6.2), and real ECH under a passing outer SNI is domain fronting through the allowed
    host (`TLSHelper`, the extension constant).
  - This adds a second ECH step to SECURITY.md's handshake list and its tests.

## Deferred — inspected-relay keep-alive

- [ ] Client-side keep-alive in the inspected relay, only if the per-request TLS handshake ever
  measurably hurts (104 handshakes added seconds to the recorded 104-archive install).
  - Both legs' framing is parsed and enforced, so the design is a request loop per client
    connection with a fresh origin connection per request.
  - This needs a larger state machine at the enforcement point and the one-request rule's
    smuggling argument re-argued in SECURITY.md.

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
  naming any host stays refused.
  - Opaque, as the simplest form; an inspected address is possible — the leaf can include an
    `iPAddress` name — and is its own further decision.
  - Opaque, the consequence is stated with it: nothing binds the tunnel to a name, so the
    origin's identity rests on the client's own certificate check, which the client may skip, and
    the grant reaches every application endpoint selectable at the address — by `Host`, by
    HTTP/2's `:authority`, by whatever protocol the client speaks after the handshake — since the
    proxy sees none of it.
- [ ] Stated cost, in SECURITY.md when it is implemented:
  - the traffic is a tunnel by construction — the hello allowed at step 10 leads to opaque
    application traffic at step 11 — so request methods, targets and bodies are neither inspected
    nor logged;
  - the sandbox then reaches, from the host's own address, services that authenticate by
    location — router and NAS pages, dev servers, dashboards, registries, CI runners — with the
    cloud metadata endpoint in the same class;
  - port 443 and the one-client network bound the attack surface, not the trust.

## Deferred — the upstream proxy's interception CA, explicit resolvers, the container matrix

- [ ] Trust an upstream proxy's interception CA, so a TLS-terminating one stops failing closed
  with certificate errors (`egress-proxy.md`, "Through an upstream proxy").
  - Its inclusion is authority — it lets that proxy read and change opaque model traffic — so it
    needs a launch-time selection and a banner line of its own.
  - Four stores are extended: the proxy's origin trust, the sandbox PEM bundle, the image JDK's
    `cacerts`, and `sandbox-jdk-use-proxy`'s certificate.
  - An endpoint CA, for an `https` endpoint under a private CA, is carried the same way but
    extends one store only, the trust the proxy verifies the endpoint against: in any of the four
    it would be interception authority.
- [ ] Explicit resolvers for the proxy container, only when podman's resolver — which follows the
  host's on Linux and the host's through the machine elsewhere — stops answering for someone.
  - Any resolver keeps the all-answers-public check for origins: an internal mirror for a public
    name is a refusal naming the non-public answer, never a private address allowed.
- [ ] Run `ProxyContainerTest`'s upstream case on native Linux and in the macOS and Windows
  podman machines, and record whether each can route to a private endpoint.
  - One that cannot must fail the launch, never bypass the upstream proxy.
  - Whether an address the host has on its network reaches a loopback helper such as cntlm under
    rootless podman is part of the same run.

## Deferred — `--explain-request`, the ordered rules traced for one request

The rule file's order being its meaning (`egress-proxy.md`, "The rule file"), the question an
operator asks is no longer "is this host allowed" — `--egress-check` answers that — but "which
line decided this request". doas answers it with `doas -C`, which evaluates a hypothetical command
against the file through the same code that would run it; the equivalent here is a trace:

- [ ] `--explain-request METHOD URL`, printing:
  - the request's classification;
  - each applicable line with the grant state it leaves;
  - the boundary the longest match selects;
  - the decision.
- [ ] The trace comes from the proxy's own resolver and authorizer emitting it as they decide, run
  through the launcher's dry run — never a second evaluator in production: the tests' plain
  ordered evaluator stays the oracle the fold is checked against, and a trace that could disagree
  with enforcement would be worse than none.

## Deferred — staged-workspace extensions and hardening

These are separate increments after the staged workspace in `plan-staged.md`, not reasons to put all
of its lifecycle into one change. The initial one-stage-per-project sharing unit and what happens
when it fails are defined in `../fuse/ko-agent-fs/doc/architecture.md` ("Who may reach the mount").

- [ ] Detect project-directory replacement before attaching a persistent stage.
  - Record a host-only root identity, an optional resolved-gitdir identity and a small secondary
    fingerprint; ordinary branch switches and host edits must remain live.
  - An uncertain or different origin preserves the stage and requires explicit reattachment.
  - Reattachment must not rewrite the per-path baselines that detect apply conflicts.
- [ ] Create a host-only rollback bundle before applying a sealed generation.
  - It records the original contents and metadata, absence of new paths, and the sealed-plan
    identity, making a partial multi-file apply recoverable.
  - Preflight its storage cost and require an explicit override when a bundle cannot be made.
- [ ] Treat stage and apply disk exhaustion as a boundary condition.
  - Preflight upper-layer, temporary-replacement, rollback and staged-control-journal space.
  - Fail writes or apply closed; retain a precise partial result.
  - Never spill into the host project directory, discard pending state, or fall back to live
    write.
  - The live mutation journal's bounded, fail-closed storage behavior is defined in the initial
    increment and is not deferred here.
- [ ] Add a tested host-side migration when a persistent stage representation first changes.
  - The staged-workspace increment versions upper layers and whiteouts, lower baselines, sealed
    generations and apply plans and refuses an unknown version; extend the manifest to rollback
    bundles when those are implemented.
  - A migration never silently reinterprets or deletes an older stage.
- [ ] Attribute mutations in shared live and staged workspaces to attached sessions where the
  request supplies reliable identity.
  - Keep this diagnostic and best-effort: journal entries may report an unknown session and
    status may report multiple or unknown sessions, while the workspace-wide journal or trusted
    upper-layer delta remains authoritative.
- [ ] Add non-interactive plan/apply only with a concrete automation use case.
  - `--stage plan` seals the current generation and returns a digest;
    `--stage apply --plan=<digest> --yes` applies the whole conflict-free plan.
  - The digest binds the project identity, representation version, generation, complete
    operation groups, content and metadata hashes, lower baselines, and rename and hardlink
    relationships.
  - A mismatch changes nothing; path selection remains interactive and rewrites the remaining
    plan under a new digest.
- [ ] Add `--stage-name=<name>` only when one project needs concurrent independent staged change
  sets.
  - Each name selects a separate upper layer, merged mount, cache and failure domain over the
    same project directory; sessions sharing a name still share those resources.
  - Define safe name encoding, resource limits, management-command selection, project-wide apply
    serialization and migration from the sole unnamed stage before exposing it.

## Deferred — `--self-test`'s remaining share rows

`--self-test` runs share rows after the crate's suites (`SelfTestShare.scala`,
`../fuse/ko-agent-fs/doc/testing.md`):

- the share is what the container suites cannot reach;
- the coherency rows cross it launcher-driven and machine-recorded;
- the scratch is gone on success and kept on failure — its files are how a row that measured a
  refusal is told apart from a row where the probe broke;
- a killed run leaves nothing outside the mounts/ sweep, `--reset-all`'s container sweep and the
  named scratch.

Still to fold, to that same standard:

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
- The watcher per host:
  - macOS, a detached sh loop (reaper pattern) running `/usr/bin/caffeinate -i -t 20` while
    fresh — the assertion doubling as the poll interval, so no child pid to manage;
  - Linux, the same loop with `/usr/bin/systemd-inhibit --what=idle:sleep`, keyed on that absolute
    path existing;
  - Windows, a daemon thread in the resident launcher calling kernel32
    `SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)` via FFM — per-thread state that
    clears when the thread dies, so no teardown path;
  - WSL is a documented gap: the Linux mechanism cannot reach the Windows power manager.
- Simpler work that comes with it:
  - `--build`/`--update` wrapped in `caffeinate -i` unconditionally on macOS (finite work, no
    reason to ask);
  - *not* a session-wide env-var wrap — the launcher's only scope is the whole session, so an idle
    open agent would keep the laptop awake, which is the reason the lease is scoped to a command
    at all.

**Open questions:** whether the feature is worth building at all, and whether a container→host
channel — however narrow — should exist for a convenience. One constraint on any implementation:
command builders must take the podman path as a parameter, never read the global, which fails fast
on podman-less machines and kills the test JVM.

## Deferred — a bound on a silent host command

An sbt server's and a mill daemon's start are bounded by the broker's progress bound
(`run-on-host.md`, "The channel and the command", "`mill`"). A command that stalls after its
server or daemon is up — or a Maven command at any point — is silent until the agent gives up:
nothing bounds it, not the wrapper, not the
broker, whose writers die only with their requester, and not the shim, which reads output to EOF.
One form would, and it waits on a measurement:

- [ ] Generic, in the broker: no output for N seconds ends the command through the same SIGTERM,
  so the command's logs are kept, with a stderr line naming the bound and the host command log.
  - Silence is measured where the command's bytes are read, and time the pump spends blocked on a
    slow requester does not count.
  - N must exceed a healthy silence — a module compiling, a large download, which the proxy logs
    once at its start, a slow test — because a value below one is not a one-off failure: the rerun
    hits the same silence, and the project cannot build on the host until the constant changes.
  - Five minutes is the smallest value defensible without measurement.

A time-to-first-output limit would miss stalls after the JVM prints its `_JAVA_OPTIONS` banner.

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
dispatch, fenced thus:

- one lock covers the broker's runtime state;
- a request takes it, marks the runtime busy and cancels its pending expiry before the command
  receives the runtime, and re-arms the expiry when the command ends;
- each re-arming increments an idle generation kept with the runtime;
- an expiry carries the generation it was armed with and, under the lock, retires the runtime
  only if that instance is idle and its generation is still the expiry's own — so a cancelled
  callback that had left its sleep before a request re-armed the timer does nothing, and a timer
  outliving a retired runtime is a no-op on its replacement.

Its tests: a request arriving as the timer fires, that late callback, and a stale timer after
replacement, each leaving one consistent runtime.

## The project mounted at its own path

- [ ] Run `sbt "testWithPodman *MountPathTest"` on Linux; all Linux cases must pass.
- [ ] On Windows, run the launcher inside a WSL distribution — as a Linux program, with Java and
  rootless podman installed there — from `/mnt/c/Users/<me>/src/app`: `bash -c pwd` must print
  that path, the one a PowerShell launch of the same directory prints.

Recorded macOS results (2026-09-18):

- `MountPathTest`, `WorkspaceGuardOffTest`, `MountLifecycleTest` and the run-on-host gate pass.
- `sbt testFull` inside a session passes in every suite except `ClipboardBrokerTest` and
  `SandboxLifecycleTest`; those two pass when run alone on Linux.
- The four agents start without a trust prompt on fresh and used volumes.
- A host build's error reports a path accessible inside the session.

Recorded Windows results (Windows Server 2025, 10.0.26100.32522, podman 6.1.0; 2026-09-19):

- A launch from PowerShell in `C:\Users\<me>\src\app` mounts the filter at
  `/mnt/c/Users/<me>/src/app`, and `bash -c pwd` prints that path.
- A launch from PowerShell in `\\wsl.localhost\podman-machine-default\home\user\<dir>` is
  refused with `error: cannot map ... into the podman machine`, before any `workspace:` line.
- A first launch of a new project prepares the image's JDK (`JdkTrust.prepareScript` through
  `HostCommands.quoteFreeSh`) and reaches a shell.
- Under `KO_AGENT_SANDBOX_CLIPBOARD=paste`, `xclip -selection clipboard -t image/png -o` in the
  session reads a copied image, 15498 bytes, through both wrapped clipboard execs.

## Deferred — readable session directory names under `--run-on-host`

- [ ] Name the sessions `broker-<random>` and `command-<random>` instead of `b<random>` and
  `s<random>` (`RunOnHostSession.Kind`), once the path length allows it.
  - The session's `tmp/` hosts sbt's boot socket, and `RunOnHostPrereqs.SessionTmpMaxLength`
    leaves that path 53 characters, of which the root and Java's 20-digit temp-directory name
    take 51.
  - Either sbt's boot socket comes to need fewer than its 50 characters past the directory
    (`sbt-issues.md`, the thin-client entry — its fix as requested only turns the crash into a
    message, and lifts no length), or the session names get a shorter random part of their own,
    with the collision retry `Files.createTempDirectory` does today.
- [ ] Name the root after the launcher and the feature,
  `/private/tmp/ko-agent-sandbox-run-on-host-<uid>` in place of `/private/tmp/ko-agent-<uid>`
  (`RunOnHostSession.root`), under the same budget: a second host feature keeping state under
  `/private/tmp` would otherwise land in a root that names neither.

## Deferred — the per-command wrapper process under `--run-on-host`

- [ ] Re-evaluate the wrapper, the `--run-command-on-host` process the broker starts for each
  request (`RunOnHostSandbox.runCommandMain`; `run-on-host.md`, "The channel and the command").
  - What it buys:
    - the broker's cancel is a SIGTERM to one process, answered by that process's shutdown hook,
      which ends exactly the command's groups and directory;
    - a command's death, however it dies, is confined to its own process and never takes the
      broker and its warm servers with it;
    - the gate drives one command's whole lifecycle as `RunOnHost` with no broker, which is how
      the wrapper rows measure the profile.
  - What it costs:
    - one more JVM start per command, about a third of a second in the jar form and tens of
      milliseconds as the native image;
    - a second code path for the command's runtime, the wrapper's own under Maven.
  - The alternative is the same work in a broker thread with cancellation done by hand; decide
    with the measured cost per command and what the gate would drive instead.

## Deferred — the native-image launcher

A GraalVM (JDK 25) native image, with `native-image` and a C toolchain, starts in tens of
milliseconds where `java -jar` takes ~350 ms. The launcher branches on running as an image
(`RunOnHostSandbox.isNativeImage`: the wrapper's self-invocation, its launch file, the Seatbelt
proxy inputs) and stays resident when GraalVM refuses the FFM execvp (`SandboxLifecycle.handOver`).
No build or test exercises any of it, and the proxy as an image does not start under its profile
(macOS 26.4.1, GraalVM CE 25.0.2, `run-on-host-profile-iterate.sh mach-proxy <binary>`):
`Fatal error: CSunMiscSignal.open() failed`. What the profile lacks for it is unmeasured, and so
are the image's Mach services, which the same mode measures once it starts.

    sbt dist
    cd target/dist
    eval $(cs java --jvm graalvm-community:25 --env)
    export PATH="$JAVA_HOME/bin:$PATH"
    native-image --enable-native-access=ALL-UNNAMED \
      --add-exports=java.base/sun.security.x509=ALL-UNNAMED \
      --add-exports=java.base/sun.security.util=ALL-UNNAMED \
      -H:IncludeResources='sandbox-build/.*|defaults/.*|agentsandbox/.*' \
      -o ko-agent-sandbox -jar ko-agent-sandbox.jar

- [ ] Build the binary in CI and run the launcher suite as the binary, on both shipping
  architectures; only then does the README offer it. build.sbt's comments explain the two exports
  and the resource includes the command carries.
- [ ] Decide it together with the published identity: whether the binary is a release artifact at
  all, or `java -jar` and a Coursier command are the two forms.

## Before the first release — continuous integration

There is no CI. [README.md](../README.md#development) gives the launcher, proxy and filter
test commands. `--self-test` runs the filter suites on demand. A user's `--build` instead performs
the gates whose answers belong to that artifact and machine: `cargo deny check licenses bans
sources`, compilation, binary identity, and the installed filter's mount self-test.

- [ ] Add CI for the launcher's and proxy's `sbt testFull`, and the filter's pure and binary suites
  on both shipping architectures. Add `cargo deny check advisories` there: `deny.toml` records why
  its moving external database must not gate installation.
- [ ] Keep the artifact-local gates above in `--build`, and keep the mounted filter suites in
  `--self-test`; CI does not prove the filter on a user's own machine.

## Before the first release — the published identity

- [ ] One decision that must settle several names together:
  - the jar's artifact name and publication coordinates;
  - the Scala package names (`agentsandbox.*`, containing neither the `ko-` prefix nor an
    organization);
  - the image label key (`ko-agent-sandbox.bundle` — OCI convention wants a reverse-DNS key, and
    the right prefix is this same identity, so deciding the key alone would decide the identity by
    accident).

  Until then a changed key ends in the "rebuild with --build" refusal, so the exposure is bounded.
