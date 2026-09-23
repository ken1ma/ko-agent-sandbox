# TODO

Remaining work that adds real security or maintainability for the actual threat model, and ideas
whose benefit is uncertain, each with the condition that decides whether to build it. An idea
examined and found without benefit is recorded in design.md with its reason, so it is not proposed
again.

## Codex review plugin (`ko-review.md`)

- [ ] A linked worktree whose main Git directory is mounted read-only: Codex's own `git` commands
  and the helper's digest against that tree; unverified.
- [ ] `--egress=deny-unless-model claude` fails the review with `CODEX_EGRESS_DENIED` before Codex
  runs; unverified in a session.
- A regression test for a fix in this plugin is run against the helper without the fix and shown
  to fail before it counts: a fake reviewer that dies on its own once the helper exits lets a test
  for an orphaned reviewer pass without the fix, and only that run shows it.
- Watch openai/codex-plugin-cc (#557 persists review threads, open as of 2026-09-23) and
  openai/codex #24833 (durable MCP resume). If OpenAI ships a stateful review, fix, re-review
  primitive, delete the helper's orchestration rather than maintain a duplicate.

## Credential brokering — its two plans, in order

- [ ] `plan-credential-broker-proxy.md` whole, through its acceptance checklist.
- [ ] Real sessions on it before `plan-provider-credential-proxy.md`, whose steps are taken one
  at a time, each on a use case those sessions produced, never as the broker's automatic second
  half: what that plan adds — storage, generations, refresh, removal — is where the field
  failures are (docker/sbx-releases #492, a removed credential still injected after a restart),
  and none of it is needed for a per-run static value.
- AWS is in neither: the broker plan's "Deliberate exclusions" has why, and what a session
  forwards instead.
- [ ] Refuse a credential that is not the session's at a model host (SECURITY.md, "Exfiltration
  through allowed network traffic", has the attack). An exception to the order above: its use
  case came from a review of the documents, not from a session on the broker. A target of
  a service definition gains a property, `require-placeholder`: on a mediated target carrying it,
  a request is forwarded only if one authentication form the target declares holds this run's
  placeholder and no other declared form is present; any other request is refused with a fixed
  reason and a `deny` audit line, at every path.
  - The target declares every form the provider accepts, not only the one the client sends: a
    request without the client's header is not thereby unauthenticated. Anthropic accepts an API
    key as `Authorization: Bearer` and as `x-api-key`
    (https://platform.claude.com/docs/en/manage-claude/authentication), so checking one header
    does not exclude a foreign key in the other. The tests send a foreign key in each declared form,
    alone and beside the placeholder. A form the provider adds later reopens the attack until the
    catalog declares it.
  - It needs a selected service instance, so provider plan delivery steps 1, 2 and 5: the
    catalog, storage with per-run generations for a static key, the mediated overlay and one
    API-key client. It needs neither executable sources and refresh (step 4) nor OAuth (step 6).
    An `--env=NAME@HOST` binding does not carry it: that plan keeps the binding separate from a
    selected service, and a binding forwards a token that is not a placeholder and names one
    header, so it cannot refuse the placeholder beside a foreign key in another declared form.
  - It protects an API-key session only. A subscription login stays a tunnel until step 6.
  - A project that tests against the provider with its own key selects no credential for that
    host, or accepts the refusal; forwarding a token that is not a placeholder stays the rule at
    every other host (broker plan, "Substitution").
  - Measure first, with the model host inspected at the root: the hosts and paths the installed
    `claude` calls, login and refresh included; that a long server-sent-event stream survives the
    one-request-per-connection relay; that `claude` trusts `NODE_EXTRA_CA_CERTS` on every
    connection to the provider.
  - Rejected: exact-path grants on the model host without mediation (`/v1/messages` alone). The
    path list is the per-release contract with the CLI the broker plan declines, and a
    retrievable-storage behavior added at an allowed endpoint reopens the attack. Rejecting it
    gives up path-based protection for a subscription session before step 6: exact-path grants
    refuse the storage endpoints whatever credential is sent.
  - Codex: taking this to the OpenAI hosts needs one `codex` turn to succeed with those hosts
    inspected, read from `--proxy-log` (broker plan, "Claude Code and Codex logins: excluded",
    has what is measured), and a second turn in the same session, to learn whether the refused
    upgrades recur per turn. If they do, measure whether a custom `[model_providers.NAME]` with
    `supports_websockets = false` accepts the ChatGPT login; the built-in provider cannot be
    overridden (`doc/design.md`, "No WebSocket in the inspected relay").

## IDE integration through VS Code's Agent Host

- [ ] `plan-ide-integration.md`, in its steps: attach VS Code to a `code agent host` in the
  sandbox, then the hostile-host test that decides where enforcement lives, then one harness,
  then `--protocol=ahp`. ACP is deferred; the plan keeps its reviewed design and the conditions
  that reopen it.

## Deferred — refuse user namespaces under `NESTING=none`

- [ ] A launcher-owned seccomp profile for `NESTING=none` that refuses a user namespace, only if
  a kernel vulnerability reachable from an unprivileged user namespace enters the threat model.
  Measured in a default session (2026-09-22): `unshare -Ur true` returns 0, so the
  containers-common default profile allows it; `io_uring_setup` returns `ENOSYS`, so that
  interface needs no rule.
  - Two rules, not one: `clone` and `unshare` carry their flags in a register, so the filter
    refuses `CLONE_NEWUSER` and passes the rest. `clone3` carries them in a `struct clone_args`
    the filter cannot read (a seccomp filter sees register values only,
    https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html), and it reaches the
    kernel here (`EINVAL` on a zero-size argument), so the profile answers every `clone3` with
    `ENOSYS`. That refuses each caller without a fallback to `clone`; measure that the image's
    libc, Node, the JVM, Python and each installed agent still spawn processes under the profile.
  - SECURITY.md, "Container, runtime and kernel escape", answers a kernel exploit with a stronger
    isolation layer, "not more flags here". This profile claims no containment of a running
    exploit; it removes a kernel interface. Adopt it only after measurements confirm that no
    installed agent, as the image configures it, creates a user namespace, and record that
    distinction in that paragraph. `same-uid` keeps the default profile: rootless podman inside
    the session creates user namespaces.
  - Cost: every unprivileged `bwrap` call fails at its first step. In this image `bwrap`
    (bubblewrap 0.12.0) with `--unshare-user`, bind mounts and a tmpfs works today; `--proc` and
    `--dev` fail with `Permission denied` (a fresh `/proc` under podman's masked entries, and
    devpts). Claude Code's Bash-command sandbox is off in the managed settings and Codex runs
    `danger-full-access` (`container/ko-agent-sandbox/Containerfile` has the reasons), so
    neither calls it as configured. `agy` 1.2.7 in print mode runs a shell command in the
    session's own user, pid and mount namespaces (the command's `/proc/self/ns/*` inodes equal
    the session shell's; measured 2026-09-22). Measure `kiro-cli`, `copilot` and `opencode` the
    same way, and whether Chromium's own sandbox (Playwright) then needs `--no-sandbox`. A
    project's own bubblewrap or `unshare -Ur` step fails with `Operation not permitted`, so the
    container instructions name the refusal.
  - Derive the profile from the installed containers-common default at `--build`, and test that
    it differs only in the added rules; a copied profile drifts on a podman upgrade. The podman
    server, not the launcher, reads the profile file, so on macOS and Windows it must sit under a
    host share the machine mounts; the launcher's state root is under one today, since the
    server resolves the audit log's bind at a path there. It joins the session's `createCommand`
    beside `--cap-drop=ALL` on the branch that skips it for `same-uid` (`nestedArgs`), not the
    proxy container's. Ship the loosening in the same change: a variable in the
    `KO_AGENT_SANDBOX_NESTING` style, exported into the session and printed every session as the
    nesting loosening is, so the first `Operation not permitted` has its switch. Measure the
    `clone3` fallback before any of this: a runtime without one ends the item.

## Deferred — executable agent configuration in the persistent volume

- [ ] `plan-executable-agent-configuration.md`, in its two phases: reconciliation of the keys
  that name a program a later session starts without a tool call, then unwritable code
  directories. Phase 2 waits for each agent's measurement on a refused write, which the plan
  names.

## Deferred — a release-age window in the other package managers

SECURITY.md, "The supply chain", has npm's seven-day window and why uv gets none.

- [ ] The same window for `cs`, Maven, Gradle and Cargo, each only if the manager offers a
  resolution-time setting that its lockfile does not record. Whether any of them does is not
  yet looked up.
- [ ] npm's `ignore-scripts`, only after measuring that the commands the image's agents and the
  common `npx` targets install still work with lifecycle scripts skipped: installation can
  succeed while leaving a package unusable because a required lifecycle script was skipped
  (https://docs.npmjs.com/cli/v11/using-npm/config/#ignore-scripts). An explicit `npm run` still
  runs its script.

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

## Deferred — writable git from a linked worktree

A launch from a linked worktree binds the main worktree's Git directory read-only
(`SECURITY.md`, "The host's git executing what the sandbox wrote"). The writable form binds the
`.git` of the main project's filter mount at the same target, so the filter's policy governs it:
`worktrees/<name>` is a nested gitdir there, whose `config`, `hooks/`, `commondir` and `gitdir`
stay frozen while its index and refs are written (`../fuse/ko-agent-fs/doc/git-metadata.md`, "The
immutable set"). Only `.git` crosses; the main worktree's working files stay out of the session.

- The linked session joins the main project's daemon as one of its sessions: its marker under the
  main project's mount directory, so that the reap counts it, and the mount-time guard run on the
  main root (`KoAgentFs`).
- `--reset` in the main worktree unmounts that filter, and every linked session's git then fails
  with `ENOTCONN`. Either record it beside the volume's behaviour (`SECURITY.md`, "What the
  persistent volume holds") or refuse the reset while a linked session mounts it, as podman
  refuses the volume.
- Unverified: a bind of a subpath of the FUSE mount keeps the filter's positional classification.
  Lookups name the parent inode, so it should; the mounted suite proves it before the bind is
  offered.
- The mount-path probe already asks about the target. The SELinux label question disappears: the
  filter's mountpoint needs no relabel.

## Deferred — a linked worktree's absolute pointer on Windows

`git worktree add` writes the pointer as `C:/Users/<me>/repo/.git/worktrees/<name>`, which the
container's git cannot follow at `/mnt/c/...`, so the read-only bind is skipped there
(`SandboxProject.linkedGitdirBind`). Two routes:

- A relative pointer resolves under `/mnt/c` as it does under `C:`, and the bind serves one. But
  `git worktree add --relative-paths`, or `git worktree repair --relative-paths` for an existing
  worktree (git 2.48 or later), also sets `extensions.relativeWorktrees`, and the image's git,
  Debian trixie's 2.47.3, refuses a repository with an extension it does not know — in the main
  worktree as in the linked one. The launch reads the extension from the common config and keeps
  the no-git warning, with a note, rather than promise git (`SandboxProject.setsRelativeWorktrees`).
  The route opens when the image's git is 2.48 or later, and that check goes with the upgrade;
  until then only a hand-written relative pointer works, which `git worktree repair` rewrites
  absolute. "The project mounted at its own path" has the measurement.
- For an absolute pointer, bind a launcher-written pointer file naming the `/mnt/<drive>` spelling
  over `<mountPath>/.git`, hiding the filter's protected pointer from the container alone. Setting
  `GIT_DIR` and `GIT_WORK_TREE` instead would redirect git in every other repository the agent
  uses, such as clones under `~`. `<main>/.git/worktrees/<name>/gitdir` keeps the `C:/` spelling
  either way; `git worktree list` reads it, and nothing the read-only bind serves needs it.

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
    `cacerts`, and `ko-sandbox-jdk-use-proxy`'s certificate.
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
- [ ] The row that needs `--run-on-host`: a command through the channel, then `target/` read back
  from the container — a host-native build turns host writes from an occasional human edit into
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

## Deferred — read grants a user adds to a host command's profile

The `curl` that macOS ships does not run under a command's profile: LibreSSL stops at
`fopen('/private/etc/ssl/openssl.cnf')`, `Operation not permitted` (`run-on-host.md`, "The
command's lifetime and environment"). The launcher grants a system path only where a build
measurably needs it (`SeatbeltProfile.SystemPaths.txt`), and no build here runs `curl`.

- [ ] A way for a user to add a read grant, only once a build of theirs needs such a program:
  `/private/etc/ssl/openssl.cnf` is the first case.
  - Where the grant is stated decides who can widen a profile. A file under
    `.ko-agent-sandbox/run-on-host/` arrives with the repository, as the program's rule file does,
    so the launch prints it as it prints that file's hosts; a launch option is the user's alone.
  - Reads of single files, never a write, an exec or a directory, and refused for a path under
    the user's home: what a host command cannot read there is its confinement.
  - Measure, before the form is chosen, that `curl` fetches from an allowed host with that one
    file granted: the acceptance test's "CA bundle variables" rows print what it does, and
    whether it then reads `CURL_CA_BUNDLE` or `SSL_CERT_FILE`.

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

## Deferred — a container mill or gradle beside the host's daemon

Under `--run-on-host` the host's mill daemon keeps its lock and `socketPort` in the project's
`out/mill-daemon`, and a `./mill` run in the container without `MILL_OUTPUT_DIR` uses the same
`out/`. The rules allow the bootstrap's downloads by default, so an agent can run it.

- [ ] Measure, on a small mill build with a host daemon up: what the container's `./mill` does
  with the host's lock and port, and what the host's next command does with what the container
  left.
  - The same run gives a cold compile with and without `MILL_OUTPUT_DIR` under `~/.cache`, which
    `fuse/ko-agent-fs/doc/troubleshooting.md` ("Everything works but slowly") says is not measured.
  - If the two conflict, the run-on-host text the launcher appends is the place to tell an agent
    to set the variable.
- [ ] The same conflict for gradle. The two sides' daemon registries are separate — the host's
  is under the broker's temporary directory (`RunOnHostSandbox.gradleCommand`), the container's
  in its gradle user home — but both builds use the project's `build/` and the locks under its
  `.gradle/`, and the rules allow `./gradlew`'s download by default.

## Deferred — an idle bound for the sbt server

The broker's sbt server has no idle bound of the broker's: it lives until the launch ends,
`ko-sandbox-run-on-host sbt shutdown`, or sbt's own `serverIdleTimeout`, seven days
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
- [ ] On Windows, from a linked worktree whose `.git` holds a relative pointer (hand-written until
  the image's git reads `extensions.relativeWorktrees`): the launch must print `git is read-only
  in this session`, `git status` must work in the session, and `git add` must fail.

Recorded macOS results (2026-09-18):

- `MountPathTest`, `MountLifecycleTest` and the run-on-host acceptance test pass.
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
    (`upstream-issues.md`, the thin-client entry — its fix as requested only turns the crash into a
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
    - the acceptance test drives one command's whole lifecycle as `RunOnHost` with no broker, which
      is how the wrapper rows measure the profile.
  - What it costs:
    - one more JVM start per command, about a third of a second in the jar form and tens of
      milliseconds as the native image;
    - a second code path for the command's runtime, the wrapper's own under Maven.
  - The alternative is the same work in a broker thread with cancellation done by hand; decide
    with the measured cost per command and what the acceptance test would drive instead.

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

There is no CI. [development.md](development.md#tests) gives the launcher, proxy and filter
test commands. `--self-test` runs the filter suites on demand. A user's `--build` instead performs
the checks whose results depend on that artifact and machine: `cargo deny check licenses bans
sources`, compilation, binary identity, and the installed filter's mount self-test.

- [ ] Add CI for the launcher's and proxy's `sbt testFull`, and the filter's pure and binary suites
  on both shipping architectures. Add `cargo deny check advisories` there: `deny.toml` records why
  its moving external database must not block installation.
- [ ] Keep the checks above in `--build`, and keep the mounted filter suites in
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
