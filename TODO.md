# TODO

Remaining work that buys real security or maintainability for the actual threat model. Ideas without
a concrete gain live under **Non-TODOs** so they stop resurfacing.

## P1 — Add black-box security integration tests

The existing launcher and proxy unit tests cover many trust-critical pure functions. What is still
missing is proof that the **effective Podman topology, mounts, and runtime behavior** have the
properties the source code intends.

Add an integration/security test mode that starts real containers with the launcher and attacks the
boundary from inside them.

### Network boundary

- [ ] Removing/unsetting `HTTP_PROXY` / `HTTPS_PROXY` inside the sandbox does not
  restore Internet access.
- [ ] Direct TCP connections to public IP addresses do not bypass the proxy.
- [ ] External DNS resolution from the sandbox fails; the proxy remains the component
  that resolves destination names.
- [ ] DNS exfiltration attempts fail, including queries whose labels encode arbitrary
  payload data.
- [ ] Unknown hosts are refused by the proxy.
- [ ] Private, loopback, link-local, metadata-service, documentation, benchmark,
  multicast, and other non-public destinations remain unreachable through the proxy.
- [ ] The sandbox can reach its own egress proxy but cannot reach another session's
  or another project's sandbox-side or egress-side resources.
- [ ] Plain HTTP and arbitrary proxy methods fail closed.
- [ ] A run's networks are created by that launch and removed when its sandbox
  exits, on both the reaper and the resident paths; a crashed run's networks are
  swept by `--reset`.

This is worth testing even though the topology is intentionally restrictive. Prior art has had real
regressions where a network-sandbox option intended for one purpose accidentally reopened arbitrary
outbound traffic, and where DNS remained an exfiltration path despite network restrictions.

Relevant issues:

- Anthropic Sandbox Runtime #225:
  https://github.com/anthropic-experimental/sandbox-runtime/issues/225
- Anthropic Sandbox Runtime #88: https://github.com/anthropic-experimental/sandbox-runtime/issues/88

### Forge policy

Use real HTTPS/Git traffic where practical so these tests cross the TLS and container boundaries
rather than re-testing only parser helpers.

- [ ] Anonymous public `git clone` / `git fetch` succeeds for an inspected forge.
- [ ] `git push` fails at the proxy.
- [ ] An arbitrary forge `POST` fails.
- [ ] The proxy's upstream leg refuses a server presenting an untrusted or wrong-name certificate.
  Inspection moves origin verification from the client to the proxy, and skipping it is invisible
  in normal operation — the classic TLS-interception failure.
- [ ] A forge `GET` / `HEAD` succeeds.
- [ ] GitHub GraphQL remains refused.
- [ ] Git LFS batch access remains refused unless download-only LFS support is
  deliberately implemented later.

### Filesystem and credential boundary

- [ ] `/workspace` is writable.
- [ ] `/workspace/.git/config` is read-only and cannot be replaced from inside.
- [ ] `/workspace/.git/hooks` is read-only and cannot be replaced from inside.
- [ ] An absent or pointer-file `.git` has the intended read-only behavior.
- [ ] `/workspace/.ko-agent-sandbox` is read-only and cannot be replaced from inside.
- [ ] Host `~/.ssh`, `~/.aws`, `~/.config`, container-engine sockets, and unrelated
  host paths are absent.
- [ ] The project CA private key is absent from both sandbox and proxy containers.
- [ ] The proxy receives only the leaf certificate/private key needed for inspected
  hosts.

### Nested read-only mount stability under host-side mutation

The `.git/config` and `.git/hooks` protections are nested read-only mounts inside the writable
`/workspace` bind mount. That is a sensible design, but a directly analogous failure has been
reported in Docker Sandboxes: after host-side mutation, a nested read-only mount can disappear and
access can fall through to the writable parent.

There is currently **no evidence that Podman has the same bug**. Treat this as an
assurance/regression test, not as a known vulnerability.

- [ ] Start a sandbox and verify `.git/config` and `.git/hooks` are read-only.
- [ ] While the sandbox remains running, mutate `.git/config` from the host:
  - edit it in place;
  - atomically replace it;
  - rename it and create a replacement.
- [ ] After each mutation, verify from inside the sandbox that:
  - the expected file remains visible;
  - write/truncate/delete/rename/replacement attempts still fail;
  - the nested read-only mount has not disappeared.
- [ ] While the sandbox remains running, mutate `.git/hooks` from the host:
  - create/remove/rename files below it;
  - rename the directory and recreate it where the host filesystem permits.
- [ ] Re-run the same read-only assertions after each operation.
- [ ] Include ordinary host Git operations that may rewrite relevant Git metadata.
- [ ] Run the regression on every supported host family where practical:
  - Linux rootless Podman;
  - macOS Podman Machine;
  - Windows/Podman environment if supported.

Relevant prior art:

- Docker Sandboxes #388: https://github.com/docker/sbx-releases/issues/388

### Effective runtime hardening

Inspect or probe the running containers. Do not limit these tests to checking that
`AgentSandboxLauncher.scala` generated the expected command-line strings.

For the sandbox, verify at least:

- [ ] non-root UID/GID and rootless Podman assumptions;
- [ ] all Linux capabilities dropped;
- [ ] `no-new-privileges`;
- [ ] read-only root filesystem;
- [ ] only the intended writable mounts/tmpfs;
- [ ] PID limit;
- [ ] memory limit when `KO_AGENT_SANDBOX_MEMORY` is supplied;
- [ ] only the intended project-internal network;
- [ ] no inherited host proxy configuration beyond the explicitly supplied sandbox
  proxy variables.

For the egress proxy, verify at least:

- [ ] all capabilities dropped;
- [ ] `no-new-privileges`;
- [ ] read-only root filesystem;
- [ ] only the intended project-specific networks;
- [ ] only the current run's leaf key/certificate and audit-log file are mounted;
- [ ] the CA private key and previous runs' logs are not mounted.

The important invariant is:

> Test the resulting boundary, not merely the code that asks Podman to create it.

This guards against future Podman, Netavark/Aardvark, OS, JVM, and launcher changes that preserve
command syntax while changing effective behavior.

## P1 — Add hostile-input/property testing around proxy parsers

`AgentEgressProxyTest.scala` already covers a substantial set of important cases, including:

- hostname case normalization and a trailing dot;
- IDN → ASCII conversion;
- alternate IPv4 literal spellings;
- IPv4/IPv6 public-address classification;
- CONNECT method/port/allowlist checks;
- bounded HTTP headers;
- fragmented/truncated TLS ClientHello;
- ECH detection;
- CONNECT hostname ↔ SNI binding;
- forge Host-header checks;
- origin-form-only inspected requests;
- HTTP Upgrade rejection;
- `Content-Length` / `Transfer-Encoding` ambiguity;
- forge method/path rules.

Keep those tests. Add a second layer aimed at **parser disagreement, canonicalization bugs, and
fail-open policy parsing**, rather than duplicating existing examples.

### Host/authority regression corpus

- [ ] Build a permanent hostile authority/hostname corpus including:
  - malformed bracket/port combinations;
  - control/whitespace characters;
  - IPv4-mapped IPv6;
  - zone identifiers;
  - Unicode/IDNA edge cases;
  - unusual but syntactically accepted authority forms;
  - forms accepted by one Java/network parser but not another.

The two historical Smokescreen bypasses are already permanent regression inputs — the bracketed
hostname (GHSA-qwrf-gfpj-qvj6) and the trailing-dot / letter-case forms (GHSA-gcj7-j438-hjj2) — in
`AgentEgressProxyTest.scala` ("Smokescreen-class canonicalization tricks reach no non-allowed host"
and "an allowed host authorizes to one canonical form however it is spelled"). What remains open
above is the wider corpus, not those two.

### Property/randomized tests

- [ ] Add property/randomized tests for the main parser boundaries.

Useful invariants:

- normalization is idempotent;
- an authorized target is a canonical hostname, never an IP literal;
- malformed/ambiguous authority syntax fails closed;
- parser input is bounded;
- malformed input results in a controlled refusal, not an unexpected parser exception or unbounded
  read;
- the hostname checked by policy is the same hostname later bound to DNS/SNI;
- an inspected HTTP request has exactly one unambiguous message boundary.

Do not add fuzzing because "fuzzing is good"; keep it focused on places where two layers may
interpret the same bytes differently.

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
channel — however narrow — should exist for a convenience. Two constraints on any implementation:
command builders must take the podman path as a parameter, never read the global (the global fails
fast on podman-less machines and kills the test JVM); and Scala 3 lambdas cannot early-`return`
under `-Werror`.


## Non-TODOs / deliberate design choices

These ideas were reviewed against broader prior art and relevant issue histories. Do not implement
them without a new requirement.

### No general capability broker

The current architecture deliberately avoids most cases in which a broker is useful by keeping
valuable credentials outside the sandbox.

A capability layer would create a second security-policy language and another enforcement surface
while providing little reduction in authority under the current operating model. Prior art proposing
exactly this shape — a host-side MCP auth broker/gateway holding credentials the agent container
never sees — solves a real problem for workflows that need credentialed MCP servers, a requirement
this project's operating model deliberately avoids:

- https://github.com/mattolson/agent-sandbox/issues/122

### No per-repository `GitRead(repository)` policy

Public repository discovery/read access is useful. There is no private forge credential in the
sandbox whose authority needs to be attenuated, and forge writes are already blocked at the protocol
boundary.

### No Git/SSH/cloud credential injection into the proxy

Private/privileged operations happen on the host. Credential injection becomes worth considering
only if that operating model changes.

### No generic "GET is safe, POST is dangerous" rule

A URL is outbound information. For example:

```text
GET https://allowed.example/<encoded-project-secret>
```

is a write from an information-flow perspective.

### No general HTTP method/path policy language

Keep protocol-specific inspection only where it buys a concrete property, as it does for forge reads
versus writes. Do not turn the proxy into a general-purpose policy engine without concrete use cases
that outgrow the current model.

### No command-name safe lists

`git`, `npm`, `python`, build tools, MCP servers, and other "normal" programs can execute
repository-controlled behavior. The outer container/network boundary should contain them all instead
of trying to classify command names as safe.

### No per-project agent-instruction override in `.ko-agent-sandbox`

Style and workflow instructions already have a native per-project channel every agent reads with no
launcher help: the project's own CLAUDE.md / AGENTS.md / GEMINI.md in the workspace, committed and
reviewed like any other file. `.ko-agent-sandbox` is mounted read-only because its content governs
the boundary — a session must not write the egress policy governing the next one — and prose
instructions govern nothing enforceable, so the ceremony would protect nothing a hostile repo cannot
already do through any file in the checkout. The image-side AGENTS.md admits only what a project
cannot know about itself (the environment, SANDBOX.md) or must not be trusted to declare (the
policy in force, appended at launch); the operator changes its defaults by editing SANDBOX.md or
STYLE.md and rebuilding.

### No richer egress-policy format

The policy stays a whole-list replacement or a `+host` / `-host` / `-**.domain` delta against the
built-in list — no fields, no globs beyond the one removal subtree, no precedence, no deny list.
SECURITY.md ("Adding hosts, not patterns") carries the reasoning; `resolvePolicy` enforces it,
tested rule by rule. The failure classes it keeps out — a validator and a runtime reading one
configuration differently, and an allow silently overriding a deny — are well attested:

- https://github.com/docker/sbx-releases/issues/410
- https://github.com/anthropic-experimental/sandbox-runtime/issues/434
- https://github.com/anthropic-experimental/sandbox-runtime/issues/122
- https://github.com/anthropic-experimental/sandbox-runtime/issues/154
- https://github.com/anthropic-experimental/sandbox-runtime/issues/432
- https://github.com/stripe/smokescreen/issues/236

Do not add wildcard additions, a deny list, ranked rules, or a richer removal-pattern language
without a concrete need that outweighs that surface.

### No PATH-resolved host executables

Resolved, not pending: the launcher resolves `podman` (and `selinuxenabled`) to an absolute path
through absolute `PATH` entries only — `HostCommands.findOnPath` — and the reaper receives
that path as an argument, so no host-side invocation consults `PATH` or, on Windows, CreateProcess's
implicit current-directory search. The launcher is started inside the repository being sandboxed, so
its working directory is untrusted by definition; a `podman.exe` shipped in a checkout must never be
what executes on the host. Prior art:

- https://github.com/docker/sbx-releases/issues/392

### No following symlinks at sandbox setup

A symlinked `.git`, `.git/config`, `.git/hooks`, `.ko-agent-sandbox` or `egress-hosts` refuses the
launch (`gitGuardVolumes`, `policyGuardVolume`, tested). Podman resolves mount sources on the host,
so mounting through a repository-controlled link would expose its target into the sandbox, and
following the link to pin its resolved target would make the pinned surface depend on where the link
points at launch time. The refusal is loud, names the path, and comes before the launcher creates
anything, so setup writes nothing through a pre-seeded link (tested: "a refused symlink shape leaves
no artifact through the link"); the project directory itself is `toRealPath()`-canonical before any
of this. Prior art for both failure shapes — a sandbox that crashed mid-setup on a symlink, and
setup code whose mount-target creation wrote through one to paths outside its root:

- https://github.com/anthropic-experimental/sandbox-runtime/issues/221
- https://github.com/bazelbuild/bazel/issues/28515

The cost is that a repository sharing hooks through a symlinked `.git/hooks` cannot be sandboxed
as-is; its user replaces the link with a real directory first. Accept that cost rather than
following links.

### No DLP/entropy/LLM firewall

It would be incomplete against encoding, timing, allowed-host selection, and protocol-specific
channels while adding false positives and another complex policy engine. Destination restriction
remains the primary exfiltration control.

### No gVisor/microVM migration yet

Rootless Podman is the chosen portability/security trade-off. Revisit only if
host-kernel/container-runtime exploitation enters the threat model.

The gVisor issue history also shows that stronger runtime isolation brings additional
rootless/nesting/mount compatibility complexity — e.g. rootless uid mapping breaking same-uid host
file access, the problem this launcher's `--userns=keep-id` solves. That does not make gVisor a bad
design; it means the additional boundary should be purchased only when the threat model requires it.

- https://gvisor.dev/
- https://github.com/google/gvisor/issues/9918

## Prior-art references worth retaining

Comparison points for future decisions, not dependencies. The specific issues that shaped a decision
are linked inline where that decision is recorded; these are the broader sources.

- Docker AI sandboxes — microVM isolation, direct-vs-clone workspace models:
  https://docs.docker.com/ai/sandboxes/ https://docs.docker.com/ai/sandboxes/security/isolation/
- Anthropic Claude Code — composed filesystem/network confinement, and its settings/credential
  model: https://www.anthropic.com/engineering/claude-code-sandboxing
  https://docs.anthropic.com/en/docs/claude-code/settings
- Stripe Smokescreen — mature egress-proxy prior art; the two ACL-bypass advisories are permanent
  regression inputs (see "Host/authority regression corpus"): https://github.com/stripe/smokescreen
  https://github.com/stripe/smokescreen/security/advisories/GHSA-qwrf-gfpj-qvj6
  https://github.com/stripe/smokescreen/security/advisories/GHSA-gcj7-j438-hjj2
- Bazel sandboxing/hermeticity — minimizing ambient inputs/outputs, testing effective boundaries:
  https://bazel.build/versions/9.1.0/docs/sandboxing
- Agent sandbox/proxy comparisons, including credential brokering:
  https://github.com/mattolson/agent-sandbox https://github.com/89luca89/clampdown

## Design principles to preserve

These are short enough to keep near the implementation as comments.

```text
Anything requiring valuable credentials happens outside the sandbox,
unless the agent fundamentally cannot function without those credentials.
```

```text
Repository-controlled execution stays inside the outer sandbox.
Do not create a host-side execution path merely to make an agent workflow easier.
```

```text
The writable workspace is untrusted output.
Protect implicit host execution paths, but keep ordinary project files writable
because editing them is the purpose of the sandbox.
```

```text
An allowed host is a possible recipient of sandbox data.
HTTP "read" semantics do not make the request an information-flow read.
```

```text
Prefer a small, observable boundary over a richer policy language.
Add policy machinery only when it removes authority the sandbox would otherwise
have to possess.
```

```text
Security configuration must fail closed.
Unknown, malformed, or ambiguously interpreted policy must not silently weaken the
effective boundary.
```
