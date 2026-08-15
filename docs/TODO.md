# TODO

Remaining work that buys real security or maintainability for the actual threat model. Ideas
without a concrete gain live in DESIGN.md as Non-TODOs so they stop resurfacing.

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

### Egress tier policy

Use real HTTPS/Git traffic where practical so these tests cross the TLS and container boundaries
rather than re-testing only parser helpers.

- [ ] Anonymous public `git clone` / `git fetch` succeeds for a `=git-fetch` host.
- [ ] `git push` fails at the proxy.
- [ ] An arbitrary `POST` to a `=git-fetch` host fails.
- [ ] The proxy's upstream leg refuses a server presenting an untrusted or wrong-name certificate.
  Inspection moves origin verification from the client to the proxy, and skipping it is invisible
  in normal operation — the classic TLS-interception failure.
- [ ] A `=git-fetch` host's `GET` / `HEAD` succeeds.
- [ ] GitHub GraphQL remains refused.
- [ ] Git LFS batch access remains refused unless download-only LFS support is
  deliberately implemented later.
- [ ] A read-only host serves a `GET` (a doc-site fetch; a registry pull end to end) and refuses a
  `POST`/`PUT` — `storage.googleapis.com` with a signed upload URL is the case the tier exists
  for.
- [ ] A read-write host (an agent endpoint) is still an opaque tunnel.
- [ ] A host a project adds to `egress-hosts/read-only` is inspected end to end: the leaf carries
  it, a `GET` succeeds, a `POST` fails.
- [ ] A project-tagged `+host=git-fetch` clones end to end.
- [ ] `npm install` gets its audit answer end to end (the `=npm-audit` allowance), and reports
  vulnerabilities for a package known to have them.
- [ ] A `blocked` `.defaults` lockdown still signs in: the agent endpoints re-added in
  `read-write`, everything else refused.
- [x] The relay enforces response framing: a truncated body is logged (`relay: …-byte response
  truncated…`) and the client end closed abortively; a zero-byte connection is an `error`, a
  half-sent header a `deny` (SECURITY.md, "The audit line grammar"). Unit-tested.
- [x] The relayed response head speaks this hop's own `Connection: close`, and the close is
  drained — HTTPHelper.toClientBytes has the RST mechanism; the symptom was apt's intermittent
  fetch EOFs with no proxy-side trace. Unit-tested. Verify after a rebuild: repeated fresh
  `install podman` runs are clean.
- [ ] Client-side keep-alive in the inspected relay, only if the per-request TLS handshake ever
  measurably hurts (a 104-archive install's 104 handshakes cost seconds today). Both legs'
  framing is parsed and enforced, so the shape is a request loop per client connection with a
  fresh upstream connection per request; the price is a larger state machine at the enforcement
  point and the one-request stance's smuggling argument re-argued in SECURITY.md.
- [x] The minted CA and leaf carry Subject/Authority Key Identifiers — strict verifiers
  (OpenSSL X509_STRICT, Python's default since 3.13) refuse a chain without them; the
  measurement is with mintLeaf. Unit-tested, the leaf AKI naming the CA's key id included. No
  migration: an identifier-less CA is rotated by hand — delete the project's tls state files
  and relaunch.

### Filesystem and credential boundary

- [ ] `/workspace` is writable.
- [ ] Default (filtered) session: no `.git` entry can be created at any depth; control state
  (`config`, `hooks/`, redirections, rebase todo) is immutable in every repository in the tree; a
  host-created repository appears live with the same control state frozen.
- [ ] Opted-out session (`KO_AGENT_SANDBOX_WORKSPACE_GUARD=none`), the rows below:
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

Scope: sessions opted out of the workspace filter (`KO_AGENT_SANDBOX_WORKSPACE_GUARD=none`) — the
default session's enforcement is the FUSE filter, which has no nested mounts to lose. In the
opted-out fallback, the `.git/config` and `.git/hooks` protections are nested read-only mounts
inside the writable `/workspace` bind mount. That is a sensible design, but a directly analogous
failure has been reported in Docker Sandboxes: after host-side mutation, a nested read-only mount
can disappear and
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

### Nested containers (KO_AGENT_SANDBOX_NESTING=same-uid)

The loosenings and their whys are SECURITY.md's "The opt-in, and its price"; the recipe, its
`utsns = "host"` hostname dodge and the image-compatibility rules are SANDBOX.md's "Containers
in here". Findings recorded only here: a newer inner podman would change nothing — 6.0.2's
vendored layer unpack (`chrootarchive`, moved to `go.podman.io/storage`) is logically identical
to 5.4.2's, and the deciding seccomp filter is the outer container's, compiled by the host
podman; Docker Hub and ECR Public moved their blob CDNs, and both successors are verified live
and built in.

Measured end to end in a same-uid session (podman-machine backend):

- [x] `docker.io/library/alpine` runs ("hello-from-alpine"); `public.ecr.aws` and `gcr.io` pulls
  work; `quay.io` is refused by the proxy. `unmask=ALL` suffices for the `/proc` mount (whether
  an enumerated `/proc/*` list would too stays unmeasured).
- [x] Distroless: the root variant runs (`java25-debian13 --version` prints Temurin 25.0.4);
  `:nonroot` bare is refused (`setresgid 65532` EINVAL); with `--user 0` it runs.
- [x] The designed failures fail: stock `postgres` and `nginx` die chowning to their service
  user (EINVAL); a `USER 65532` image builds (`USER` is metadata), is refused at run
  (`setresuid` EINVAL), and runs under `--user 0`.
- [x] `/dev/fuse` is unnecessary: the container rootfs mounts as kernel-native `overlay`, and
  the matrix passes with the fuse-overlayfs binary removed and again in a session launched
  without the device — `NestingLoosenings` holds three loosenings.
- [x] sandbox-apt-get refuses an install whose download failed instead of unpacking the partial
  set: apt's exit decides (through a log file — a pipeline reports its last stage), fetches
  retry, `update` runs under `APT::Update::Error-Mode=any`, and a failing run's apt output is
  kept as `install-failed.log`.

Open:

- [ ] A default session still fails closed. Today that should mean a pull dying at layer unpack
  (`chroot` seccomp-refused with no capability granted) before crun's `/proc` refusal is even
  reachable — yet the earliest default-session measurement reached crun, implying an unpack once
  succeeded under the same filter. Re-measure and explain.
- [ ] A narrower SELinux answer than `label=disable`: measure whether the machine's policy has a
  type that permits the nested `/proc` mount (`label=type:container_engine_t` is the candidate) —
  if it works, narrow `NestingLoosenings` and SECURITY.md's price.

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
  proxy variables;
- [ ] the bundle version lock end to end: a default-named image whose label mismatches this
  jar's digest (or predates the label) refuses the launch with the rebuild hint, and an
  explicitly overridden image only warns.

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
- inspected-host Host-header checks;
- the read-only tier (GET/HEAD only, no POST exception, tier-aware refusals);
- per-tier delta and blocked resolution (fail-closed refusals, `.defaults`, overlap, the
  closed tag set and its one-tagging override);
- origin-form-only inspected requests;
- HTTP Upgrade rejection;
- `Content-Length` / `Transfer-Encoding` ambiguity;
- response-framing enforcement (truncation detection, the no-body statuses, origin-fault
  refusals) and the unused-connection / half-sent-header split;
- the relay on loopback socket pairs: the hop-owned `Connection: close` on the wire, a pipelined
  straggler drained, mid-body truncation, `Expect: 100-continue`, 1xx forwarding;
- the `=git-fetch` and `=npm-audit` method/path rules.

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
