# Design decisions

What was decided and must not change silently:

- the words the documents share;
- the standing decisions, recorded so they stop being reopened;
- the properties verification has to separate;
- the prior art they were reviewed against;
- the principles to preserve.

What remains to do is TODO.md; the security model is SECURITY.md.

## Terminology

The words the documents share, each defined where it binds and listed here once:

- **sandbox** — the container the agent runs in, rootless, as `nonroot`; its boundary is the subject
  of SECURITY.md.
- **proxy** — the egress proxy, one per session in its own container, which every request of the
  session leaves through (`egress-proxy.md`).
  - Under `--run-on-host`, a host proxy beside it per program and build directory, kept across the
    launch's commands, or per command under Maven, with rules of its own: `deny defaults`, the
    program's Maven Central host, and the file `.ko-agent-sandbox/run-on-host/<program>/egress/rule`
    (`run-on-host.md`, "The command's egress proxy").
  - **rule, ruleset, profile** — a rule is a line of the project's `.ko-agent-sandbox/egress/rule`;
    the ruleset is what a launch enforces, the defaults, the profile and the file resolved together
    and printed at every start; a profile is one of the four `--egress=` treatments
    (`egress-proxy.md`). Under `--run-on-host` a profile is also a Seatbelt profile, the generated
    sandbox a host command runs under; each document names which it means.
  - **grant word** — what a rule permits at its URL: `tunnel`, `read`, `git-fetch`, `method=`
    (`egress-proxy.md`, "The rule file").
  - **listed host, unlisted host** — a host some rule names, and one none does; under
    `allow-unless-denied` an unlisted host holds an inspected `read` and nothing else.
  - **tunnel, inspected** — an allowed host's two treatments: application traffic left opaque after
    the TLS identity check, or TLS terminated and each request decided against its grants
    (SECURITY.md, "Reading without being able to write").
    - Use `tunnel` for the grant and host treatment in code and output.
    - Retain `opaque` when describing application traffic the proxy does not decrypt or inspect: a
      CONNECT tunnel can also carry inspected traffic, so the transport description needs that
      distinction.
- **boundary directory** — `.ko-agent-sandbox`, read on the host before launch and unwritable in
  every write mode (SECURITY.md, "Why the rules are per project, in the project, and read-only").
- **workspace filter** — `ko-agent-fs`, the FUSE mount the project is shared through, which refuses
  the Git entries and links a session must not write (`../fuse/ko-agent-fs/doc/architecture.md`).
- **launch** — one invocation of the launcher for one project, from its command line to the
  sandbox's end; the run and the session are its two views.
- **run** — the launch as the host sees it, the objects created for it:
  - the two networks and the proxy and sandbox containers, removed when it ends;
  - the `run-<suffix>` directory holding the CA leaf, swept by a later launch or a reset;
  - its audit log, written per run and kept.
- **session** — the same interval from inside: the agent's time in the sandbox container, what it
  can reach, and what outlives it — agent state kept across sessions, concurrent sessions of one
  project, what this session may do.
- **launcher** — the program run on the host, the jar or the native image built from it, which
  builds the images, creates a run's objects and keeps its state under the host's state directory
  ([README.md](../README.md#reference)).
- **reaper** — the detached shell the launcher spawns before it execs podman, which waits for the
  sandbox container to stop and then removes the proxy container and the networks the run created; a
  launch that stays resident, on Windows or after a failed spawn, removes them itself
  (`SandboxLifecycle.scala`).
- **broker** — a host process answering requests the sandbox makes through a FIFO under its `/tmp`,
  never a listener, and not the capability broker this document declines:
  - the clipboard broker (SECURITY.md, "Clipboard");
  - the run-on-host broker, one per session, which relays each host command and owns the processes
    it starts (`run-on-host.md`).
- **shim, wrapper, command** — under `--run-on-host`:
  - the shim is `sandbox-run-on-host` inside the sandbox, which sends one command to the broker;
  - the wrapper is the launcher process the broker spawns for it on the host, which runs the
    program under its Seatbelt profile;
  - a command session is the wrapper's own record of that one invocation, beside the broker's
    session for the launch (`run-on-host.md`, "The command's lifetime and environment").

## Standing design decisions

Each says what is fixed and why. A named revisit condition records the anticipated reason to
reopen it; otherwise reopening takes a new requirement, or evidence that an assumption or security
argument the decision rests on no longer holds. Nothing less reopens one.

### No richer rule format

The rules stay four fixed profiles over one file, `rule`, in the grammar `doc/egress-proxy.md`
spells out:

- `allow` and `deny` lines naming URLs;
- four grant words;
- no pattern but the taking-away subtree;
- no open vocabulary;
- no selected-provider-plus-extras profile variant.

Its model is a small part of OpenBSD's policy languages, chosen as precedent, not as a
compatibility target:

- PF evaluates rules in textual order and lets the last matching one decide, so the restrictive
  ordering puts a broad block before its exceptions.
- relayd applies the same model at the application layer, to HTTP requests by method, path and
  host — and reached it by replacing its own earlier design: until 2014 its HTTP filtering was
  per-header protocol directives, matched by name with no order among them, which Reyk Floeter
  replaced with linear last-matching `pass`/`block` rules "inspired by pf" (the commit below).
- doas uses the same ordering at smaller scale: `permit`/`deny`, last match wins, and no match
  denies. It is the precedent for keeping the vocabulary this small.

That history is why this grammar has textual order and no specificity precedence: a later root
`deny` beats an earlier `/api/` allow of the same grant however specific the path, where a
most-specific-wins rule would allow it. Provider rules follow the same ordering, regardless of
where earlier grants came from; `egress-proxy.md`, "The rule file", defines their expansion. The
lessons kept:

- The file's order is its meaning; broad restrictions precede their narrower exceptions.
- The resolved ruleset may compile the rules into host and path scopes, and that compilation must
  not change their simple ordered meaning — PF's discipline for its skip steps, held here by the
  tests' plain ordered evaluator, which the ruleset is checked against over a drawn domain.
- doas's `-C`, which evaluates the file against a hypothetical command through the code that would
  enforce it, is the precedent for the request-level explanation TODO.md defers: driven by the
  enforcing resolver, never by a second interpretation of the file.

What is deliberately not borrowed:

- A path on `deny`: a denial by path fails open against the origin's canonicalization — an HTTP
  origin, not the proxy, is the final authority on how a path reads — where PF's block on a
  network is safe, the kernel being the one authority on what an address means.
- PF's `quick` and relayd's `match`, and IAM's deny-overrides: each a second kind of rule
  behavior — a precedence apart from the order, a denial no later line can undo.
- The profile system in place of relayd's unmatched-filter default.
- First-match evaluation, Squid's and nginx's, which reads the exception before the rule.
- A wildcard on the granting side.

The decision behind the grammar: the syntax alone decides the file's meaning, and not the project's
choices, which `tunnel` is right there to make; restricting the grammar further would add no
security about what a reviewed project may open. Syntax alone means:

- one parser, one resolver the launcher's dry run executes;
- exact hosts, so a grant is enumerable and the leaf certificate can name it;
- every ambiguity a refused launch.

A URL is the form every comparable project's operator already writes, and a path on the granting
side is what every one of them has been asked for — the multi-tenant host a project adds for one
tenant's content, its own bucket, one owner on a forge:

- sandbox-runtime's open request names `storage.googleapis.com` and `raw.githubusercontent.com`:
  https://github.com/anthropic-experimental/sandbox-runtime/issues/468
- Copilot's coding-agent firewall accepts a URL entry beside a domain:
  https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-firewall
- coder/boundary has path rules: https://github.com/coder/boundary
- OpenBSD pf.conf(5), relayd.conf(5), doas.conf(5) and doas(1); relayd's move to last-matching
  rules, 2014-07-09: https://github.com/openbsd/src/commit/cb8b0e5645

SECURITY.md ("Adding hosts, not patterns") has the reasoning; `resolveRuleset` enforces it. The
failure classes kept out are well attested:

- a validator and a runtime reading one configuration differently;
- an allow silently overriding a deny (the later line decides, in the order written, and a denial
  names a host or a subtree whole).

Attested in:

- https://github.com/docker/sbx-releases/issues/410
- https://github.com/anthropic-experimental/sandbox-runtime/issues/434
- https://github.com/anthropic-experimental/sandbox-runtime/issues/122
- https://github.com/anthropic-experimental/sandbox-runtime/issues/154
- https://github.com/anthropic-experimental/sandbox-runtime/issues/432
- https://github.com/stripe/smokescreen/issues/236

Do not add a wildcard on the granting side, a second precedence, a richer pattern language, or
a grant word outside the closed set without a concrete need that outweighs the added attack surface.

### No approve-on-miss prompt for a refused host

Codex, Gemini CLI's "sandbox expansion" and Copilot's `allowBypass` answer a refused request with
a prompt to widen the rules. Not here:

- A prompt is a prompt-injection target.
- A grant made through one widens the rules mid-session, harder to review than a line committed to
  the repository and applied at launch.

The rules stay launch-only: a refusal's `403` body names the step (`RefusalAdvice` in the proxy),
and the user adds the `allow` line to `.ko-agent-sandbox/egress/rule` on the host and relaunches.

- https://github.com/openai/codex/issues/22387 — no DNS inside the sandbox surprised users
- https://github.com/google-gemini/gemini-cli/issues/23875 — network off by default read as
  "sandbox unusable"

### Sign-in

A browser callback to 127.0.0.1 reaches the host, while the agent listens inside the container.
The supported device-code and pasted-code sign-ins need no callback listener exposed to the
host. [README.md](../README.md#running-command) gives each agent’s sign-in steps.

### The agent-instruction override replaces only the conventions

`.ko-agent-sandbox/agent/AGENTS-CUSTOM.md` replaces the image's `AGENTS-CUSTOM.md` and nothing
else: `AGENTS-SANDBOX.md` is what a project cannot know about itself, and "What this session may
do" is what it must not be trusted to declare. It is not an agent's own project-level instructions,
which that agent reads with no launcher help, for two reasons:

- The managed-policy location loads unconditionally: a project file can add to the image's
  conventions but never drop them.
- `.ko-agent-sandbox` is read on the host and unwritable in every write mode, so a session cannot
  rewrite the instructions governing the next one, as it could any file in the project directory.

The instruction file changes no enforcement; it is in the boundary directory for that
read-before-launch property alone.

### No following symlinks at sandbox setup

A symlinked `.git`, `.git/config`, `.git/hooks`, `.ko-agent-sandbox`, `egress`, `agent` or a file
inside them refuses the launch (`gitGuardVolumes`, `boundaryDirError`, `readRuleFiles`,
`readAgentInstructions`, tested).

- podman resolves mount sources on the host, so mounting through a repository-controlled link
  would expose its target into the sandbox.
- Following the link to mount its resolved target read-only would make the protected paths depend
  on where the link points at launch time.
- The refusal is loud, names the path, and comes before the launcher creates anything, so setup
  writes nothing through a pre-seeded link (tested: "a refused symlink form leaves no artifact
  through the link"); the project directory itself is `toRealPath()`-canonical before any of this.

Prior art for both failure cases — a sandbox that crashed mid-setup on a symlink, and setup code
whose mount-target creation wrote through one to paths outside its root:

- https://github.com/anthropic-experimental/sandbox-runtime/issues/221
- https://github.com/bazelbuild/bazel/issues/28515

The cost is that a repository sharing hooks through a symlinked `.git/hooks` cannot be sandboxed
as-is; its user replaces the link with a real directory first. Accept that cost rather than
following links.

### No repository-controlled host executable resolution

The launcher resolves `podman` (and `selinuxenabled`) through `PATH` entries that are absolute
**and** outside the project directory — `HostCommands.findOnPath` — and the reaper receives the
resolved path as an argument, so no host-side invocation consults `PATH` or, on Windows,
CreateProcess's implicit current-directory search.

Absoluteness is not consent, and a repository must never be what supplies the host's container
runtime: both halves of that filter are necessary, and `findOnPath`'s comment has why. Prior
art:

- https://github.com/docker/sbx-releases/issues/392

### No command-name safe lists

`git`, `npm`, `python`, build programs, MCP servers, and other "normal" programs can execute
repository-controlled behavior. The outer container/network boundary should contain them all instead
of trying to classify command names as safe.

### No generic "GET is safe, POST is dangerous" rule

Inspection enforces method and path grants; it does not establish that a request is harmless.
SECURITY.md, "Exfiltration through allowed network traffic", explains the limits.

### No per-repository `GitRead(repository)` grant

The ruleset names destinations and its grant words name operations; nothing names a repository,
because public reading is meant to be broad and the sandbox holds no credential a finer grant
would attenuate. SECURITY.md, "Why the ruleset is not a capability system", has the argument and
the one condition that would reopen it.

### No masking of secret-named files in the workspace

Gemini CLI, Codex CLI, clampdown and sandbox-runtime hide or empty `.env`, `.env.*`, `*.pem` and the
like inside the sandbox. Here the boundary is that the project directory is hostile data and nothing
credentialed goes in (SECURITY.md, "Credential theft"), and a name mask leaves that boundary where
it is:

- It hides one class of files by name: a secret under any other name, in `config.yaml`, or in git
  history stays visible.
- It applies to every project to protect the few that store a credential under such a name: a
  default `.env` mask breaks tests that read `.env`, the first `-name .env` removes the
  protection, and the user who commits a credential is the one least likely to review a third
  boundary file in `.ko-agent-sandbox`.
- Password-protected containers (`*.p12`, `*.pfx`) are inert without the password, and these
  formats have no standard password file or environment-variable name.

Keep the rule procedural: a credential in the project directory violates the operating model, and
it is the user's to keep out. A `deny` of the forge in `egress/rule` removes one way to spend a
forge token left there, not the risk — every allowed host is a possible recipient of what the
sandbox holds.

### No DLP/entropy/LLM firewall

It would be incomplete against encoding, timing, allowed-host selection, and protocol-specific
channels while adding false positives and another complex policy engine. Destination restriction
remains the primary exfiltration control.

### No signing broker for the proxy's leaves, and no run intermediate

Under `allow-unless-denied` the proxy issues a leaf per unlisted host from a CA created for the run
(SECURITY.md, "Who holds the CA key"). Two designs that would keep the CA key on the host were
rejected:

- A signing broker — the proxy asking the launcher to sign each leaf — satisfies "the launcher
  holds the key" literally but not its purpose: the broker is a signing oracle for whatever the
  proxy asks, so the key's location no longer bounds what a compromised proxy can issue, only
  where the bytes are stored, at the cost of a channel and a round trip per host.
- A run intermediate signed by the project CA would keep the project-level trust store and JDK
  keystore, and would let a leaf a compromised proxy issued chain to the project CA and be
  honoured by every other session of the project, which is what the run scope exists to prevent.

A launch-issued leaf beside the run CA proves nothing either: a missing or extra name, the two
defects the "names exactly" check exists for, cannot happen when the proxy issues what it
inspects.

### No upstream-proxy discovery, exclusions, chaining or negotiated authentication

`HTTPS_PROXY` is the whole upstream-proxy contract (`egress-proxy.md`, "Through an upstream
proxy"), and each of these stays out of it for a reason of its own:

- OS proxy discovery and PAC files: ambient or executable host state would choose a launch's
  transport without that choice appearing anywhere the user reads.
- `NO_PROXY` and per-origin direct exceptions: a second path around the upstream transport, and
  one a failure could widen.
- Hostname-form upstream CONNECT: some upstream proxies allow only a hostname authority and refuse
  a numeric one. That incompatibility is reported, never worked around by sending the name: the
  upstream proxy would then resolve the origin itself, severing the proof that the address checked
  for private ranges is the one reached, and its resolver would join the trusted computing base.
- More than one hop, SOCKS, NTLM, Kerberos and Negotiate: each adds a handshake, an identity broker
  or a chain-attribution question that no present deployment needs. A static `Basic` value is the
  only authentication.
- A credential outside the variable's own userinfo: the launcher never parses it, so it is in no
  argument, banner, log line or error, and the proxy is its one reader; a second source would need
  a second reader.

### No HTTP query endpoint on the proxy

Considered: the RFC 9110 request `OPTIONS * HTTP/1.1` with `Max-Forwards: 0` and a custom query
header, answering the ruleset in force from the live proxy. Rejected:

- Every consumer already gets that answer from the proxy's own `--print-ruleset` dry run —
  `--egress-effective`, the launch banner and `KO_AGENT_SANDBOX_EGRESS_RULESET`.
- The launcher cannot use a live query anyway: the rules must be validated and the leaf issued
  before the proxy container exists, since the leaf is a mount fixed at `podman create`.
- What the endpoint would add is a second parsed request format at the enforcement point, against
  its CONNECT-only, one-request rule, for information already delivered.

`Max-Forwards` itself creates no obligation here: it binds a proxy that *forwards* OPTIONS/TRACE,
and this one never does — non-CONNECT is refused at the proxy layer, both methods are refused
inside inspected tunnels, and an opaque tunnel is not an HTTP hop at all.

### No Via header

A standards deviation, knowingly: RFC 9110 §7.6.3 makes Via a MUST for an intermediary, and the
inspected forwarding omits it.

- Via exists for loop detection and protocol-capability discovery across proxy chains, and this
  hop is a single, terminal one — it forwards to the origin and never to another intermediary, so
  a loop through it cannot form.
- What Via would actually do here is stamp the proxy's presence and software onto every inspected
  request for every origin to read, metadata this design sends nowhere, and some origins vary
  caching behavior on it.
- The client side is not deceived: it addressed the proxy by CONNECT.
- The upstream proxy `HTTPS_PROXY` selects (`egress-proxy.md`, "Through an upstream proxy")
  changes none of this: the CONNECT that opens a tunnel through it is this proxy's own request as
  a client, not a forwarded one, carries no Via either, and the sandbox's requests pass inside that
  tunnel unchanged; a loop still cannot form, since nothing routes into the per-run network.

Revisit if this proxy ever forwards a request to another intermediary.

### No per-agent violations channel

sandbox-runtime annotates the agent's context with a `<sandbox_violations>` block; Copilot's
coding-agent firewall reports a blocked request with the address and the command that made it.

- Each needs integration per CLI release.
- The `403` body already appears in the tool output every agent reads, at the enforcement point,
  so nothing is integrated.

Revisit if an agent stops showing its tools' output to the model, which is what the body's route
relies on.

### No general capability broker

This architecture deliberately avoids most cases in which a broker is useful by keeping
valuable credentials outside the sandbox.

A capability layer would create a second security-policy language and another enforcement point
while providing little reduction in authority under this operating model. Prior art proposing
exactly this design — a host-side MCP auth broker/gateway holding credentials the agent container
never sees — solves a real problem for workflows that need credentialed MCP servers, a requirement
this project's operating model deliberately avoids:

- https://github.com/mattolson/agent-sandbox/issues/122

`plan-credential-broker-proxy.md` is inside this decision, not an exception to it: it moves a
value the user forwards out of the sandbox and adds no grant word — what the value may do stays
with its issuer's scope and the ruleset (SECURITY.md, "Why the ruleset is not a capability
system").

### No gVisor or microVM isolation layer

Rootless podman is the chosen portability/security trade-off. Revisit only if
host-kernel/container-runtime exploitation enters the threat model.

The gVisor issue history also shows that stronger runtime isolation brings additional
rootless/nesting/mount compatibility complexity — e.g. rootless uid mapping breaking same-uid host
file access, the problem this launcher's `--userns=keep-id` solves. That does not make gVisor a bad
design; it means the additional boundary is added only when the threat model requires it.

- https://gvisor.dev/
- https://github.com/google/gvisor/issues/9918

### No test hook that pauses a launch mid-flight

The workspace filter's reference count has one state worth attacking: a launch between its `podman
create` and its `podman start`, where the marker and a container that is not running exist together
and a reap must count the marker (`KoAgentFs`, "The workspace FUSE filter's mount lifecycle").
Arranging that interleaving at an arbitrary instant would need the launcher pausable from outside —
a variable read on the launch path. It would need to be known, documented in `--help`, and fail
closed like every other variable: boundary code carrying a hook that exists only for a test, on the
path that decides whether the filter is mounted at all.

`MountLifecycleTest` provides the same evidence without it; its header has how. It does not cover
an interleaving at some other instant, and a pause hook would not enumerate one either.

### No scheduled or self-triggering verification

`--self-test` runs when a person runs it. It does not run on a schedule, report anywhere, or start
itself after detecting an upgrade. The enforcement is at the launch that would rely on the answer:

- today, the filter's own self-test before every filtered launch (`KoAgentFs.prepareKoAgentFs`),
  which refuses the launch when it fails;
- for the staged engine, the stamp `plan-staged.md` specifies — source, machine, kernel and
  backing filesystem — whose absence or mismatch refuses a staged launch.

Both act at the moment the answer matters rather than at some earlier one. Revisit if an unattended
workflow needs a stale verification detected before its next attempted launch, rather than a
failed launch being enforcement enough — a CI failure a person reads later is still that
enforcement.

## The properties verification has to separate

Conflating them is what makes verification look larger than it is.

- **The code's own logic** depends on neither of the others. The privileged dev rig settles it once,
  on whichever host a developer has (`../fuse/ko-agent-fs/doc/testing.md`).
- **The kernel** is not one kernel: every podman machine runs its own — Fedora CoreOS on macOS, a
  Microsoft build on Windows, the user's own on native Linux — and this mount already hinges on what
  a kernel offers, refusing to mount at all when `init` cannot negotiate `AUTO_INVAL_DATA`
  (`../fuse/ko-agent-fs/doc/architecture.md`).
- **The share**, and the backing under it: the host project directory as it arrives inside the
  machine, over virtiofs on macOS and the WSL share on Windows. On native Linux the upper varies
  instead, a named volume stored in the host's container storage — btrfs, ZFS, XFS or overlay —
  against the machine's own ext4 everywhere else.

Every case asserts a premise behaviorally, at the layer the product uses it — never a version, a
mount option or a declared feature. That is the rule the virtiofs premise is already recorded under
(`../fuse/ko-agent-fs/doc/verification-log.md`), and it keeps the suite indifferent to *why* an
environment changed: a podman upgrade, a recreated machine, a host OS update and a changed storage
driver each appear to it as a changed behavior, and no case has to anticipate which.

## Prior-art references worth retaining

Comparison points for future decisions, not dependencies. The specific issues a decision rests on
are linked inline where that decision is recorded; these are the broader sources.

- Docker AI sandboxes — microVM isolation, direct-vs-clone workspace models:
  https://docs.docker.com/ai/sandboxes/ https://docs.docker.com/ai/sandboxes/security/isolation/
- The project mounted at its own path (`SandboxProject.mountPathOf`) — what the two container
  sandboxes doing the same ran into, read in September 2026. Gemini CLI mounts the unresolved
  path while its tools resolve real paths, so a symlinked project (macOS's `/tmp`) fails its own
  lookups and splits its sessions; this launcher mounts the real path only. Docker Sandboxes
  spells a Windows drive `/c/…` and serves `\\wsl.localhost` workspaces, where `chmod` and
  `symlink` fail; its users asked for a remapped path over the disclosure of the username and
  layout, and a maintainer answered in May 2026 that the host path serves scripts expecting it
  and the default may change. Antigravity confines commands on the host instead, paths the
  host's by construction; hosted agents and VS Code dev containers use a fixed path. Open: a
  second bind at the launch spelling for an IDE that opened a symbolic path, and `/mnt/<drive>`
  against those tools' `/c/`.
  https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/sandbox.md
  https://github.com/google-gemini/gemini-cli/issues/28416
  https://github.com/google-gemini/gemini-cli/issues/27278
  https://github.com/docker/sbx-releases/issues/598
  https://github.com/docker/sbx-releases/issues/137
  https://github.com/docker/desktop-feedback/issues/158
  https://antigravity.google/docs/sandbox
  https://code.visualstudio.com/remote/advancedcontainers/change-default-source-mount
- Anthropic Claude Code — composed filesystem/network confinement, and its settings/credential
  model: https://www.anthropic.com/engineering/claude-code-sandboxing
  https://docs.anthropic.com/en/docs/claude-code/settings
- Docker AI sandboxes' upstream-proxy configuration — the comparison point for `HTTPS_PROXY`:
  https://docs.docker.com/ai/sandboxes/configuration/upstream-proxy/
- Stripe Smokescreen — mature egress-proxy prior art; its ACL-bypass advisories are permanent
  regression inputs, in the proxy's `AgentEgressProxyTest`:
  https://github.com/stripe/smokescreen
  https://github.com/stripe/smokescreen/security/advisories/GHSA-qwrf-gfpj-qvj6
  https://github.com/stripe/smokescreen/security/advisories/GHSA-gcj7-j438-hjj2
- Bazel sandboxing/hermeticity — minimizing ambient inputs/outputs, testing effective boundaries:
  https://bazel.build/versions/9.1.0/docs/sandboxing
- Anthropic Sandbox Runtime — network-boundary regressions that motivate black-box runtime tests:
  https://github.com/anthropic-experimental/sandbox-runtime/issues/225
  https://github.com/anthropic-experimental/sandbox-runtime/issues/88
- Agent sandbox/proxy comparisons, including credential brokering:
  https://github.com/mattolson/agent-sandbox https://github.com/89luca89/clampdown
- Refusal reasons handed to the agent — sandbox-runtime's `deniedDomainReasons`, Codex's
  `codex.network_proxy.policy_decision` reasons, Copilot's firewall report; here fixed and
  launcher-owned, since the ruleset allows hosts, not patterns:
  https://github.com/anthropic-experimental/sandbox-runtime
  https://github.com/openai/codex/tree/main/codex-rs/network-proxy
  https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-firewall

## Naming

Directory names follow the terse Unix tradition where the choice is free:

- an abbreviation drops the plural marker with the rest of the word (`doc`, like `bin`, `lib`,
  `src`), and a full word names the directory's role in the singular (`probe`, like `spec`,
  `vendor`, `container`), never its contents' count;
- an abbreviation is cut as short as it stays unambiguous — `conf`, not `config`;
- where a program mandates the name, that name is used: Cargo's `tests/` and `examples/`, sbt's
  `src/main/resources`, XDG's `~/.config`;
- where a grammar spells it, that spelling is used: the proxy's `defaults/` is the `defaults` of
  `deny defaults`.

The accepted costs of `doc` over `docs`:

- SECURITY.md stays at the repository root (GitHub's community-health lookup reads only root,
  `.github/` and `docs/`);
- a future GitHub Pages site publishes through an Actions workflow rather than the branch-folder
  setting;
- a future mdoc build sets `mdocIn` instead of inheriting its default.

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
Rule syntax has one meaning. Compiling or optimizing a ruleset may change its representation,
never its semantics: the plain ordered reading of the rules is the specification.
```

```text
What a session may do is decided before launch and cannot be widened by the running sandbox: the
rule file is read on the host and frozen, a refused request names the step but grants nothing, and
a changed file applies at the next launch.
```

```text
The workspace's writability is the user's per-launch choice (`--write`).
In a writable mode, the workspace is untrusted output: protect implicit host execution
paths, but keep other project files writable, because editing them is the purpose
of such a session; a read-only session's purpose is reading, and its results leave
through the conversation.
```

```text
An allowed host is a possible recipient of sandbox data.
Calling a GET request "read" does not make it an information-flow read.
```

```text
Prefer a small, observable boundary over a richer policy language.
Add policy code only when it removes authority the sandbox would otherwise
have to possess.
```

```text
Do not trade security for performance. A slow boundary is still a boundary;
one loosened for speed is not.
```

```text
Security configuration must fail closed.
Unknown, malformed, or ambiguously interpreted configuration must not silently weaken the
effective boundary.
```
