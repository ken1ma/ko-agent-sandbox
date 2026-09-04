# Design decisions

What was decided and must not silently drift: the standing decisions, recorded so they stop
resurfacing; the axes verification has to separate; the prior art they were reviewed against; and
the principles to preserve. The work that remains is TODO.md; the security model is SECURITY.md.

## Standing design decisions

Each was reviewed against broader prior art and relevant issue histories, and says what is fixed
and why. A named revisit condition records the anticipated reason to reopen it; otherwise
reopening takes a new requirement, or evidence that an assumption or security argument the
decision rests on no longer holds. Nothing less reopens one.

### No general capability broker

This architecture deliberately avoids most cases in which a broker is useful by keeping
valuable credentials outside the sandbox.

A capability layer would create a second security-policy language and another enforcement surface
while providing little reduction in authority under this operating model. Prior art proposing
exactly this design — a host-side MCP auth broker/gateway holding credentials the agent container
never sees — solves a real problem for workflows that need credentialed MCP servers, a requirement
this project's operating model deliberately avoids:

- https://github.com/mattolson/agent-sandbox/issues/122

### No per-repository `GitRead(repository)` policy

The policy names destinations and its grant words name operations; nothing names a repository,
because public reading is meant to be broad and the sandbox holds no credential a finer grant
would attenuate. SECURITY.md, "Why the policy is not a capability system", has the argument and
the one condition that would reopen it.

### No generic "GET is safe, POST is dangerous" rule

SECURITY.md, "Exfiltration through an allowed host". The inspected treatment removes a host's
write API, never declares a GET safe.

### No command-name safe lists

`git`, `npm`, `python`, build tools, MCP servers, and other "normal" programs can execute
repository-controlled behavior. The outer container/network boundary should contain them all instead
of trying to classify command names as safe.

### The agent-instruction override replaces only the conventions

`.ko-agent-sandbox/agent/AGENTS-CUSTOM.md` replaces the image's `AGENTS-CUSTOM.md` and nothing
else: `AGENTS-SANDBOX.md` is what a project cannot know about itself, and the policy section is
what it must not be trusted to declare. It is not an agent's own project-level instructions,
which that agent reads with no launcher help, because the managed-policy location
loads unconditionally — a project file can add to the image's conventions but never drop them —
and because `.ko-agent-sandbox` is read on the host and unwritable in every write mode, so a
session cannot rewrite the instructions governing the next one, as it could any file in the
project directory. Prose governs nothing enforceable; the file sits in the boundary directory for
that read-before-launch property alone.

### No richer egress-policy format

The policy stays four fixed profiles over one file, `rule`, in the grammar `doc/egress-proxy.md`
spells out: `allow` and `deny` lines naming URLs, four grant words, no pattern but the
taking-away subtree, no open vocabulary, no selected-provider-plus-extras profile variant.

Its design lineage is a small part of OpenBSD's policy-language tradition, chosen as precedent,
not as a compatibility target. PF evaluates rules in textual order and lets the last matching
one decide, the restrictive shape a broad block followed by its exceptions. relayd applies the
same model at the application layer, to HTTP requests by method, path and host — and reached it
by replacing its own earlier design: until 2014 its HTTP filtering was per-header protocol
directives, matched by name with no order among them, which Reyk Floeter replaced with linear
last-matching `pass`/`block` rules "inspired by pf" (the commit below). That history is why this
grammar has textual order and no specificity precedence: a later root `deny` beats an earlier
`/api/` allow of the same grant however specific the path, where a most-specific-wins rule
would admit it. doas is the same house's smaller instance — `permit`/`deny`, last match wins, no
match denies — and the precedent for keeping the vocabulary this small. The lessons kept: the
file's order is its meaning; broad restrictions precede their narrower exceptions; the resolved
policy may compile the rules into host and path scopes, and that compilation must not change
their simple ordered meaning — PF's discipline for its skip steps, held here by the tests'
plain ordered evaluator, which the resolved policy is checked against over a drawn domain.
doas's `-C`, which evaluates the file against a hypothetical command through the code that
would enforce it, is the precedent for the request-level explanation TODO.md defers: driven by
the enforcing resolver, never by a second interpretation of the file.

What is deliberately not borrowed: a path on `deny`, since a denial by path fails open against
the origin's canonicalization — an HTTP origin, not the proxy, is the final authority on how a
path reads — where PF's block on a network is safe, the kernel being the one authority on what
an address means; PF's `quick` and relayd's `match`, and IAM's deny-overrides, each a second
kind of rule behavior — a precedence apart from the order, a denial no later line can undo; the
profile system in place of relayd's unmatched-filter default; first-match evaluation, Squid's
and nginx's, which reads the exception before the rule; a wildcard on the granting side. The
decision the grammar rests on: syntax buys the file's meaning — one parser, one resolver the
launcher's dry run executes, exact hosts so a grant is enumerable and the leaf certificate can
name it, every ambiguity a refused launch — and not the project's choices, which `tunnel` is
right there to make; restricting the grammar further would buy no security about what a
reviewed project may open.

A URL is the form every comparable project's operator already writes, and a path on the granting
side is what every one of them has been asked for — the multi-tenant host a project adds for one
tenant's content, its own bucket, one owner on a forge: sandbox-runtime's open request names
`storage.googleapis.com` and `raw.githubusercontent.com`, Copilot's coding-agent firewall accepts
a URL entry beside a domain, coder/boundary has path rules:

- https://github.com/anthropic-experimental/sandbox-runtime/issues/468
- https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-firewall
- https://github.com/coder/boundary
- OpenBSD pf.conf(5), relayd.conf(5), doas.conf(5) and doas(1); relayd's move to last-matching
  rules, 2014-07-09: https://github.com/openbsd/src/commit/cb8b0e5645

SECURITY.md ("Adding hosts, not patterns") has the reasoning;
`resolvePolicy` enforces it, and the tests hold the resolved policy to a plain ordered evaluator
over a drawn domain. The failure classes kept out — a
validator and a runtime reading one configuration differently (one resolver, in the proxy, which
the launcher's dry run executes), and an allow silently overriding a deny (the last word decides,
in the order written, and a denial names a host or a subtree whole) — are well attested:

- https://github.com/docker/sbx-releases/issues/410
- https://github.com/anthropic-experimental/sandbox-runtime/issues/434
- https://github.com/anthropic-experimental/sandbox-runtime/issues/122
- https://github.com/anthropic-experimental/sandbox-runtime/issues/154
- https://github.com/anthropic-experimental/sandbox-runtime/issues/432
- https://github.com/stripe/smokescreen/issues/236

Do not add a wildcard on the granting side, a second precedence, a richer pattern language, or
a grant word outside the closed set without a concrete need that outweighs that surface.

### No HTTP query surface on the proxy

Considered: the RFC 9110 request `OPTIONS * HTTP/1.1` with `Max-Forwards: 0` and a custom query
header, answering the effective policy from the live proxy. Rejected, because every consumer
already gets that answer from the proxy's own `--print-policy` dry run — `--egress-effective`, the
launch banner, `KO_AGENT_SANDBOX_EGRESS_POLICY`, and the appended agent instructions — and the
launcher cannot use a live query anyway: the policy must be validated and the leaf minted before
the proxy container exists, since the leaf is a mount fixed at `podman create`. What the endpoint
would add is a second parsed request format at the enforcement point, against its
CONNECT-only-one-request rule, for information already delivered. `Max-Forwards` itself creates
no obligation here: it binds a proxy that *forwards* OPTIONS/TRACE, and this one never does —
non-CONNECT is refused at the proxy layer, both methods are refused inside inspected tunnels, and
an opaque tunnel is not an HTTP hop at all.

### No Via header

A standards deviation, knowingly: RFC 9110 §7.6.3 makes Via a MUST for an intermediary, and the
inspected forwarding omits it. Via exists for loop detection and protocol-capability discovery
across proxy chains, and this hop is a single, terminal one — it forwards to the origin and never
to another intermediary, so a loop through it cannot form. What Via would actually do here is
stamp the proxy's presence and software onto every inspected request for every origin to read,
metadata this design sends nowhere, and some origins vary caching behavior on it. The client side
is not deceived: it addressed the proxy by CONNECT. Revisit if this proxy ever forwards to another
intermediary or joins a chain: the assumption above is then gone.

### No test hook that pauses a launch mid-flight

The workspace filter's reference count has one window worth attacking: a launch between its mount
and its `podman create`, where the marker exists and the container does not (`KoAgentFs`, "The
workspace FUSE filter's mount lifecycle"). Arranging that interleaving at an arbitrary instant
would need the launcher pausable from outside — a variable read on the launch path. It would need
to be known, documented in `--help`, and fail closed like every other variable: boundary code
containing scaffolding for a test, on the path that decides whether the filter is mounted at all.

`MountLifecycleTest` reaches the same evidence without it; its header has how. What stays out of
reach is an interleaving at some other instant — which a pause hook would not enumerate either.

### No scheduled or self-triggering verification

`--self-test` runs when a person runs it. It does not run on a schedule, report anywhere, or start
itself after detecting an upgrade. A stale stamp refusing a staged launch is the whole of the
enforcement, and it acts at the moment the answer matters rather than at some earlier one.
Revisit if an unattended workflow needs a stale verification detected before its next attempted
launch, rather than a failed launch being enforcement enough — a CI failure a person reads
later is still that enforcement.

### No repository-controlled host executable resolution

The launcher resolves `podman` (and `selinuxenabled`) through `PATH` entries that are absolute
**and** outside the project directory — `HostCommands.findOnPath` — and the reaper receives the
resolved path as an argument, so no host-side invocation consults `PATH` or, on Windows,
CreateProcess's implicit current-directory search.

Absoluteness is not consent, and a repository must never be what supplies the host's container
runtime: both halves of that filter are necessary, and `findOnPath`'s comment has why. Prior
art:

- https://github.com/docker/sbx-releases/issues/392

### No following symlinks at sandbox setup

A symlinked `.git`, `.git/config`, `.git/hooks`, `.ko-agent-sandbox`, `egress`, `agent` or a file
inside them refuses the launch (`gitGuardVolumes`, `policyDirError`, `readPolicyFiles`,
`readAgentInstructions`, tested). podman resolves mount sources on the host, so mounting through a
repository-controlled link would expose its target into the sandbox, and following the link to pin
its resolved target would make the pinned surface depend on where the link points at launch time.
The refusal is loud, names the path, and comes before the launcher creates anything, so setup writes
nothing through a pre-seeded link (tested: "a refused symlink form leaves no artifact through the
link"); the project directory itself is `toRealPath()`-canonical before any of this. Prior art for
both failure cases — a sandbox that crashed mid-setup on a symlink, and setup code whose
mount-target creation wrote through one to paths outside its root:

- https://github.com/anthropic-experimental/sandbox-runtime/issues/221
- https://github.com/bazelbuild/bazel/issues/28515

The cost is that a repository sharing hooks through a symlinked `.git/hooks` cannot be sandboxed
as-is; its user replaces the link with a real directory first. Accept that cost rather than
following links.

### No DLP/entropy/LLM firewall

It would be incomplete against encoding, timing, allowed-host selection, and protocol-specific
channels while adding false positives and another complex policy engine. Destination restriction
remains the primary exfiltration control.

### No masking of secret-named files in the workspace

Gemini CLI, Codex CLI, clampdown and sandbox-runtime hide or empty `.env`, `.env.*`, `*.pem` and
the like inside the sandbox. Here the boundary is that the project directory is hostile data and
nothing credentialed goes in (SECURITY.md, "Credential theft"); a name mask leaves that boundary
where it is and hides one class of files by name, without strengthening the boundary: a secret
under any other name, in `config.yaml`, or in git history stays visible. It also costs every
project to serve the undisciplined one: a default `.env` mask
breaks tests that read `.env`, the first `-name .env` removes the protection, and the user who
commits a credential is the one least likely to review a third policy file in `.ko-agent-sandbox`.
Password-protected containers (`*.p12`, `*.pfx`) are inert without the password, which lives
under no well-known name. Keep the rule procedural: a credential in the project directory
violates the operating model, and it is the user's to keep out. A `deny` of the forge in
`egress/rule` removes one way to spend a forge token left there, not the risk — every admitted
host is a possible recipient of what the sandbox holds.

### No gVisor or microVM isolation layer

Rootless podman is the chosen portability/security trade-off. Revisit only if
host-kernel/container-runtime exploitation enters the threat model.

The gVisor issue history also shows that stronger runtime isolation brings additional
rootless/nesting/mount compatibility complexity — e.g. rootless uid mapping breaking same-uid host
file access, the problem this launcher's `--userns=keep-id` solves. That does not make gVisor a bad
design; it means the additional boundary should be purchased only when the threat model requires it.

- https://gvisor.dev/
- https://github.com/google/gvisor/issues/9918

### No approve-on-miss prompt for a refused host

Codex, Gemini CLI's "sandbox expansion" and Copilot's `allowBypass` answer a refused request with
a prompt to widen the policy. A prompt is a prompt-injection target, and a grant made through one
is authority added mid-session, harder to review than a line committed to the repository and
applied at launch. Authority here stays launch-only: a refusal's `403` body names the
step (`RefusalAdvice` in the proxy), and the user adds the `allow` line to
`.ko-agent-sandbox/egress/rule` on the host and relaunches.

- https://github.com/openai/codex/issues/22387 — no DNS inside the sandbox surprised users
- https://github.com/google-gemini/gemini-cli/issues/23875 — network off by default read as
  "sandbox unusable"

### No per-agent violations channel

sandbox-runtime annotates the agent's context with a `<sandbox_violations>` block; Copilot's
coding-agent firewall reports a blocked request with the address and the command that made it.
Each needs integration per CLI release. The `403` body already lands in the tool output every
agent reads, at the enforcement point, so nothing is integrated. Revisit if an agent stops
surfacing its tools' output to the model, which is what the body's route relies on.

## The axes verification has to separate

Conflating them is what makes verification look larger than it is.

- **The code's own logic** depends on neither of the others. The privileged dev rig settles it once,
  on whichever host a developer has (`../fuse/ko-agent-fs/doc/testing.md`).
- **The kernel** is not one kernel: every podman machine runs its own — Fedora CoreOS on macOS, a
  Microsoft build on Windows, the user's own on native Linux — and this mount already hinges on what
  a kernel offers, refusing to mount at all when `init` cannot negotiate `AUTO_INVAL_DATA`
  (`../fuse/ko-agent-fs/doc/architecture.md`).
- **The share**, and the backing under it: the host project directory as it arrives inside the
  machine, over virtiofs on macOS and the WSL share on Windows. On native Linux the upper varies
  instead, a named volume landing in the host's container storage — btrfs, ZFS, XFS or overlay —
  against the machine's own ext4 everywhere else.

Every case asserts a premise behaviorally, at the layer the product uses it — never a version, a
mount option or a declared feature. That is the rule the virtiofs premise is already recorded under
(`../fuse/ko-agent-fs/doc/verification-log.md`), and it keeps the suite indifferent to *why* an
environment moved: a podman upgrade, a recreated machine, a host OS update and a changed storage
driver all reach it the same way, and no case has to anticipate which.

## Prior-art references worth retaining

Comparison points for future decisions, not dependencies. The specific issues that shaped a decision
are linked inline where that decision is recorded; these are the broader sources.

- Docker AI sandboxes — microVM isolation, direct-vs-clone workspace models:
  https://docs.docker.com/ai/sandboxes/ https://docs.docker.com/ai/sandboxes/security/isolation/
- Anthropic Claude Code — composed filesystem/network confinement, and its settings/credential
  model: https://www.anthropic.com/engineering/claude-code-sandboxing
  https://docs.anthropic.com/en/docs/claude-code/settings
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
  launcher-owned, since the policy admits hosts, not patterns:
  https://github.com/anthropic-experimental/sandbox-runtime
  https://github.com/openai/codex/tree/main/codex-rs/network-proxy
  https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-firewall

## Naming

Directory names follow the terse Unix tradition where the choice is free: an abbreviation drops
the plural marker with the rest of the word (`doc`, like `bin`, `lib`, `src`), and a full word
names the directory's role in the singular (`probe`, like `spec`, `vendor`, `container`), never its
contents' count. An abbreviation is cut as short as it stays unambiguous — `conf`, not `config`.
Where a tool mandates the name, the tool wins: Cargo's `tests/` and `examples/`, sbt's
`src/main/resources` and `src/test`, XDG's `~/.config`; where a grammar spells it, the grammar
wins: the proxy's `defaults/` is the `defaults` of `deny defaults`. The accepted prices of `doc`
over `docs`: SECURITY.md stays at the repository root (GitHub's community-health lookup reads only
root, `.github/` and `docs/`); a future GitHub Pages site publishes through an Actions workflow
rather than the branch-folder setting; a future mdoc build sets `mdocIn` instead of inheriting
its default.

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
Policy syntax has one meaning. Compiling or optimizing a policy may change its representation,
never its semantics: the plain ordered reading of the rules is the specification.
```

```text
Authority is decided before launch and cannot be widened by the running sandbox: the rule file
is read on the host and frozen, a refused request names the step but grants nothing, and a
changed file applies at the next launch.
```

```text
The workspace's writability is the user's per-launch authority decision (`--write`).
In a writable mode, the workspace is untrusted output: protect implicit host execution
paths, but keep files outside that control state writable, because editing them is the purpose
of such a session; a read-only session's purpose is reading, and its results leave
through the conversation.
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
Do not trade security for performance. A slow boundary is still a boundary;
one loosened for speed is not.
```

```text
Security configuration must fail closed.
Unknown, malformed, or ambiguously interpreted policy must not silently weaken the
effective boundary.
```
