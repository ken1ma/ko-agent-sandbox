# Design decisions

What was decided and must not silently drift: rejected ideas (Non-TODOs), recorded so they stop
resurfacing; the axes verification has to separate; the prior art they were reviewed against; and
the principles to preserve. The work that remains is TODO.md; the security model is SECURITY.md.

## Non-TODOs / deliberate design choices

These ideas were reviewed against broader prior art and relevant issue histories. Do not implement
them without a new requirement.

### No general capability broker

This architecture deliberately avoids most cases in which a broker is useful by keeping
valuable credentials outside the sandbox.

A capability layer would create a second security-policy language and another enforcement surface
while providing little reduction in authority under this operating model. Prior art proposing
exactly this shape — a host-side MCP auth broker/gateway holding credentials the agent container
never sees — solves a real problem for workflows that need credentialed MCP servers, a requirement
this project's operating model deliberately avoids:

- https://github.com/mattolson/agent-sandbox/issues/122

### No per-repository `GitRead(repository)` policy

SECURITY.md, "Why the policy is not a capability system".

### No generic "GET is safe, POST is dangerous" rule

SECURITY.md, "Exfiltration through an allowed host". The restricted treatment removes a host's
write API, never declares a GET safe.

### No command-name safe lists

`git`, `npm`, `python`, build tools, MCP servers, and other "normal" programs can execute
repository-controlled behavior. The outer container/network boundary should contain them all instead
of trying to classify command names as safe.

### The agent-instruction override replaces only the conventions

`.ko-agent-sandbox/agent/AGENTS-CUSTOM.md` replaces the image's `AGENTS-CUSTOM.md` and nothing
else: `AGENTS-SANDBOX.md` is what a project cannot know about itself, and the policy section is
what it must not be trusted to declare. It is not the workspace's own CLAUDE.md / AGENTS.md /
GEMINI.md, which every agent reads with no launcher help, because the managed-policy location
loads unconditionally — a project file can add to the image's conventions but never drop them —
and because `.ko-agent-sandbox` is read on the host and unwritable in every write mode, so a
session cannot rewrite the instructions governing the next one, as it could any file in the
checkout. Prose governs nothing enforceable; the file sits in the boundary directory for that
read-before-launch property alone, and is the directory's second tenant, so its closed namespace
admits `agent/` with the one filename.

### No richer egress-policy format

The policy stays four fixed profiles over two fixed files, `allowed` and `denied`, in the grammar
the README's "Modifying the egress policy" spells — no fields, no globs beyond the taking-away
subtree, no ranked rules, no open allowance vocabulary, no selected-provider-plus-extras
profile variant. SECURITY.md ("Adding hosts, not patterns") carries the reasoning;
`resolvePolicy` enforces it, tested rule by rule. The failure classes kept out — a
validator and a runtime reading one configuration differently (one resolver, in the proxy, which
the launcher's dry run executes), and an allow silently overriding a deny (one fixed order,
`denied` last, every contradiction a refusal) — are well attested:

- https://github.com/docker/sbx-releases/issues/410
- https://github.com/anthropic-experimental/sandbox-runtime/issues/434
- https://github.com/anthropic-experimental/sandbox-runtime/issues/122
- https://github.com/anthropic-experimental/sandbox-runtime/issues/154
- https://github.com/anthropic-experimental/sandbox-runtime/issues/432
- https://github.com/stripe/smokescreen/issues/236

Do not add wildcard additions, ranked rules, a richer removal-pattern language, or an allowance
outside
the closed set without a concrete need that outweighs that surface.

### No HTTP query surface on the proxy

Considered: the RFC 9110 shape `OPTIONS * HTTP/1.1` with `Max-Forwards: 0` and a custom query
header, answering the effective policy from the live proxy. Rejected, because every consumer
already gets that answer from the proxy's own `--print-policy` dry run — `--egress-effective`, the
launch banner, `KO_AGENT_SANDBOX_EGRESS_POLICY`, and the appended agent instructions — and the
launcher cannot use a live query anyway: the policy must be validated and the leaf minted before
the proxy container exists, since the leaf is a mount fixed at `podman create`. What the endpoint
would add is a second parsed request shape at the enforcement point, against its
CONNECT-only-one-request stance, for information already delivered. `Max-Forwards` itself creates
no obligation here: it binds a proxy that *forwards* OPTIONS/TRACE, and this one never does —
non-CONNECT is refused at the proxy layer, both methods are refused inside inspected tunnels, and
an unrestricted tunnel is not an HTTP hop at all.

### No Via header

RFC 9110 §7.6.3 makes Via a MUST for an intermediary, and this proxy knowingly does not send it:
Via exists for loop detection and protocol-capability discovery across proxy chains, and this hop
is a single, terminal one — a loop through it cannot form. What Via would actually do here is
stamp the proxy's presence and software onto every inspected request for every origin to read,
metadata this design sends nowhere, and some origins vary caching behavior on it. The client side
is not deceived: it addressed the proxy by CONNECT.

### No test hook that pauses a launch mid-flight

The workspace filter's reference count has one window worth attacking: a launch between its mount
and its `podman create`, where the marker exists and the container does not (`KoAgentFs`, "The
workspace FUSE filter's mount lifecycle"). Arranging that interleaving at an arbitrary instant
would need the launcher pausable from outside — a variable read on the launch path. It would need
to be known, documented in `--help`, and fail closed like every other variable: boundary code
carrying scaffolding for a test, on the path that decides whether the filter is mounted at all.

`MountLifecycleTest` reaches the same evidence without it; its header has how. What stays out of
reach is an interleaving at some other instant — which a pause hook would not enumerate either.

### No scheduled or self-triggering verification

`--self-test` runs when a person runs it. It does not run on a schedule, report anywhere, or start
itself after detecting an upgrade. A stale stamp refusing a staged launch is the whole of the
enforcement, and it acts at the moment the answer matters rather than at some earlier one.

### No PATH-resolved host executables

The launcher resolves `podman` (and `selinuxenabled`) through `PATH`
entries that are absolute **and** outside the repository being sandboxed —
`HostCommands.findOnPath` — and
the reaper receives the resolved path as an argument, so no host-side invocation consults `PATH` or,
on Windows, CreateProcess's implicit current-directory search.

Absoluteness is not consent, and a repository must never be what supplies the host's container
runtime: both halves of that filter are load-bearing, and `findOnPath`'s comment has why. Prior
art:

- https://github.com/docker/sbx-releases/issues/392

### No following symlinks at sandbox setup

A symlinked `.git`, `.git/config`, `.git/hooks`, `.ko-agent-sandbox`, `egress`, `agent` or a
file inside them refuses the launch (`gitGuardVolumes`, `policyDirError`, `readPolicyFiles`,
`readAgentInstructions`,
tested). Podman resolves mount sources on the host,
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

### No masking of secret-named files in the workspace

Gemini CLI, Codex CLI, clampdown and sandbox-runtime hide or empty `.env`, `.env.*`, `*.pem` and
the like inside the sandbox. Here the boundary is that the checkout is hostile data and nothing
credentialed goes in (SECURITY.md, "Credential theft"); a name mask leaves that boundary where it
is and hides one class of files by name, so the document could claim nothing more afterwards than
it claims now — a secret under any other name, in `config.yaml`, or in git history stays visible.
It also costs every project to serve the undisciplined one: a default `.env` mask breaks tests
that read `.env`, the first `-name .env` removes the protection, and the user who commits a
credential is the one least likely to review a third policy file in `.ko-agent-sandbox`.
Password-protected containers (`*.p12`, `*.pfx`) are inert without the password, which lives
under no well-known name. Keep the rule procedural: a credential in the checkout is the user's to
keep out, and a forge token there is answered by denying the forge in `egress/denied`.

### No gVisor or microVM isolation layer

Rootless Podman is the chosen portability/security trade-off. Revisit only if
host-kernel/container-runtime exploitation enters the threat model.

The gVisor issue history also shows that stronger runtime isolation brings additional
rootless/nesting/mount compatibility complexity — e.g. rootless uid mapping breaking same-uid host
file access, the problem this launcher's `--userns=keep-id` solves. That does not make gVisor a bad
design; it means the additional boundary should be purchased only when the threat model requires it.

- https://gvisor.dev/
- https://github.com/google/gvisor/issues/9918

## The three axes verification has to separate

Conflating them is what makes verification look larger than it is.

- **The code's own logic** depends on neither of the others. The privileged dev rig settles it once,
  on whichever host a developer has (`../fuse/ko-agent-fs/doc/testing.md`).
- **The kernel** is not one kernel: every Podman machine carries its own — Fedora CoreOS on macOS, a
  Microsoft build on Windows, the user's own on native Linux — and this mount already hinges on what
  a kernel offers, refusing to mount at all when `init` cannot negotiate `AUTO_INVAL_DATA`
  (`../fuse/ko-agent-fs/doc/architecture.md`).
- **The share**, and the backing under it: the host project directory as it arrives inside the
  machine, over virtiofs on macOS and the WSL share on Windows. On native Linux the upper varies
  instead, a named volume landing in the host's container storage — btrfs, ZFS, XFS or overlay —
  against the machine's own ext4 everywhere else.

Every case asserts a premise behaviourally, at the layer the product uses it — never a version, a
mount option or a declared feature. That is the rule the virtiofs premise is already recorded under
(`../fuse/ko-agent-fs/doc/verification-log.md`), and it keeps the suite indifferent to *why* an
environment moved: a podman upgrade, a recreated machine, a host OS update and a changed storage
driver all reach it by the same door, and no case has to anticipate which.

## Prior-art references worth retaining

Comparison points for future decisions, not dependencies. The specific issues that shaped a decision
are linked inline where that decision is recorded; these are the broader sources.

- Docker AI sandboxes — microVM isolation, direct-vs-clone workspace models:
  https://docs.docker.com/ai/sandboxes/ https://docs.docker.com/ai/sandboxes/security/isolation/
- Anthropic Claude Code — composed filesystem/network confinement, and its settings/credential
  model: https://www.anthropic.com/engineering/claude-code-sandboxing
  https://docs.anthropic.com/en/docs/claude-code/settings
- Stripe Smokescreen — mature egress-proxy prior art; the two ACL-bypass advisories are permanent
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

## Naming

Directory names follow the terse Unix tradition where the choice is free: an abbreviation drops
the plural marker with the rest of the word (`doc`, like `bin`, `lib`, `src`), and a full word
names the directory's role in the singular (`probe`, like `spec`, `vendor`, `container`), never its
contents' count. An abbreviation is cut as short as it stays unambiguous — `conf`, not `config`.
Where a tool mandates the name, the tool wins: Cargo's `tests/` and `examples/`, sbt's
`src/main/resources` and `src/test`, XDG's `~/.config`. The accepted prices of `doc` over
`docs`: SECURITY.md stays at the repository root (GitHub's community-health lookup reads only
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
The workspace's writability is the user's per-launch authority decision (`--write`).
In a writable mode, the workspace is untrusted output: protect implicit host execution
paths, but keep ordinary project files writable, because editing them is the purpose
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
