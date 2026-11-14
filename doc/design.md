# Design decisions

What was decided and must not change silently:

- the words the documents share;
- the standing decisions, recorded so they stop being reopened;
- the properties verification has to separate;
- the prior art they were reviewed against;
- the principles to preserve.

TODO.md lists what remains to do, and SECURITY.md states the security model.

## Terminology

The documents share these words. Each word is defined in the document its entry names, and listed
here once:

- **workspace** — the host directory tree the launcher exposes to the sandbox: one directory, and
  later the directories `--add-dir` adds (`TODO.md`).
  - The tools around the launcher use the word for the directory a tool opens and acts in: Codex's
    `--sandbox read-only|workspace-write` and "the primary workspace", Antigravity's `--add-dir`
    ("a directory to the workspace"), VS Code's workspace and Workspace Trust.
  - **workspace root** — the directory the launcher starts in. The launcher mounts it at its own
    path, and it holds `.ko-agent-sandbox`. The root's path identifies the workspace: the id, the
    hash, the state directory and the trust entries.
  - **workspace mode** — how the sandbox's writes reach the workspace, selected by
    `--workspace=read-only|live` (`staged` in `plan-staged.md`). Each value names where writes
    land, or that they land nowhere.
    - Like `--egress=` and `--clipboard=`, the option names the thing and takes its mode.
    - The option never takes a path. The workspace root is the current directory, and `--add-dir`
      adds directories, as it does in Claude Code, Codex, Antigravity and Copilot.
    - The option is not `--project=`: Antigravity's `--project` takes the ID or name of a project
      of its own.
- **project** — always another system's concept, never the launcher's directory: sbt's
  `project/`, a Gradle multi-project build, a JetBrains project, Claude Code's project settings,
  the agents' `projects` keys and trust lists.
  - A workspace holds one or more projects or repositories, or none. The launcher selects the
    workspace's boundary rather than inferring it from a build or a repository.
- **sandbox** — the container the agent runs in, rootless, as `nonroot`. SECURITY.md describes its
  boundary.
- **proxy** — the egress proxy, one per session in its own container. Every request of the session
  leaves through it (`egress-proxy.md`).
  - Under `--run-on-host`, a host proxy runs beside it for each program and build directory, kept
    across the launch's commands, or for each command under Maven. A host proxy has rules of its
    own: `deny defaults`, the program's Maven Central host, and the file
    `.ko-agent-sandbox/run-on-host/<program>/egress/rule` (`run-on-host-internals.md`, "The
    command's egress proxy").
  - **rule, ruleset, profile** (`egress-proxy.md`):
    - A rule is a line of the workspace's `.ko-agent-sandbox/egress/rule`.
    - The ruleset is what a launch enforces: the defaults, the profile and the file resolved
      together. Every start prints it.
    - A profile is one of the three `--egress=` treatments.
    - Under `--run-on-host`, a profile is also a Seatbelt profile, the generated sandbox a host
      command runs under. Each document names which kind of profile it means.
  - **grant word** — what a rule permits at its URL: `tunnel`, `read`, `git-fetch`, `method=`
    (`egress-proxy.md`, "The rule file").
  - **tunnel, inspected** — the two treatments of an allowed host (SECURITY.md, "Reading without
    being able to write"):
    - A tunnel leaves the application traffic opaque after the TLS identity check.
    - On an inspected host, the proxy terminates TLS and decides each request against its grants.
    - Use `tunnel` for the grant and the host treatment in code and output.
    - Keep `opaque` for application traffic the proxy does not decrypt or inspect. A CONNECT tunnel
      can also carry inspected traffic, so the transport description needs that distinction.
- **boundary directory** — `.ko-agent-sandbox`. The launcher reads it on the host before launch,
  and it is unwritable in every workspace mode (SECURITY.md, "Why the rules are per workspace, in
  the workspace, and read-only").
- **FUSE backend** — `ko-agent-fs-fuse`, the FUSE daemon whose mount the workspace is shared
  through. It refuses the Git entries and links a session must not write
  (`../ko-agent-fs/fuse/doc/architecture.md`). The other workspace backend is the BPF backend
  (`bpf-lsm-cgroup.md`).
- **launch** — one invocation of the launcher for one workspace, from its command line to the
  sandbox's end. The run and the session are its two views.
- **run** — the launch as the host sees it: the objects created for it.
  - The two networks and the proxy and sandbox containers are removed when the run ends.
  - The `run-<suffix>` directory holds the run's mount sources: the inspection leaf and its key,
    the CA, the assembled instructions, the JDK trust files and the resolved file rules. A later
    launch or a reset sweeps it.
  - The run's audit log is written per run and kept until pruned (`egress-proxy.md`, "Audit what
    has been allowed or denied").
- **session** — the same interval seen from inside: the agent's time in the sandbox container, what
  it can reach, and what outlives it. Examples are the agent state kept across sessions, concurrent
  sessions of one workspace, and what this session may do.
- **launcher** — the program run on the host: the jar, or the native image built from it. The
  launcher builds the images, creates a run's objects and keeps its state under the host's state
  directory ([README.md](../README.md#reference)).
- **reaper** — the detached shell the launcher spawns before it execs podman
  (`SandboxLifecycle.scala`).
  - The reaper waits for the sandbox container to stop. The reaper then removes the proxy container
    and the networks the run created.
  - A launch that stays resident, on Windows or after a failed spawn, removes those objects itself.
- **clipboard relay, microphone relay, runner** — host processes that answer requests the sandbox
  makes through a FIFO under its `/tmp`, never through a listener. "Broker" is reserved for the
  credential sense ("No general capability broker", "Credential brokering at the egress proxy").
  - The clipboard relay copies between the host clipboard and the sandbox (SECURITY.md,
    "Clipboard").
  - The microphone relay, under `--audio=mic`, forwards the host microphone into the sandbox's audio
    server while a process there records (SECURITY.md, "Mic"; `mic.md`).
  - The runner, one per session, dispatches each host command and owns the processes it starts
    (`run-on-host-internals.md`).
- **shim, supervisor, command** — under `--run-on-host`:
  - The shim is `ko-sandbox-run-on-host` inside the sandbox. The shim sends one command to the
    runner.
  - The supervisor is the launcher process the runner spawns for that command on the host. The
    supervisor runs the program under its Seatbelt profile.
  - A command session is the supervisor's own record of that one invocation. The command session
    sits beside the runner's session for the launch (`run-on-host-internals.md`, "The command's
    lifetime and environment").
  - The leader is the process `RunOnHostSession.registeredSpawn` starts for a command, a proxy, an
    sbt server or a mill daemon's starter. The leader leads its own process group, registers the
    group and publishes the exit of what it ran.
  - The lock holder is the process `RunOnHostSession.lockedSpawn` starts. The lock holder takes the
    build lock and execs the supervisor, which keeps holding the lock.

## Standing design decisions

Each decision says what is fixed and why.

- A named revisit condition records the anticipated reason to reopen a decision.
- Without one, reopening a decision takes a new requirement, or evidence that an assumption or
  security argument the decision rests on no longer holds. Nothing less reopens a decision.

### No richer rule format

The rules stay three fixed profiles over one file, `rule`, in the grammar that `doc/egress-proxy.md`
spells out:

- `allow` and `deny` lines naming URLs;
- a few fixed grant words;
- no pattern except the taking-away subtree;
- no open vocabulary;
- no profile per provider set: a launch selects its providers with `--model-provider`, over the
  same three profiles.

The model is a small part of OpenBSD's policy languages, chosen as precedent, not as a
compatibility target:

- PF evaluates rules in textual order, and the last matching rule decides. So the restrictive
  ordering puts a broad block before its exceptions.
- relayd applies the same model at the application layer, to HTTP requests by method, path and
  host. relayd reached the model by replacing its own earlier design (the commit below):
  - Until 2014, its HTTP filtering was per-header protocol directives, matched by name with no
    order among them.
  - Reyk Floeter replaced them with linear last-matching `pass`/`block` rules "inspired by pf".
- doas uses the same ordering at a smaller scale: `permit`/`deny`, the last match wins, and no match
  denies. doas is the precedent for keeping the vocabulary this small.

That history is why this grammar has textual order and no specificity precedence:

- A later root `deny` beats an earlier `/api/` allow of the same grant, however specific the path.
  A most-specific-wins rule would allow the request.
- Provider rules follow the same ordering, regardless of where earlier grants came from
  (`egress-proxy.md`, "The rule file", defines their expansion).

The lessons kept:

- The file's order is its meaning: broad restrictions precede their narrower exceptions.
- The resolved ruleset may compile the rules into host and path scopes. That compilation must not
  change their simple ordered meaning.
  - PF keeps the same discipline for its skip steps.
  - Here the tests' plain ordered evaluator holds it: the tests check the ruleset against that
    evaluator over a drawn domain.
- doas's `-C` evaluates the file against a hypothetical command, through the code that would enforce
  it. doas's `-C` is the precedent for the request-level explanation that TODO.md defers. The
  enforcing resolver drives that explanation, never a second interpretation of the file.

What is deliberately not borrowed:

- A path on `deny`: a denial by path fails open against the origin's canonicalization.
  - An HTTP origin, not the proxy, is the final authority on how a path reads.
  - PF's block on a network is safe, because the kernel is the one authority on what an address
    means.
- PF's `quick`, relayd's `match`, and IAM's deny-overrides. Each is a second kind of rule behavior:
  a precedence apart from the order, or a denial that no later line can undo.
- relayd's unmatched-filter default: the profile system takes its place.
- First-match evaluation, as in Squid and nginx, which reads the exception before the rule.
- A wildcard on the granting side.

The decision behind the grammar: the syntax alone decides the file's meaning, not the workspace's
choices. `tunnel` is right there for a workspace to make those choices. Restricting the grammar
further would add no security about what a reviewed workspace may open. Syntax alone means:

- one parser, and one resolver, which the launcher's dry run executes;
- exact hosts, so a grant is enumerable and the leaf certificate can name it;
- a refused launch for every ambiguity.

A URL is the form every comparable project's operator already writes. A path on the granting side
is what every one of those projects has been asked for: the multi-tenant host a workspace adds for
one tenant's content, its own bucket, or one owner on a forge.

- sandbox-runtime's open request names `storage.googleapis.com` and `raw.githubusercontent.com`:
  https://github.com/anthropic-experimental/sandbox-runtime/issues/468
- Copilot's coding-agent firewall accepts a URL entry beside a domain:
  https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-firewall
- coder/boundary has path rules: https://github.com/coder/boundary
- OpenBSD pf.conf(5), relayd.conf(5), doas.conf(5) and doas(1); relayd's move to last-matching
  rules, 2014-07-09: https://github.com/openbsd/src/commit/cb8b0e5645

SECURITY.md has the reasoning ("Adding hosts, not patterns"), and `resolveRuleset` enforces it. The
failure classes kept out are well attested:

- a validator and a runtime that read one configuration differently;
- an allow that silently overrides a deny. Here the later line decides, in the order written, and a
  denial names a host or a subtree whole.

Attested in:

- https://github.com/docker/sbx-releases/issues/410
- https://github.com/anthropic-experimental/sandbox-runtime/issues/434
- https://github.com/anthropic-experimental/sandbox-runtime/issues/122
- https://github.com/anthropic-experimental/sandbox-runtime/issues/154
- https://github.com/anthropic-experimental/sandbox-runtime/issues/432
- https://github.com/stripe/smokescreen/issues/236

Do not add a wildcard on the granting side, a second precedence, a richer pattern language, or
a grant word outside the closed set without a concrete need that outweighs the added attack surface.

The file rules (`file-rules.md`) apply the same model to names. `read-only` and `writable` lines
apply in order over the launcher's defaults, and the last line naming an entry or an ancestor
decides. The lines carry no path pattern beyond `*` within a component:

- A name matches at any depth, as `.git` does. A line anchored at the root would miss a nested
  folder, which the programs read when you open or enter it.
- The workspace policy folds the name as it folds `.git`. The FUSE backend decides each entry at
  lookup, from its parent's context and its own name. A richer language would need a path, which no
  inode stores.
- An outermost-wins or most-specific-wins order would be a second precedence. The ordered form
  already makes `node_modules` the exception with its last line.
- The file rules differ from `egress/rule` in two ways (SECURITY.md, "Adding hosts, not patterns"):
  - They carry one bit instead of grant words.
  - `read-only` may name a path, since the workspace policy, not an origin, decides how a name
    reads.

### No approve-on-miss prompt for a refused host

Codex, Gemini CLI's "sandbox expansion" and Copilot's `allowBypass` answer a refused request with
a prompt to widen the rules. This launcher does not:

- A prompt is a prompt-injection target.
- A grant made through a prompt widens the rules mid-session. That grant is harder to review than a
  line committed to the repository and applied at launch.

The rules stay launch-only. A refusal's `403` body names the step (`RefusalAdvice` in the proxy).
The user then adds the `allow` line to `.ko-agent-sandbox/egress/rule` on the host and relaunches.

- https://github.com/openai/codex/issues/22387 — no DNS inside the sandbox surprised users
- https://github.com/google-gemini/gemini-cli/issues/23875 — network off by default read as
  "sandbox unusable"

### Sign-in

A browser callback to 127.0.0.1 reaches the host, while the agent listens inside the container.
The supported device-code and pasted-code sign-ins need no callback listener exposed to the
host. [README.md](../README.md#running-command) gives each agent’s sign-in steps.

### The image carries no working conventions

A session receives two sets of agent instructions:

- the image's `AGENTS-SANDBOX.md`, which says what a workspace cannot know about itself;
- the launcher's "What this session may do", which a workspace must not be trusted to declare.

How an agent writes, codes and uses git is each workspace's choice. That choice goes in the
workspace's own instruction files, which each installed agent reads without the launcher's help
([agent-settings.md](agent-settings.md#adding-project-instructions)). The image's file loads
unconditionally, for `claude` from the managed-policy location. A workspace could add to
conventions placed there, but never drop them.

A session can edit the workspace's instruction files, and a later session reads the edit. The
launcher does not prevent that: instruction files change no enforcement.

### No following symlinks at sandbox setup

The launcher refuses the launch when any of these is a symlink: `.ko-agent-sandbox`, an entry of it
(`egress`, `file` or `run-on-host`), or a file inside an entry (`boundaryDirRefusal`,
`ruleDirectoryRefusal`, `RunOnHostPrereqs.readProgramRules`, tested). The workspace policy refuses
to serve a workspace whose `.git` is a symlink. The workspace policy keeps a `.git/hooks`
symlinked to a directory inside the workspace read-only instead
(`../ko-agent-fs/policy/doc/git-metadata.md`, "Relocated hook directories").

- The launcher reads the rules on the host. So a repository-controlled link would choose which host
  file the launcher reads as this workspace's rules.
- Following the link would make the protected paths depend on where the link points at launch
  time.
- The launcher's refusal is loud, names the path, and comes before the launcher creates anything.
  So setup writes nothing through a pre-seeded link (tested: "a refused symlink form leaves no
  artifact through the link").
- The workspace root itself is `toRealPath()`-canonical before any of this.

Prior art for both failure cases, a sandbox that crashed mid-setup on a symlink, and setup code
whose mount-target creation wrote through a symlink to paths outside its root:

- https://github.com/anthropic-experimental/sandbox-runtime/issues/221
- https://github.com/bazelbuild/bazel/issues/28515

The cost:

- A workspace whose `.git` is a symlink cannot be sandboxed writable as-is.
- A workspace with a symlink at or inside `.ko-agent-sandbox` cannot be launched.
- The user of such a workspace replaces the link with a real directory or file first.

Accept that cost rather than following links.

### No repository-controlled host executable resolution

The launcher resolves `podman`, `getenforce`, `stat` and the clipboard programs through `PATH`
entries that are absolute **and** outside the workspace (`HostCommands.findOnPath`). The reaper
receives the resolved path as an argument. So those invocations consult neither `PATH` nor, on
Windows, CreateProcess's implicit current-directory search.

- The `sh` scripts the launcher prefixes with `HostCommands.withScriptPath` find what they run
  through a fixed `PATH` of system directories (`ScriptPath`).
- `--run-on-host` starts the macOS programs it observes processes with, `ps`, `pgrep` and
  `lsof`, by absolute path (`RunOnHostSession.HostProcesses`). The launcher starts `/bin/kill` and
  `/usr/bin/sandbox-exec` by absolute path too.

Absoluteness is not consent, and a repository must never supply the host's container runtime. So
both halves of that filter are necessary; `findOnPath`'s comment explains why. Prior art:

- https://github.com/docker/sbx-releases/issues/392

### No command-name safe lists

`git`, `npm`, `python`, build programs, MCP servers, and other "normal" programs can execute
repository-controlled behavior. The outer container and network boundary should contain them all,
instead of trying to classify command names as safe.

### No generic "GET is safe, POST is dangerous" rule

Inspection enforces method and path grants; it does not establish that a request is harmless.
SECURITY.md explains the limits ("Exfiltration through allowed network traffic").

### No per-repository `GitRead(repository)` grant

The ruleset names destinations, and its grant words name operations. Nothing names a repository:
public reading is meant to be broad, and the sandbox holds no credential that a finer grant would
attenuate. SECURITY.md has the argument and the one condition that would reopen this decision ("Why
the ruleset is not a capability system").

### No masking of secret-named files in the workspace

Gemini CLI, Codex CLI, clampdown and sandbox-runtime hide or empty `.env`, `.env.*`, `*.pem` and the
like inside the sandbox. Here the boundary is different: the workspace is hostile data, and nothing
credentialed goes in (SECURITY.md, "Credential theft"). A name mask leaves that boundary where it
is:

- A mask hides one class of files by name. A secret under any other name, in `config.yaml`, or in
  git history stays visible.
- A mask applies to every workspace to protect the few that store a credential under such a name:
  - a default `.env` mask breaks tests that read `.env`;
  - the first `-name .env` removes the protection;
  - the user who commits a credential is the one least likely to review a third boundary file in
    `.ko-agent-sandbox`.
- Password-protected containers (`*.p12`, `*.pfx`) are inert without the password, and these
  formats have no standard password file or environment-variable name.

Keep the rule procedural: a credential in the workspace violates the operating model, and keeping
it out is the user's job. A `deny` of the forge in `egress/rule` removes one way to use a forge
token left there, not the risk: every allowed host is a possible recipient of what the sandbox
holds.

### A `--run-on-host` limit, not a stricter form

Every session gets the same file rules, with `writable node_modules` among the defaults. Under
`--run-on-host`, a host command can carry a listed file out of `node_modules` (`file-rules.md`,
"Under `--run-on-host`", states the limit). The limit is a cost of `--run-on-host`, like the
workspace that a host command writes under `--workspace=read-only` (SECURITY.md, "Run on host").

The alternative weighed is a strict form under `--run-on-host`, in which a `writable` line only
cancels an earlier `read-only` line of the same name. The strict form closes the limit, and costs:

- npm would install a package without a file of a listed name that the package carries, with a
  warning. The measured packages carry such development leftovers (`file-rules.md`,
  "Measurements").
- `writable` lines would hold in one kind of session and not the other: a second meaning of
  `writable` for the reader to keep in mind.
- A session with `--run-on-host` and a session without it could not share a FUSE mount, since
  their rules differ.

Revisit when `../src/probe/seatbelt-semantics.sh` E13-E16 find a rule that refuses a move out of
`node_modules` but leaves npm's renames and `rmdir` there. Such a rule would close the limit.

### Read-only mounts over the protected entries are not a backend

The cheapest writable session would bind the workspace directly and mount `.git/config`,
`.git/hooks` and `.ko-agent-sandbox` back over themselves read-only. A read-only bind mount
protects the path it is mounted at, from the moment of the launch. That leaves these gaps:

- A host program that replaces a mounted file takes the protection with it. A rename over the file
  is how `git config` and most editors write. No mount prevents this.
  - Measured on a macOS podman machine: about two seconds later, the session writes the host's new
    file through the writable parent, while the mount stays listed in the session's mount table.
- The mounts are chosen at launch, for the repository at the workspace root.
  - A repository nested deeper, by the host or by the session, has no mounts. A repository the
    session creates mid-session cannot get any.
  - A policy that judges each operation protects every repository's entries at any depth. The
    backend of `bpf-lsm-cgroup.md` does this, and so does the FUSE backend.
- On an NTFS volume with 8.3 names, `.git` is also `GIT~1`, and `.ko-agent-sandbox` is also
  `KO-AGE~1`. A path through the short name does not pass the mount.
  - Measured on Windows Server 2025 with podman 6.1.0: appends to `.git/config` and
    `.ko-agent-sandbox/egress/rule` and a `touch` under `.git/hooks` fail with
    `Read-only file system`. The same three through `GIT~1` and `KO-AGE~1` succeed and reach the
    host's files.
  - Closing the gap takes a second mount per guarded entry, at a name the volume generated, read
    from the host at launch. The first two items apply to that mount too.
- A workspace with no repository needs an empty directory mounted at `.git`. An absent
  `.ko-agent-sandbox` needs one as well. Without them, the session could create either.
  - The container runtime creates those mount targets in the workspace. No launch otherwise makes
    that change to the user's tree (SECURITY.md, "Silent changes to what you own").
  - On Windows, the created `.git` has a short name of its own. Through that short name, the
    session lays out the repository that the mount was there to prevent.
- On an SELinux-enforcing host, the container reads a bind mount only under `:Z`, which relabels
  the workspace tree recursively.

What serves instead:

- `--workspace=read-only` is the read-only session, with no policy to enforce.
- The probes that need a plain bind mount as their writable control run one outside the launcher
  (`../ko-agent-fs/bench/plain-bind.sh`).
- `../ko-agent-fs/fuse/doc/verification-log.md` measures the FUSE backend's cost ("The cost of a
  path walk").
- `bpf-lsm-cgroup.md` is the backend that mounts the workspace directory itself and judges each
  operation in the kernel instead: `--workspace=live,bpf` on the podman machines.
- `bpf` is the default backend (`bpf-lsm-cgroup.md`, "Launches").

### No DLP/entropy/LLM firewall

Such a firewall would be incomplete against encoding, timing, allowed-host selection and
protocol-specific channels. Such a firewall would also add false positives and another complex
policy engine. Destination restriction remains the primary exfiltration control.

### No profile that allows hosts no rule names

Every profile reaches the hosts its ruleset lists and nothing else. A rule file cannot grant a
pattern (SECURITY.md, "Adding hosts, not patterns"). A profile that reads every public host that no
line denies is rejected:

- Inspecting a host that no rule names needs a leaf issued at its first connection. That needs a CA
  key inside the proxy container, the process facing the internet.
  - A compromised proxy could then issue a certificate for an opaque tunnel host and intercept
    model traffic or provider tokens.
  - With the CA key on the host, the proxy holds one leaf naming the inspected set and can issue
    nothing.
- Such a profile, selected on the launch command line, leaves no trace in the repository. A
  reviewer of `.ko-agent-sandbox/egress/rule` sees a narrower policy than the session runs.
- Work whose hosts cannot be listed in advance has a form that the rule file can list: a fetcher
  the user runs, granted `read` by one line, which fetches the URL its query names.
  - The fetcher then holds the policy that the proxy cannot apply to the URL: the private-address
    refusal and any per-domain denial.
  - The audit log records the fetcher's URL, with the target in the query.

### No upstream-proxy discovery, exclusions, chaining or negotiated authentication

`HTTPS_PROXY` is the whole upstream-proxy contract (`egress-proxy.md`, "Through an upstream
proxy"). Each of these stays out of it for a reason of its own:

- OS proxy discovery and PAC files: ambient or executable host state would choose a launch's
  transport, and that choice would appear nowhere the user reads.
- `NO_PROXY` and per-origin direct exceptions: each is a second path around the upstream
  transport, and one that a failure could widen.
- Hostname-form upstream CONNECT: some upstream proxies allow only a hostname authority and refuse
  a numeric one.
  - The launcher reports that incompatibility, and never works around it by sending the name.
  - Given the name, the upstream proxy would resolve the origin itself. That severs the proof that
    the address checked for private ranges is the one reached. The upstream proxy's resolver would
    also join the trusted computing base.
- More than one hop, SOCKS, NTLM, Kerberos and Negotiate: each adds a handshake, an identity broker
  or a chain-attribution question that no present deployment needs. A static `Basic` value is the
  only authentication.
- A credential outside the variable's own userinfo: the launcher never parses the credential, so
  the credential is in no argument, banner, log line or error, and the proxy is its one reader. A
  second source would need a second reader.

### WebSocket only at a path that a line names

Considered: relaying a WebSocket on any inspected host after checking the upgrade request's
headers. Chosen instead: the `upgrade=websocket` grant, at a path that a line names
(`egress-proxy.md`, "The rule file"). Claude Code's `/voice` streams over a WebSocket to
`api.anthropic.com` (`mic.md`, "Claude Code"), so inspecting that host without the grant would end
`/voice`.

- A WebSocket matters only on an inspected host; on a tunnel it passes as bytes.
- After the `101`, the proxy relays decrypted bytes without applying method and path grants. That
  is a third treatment beside inspected and tunnel, and a line confines it to the path that a
  feature needs. The launch's widening report shows a workspace's line.
- The relay starts only after a `101` whose `Sec-WebSocket-Accept` matches the request's key. So
  up to the switch, the connection still carries one request that the proxy reads (`SECURITY.md`,
  "Reading without being able to write").
- A grant at a host's root would let any client move its traffic into streams that the log shows
  as one line each. The defaults grant at a path, never at a root (`plan-tls-inspect-agents.md`,
  "Guarantees").
- The Codex CLI's built-in provider opens a WebSocket to its model host, and falls back to HTTP
  after the refusal (`defaults/model-provider/openai` has the measurement). Its hosts take no grant
  while the fallback works: with the grant, the log would show one line per connection in place of
  a line per request.
  - A `403` costs each new Codex process about seven seconds and seven refused upgrades before the
    fallback. So the proxy answers a refused handshake at `chatgpt.com`'s
    `/backend-api/codex/responses` with `426`, on which Codex falls back at once.
  - That `426` breaks RFC 9110's rule that a `426` names, in `Upgrade`, a protocol the server would
    accept: the proxy accepts none, and sends no `Upgrade` field.
  - The host and path select the `426`, not the User-Agent, which differs by Codex's entry point
    and release. `/v1/responses` on `api.openai.com` keeps the `403`, since other OpenAI clients
    use it, so Codex under an API key still spends the retries.
  - The client's `supports_websockets = false` cannot be set for that provider: codex-cli 0.169.0
    keeps a built-in provider's routing and accepts only `model_catalog_url` from an override
    (`codex-rs/model-provider-info/src/lib.rs`, `merge_configured_providers`).
- Copilot CLI opens a WebSocket at its plan host's `/responses`, and after the `403` sends the
  turn over HTTP at once (`defaults/model-provider/github` has the measurement). Its hosts take no
  grant, for Codex's reason above.
- The binaries of the other installed agents hold no `wss://` literal for a model host.
  - `claude` holds one for its Remote Control bridge, `bridge.claudeusercontent.com`, which no
    default rule allows.
  - A URL built at run time escapes that search.

Revisit the Codex or Copilot hosts' missing grant if one of that agent's turns fails on the HTTP
fallback, or the provider drops the HTTP path. Remove the `426` once Codex gains an HTTPS-only
option (openai/codex #27381) or stops retrying before the fallback (#19821), and a measurement shows
that a `403` costs no retries.

### No inspecting every allowed host

The defaults inspect an agent's model hosts once the agent's client passes a measurement over an
inspected connection (`plan-tls-inspect-agents.md`, "Measurement"). That is no reason to terminate
TLS everywhere and drop `tunnel`. Terminating TLS everywhere would have these costs, the most
serious first:

- It would break the agents whose clients an inspected connection cannot carry.
  - A certificate-pinned client cannot be terminated at all.
  - An HTTP/2-only client needs a relay that the proxy lacks, and a WebSocket client needs a line
    for each path it streams at.
  - The measurement finds these clients one agent at a time. Each provider's defaults file records
    the result beside its lines.
- It would take away a workspace's way to keep a host out of the proxy's plaintext view: a
  `tunnel` line of its own, or a defaults tunnel restored under `deny defaults`.
  - For a measured model host, the defaults accept that view without a per-launch consent
    (`plan-tls-inspect-agents.md`, "Outcome").
  - SECURITY.md has the exposure ("Not defended", "What is inside TLS").
- It would gain no substitution at a signed cloud API, where no header holds a value to
  substitute, while costing every request a handshake ("Credential brokering at the egress
  proxy").

Revisit per agent, with that agent's measurement (`plan-tls-inspect-agents.md`, "The agents, in
order").

### No HTTP query endpoint on the proxy

Considered: the RFC 9110 request `OPTIONS * HTTP/1.1` with `Max-Forwards: 0` and a custom query
header, which the live proxy would answer with the ruleset in force. Rejected:

- Every consumer already gets that answer from the proxy's own `--print-ruleset` dry run:
  `--egress-effective`, the launch banner and `KO_AGENT_SANDBOX_EGRESS_RULESET`.
- The launcher cannot use a live query anyway. The rules must be validated and the leaf issued
  before the proxy container exists, since the leaf is a mount fixed at `podman create`.
- The endpoint would add a second parsed request format at the enforcement point, against its
  CONNECT-only, one-request rule, for information already delivered.

`Max-Forwards` itself creates no obligation here. `Max-Forwards` binds a proxy that *forwards*
OPTIONS/TRACE, and this proxy never does:

- The proxy layer refuses every request that is not CONNECT.
- Both methods are refused inside inspected tunnels.
- An opaque tunnel is not an HTTP hop at all.

The run-on-host supervisor does send that request, and the request is no query endpoint:

- The proxy parses nothing of the request and refuses it, as it refuses any request that is not
  CONNECT. The supervisor reads the refusal itself.
- After a write to the audit log failed, every refusal is a `403` whose `Proxy-Status` names that
  reason (`SECURITY.md`, "Egress proxy"). The log cannot record the reason, and a program need not
  print it (`run-on-host-internals.md`, "Refusals").
- The supervisor sends no CONNECT, so that a proxy that is still logging records no refused host
  for it.
- The supervisor sends `Max-Forwards: 0` for a recipient that is not this proxy
  (`RunOnHostProxy.unwritableProxyLog`).

### Proxy-Status on the proxy's own responses

The proxy puts RFC 9209's response field on every response it generates itself, and on none that it
relays. The proxy generates the responses to a refusal, a malformed request, a failed origin leg and
the connection limit. The field reads
`Proxy-Status: ko-agent-egress-proxy; error=<type>; details="<why>"`.

- `error` is the registered proxy error type. The field's presence tells a client that the origin
  did not send this response.
  - The ruleset's refusals are `http_request_denied`.
  - A refusal or failure with a more specific registered type uses that type
    (`destination_ip_prohibited`, `dns_error`, `tls_certificate_error`).
  - The status codes stay the proxy's own where RFC 9209 recommends another. A refusal is a `403`
    whatever its type, and `ko-sandbox-egress-check` exits 1 on that `403`.
- `details` is the audit line's `<why>`, which is also the body's first line where there is a body.
  The next step stays in the body alone: it is a sentence for the agent, not a diagnostic.
  - The `500` names the exception's class and leaves its message to the log. The message of an
    exception nobody planned for may hold what the sandbox should not read.
  - The `503` has no `details`: `connection_limit_reached` is the whole reason.
- The reason goes in a header as well as the body, because clients that discard a failed CONNECT's
  body still show its header section (`curl -v`). A program can also read one field, where the body
  is text for people.
  - `ko-sandbox-egress-check` prints the field before the body.
  - Some responses have no body: the `400` to a malformed CONNECT, the `500`, the `503`, and any
    answer to a `HEAD` inside the tunnel (RFC 9110 §9.3.2). For them, the field is all the client
    receives.
- Unlike Via ("No Via header", below), the field reaches the client alone, never an origin.
- The member is the image's name, not a deployment's, against RFC 9209's advice: a session has
  one proxy, and the refusal body already starts with that name.

### No Via header

The inspected forwarding omits Via, a deliberate standards deviation: RFC 9110 §7.6.3 makes Via a
MUST for an intermediary.

- Via exists for loop detection and protocol-capability discovery across proxy chains. This hop is
  a single, terminal one: it forwards to the origin and never to another intermediary, so a loop
  through it cannot form.
- Here, Via would stamp the proxy's presence and software onto every inspected request for every
  origin to read. This design sends that metadata nowhere, and some origins vary caching behavior
  on it.
- The client side is not deceived: it addressed the proxy by CONNECT.
- The upstream proxy that `HTTPS_PROXY` selects changes none of this (`egress-proxy.md`, "Through
  an upstream proxy"):
  - The CONNECT that opens a tunnel through the upstream proxy is this proxy's own request as a
    client, not a forwarded one. That CONNECT carries no Via either.
  - The sandbox's requests pass inside that tunnel unchanged.
  - A loop still cannot form, since nothing routes into the per-run network.

Revisit if this proxy ever forwards a request to another intermediary.

### No per-agent violations channel

sandbox-runtime annotates the agent's context with a `<sandbox_violations>` block. Copilot's
coding-agent firewall reports a blocked request with the address and the command that made it.

- Each channel needs integration per CLI release.
- The `403` body already appears in the tool output every agent reads, at the enforcement point, so
  the body needs no integration.

Revisit if an agent stops showing its tools' output to the model, which is what the body's route
relies on.

### No general capability broker

This architecture deliberately avoids most cases in which a broker is useful, by keeping
valuable credentials outside the sandbox.

A capability layer would create a second security-policy language and another enforcement point,
while it would reduce authority little under this operating model. Prior art proposes exactly this
design: a host-side MCP auth broker or gateway that holds credentials the agent container never
sees. That design solves a real problem for workflows that need credentialed MCP servers, a
requirement this project's operating model deliberately avoids:

- https://github.com/mattolson/agent-sandbox/issues/122

`--egress-cred` is inside this decision, not an exception to it. `--egress-cred` moves a value the
user forwards out of the sandbox and adds no grant word. What the value may do stays with its
issuer's scope and the ruleset (SECURITY.md, "Why the ruleset is not a capability system").

### Credential brokering at the egress proxy

`--egress-cred` keeps a credential the user names out of the sandbox and the host commands
(egress-proxy.md, "Brokered credentials"). Every comparable project that holds a credential
converged on one design. This launcher keeps that design's recurring rules: a placeholder inside,
one host per secret, and a rewrite in a declared header or one named parameter, never in a body or
a response.

- Claude Code on the web: the real GitHub token in a proxy outside the VM
  (https://code.claude.com/docs/en/cloud-environments);
- Codex CLI: a dummy of the same prefix and length in the child's environment, swapped only for
  the bound GitHub hosts (`codex-rs/network-proxy/src/credential_broker.rs`);
- Docker Sandboxes: a `proxy-managed` sentinel, the value in the OS keychain
  (https://docs.docker.com/ai/sandboxes/);
- anthropic-experimental/sandbox-runtime's credential masking (`injectHosts`, its README),
  GreyhavenHQ/greywall's `greyproxy:credential:v1:…` in headers and query alone,
  89luca89/clampdown's auth-proxy container holding the real key.

A forwarded SSH agent's socket is how docker/sbx-releases #121 reached a private repository under a
public-reads ruleset. Brokering protects a value only while no other channel that authenticates is
mounted (SECURITY.md, "Who holds a brokered value").

The binding:

- `--egress-cred` is an option of its own, not a form of `--env`. So a forgotten `@HOST` is a
  refusal, not the value forwarded into the sandbox.
- Like `--env`, the option comes from the command line or the options file, never from a repository
  file: a repository cannot bind a host ([README.md](../README.md#options-file)).
- The option takes no `NAME=VALUE@HOST`, though `--env` takes `NAME=VALUE`:
  - `ps` shows a process's arguments to every user of the host. A launcher that stays resident
    keeps them for the whole launch, and a value typed there is in the shell's history file.
  - The value grammar admits `@`, `:`, `?` and `/`, which would end the value and start the host
    and the place.
  - `NAME=VALUE <launcher> --egress-cred=NAME@HOST` already sets a value for one launch.
- Each binding names one host, which a proxy of the launch must inspect.
  - A binding the proxy cannot substitute is refused at launch, and again at the proxy's start.
  - Otherwise the binding would show as a 401 inside the sandbox, with nothing in the log to
    explain it.
  - A model host that the defaults inspect takes a binding, such as
    `ANTHROPIC_API_KEY@api.anthropic.com:x-api-key` or `OPENAI_API_KEY@api.openai.com`, with a
    fixed header and no lifecycle. Claude Code sends its key in `X-Api-Key`, not in
    `Authorization`, which a binding defaults to.
- The launcher and the proxy compile one grammar object (`CredentialGrammar`), rather than the
  launcher asking the proxy's dry run:
  - The dry run mounts nothing by design.
  - A value handed to the dry run would be one more place holding the secret.
  - `plan-provider-credential-proxy.md`'s management actions must validate before any run exists.

The value travels by pipe and is held in memory alone (SECURITY.md, "Who holds a brokered value"):

- Not a file: a token works from anywhere until it is revoked, and a file under the state root
  reaches backups and outlives a lost reaper. The leaf key is a file, since it serves only someone
  between the sandbox and the proxy.
- Not an environment variable or an argument of a process the launcher starts:
  - Every helper inherits an environment.
  - Other processes of the same user read both (SECURITY.md, "Run on host").
  - On a container, `podman inspect` shows the environment.
  - An agent can persist an environment, as Codex's shell snapshots did (openai/codex #30971,
    #32327). `ProxyContainerTest` checks the persistent volume after a brokered session.
- Not a podman secret, whose default driver keeps it in a file (podman-secret-create(1)).
- Not a `podman exec` writing into the proxy container: the container's root is read-only with no
  tmpfs, and the proxy would take bindings a second way.

Left out:

- Repository scoping, as in Claude Code on the web's "attached repositories" 403. Repository scoping
  needs path knowledge per forge API, a separate increment. SECURITY.md has what the credential
  reaches meanwhile ("Who holds a brokered value").
- Response and body rewriting, and rewriting every occurrence of a token in a query.
  - Broader rewriters recurrently fail by breaking applications that carry tokens of their own
    (docker/sbx-releases #8).
  - A declared header or one named parameter is the durable form.
- Brokering at a tunnel host, where no substitution can happen.
  - The launcher refuses such a binding, such as `AWS_BEARER_TOKEN_BEDROCK` at a workspace's
    `bedrock-runtime.<region>.amazonaws.com`.
- Brokering the agents' own logins:
  - Claude Code's login is an OAuth pair with local expiry bookkeeping and a refresh exchange. The
    proxy would mirror that lifecycle per release.
    - A stolen model token is a nuisance to the account holder. A stolen forge token reaches every
      private repository. Hiding the model token does not pay for a per-release contract.
  - The Codex CLI trusts the CA in `SSL_CERT_FILE`. The CLI's built-in provider opens a websocket
    first, which the proxy refuses on an inspected connection. Codex then falls back to HTTP, and
    its turns complete under a ChatGPT login and under an API key (`defaults/model-provider/openai`
    records the measurement).
  - Which credential may reach a model host is a rule that an inspected host could apply and a
    tunnel cannot (SECURITY.md, "Exfiltration through allowed network traffic"). `TODO.md` has
    that item ("Credential brokering").
- AWS SigV4 re-signing, which sandbox-runtime does. Every AWS login (`aws login`, `aws sso login`,
  a static key) ends in an access key that the client signs with and never sends. So no header
  carries a placeholder.
  - With the hosts as tunnels, the binding is refused at launch. With the hosts inspected, the
    origin answers `SignatureDoesNotMatch`.
  - `doc/cloud-credentials.md` describes what a session forwards instead.
- A keychain or secret-manager resolver on the host (Docker's `gh auth token`, 1Password). The
  binding reads the host environment as `--env=NAME` does, and a resolver is a shell pipeline in
  front of it.
  - AWS is the exception, `--env-aws-cred` (`AwsCredential.scala`). The pipeline it replaces is
    retyped at every login, and the launcher checks what the pipeline cannot: that the set expires.
  - A GCP or Azure resolver can follow on the same terms: one CLI command, forwarded by name,
    refused when what it resolves does not expire.
- Rotation or revocation on exit:
  - The value is in no file for an exit to leave.
  - The issuer's own revocation covers a leak.
  - An automatic revoke needs a provider API call that the launcher does not make.
- Copilot CLI's forge-credential sign-in: `plan-provider-credential-proxy.md`, "OAuth mechanisms".

### No gVisor or microVM isolation layer

Rootless podman is the chosen trade-off between portability and security. Revisit only if
exploitation of the host kernel or the container runtime enters the threat model.

The gVisor issue history also shows that a stronger isolation layer adds compatibility problems of
its own with rootless operation, nesting and mounts. For example, rootless uid mapping breaks
same-uid host file access, the problem that this launcher's `--userns=keep-id` solves. That does not
make gVisor a bad design. The history means that the launcher adds the additional boundary only when
the threat model requires it.

Running more images inside the session is not a second revisit condition. A microVM's guest kernel
would let an image that needs a second uid run unchanged. "Services run as processes, not as
multi-uid nested containers" records what the session offers instead, and which workflows it leaves
out.

The same reason excludes a dedicated podman machine with narrower host shares, and a launch-time
warning about broad shares. Both address container escape, which is outside the threat model.
SECURITY.md has what an escape into the machine reaches ("Container, runtime and kernel escape").

- https://gvisor.dev/
- https://github.com/google/gvisor/issues/9918

### Services run as processes, not as multi-uid nested containers

Under `--nesting=same-uid`, a nested container maps one uid, because `no-new-privileges` denies
`newuidmap` its setuid privilege (SECURITY.md, "No containers inside the sandbox by default").
Stock `postgres` and `nginx` switch to a second uid and fail. A session that needs such a service
runs it as a process bound to 127.0.0.1 (AGENTS-SANDBOX.md, "Containers in here: only if this
session opted in").

A second uid would need one of two things:

- the setuid privilege, which `no-new-privileges` withholds from every process in the session;
- a guest kernel with its own uid range, the layer declined above.

The process has two limits that the design accepts:

- The process serves tests that connect to an address they are given.
  - A test that creates its own container through the Docker API, as Testcontainers does, cannot
    use it.
  - An image that needs a second uid stays unsupported under `same-uid`.
- The service runs under the session's uid. PostgreSQL recommends a separate account, so that a
  compromised server cannot modify its executables.
  - The design does not rely on isolation between session processes. The boundary is the
    container, and every process in it is untrusted.
  - A compromised service reaches exactly what a hijacked agent already reaches.

### No test hook that pauses a launch mid-flight

The FUSE mount's reference count has one state worth attacking: a launch between its `podman
create` and its `podman start`. In that state, the marker and a container that is not running exist
together, and a reap must count the marker (`KoAgentFs`, "The FUSE backend's mount
lifecycle").

Arranging that interleaving at an arbitrary instant would need the launcher to be pausable from
outside, through a variable read on the launch path.

- Such a variable would need to be known, documented in `--help`, and fail closed like every other
  variable.
- The result would be boundary code that carries a hook existing only for a test, on the path that
  decides whether the FUSE backend is mounted at all.

`MountLifecycleTest` provides the same evidence without the hook; its header has how. The test does
not cover an interleaving at some other instant, and a pause hook would not enumerate one either.

### No scheduled or self-triggering verification

`--self-test` runs when a person runs it. It does not run on a schedule, report anywhere, or start
itself after detecting an upgrade. The enforcement happens at the launch that would rely on the
answer:

- today, the FUSE backend's own self-test before every launch under it
  (`KoAgentFs.prepareKoAgentFs`), which refuses the launch when it fails;
- for the staged engine, the stamp that `plan-staged.md` specifies: source, machine, kernel and
  backing filesystem. A missing or mismatched stamp refuses a staged launch.

Both act at the moment the answer matters, rather than at some earlier one. Revisit if an
unattended workflow needs a stale verification detected before its next attempted launch, and a
failed launch is not enforcement enough. A CI failure that a person reads later is still that
enforcement.

### No Stop hook that gates on a ko-review approval

A managed Stop hook could refuse to let Claude end its turn while the working tree differs from
HEAD without a fresh approval or a recorded escalation from a `ko-review` skill (`ko-review.md`).
Rejected:

- The only check a local hook can make cannot tell Claude's changes from the user's own uncommitted
  edits, from a one-line change the user asked for, or from a turn that answered a question. The
  hook would block each stop until the reviewer reviews, spending quota the user did not intend to
  spend.
- Under an egress profile that refuses the reviewer's provider, or before the reviewer is signed
  in, the only way past the block is to record an escalation. That makes the gate a formality.
  Letting the hook pass when the reviewer is unreachable reopens the loophole the hook exists to
  close.
- A managed hook applies to every workspace on the image. A per-workspace opt-in marker would add a
  second mechanism for a workflow that starts only at the user's request.
- Claude skipping a requested review is an instruction failure. The fix belongs in the skill text
  or `AGENTS.md`, not in a hook that runs on every stop.

Revisit if, in use, Claude regularly ends a turn with unreviewed changes after being told to
review, and the instruction fix does not hold. The shape would then be a managed hook with a
per-workspace opt-in marker, still a local check that never runs Codex.

### Host resources are granted by launch options, not variables

A grant of a host resource, such as `--clipboard=<mode>`, `--audio=mic` or `--nesting=same-uid`,
comes from a launcher option, never from a variable. The launcher reads its options from its command
line and from its options file (README, "Options file"), and from no `KO_AGENT_SANDBOX_*` variable.
Every launch prints each grant and each option the file supplies.

- A variable that a shell profile exports reaches every child process: IDE terminals, scripts, and
  a launcher run inside a session. That launcher would take the session's
  `KO_AGENT_SANDBOX_NESTING=same-uid` as its own input. An option reaches only the launch that names
  it, on its command line or in its file.
- The file is under the configuration roots, `XDG_CONFIG_HOME` and `%APPDATA%`, rather than under
  the state root, since the user writes it. The launcher refuses a file inside the workspace, as it
  refuses a state root there: a repository must not choose its own launch's grants.
- The launcher refuses each variable that an option replaced, when the variable is in its
  environment, and names the option (`AgentSandboxLauncher.ReplacedVariables`). The launcher does
  not ignore a profile that exports such a variable.
  - The launcher refuses `KO_AGENT_SANDBOX_NESTING`, `_SESSION_START` and `_CLIPBOARD` on the host
    alone. The launcher sets them inside the sandbox, so a launcher run in a session inherits them.
- The launcher sets `KO_AGENT_SANDBOX_*` variables only inside the sandbox, for the agent and the
  image's scripts to read. No variable with the prefix configures the launcher, and `--env` refuses
  the prefix (`CommandLine.RefusedForwardPrefix`).
- Every option the file can hold has a value that returns it to its default for one launch.
  - A closed choice names its default, and keeps refusing an empty value.
  - A script's unset variable produces an empty value: `--workspace=$MODE` would otherwise launch
    `live`.

### The launcher's text is ASCII

Every string in the launcher's sources is ASCII, except characters it matches or writes into a
script. `AsciiTextTest` enforces this and lists those characters. A Windows host shows any other
character wrong wherever the text goes. Some of that text is consent or refusal text, which a
reader must be able to trust verbatim. Measured on Japanese Windows (Windows Server 2025):

- In Windows Terminal, Java writes `System.out` in the console's code page, 932: `—`, which code
  page 932 lacks, prints as `?`.
- Redirected to a file, Java writes in the system's code page (`native.encoding`, MS932), while
  podman's lines in the same file are UTF-8.
- Written as UTF-8, `→—` shows in Windows Terminal as `竊停・`.

ASCII is the same bytes in every one of these encodings. The launcher prints text it passes along
as it is, such as a path with a non-ASCII name or podman's own lines.

Revisit if Windows consoles default to code page 65001 (UTF-8), or if the launcher sets the
console's code page itself (`SetConsoleOutputCP`). Every process attached to that console would
then share that code page.

## The properties verification has to separate

Conflating these properties makes verification look larger than it is.

- **The code's own logic** depends on neither of the others. The privileged dev rig settles it once,
  on whichever host a developer has (`../ko-agent-fs/doc/testing.md`).
- **The kernel** is not one kernel. Each podman machine runs its own: Fedora CoreOS on macOS, and a
  Microsoft build on Windows. Native Linux runs the user's own kernel.
  - The FUSE mount already depends on what a kernel offers. The FUSE backend refuses to mount at all
    when `init` cannot negotiate `AUTO_INVAL_DATA` (`../ko-agent-fs/fuse/doc/architecture.md`).
- **The share**, and the backing under it: the host's workspace as it arrives inside the machine,
  over virtiofs on macOS and over the WSL share on Windows.
  - On native Linux, the upper varies instead. The upper there is a named volume stored in the
    host's container storage: btrfs, ZFS, XFS or overlay. Everywhere else, the upper is the
    machine's own ext4.

Every case asserts a premise behaviorally, at the layer the product uses it. A case never asserts a
version, a mount option or a declared feature.

- The virtiofs premise is already recorded under this rule
  (`../ko-agent-fs/fuse/doc/verification-log.md`).
- The rule keeps the suite indifferent to *why* an environment changed. A podman upgrade, a
  recreated machine, a host OS update and a changed storage driver each appear to the suite as a
  changed behavior, and no case has to anticipate which.

## Prior-art references worth retaining

These are comparison points for future decisions, not dependencies. Each decision links inline the
specific issues it rests on; these are the broader sources.

- Docker AI sandboxes — microVM isolation, direct-vs-clone workspace models:
  https://docs.docker.com/ai/sandboxes/ https://docs.docker.com/ai/sandboxes/security/isolation/
- The workspace root mounted at its own path (`SandboxWorkspace.mountPathOf`) — what the two
  container sandboxes that do the same ran into, read in September 2026:
  - Gemini CLI mounts the unresolved path while its tools resolve real paths. So a symlinked
    workspace root (macOS's `/tmp`) fails its own lookups and splits its sessions. This launcher
    mounts the real path only.
  - Docker Sandboxes spells a Windows drive `/c/…` and serves `\\wsl.localhost` workspaces, where
    `chmod` and `symlink` fail. Docker Sandboxes' users asked for a remapped path, because the host
    path discloses the username and the layout. A maintainer answered in May 2026 that the host path
    serves scripts expecting it, and that the default may change.
  - Antigravity confines commands on the host instead, so its paths are the host's by
    construction. Hosted agents and VS Code dev containers use a fixed path.
  - Open: a second bind at the launch spelling, for an IDE that opened a symbolic path; and
    `/mnt/<drive>` against those tools' `/c/`.

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
- OpenAI's Codex Windows sandbox:
  - Proxy variables cannot enforce network isolation.
  - Dedicated Windows users let firewall rules cover spawned commands, while host ACL changes carry
    setup and policy-update costs.
  - The account does not establish protection for guarded directories created during execution.
    That protection is the Windows host-command requirement in
    ["Why only macOS"](run-on-host-internals.md#why-only-macos).

  https://openai.com/index/building-codex-windows-sandbox/
- Docker AI sandboxes' upstream-proxy configuration — the comparison point for `HTTPS_PROXY`:
  https://docs.docker.com/ai/sandboxes/configuration/upstream-proxy/
- Stripe Smokescreen — mature egress-proxy prior art. Smokescreen's ACL-bypass advisories are
  permanent regression inputs, in the proxy's `AgentEgressProxyTest`:
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
  `codex.network_proxy.policy_decision` reasons, Copilot's firewall report. Here the reasons are
  fixed and launcher-owned, since the ruleset allows hosts, not patterns:
  https://github.com/anthropic-experimental/sandbox-runtime
  https://github.com/openai/codex/tree/main/codex-rs/network-proxy
  https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-firewall

## Naming

Directory names follow the terse Unix tradition where the choice is free:

- An abbreviation drops the plural marker with the rest of the word (`doc`, like `bin`, `lib`,
  `src`). A full word names the directory's role in the singular (`probe`, like `spec`, `vendor`,
  `container`), never its contents' count.
- An abbreviation is cut as short as it stays unambiguous: `conf`, not `config`.
- Where a program mandates the name, that name is used: Cargo's `tests/` and `examples/`, sbt's
  `src/main/resources`, XDG's `~/.config`.
- Where a grammar spells it, that spelling is used: the proxy's `defaults/` is the `defaults` of
  `deny defaults`.

Program, plugin and variable names say where they work:

- `ko-sandbox-*` and `KO_SANDBOX_*` name what works only inside the image (`ko-sandbox-entrypoint`,
  `ko-sandbox-egress-check`).
- `ko-agent-sandbox` and `KO_AGENT_SANDBOX_*` name the launcher and the project.
- What also runs on a host carries its own name. That name is the workflow's, not a component's, so
  that another component can join. For example, `ko-review`'s skill asks for `codex` or `claude`,
  and the name is not `ko-codex`, so that `agy` can review too.

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
The workspace's writability is the user's per-launch choice (`--workspace`).
In a writable mode, the workspace is untrusted output: protect implicit host execution
paths, but keep other workspace files writable, because editing them is the purpose
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
