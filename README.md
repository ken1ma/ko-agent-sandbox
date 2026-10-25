# A sandbox container for AI agents

Status: Beta

The programs in this sandbox, by default

1. reach no network destinations except:
    1. the model provider of the agent you launch
    1. a customizable selection of sites, read-only
1. reach no host files outside the workspace
    1. except from a Git linked worktree
1. cannot change Git files that can hold arbitrary commands, such as hooks and rebase
   instructions, so `git rebase` fails in the workspace

The containers run rootless, and the programs run as the `nonroot` user.

    ┌─ macOS / Linux / Windows ─────────────────────────────────────────────────┐
    │                                                                           │
    │  ┌─ sandbox launcher ──────────────────────────────────────────────────┐  │
    │  │  manages the containers, volumes, and networks                      │  │
    │  └─────────────────────────────────────────────────────────────────────┘  │
    │                                                                           │
    │  ┌─ workspace ───────────────────┐     ┌─ named volume (per workspace) ┐  │
    │  │  files shared between host    │     │  agents' auth and config,     │  │
    │  │  and sandbox                  │     │  kept across sessions;        │  │
    │  │                               │     │  ~/.claude ~/.codex ~/.gemini │  │
    │  │                               │     │  ... point into it            │  │
    │  └────┬──────────────────────────┘     └───────┬───────────────────────┘  │
    │       │ mounted at the same path               │ at ~/persistent-volume   │
    │       │ (WSL's path on Windows)                │ writable                 │
    │       │ writable by default                    │                          │
    │       │                      ┌─────────────────┘                          │
    │       │                      │                                            │
    │  ┏━ sandbox container ━━━━━━━┷━━━┓     ┌─ egress proxy container ──────┐  │
    │  ┃  runs claude/codex/agy/...    ┃     │  https only, stateless,       │  │
    │  ┃  capabilities dropped,        ┃     │  TLS-inspects except model    │  │
    │  ┃  read-only rootfs,            ┠────>│  providers                    ├──┼─> Internet
    │  ┃  ephemeral $HOME and /tmp     ┃     │                               │  │
    │  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛     └─────┬─────────────────────────┘  │
    │              only internal network,          │                            │
    │              no gateway, no outbound DNS     │                            │
    │                                              │                            │
    │                                            ┌─┴─ proxy log (audit) ─────┐  │
    │  the containers and networks are created   │  every allow and refusal; │  │
    │  per run, and when the sandbox exits       │  outlives the run         │  │
    │  they are all removed                      └───────────────────────────┘  │
    │                                                                           │
    │                                                                           │
    │  ┌─ macOS only: --run-on-host for resource-intensive commands ─────────┐  │
    │  │  sbt/mill/gradle/mvn run in a Seatbelt sandbox                      │  │
    │  └─────────────────────────────────────────────────────────────────────┘  │
    └───────────────────────────────────────────────────────────────────────────┘

A typical workflow:

1. `git clone`/`pull` on the host first — no host credentials are automatically forwarded.
2. Run a program in the sandbox: it should feel mostly like running it on the host.
    1. The program can `git clone` public GitHub repositories into the sandbox's `$HOME`.
3. Review the changes, then `git commit`/`push` on the host.

The sandbox image preinstalls:

1. [Claude Code](https://github.com/anthropics/claude-code)             (Anthropic)
1. [Codex](https://github.com/openai/codex)                             (OpenAI)
1. [Antigravity](https://github.com/google-antigravity/antigravity-cli) (Google)
1. [Kiro CLI](https://kiro.dev/cli/)                                    (AWS)
1. [Copilot CLI](https://github.com/github/copilot-cli)                 (GitHub)
1. [OpenCode](https://github.com/anomalyco/opencode)                    (multiple providers)
1. plus the toolchains: Node.js / Python + uv / Rust / Java / Scala, and the VS Code CLI.

The agents are configured to run without permission prompts, to avoid training users to approve
without reading. The sandbox enforces the boundary; inside it, the agents can call each other.


## Install

### Prerequisites

1. [podman](https://github.com/containers/podman) 6.1.0 or later
    1. Download [the installer](https://github.com/containers/podman/releases)
        1. On macOS and Windows, run `podman machine init` after a new installation;
           on native Linux, podman runs rootless without a machine.
        1. `podman machine start` is optional: the launcher automatically starts a stopped machine.
    1. [Windows prerequisite](https://github.com/podman-container-tools/podman/blob/main/docs/tutorials/podman-for-windows.md):
       WSL 2 or Hyper-V. Assuming the default WSL 2 provider:
        1. `wsl --version` shows the versions if WSL is installed.
            1. Update WSL with `wsl --update`, then `wsl --shutdown`.
        1. No Linux distribution is needed; `wsl --install --no-distribution` is enough.
        1. AWS EC2: before `podman machine init`, shut down the instance, then
            1. Actions → Instance settings → Change CPU options: Enable Nested virtualization

1. Java 25 LTS

### Build from source

Coursier installation is planned. Until it is available, build the jar from a checkout using the
[build instructions](#development).


## Usage

### Getting started

Build the container images once, and again after upgrading the jar:

    java -jar "<path-to-jar>/ko-agent-sandbox.jar" --build

Start an agent from a trusted directory, such as `~/my-project`, which becomes the workspace:

    java -jar "<path-to-jar>/ko-agent-sandbox.jar" claude

Insert these launcher options before the agent command (`claude` above):

1. Use `--model-provider=<names>` to reach other model providers than the agent's own:
   `anthropic`, `openai`, `google`, `aws` or `github`, separated by commas. `opencode` has no
   fixed provider and is refused without the option.
   For example, to run `claude` and review with `codex` through `/ko-review`:

       java -jar "<path-to-jar>/ko-agent-sandbox.jar" --model-provider=openai claude

1. Use `--egress=deny-unless-model` to limit network access to the selected model providers,
   dropping the read-only sites.
1. On macOS, use `--run-on-host=sbt,mill,gradle,mvn`, selecting the programs the agent needs,
   to build at host speed without consuming the podman machine's memory.

1. Use `--workspace=read-only` to make the workspace read-only inside the sandbox.

The launcher refuses to use your home directory as the workspace because it would expose credentials
in directories such as `.aws` and `.ssh` ([SECURITY.md](SECURITY.md#defended)).

### Running `<command>`

1. The current directory is the workspace root; the sandbox mounts it at the same path.
1. To change a session option such as `--egress=`, quit, then relaunch with the new options and
   the agent's resume arguments:

        java -jar "<path-to-jar>/ko-agent-sandbox.jar" --egress=deny-unless-model claude --continue

    1. The resume arguments are `claude --continue`, `codex resume --last`, `agy --continue`,
       `kiro-cli chat --resume`, `copilot --continue` or `opencode --continue`.

1. Use Ctrl-C to quit.
1. Put the options you give every launch in the [options file](#options-file).

#### `claude`

1. Sign-in prints an authorization URL; open it in an external browser and paste the resulting
   code back.
1. Ctrl-V pastes a copied image only under `--clipboard=paste` or `--clipboard=bidirectional`.
1. `/voice` needs the `--audio=mic` launcher option.
1. The image keeps Claude Code's conversation in the terminal's scrollback, where you can select
   and copy it. For the fullscreen renderer, launch with `--env=CLAUDE_CODE_NO_FLICKER=1`: the
   image's managed setting overrides `/tui fullscreen`.
1. `/ko-review`, the skill of the image's `ko-review` plugin, reviews the working tree.
   Choose Codex or a separate Claude Code session as the reviewer. Claude fixes or disputes each
   finding on the same reviewer thread until the reviewer approves the exact tree or asks for a
   decision only you can make.
   - A Codex reviewer needs `--model-provider` to name `openai` (the launch example above).
   - The reviewer's suggestions, opinions on the design that do not block approval, Claude adopts
     or disputes; it brings to you those that are yours to decide and names the adopted ones that
     changed the design.
   - The review covers the uncommitted changes by default.
   - Codex reviews under this workspace's Codex sign-in.
   - Each round's tree and transcript are on a Git ref under `refs/ko-review/` in the repository,
     for `git diff` between rounds ([doc/ko-review.md](doc/ko-review.md)).
1. To have a classifier screen Claude's actions, such as sending workspace data out on an injected
   instruction, launch `claude --permission-mode auto`. It adds a check, not a boundary
   ([SECURITY.md](SECURITY.md#not-defended), "Prompt injection").
   - A `claude` started without the flag, such as one in the session's shell or the `/ko-review`
     reviewer, runs under the image's managed `bypassPermissions`.
1. A prompt remains for some `rm` commands
   ([doc/limitations.md](doc/limitations.md#permission-prompts-that-remain)).

#### `codex`

1. Sign-in: on the ChatGPT website, "Settings" → "Security and login" → "Enable device code
   authorization for Codex", then choose "Sign in with Device Code" in the login UI.
1. The image keeps Codex's conversation in the terminal's scrollback, where you can select and copy
   it. To restore Codex's default, pass `-c tui.fullscreen_transcript=true` for one launch, or set
   `tui.fullscreen_transcript = true` in `~/.codex/config.toml`.
1. Ctrl-V pastes no image in any `--clipboard` mode
   ([clipboard plan](doc/plan-clipboard.md)).
1. `/voice` under `--audio=mic` reports "voice transport could not connect"
   ([doc/microphone.md](doc/microphone.md#codex)).
1. `$ko-review` runs the same review as [`/ko-review`](#claude), with Codex fixing or disputing
   the findings. Codex asks its questions in replies, since it has no question tool outside Plan
   mode. For a Claude reviewer, launch with `--model-provider=anthropic`.

#### `agy`

1. Sign in with the URL and pasted code, as for [`claude`](#claude).
1. `/voice` needs `--audio=mic`.
1. Its terminal sandbox fails to start in a session, so in Auto mode commands run without it
   ([doc/limitations.md](doc/limitations.md#agys-terminal-sandbox-and-auto-mode)).

#### `kiro-cli`

1. `kiro-cli login --use-device-flow` prints a URL and a one-time code to enter there, and exits
   once signed in; run `kiro-cli` again to chat.

#### `copilot`

1. Run `/login` and choose "Sign in with a device code"; open https://github.com/login/device

    1. Unlike the other sign-ins, the stored token grants access to your private repositories
       (SECURITY.md, "The web reached through the model provider").

1. Prompts for paths outside the workspace and for URLs remain unless you run `copilot --yolo`.
1. Its fullscreen TUI cannot be turned off, so use `/copy` to copy text out. It writes OSC 52,
   which sets the clipboard on a terminal that honors it
   ([SECURITY.md](SECURITY.md#terminal-clipboard-requests-osc-52)); on another terminal it needs
   `--clipboard=bidirectional`.

#### `opencode`

1. Launch with `--model-provider=<names>` naming the providers you will connect.
1. Run `/connect`, then `/models` to pick a model from the connected provider.
    1. Anthropic and Google take an API key.
    1. For a ChatGPT plan, choose the headless method, not the browser method.
    1. GitHub Copilot prints a device code, and the token it stores has the `read:user` scope,
       not `repo`.
1. The default model, `opencode/big-pickle`, posts to `opencode.ai`, where the proxy allows only
   reads, so its requests are refused.

#### Sign-in

Use the device-code or pasted-code methods above. Sign-in methods that redirect the browser to
127.0.0.1 cannot reach the agent in the sandbox. [doc/design.md](doc/design.md#sign-in)
explains why.

#### Cloud credentials

The launcher forwards nothing from `~/.aws` or another cloud CLI's configuration directory.
`--env-aws-cred[=<profile>]` forwards the temporary credentials an AWS login resolves on the host.
[doc/cloud-credentials.md](doc/cloud-credentials.md) explains that option, how to forward the
credentials another cloud's login produced, and what forwarding costs.

#### Sessions

1. Each launch prints the workspace mode and the resolved egress profile, plus the rule files, each
   option the options file supplied, and any warning.
1. More than one session can run at once from the same workspace; they share the
   workspace mount and the agent-state volume.

    1. When sessions change the same file concurrently, later writes can overwrite earlier changes.

1. From a Git linked worktree, the launch asks whether to share the main worktree's agent state,
   and where the container can follow the worktree's `.git` pointer (a relative one anywhere, an
   absolute one on macOS and Linux) the session also mounts the main worktree's Git directory,
   read-only, so `git` works there ([SECURITY.md](SECURITY.md#defended), "The host's git executing
   what the sandbox wrote").
1. A session creates no user namespace and mounts nothing: `unshare -Ur`, bubblewrap and an
   agent's or a browser's own sandbox fail with `Operation not permitted`.
   `--nesting=user-namespace` allows both for the whole session
   ([SECURITY.md](SECURITY.md#no-containers-inside-the-sandbox-by-default)).
1. `--nesting=same-uid` lets the session run containers of its own.

    1. Follow [AGENTS-SANDBOX.md](container/ko-agent-sandbox/AGENTS-SANDBOX.md) for the container
       limits: `debian` and `alpine` images work.
    1. Stock `postgres` and `nginx` need multiple uids and fail.


### Egress proxy

Every session accesses the network through the launcher's HTTPS proxy. The `--egress=` profile
and the workspace's `.ko-agent-sandbox/egress/rule` determine which destinations and operations are
allowed. The defaults include tunnels to supported model providers and TLS-inspected access
to selected documentation sites, package registries, and Git hosting services.

On the host, write one rule per line in `.ko-agent-sandbox/egress/rule`, then relaunch; a running
session keeps the ruleset it started with:

    deny https://github.com/                         # the forge, whole
    allow https://github.com/my-org/ read git-fetch  # then one owner, readable and clonable
    allow https://api.example/ tunnel                # permits traffic without inspection

See [doc/egress-proxy.md](doc/egress-proxy.md) for profiles, rule syntax, TLS inspection, audit logs
and diagnostics, and [SECURITY.md](SECURITY.md#egress-proxy) for the limits.

To use an upstream proxy, set `HTTPS_PROXY` in the launcher's environment; the launch banner
prints the selected endpoint. A proxy that terminates TLS with its own certificate is unsupported;
connections fail with certificate errors. See
[doc/egress-proxy.md](doc/egress-proxy.md#through-an-upstream-proxy) for
upstream-proxy requirements.


### Agent settings

[doc/agent-settings.md](doc/agent-settings.md) explains how to add project instructions,
restore permission prompts and set the Claude Code status line.


### Reference

    Run an AI agent inside the sandbox container.

    Usage, from the workspace root, mounted in the sandbox at the same path
    (on Windows, at the path WSL gives it: /mnt/<drive>/...):

      java -jar ko-agent-sandbox.jar [options] [--] [<command> [args...]]

    <command> runs inside the sandbox: claude, codex, agy, kiro-cli, copilot, opencode, bash, ...
    The first non-option starts the command; all remaining arguments pass through unchanged.
    Use -- before a command whose name looks like a launcher option.

    Session options, selected on every launch and never persisted, on the command line or in the
    options file below. An empty value, as in --memory=, returns an option to its default; a closed
    choice such as --clipboard names its default instead:
      --workspace=read-only|live
                         read-only makes the workspace read-only to the
                         sandbox's processes; live (default) lets the agent
                         edit the shared workspace files and the Git state the
                         filter lists (refs, objects, the index, HEAD and the
                         like); every other Git entry, such as config and
                         hooks, .ko-agent-sandbox and what the file rules
                         protect are frozen at any depth (SECURITY.md)
      --egress=deny-all|deny-unless-model|deny-unless-allowed
                         which hosts the session reaches; the default,
                         deny-unless-allowed, allows the launcher-owned
                         defaults modified by .ko-agent-sandbox/egress/rule.
                         Each profile: doc/egress-proxy.md
      --model-provider=<names>
                         the model providers the session reaches beside the
                         agent's own: anthropic, openai, google, aws or github,
                         separated by commas. Repeatable, each name once. Required
                         for opencode, which has no fixed provider; refused under
                         --egress=deny-all
      --clipboard=off|paste|bidirectional
                         off (default) keeps the host clipboard out; paste lets
                         the agent read a copied image; bidirectional also lets
                         it set your clipboard (SECURITY.md). A Linux host needs
                         xclip or wl-clipboard
      --audio=off|<devices>
                         off (default) keeps the host's audio out; mic lets the agents' voice
                         dictation record the host microphone. The microphone stays open on
                         the host for the whole session, and its audio reaches the sandbox
                         while any process there records (SECURITY.md "Microphone"). Needs a
                         recorder on the host: rec from sox_ng or sox on macOS (brew install
                         sox_ng); arecord (alsa-utils) or parecord (pulseaudio-utils) on Linux;
                         sox_ng.exe on PATH on Windows. On macOS the terminal needs the
                         microphone permission (System Settings > Privacy & Security >
                         Microphone)
      --nesting=none|user-namespace|same-uid
                         none (default) runs the session under the launcher's seccomp
                         profile, which refuses creating a user namespace and mounting;
                         user-namespace allows both, under podman's default profile;
                         same-uid also allows rootless containers with one uid, host
                         networking and session-only storage, but unmasks /proc, disables
                         SELinux labeling and adds SYS_CHROOT for the whole session
                         (SECURITY.md)
      --session-start=pause|immediate
                         pause (default) holds a launch's startup lines on screen, because the
                         agent TUIs clear it: Enter or y starts, n or EOF at the prompt exits
                         without starting; from a Git linked worktree, it first asks whether to
                         share the main worktree's agent state. immediate starts the agent at
                         once
      --memory=<size>    container memory limit, e.g. 8g. Default: the podman machine's memory
                         (on Linux, the host's) minus 1 GiB, and on Linux no more than was
                         available at launch; at least 1 GiB, or all memory if less than 1 GiB.
                         The sandbox never swaps
      --persistent-volume=<name>
                         a podman volume name; every workspace launched with it shares that
                         volume as its agent state, and --reset leaves it alone
      --image=<reference>
                         sandbox image (default ko-agent-sandbox:latest)
      --proxy-image=<reference>
                         egress proxy image (default ko-agent-egress-proxy:latest)
      --run-on-host=<programs>
                         macOS only: select sbt / mill / gradle / mvn, separated by commas.
                         Adds the ko-sandbox-run-on-host command inside the sandbox, to run
                         those programs on the host under Seatbelt. Host commands can write
                         the workspace even under --workspace=read-only, except what the file
                         rules protect; access is confined to the workspace (excluding .git and
                         .ko-agent-sandbox), per-workspace caches, and a dedicated egress proxy.
                         Before the start prompt, offers to run the workspace's ./mill,
                         ./gradlew or ./mvnw when its launcher, JDK or
                         distribution is not yet provisioned.
                         The session keeps one sbt/mill daemon warm per build directory.
                         On first use there, a daemon you started is shut down after its
                         current build finishes; your new clients then share the session's
                         confined daemon. Gradle's session daemons stay separate from yours.
                         Linux gains nothing: container builds already use host speed and memory.
                         Windows needs a different design to enforce the filesystem restrictions.
                         See SECURITY.md "Run on host" and doc/run-on-host.md
                         "Program prerequisites".
      --env=<name>[=<value>]
                         set an environment variable in the sandbox and --run-on-host
                         commands.
                         An explicit <value> needs no export on the host.
                         Without <value>, use the host's value; an unset name fails.
                         Repeatable; KO_AGENT_SANDBOX_* names are refused.
                         Before forwarding a secret, read SECURITY.md; in the options file,
                         name it without its value
      --env-aws-cred[=<profile>]
                         forward the temporary credentials the AWS CLI on the host
                         resolves for <profile>, else for AWS_PROFILE, as
                         AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN,
                         by name as --env does, with the profile's region as AWS_REGION;
                         prints when they expire.
                         Fails without a profile or aws on PATH, on an expired login,
                         and on a static key. See doc/cloud-credentials.md
      --egress-cred=<name>@<host>[/<prefix>/][:<header>|?<param>]
                         give environment variable <name> to the egress proxy, which
                         puts its value in Authorization, or in header <header> or
                         query parameter <param>, of requests to <host> under
                         /<prefix>/ alone. The sandbox and --run-on-host commands
                         see <name> set to a placeholder, which the proxy replaces.
                         <host> must be inspected by the session's rules or a
                         --run-on-host program's. Repeatable, each name once.
                         See doc/egress-proxy.md "Brokered credentials" and SECURITY.md
                         "Who holds a brokered value".

    Claude Code options, selected on every launch like the session options and configuring
    the session's claude rather than the sandbox:
      --claude-plugin-dir=<dir>
                         load a host plugin directory into the session's claude as a managed
                         plugin, the only kind whose hooks and mod the image lets run. Mounted
                         read-only as <dir's name>@host. Repeatable, in the order the mods run;
                         refused when it holds or is inside the workspace or a directory that
                         --run-on-host commands write; an organization's remote policy can keep
                         it from loading. See doc/agent-settings.md "Claude Code plugins and
                         mods"

    Options file, $XDG_CONFIG_HOME/ko-agent-sandbox/options, by default
    ~/.config/ko-agent-sandbox/options (%APPDATA%\ko-agent-sandbox\options on Windows): one
    session or Claude Code option per line, spelled as above; # starts a comment, "..." quotes a
    value, ${NAME} expands a variable of the launcher's environment. Every launch prints each
    option it supplies. A command-line option replaces the file's; --env and --egress-cred replace
    the file's entry of the same name, and --model-provider adds its names to the file's.
    --reset reads its --persistent-volume, --egress-effective and --egress-check its egress
    options and --proxy-image; the other actions read none. See README.md "Options file"
      --no-options-file  before the command: skip the options file for this launch or action

    Management actions, each recognized before the command; whatever follows
    belongs to the action:

      --build            build the container images, install the workspace filter and
                         derive the --nesting=none seccomp profile from podman's default,
                         always pulling remote base images
      --update           update the agents: rebuild only the sandbox container
                         image, without cache, on the base images --build built, and
                         derive the seccomp profile again

      --stats            show the resource use of the machine, the live sessions and each workspace.
                         Flags caches worth clearing with --reset-run-on-host

      --reset-run-on-host
                         clear this workspace's host build caches; keep its sessions
                         and other state
      --reset [<id>...]  in addition to --reset-run-on-host, remove this workspace's
                         containers (ending any live session), volume (signing its
                         agents out), networks, TLS inspection CA, cached ruleset
                         resolution, logs and workspace-filter mount;
                         images and any shared volume are left untouched. From a
                         linked worktree, the main worktree's volume is left
                         untouched too.
                         Ids, as --stats prints them, name workspaces whose
                         directories are gone instead of the current one
      --reset-all        the same as --reset, for every workspace

      --egress-effective [--] [<command> [args...]]
                         print the ruleset the accompanying --egress=<profile>
                         resolves to for this workspace, with per-line
                         provenance; the command and --model-provider select
                         the model providers without launching anything
      --egress-check=<host> [--] [<command> [args...]]
                         print the host's rule decision and DNS result using the proxy's
                         resolver; with HTTPS_PROXY, also check the upstream proxy's tunnel.
                         Starts a temporary proxy container.
                         Inside a session, ko-sandbox-egress-check <host>
                         checks through the running proxy
      --egress-log       print this workspace's retained proxy audit logs, the
                         run-on-host proxies' included; with extra args (-f,
                         --tail 50), run podman logs on the running session proxies instead

      --self-test [<filter>]
                         run the workspace filter's own suites; <filter> selects one
                         case or family. Without a filter, also check the host share;
                         its scratch directory in the workspace is removed on success
                         and retained on failure. Removes replaced self-test images
                         (fuse/ko-agent-fs/doc/testing.md)

      --help             this text

    Environment variables:
      HTTPS_PROXY / https_proxy  an upstream proxy the session's egress leaves through,
                                 http[s]://[user:password@]host:port; the lowercase name is read
                                 when the uppercase is unset or empty. NO_PROXY is ignored
                                 (doc/egress-proxy.md)

    .ko-agent-sandbox/egress/rule in the workspace root modifies the egress ruleset: allow
    and deny lines naming URLs, applied in order over the launcher-owned defaults
    (doc/egress-proxy.md).

    .ko-agent-sandbox/file/rule modifies which workspace files a session cannot change because a
    host program takes a command or a server from them: read-only and writable lines naming files or
    directories at any depth, applied in order over the launcher-owned defaults (doc/file-rules.md).


### `--build`

1. Builds the sandbox and egress-proxy images from the jar; no checkout is needed.
1. Installs the workspace filter, `ko-agent-fs`, compiled from bundled source, at
   `~/.local/share/ko-agent-sandbox/ko-agent-fs` — inside the podman machine on macOS and Windows,
   in your home on native Linux.

    1. To remove it:
       `podman machine ssh rm .local/share/ko-agent-sandbox/ko-agent-fs` (plain `rm` on Linux).

1. Use `--update` to install new agent releases.

    1. It rebuilds without cache; `--build` may reuse cached versions. Agents cannot update
       themselves inside the sandbox.

1. May ask to add `user_allow_other` to the podman machine's `/etc/fuse.conf`, shown as a diff
   first (SECURITY.md, "Silent changes to what you own"). A native Linux host is never prompted.
1. For workspace-filter failures, see [troubleshooting.md](fuse/ko-agent-fs/doc/troubleshooting.md).
1. `--build`, `--update` and `--self-test` all end by removing the container images they
   superseded, never a pulled image.


### Options file

Put the options you give every launch in the options file, one per line, spelled as on the
command line:

    # ~/.config/ko-agent-sandbox/options
    --model-provider=anthropic,openai
    --memory=8g
    --clipboard=paste
    --env=GH_TOKEN          # forwards the host's value, read at each launch

1. The file is `$XDG_CONFIG_HOME/ko-agent-sandbox/options`, by default
   `~/.config/ko-agent-sandbox/options`; on Windows, `%APPDATA%\ko-agent-sandbox\options`. An
   absent file supplies nothing.
1. Every launch prints each option the file supplies, naming the file:
   `--memory=8g (from ~/.config/ko-agent-sandbox/options)`. A line that already states the option,
   such as a grant's orange line or the `egress:` line, names the file instead.
1. An option on the command line replaces the file's for that launch.

    1. `--env` and `--egress-cred` replace the file's entry of the same name;
       `--claude-plugin-dir` loads a directory both spell alike once, and `--model-provider` adds
       its names to the file's.
    1. An empty value returns an option to its default: `--memory=`, `--run-on-host=`. A closed
       choice names its default instead: `--clipboard=off`, `--nesting=none`.
    1. The empty value of `--env`, `--egress-cred`, `--claude-plugin-dir` or `--model-provider`
       drops the file's entries of that option; those after it on the command line still add.

1. `--no-options-file`, before the command, skips the file for one launch or action.
1. `--reset` reads the file's `--persistent-volume`. `--egress-effective` reads its `--egress`,
   `--model-provider`, `--egress-cred` and `--proxy-image`, and `--egress-check` the same but
   for `--egress-cred`. The other actions read none.
1. Forward a secret as `--env=NAME`, with the value in the launcher's environment. A value in the
   file, as `--env=NAME=VALUE` or `--env=NAME=${SECRET}`, is in podman's arguments and in the create
   command podman records for the container.

The file's format:

- `#` outside double quotes starts a comment, inside a word too. Whitespace around the line, the
  name and the value is removed.
- A value in double quotes keeps its whitespace and `#`, and takes the escapes `\"`, `\\` and `\$`.
  Outside quotes every backslash is literal, so a Windows path needs no quotes.
- `${NAME}` in a value, quoted or not, expands to the launcher's environment variable `NAME`. An
  unset variable fails the launch, and so does a `$` that starts no `${`.
- The launch fails naming the file and the line on invalid UTF-8 or syntax, a command, `--`, a
  management action, `--no-options-file` or an unknown option. It also fails on a file inside the
  workspace: a repository must not choose its own launch's grants.


## Development

1. The launcher is the sbt project at the repository root.
2. The egress proxy is its own sbt project under `container/ko-agent-egress-proxy/app`.
3. The workspace filter is the Rust crate under `fuse/ko-agent-fs`.

Run the commands below from the repository root.

### Build environment

1. Java 25 and [sbt](https://www.scala-sbt.org)

    1. [Install Coursier](https://get-coursier.io/docs/cli-installation), then

        1. macOS / Linux / bash on Windows

               eval $(cs java --jvm temurin:25 --env)

        1. Windows PowerShell

               $env:JAVA_HOME = cs java-home --jvm temurin:25
               $env:PATH = "$env:JAVA_HOME\bin;$env:PATH"

        1. Windows Command Prompt

               for /f "delims=" %i in ('cs java-home --jvm temurin:25') do set "JAVA_HOME=%i"
               set "PATH=%JAVA_HOME%\bin;%PATH%"


### Build the launcher and images

    sbt dist && java -jar target/dist/ko-agent-sandbox.jar --build

1. This assembles one self-contained jar — a single file is the whole install.
1. On Windows, PowerShell 7 or later is recommended. Windows PowerShell 5.1 does not support `&&`.

### Tests

[doc/development.md](doc/development.md#tests) gives the test commands and the machines we run
them on.
