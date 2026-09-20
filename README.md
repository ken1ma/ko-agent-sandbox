# A sandbox container for AI agents

Status: Beta on macOS, alpha on Linux and Windows

The AI agents in this sandbox by default

1. reach no user files except the current directory (project directory)
1. reach no network destinations except:
    1. the model providers supported by the sandbox
    1. an opinionated, customizable selection of sites, limited to reading and explicitly
       permitted operations, such as `git clone`/`pull`

The sandbox runs rootless, and its agents run as the `nonroot` user.

    ┌─ macOS / Linux / Windows (with/without WSL) ─────────────────────────────────┐
    │                                                                              │
    │  ┌─ launcher ──────────────────────────────────────────────────────────┐     │
    │  │  runs podman to manage the containers, volumes, and networks        │     │
    │  └─────────────────────────────────────────────────────────────────────┘     │
    │                                                                              │
    │  ┌─ project directory ───────────┐     ┌─ named volume (per project) ──┐     │
    │  │  the only user files          │     │  agents' auth and config,     │     │
    │  │  shared with the sandbox      │     │  kept across sessions;        │     │
    │  │                               │     │  ~/.claude ~/.codex ~/.gemini │     │
    │  │                               │     │  ... point into it            │     │
    │  └─────┬─────────────────────────┘     └───────┬───────────────────────┘     │
    │        │ mounted at its own path: RW (--write= │ at ~/persistent-volume, RW  │
    │        │ live, the default) with protected     │                             │
    │        │ Git entries (including hooks) frozen  │                             │
    │        │ at every depth                        │                             │
    │        │                                       │                             │
    │        │                  ┌────────────────────┘                             │
    │        │                  │                                                  │
    │  ┏━ sandbox container ━━━━┷━━━━━━┓     ┌─ egress proxy container ──────┐     │
    │  ┃  runs claude/codex/agy/...    ┃     │  https only, stateless,       │     │
    │  ┃  capabilities dropped,        ┃ (a) │  TLS-inspects except model    │ (b) │
    │  ┃  read-only rootfs,            ┠────>│  providers                    ├─────┼─> Internet
    │  ┃  ephemeral /tmp and $HOME     ┃     │                               │     │
    │  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛     └────┬──────────────────────────┘     │
    │  (a) internal network, no gateway           │                                │
    │  (b) only egress network                    │                                │
    │                                             │                                │
    │                                           ┌─┴─ proxy log (audit) ─────┐      │
    │  the containers and networks are created  │  every allow and refusal; │      │
    │  per run, and when the sandbox exits      │  outlives the run         │      │
    │  they are all removed                     └───────────────────────────┘      │
    │                                                                              │
    │  ┌─ macOS: --run-on-host sandbox for resource-intensive commands ───────┐    │
    │  │  sbt/mill/gradle/mvn relayed under Seatbelt                          │    │
    │  └──────────────────────────────────────────────────────────────────────┘    │
    └──────────────────────────────────────────────────────────────────────────────┘

A typical workflow:

1. `git clone`/`pull` on the host first — host Git credentials are not automatically forwarded.
2. Run an agent in the sandbox: it should feel mostly like running it on the host.
3. Review the changes, then `git commit`/`push` on the host.

The sandbox image preinstalls:

1. [Claude Code](https://github.com/anthropics/claude-code)             (Anthropic)
1. [Codex](https://github.com/openai/codex)                             (OpenAI)
1. [Antigravity](https://github.com/google-antigravity/antigravity-cli) (Google)
1. [Kiro CLI](https://kiro.dev/cli/)                                    (AWS)
1. [Copilot CLI](https://github.com/github/copilot-cli)                 (GitHub)
1. [OpenCode](https://github.com/anomalyco/opencode)                    (multiple providers)
1. plus the toolchains: Python + uv / Node.js / Rust / Java / Scala.

The agents are configured to run without permission prompts to avoid training users to approve
without reading. The sandbox enforces the boundary.


## Install

### Prerequisites

1. [podman](https://github.com/containers/podman) 6.1.0 or later
    1. Download [the installer](https://github.com/containers/podman/releases)
        1. On macOS and Windows, run `podman machine init` after a new installation;
           on native Linux, podman runs rootless without a machine.
        1. `podman machine start` is not needed: the launcher starts a stopped machine.
    1. [Windows Prerequisite](https://github.com/podman-container-tools/podman/blob/main/docs/tutorials/podman-for-windows.md):
       WSL 2 or Hyper-V.  Assuming the default WSL 2 provider:
        1. `wsl --version` shows the versions if WSL is installed.
            1. Update WSL with `wsl --update`, then `wsl --shutdown`.
        1. No Linux distribution is needed; `wsl --install --no-distribution` is enough.
        1. AWS EC2: before `podman machine init`, shut down the instance then
            1. Actions → Instance settings → Change CPU options: Enable Nested virtualization

1. Java 25 LTS

### Build from source

Coursier installation is planned. Until it is available, build the jar from a checkout using the
[build instructions](#development).


## Usage

### Getting started

Build the container images once, and again after upgrading the jar:

    java -jar "<path-to-jar>/ko-agent-sandbox.jar" --build

Start an agent in a trusted project directory, such as `~/my-project`:

    java -jar "<path-to-jar>/ko-agent-sandbox.jar" claude

Insert these options before the agent command (`claude` above):

1. Use `--write=reject` to make the project read-only inside the sandbox.
1. Use `--egress=deny-unless-model` to limit network access to the agent's provider; for
   `opencode`, that is all the default providers.
1. On macOS, use `--run-on-host=sbt,mill,gradle,mvn`, selecting the programs the agent needs,
   to build at host speed without consuming the podman machine's memory.

    1. These host commands can write the project even with `--write=reject`. See
       [doc/run-on-host.md](doc/run-on-host.md#program-prerequisites) for requirements and
       [SECURITY.md](SECURITY.md#run-on-host) for the access it grants.

The launcher refuses to use your home directory as the project because it would expose credentials
in directories such as `.aws` and `.ssh` ([SECURITY.md](SECURITY.md#defended)).

### Running `<command>`

1. To change `--write=` or `--egress=`, quit, then relaunch with the new option and the agent's
   resume arguments:

        java -jar "<path-to-jar>/ko-agent-sandbox.jar" --write=reject claude --resume

    1. The resume arguments are `claude --resume`, `codex resume`, `agy --continue`,
       `kiro-cli chat --resume`, `copilot --continue` or `opencode --continue`.

1. Use Ctrl-C to quit.

#### `claude`

1. Sign-in prints an authorization URL; open it in an external browser and paste the resulting
   code back.
1. Ctrl-V pastes a copied image only when `KO_AGENT_SANDBOX_CLIPBOARD` is `paste` or
   `bidirectional`.
1. A prompt remains for some `rm` commands
   ([doc/limitations.md](doc/limitations.md#permission-prompts-that-remain)).

#### `codex`

1. Sign-in: "ChatGPT Settings" → "Security and login" → "Enable device code authorization for
   Codex", then choose "Sign in with Device Code" in the login UI.

#### `agy`

1. Sign in with the URL and pasted code, as for [`claude`](#claude).

#### `kiro-cli`

1. `kiro-cli login --use-device-flow` prints a URL and a one-time code to enter there, and exits
   once signed in; run `kiro-cli` again to chat.

#### `copilot`

1. Run `/login` and choose "Sign in with a device code"; open https://github.com/login/device

    1. Unlike the other sign-ins, the stored token grants access to your private repositories
       (SECURITY.md, "The web reached through the model provider").

1. Prompts for paths outside the project and for URLs remain unless you run `copilot --yolo`.
1. Its fullscreen TUI cannot be turned off, so use `/copy` to copy text out; this requires
   `KO_AGENT_SANDBOX_CLIPBOARD=bidirectional`.

#### `opencode`

1. Run `/connect`, then `/models` to pick a model from the connected provider.
    1. Anthropic and Google take an API key.
    1. For a ChatGPT plan choose the headless method, not the browser method.
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
[doc/cloud-credentials.md](doc/cloud-credentials.md) explains how to forward the credentials a login
produced, and what that costs.

#### Sessions

1. Each launch prints the workspace mode and the resolved egress profile, plus its rule file and
   any warning.
1. More than one session can run at once from the same project directory; they share the
   workspace mount and the agent-state volume.

    1. When sessions change the same file concurrently, later writes can overwrite earlier changes.

1. Calling another installed agent's command or MCP server reuses that agent's login and
   configuration. Treat the project directory as their shared trust domain.
1. `KO_AGENT_SANDBOX_NESTING=same-uid` lets the session run containers of its own.

    1. Follow [AGENTS-SANDBOX.md](container/ko-agent-sandbox/AGENTS-SANDBOX.md) for the container
       limits: `distroless` and `alpine` images work.
    1. Stock `postgres` and `nginx` need multiple uids and fail.


### Egress proxy

Every session accesses the network through one HTTPS proxy. The `--egress=` profile and the
project's `.ko-agent-sandbox/egress/rule` determine which destinations and operations are
allowed. The defaults include tunnels to supported model providers and TLS-inspected access
to selected documentation sites, package registries, and Git hosting services.

On the host, write one rule per line in `.ko-agent-sandbox/egress/rule`, then relaunch; a running
session keeps the ruleset it started with:

    deny https://github.com/                         # the forge, whole
    allow https://github.com/my-org/ read git-fetch  # then one owner, readable and clonable
    allow https://api.example/ tunnel                # permits traffic without inspection

See [doc/egress-proxy.md](doc/egress-proxy.md) for profiles, rule syntax, TLS inspection, audit logs
and diagnostics, and [SECURITY.md](SECURITY.md#egress-proxy) for the limits.

To use an upstream proxy, set `HTTPS_PROXY` in the launcher’s environment; the launch banner
prints the selected endpoint. A proxy that terminates TLS with its own certificate is unsupported;
connections fail with certificate errors. See
[doc/egress-proxy.md](doc/egress-proxy.md#through-an-upstream-proxy) for
upstream-proxy requirements.


### Agent settings

[doc/agent-settings.md](doc/agent-settings.md) explains how to add project instructions,
restore permission prompts and set the Claude Code status line.


### Reference

    Run an AI agent inside the sandbox container.

    Usage, from a project directory, mounted in the sandbox at the same path
    (on Windows, at the path WSL gives it: /mnt/<drive>/...):

      java -jar ko-agent-sandbox.jar [options] [--] [<command> [args...]]

    <command> runs inside the sandbox: claude, codex, agy, kiro-cli, copilot, opencode, bash, ...
    The first non-option starts the command; all remaining arguments pass through unchanged.
    Use -- before a command whose name looks like a launcher option.

    Session options, selected on every launch and never persisted:
      --write=reject|live
                         reject makes the project read-only; live (default)
                         lets the agent edit the shared project files, except
                         Git configuration, hooks, other protected Git entries
                         and .ko-agent-sandbox at any depth (SECURITY.md)
      --egress=deny-all|deny-unless-model|deny-unless-allowed|allow-unless-denied
                         which hosts the session reaches; the default,
                         deny-unless-allowed, allows the launcher-owned
                         defaults modified by .ko-agent-sandbox/egress/rule.
                         Each profile: doc/egress-proxy.md
      --run-on-host=<programs>
                         macOS only: select sbt / mill / gradle / mvn, separated by commas.
                         Adds the ko-sandbox-run-on-host command inside the sandbox, to run
                         those programs on the host under Seatbelt. Host commands can write
                         the project even under --write=reject; access is
                         confined to the project (excluding .git and .ko-agent-sandbox),
                         per-project caches, and a dedicated egress proxy.
                         Before the start prompt, offers to run the project's ./mill,
                         ./gradlew or ./mvnw for a launcher or distribution not yet
                         provisioned, if you answer yes.
                         The session keeps one sbt/mill daemon warm per build directory.
                         On first use there, a daemon you started is shut down after its
                         current build finishes; your new clients then share the session's
                         confined daemon. Gradle's session daemons stay separate from yours.
                         Linux gains nothing: container builds already use host speed and memory.
                         Windows needs a different design to enforce the filesystem restrictions.
                         See SECURITY.md "Run on host" and doc/run-on-host.md.
      --env=<name>[=<value>]
                         set a variable in the sandbox and --run-on-host commands.
                         An explicit <value> needs no export on the host.
                         Without <value>, use the host's value; an unset name fails.
                         Repeatable; KO_AGENT_SANDBOX_* names are refused.
                         Before forwarding a secret, read SECURITY.md

    Management actions, each recognized before the command; whatever follows
    belongs to the action:

      --build            build the container images and install the workspace filter,
                         always pulling remote base images
      --update           update the agents: rebuild only the sandbox container
                         image, without cache

      --stats            show the resource use of the machine, the live sessions and each project.
                         Flags caches worth clearing with --reset-run-on-host

      --reset-run-on-host
                         clear this project's host build caches; keep its sessions
                         and other state
      --reset [<id>...]  in addition to --reset-run-on-host, remove this project's
                         containers (ending any live session), volume (signing its
                         agents out), networks, TLS inspection CA, cached ruleset
                         resolution, logs and workspace-filter mount;
                         images and any shared volume are left untouched.
                         Ids, as --stats prints them, name projects whose
                         directories are gone instead of the current one
      --reset-all        the same as --reset, for every project

      --egress-effective [--] [<command> [args...]]
                         print the ruleset the accompanying --egress=<profile>
                         resolves to for this project, with per-line
                         provenance; the command selects the model provider
                         without being launched
      --egress-check=<host> [--] [<command> [args...]]
                         print the host's rule decision and DNS result using the proxy's
                         resolver; with HTTPS_PROXY, also check the upstream proxy's tunnel.
                         Starts a temporary proxy container.
                         Inside a session, ko-sandbox-egress-check <host>
                         checks through the running proxy
      --proxy-log        print this project's retained proxy audit logs;
                         with extra args (-f, --tail 50), run podman logs on the
                         running proxies instead

      --self-test [<filter>]
                         run the workspace filter's own suites; <filter> selects one
                         case or family. Without a filter, also check the host share;
                         its scratch directory in the project is removed on success
                         and retained on failure. Removes replaced self-test images
                         (fuse/ko-agent-fs/doc/testing.md)

      --help             this text

    Environment variables:
      HTTPS_PROXY / https_proxy           an upstream proxy the session's egress leaves through,
                                          http[s]://[user:password@]host:port; the lowercase
                                          name is read when the uppercase is unset or empty.
                                          NO_PROXY is ignored (doc/egress-proxy.md)
      KO_AGENT_SANDBOX_CLIPBOARD          "off" (default) keeps the host clipboard out; "paste"
                                          lets the agent read a copied image; "bidirectional"
                                          also lets it set your clipboard (SECURITY.md). A
                                          Linux host needs xclip or wl-clipboard
      KO_AGENT_SANDBOX_NESTING            "none" (default) allows no container runtime; "same-uid"
                                          allows rootless containers with one uid, host networking
                                          and session-only storage, but unmasks /proc, disables
                                          SELinux labeling and adds SYS_CHROOT for the whole
                                          session (SECURITY.md)
      KO_AGENT_SANDBOX_SESSION_START      "pause" (default) holds a launch's startup lines on
                                          screen, because the agent TUIs clear it: Enter or y
                                          starts, n or EOF at the prompt exits without starting;
                                          "immediate" starts the agent at once
      KO_AGENT_SANDBOX_MEMORY             container memory limit, e.g. 8g. Default: the podman
                                          machine's memory (on Linux, the host's) minus 1 GiB,
                                          and on Linux no more than was available at launch;
                                          at least 1 GiB, or all memory if less than 1 GiB.
                                          The sandbox never swaps
      KO_AGENT_SANDBOX_PERSISTENT_VOLUME  a podman volume name; every project launched with it
                                          shares that volume as its agent state, and --reset
                                          leaves it alone
      KO_AGENT_SANDBOX_IMAGE              sandbox image (default ko-agent-sandbox:latest)
      KO_AGENT_SANDBOX_PROXY_IMAGE        egress proxy image (default ko-agent-egress-proxy:latest)

    .ko-agent-sandbox/egress/rule in the project directory modifies the egress ruleset: allow
    and deny lines naming URLs, applied in order over the launcher-owned defaults
    (doc/egress-proxy.md).


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


## Development

1. The launcher is the sbt project at the repository root
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
1. On Windows PowerShell below version 7, run the commands separated by `&&` individually.

### Tests

#### launcher

1. On the host, run the container-launching suites against the jar and images from
   "Build the launcher and images" above. `test` and `testFull` skip these suites:

       sbt testWithPodman

    1. `testOnly` patterns can follow, quoted with the command:
       `sbt "testWithPodman *RunTopologyTest"`.
    1. One test is skipped unless `SIGNED_PUT_URL` holds a presigned S3 PUT URL for a
       bucket you own: the refusal of an owner-signed upload inside the inspected tunnel.

        1. The case's header in `src/test/scala/EgressSessionTest.scala` has the commands that sign
           the URL and the test command, which uses `sbt --server` so the variable reaches the
           tests.

1. On the host, start a sandbox with the default egress rules:

       KO_AGENT_SANDBOX_SESSION_START=immediate \
           java -jar target/dist/ko-agent-sandbox.jar bash

   Inside that session, remove dangling host-cache links as described in
   [AGENTS-SANDBOX.md](container/ko-agent-sandbox/AGENTS-SANDBOX.md#host-cache-links),
   then run `sbt testFull`, which also runs `SessionBoundaryTest`.

1. `testFull` executes every test every time, unlike `test` which is incremental.

#### egress-proxy

    (cd container/ko-agent-egress-proxy/app; sbt testFull)

#### ko-agent-fs

    java -jar target/dist/ko-agent-sandbox.jar --self-test

1. `--self-test` runs the suite that needs no mount and the suite that mounts a real filter in a
   privileged container, on any machine with podman; running either suite directly is documented in
   [testing.md](fuse/ko-agent-fs/doc/testing.md).
