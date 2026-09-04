# A sandbox container for AI agents

Status: Beta on macOS, alpha on Linux and Windows

The AI agents in this sandbox, by default,

1. reach no user files except the project directory (current directory)
1. reach no network except the launcher-owned defaults:
    1. the model providers of the agents
    1. a curated set of sites, limited to reads and named grants, such as `git clone`/`pull`,
       modified per project by `.ko-agent-sandbox/egress/rule`

How it is put together:

    ┌─ macOS / Linux / Windows (WSL, native) ──────────────────────────────────────┐
    │                                                                              │
    │  ┌─ launcher ──────────────────────────────────────────────────────────┐     │
    │  │  runs podman to manage the containers, volumes, and networks        │     │
    │  └─────────────────────────────────────────────────────────────────────┘     │
    │                                                                              │
    │  ┌─ project directory ───────────┐     ┌─ named volume (per project) ──┐     │
    │  │  the only user files the      │     │  agents' auth and config,     │     │
    │  │  sandbox can reach            │     │  kept across sessions;        │     │
    │  │                               │     │  ~/.claude ~/.codex ~/.gemini │     │
    │  │                               │     │  ... point into it            │     │
    │  └─────┬─────────────────────────┘     └───────┬───────────────────────┘     │
    │        │ mounted at /workspace: RW (--write=   │ at ~/persistent-volume, RW  │
    │        │ live, the default) with git control   │                             │
    │        │ state (including hooks) frozen at any │                             │
    │        │ depth, or read-only (--write=reject)  │                             │
    │        │                                       │                             │
    │        │                  ┌────────────────────┘                             │
    │        │                  │                                                  │
    │  ┏━ sandbox container ━━━━┷━━━━━━┓     ┌─ egress proxy container ──────┐     │
    │  ┃  runs claude/codex/agy/...    ┃     │  https only, stateless,       │     │
    │  ┃  nonroot user, caps dropped,  ┃ (a) │  TLS-inspects except model    │ (b) │
    │  ┃  read-only rootfs,            ┠────>│  providers                    ├─────┼─> Internet
    │  ┃  ephemeral /tmp and $HOME     ┃     │                               │     │
    │  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛     └────┬──────────────────────────┘     │
    │  (a) internal network, no gateway           │                                │
    │  (b) only egress network                    │                                │
    │                                             │                                │
    │                                           ┌─┴─ proxy log (audit) ─────┐      │
    │  the containers and networks are created  │  every allow and refusal; │      │
    │  per run, and when the sandbox exits      │  outlives the run         │      │
    │  they are all removed (not reused)        └───────────────────────────┘      │
    │                                                                              │
    │  ┌─ macOS: --run-on-host sandbox for heavy workloads ───────────────────┐    │
    │  │  sbt/mill relayed to the host under Seatbelt                         │    │
    │  └──────────────────────────────────────────────────────────────────────┘    │
    └──────────────────────────────────────────────────────────────────────────────┘

1. An intended workflow:
    1. `git clone`/`pull`/`fetch` on the host first — the launcher passes none of your host
       credentials in
    1. run an agent in the sandbox: it should feel mostly like running it on the host
    1. review the changes, then `git commit`/`push` on the host
1. The launcher refuses `$HOME` and its ancestors as the project directory
   (it would expose `~/.aws`, `~/.ssh`), along with the well-known home
   containers (`/home`, `/Users`, the Windows profiles root), and any path
   containing a dot-prefixed directory.

The sandbox image preinstalls:

1. Claude Code (Anthropic)
1. Codex CLI (OpenAI)
1. Antigravity CLI (Google)
1. Copilot CLI (GitHub)
1. plus the toolchains: Python + uv / Node.js / Rust / Java / Scala.

and configures them to

1. not ask for permissions
    1. `agy` needs a one-time step, and `copilot` a flag; see
       [Running `<command>`](#running-command)

[SECURITY.md] describes the security model — what the sandbox defends against, how, and what it does
not.


## Install

### Runtime Environment

1. [podman](https://github.com/containers/podman) 6.1.0 or later
    1. Download [the installer](https://github.com/containers/podman/releases)
        1. Run `podman machine init` after a new installation
    1. [Windows Prerequisite](https://github.com/podman-container-tools/podman/blob/main/docs/tutorials/podman-for-windows.md):
       WSL 2 or Hyper-V.  Assuming the default WSL 2 provider:
        1. `wsl --version` should show the version.
        1. No Linux distribution is needed; `wsl --install --no-distribution` is enough.
        1. AWS EC2: before `podman machine init`, shut down the instance then
            1. Actions → Instance settings → Change CPU options: Enable Nested virtualization

1. Java 25 LTS

### With Coursier

Publication coordinates wait on the artifact's name, which is undecided; the jar is built from a
checkout — [Development](#development).


## Usage

### Typical sequence

    java -jar ko-agent-sandbox.jar --build  # once, and again after upgrading

    java -jar ko-agent-sandbox.jar claude   # launch an agent in a trusted directory

1. Insert `--write=reject` before `<command>` when the agent must only read the directory.
1. Insert `--egress=deny-unless-model` when the agent must not talk to
   anything other than its own provider.
1. On macOS, insert `--run-on-host=sbt,mill --auto-shutdown-foreign-sbt-on-host` when the
   agent will run builds or tests: a build inside the podman machine takes memory from every
   other container there and keeps it until the session ends.

### Reference

    Run an AI agent inside the sandbox container.

    Usage, from a project directory (which becomes /workspace):

      java -jar ko-agent-sandbox.jar [options] [--] [<command> [args...]]

    <command> runs inside the sandbox: claude, codex, agy, copilot, bash, ...
    The first non-option ends launcher parsing and everything after it is
    forwarded verbatim; -- is an optional escape for a command that could
    look like a launcher option.

    Authority options, selected on every launch and never persisted:
      --write=reject|live
                         reject mounts /workspace read-only; live (the
                         default) is the shared writable mount
      --egress=deny-all|deny-unless-model|deny-unless-allowed|allow-unless-denied
                         which hosts the session reaches; the default,
                         deny-unless-allowed, admits the launcher-owned
                         defaults modified by .ko-agent-sandbox/egress/rule.
                         Each profile: doc/egress-proxy.md
      --run-on-host=<tools>
                         macOS only: sbt / mill can be run on the host. This buys
                         nothing on Linux, and cannot be securely
                         implemented on Windows. Adds the sandbox-run-on-host
                         command, which runs those build tools OUTSIDE
                         the container — on this host, confined by a
                         Seatbelt profile to the project (its git
                         control state and .ko-agent-sandbox
                         unreachable), per-project build caches, and
                         the build's own egress proxy. Host builds
                         write the project even under --write=reject.
                         SECURITY.md "Run on host" has the why and the cost;
                         doc/run-on-host.md has how it works
      --auto-shutdown-foreign-sbt-on-host
                         with --run-on-host naming sbt: when your own live
                         sbt server holds the project, a host build shuts
                         it down and proceeds — one transcript line names
                         the socket — instead of refusing until you run
                         `sbt shutdown` there. The shutdown is sent only to
                         the socket sbt derives for this project. Your warm
                         server dies with whatever clients it had; your
                         next sbt command starts a fresh one
      --env=<name>[=<value>]
                         forward the host's <name>, which must be set, into
                         the sandbox — or with <value>, set it to that
                         without exporting it on the host. Repeatable;
                         only KO_AGENT_SANDBOX_* is refused. Before
                         forwarding a secret, read SECURITY.md

    Management verbs, each recognized before the command; whatever follows
    belongs to the verb:

      --build            build the sandbox container image, always pulling remote updates
      --update           update the agents: rebuild only the sandbox container
                         image, without cache

      --reset            remove this project's containers (ending any live
                         session), volume (signing its agents out), networks,
                         TLS inspection CA, cached policy resolution, logs,
                         and workspace-filter mount; images, any shared
                         volume and the host-build caches are left
                         untouched
      --reset-cache      remove this project's host-build caches — what
                         --run-on-host builds resolved; a warm cache
                         --reset deliberately keeps
      --reset-all        the same as --reset, for every project, and the
                         whole build-cache root with them

      --egress-effective [--] [<command> [args...]]
                         print the policy the accompanying --egress=<profile>
                         resolves to for this project, with per-line
                         provenance; the command selects the model provider
                         without being launched
      --egress-check=<host> [--] [<command> [args...]]
                         one host's policy decision plus its current DNS
                         resolution, through a one-shot proxy container on
                         enforcement's own resolver path; inside a session,
                         sandbox-egress-check <host> asks the running proxy
      --proxy-log        print this project's retained proxy audit logs;
                         with extra args (-f, --tail 50), run podman logs on the
                         running proxies instead
      --stats            report the machine's memory and storage headroom,
                         live sessions, and per-project disk use across
                         the launcher's state and build-cache roots and
                         the agents' volumes, each project named by its
                         directory and any cache worth a --reset-cache
                         flagged; read-only — a stopped podman machine is
                         not started

      --self-test [<filter>]
                         run the workspace filter's own suites, always
                         pulling remote updates; <filter> selects one
                         case or family. Removes the self-test images
                         it replaces and leaves the machine otherwise
                         untouched (fuse/ko-agent-fs/doc/testing.md)

      --help             this text

    Environment:
      KO_AGENT_SANDBOX_IMAGE              sandbox image (default ko-agent-sandbox:latest)
      KO_AGENT_SANDBOX_PROXY_IMAGE        egress proxy image (default ko-agent-egress-proxy:latest)
      KO_AGENT_SANDBOX_PERSISTENT_VOLUME  share one agent-state volume across projects
      KO_AGENT_SANDBOX_MEMORY             container memory ceiling, e.g. 8g. Default: the podman
                                          machine's memory (on Linux, the host's) minus 1 GiB,
                                          and on Linux no more than was available at launch;
                                          at least 1 GiB, or the whole memory when that is
                                          less. The sandbox never swaps
      KO_AGENT_SANDBOX_WORKSPACE_GUARD    "fuse" (default) keeps /workspace shared live and
                                          writable while protecting Git control state and
                                          .ko-agent-sandbox at any depth; "none" weakens this
                                          to mount pins at the workspace root (SECURITY.md).
                                          Applies to --write=live sessions only
      KO_AGENT_SANDBOX_NESTING            "none" (default) allows no container runtime; "same-uid"
                                          allows rootless containers with one uid, host networking
                                          and session-only storage, but unmasks /proc, disables
                                          SELinux labeling and adds SYS_CHROOT for the whole
                                          session (SECURITY.md)
      KO_AGENT_SANDBOX_SESSION_START      "pause" (default) holds a launch's startup lines on
                                          screen, because the agent TUIs clear it: Enter or y
                                          starts, n or EOF at the prompt exits without starting;
                                          "immediate" starts the agent at once
      KO_AGENT_SANDBOX_CLIPBOARD          "off" (default) keeps the host clipboard out; "paste"
                                          lets the agent read a copied image; "bidirectional"
                                          also lets it set your clipboard (SECURITY.md). A
                                          Linux host needs xclip or wl-clipboard

    .ko-agent-sandbox/egress/rule in the project directory modifies the egress policy: allow
    and deny lines naming URLs, applied in order over the launcher-owned defaults
    (doc/egress-proxy.md). .ko-agent-sandbox/agent/AGENTS-CUSTOM.md replaces the image's
    conventions in the agent instructions (README "Overriding the agent instructions").


### `--build`

1. Builds the containers in the diagram with `podman build`, after refreshing every remote image
   source with a fail-closed pull.
    1. Image-producing verbs require their source registries on every run: `--build` reaches
       Docker Hub, `ghcr.io` and `gcr.io`; `--update` reaches `ghcr.io`; `--self-test` reaches
       Docker Hub. A warm cache does not provide an offline mode.
    1. The images' build context is bundled in the jar, so it runs standalone.
    1. Run it again after upgrading the jar: a launch refuses images an older jar built.
        1. `--update` is for new agent releases, not for that.
    1. Its last step removes superseded launcher images. It never removes pulled images; other
       local workloads may use them. `--update` performs the same launcher-image cleanup.
1. Also compiles `ko-agent-fs`, the workspace filter,
   from bundled source and installs the binary at `~/.local/share/ko-agent-sandbox/ko-agent-fs` —
   inside the podman machine on macOS and Windows, in your home on native Linux.
    1. Ends with the filter's self-test: an unprivileged mount over a scratch tree, with the
       `.git` policy and live host-write visibility both proven on the installed binary.
    1. The filter's `allow_other` mount needs `user_allow_other` in the machine's
       `/etc/fuse.conf`. If it is missing, `--build` shows the change as a diff and asks before
       writing that one line — never silently; the original is saved to
       `/etc/fuse.conf.ko-agent-sandbox.orig`, and declining prints the script to run yourself.
       One-time until the machine is recreated. Your native Linux host is never touched or
       prompted for.
    1. Every `--write=live` session mounts through it unless
       `KO_AGENT_SANDBOX_WORKSPACE_GUARD=none` (above) selects the mount pins, and a session that
       does says so on its `workspace:` line; `--write=reject` binds the tree read-only and needs
       neither.
    1. One filter daemon per project, shared by that project's concurrent sessions and never
       across projects ("workspace: live; ko-agent-fs filter in the podman machine, reusing the
       mount shared by sessions in the same project directory"; "on the host" on Linux); when the
       project's last session ends, it is unmounted and exits. A crashed launcher can leave one
       running — the next session's end, or `--reset`, collects it.
    1. To remove: `podman machine ssh rm .local/share/ko-agent-sandbox/ko-agent-fs`
       (plain `rm` on Linux).
    1. When something looks wrong: `fuse/ko-agent-fs/doc/troubleshooting.md`, keyed by symptom.


### Running `<command>`

1. Each launch prints both authorities — the workspace mode and the resolved egress profile —
   plus its rule file and any warning, then asks `[Y/n]` over the full command
   (`KO_AGENT_SANDBOX_SESSION_START`, Reference).
1. Agent state persists in a per-project named volume.
    1. `claude`: sign-in prints an authorization URL; open it in an external browser and paste the
       resulting code back.
        1. Ctrl-C twice in quick succession to quit.
        1. Without `KO_AGENT_SANDBOX_CLIPBOARD` (above; SECURITY.md "Clipboard") the clipboard
           does not cross into the container: Ctrl-V answers "No image found in clipboard", and
           claude 2.1.227's `/tui fullscreen` on macOS Terminal copies nothing out even with
           Shift/Alt.
    1. `codex`: "Enable device code authorization for Codex" in ChatGPT Settings → Security and
       login, then choose "Sign in with Device Code" in the login UI.
    1. `agy`: sign-in works like `claude`: open the printed URL in an external browser and paste
       the code back. Unlike `claude` and `codex`, permission prompts are not pre-disabled (agy has
       no documented settings key for it); run `agy --dangerously-skip-permissions`, or set it once
       via the in-app `/permissions` command, which persists.
    1. `copilot`: `copilot login` prints a device code and the URL to enter it at. Unlike the
       other sign-ins, the token it stores reaches your private repositories (SECURITY.md, "The
       web reached through the model provider"). Prompts for paths outside `/workspace` and for
       URLs remain unless you run `copilot --yolo`. Its fullscreen TUI cannot be turned off, so
       copying text out is `/copy`, which needs `KO_AGENT_SANDBOX_CLIPBOARD=bidirectional`.
    1. `claude --resume`, `codex resume`, `agy --continue` and `copilot --continue` work.
    1. To put permission prompts back for an untrusted repository: `codex` reads your own
       `~/.codex/config.toml` over the image's defaults, so set
       `approval_policy = "on-request"` there;
       `claude`'s are managed settings the image fixes at the highest precedence, so restoring
       them is a Containerfile edit and a rebuild; `copilot`'s is one environment variable,
       `COPILOT_ALLOW_ALL=false`.
1. More than one session can run at once from the same project directory; they share the
   workspace mount and the agent-state volume, and race on both.
1. Calling another installed agent's command or MCP server reuses that agent's login and
   configuration. Treat the project directory as their shared trust domain.
1. `KO_AGENT_SANDBOX_NESTING=same-uid` lets the session run containers of its own (recipe
   in AGENTS-SANDBOX.md): `distroless` and `alpine` images work — one uid, so
   stock `postgres` and `nginx` cannot.


## Egress proxy

Every session reaches the network through one HTTPS proxy: the launcher-owned defaults — the
agents' model providers as opaque tunnels, a curated catalog of TLS-inspected documentation,
package-registry and forge hosts — under the `--egress=` profile selected at launch, modified by
the project's `.ko-agent-sandbox/egress/rule`, one line per rule:

    deny https://github.com/                     # the forge, whole
    allow https://github.com/my-org/ read git-fetch  # then one owner, readable and clonable
    allow https://api.example/ tunnel            # an opaque tunnel: the widest word

`doc/egress-proxy.md` is the reference: the profiles, the rule grammar and what each word grants,
the policy a launch prints, the audit log and TLS inspection. SECURITY.md, "Egress proxy", is
the security model.

## Overriding the agent instructions

Every agent receives one assembled instruction file: sandbox facts from `AGENTS-SANDBOX.md`,
working conventions from `AGENTS-CUSTOM.md`, and the authority appended for this session. To
replace only the working conventions for a project, put yours at
`.ko-agent-sandbox/agent/AGENTS-CUSTOM.md`; the image's parts in
`container/ko-agent-sandbox/` are the starting point. The sandbox facts and session authority are
not overridable, and the file cannot be empty — delete it to return to the image's. The
directory's rules above apply: one filename, no symlinks, read on the host at launch, uneditable
from the sandbox, committed and reviewed with the rest. Instructions that should merely *add* to
the image's belong in the agent's own project-level instruction file, such as `CLAUDE.md`,
`AGENTS.md`, or `GEMINI.md`.

## Development

1. The launcher is the sbt project at the repository root
2. The egress proxy is its own project under `container/ko-agent-egress-proxy/app`.

### Build environment

1. Java and [sbt](https://www.scala-sbt.org)

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

1. On the host, after "Build the launcher and images" above: the variable opts the
   container-launching suites in, and they run the jar and images that step built.

    1. macOS / Linux / bash on Windows

           KO_AGENT_SANDBOX_INTEGRATION=1 sbt testFull

    1. Windows PowerShell (version 7 or later)

           $env:KO_AGENT_SANDBOX_INTEGRATION = 1 && sbt testFull

    1. Windows Command Prompt

           set "KO_AGENT_SANDBOX_INTEGRATION=1" && sbt testFull

1. On Linux, in a session with the default egress profile, which skips the container suites

       KO_AGENT_SANDBOX_SESSION_START=immediate \
           java -jar target/dist/ko-agent-sandbox.jar \
           sh -c 'find target -xtype l -delete && sbt testFull'

1. `testFull` executes every test every time, unlike `test` which is incremental.
1. The `find` removes the host sbt's cache links under `target/`, which dangle in the session
   (`container/ko-agent-sandbox/AGENTS-SANDBOX.md`). The session run adds `SessionBoundaryTest`,
   which runs only inside a session and checks the defaults, so a broader `--egress=` fails
   it.

#### egress-proxy

    (cd container/ko-agent-egress-proxy/app; sbt testFull)

#### ko-agent-fs

    java -jar target/dist/ko-agent-sandbox.jar --self-test

1. `--self-test` runs the suite that needs no mount and the suite that mounts a real filter in a
   privileged container, on any machine with podman; running either suite directly is documented in
   `fuse/ko-agent-fs/doc/testing.md`.

### Native image (optional, instant startup)

    sbt dist
    cd target/dist
    native-image --enable-native-access=ALL-UNNAMED \
      -H:IncludeResources='sandbox-build/.*|default/.*|agentsandbox/.*' \
      -o ko-agent-sandbox -jar ko-agent-sandbox.jar

1. `java -jar` starts in ~350 ms; the native image in tens of milliseconds. Put the resulting
   `ko-agent-sandbox` binary on PATH.
1. Requires GraalVM (JDK 25) with `native-image` and a C toolchain.
1. `-H:IncludeResources` embeds the bundled build context, the proxy's defaults, and the
   launcher's own resources (the `--help` text, the measured Seatbelt runtime authority) into the
   binary; native-image drops resources that are not explicitly requested.
1. The FFM `execvp` handoff is supported by native-image on recent GraalVM releases (linux/macOS,
   amd64/arm64). If a given version refuses it, the launcher still works: it falls back to staying
   resident and waiting on podman — the model native Windows always uses.


[SECURITY.md]: SECURITY.md
