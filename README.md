# A sandbox container for AI agents

Status: Beta on macOS, alpha on Linux and Windows

The sandbox reaches no user files but the project directory (current directory), and by default
no network but a launcher-owned baseline: the agents' model providers, plus a curated catalog of
inspected read-only sites with `git clone`/`pull`, shaped per project by
`.ko-agent-sandbox/egress/`. Narrower egress — one model provider, or none — and wider — public
HTTPS — are each an explicit `--egress` profile.

    ┌─ Linux / macOS / Windows (WSL, native) ──────────────────────────────────────┐
    │                                                                              │
    │  ┌─ launcher ──────────────────────────────────────────────────────────┐     │
    │  │  runs podman to manage the containers, volumes, and networks        │     │
    │  └─────────────────────────────────────────────────────────────────────┘     │
    │                                                                              │
    │  ┌─ project directory ───────────┐     ┌─ named volume (per project) ──┐     │
    │  │  the only user files the      │     │  agents' auth and config,     │     │
    │  │  sandbox can reach            │     │  kept across sessions;        │     │
    │  │                               │     │  ~/.claude ~/.codex ~/.gemini │     │
    │  │                               │     │  ~/.copilot point into it     │     │
    │  └─────┬─────────────────────────┘     └───────┬───────────────────────┘     │
    │        │ mounted at /workspace: RW (--write=   │ at ~/persistent-volume, RW  │
    │        │ live, the default) with git control   │                             │
    │        │ state (including hooks) frozen at any │                             │
    │        │ depth, or read-only (--write=reject)  │                             │
    │        │                                       │                             │
    │        │                  ┌────────────────────┘                             │
    │        │                  │                                                  │
    │  ┌─ sandbox container ────┴──────┐     ┌─ egress proxy container ──────┐     │
    │  │  runs claude/codex/agy/copilot│     │  https only, profile-selected │     │
    │  │  nonroot user, caps dropped,  │ (a) │  hosts, stateless;            │ (b) │
    │  │  read-only rootfs             ├────>│  TLS-inspects restricted      ├─────┼─> Internet
    │  │                               │     │  hosts: read-only + git fetch │     │
    │  └───────────────────────────────┘     └────┬──────────────────────────┘     │
    │  (a) internal network, no gateway           │                                │
    │  (b) only egress network                    │                                │
    │                                           ┌─┴─ proxy log (audit) ─────┐      │
    │  the containers and networks are created  │  every allow and refusal; │      │
    │  per run, and when the sandbox exits      │  outlives the run         │      │
    │  they are all removed (not reused)        └───────────────────────────┘      │
    └──────────────────────────────────────────────────────────────────────────────┘

1. The launcher refuses `$HOME` and its ancestors as the project directory
   (it would expose `~/.aws`, `~/.ssh`), along with the well-known home
   containers (`/home`, `/Users`, the Windows profiles root), and any path
   containing a dot-prefixed directory.
1. To work with private repositories, `git clone`/`pull`/`fetch` on the host first:
   the launcher passes none of your host credentials in.
   Review the sandbox's changes and `commit`/`push` on the host.

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
    1. [Windows Prerequisite](https://github.com/podman-container-tools/podman/blob/main/docs/tutorials/podman-for-windows.md): WSL 2 or Hyper-V.  Assuming the default WSL 2 provider:
        1. `wsl --version` should show the version.
        1. No Linux distribution is needed; `wsl --install --no-distribution` is enough.
        1. AWS EC2: before `podman machine init`, shut down the instance then
            1. Actions → Instance settings → Change CPU options: Enable Nested virtualization

1. Java 25 LTS

### With Coursier

Publication coordinates wait on the artifact's name, which is undecided; the jar is built from a
checkout — [Development](#development).


## Commands

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
                         deny-unless-allowed (default) admits the
                         launcher-owned baseline shaped by
                         .ko-agent-sandbox/egress/; deny-unless-model
                         admits only the launched agent's model provider
                         (claude -> anthropic, codex -> openai, agy ->
                         google, copilot -> github; anything else, bash
                         included, admits no host); allow-unless-denied
                         admits every public host on port 443, the
                         restricted catalog staying inspected; deny-all
                         admits none
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
      --self-test [<filter>]
                         run the workspace filter's own suites, always pulling
                         remote updates; builds the self-test image on top of the
                         sandbox image, mounted cases included; <filter> selects
                         one case or family. Removes self-test images it replaces;
                         leaves no bind mount or volume and does not change Podman
                         machine configuration

      --reset            remove this project's containers (ending any live
                         session), volume (signing its agents out), networks,
                         TLS inspection CA, cached policy resolution, logs,
                         and workspace-filter mount; images and any shared
                         volume are left untouched
      --reset-all        the same, for every project

      --egress-effective [--] [<command> [args...]]
                         print the policy the accompanying --egress=<profile>
                         resolves to for this project, with per-entry
                         provenance; the command selects the model provider
                         without being launched
      --egress-check=<host> [--] [<command> [args...]]
                         one host's policy decision plus its current DNS
                         resolution, through a one-shot proxy container on
                         enforcement's own resolver path
      --proxy-log        print this project's retained proxy audit logs;
                         with extra args (-f, --tail 50), run podman logs on the
                         running proxies instead

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
      KO_AGENT_SANDBOX_WORKSPACE_GUARD    "fuse" (default) mounts /workspace through the ko-agent-fs
                                          filter; "none" binds it directly — a weaker boundary,
                                          pinning only .git/config and .git/hooks (SECURITY.md).
                                          Applies to --write=live sessions only
      KO_AGENT_SANDBOX_NESTING            "none" (default) allows no container runtime; "same-uid"
                                          allows one: unmasks /proc, disables SELinux
                                          labeling and adds SYS_CHROOT for the whole
                                          session, one mapped uid only (SECURITY.md)
      KO_AGENT_SANDBOX_SESSION_START      "pause" (default) holds a launch's startup lines on
                                          screen, because the agent TUIs clear it: Enter or y
                                          starts, n or EOF at the prompt exits without starting;
                                          "immediate" starts the agent at once
      KO_AGENT_SANDBOX_CLIPBOARD          "off" (default) keeps the host clipboard out; "paste"
                                          lets the agent read an image you copied (Ctrl-V in
                                          claude); "bidirectional" also lets it set your
                                          clipboard (SECURITY.md). A Linux host needs xclip
                                          or wl-clipboard

    Files in .ko-agent-sandbox/egress/ of the project directory modify the egress policy:
    "allowed" is a delta over the launcher-owned baseline, "denied" removes hosts and
    provider groups under every profile. .ko-agent-sandbox/agent/AGENTS-CUSTOM.md replaces
    the image's conventions in the agent instructions ("Overriding the agent instructions").


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
   inside the Podman machine on macOS and Windows, in your home on native Linux.
    1. Ends with the filter's self-test: an unprivileged mount over a scratch tree, with the
       `.git` policy and live host-write visibility both proven on the installed binary.
    1. The filter's `allow_other` mount needs `user_allow_other` in the machine's
       `/etc/fuse.conf`. If it is missing, `--build` shows the change as a diff and asks before
       writing that one line — never silently; the original is saved to
       `/etc/fuse.conf.ko-agent-sandbox.orig`, and declining prints the script to run yourself.
       One-time until the machine is recreated. Your native Linux host is never touched or
       prompted for.
    1. Every session mounts through it unless `KO_AGENT_SANDBOX_WORKSPACE_GUARD=none` (above)
       selects the mount pins, and a session that does says so on its `workspace:` line.
    1. One filter daemon per project, shared by that project's concurrent sessions and
       never across projects ("ko-agent-fs filter in the podman machine: reusing the existing
       mount"; "on the host" on Linux); when the project's last session ends, it is unmounted
       and exits. A crashed launcher can leave one running — the next session's end, or
       `--reset`, collects it.
    1. To remove: `podman machine ssh rm .local/share/ko-agent-sandbox/ko-agent-fs`
       (plain `rm` on Linux).
    1. When something looks wrong: `fuse/ko-agent-fs/doc/troubleshooting.md`, keyed by symptom.


### Running `<command>`

1. Each launch prints both authorities — the workspace mode and the resolved egress profile —
   plus its policy files and any warning, then asks `[Y/n]` over the full command
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
       `~/.codex/config.toml` over the image's defaults, so it is one setting in the volume;
       `claude`'s are managed settings the image fixes at the highest precedence, so restoring
       them is a Containerfile edit and a rebuild; `copilot`'s is one environment variable,
       `COPILOT_ALLOW_ALL=false`.
1. More than one session can run at once from the same project directory; they share the
   workspace mount and the agent-state volume, and race on both.
1. Calling another installed agent’s command or MCP server reuses that agent’s login and
   configuration. Treat the project directory as their shared trust domain.
1. `KO_AGENT_SANDBOX_NESTING=same-uid` lets the session run containers of its own (recipe
   in AGENTS-SANDBOX.md): `distroless` and `alpine` images work — one uid, so
   stock `postgres` and `nginx` cannot.


## Egress proxy

### Choosing an egress profile

Every launch selects one of four profiles with `--egress=`; `deny-unless-allowed` is the default.
A host's treatment is one of two: `unrestricted` — an opaque tunnel — or `restricted` — the
default, which an `allowed` entry spells by saying nothing — TLS-inspected, GET and HEAD only,
except for a named allowance ("Modifying the egress policy" below; SECURITY.md, "Reading without
being able to write", has what each one opens).

The launcher-owned baseline is every model-provider group (`anthropic`, `openai`, `google`,
`github` — each expanding to that provider's model, authentication and control-plane endpoints,
unrestricted, except that `github`'s forge hosts stay restricted, with `allow=github-login-device`
for the sign-in) plus a curated catalog of restricted documentation, package-registry and forge
hosts.

1. `deny-unless-allowed` (the default) — the baseline, shaped by the project's `allowed` delta.
1. `deny-unless-model` — only the launched agent's own provider group: `claude` selects
   `anthropic`, `codex` selects `openai`, `agy` selects `google`, `copilot` selects `github`.
   Only the basename of the directly launched command is classified; anything else — `bash`, a
   wrapper script — selects no provider, admits no host, and says so at startup.
1. `allow-unless-denied` — every public hostname on port 443, unrestricted, except that the
   baseline's restricted entries (plus restricted `allowed` additions) stay inspected,
   allowances and all, and `denied` still applies.
1. `deny-all` — nothing.

### Modifying the egress policy

Create `.ko-agent-sandbox/egress/` in the project directory, holding up to two files. Entries
are one per line; `#` comments and blank lines ignored.

`allowed` is a delta over the baseline, consulted by `deny-unless-allowed` (and, for its
restricted additions, by `allow-unless-denied`'s narrowing set):

    # egress/allowed
    +host html.spec.whatwg.org             # a spec site this project reads: restricted
    +host mirror.example allow=git-fetch   # a git mirror: clonable, never pushable
    +host api.example unrestricted         # an opaque tunnel: the one word that widens
    -host github.com                       # a baseline host this project drops
    -host **.example.com                   # a subtree removal: the apex and everything under it
    -model-provider google                 # a provider group this project never uses

An addition with no treatment word is restricted; `unrestricted` is the only word that widens,
so the dangerous entry is the one that says more. An addition states its host's complete
allowances and overrides the baseline entry for the same host — `+host gitlab.com` makes
gitlab.com plain restricted, its baseline `allow=git-fetch` gone. The allowances are a closed
set the proxy defines: `git-fetch`, `github-login-device` and `npm-audit`, each named for the
one operation it opens; several go in one word, `allow=git-fetch,github-login-device`. A
provider entry adds or takes back the group's own contribution and no more: `github.com` is in
the catalog (`allow=git-fetch`) and in the `github` group (`allow=github-login-device`), so
`+model-provider github` merges the login allowance in and `-model-provider github` leaves the
catalog's clonable host behind; to drop the host outright, deny the group. Widening has no
delta spelling: re-adding a restricted baseline host as `unrestricted` is refused; a project
that needs it writes `-**` — which removes the whole baseline, wherever in the file it appears;
the file's own additions stand — and states its complete replacement policy:

    # egress/allowed
    -**                                    # nothing built-in survives
    +model-provider anthropic              # re-added Claude Code's endpoints

`doc/egress-policy-examples/` holds complete `egress/` directories for common needs, a Pulumi AWS
stack among them, to copy over `.ko-agent-sandbox/egress/` and trim.

`denied` applies under every profile and only ever takes away — no `+`/`-` prefixes, no
allowances:

    # egress/denied
    host telemetry.example.com    # an exact host
    host **.googleapis.com        # the apex and every subdomain, whatever their treatment
    model-provider google         # the group, whatever its concrete endpoints become

1. An absent directory or file is empty policy input; the launcher creates the directory only
   as the empty mount target of `KO_AGENT_SANDBOX_WORKSPACE_GUARD=none` (SECURITY.md, "Silent
   changes to what you own").
   An empty *resolved* policy is valid and reported as such — `deny-all` resolves empty by
   design, as does `deny-unless-model` under `bash`.
1. Every ambiguity is a failed launch with the reason printed: an entry outside the grammar,
   duplicate additions with different treatments, a host both added and removed, a removal
   matching neither the baseline nor an addition, an unknown profile, provider, treatment or
   allowance, a filename that is neither `allowed` nor `denied` (and in `.ko-agent-sandbox/`
   itself, an entry other than `egress` or `agent`). A `denied` entry matching nothing the
   profile admits is a startup warning, not an error: it can still apply under another profile.
1. `--egress-effective` and `--egress-check=<host>` (Reference) answer without starting a
   session. Every start prints your policy files as written, and the resolved hosts as counts.
1. Editing the files takes effect on the next launch, which starts its own proxy; a session
   already running keeps the policy it started with.
1. The sandbox cannot edit them, under either write mode ([SECURITY.md], "Why the policy is per
   project, in the project, and read-only").
1. The directory is meant to be committed. Review it in an unfamiliar repository before
   launching, exactly as you would its build scripts — `unrestricted` additions most of all.

### Overriding the agent instructions

Every agent starts from one instruction file the image assembles: `AGENTS-SANDBOX.md` (what the
container is), `AGENTS-CUSTOM.md` (how to work: priorities, writing and coding style), and the
authority in force this session, appended at launch. To replace the middle part for a project,
put yours at `.ko-agent-sandbox/agent/AGENTS-CUSTOM.md`; the image's copy in
`container/ko-agent-sandbox/` is the starting point. The other two parts are not overridable, and
the file cannot be empty — delete it to return to the image's. The directory's rules above apply:
one filename, no symlinks, read on the host at launch, uneditable from the sandbox, committed and
reviewed with the rest. Instructions that should merely *add* to the image's belong in the
project's own CLAUDE.md / AGENTS.md / GEMINI.md, which every agent reads anyway.

### Audit what has been allowed or denied

Run with `--proxy-log` from the project directory. Every request from the sandbox is logged,
and the proxy appends the log to a per-run file on the host, under

    ~/.local/state/ko-agent-sandbox/log/<project>/     # Linux / macOS / WSL
    %LOCALAPPDATA%\ko-agent-sandbox\log\<project>\     # native Windows

With no arguments, `--proxy-log` prints the retained files oldest first — the newest 20 runs, and
any older one whose session is still running, since a live proxy is still appending to its file.
The startup lines are the resolved policy and whether inspection is active;
every connection event after them is one line, with an inspected request's full target — query
string included, which is what makes an exfiltrating `GET` visible. A refusal reads as

    2026-08-26T11:59:38Z deny github.com POST /owner/repo.git/git-receive-pack restricted path

[SECURITY.md], "The audit line grammar", has every field and reason.

### TLS inspection

The proxy terminates the TLS of every `restricted` host so that reading can be allowed and
writing refused. Only `unrestricted` hosts — the model providers, unless a project adds more —
stay opaque.

The per-project CA lives on the host, under

    ~/.local/state/ko-agent-sandbox/tls/<project>/     # Linux / macOS / WSL
    %LOCALAPPDATA%\ko-agent-sandbox\tls\<project>\     # native Windows

1. The CA is created on first launch and reissued a month before it expires. The leaf is reissued
   with it, and whenever the inspected host list changes.
1. Deleting that directory is how you rotate the CA. The next launch recreates it, and every
   launch's proxy starts with the certificates current at that moment.


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
   which runs only inside a session and checks the baseline policy, so a broader
   `--egress=` fails it.

#### egress-proxy

    (cd container/ko-agent-egress-proxy/app; sbt testFull)

#### ko-agent-fs

    java -jar target/dist/ko-agent-sandbox.jar --self-test

1. `--self-test` runs both of its suites — one mounts nothing and runs anywhere, one mounts a
   real filter in a privileged container — on any machine with podman; running either on its
   own is in `fuse/ko-agent-fs/doc/testing.md`.

### Native image (optional, instant startup)

    sbt dist
    cd target/dist
    native-image --enable-native-access=ALL-UNNAMED \
      -H:IncludeResources='sandbox-build/.*' \
      -o ko-agent-sandbox -jar ko-agent-sandbox.jar

1. `java -jar` starts in ~350 ms; the native image in tens of milliseconds. Put the resulting
   `ko-agent-sandbox` binary on PATH.
1. Requires GraalVM (JDK 25) with `native-image` and a C toolchain.
1. `-H:IncludeResources` embeds the bundled build context into the binary; without it `--build` and
   `--update` would find nothing to unpack, since native-image drops resources that are not
   explicitly requested.
1. The FFM `execvp` handoff is supported by native-image on recent GraalVM releases (linux/macOS,
   amd64/arm64). If a given version refuses it, the launcher still works: it falls back to staying
   resident and waiting on podman — the model native Windows always uses.


[SECURITY.md]: SECURITY.md
