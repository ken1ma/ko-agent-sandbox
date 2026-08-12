# A sandbox container for AI CLI tools

Status: Beta on macOS, alpha on Linux and Windows

The runtime structure:

    ┌─ Linux / macOS / Windows ────────────────────────────────────────────────────┐
    │                                                                              │
    │  ┌─ launcher ──────────────────────────────────────────────────────────┐     │
    │  │  manages the containers, volumes, and networks                      │     │
    │  └─────────────────────────────────────────────────────────────────────┘     │
    │                                                                              │
    │  ┌─ current directory (project) ─┐     ┌─ named volume (per project) ──┐     │
    │  │                               │     │                               │     │
    │  │  the only host files the      │     │  the tools' auth and config,  │     │
    │  │  sandbox can reach            │     │  kept across sessions;        │     │
    │  │                               │     │  ~/.claude, ~/.codex and      │     │
    │  │                               │     │  ~/.gemini point into it      │     │
    │  └─────┬─────────────────────────┘     └───────┬───────────────────────┘     │
    │        │                                       │                             │
    │        │ bind-mounted at /workspace, RW        │ at ~/persistent-volume, RW  │
    │        │ except .git/config, .git/hooks,       │                             │
    │        │ and .ko-agent-sandbox are read only,  │                             │
    │        │ denies creating .git entries          │                             │
    │        │                                       │                             │
    │        │                  ┌────────────────────┘                             │
    │        │                  │                                                  │
    │  ┌─ sandbox container ────┴──────┐     ┌─ egress proxy container ──────┐     │
    │  │                               │     │                               │     │
    │  │  claude / codex / agy         │     │  explicit allowlist,          │     │
    │  │  nonroot user, caps dropped,  │     │  stateless, https only,       │     │
    │  │  read-only rootfs             ├────>│  TLS-inspects forge hosts     ├─────┼─> Internet
    │  │                               │     │  (GitHub) to refuse git push  │     │
    │  └───────────────────────────────┘     └────┬──────────────────────────┘     │
    │    internal network, no gateway             │ the proxy's own egress network │
    │                                             │                                │
    │                                           ┌─ proxy log (audit) ───────┐      │
    │                                           │  every allow and refusal; │      │
    │  containers and networks are              │  outlives the run         │      │
    │  removed on exit                          └───────────────────────────┘      │
    └──────────────────────────────────────────────────────────────────────────────┘

1. The launcher refuses `$HOME` and above as the project directory
   (it would expose `~/.ssh`, `~/.aws`)
1. To work with private repositories, git clone/pull/fetch on the host first: the sandbox is not
   meant to receive your forge credentials.
   Review the sandbox's changes and commit/push on the host.
1. Nothing else, including the host's container socket, is exposed to the sandbox.

The following tools will be preinstalled:

1. Claude Code (Anthropic)
1. Codex CLI (OpenAI)
1. Antigravity CLI (Google)

The tools will be configured to

1. not ask for permissions
    1. `agy` needs a one-time step; see [Run agent](#run-agent)

[SECURITY.md] describes the security model — what the sandbox defends against, how, and what it does
not.


## Install

### Runtime Environment

1. [podman](https://github.com/containers/podman) 6.0.2 or later
    1. Download [the installer](https://github.com/containers/podman/releases)

1. Java 25 LTS

### With Coursier

TODO


## Commands

### Build container images

    java -jar ko-agent-sandbox.jar --build

1. `--build` runs `podman build` for the containers in the diagram.
    1. The images' build context is bundled in the jar, so no checkout is needed.
1. It also compiles `ko-agent-fs`, the workspace filter (SECURITY.md, "The workspace filter"),
   from bundled source and installs the binary at `~/.local/share/ko-agent-sandbox/ko-agent-fs` —
   inside the Podman machine on macOS and Windows, in your home on native Linux.
    1. `--build` fails unless the installed binary reports the digest of the bundled source, and
       ends with the filter's self-test (an unprivileged mount over a scratch tree).
    1. The filter's `allow_other` mount needs `user_allow_other` in the machine's
       `/etc/fuse.conf`. If it is missing, `--build` shows the change as a diff and **asks** before
       writing that one line — never silently; the original is saved to
       `/etc/fuse.conf.ko-agent-sandbox.orig`, and declining prints the script to run yourself.
       One-time until the machine is recreated. Your native Linux host is never touched or
       prompted for: if the self-test reports the line missing there, apply its printed fix
       yourself.
    1. Every session mounts through it. `KO_AGENT_SANDBOX_NO_FUSE_FILTER=1` binds `/workspace`
       directly instead, which is the weaker boundary: it keeps only the `.git/config` and
       `.git/hooks` pins, where the filter enforces a strict superset of them. A session that
       opts out says so on its first line.
    1. One filter daemon per project, shared by that project's sessions and never across projects.
       Concurrent sessions reuse it ("workspace FUSE filter: reusing the existing mount"); when the
       project's last session ends, it is unmounted and exits. A crashed
       launcher can leave one running — the next session's end, or `--reset`, collects it.
    1. To remove: `podman machine ssh rm .local/share/ko-agent-sandbox/ko-agent-fs`
       (plain `rm` on Linux).
    1. When something looks wrong: `fuse/ko-agent-fs/docs/troubleshooting.md`, keyed by symptom.


### Run agent

    java -jar ko-agent-sandbox.jar claude

1. The same command runs `codex` and `agy`.
1. One launcher covers Linux, macOS, WSL and native Windows.
1. Agent state persists in a per-project named volume.
    1. `claude`: sign-in prints an authorization URL; open it in an external browser and paste the
       resulting code back.
        1. Ctrl-C twice in quick succession to quit.
        1. claude 2.1.227: macOS terminal + `/tui fullscreen`:
           selecting text fails to copy to the clipboard even with Shift/Alt.

    1. `codex`: "Enable device code authorization for Codex" in ChatGPT settings,
       then choose "Sign in with Device Code" in the login UI.
    1. `agy`: sign-in works like `claude`: open the printed URL in an external browser and paste
       the code back. Unlike `claude` and `codex`, permission prompts are not pre-disabled (agy has
       no documented settings key for it); run `agy --dangerously-skip-permissions`, or set it once
       via the in-app `/permissions` command, which persists.
    1. `claude --resume`, `codex resume`, and `agy --continue` work.


### Reference

The launcher's `--help` displays

    $ java -jar ko-agent-sandbox.jar --help
    Run an AI agent inside the sandbox container.

    Usage, from a project directory (which becomes /workspace):
      java -jar ko-agent-sandbox.jar <command> [args...]

    <command> runs inside the sandbox: claude, codex, agy, bash, ...
    No arguments gives an interactive bash. Everything is forwarded
    verbatim except the verbs below, each recognized only as the first
    argument; whatever follows belongs to the verb, never to a container:

      --build          build the container images for the sandbox
      --update         rebuild ko-agent-sandbox only without cache, for new
                       claude/codex/agy releases

      --reset          remove this project's containers (ending any live
                       session), volume (signing its agents out), networks,
                       TLS inspection CA, cached policy resolution, logs,
                       and workspace-filter mount; images and any shared
                       volume are left untouched
      --reset-all      the same, for every project

      --proxy-allowed  print the egress allowlist this project would apply —
                       the built-in list adjusted by any +/- delta — without
                       starting a session
      --proxy-log      print this project's retained proxy audit logs; with
                       extra args (-f, --tail 50), run podman logs on the
                       running proxies instead

      --help           this text

    Environment:
      KO_AGENT_SANDBOX_IMAGE              sandbox image (default ko-agent-sandbox:latest)
      KO_AGENT_SANDBOX_PROXY_IMAGE        egress proxy image (default ko-agent-egress-proxy:latest)
      KO_AGENT_SANDBOX_PERSISTENT_VOLUME  share one agent-state volume across projects
      KO_AGENT_SANDBOX_MEMORY             container memory ceiling, e.g. 8g
      KO_AGENT_SANDBOX_NO_FUSE_FILTER     set to 1 to bind /workspace directly instead of
                                          through the ko-agent-fs filter — a weaker boundary,
                                          pinning only .git/config and .git/hooks (SECURITY.md)

    .ko-agent-sandbox/egress-hosts replaces or adjusts the built-in egress allowlist.


## Egress proxy

The proxy and the networks are created per sandbox.

### Modifying the allowlist

Create `.ko-agent-sandbox/egress-hosts` in the project directory — whitespace-separated hostnames,
conventionally one per line; `#` comments and blank lines ignored.

It takes one of two forms, and a file must not mix them.

**Replacement** form — bare hostnames are the complete allowlist:

    # Claude Code only; no public documentation sites
    api.anthropic.com    # model traffic (WebSearch rides this; WebFetch doesn't)
    claude.ai            # for interactive login
    platform.claude.com  # ditto

**Delta** form — every line prefixed `+` or `-`, adjusting the built-in list: `+host` adds one,
`-host` removes one, and `-**.domain` removes a whole subtree (the domain and everything under it).
Usually what you want when you only need to reach a few more sites:

    +html.spec.whatwg.org  # add a spec site
    -gitlab.com            # remove forge this project never reads from
    -**.googleapis.com     # remove every googleapis.com host

1. When `.ko-agent-sandbox/egress-hosts` does not exist, the proxy applies the built-in list baked
   into its image — conservative and tuned to the author's needs for now, so expect to adjust it.
1. Every ambiguity is a failed launch with the reason printed, checked before a session's resources
   exist and again as the proxy starts. Additions must be exact hostnames; the one wildcard is
   `-**.domain` on the removal side. [SECURITY.md] ("Adding hosts, not patterns") has the rules and
   why they are asymmetric.
1. Run `--proxy-allowed` to resolve the policy to a concrete allowlist without starting a session;
   the launcher prints the policy as written on every start, with the resolved counts.
1. Editing the file takes effect on the next launch, which starts its own proxy; a session already
   running keeps the policy it started with.
1. The file is meant to be committed. Review it in an unfamiliar repository before launching,
   exactly as you would its build scripts.
1. TLS inspection covers only the forge hosts (below). Adding another host that speaks to a
   forge — say `gist.github.com` or `github.dev` — grants an *opaque, writable* tunnel to it. Widen
   this file toward a forge only when a session genuinely needs it.

### Audit what has been allowed or denied

    java -jar ko-agent-sandbox.jar --proxy-log

Run from the project directory. Every request from the sandbox is logged,
and the proxy appends the log to a per-run file on the host, under

    ~/.local/state/ko-agent-sandbox/log/<project>/     # Linux / macOS / WSL
    %LOCALAPPDATA%\ko-agent-sandbox\log\<project>\     # native Windows

so the record outlives the proxy container. With no arguments, `--proxy-log` prints the
retained files (the newest 20 runs) oldest first; with trailing arguments (`-f` to follow, `--tail
50` to limit) it runs `podman logs` on the currently running proxies instead, which is the live view
of the same lines. The effective allowlist is the second log line and the inspected hosts the
third. For an inspected host the log also names the method and path, so a refusal reads as

    deny github.com: POST /owner/repo.git/git-receive-pack is not allowed;
    the only permitted POST is git fetch to .../git-upload-pack

### TLS inspection of the forge hosts

The GitHub, GitLab and Codeberg hosts are one part of the allowlist where the proxy looks
inside TLS, so that reading a repository can be allowed and writing to one refused. `GET`, `HEAD`
and `git fetch` are admitted; `git push`, every other `POST`, and `PUT`/`PATCH`/`DELETE` are not.

The per-project CA lives on the host, under

    ~/.local/state/ko-agent-sandbox/tls/<project>/     # Linux / macOS / WSL
    %LOCALAPPDATA%\ko-agent-sandbox\tls\<project>\     # native Windows

1. Only the leaf certificate and its key reach the proxy, never the CA key.
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

           eval $(cs java --jvm temurin:25 --env)

### Build the launcher

    sbt dist

1. This assembles one self-contained jar — a single file is the whole install.

### Tests

    sbt testFull

1. `testFull` executes every test every time,
   unlike `test` which is incremental and reports "No tests to run" when
   it believes nothing relevant changed.
1. That covers the launcher. The egress proxy has its own suite, run by its image build
   (`container/ko-agent-egress-proxy/Containerfile`). `ko-agent-fs` has two tiers — one that mounts
   nothing and runs anywhere, one that mounts a real filter in a privileged container — whose exact
   commands, the shipping musl target included, are in `fuse/ko-agent-fs/docs/testing.md`.

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
