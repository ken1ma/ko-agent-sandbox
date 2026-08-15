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
    │  │  read-only rootfs             ├────>│  TLS-inspects most hosts:     ├─────┼─> Internet
    │  │                               │     │  read-only, allows git clone  │     │
    │  └───────────────────────────────┘     └────┬──────────────────────────┘     │
    │    internal network, no gateway             │ the proxy's own egress network │
    │                                             │                                │
    │                                           ┌─ proxy log (audit) ───────┐      │
    │  proxy and networks are created per       │  every allow and refusal; │      │
    │  sandbox, and when it exits the two       │  outlives the run         │      │
    │  containers and networks are removed      └───────────────────────────┘      │
    └──────────────────────────────────────────────────────────────────────────────┘

1. The launcher refuses `$HOME` and above as the project directory
   (it would expose `~/.aws`, `~/.ssh`)
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
    1. The images' build context is bundled in the jar, so it runs standalone.
    1. The sandbox and proxy images record the digest of their bundled sources as a label, and a
       launch refuses a default-named image whose label does not match this jar — so a jar
       upgrade never runs silently against last month's images; the refusal says to rebuild. An
       explicitly overridden `KO_AGENT_SANDBOX_*_IMAGE` only warns. The digest also makes
       `--update` honest after a jar upgrade: it suffices exactly when the proxy's bundled
       sources did not change.
1. It also compiles `ko-agent-fs`, the workspace filter (SECURITY.md, "The workspace filter"),
   from bundled source and installs the binary at `~/.local/share/ko-agent-sandbox/ko-agent-fs` —
   inside the Podman machine on macOS and Windows, in your home on native Linux.
    1. `--build` fails unless the installed binary reports the digest of the bundled source, and
       ends with the filter's self-test (an unprivileged mount over a scratch tree).
    1. The filter's `allow_other` mount needs `user_allow_other` in the machine's
       `/etc/fuse.conf`. If it is missing, `--build` shows the change as a diff and asks before
       writing that one line — never silently; the original is saved to
       `/etc/fuse.conf.ko-agent-sandbox.orig`, and declining prints the script to run yourself.
       One-time until the machine is recreated. Your native Linux host is never touched or
       prompted for.
    1. Every session mounts through it; `KO_AGENT_SANDBOX_WORKSPACE_GUARD=none` (below) is the
       opt-out, and a session that takes it says so on its first line.
    1. One filter daemon per project, shared by that project's concurrent sessions and
       never across projects ("workspace FUSE filter: reusing the existing mount"); when the
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
1. `KO_AGENT_SANDBOX_NESTING=same-uid` lets the session run containers of its own (recipe 
   in SANDBOX.md, price in SECURITY.md): `distroless` and `alpine` images work — one uid, so
   stock `postgres` and `nginx` cannot.


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

      --build            build the container images for the sandbox
      --update           rebuild ko-agent-sandbox only without cache, for new
                         claude/codex/agy releases

      --reset            remove this project's containers (ending any live
                         session), volume (signing its agents out), networks,
                         TLS inspection CA, cached policy resolution, logs,
                         and workspace-filter mount; images and any shared
                         volume are left untouched
      --reset-all        the same, for every project

      --proxy-effective  print this project's effective egress policy
      --proxy-log        print this project's retained proxy audit logs; with
                         extra args (-f, --tail 50), run podman logs on the
                         running proxies instead

      --help             this text

    Environment:
      KO_AGENT_SANDBOX_IMAGE              sandbox image (default ko-agent-sandbox:latest)
      KO_AGENT_SANDBOX_PROXY_IMAGE        egress proxy image (default ko-agent-egress-proxy:latest)
      KO_AGENT_SANDBOX_PERSISTENT_VOLUME  share one agent-state volume across projects
      KO_AGENT_SANDBOX_MEMORY             container memory ceiling, e.g. 8g
      KO_AGENT_SANDBOX_WORKSPACE_GUARD    "fuse" (default) mounts /workspace through the ko-agent-fs
                                          filter; "none" binds it directly — a weaker boundary,
                                          pinning only .git/config and .git/hooks (SECURITY.md)
      KO_AGENT_SANDBOX_NESTING            "none" (default) allows no container runtime; "same-uid"
                                          allows one: unmasks /proc, disables SELinux
                                          labeling and adds SYS_CHROOT for the whole
                                          session, one mapped uid only (SECURITY.md)

    Files in .ko-agent-sandbox/egress-hosts/ adjust the egress policy: a +/- delta file per
    tier ("read-write", "read-only"), and "blocked" applied last.


## Egress proxy

### Modifying the egress policy

The policy is two tiers of destination hosts, and every entry names its tier:

1. `read-write` — opaque tunnels; only the agent endpoints by default.
1. `read-only` — TLS-inspected. An entry tagged `=git-fetch` also serves `git clone`/`fetch`,
   whose transfer leg is a `POST`; one tagged `=npm-audit` serves npm's install-time audit.

Create `.ko-agent-sandbox/egress-hosts/` in the project directory, holding up to three files: one
per tier, plus `blocked`. Entries are one per line; `#` comments and blank lines ignored.

Each tier file is a delta against that tier's built-in list — every entry `+host`, `-host`, or
`-**.domain` (the domain and everything under it). A `read-only` addition may carry a tag:

    # egress-hosts/read-only
    +html.spec.whatwg.org  # a spec site this project reads
    +mirror.example=git-fetch  # a git mirror: readable and clonable, never pushable

An addition states its host's complete tagging and overrides the built-in entry for the same host
— `+gitlab.com` makes gitlab.com plain read-only, its built-in `=git-fetch` gone. The tags are a
closed set the proxy defines: `git-fetch` and `npm-audit`, each named for the one operation it
opens.

`blocked` takes precedence over all the others, and only ever takes away — bare `host`,
`**.domain`, or `.defaults`, the entire built-in policy:

    # egress-hosts/blocked
    gitlab.com             # a git host this project never reads from
    **.googleapis.com      # every googleapis.com host, whatever its tier

`.defaults` names the built-in lists themselves, which turns the other files into a replacement —
block everything built in, then `+` back what the project needs:

    # egress-hosts/blocked
    .defaults              # nothing built-in survives

    # egress-hosts/read-write
    +api.anthropic.com     # re-added Claude Code's endpoints
    +claude.ai
    +platform.claude.com

1. When the directory does not exist, the proxy applies the built-in lists baked into its image —
   conservative and tuned to the author's needs for now, so expect to adjust them.
1. Every ambiguity is a failed launch with the reason printed, checked before a session's
   resources exist and again as the proxy starts: an entry without its `+`/`-` prefix, a removal
   or blocked entry matching nothing, a host both tiers claim, an unknown tag, two entries
   tagging one host differently, a tag anywhere outside a `read-only` addition, a filename that
   is none of the three (in `.ko-agent-sandbox/` itself too), a policy allowing nothing.
   [SECURITY.md] ("Adding hosts, not patterns") has why additions are exact while taking-away may
   wildcard.
1. Run `--proxy-effective` to resolve the policy to the concrete tier lists without starting a
   session. Every start prints your delta files as written — a repository-shipped policy never
   takes effect unseen — but the resolved lists only as counts: dozens of hostnames would be a
   line people learn to skip.
1. Editing the files takes effect on the next launch, which starts its own proxy; a session
   already running keeps the policy it started with.
1. The directory is meant to be committed. Review it in an unfamiliar repository before launching,
   exactly as you would its build scripts — the `read-write` file most of all.
1. A host a project adds to `read-only` is TLS-inspected like the built-in ones: the leaf
   certificate is minted from this project's resolved policy at launch.

### Audit what has been allowed or denied

    java -jar ko-agent-sandbox.jar --proxy-log

Run from the project directory. Every request from the sandbox is logged,
and the proxy appends the log to a per-run file on the host, under

    ~/.local/state/ko-agent-sandbox/log/<project>/     # Linux / macOS / WSL
    %LOCALAPPDATA%\ko-agent-sandbox\log\<project>\     # native Windows

so the record outlives the proxy container. With no arguments, `--proxy-log` prints the
retained files (the newest 20 runs) oldest first; with trailing arguments (`-f` to follow, `--tail
50` to limit) it runs `podman logs` on the currently running proxies instead, which is the live view
of the same lines. The startup lines are the effective tier lists and whether inspection is
active; every connection event after them is one line — `allow`, `deny` or `error`, then the host
and the method, then for an inspected request the full target, query string included, which is
what makes an exfiltrating `GET` visible. Those fields are stable for greps and tooling; the
trailing text is not ([SECURITY.md], "The audit line grammar", has the full inventory). A refusal
reads as

    deny github.com POST /owner/repo.git/git-receive-pack read-only path

### TLS inspection

Most of the policy is inspected: the proxy terminates the TLS of every `read-only` host so that
reading can be allowed and writing refused. Only the `read-write` hosts stay opaque.

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
   (`container/ko-agent-egress-proxy/Containerfile`). `ko-agent-fs` has two suites — one that mounts
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


[SECURITY.md]: docs/SECURITY.md
