# Sandbox environment

This container is the security boundary.

## Unprivileged user, read-only root filesystem

You are `nonroot` with `no-new-privileges` set. Linux capabilities are dropped except for
`SYS_CHROOT` when `$KO_AGENT_SANDBOX_NESTING` is `same-uid`.
You cannot become `root`; `apt-get install` and `systemctl` fail.
`/home/nonroot`, `/tmp` and `/var/tmp` are writable. The appended "What this session may do"
section gives `/workspace`'s write mode.

`/workspace` is the user's project, and the only place deliverables belong.
`/tmp` and the rest of `/home/nonroot` are discarded when the session ends.
`~/persistent-volume` survives and holds agent state, not project output. These paths point into
it: `~/.claude`, `~/.codex`, `~/.gemini`, `~/.kiro`, `~/.copilot`, `~/.local/share/kiro-cli` and
opencode's `~/.config/opencode`, `~/.local/share/opencode`, `~/.local/state/opencode`.

When `$KO_AGENT_SANDBOX_CLIPBOARD` is `paste`, read a copied image with Ctrl-V in claude or
`xclip -selection clipboard -t image/png -o`; `bidirectional` also accepts text on `wl-copy`'s
stdin. Without clipboard access, paste reports no image; tell the user to save it under the
project and pass its path instead.

With the default `ko-agent-fs` guard, new symlinks in `/workspace` must have relative targets
staying inside it; even absolute `/workspace/...` targets fail. Programs caching outside it, such
as `sbt`, fall back to copying. The appended section identifies unfiltered direct bind mounts.

### Host-cache links

Host-created symlinks keep their targets, which may be absent here. Host sbt leaves `target/`
class files linked into its cache. If compilation fails on those links, remove dangling links from
every `target` tree, including the meta-build and subprojects:

```sh
find . \( -name .git -o -name .ko-agent-sandbox \) -prune -o \
    -type d -name target -exec find {} -xtype l -delete \;
```


## Use what is already installed

Java 25, Scala (`sbt`, `cs`, `scalafmt`, and `scala`, which is Scala CLI), Python 3.14 (`uv`,
`uvx`), Node 24, Rust stable (`clippy`, `rustfmt`, and the static musl target), plus `rg`, `jq`,
`patch`, `zstd`, `openssl`, binutils, and the usual GNU text and process commands.

Absent: `make`, `g++`, `mvn`, `gradle`, `ssh`, `rsync`, `wget`, `zip`, `shellcheck`, and the
`sqlite3` CLI — use `python3 -c "import sqlite3; ..."`.


## git

Read history freely. `add`, `commit`, `checkout`, `switch`, `fetch` and `merge` work.

The default `ko-agent-fs` guard refuses these operations. Report refusals; do not work around them.

- Writing `config`, `hooks/` or rebase state in any repository under `/workspace`.
- `git init` and `git clone` under `/workspace`. Clone under `~`; the unblocked bare forms
  (`--bare`, `--mirror`) belong there too.
- `git rebase` in any form, `git am`, and a ranged or conflicted `cherry-pick`/`revert`. One
  clean `cherry-pick` or `revert` works. Do rebases on the host, or on a clone under `~`.
- `git worktree add` under `/workspace`.
- `git submodule update --init` on a submodule not yet checked out, even a public one.
  Host-initialized submodules work normally.
- Creating or editing `.ko-agent-sandbox` at any depth. Ask the user to change it on the host.

Without the filter, the appended section names the workspace-root paths mounted read-only. Do not
bypass restrictions through writable Git configuration, hooks or other Git entries in nested
repositories, symlinks with absolute targets, or symlinks that can resolve outside the project on
the host. Make those changes on the host.

Leave `git push` to the user on the host. The default egress rules refuse it.

`git config --global`, `git -c` and `GIT_AUTHOR_*`/`GIT_COMMITTER_*` work. If an identity is
missing, ask the user; never invent one. Leave changes uncommitted meanwhile.

If a task needs a private remote or any credential, report the operation to the user. Do not ask
to mount or copy credentials in, or look for another route.

Clone and build under `~`, not `/tmp`: `/tmp` is RAM, and a large checkout or build there can
take the whole podman machine down with it.

When every command turns slow, check `/proc/pressure/memory`: `some avg60` above 10 means the
machine, not this container, is short on memory. In `/sys/fs/cgroup/memory.events`, non-zero
`oom_kill` means this container reached its memory limit. For either condition, run fewer things
in parallel and report which occurred.

LFS files check out as pointer stubs; installing `git-lfs` does not help. Read content one file at
a time from
`https://media.githubusercontent.com/media/<owner>/<repo>/<ref>/<path>`.


## Installing a missing program

Everything installs into `~`, and is gone next session.

```sh
uvx PROGRAM ...             # Python program, without installing it
uv run --with PKG script.py # script that needs one dependency
npx -y PKG ...              # Node program
cs install PROGRAM          # JVM program -> ~/.local/share/coursier/bin, on PATH
curl -fsSL URL -o ~/.local/bin/PROGRAM && chmod +x ~/.local/bin/PROGRAM
```

Last resort, when only a Debian package will do:

```sh
sandbox-apt-get update
sandbox-apt-get install shellcheck   # shellcheck is then on PATH
```

It unpacks rather than installs, so a package expecting users, services or setuid bits will not
work.

Tell the user what you installed and why. Report recurring needs; only they can add programs to
the image.


## Network

The only network access outside the sandbox is through `$HTTPS_PROXY`.
The appended section gives the egress profile and how to consult its rules.

On a TLS-inspected host a write — `git push`, a `POST` or `PUT` no line grants at its path — is
refused, and the `403` body says what to do next. If a host will not connect, run
`sandbox-egress-check <host>` and report its lines to the user; do not look for another route.
For TLS errors on allowed hosts, check the trust store (below). Connections without SNI or with
Encrypted ClientHello, including browser GREASE, are closed. Inspected hosts require HTTP/1.1;
HTTP/2-only clients fail. Plain `curl` and `git` have none of these incompatibilities.

External DNS lookups fail by design; proxied requests use the proxy's DNS. A failed local lookup
does not explain a failed proxied fetch.
Programs that ignore `HTTPS_PROXY` need it spelled out — `openssl s_client -connect host:443
-servername host -proxy egress-proxy:3128`.

A program with its own trust store needs the proxy's CA:
`/etc/ko-agent-sandbox/egress-proxy-ca.crt`, or the whole bundle in `$SSL_CERT_FILE`. A JVM needs
the proxy as well, and ignores `HTTPS_PROXY`: run `sandbox-jdk-use-proxy <jdk-home>` on one you
installed yourself. The native-image `scala` and `cs` launchers need the proxy and CA options on
their command lines: `scala $KO_AGENT_SANDBOX_JAVA_OPTS run ...` or
`cs ${KO_AGENT_SANDBOX_JAVA_OPTS//-D/-J-D} fetch ...`. `sbt` needs no additional setup.


## Containers in here: only if this session opted in

At `KO_AGENT_SANDBOX_NESTING=none` (default), no container runtime is available or installable.
Do not fight it. Run services directly: PostgreSQL rootless via `initdb`/`pg_ctl`, a JVM S3 mock
such as Adobe S3Mock via `java -jar`. Bind to 127.0.0.1 and point the tests there. If a task needs
a real runtime, tell the user and stop.

At `same-uid` a runtime runs, within four limits:

- **Single uid.** An image that switches `USER` or chowns to a second uid fails — stock
  `postgres` and `nginx` included, and any `Containerfile` doing `useradd` or `install -o`.
  `alpine`, `debian`, `eclipse-temurin` and the distroless root variants work; run
  nonroot-by-default images with `--user 0`. For databases, run them as processes as above.
- **Host network only.** `-p` does not exist; services bind 127.0.0.1 directly, and egress is
  still the proxy's.
- **Most registries need a rule.** Docker Hub, `ghcr.io`, `quay.io`, `gcr.io` and
  `public.ecr.aws` are in the defaults; for any other, ask the user to add
  `allow https://<registry>/ read` to `.ko-agent-sandbox/egress/rule`. If a pull stalls, run
  `sandbox-egress-check <registry>` and report its output to the user.
- **Storage dies with the session**, and inner containers have no cgroups, so no resource limits.

podman is not preinstalled. `sandbox-install-podman` fetches and configures it:

```sh
sandbox-install-podman
export XDG_RUNTIME_DIR=/tmp/xdg          # in every shell that runs podman
podman run --rm docker.io/library/alpine:latest echo hello
```

Its "Using rootless single mapping into the namespace" warning is expected; do not try to fix it.
