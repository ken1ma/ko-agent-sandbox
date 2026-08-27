# Sandbox environment

You are running inside a container that is the security boundary.

## Unprivileged user, read-only filesystem

You are `nonroot` with `no-new-privileges` set and every Linux capability dropped.
`root` cannot be obtained.
`apt-get install`, `systemctl` fail.
`/home/nonroot`, `/tmp` and `/var/tmp` are writable; whether `/workspace` is, is this session's
write mode — the appended "Authority in force for this session" section says which.

`/workspace` is the user's project, and the only place deliverables belong.
`/tmp` and the rest of `/home/nonroot` are discarded when the session ends.
`~/persistent-volume` — where `~/.claude`, `~/.codex`, `~/.gemini` and `~/.copilot` point —
survives, and holds agent state, not project output.

The host clipboard is reachable only when `KO_AGENT_SANDBOX_CLIPBOARD` is set: `paste` serves an
image the user copied (Ctrl-V in claude, or `xclip -selection clipboard -t image/png -o`), and
`bidirectional` also accepts text on `wl-copy`'s stdin. Unset, a paste reports no image; tell the
user to save the image under the project and pass its path instead.

A symlink in `/workspace` needs a relative target staying inside it; anything else, an absolute
`/workspace/...` included, fails. A tool that caches outside the workspace, such as `sbt`,
falls back to copying instead of linking.

The host's own symlinks are served as they are, so one with an absolute target dangles in here.
sbt on the host leaves `target/` class files as links into its cache; a compile then fails.
`find target -xtype l -delete` removes just the dead links.


## Use what is already installed

Java 25, Scala (`sbt`, `scala-cli`, `cs`, `scalafmt`), Python 3.14 (`uv`, `uvx`), Node 24, Rust
stable (`clippy`, `rustfmt`, and the static musl target), plus `rg`, `jq`, `patch`, `zstd`,
`openssl`, binutils, and the usual GNU text and process commands.

Absent: `make`, `g++`, `mvn`, `gradle`, `ssh`, `rsync`, `wget`, `zip`, `shellcheck`, and the
`sqlite3` CLI — for that last one use `python3 -c "import sqlite3; ..."`.


## git

Read history freely. `add`, `commit`, `checkout`, `switch`, `fetch` and `merge` work.

These fail, by policy. Report them; do not work around them.

- Writing `config`, `hooks/` or rebase state in any repository under `/workspace`.
- `git init` and `git clone` under `/workspace`. Clone under `~` instead — the bare forms
  (`--bare`, `--mirror`) are not blocked, but belong under `~` all the same.
- `git rebase` in any form, `git am`, and a ranged or conflicted `cherry-pick`/`revert`. One
  clean `cherry-pick` or `revert` works. Do rebases on the host, or on a clone under `~`.
- `git worktree add` under `/workspace`.
- `git submodule update --init` on a submodule not yet checked out; being public does not help.
  One the host already initialized is an ordinary directory to work in.
- Creating or editing `.ko-agent-sandbox` at any depth. Ask the user to change it on the host.
- `git push` to any remote, and `git commit` until an identity is set.

`git config --global`, `git -c` and `GIT_AUTHOR_*`/`GIT_COMMITTER_*` do work. Do not use them to
invent a name and email — ask the user, and leave the work as uncommitted changes meanwhile.

If a task needs a private remote, or any other credential, report the operation to the user. Do
not ask for a credential to be mounted or copied in, and do not look for another route.

Clone and build under `~`, not `/tmp`: `/tmp` is RAM, and a large checkout or build there can
take the whole podman machine down with it.

When every command turns slow, read `/proc/pressure/memory` — it is the machine's, not this
container's; `some avg60` above 10 means the machine is short — and
`/sys/fs/cgroup/memory.events`, where a non-zero `oom_kill` means this container hit its own
ceiling. Either way run fewer things in parallel, and tell the user which of the two it was.

An LFS-tracked file checks out as its pointer stub, and installing `git-lfs` will not change
that. Read the content one file at a time from
`https://media.githubusercontent.com/media/<owner>/<repo>/<ref>/<path>`.


## Installing a tool that is genuinely missing

Everything installs into `~`, and is gone next session.

```sh
uvx TOOL ...                # Python tool, without installing it
uv run --with PKG script.py # script that needs one dependency
npx -y PKG ...              # Node tool
cs install TOOL             # JVM tool -> ~/.local/share/coursier/bin, on PATH
curl -fsSL URL -o ~/.local/bin/TOOL && chmod +x ~/.local/bin/TOOL
```

Last resort, when only a Debian package will do:

```sh
sandbox-apt-get update
sandbox-apt-get install shellcheck   # `shellcheck` is then on PATH
```

It unpacks rather than installs, so a package expecting users, services or setuid bits will not
work.

Tell the user what you installed and why. If the same tool is needed session after session, say
so — only they can add it to the image.


## Network

The only egress is an HTTPS tunnel through `HTTPS_PROXY`. Which hosts this session reaches, and
with what treatment, is the appended "Authority in force for this session" section;
`KO_AGENT_SANDBOX_EGRESS_POLICY` carries the same lines.

On a restricted host, a `git push`, an API `POST`, a `PUT` are refused by the proxy, with the
reason in the body. GraphQL is a `POST`; read through REST.

If a host will not connect, name it to the user and stop. Do not look for another route, and do
not spend the session diagnosing it — they can add a host in seconds.

`getent hosts` and every other name lookup fail by design; that is never why a fetch failed.
Tools that ignore `HTTPS_PROXY` need it spelled out — `openssl s_client -connect host:443
-servername host -proxy egress-proxy:3128`.

A tool with its own trust store needs the proxy's CA: `/etc/ko-agent-sandbox/egress-ca.crt`, or
the whole bundle in `$SSL_CERT_FILE`. A JVM needs the proxy as well, and ignores `HTTPS_PROXY`:
run `sandbox-prepare-jdk <jdk-home>` on one you installed yourself.


## Containers in here: only if this session opted in

At `KO_AGENT_SANDBOX_NESTING=none` — the default — there is no container runtime and installing
one fails. Do not fight it. Run the service itself: PostgreSQL rootless via `initdb`/`pg_ctl`, a
JVM S3 mock such as Adobe S3Mock via `java -jar`. Bind to 127.0.0.1 and point the tests there. If
a task cannot proceed without a real runtime, say so to the user and stop.

At `same-uid` a runtime runs, within four limits:

- **Single uid.** An image that switches `USER` or chowns to a second uid fails — stock
  `postgres` and `nginx` included, and any `Containerfile` doing `useradd` or `install -o`.
  `alpine`, `debian`, `eclipse-temurin` and the distroless root variants work; run
  nonroot-by-default images with `--user 0`. For databases, run them as processes as above.
- **Host network only.** `-p` does not exist; services bind 127.0.0.1 directly, and egress is
  still the proxy's.
- **Most registries need the allowlist.** Docker Hub, `gcr.io` and `public.ecr.aws` are in the
  baseline; for any other, ask the user to add `+host <registry>` to
  `.ko-agent-sandbox/egress/allowed`. A stalled pull is a refused host.
- **Storage dies with the session**, and inner containers have no cgroups, so no resource limits.

podman is not preinstalled. `sandbox-install-podman` fetches and configures it:

```sh
sandbox-install-podman
export XDG_RUNTIME_DIR=/tmp/xdg          # in every shell that runs podman
podman run --rm docker.io/library/alpine:latest echo hello
```

Its "Using rootless single mapping into the namespace" warning is this mode working, not a
problem to fix.
