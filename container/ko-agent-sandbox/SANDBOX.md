# Sandbox environment

You are running inside a container that is the security boundary.

## Unprivileged user, read-only filesystem

You are uid 65532 (`nonroot`), with all Linux capabilities dropped and `no-new-privileges` set.
There is no way to obtain `root`. `apt-get install`, `systemctl`, and any write outside the table
below fail with `Read-only file system` or `Permission denied`.

| Path                   | Writable | Survives container exit          |
| ---------------------- | -------- | -------------------------------- |
| `/workspace`           | yes      | yes — bind-mounted from the host |
| `~/persistent-volume`  | yes      | yes — agent auth and config only |
| `~` (`/home/nonroot`)  | yes      | **no**                           |
| `/tmp`, `/var/tmp`     | yes      | **no**                           |
| everything else        | no       | —                                |

`/workspace` is the user's project and the only place deliverables belong.

`~/.claude`, `~/.codex` and `~/.gemini` are symlinks into `~/persistent-volume`; that volume is for
agent state, not for project output or scratch files. The rest of `~` is discarded on exit, so build
caches (`~/.cache`, `~/.sbt`, `~/.npm`) work normally but are rebuilt from scratch next session.

## Use what is already installed

| Area           | Available                                                       |
| -------------- | --------------------------------------------------------------- |
| search, text   | `rg`, `jq`, `file`, `diff`, `patch`, `awk`, `sed`               |
| processes      | `ps`, `pgrep`, `top`, `free`, `pstree`, `fuser`, `killall`      |
| archives       | `tar`, `unzip`, `xz`, `zstd`, `gzip`                            |
| Java 25 LTS    | `java`, `javac`, `jar`, `jshell`, `keytool`                     |
| Scala          | `scala`, `scala-cli`, `scalac`, `sbt`, `scalafmt`, `cs`         |
| Python 3.14    | `python3`, `uv`, `uvx`                                          |
| Node 24 LTS    | `node`, `npm`, `npx`                                            |
| Rust stable    | `cargo`, `rustc`, `rustfmt`, `clippy`, musl target (static)     |
| binaries       | `strings`, `objdump`, `readelf`, `nm`, `ldd`                    |
| net, TLS       | `curl`, `openssl`                                               |

One omission is deliberate, because something installed already covers it:

- **No `sqlite3` CLI.** Python's bundled module reads project databases: `python3 -c "import
  sqlite3; ..."`.

Also absent: `make`, `g++`, `mvn`, `gradle`, `ssh`, `rsync`, `wget`, `zip`, `less`,
`shellcheck`, `git-lfs`.

## git

The repository under `/workspace` is real and writable, but this container carries no identity: no
`user.name`, no `user.email`, no credential helper, and no SSH key. Reading history — `log`, `diff`,
`show`, `blame` — works normally, as do `git add` and `git fetch`.

Git's control state — `config`, `hooks/`, the redirection files, rebase todo — is frozen by the
workspace filter serving `/workspace`: writing any of it fails with `Operation not permitted`, in
every repository in the tree, by design and not as breakage to work around. Operational state
(`index`, refs, objects, `HEAD`, reflogs) stays writable, so `status`, `add`, `commit`, `checkout`,
`switch`, `fetch` and `merge` work normally.

The same filter refuses to create any entry named `.git`, at any depth and under any spelling a
case-insensitive filesystem would fold to it. Consequences, each enforced rather than conventional:

- `git init` and `git clone` anywhere under `/workspace` fail. Clone under `/tmp` (more below).
- `git rebase` (any form), `git am`, and a ranged or conflicted `cherry-pick`/`revert` fail: their
  todo files can carry `exec` lines a later host-side `git rebase --continue` would run. A single
  clean `cherry-pick` or `revert` works. Do rebases on the host, or on a clone under `/tmp`.
- `git worktree add` into `/workspace` fails (it writes a `.git` pointer file at the new worktree).

Report these to the user rather than working around them. A repository the user creates on the
host mid-session appears here immediately — the filter serves the live tree — writable in its
operational state like any other, with the same control files frozen.

`git commit` fails until an identity is set, and `git push` cannot authenticate to any remote.
Repository config is frozen, but `git config --global`, `git -c` and the
`GIT_AUTHOR_*`/`GIT_COMMITTER_*` variables do still work — do not use them to invent a name and
email: the missing identity is policy, not breakage. Ask the user instead, and leave the work as
uncommitted changes in the meantime.

Pushing to GitHub, GitLab or Codeberg is disabled outright: the proxy refuses it whatever the
remote URL says, while fetching and cloning public repositories works normally — the Network
section below has the mechanics. That is policy, not a misconfiguration — report it rather than
work around it.

Clone upstream repositories under `/tmp`, never into `/workspace`: the workspace is the user's own
checkout, and a repository created inside it is residue the user then has to distrust and clean up.
One caveat at scale: `/tmp` is tmpfs, so a checkout or build output there is paid for in the
machine's RAM — a multi-gigabyte build can take down the whole podman machine, not just this
container. For gigabyte-scale work use a directory under `~` instead: disk-backed, equally
discarded on exit.

If a task needs a private remote, or any other credential that is not available in here, report the
required operation to the user. Do not ask for the credential to be mounted or copied into the
sandbox, and do not search for another route around the restriction — credentialed operations happen
on the host by design.

An LFS-tracked file checks out as its small pointer stub: the proxy refuses the LFS batch endpoint,
and installing git-lfs would not change that. Read the real content one file at a time from
`https://media.githubusercontent.com/media/<owner>/<repo>/<ref>/<path>`, which is where the GitHub
API's `download_url` points for such a file.

## Installing a tool that is genuinely missing

Everything here installs into `~` (ephemeral).

```sh
uvx TOOL ...                # Python tool, without installing it
uv run --with PKG script.py # script that needs one dependency
npx -y PKG ...              # Node tool
cs install TOOL             # JVM tool -> ~/.local/share/coursier/bin, on PATH
curl -fsSL URL -o ~/.local/bin/TOOL && chmod +x ~/.local/bin/TOOL
```

`npm install -g` works and lands in `~/.local`, but is discarded on exit like everything else in
`~`.

Last resort, when only a Debian package will do: `sandbox-apt-get` (preinstalled) speaks
apt-get's verbs but unpacks into `$HOME` without root, dependencies resolved against what the
image already has:

```sh
sandbox-apt-get update
sandbox-apt-get install shellcheck   # `shellcheck` is then on PATH
```

Behind it is plain apt pointed at directories under `~/.local/deb` — Release signatures still
verified through the image's own keyrings — then every fetched archive is unpacked and each new
command gets a wrapper in `~/.local/bin` carrying the library path it needs, so nothing has to be
exported and it works from any shell, script, or pipe. Three things about it:

- **It is not an install**, and `apt-get install` itself never works here (read-only rootfs,
  uid 65532) — that is why this exists. No maintainer scripts run and nothing registers with dpkg,
  so a package expecting users, services, or setuid bits will not function.
- **A command the image already provides is never shadowed**: a dependency chain that happens to
  carry `python3` cannot change which `python3` the session runs. The tool says what it skipped.
- **Recommends are included**, so a metapackage arrives runnable (installing `podman` brings
  `netavark`, `passt`, `fuse-overlayfs`, …) at the cost of pulling more than the strict minimum.

## Report what you installed

Tell the user which tools you pulled in and why. If the same tool keeps being installed session
after session, say so explicitly — the fix is one line in the Containerfile, and only the user can
make it.

## Network

Everything leaves through an egress proxy, already configured in `HTTPS_PROXY` and `https_proxy`;
there is no other route out. It allows `CONNECT` to port 443 for an exact list of hostnames — no
wildcards — and requires the TLS SNI to match. In practice: `https://` to an allowed host behaves
completely normally, plain `http://` never works whatever the host, and everything else fails.

Most hosts are an exception to "behaves completely normally". The policy is two tiers:
read-write hosts (the agent endpoints) behave normally; every other host is read-only — the proxy
terminates TLS with a certificate this image trusts and admits `GET` and `HEAD` only. Package
installs work normally, npm's install-time audit included. The read-only entries tagged
`=git-fetch` — GitHub, GitLab
and Codeberg — additionally admit the `POST` that `git clone` and `git fetch` need. A write —
`git push`, a `POST` to an API, a `PUT` — comes back as `403 Forbidden` from
`ko-agent-egress-proxy` with the reason in the body. The GraphQL endpoints are a `POST` and
are refused with everything else, so use the REST endpoints to read. None of that is a bug to
route around; report it if it blocks the task.

There is also no resolver configured: name lookups are the proxy's job, not this container's, so
`getent hosts` and friends fail by design and that is not the reason a fetch failed. Tools that do
not read `HTTPS_PROXY` need it spelled out — e.g. `openssl s_client -connect host:443 -servername
host -proxy egress-proxy:3128`.

The policy actually in force for this session is at the end of these instructions, under "Egress
policy in force for this session" — the proxy's own answer, one line per tier, not a copy.
`KO_AGENT_SANDBOX_EGRESS_POLICY` carries the same two lines for a script to read. Consult it
before assuming a host is unreachable, and before spending a turn on a request that will be
refused.

Built-in web search (Claude Code's WebSearch, Codex's equivalent) runs on the model provider's
servers, not from in here, so it works regardless of this proxy and can describe hosts you cannot
reach. WebFetch, curl and every other direct request go through the proxy: an allowed host works,
everything else is refused and logged. Search succeeding while a fetch of the same site fails is
therefore the policy working, not a fault to diagnose.

If a host will not connect, name it to the user and stop. Do not look for another route to it, and
do not spend the session diagnosing it: that policy is part of the boundary, not an obstacle to
route around. The user can add a host in seconds once you say which one you need — and the proxy
logs every refusal on the host, so they can see exactly what you asked for.

One quirk, so you do not rediscover it the hard way: **JVM tools ignore `HTTPS_PROXY`.** `cs`, `sbt`
and `scala-cli` read the `-Dhttps.proxyHost` / `-Dhttps.proxyPort` system properties instead, so out
of the box any of them that has to resolve a dependency it has not already cached will simply hang
and then fail. Point them at the proxy for that command:

    JAVA_TOOL_OPTIONS="-Dhttps.proxyHost=egress-proxy -Dhttps.proxyPort=3128 \
        -Dhttp.proxyHost=egress-proxy -Dhttp.proxyPort=3128" sbt ...

It is not set globally because it prints a `Picked up JAVA_TOOL_OPTIONS` banner on stderr for every
JVM start, which corrupts output that other tools parse.

A second JVM quirk, if you install one: the JDK in this image already trusts the egress proxy's
inspection CA, but a JVM you install yourself (`cs java --jvm temurin:25`) brings its own trust
store, so a build resolving from any inspected host (a git host, `javadoc.io`, a doc site) fails
there with a certificate error.
`sandbox-trust-ca` fixes that JVM — no argument for `$JAVA_HOME`, or pass the JDK's path.
It is idempotent and reports what it did. Set it only on the build that needs the
network, and only the allowlisted registries (`repo1.maven.org`, `repo.maven.apache.org`) will
answer — a dependency from anywhere else still fails, and that is the policy, not a
misconfiguration.

## Containers in here: only if this session opted in

Check `KO_AGENT_SANDBOX_NESTING`. At `none` (the default, what unset means), there is no
container runtime and the container deliberately lacks what one would need (an unmasked `/proc`,
a chroot for layer unpack), so installing a rootless Podman does not work: the attempt dies with
a permission error, at layer unpack (``after fallback to chroot: operation not permitted``) or at
crun's fresh `/proc` mount. That is a decision, not a podman bug.
When a task calls for Testcontainers or docker/podman, do not install a runtime and fight it. Run
the service itself: PostgreSQL works rootless via `initdb`/`pg_ctl` as this uid, and a JVM S3 mock
(e.g. Adobe S3Mock) is a `java -jar` away. Bind to 127.0.0.1 and point the tests at localhost.
If a task genuinely cannot proceed without a real container runtime, say so to the user and stop —
relaunching with the variable is the user's call.

With `KO_AGENT_SANDBOX_NESTING=same-uid`, a runtime can run, within hard limits it cannot exceed:

- **Single uid.** Exactly one uid exists in a nested namespace, so an image that switches `USER` or
  chowns to a second uid fails by design — stock `postgres` and `nginx` included (each chowns its
  data or cache directories to its service user), and
  any `Containerfile` doing `useradd` or `install -o`. Root-only images and builds work: `alpine`,
  `debian`, `eclipse-temurin`, and the distroless root variants. Nonroot-by-default images —
  distroless `:nonroot`, Chainguard — run with `--user 0`, which lands on the same one uid anyway.
  For databases, the run-it-as-a-process guidance above still stands.
- **Host network only.** Inner containers share this sandbox's network namespace: `-p` does not
  exist, services bind 127.0.0.1 directly (which is where tests want them), and egress remains the
  proxy's — an inner container can reach nothing this sandbox cannot. They share the hostname too:
  the recipe's `utsns = "host"`, because `sethostname` in a fresh UTS namespace is refused for
  want of a capability this sandbox does not carry.
- **Most registries need the allowlist.** A pull is ordinary egress. Docker Hub, `gcr.io`
  (distroless) and `public.ecr.aws` (Amazon Linux) are on the built-in list and pull as-is; any
  other registry (`+ghcr.io`, `+quay.io`) goes in the project's
  `.ko-agent-sandbox/egress-hosts/read-only` first. If a pull stalls, the proxy log on the host
  names the refused host to add.
- **Storage dies with the session** (it lives under `~`), so every session re-pulls; and inner
  containers run cgroup-less, so per-container resource limits are unavailable.

podman is not preinstalled — it would be dead weight in every default session.
`sandbox-apt-get install podman` brings the whole rootless stack (crun, conmon, netavark — unused
under host networking, but podman refuses to start without the binary):

```sh
sandbox-apt-get update
sandbox-apt-get install podman

export XDG_RUNTIME_DIR=/tmp/xdg; mkdir -p $XDG_RUNTIME_DIR ~/.config/containers
cat > ~/.config/containers/containers.conf <<EOF
[containers]
netns = "host"
utsns = "host"
cgroups = "disabled"
[engine]
events_logger = "file"
helper_binaries_dir = ["$HOME/.local/deb/usr/lib/podman", "$HOME/.local/deb/usr/bin"]
[engine.runtimes]
# via the ~/.local/bin wrapper: helper_binaries_dir would resolve the unwrapped crun,
# which cannot find its own libraries
crun = ["$HOME/.local/bin/crun"]
EOF
printf '{ "default": [ { "type": "insecureAcceptAnything" } ] }\n' \
    > ~/.config/containers/policy.json
printf 'unqualified-search-registries = ["docker.io"]\n' > ~/.config/containers/registries.conf
printf '[storage]\ndriver = "overlay"\n[storage.options]\nignore_chown_errors = "true"\n' \
    > ~/.config/containers/storage.conf

podman run --rm docker.io/library/alpine:latest echo hello-from-alpine
```

podman's startup warning — "Using rootless single mapping into the namespace. This might break some
images." — is this mode working as designed, not a problem to fix.
