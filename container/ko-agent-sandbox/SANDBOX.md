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

`.git/config` and `.git/hooks` are mounted read-only: `git config` on this repository and installing
hooks fail by design, not as breakage to work around.

A project without a repository stays that way for the session: `git init` fails on a read-only
mount, by design. A repository the user creates on the host mid-session appears here readable but
entirely read-only until the next session. In either case report it to the user rather than working
around it.

`git commit` therefore fails until an identity is set, and `git push` cannot authenticate to any
remote. Only this repository's config is pinned, so `git config --global`, `git -c` and the
`GIT_AUTHOR_*`/`GIT_COMMITTER_*` variables do still work — do not use them to invent a name and
email: the missing identity is policy, not breakage. Ask the user instead, and leave the work as
uncommitted changes in the meantime.

Pushing to GitHub, GitLab and Codeberg is disabled outright: the egress proxy refuses it with a
`403`, whatever the remote URL says, while fetching and cloning public repositories works normally —
the Network section below has the mechanics. That is policy, not a misconfiguration — report it
rather than work around it.

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

Last resort, when only a Debian package will do — unpack one into `$HOME` without root:

```sh
deb-install() {
  local root=$HOME/.local/deb apt=$root/apt
  mkdir -p "$apt"/lists/partial "$apt"/cache/archives/partial "$apt/log" "$root"
  printf 'deb https://deb.debian.org/debian trixie main\n' > "$apt/sources.list"
  local o=(-o Dir::State::Lists="$apt/lists" -o Dir::Cache="$apt/cache"
           -o Dir::Etc::SourceList="$apt/sources.list" -o Dir::Etc::SourceParts=/dev/null
           -o Dir::Etc::Preferences="$apt/prefs" -o Dir::Etc::PreferencesParts=/dev/null
           -o Dir::Log="$apt/log" -o Acquire::Languages=none)
  apt-get "${o[@]}" update -qq
  ( cd "$apt/cache/archives" && apt-get "${o[@]}" download "$@" )
  for d in "$apt"/cache/archives/*.deb; do dpkg-deb -x "$d" "$root"; done
  export PATH="$root/usr/bin:$root/bin:$PATH"
  local libs="$root/usr/lib/$(uname -m)-linux-gnu:$root/usr/lib"
  export LD_LIBRARY_PATH="$libs${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
}

deb-install shellcheck          # then run it normally
```

Three things about it:

- Dependencies are **not** resolved. Name them yourself, as in `deb-install procps libproc2-0`.
- Do not call it through a pipe. The `export`s would be lost to the subshell and the tool would
  appear not to have installed.
- `apt-get update` prints `rm: cannot remove '/var/cache/apt/archives/partial/*.deb': Permission
  denied`. That is expected and harmless — it is the read-only system cache, not the private one
  above.

## Report what you installed

Tell the user which tools you pulled in and why. If the same tool keeps being installed session
after session, say so explicitly — the fix is one line in the Containerfile, and only the user can
make it.

## Network

Everything leaves through an egress proxy, already configured in `HTTPS_PROXY` and `https_proxy`;
there is no other route out. It allows `CONNECT` to port 443 for an exact list of hostnames — no
wildcards — and requires the TLS SNI to match. In practice: `https://` to an allowed host behaves
completely normally, plain `http://` never works whatever the host, and everything else fails.

The GitHub, GitLab and Codeberg hosts are the exception to "behaves completely normally". The proxy
terminates their TLS with a certificate this image trusts, and admits only reading: `GET`, `HEAD`,
and the `POST` that `git clone` and `git fetch` need. A write — `git push`, a `POST` to the API, a
`PUT` — comes back as `403 Forbidden` from `ko-agent-egress-proxy` with the reason in the body. The
GraphQL endpoints are a `POST` and are refused with everything else, so use the REST endpoints to
read. None of that is a bug to route around; report it if it blocks the task.

There is also no resolver configured: name lookups are the proxy's job, not this container's, so
`getent hosts` and friends fail by design and that is not the reason a fetch failed. Tools that do
not read `HTTPS_PROXY` need it spelled out — e.g. `openssl s_client -connect host:443 -servername
host -proxy egress-proxy:3128`.

The allowlist actually in force for this session is at the end of these instructions, under "Egress
policy in force for this session" — the proxy's own answer, not a copy.
`KO_AGENT_SANDBOX_EGRESS_POLICY` carries the same two lines for a script to read. Consult it before
assuming a host is unreachable, and before spending a turn on a request that will be refused; the
inspected hosts in the second line are the forges, reachable but for reading only.

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
store, so a build resolving from an inspected forge host fails there with a certificate error.
`ko-agent-sandbox-trust-ca` fixes that JVM — no argument for `$JAVA_HOME`, or pass the JDK's path.
It is idempotent and reports what it did. Set it only on the build that needs the
network, and only the allowlisted registries (`repo1.maven.org`, `repo.maven.apache.org`) will
answer — a dependency from anywhere else still fails, and that is the policy, not a
misconfiguration.

## No containers in here

There is no container runtime, and the container deliberately lacks what one would need
(`/dev/net/tun`, `/dev/fuse`, an unmasked `/proc`), so installing a rootless Podman does not work
either. This is a decision, not a gap.

When a task calls for Testcontainers or docker/podman, do not install a runtime and fight it. Run
the service itself: PostgreSQL works rootless via `initdb`/`pg_ctl` as this uid, and a JVM S3 mock
(e.g. Adobe S3Mock) is a `java -jar` away. Bind to 127.0.0.1 and point the tests at localhost. If a
task genuinely cannot proceed without a real container runtime, say so to the user and stop.
