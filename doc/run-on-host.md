# Run on Host — sbt and `mill` builds outside the container

`--run-on-host=<tools>` (macOS only, off by default) relays this project's sbt and `mill` builds to
the host, where each runs under a Seatbelt profile of its own. This document is the reference for
how host builds work and what they require; each piece's enforcement lives with its code:

| concern | binding site |
| --- | --- |
| the threat model, priced | `SECURITY.md` "Run on host" |
| the option, the command, what a build may write | README Reference, `--run-on-host` |
| the channel protocol and its teardown | `RunOnHostChannel.scala`, `sandbox-run-on-host` |
| the session lifecycle: publish, lock, scavenge | `RunOnHostSession.scala` |
| prerequisite validation and path policy | `RunOnHostPolicy.scala` |
| the wrapper: proxy, environment, diagnostics | `RunOnHostSandbox.scala` |
| the generated profile | `SeatbeltProfile.scala` |
| the exit criteria, measured | `src/probe/build-profile-gate.sh` |

The measurement behind the feature: an `sbt test` of this project takes about 2 GB inside the podman
machine, whose total is fixed when the machine is created and shared with every other session on
it — and whose footprint, once grown to hold a build, macOS never gets back. On the host the same
build runs on memory reclaimed when it exits, at host speed.

A host build's recurring cost is startup: sbt's server lives for one `sandbox-run-on-host` command
and `mill` runs `--no-daemon` — no warm daemon spans invocations (`SECURITY.md` "One sbt server
per project" has the security argument) — so every invocation pays JVM start and build load,
while the on-disk state stays warm: the caches, and the incremental-compile outputs under
`target/`. This is why the agent instructions say to batch commands into one invocation.

Out of scope, deliberately: arbitrary build tools (`scala-cli`, `scalafmt` and ad-hoc `scala` stay
in the container); arbitrary globally installed JVMs — Homebrew, SDKMAN and asdf JVMs included;
direct Internet access from the build; any automatic expansion of permissions when a build fails,
and any fallback to the container; implicit access to `~/.m2`, `~/.ivy2`, user git credentials, SSH
credentials or unrelated home-directory state; stdin — `sbt console`, `sbt shell` and `sbtn`'s
interactive modes; mounting the container's workspace at its host path (`TODO.md`, "same-path
mounting"). The container keeps its Scala toolchain: host builds are the fast path, not a
replacement, and a session without `--run-on-host` builds in the container as before.

## Why only macOS

The feature exists only where the guard's access-time name denies hold. What the alternatives
look like, for whoever revisits them:

On Linux, bubblewrap does the *positive* half better than Seatbelt: it starts with nothing mounted
and builds up, so the grant table holds by construction, and `--unshare-all` removes the network
namespace outright, making proxy bypass impossible rather than merely denied. But its mounts are
established once at start, so covering `.git` at any depth means binding over each one found then —
and a `.git` created during the build has no mount over it. Landlock is no better: its ruleset is
fixed at creation. With no payoff to buy — a container build already runs at host speed on host
memory, reclaimed on exit — the feature would also cost Linux the one thing the container has that a
host build does not: the cgroup ceiling that kills a runaway build inside the sandbox instead of
taking the machine down.

On Windows, AppContainer expresses the grants perfectly well: a per-user profile with a derived
SID, inheritable ACEs on the granted roots, private profile storage, network confinement by
capability plus a WFP rule restricted to the proxy endpoint. What it cannot express is the denies.
ACL inheritance has no name patterns, so "deny `.git` at any depth" can only be an enumerated set
of deny ACEs placed by a launch-time scan, and a `.git` created *during* the build inherits the
project's allow — a race where the deny must hold at every access. A Windows backend needs an
equivalent of access-time path filters — a filesystem minifilter, or a design that does not put the
guard in ACLs at all — before it is worth reconsidering.

## The contract's mechanics

The mechanics beneath the reach — what a build may touch, in whole — and the two deny rows that
make host builds safe to expose to a sandbox:

- **Writable implies executable for the project and the session temp, and for nothing else.** A
  child inherits the profile, so a build running what it wrote gains no authority it did not
  have — and a build's tests routinely write and run stubs, as this repository's own do. The agent
  cache is writable and not executable: it holds artifacts the JVM reads, and nothing there is run.
- **Seatbelt has no mount namespace**, so `$HOME` cannot be replaced with an empty directory the
  way a container image would. The profile denies it instead: a build cannot create `$HOME/.netrc`,
  a Coursier mirror file, or any other configuration a later step would read, because the write is
  denied rather than because the directory is bare.
- **Both guard rows fold case.** APFS is case-insensitive by default, so `.GIT` reaches the same
  directory as `.git`, and `ko-agent-fs` already folds on the filter's side; two guards over one
  tree protect only where they agree about a name — a write arrives through the laxer one.
- **Both guard rows deny link creation, not only writes.** On the host the project and its `.git`
  are one filesystem, so `link(PROJECT/.git/config, PROJECT/x)` would succeed and a later write to
  `x` reach `.git/config` by a path no write rule matches. `SECURITY.md` dismisses hardlinks for
  the container because `/workspace` and the container root are different filesystems; that
  argument does not transfer here.
- **The bare-layout residue stays.** A git *layout* the build assembles from ordinary names in the
  writable tree is not a `.git` directory, and neither guard refuses it — running host `git` inside
  a directory the agent created is running the agent's output, the same residue `SECURITY.md`
  records for the workspace filter.
- **The session temporary directory is the only unnamed writable space**, and it is
  session-scoped: it starts empty and no build reads temporary state left by another. That is not
  the same as an orderly exit always happening — a killed build can leave a directory, and the next
  start reclaims it rather than reuses it (`RunOnHostSession.scala`).

## Network

The build's only egress is its own proxy (below); Seatbelt permits connections to that loopback
endpoint and nothing else, with UNIX-domain sockets only inside the session temp. Loopback is every
local service, so no TCP listener or other loopback connect is granted: a test suite that binds
one — the proxy's own wire-relay tests do — gets `EPERM` on the host and runs in the container.
Three measured rules (`src/probe/loopback-rule.sh`, `src/probe/jvm-proxy-rule.sh`):

- The proxy rule is `(remote ip "localhost:<port>")`: an ip-literal host is refused by the
  compiler ("host must be * or localhost").
- The "localhost" class covers native `127.0.0.1` and `::1` but not a JVM's dual-stack connect,
  which reaches `127.0.0.1` as v4-mapped `::ffff:127.0.0.1` and dies with `EPERM`; the environment
  contract pins `-Djava.net.preferIPv4Stack=true` for exactly this.
- Seatbelt counts a local socket as network: without `(local unix-socket (subpath SESSION_TMP))`
  sbt's server gets `EPERM` from `bind()` on its boot socket and its client waits for it forever.

The proxy settings handed to the JVM are convenience, not the boundary: Seatbelt is what prevents
bypass via direct sockets, and the gate's bypass rows measure it.

Every build's proxy admits one host on its own, `repo1.maven.org:443` — Coursier's and sbt's
default Maven Central URL, not the `repo.maven.apache.org` alias almost nothing resolves against.
`repo.scala-sbt.org` is deliberately absent: it hosts the Ivy-style plugin repository and is not
part of sbt's bootstrap — an uncached sbt version named in `project/build.properties` resolves from
Maven Central. A build that needs more adds it explicitly ("Configuration", below); nothing is
inferred or silently permitted.

## Failure policy

Missing prerequisites and denied accesses fail clearly, nothing expands authority, and nothing
falls back: a host build that cannot run is reported to the user, never re-run in the
container — the same rule the egress refusal follows.

Every pre-build refusal is a `RunOnHostPolicy.Refusal` value, one case per category, so the wrapper
and the channel word the same refusal for their own readers without the tests matching on either
wording. A denial that happens mid-build has no launcher category to carry: a filesystem denial
reaches the build's own stderr as the OS error, and a network denial is the proxy's audit line,
which the wrapper reads and reports per host after the build ("Build requested network access
to: …"). It never adds the host itself.

## Tool prerequisites

The rule that explains both tools: **the user provisions the launcher; the sandbox fetches only
artifacts.** sbt's launcher comes from `cs install sbt`, and everything else it needs is a jar the
JDK reads, fetched into the writable agent cache through the proxy. `mill`'s launcher *is* the
fetched thing, and it is an executable — so it is provisioned, not fetched, and a version bump
becomes an explicit host step rather than something a build definition performs on itself.
`RunOnHostPolicy.scala` validates all of the below before a build starts; a violation is a refusal
naming what to fix, and `src/probe/host-layout.sh` shows what a host actually has.

### The JVM

Only Coursier-managed JVMs. `JAVA_HOME` is the only source, and must resolve to one canonical JDK
home under the user's Coursier cache root — `java` on `PATH` is `/usr/bin/java`, a macOS stub that
resolves through `JAVA_HOME` or `/usr/libexec/java_home`, reporting the right JVM while being the
wrong path. Rejected: the stub, `/Library/Java/JavaVirtualMachines`, Homebrew and SDKMAN JVMs, and
a `JAVA_HOME` resolving outside the Coursier cache.

A current Coursier unpacks a JDK into its archive cache, so the home is a URL-derived path under
`arc/` with a percent-encoded `+` in it. The grant is that resolved home: granting the `arc` root
instead would hand the build every archive Coursier ever extracted. The JDK is read-only to the
build, so sharing the user's copy exposes no write path, and duplicating one per project would cost
hundreds of megabytes for nothing.

### sbt

`cs install sbt`, and no arbitrary `sbt` from `PATH`: the wrapper verifies the launcher belongs to
the Coursier application-install directory — on macOS `~/Library/Application Support/Coursier/bin`,
whose space every interpolated path must survive. The launcher is two files: the 1.2 KB wrapper on
`PATH` execs a second `sbt` inside an unpacked distribution in the archive cache, and the profile
grants the distribution's *home* — the inner launcher reads `sbt-launch.jar` and `conf/` relative
to itself. The home is read from the wrapper's text (`SeatbeltProfile.sbtDistribution`); running
the wrapper to ask would execute what the profile exists to contain, on the host, unconfined.

sbt 2 is client/server by construction — there is no one-shot mode — so the server starts *inside*
the profile and its state follows `-Dsbt.global.base` into the project's agent cache. The base must
be persistent, not session-temporary: sbt 2 leaves `target/` outputs as symlinks into its
content-addressed store, so a base removed with the session would dangle the build's own outputs.
The same fact cuts the other way at entry: a tree the user's unconfined sbt built links into a
store the profile denies, so the wrapper sweeps `target/` symlinks that resolve outside the granted
roots before each build. `~/.sbt/boot` is not granted and has no consumer — with the global base
redirected, the launcher boots from the agent cache, warm across sessions. `~/.sbt/1.0`,
`~/.sbt/2.0`, `~/.ivy2` and `~/.m2` are not granted either.

The wrapper passes `--jvm-client`: sbt 2 defaults to `sbtn`, which under the profile prints that it
is starting the server and returns with no build run — a gate row keeps measuring it, and if it
starts passing, the pin becomes a choice. The inner launcher resolves `java` from `PATH`, so the
wrapper puts the granted JDK's `bin` first: the client starts the server by re-running the script,
and `-java-home` reaches the client alone.

### `mill`

A project-local bootstrap script (`<PROJECT>/mill`); no globally installed `mill`. The launcher for
the pinned version must already be provisioned — `./mill --version` once, in a host terminal,
whenever the pinned version changes — because `mill` 1.x publishes *native launchers*, and fetching
one would put an executable the sandbox chose into a directory the user's own `./mill` runs from,
outside any sandbox. What is granted is that one file, never the download folder around it, which
holds every launcher the user ever ran. A version the user never ran `./mill` for is a refusal
naming the file to run.

The wrapper resolves the version the way the bootstrap does — `MILL_VERSION`, `.mill-version`,
`.config/mill-version`, `build.mill.yaml`, the build script's `//|` header, then the script's own
default — and derives the launcher file the way the bootstrap does (`RunOnHostPolicy.millVersion`,
`millLauncher`). Reading the version is a read; asking the script by running it would execute
agent-authored shell on the host.

Three more things `mill` needs, each measured by the gate against `src/probe/mill-fixture`:
`mill-jvm-version: system` in the project — its default provisions a JVM through Coursier's index
into a writable, executable place, which is what the JVM rule refuses; `--no-daemon` — the launcher
and the daemon talk over a loopback TCP socket, which the profile denies ("Network"); and
`out/mill-daemon/` cleared at session start — the launcher memoizes its resolved classpath against
the cache of whatever run wrote it, and a memo from an unconfined run names paths the profile
denies.

## The session

`RunOnHostSession.scala` is the lifecycle: a session directory published by rename so it is never
seen half-made, a lock stating the wrapper's liveness, records owning the children's, condemnation
before collection, and the portfile-attributed shutdown of an orphaned server. The wrapper root is
`/private/tmp/ko-agent-<uid>`, short on purpose: sbt's boot socket path must fit a UNIX-domain
socket's `sun_path` (`RunOnHostPolicy.SessionTmpMaxLength`).

The build's environment is the contract, not its command line: the JVM settings travel in
`JAVA_TOOL_OPTIONS`, which every JVM in the chain reads and inherits, for the reason
`RunOnHostSandbox` states where it assembles it. The gate's `build_env` mirrors it.

## The channel and the command

`sandbox-run-on-host <tool> [args…]` is a named command, a sibling of `sandbox-apt-get`, rather
than a shim shadowing `sbt` on `PATH`: where each build ran is then visible in the transcript
the user reads. It cannot inherit `sandbox-apt-get`'s discoverability — `apt-get install` *fails*
in the sandbox and teaches the agent to look for the prefixed name, while `sbt test` in the
container *succeeds*, slower, and nothing prompts a reconsideration. So the authority section
carries the instruction, and only where it can be true: the launcher knows the platform, so a
macOS session launched without the option gets one discovery line, and Linux and Windows
sessions hear nothing about a command they can never have. That makes the host build a norm
rather than an enforcement: an agent that ignores the instruction gets a slower build, not a
refusal — a deliberate difference from the egress rule, where the proxy actually refuses.

The transport, its framing and its teardown are `RunOnHostChannel.scala`'s header and the shim's
own comments. One build runs at a time, serial by design rather than as a shortcut: one sbt server
per project means a concurrent second sbt request would be *refused* where a queued one simply runs
next, and `mill` contends on `out/` the same way; the per-transaction FIFOs leave a concurrent
broker open as a later addition if a tool ever makes it worth having. A *foreign* live server — the
user's own, holding the project's portfile — is a refusal rather than a queue entry, unless the
launch carried `--auto-shutdown-foreign-sbt-on-host`: the wrapper then ends it first, at the
socket it derives itself.

Ending it is the only resolution available, because the portfile is not merely a rendezvous: its
one-server-per-project exclusivity is also the lock over `target/`. A second rendezvous on the
same tree — a shadow base directory, a relocated portfile — would put two unsynchronized
compilers in one content-addressed store, which is why container and host builds coexist on the
source and never on the outputs. Nor can an invocation opt out: sbt's build directory is always
its working directory, and sbt 2 has no one-shot mode ("sbt", above), so every invocation either
attaches to the portfile's server or contends for it. `mill` needs none of this, running
`--no-daemon`; the upstream request that would remove the option is in `sbt-issues.md`.

## The Seatbelt profile

Apple does not document SBPL for third-party use: `sandbox-exec` compiles it through private entry
points, and the published write-ups are reverse-engineered and date from 2011. Two sources are
authoritative here — measurement (`src/probe/seatbelt-semantics.sh`,
`src/probe/build-profile-iterate.sh`), and Apple's own shipped profiles under
`/System/Library/Sandbox/Profiles/`, current and written against the implementation; `system.sb` is
the one worth reading first. `SeatbeltProfile.scala` encodes the findings, the two that shape
everything in its header. The rest, measured:

- What the guard rests on (`src/probe/seatbelt-semantics.sh`): the accessed path is canonicalized —
  a write through `link -> .git` is denied — and canonicalization folds case where the volume does;
  rules are evaluated at access time, so a `.git` created *during* the build is covered; one regex
  spans every depth; and `file-write*` already refuses a hardlink to a denied target, so the
  explicit link clause is redundancy — kept, because the membership of a wildcard operation family
  is Apple's to change.
- `/dev/tty` is the terminal, whatever stdin is: closing the child's stdin does not detach its
  controlling terminal. The profile grants `/dev/null` and the random devices only.
- An invalid profile fails exactly like a denial: `sandbox-exec` aborts the child either way, the
  difference only on its own stderr — a search that discards it chases missing grants that were
  never missing.
- What this toolchain needs, per layer: the JDK needs `sysctl-read`, its home, and
  `/System/Library/CoreServices/SystemVersion.plist` — without that one file `java` refuses to
  start with `os.version malformed: -1.0`. It does *not* need `file-map-executable`, which Apple's
  profiles use for system frameworks; a JDK outside those paths loads without it.
- Adopted from `system.sb` rather than re-derived: `file-test-existence`, a narrower operation than
  `file-read*` for the ancestor chain; and `(import "dyld-support.sb")`, Apple's own statement of
  what a process needs from the loader.

Prior art: Bazel sandboxes build actions on macOS with `sandbox-exec` — this feature's problem
exactly — and its generated profile is worth reading and worth *not* copying. It is a blacklist
(`(allow default)`, then writes and network taken away), which is why Bazel never meets the
findings above: with nothing denied by default, path resolution cannot fail, so the root entry and
the ancestor chain never arise. It is also why that design cannot serve here: a build under it reads
the whole filesystem, and "everything else user-owned inaccessible" is the property this feature
exists to provide. The difficulty of deny-by-default is the price of that row, not evidence of a
wrong turn — worth stating because the blacklist form is the obvious simplification when the
whitelist will not start. One thing is taken from Bazel: `(debug deny)`, which makes denials
visible without the unified log's redaction, and which `src/probe/build-profile-iterate.sh` puts
at the top of every profile it iterates.

**Runtime authority** — the loader, libc, the CA bundle and the rest a toolchain needs from the
system — is discovered by running a real build under a deny-default profile and reading the
denials, never by listing what a host happens to have, and never as a way to reach a user path. The
measured set is one file, a resource of the launcher's own artifact
(`src/main/resources/agentsandbox/runtime-authority.txt`): what the production wrapper grants is
what the probes measured, and the gate and a session run one authority rather than two copies that
can drift. `src/probe/build-profile-iterate.sh` is how the file grows. Do not pre-authorize broad
paths (`/System/**`, `/usr/**`, `/opt/homebrew/**`); add the narrowest rule testing justifies.

## The build's egress proxy

Each build runs its own proxy process, from the same codebase as the container's.

Not the session's proxy: that one is per run, on a network created `--internal`, inside the podman
machine. There is no host route to it, and making one would either publish the session's full
`--egress` allowlist — `api.anthropic.com` and forges included — to any host process, or relay each
connection through `podman exec`, paying the VM round trip on exactly the path the build was moved
out of the VM to avoid. A JVM proxy client speaks TCP, so a loopback listener is unavoidable either
way; what is worth controlling is the policy behind it, and a proxy admitting one artifact
repository is a prize barely worth stealing.

Its lifetime is the session's, bound to the session lock rather than to the client process: the
server the client forks is what resolves, and it lives past the client until the wrapper ends it.
Binding to the lock keeps the answer unchanged if a warm server spanning invocations is ever added.

Its vehicle is the launcher's own artifact: the proxy sources share the launcher's Scala version,
`dist` compiles them in beside their `/default` resources, and the wrapper starts the proxy by
re-invoking whichever vehicle it is running in — `java -jar` or the native binary — under a private
verb. It binds an ephemeral port on `127.0.0.1` (the codebase's wildcard `:3128` default is safe
only in the container's own network namespace), and the wrapper reads the port from the same ready
line the container launcher gates on.

It runs unconfined, unlike the container's hardened copy of the same codebase — the one process
that parses hostile bytes from the thing being sandboxed, holding the uid whose files the profile
exists to deny. Accepted, not a hole: a JVM parse bug is an exception, the listener is
loopback-only, and `HostileInputTest` covers the surface; a Seatbelt profile of the proxy's own is
low-value defense in depth, deferred in `TODO.md`.

It runs without inspection material: no-material mode enforces the destination host and port at
CONNECT time and tunnels opaquely, so the build needs no extra trust material and the read-only
JDK's own trust store suffices. If inspection is ever wanted, point the JVM at a wrapper-owned
store with `-Djavax.net.ssl.trustStore` rather than touching the JDK.

## Configuration

A build that resolves beyond Maven Central names its repositories in a project file, in the
directory that already holds reviewed boundary configuration:

```text
.ko-agent-sandbox/host-command/<tool>/egress/rule
```

One file per tool, so a repository that builds with both grants each only what it resolves. The
grammar is its own, narrower than the proxy's: `allow https://<host>/ read` lines and comments,
nothing else — no other grant, no path, no provider, no deny — refused at validation rather than
passed through. The full grammar would let one `allow model-provider` line expand into endpoints
that are no artifact repository, and a `tunnel` word means nothing to a proxy running without
inspection. The wrapper hands the proxy `deny defaults`, Maven Central, then the file's lines
(`RunOnHostPolicy.egressRuleText`), so the container's catalog contributes nothing.

The file inherits the directory's properties: the workspace filter freezes it at any depth, the
launcher reads it on the host, and it is reviewed in a pull request like any other file.
`host-command/` extends `.ko-agent-sandbox`'s closed namespace — a stray entry fails the launch and
never sits as ignored config (`SandboxProject.policyDirError`, `RunOnHostSandbox.hostCommandStray`).

Neither tool needs a GitHub release CDN: the only fetch that ever used one is the `mill`
bootstrap's own launcher download, which the user provisions on the host instead.

Derived paths come from Coursier conventions and environment APIs; advanced overrides
(`cache-root`, `jvm-root`, `install-root`) are not added until needed.

## The build cache

Agent-invoked builds get their own build-cache root, per project —
`${XDG_CACHE_HOME:-~/.cache}/ko-agent-sandbox/cache/<projectId>/`, Coursier's `v1` and sbt's global
base under one directory, so `--reset-cache` is a single removal and a further cache kind can join
without moving anything. It is discovered exactly as the launcher's state root is, so the two
answer alike on one machine; a relative override is refused because it would resolve against the
repository being sandboxed, and a root inside the project is refused outright.

Why not the user's cache: `SECURITY.md` "Cache poisoning stops at the project" prices it. The cost
is a cold cache on a project's first agent build, warm from the second onward.

Why not the launcher state root: the state root is kind-first (`tls/<id>`, `log/<id>`, …) and the
proxy's audit log must not sit beside the CA key. On the host the build runs as the user's own uid,
which owns that key, so file permissions protect nothing and the profile is the only thing standing
there; a separate root makes its job structural — no path the build is ever granted has a sensitive
ancestor or sibling. `XDG_CACHE_HOME` is also simply where a reconstructible cache belongs.

The build reaches its cache through one variable: the wrapper sets `COURSIER_CACHE` to the `v1`
directory, which the sbt launcher, sbt's own resolution and Coursier all honour.

## Sources

- Coursier managed JVMs and platform JVM-cache locations: https://get-coursier.io/docs/cli-java
- Coursier artifact cache and platform `v1` locations:
  https://get-coursier.io/upcoming/features-cache/
- Coursier installation/application directory behavior:
  https://get-coursier.io/docs/cli-installation
- `mill` project-local bootstrap scripts: https://mill-build.org/mill/cli/installation-ide.html
- sbt server — domain-socket and TCP modes, the port file, discovery and the token:
  https://www.scala-sbt.org/1.x/docs/sbt-server.html
