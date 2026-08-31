# Native sbt / Mill Build Sandbox — Implementation Plan

**Target platform:** macOS 26.4+
**Build tools:** sbt, Mill
**Primary goal:** run the sandboxed agent's Scala builds natively — at host speed, on host memory —
granting only the filesystem and network access the build requires.

---

## 1. Scope

A native build sandbox, and the channel that lets the agent inside the container reach it:

| Concern | Mechanism |
|---|---|
| Filesystem and process | Seatbelt via `sandbox-exec` |
| Network containment | Seatbelt permits only the build's own egress proxy |
| Invocation from the sandbox | `sandbox-run-on-host`, behind the `--run-on-host` launch option |

The sandbox is deliberately narrower than the agent container. It supports sbt and Mill builds under
documented prerequisites, and nothing else.

Out of scope:

- arbitrary build tools — `scala-cli`, `scalafmt` and ad-hoc `scala` stay in the container;
- arbitrary globally installed JVMs; Homebrew, SDKMAN and asdf JVMs;
- direct Internet access from the build;
- automatic expansion of permissions when a build fails, and any fallback to another venue;
- implicit access to `~/.m2`, `~/.ivy2`, user Git credentials, SSH credentials, or unrelated
  home-directory state;
- stdin: `sbt console`, `sbt shell` and `sbtn`'s interactive modes;
- mounting the container's workspace at its host path (§9 records what that costs).

The container keeps its Scala toolchain. The host venue is the fast path, not a replacement: `sbt`
in the container still runs, and is what a session without `--run-on-host` uses.

The measurement behind this: on macOS, an `sbt test` of this project takes about 2 GB inside the
podman machine, whose total is fixed when the machine is created and shared with every other
session on it. §1.1 is why the same 2 GB costs nothing comparable on Linux.

### 1.1 Linux is excluded

Two independent reasons, either sufficient.

**No payoff.** There is no VM: `podman info` reports the host's memory, the container's ceiling is
the host total less 1 GiB (`AgentSandboxLauncher.memoryCeiling`), and a build's heap is ordinary
host memory in a cgroup, reclaimed on exit exactly as a host-native build's would be. The container
filesystem is native too, so a container build already runs at host speed. What remains is a warm
Coursier cache, which `PLAN-COURSIER.md`'s overlay buys for a fraction of this plan's cost.

**bubblewrap cannot express §2.1's guard either.** What it does better than Seatbelt is the
positive half: it starts with nothing mounted and builds up, so the table holds by construction
rather than by enumerating what to hide, and `--unshare-all` removes the network namespace outright
so proxy bypass is impossible rather than merely denied. But its mounts are established once at
start. Covering `.git` at any depth means binding over each one found then, and a `.git` created
during the build has no mount over it. Landlock is no better: its ruleset is fixed at creation over
paths opened then. Neither evaluates a name at access time, which is what the rule needs.

What Linux keeps that this plan gives up: the cgroup ceiling means a runaway build is killed inside
the sandbox rather than taking the machine down with it. A host-native build has no such bound.

### 1.2 Windows is excluded

AppContainer expresses §2.1's *grants* perfectly well, and a design for them already exists: a
per-user profile with a derived SID, inheritable ACEs on named roots for the project, the cache,
`~\.sbt\boot` and the launcher, its own private profile storage, and network confinement by
capability plus a Windows Filtering Platform rule restricted to the proxy endpoint. Even §4's
session directory has an answer there — the lock cannot live in the AppContainer's own storage or
in a project-local `.sandbox\tmp`, because the build writes both, so it belongs in the same
wrapper-owned per-user root macOS uses.

What it cannot express is the *denies*. Windows ACL inheritance has no name-pattern matching, so no
ACE on the project root means "deny `.git` at any depth"; the rule can only be an enumerated set of
explicit deny ACEs placed by a launch-time scan, and a `.git` created *during* the build — a
`git init` in a subdirectory, an unpacked fixture repository — inherits the project's allow with no
deny. That is a race, not an invariant, and the guard is the reason this feature can exist at all.

Seatbelt expresses it because SBPL path filters are evaluated at access time, so a directory that
appears mid-build is covered by the same rule — measured, not assumed (§7.2). A Windows backend
needs an equivalent — a filesystem
minifilter, or a design that does not put the guard in ACLs at all — before it is worth
reconsidering.

---

## 2. Security contract

### 2.0 Who invokes this

The default caller is the agent in the sandbox container, through `sandbox-run-on-host` (§6). A
person may run the wrapper directly, and the same policy applies.

Every grant below is read as *a grant to code the agent chose*. sbt executes the build definition,
task arguments, source generators and test code, all of which a sandboxed agent can author or
supply on the command line — `sbt 'set …'` and `sbt 'runMain …'` reach arbitrary Scala without
touching `build.sbt`. Nothing here routes through a build tool's own API, so "the build can only
write the cache through Coursier" is not a constraint that holds.

### 2.1 Filesystem

```text
PROJECT/**                          read-write-execute
PROJECT/**/.git/**                  inaccessible
PROJECT/**/.ko-agent-sandbox/**     inaccessible

resolved Coursier JDK home/**       read/execute       # §3.1, one home, never a root
agent cache root/coursier/v1/**     read-write         # §5

Coursier-installed sbt launcher     read/execute       # sbt only, two parts — §3.2
provisioned Mill launcher           read/execute       # Mill only, one file — §3.3

session temporary directory         read-write-execute # fresh per session

everything else user-owned          inaccessible
```

Writable implies executable for the project and the session temporary directory, and for nothing
else. A child inherits the profile, so a build running what it wrote gains no authority it did not
have — and a build's tests routinely write and run stubs, as this repository's own do. The agent
cache is writable and not executable: it holds artifacts the JVM reads, and nothing there is run.

The profile is deny-by-default: nothing outside this table is visible to the build. A runtime path
a toolchain requires — the loader, libc, the CA bundle — is added narrowly, read-only, and only
where testing proves the read is stable. That is runtime authority, and it is never a way to reach
a user path.

Seatbelt has no mount namespace, so `$HOME` cannot be replaced with an empty directory. The profile
denies it and permits only the paths above; a build cannot create `$HOME/.netrc`, a Coursier mirror
file, or any other configuration a later step in the same session would read, because the write is
denied rather than because the directory is bare.

**The two deny rows are the whole reason this is safe to invoke from a sandbox.** They reproduce
what `ko-agent-fs` enforces on `/workspace`, and they defend the property
`fuse/ko-agent-fs/doc/git-metadata.md` states: the sandbox can never alter repository state that
causes a later *host-side* `git` command to run a program the sandbox chose. A build that writes
`.git/hooks/post-checkout` or `core.fsmonitor` is perfectly contained and entirely beside the
point — the payload runs on the user's next `git status`, outside every sandbox, with their full
authority. `.ko-agent-sandbox` is frozen for the reason `policy.rs` gives: the *next* launch reads
it, so a build writing `apps/web/.ko-agent-sandbox/egress/allowed` authors a later session's
boundary.

Both rows fold case. APFS is case-insensitive by default, so `.GIT` and `.Git` reach the same
directory, and `policy.rs`'s `folds_to` already folds on the filter's side; two guards over one
tree that disagree about a name are one guard.

Both rows also deny link creation, not only writes. On the host, the project and its `.git` are one
filesystem, so `link(PROJECT/.git/config, PROJECT/x)` succeeds and a later write to `x` reaches
`.git/config` by a path no write rule matches. `SECURITY.md` dismisses hardlinks for the container
because `/workspace` and the container root are different filesystems and `link` is `EXDEV` in both
directions; that argument does not transfer here.

The residue `SECURITY.md` records for the filter stays: a *bare layout* the agent assembles from
ordinary names anywhere in the writable tree is not a `.git` directory and neither guard refuses
it. Running host `git` inside a directory the agent created is running the agent's output.

The temporary directory is the only unnamed writable space, and it is session-scoped: it starts
empty, no session ever sees another's, and nothing may rely on it persisting. What holds is that no
build reads temporary state left by another, which is not the same as an orderly exit always
happening: a killed build can leave a directory on disk, and the next start reclaims it rather than
reuses it (§4).

### 2.2 Network

```text
direct network                     denied
build egress proxy                 allowed

build egress proxy policy:
    explicitly allowed artifact repositories   allowed
    everything else                            denied
```

Initial repository allowlist:

```text
repo1.maven.org:443
```

That host, not `repo.maven.apache.org`. Coursier's and sbt's default Maven Central URL is
`repo1.maven.org/maven2`; the apache.org spelling is an alias almost nothing resolves against by
default. This project's own proxy baseline admits both
(`container/ko-agent-egress-proxy/app/src/main/resources/baseline/host`).

`repo.scala-sbt.org` is deliberately absent. It hosts the Ivy-style `sbt-plugin-releases`
repository and is not part of sbt's bootstrap — an uncached version named in
`project/build.properties` resolves from Maven Central. The same baseline admits `www.scala-sbt.org`
for documentation and not `repo.scala-sbt.org`, and this repository's sbt 2 build needs nothing
more. A build that depends on an old Ivy-published plugin adds it explicitly (§11).

Additional repositories must be explicitly configured. Do not infer or silently permit them.

### 2.3 Failure policy

Missing prerequisites or denied accesses fail clearly. Nothing expands authority, and **nothing
falls back to another venue**: a host build that cannot run is reported to the user, never re-run
in the container. This is the same stance the egress refusal takes — name what was refused and
stop, rather than looking for another route.

```text
Coursier JVM missing               -> fail before entering sandbox
sbt not installed by cs            -> fail before entering sandbox
Mill bootstrap absent              -> fail before entering sandbox
Mill version unpinned (no default) -> fail before entering sandbox
Mill launcher not provisioned      -> fail before entering sandbox; ask the user to run ./mill
Mill JVM not `system`              -> fail before entering sandbox; name the header key (§3.3)
repository not allowlisted         -> proxy denial; report requested host
filesystem path not allowed        -> sandbox denial; report path when observable
backend unavailable                -> fail; report; do not run in the container
```

---

## 3. Tool prerequisites

### 3.1 JVM

Only Coursier-managed JVMs are supported. The wrapper resolves one before entering the sandbox and
the profile grants that **one canonical JDK home**, not a root directory containing JDKs. Inside
the cache is necessary and not sufficient — the cache root, `arc` and `v1` are inside it too —
and a home is what holds `bin/java`.

`JAVA_HOME` is the only source. `java` on `PATH` is `/usr/bin/java`, a macOS stub that resolves
through `JAVA_HOME` or `/usr/libexec/java_home`; it reports the right JVM while being the wrong
path, so validating the binary establishes nothing. Validate what it redirects to.

There is no `jvm/` directory to name. A current Coursier unpacks a JDK into its archive cache, and
the resulting home is a URL-derived path:

```text
~/Library/Caches/Coursier/arc/https/github.com/adoptium/temurin25-binaries/releases/
  download/jdk-25.0.4%252B7/OpenJDK25U-jdk_aarch64_mac_hotspot_25.0.4_7.tar.gz/
  jdk-25.0.4+7/Contents/Home
```

Granting the `arc` root instead would hand the build every archive Coursier has ever extracted —
gigabytes of unrelated content — so the grant is the resolved home and the check is that it
canonicalizes to somewhere under the user's Coursier cache root.

That path shape is also why §7.2 forbids building a path rule by interpolation into a regex: it
carries a percent-encoded `+`, a literal `+`, dots, and a directory named like an archive.

Reject:

```text
/usr/bin/java                       the stub; it is a redirector, not a JDK
/Library/Java/JavaVirtualMachines/**
/opt/homebrew/**
SDKMAN JVMs
JAVA_HOME unset, or resolving outside the Coursier cache root
```

The JDK is read-only to the build, so sharing the user's copy exposes no write path, and
duplicating one per project would cost hundreds of megabytes for nothing.

### 3.2 sbt

Require:

```text
cs install sbt
```

Resolve the `sbt` launcher and verify it belongs to the Coursier application-install directory. Do
not accept an arbitrary `sbt` from `PATH`. On macOS that directory is

```text
~/Library/Application Support/Coursier/bin
```

not the XDG spelling the container image uses — and it contains a space, which every path this
plan hands to a profile, a process or the channel has to survive.

**The launcher is two files, not one.** What `cs install sbt` puts on `PATH` is a 1.2 KB shell
wrapper; it execs a second `sbt` inside an unpacked distribution in the Coursier archive cache:

```text
~/Library/Application Support/Coursier/bin/sbt          the wrapper, #!/usr/bin/env sh
~/Library/Caches/Coursier/arc/https/github.com/sbt/sbt/
  releases/download/v2.0.4/sbt-2.0.4.zip/sbt/bin/sbt    what it runs
```

So `TOOL` is two grants. The second cannot be derived from a convention — it encodes the download
URL of whichever sbt version Coursier installed, independent of the version
`project/build.properties` pins. It also cannot be found by running the wrapper, for §3.3's reason.
Reading the wrapper and taking the Coursier-cache path it names is a read, and is what
`SeatbeltProfile.sbtDistribution` does.

**The grant is the distribution's home, not the file the wrapper execs.** The inner launcher
resolves `sbt_home` as the parent of its own `bin` directory and reads `sbt-launch.jar`, `conf/`
and the `sbtn` binaries from there, so a grant on `…/sbt/bin/sbt` alone starts a build that cannot
find its own launcher jar.

Granting the enclosing `arc` tree instead is refused for the same reason §3.1 refuses it: that is
every archive Coursier has ever extracted.

**The inner launcher is `bash`, and resolves `java` from `PATH`.** It declares `java_cmd=java`, so
left alone it would reach `/usr/bin/java` — a path the profile does not grant, and the stub §3.1
rejects. `-java-home` reaches the client JVM alone: the client starts the server by re-running the
script (`-Dsbt.script=…`), without it, so the server's JVM is whatever `PATH` yields. Measured on a
host with fifty orphaned servers, every one on `/usr/bin/java`; under the profile that fork dies
silently and the client waits forever. The wrapper puts the resolved JDK's `bin` first on `PATH`
(§4), and §7.4's "server runs the granted JDK" row is what holds it there.

`~/.sbt/boot` is not granted and has no consumer: with `sbt.global.base` under the agent cache the
launcher boots into `sbt-global/boot` there, from the agent Coursier cache, warm across sessions
(§7.4's gate with the grant removed).

**sbt 2 has no one-shot mode, and `-Dsbt.server.autostart=false` guarantees failure rather than
avoiding a server.** Its own `--no-server` is documented in the launcher as "run sbtn, and fail if
it cannot connect to a server", and sets that same property; passing it yields
`[error] no sbt server is running`. sbt 2 is client/server by construction.

So the server starts *inside* the sandbox, and its state follows `-Dsbt.global.base` into the
project's agent cache (`RunOnHostPolicy.agentSbtGlobal`, granted read-write beside the Coursier
one) — where it writes a content-addressed store and a process registry (`cache/v2/{cas,ac,proc}`).
The base must be persistent, not session-temporary: sbt 2 leaves `target/` outputs as *symlinks
into that store* (measured on this host, against the user's own `~/Library/Caches/sbt/v2/cas`), so
a base removed with the session would dangle the build's own outputs at step 11. The same fact
cuts the other way at entry: a tree the user's unconfined sbt built links into a store the profile
denies, and zinc fails on the unreadable state rather than starting cold, so the wrapper removes
`target/` symlinks that resolve outside the granted roots before each build (§9.2's venue cost,
automated; the artifacts survive in the store of the venue that linked them).

Two consequences: §4's session is a server's lifetime rather than one build's, which is why the
build's proxy binds to the session lock (§8.2); and the wrapper must end that server rather than
leave it running when the session's lock is released.

**One sbt server per project at a time.** A thin client attaches to whatever server
`project/target/active.json` names, and the command then runs with *that server's* environment —
its cache, its JVM, its confinement or lack of it. A client that cannot connect deletes the
portfile and starts its own (`NetworkClient`). Both directions were measured: a sandboxed client
found the user's server and was refused by §7.3's socket rule, which is the refusal that keeps a
sandboxed build out of an unconfined JVM; and an unsandboxed warm-up attached to a host server and
resolved into the wrong cache. The path is fixed and nothing in sbt makes a client ignore it, so
the wrapper refuses to start while a live host server holds the portfile — the diagnostic says
`sbt shutdown` — and the session's own server is gone, portfile included, before the lock is
released. This is what "sbt on the host and in the sandbox at once" means for sbt 2, and it is
a launch-time refusal rather than a coexistence.

**The wrapper passes `--jvm-client`.** sbt 2 defaults to `sbtn`, a native binary in the
distribution; under the profile it prints that it is starting the server and returns with no build
run and nothing in its log, and no server is left to shut down. The JVM client completes the same
commands, and is what every other JVM in the chain already proves.

Do not grant `~/.sbt/1.0`, `~/.sbt/2.0`, `~/.ivy2`, or `~/.m2` by default.

### 3.3 Mill

Require a project-local bootstrap script:

```text
<PROJECT>/mill
```

Do not support a globally installed Mill.

Also require a launcher the user has already provisioned, for the version the bootstrap resolves:

```text
./mill --version        # once, in a host terminal, whenever the pinned version changes
```

The sandbox does not fetch the launcher. Mill 1.x publishes native launchers — a real host's
download folder holds entries like `1.1.8-native-mac-aarch64` beside older jars — so fetching it
would put an executable the sandbox chose into a directory the user's own `./mill` runs from,
outside any sandbox. Provisioning it instead makes Mill follow sbt's rule rather than its own.

That rule, stated once because it explains both tools: **the user provisions the launcher; the
sandbox fetches only artifacts.** sbt's launcher comes from `cs install sbt` and everything else it
needs is a jar the JDK reads, fetched into the writable agent cache through the proxy. Mill's
launcher *is* the fetched thing, and it is an executable. Provisioned, it is read/execute like
sbt's — that one file, not the download folder around it, which holds every launcher the user ever
ran. The folder is `MILL_FINAL_DOWNLOAD_FOLDER` or `${XDG_CACHE_HOME:-$HOME/.cache}/mill/download`.

Two consequences worth having: the build needs no GitHub release CDN, since only the bootstrap's
own download ever used one (§11); and a version bump becomes an explicit host step rather than
something a build definition performs on itself.

### Detecting that the host step is needed

Before entering the sandbox, resolve the version the way the bootstrap does — its file reads, in
its order, then its own default — and derive the file it will run the way the bootstrap does:

```text
MILL_VERSION → .mill-version → .config/mill-version → build.mill.yaml (mill-version:)
             → the build script (//| … mill-version): build.mill, else build.mill.scala,
               else build.sc
```

The first file that exists decides, even when what it yields is empty: the script's `elif` chain
has no fall-through. What the chain leaves empty falls to `DEFAULT_MILL_VERSION` — the
environment, else the assignment at the top of the bootstrap — which is Mill's recommended way to
manage the version (`./mill updateMillScripts`); `.mill-version` and the header are overrides.
Only a script with no default at all is unpinned.

The file is `<download folder>/<version><suffix>`, from the script's `case "$MILL_VERSION"`: a
`-native` suffix is stripped and the platform suffix applied; `-jvm` is stripped and none applied;
otherwise every version past 0.12 takes the platform suffix and 0.1–0.12, the jar era, none. The
platform suffix is `-native-mac-aarch64` or `-native-mac-amd64` by `uname -m`. That file must be
present and executable; a prefix match would accept a neighbour, and `1.1.8-jvm` names `1.1.8`,
which no prefix of the pinned text finds. The download folder is `MILL_FINAL_DOWNLOAD_FOLDER` or
`${XDG_CACHE_HOME:-$HOME/.cache}/mill/download`; `MILL_USER_CACHE_DIR` is assigned by the script,
never read.

The file sources are all project files, the bootstrap included; `MILL_VERSION` and
`DEFAULT_MILL_VERSION` in the environment are the wrapper's, not the build's. Whichever names the
version, what is granted is one launcher the user provisioned; a version the user never ran
`./mill` for is a refusal naming the file to run.

The script's `MILL_TEST_DRY_RUN_LAUNCHER_SCRIPT=1` mode prints the exact launcher path without
downloading, and it is not used. Reading the version is a
read; asking the script is executing agent-authored shell on the host with full user authority,
which is what §2.1 exists to prevent.

The script stages a download at `${MILL_OUTPUT_DIR:-out}/mill-temp-download`, inside the project,
which `PROJECT` already covers. It needs no row of its own.

**Three more things Mill needs, each measured by §7.4's gate against `probe/mill-fixture`:**

- **`mill-jvm-version: system` in the build header.** Mill provisions its own JVM through
  Coursier's index by default (`zulu:25`, "regardless of what is installed"), which is a JDK
  fetched by the build into a writable, executable place — what §3.1 refuses for sbt. `system`
  takes `java` from `PATH`, which §4 makes the granted JDK. The key lives in the project — a
  `.mill-jvm-version` file, else `.config/mill-jvm-version`, else the header of `build.mill.yaml`
  or `build.mill`, the first existing source authoritative — so it is a prerequisite of the
  project, read at preflight like the version.
- **`--no-daemon`.** The launcher and the daemon talk over a loopback TCP socket
  (`out/mill-daemon/socketPort`), which the profile grants to nothing: loopback is every local
  service. Without the daemon there is no socket. Mill's counterpart of sbt's `--jvm-client`,
  measured the same way — the daemon form stays a gate row.
- **`out/mill-daemon/` is cleared at session start.** The launcher memoizes its resolved
  daemon classpath and JVM home under `out/mill-daemon/cache` and reuses them while the files they
  name exist (`runner/launcher/src/mill/launcher/CoursierClient.scala`); a memo from a run against
  the user's cache names paths the profile denies, and a redirected `COURSIER_CACHE` never takes
  effect. The daemon's `processId` and `socketPort` beside it are believed alive or not. A memo,
  safe to drop.

---

## 4. Wrapper design

One front-end command:

```text
ko-agent-build-sandbox sbt [args...]
ko-agent-build-sandbox mill [args...]
```

or the same functionality inside the existing `ko-agent-sandbox` CLI. §6 is how the agent reaches
it; a person runs it directly.

The wrapper performs these steps:

```text
 1. canonicalize project root
 2. detect requested build tool
 3. locate the user Coursier JVM root and this project's agent cache root
 4. validate the Coursier-managed JVM
 5. validate the build-tool prerequisite
 6. publish the session directory, empty, and take its lock
 7. start this build's egress proxy (§8), bound to that lock
 8. construct the Seatbelt policy
 9. configure proxy environment / JVM proxy properties
10. launch the build under sandbox-exec
11. end the sbt server it started, stop the proxy, and remove the session directory
12. preserve child exit code
13. provide actionable diagnostics for known denials
```

Step 6 creates a fresh, uniquely named directory under a wrapper-owned root and never adopts an
existing one; step 11 removes it on every exit the wrapper survives to see, error and handled
signal included. `SIGKILL`, a crashed wrapper and a lost machine defeat any handler, so a start
also scavenges the root. Each session owns a directory there, holds its lock for the life of the
build, and grants the build a writable child of it and nothing more:

```text
<wrapper root>/<session>/lock     wrapper-owned; named in no policy rule
<wrapper root>/<session>/tmp      SESSION_TMP; the only part the build can write
```

The lock has to sit outside the build's authority. A lock inside `SESSION_TMP` is one the build can
unlink and replace — deliberately, or by clearing its own temporary directory — leaving the wrapper
holding a lock on an inode with no name; the next start would then lock the replacement, read a
live session as stale, and delete a running build's working directory.

A session directory whose lock is free belongs to no live session and is removed whole. Liveness,
not age — concurrent builds are ordinary, and a slow build must not have its temporary state
collected out from under it.

That test is only sound if a directory reaches the scanned namespace already locked, so a session
is published rather than built in place: the wrapper creates its directory in a staging area the
scan does not visit, takes the lock there, and renames it into the root. A rename keeps the inode,
and with it the lock, so no scanned entry is ever one whose session is still starting. Staging and
root share a filesystem, which is what makes the rename atomic.

A wrapper killed between creating its staging directory and renaming it leaves an entry there, so
the scavenger clears staging too — and that is what a root lock is for: publication holds it from
creating the staging directory through taking the lock to the rename, and staging cleanup holds it
to remove what a kill left. A scavenger free to delete a directory whose creator has not locked it
yet does not collect litter; it fails an ordinary start, whose rename then has nothing to move.

Nothing expensive runs inside that lock. A staging entry is a directory no build has written to,
and the removal of published directories — where the bytes are — needs no root lock at all, since
every published directory is locked by construction.

A `SIGKILL`ed wrapper leaves its processes running with the lock free, and a scavenger that
removed only the directory would leave an orphaned server holding the project's portfile against
the next start (§3.2). The lock states only the wrapper's liveness; the children's is owned by
records. Everything the wrapper spawns becomes its own process group's leader and publishes that
group and its start time the way the session itself was published — written beside, renamed into
place — before it execs, aborting if the rename fails; a record is complete or absent, never a
partial read through a descriptor that outlived a rename. The sbt server needs no record of its
own: the client forks it without `setsid`, so it stays in the client's registered group — which is
also what covers it between fork and its first bind.

The scavenger condemns before it reads: the publication rename run backwards moves the directory
into `<wrapper root>/condemned`, which every start processes before anything else — recorded
groups ended, then deleted — so a scavenger killed mid-collection leaves work the next start
finds, not a directory no scan visits. Staging needs no such pass: nothing is spawned before
publication, so a staging entry never has processes. Every interleaving of a kill lands somewhere
accounted for — a child caught before registering finds its directory gone, fails its rename and
exits; a registered one is in the condemned directory's records and is ended.

A record identifies its group only while the leader lives: the leader's pid and start time are the
check, and a group whose members have all exited frees its id for strangers, so the scavenger
signals nothing on a dead or mismatched leader. The one process of ours built to outlive its
leader is the sbt server, and it is ended by attribution instead: the session records its project
root, and a portfile there whose socket lies under this session's directory names our server and
no other. The wrapper speaks the shutdown itself, the sequence the pinned client implements
(`NetworkClient`): connect at the socket's current pathname — condemnation moved it with the
directory, and the portfile's spelling goes stale at the moment it matters — send the `initialize`
handshake, tokenless and with `skipAnalysis`, because a local-mode server authenticates nothing
and its portfile carries no token (`Defaults.serverAuthentication` is TCP-only), then `sbt/exec`
`shutdown` and a bounded wait for the process to end. Never through sbt's own client, which
answers a dead socket by deleting the portfile and starting its own server (§3.2) — here, an
unconfined one. A server that answers nothing past the bound is reported, never guessed at by
group id. Measured, for when attribution meets what: a server outlives a client that exits
cleanly, and dies with one killed mid-exec — so a live orphan follows a completed command, and a
kill usually leaves only a refused connect, which is itself the definitive answer. A process that
leaves its group by `setsid` escapes the scavenger, not the sandbox: reach here is lifecycle,
§2.1 is authority.

The session lock is also what the build's proxy binds to (§8.2).

**The wrapper root is `/private/tmp/ko-agent-<uid>`, and it is short on purpose.** sbt's boot
socket is `<XDG_RUNTIME_DIR or java.io.tmpdir>/.sbt/sbt-socket<hash>/sbt-load.sock`, 50 characters
past the directory, against the 104-byte `sun_path` of a UNIX-domain socket; the server refuses a
longer path with a message, the client's JNI connect has no check and dies in `memcpy`. Measured:
52 characters run, 56 trap. The macOS per-user temporary directory is 49 before anything is added,
so no session directory under it can fit, and `~/.cache/ko-agent-sandbox/…` fits only for a short
user name. `RunOnHostPolicy.SessionTmpMaxLength` is that budget, and the wrapper refuses a
session directory over it. `/tmp` is shared and sticky, so the root is checked the way an XDG
runtime directory is — this user's, mode 0700, not a symlink — and refused otherwise.

**The build's environment is the contract, not its command line.** sbt 2's client forks the server
with its own arguments, so a `-D` flag given to the client never reaches the server; the JVM
settings travel in `JAVA_TOOL_OPTIONS`, which every JVM in the chain reads and inherits:

```text
PATH                   COURSIER_JDK_HOME/bin first   the server's JVM, §3.2
JAVA_TOOL_OPTIONS      -Djava.io.tmpdir=SESSION_TMP -Djava.util.prefs.userRoot=SESSION_TMP
                       -Dsbt.global.base=<agent cache>/sbt-global   §3.2: target/ links into it
                       -Djava.net.preferIPv4Stack=true              §7.3: the proxy connect
XDG_RUNTIME_DIR        SESSION_TMP      sbt's boot socket
SBT_GLOBAL_SERVER_DIR  SESSION_TMP      sbt's server socket
COURSIER_CACHE         the agent v1     §5
```

`java.io.tmpdir` is set because on macOS a JVM takes it from `confstr(_CS_DARWIN_USER_TEMP_DIR)`,
never from `TMPDIR`, and the preference store because a JVM writes one under `$HOME` on first use;
both would otherwise be denials in a place the build cannot name.

All paths passed to the sandbox backend are canonicalized before policy construction. Reject paths
that cannot be canonicalized.

---

## 5. Coursier cache policy

Agent-invoked builds get their **own build-cache root, per project**. The user's artifact cache is
not granted, not mounted and not read.

```text
<cache root>/ko-agent-sandbox/cache/<projectId>/coursier/v1/       sbt, scala, Coursier
```

Grouping by project inside the kind directory makes one project's caches one directory: a
per-project cache reset is a single removal, and `cache/<projectId>/ivy2/` can join later without
moving anything.

`<cache root>` is discovered the way `AgentSandboxLauncher.stateRootOf` discovers the state root, so
the two answer alike on one machine: `XDG_CACHE_HOME` when it is set and absolute, otherwise
`$HOME/.cache`. `XDG_CACHE_HOME` is normally unset on macOS, which is the ordinary case rather than
the exception, so the fallback is tested first and a literal unexpanded value is never a path. A
relative override is refused with its own message, as `stateRootOf` refuses one: a relative value
resolves against the current directory, which is the repository being sandboxed.

The build reaches it through one variable: the wrapper sets `COURSIER_CACHE` to the `v1` directory
in the build's environment, which the sbt 2 launcher, sbt's own resolution and Coursier all honour.
Nothing else routes it — with the variable unset the launcher resolves into the user's `v1`, which
the profile denies, and dies in `createDirectories` with `FileAlreadyExistsException` on a directory
it cannot see (§7.4's gate measured exactly that).

Permissions, against §2.1:

```text
agent cache root/coursier/v1/**   RW      artifacts the build downloads
resolved Coursier JDK home/**     RX      §3.1
provisioned Mill launcher         RX      §3.3, one file, provisioned rather than fetched
user Coursier v1/**               absent  not granted at all
user Mill cache, except download/ absent  not granted at all
```

### 5.1 Why not the user's cache

`v1` is a machine-wide directory every project on the host resolves against, and a grant to write
it is a grant to code the agent chose (§2.0). A build that writes an artifact and a matching
checksum under a coordinate some *other* project resolves poisons a later ordinary host build of
that project — no agent, no sandbox, no review, and no expiry, because a cached release artifact is
treated as immutable.

`PLAN-COURSIER.md` forbids exactly this for the container, and reaches it differently: a Podman `:O`
upper layer keeps the host cache readable and unwritable. Seatbelt has no mount namespace, so no
overlay is available here and separation has to be by root. The two documents agree on the
property and differ only in mechanism.

The cost is a cold cache on a project's first agent build. It is warm from the second onwards,
shared by every agent build of that project, and the blast radius of poisoning it is later builds
of the same project, which are themselves sandboxed.

### 5.2 Why not the launcher state root

`AgentSandboxLauncher.scala` keeps the state root kind-first — `tls/<projectId>`, `log/<projectId>`,
`policy/<projectId>` — and says why at `logStateRoot`: the proxy writes its audit log there, and
"must not sit beside the CA key". A project-first layout would put a granted cache directory back
beside `ca.key` and beside `policy/<projectId>/agents.md`, the assembled agent instructions the
launcher reuses on a stamp match.

That adjacency matters more here than it would in the container. In the container the CA key is out
of reach because it is never mounted; on the host the build runs as the user's own uid, which owns
the key, so file permissions protect nothing and the Seatbelt profile is the only thing standing
there. A separate root makes the profile's job structural: no path the build sandbox is ever
granted has a sensitive ancestor or sibling.

`XDG_CACHE_HOME` is also where a reconstructible cache belongs, and it makes `--reset-cache` a
whole-directory operation with nothing to be careful about.

The cache root gets the same treatment `requireStateRootOutside` gives the state root: refuse when
it resolves inside the project.

---

## 6. The sandbox → host channel

### 6.1 The command

```text
sandbox-run-on-host sbt [args...]
sandbox-run-on-host mill [args...]
```

A named command, a sibling of `sandbox-apt-get` and `sandbox-jdk-use-proxy`, rather than a shim
shadowing `sbt` on `PATH`. The venue is then visible in the transcript the user reads.

It does not inherit `sandbox-apt-get`'s discoverability. `apt-get install` fails in the sandbox, so
the plain name teaches the agent to look for the prefixed one; `sbt test` in the container
*succeeds*, in the slower venue against a different cache, and nothing prompts a reconsideration. So
the authority section carries the instruction instead (§9.2), and container `sbt` stays reachable
and unshadowed.

That makes the venue a norm rather than an enforcement: an agent that ignores the instruction gets
a slower build, not a refusal. This is a deliberate difference from the egress rule, where the proxy
actually refuses.

### 6.2 Transport

The shape `ClipboardBroker` already uses: FIFOs under the sandbox's `/tmp`, made by the host side's
first exec, so a session without the channel has none and the command fails at once. The host side
holds one long-lived `podman exec` reading requests, and answers each through a short one, so the
sandbox opens nothing outward and the host runs nothing it did not start.

A build is a larger protocol than a clipboard request: streamed stdout and stderr, an exit code, and
a working directory. Stdin is excluded (§1), which removes the interactive modes and the
half-closed cases with them.

The launcher injects the host project path so the shim can translate its own working directory from
`/workspace/<sub>`. The container therefore learns the host path — the disclosure §9.3 records —
whether or not same-path mounting is ever adopted.

**The working directory is attacker-supplied, and it never becomes a profile grant.** `PROJECT` is
always the launcher's canonical project root, resolved at §4 step 1 from the launch and not from any
request. The translated path becomes a separate `WORKING_DIRECTORY`, used only as the child
process's cwd.

Keeping the two apart is a correctness rule before it is a security one. Deriving `PROJECT` from the
request would *shrink* the grant whenever the agent invokes from a subdirectory, and sbt and Mill
both walk upward to discover their build root and write sibling modules' output; the build would
fail on denials that look like a broken profile.

`WORKING_DIRECTORY` is still validated, because a request choosing a path outside the project would
otherwise produce a confusing wall of denials rather than one answer. The broker resolves it
canonically and refuses it unless it is `PROJECT` or beneath it, with `CHANNEL_UNAVAILABLE` and the
path — never a silent fall back to the root. §14.1 and §15 carry the hostile cases.

### 6.3 Availability

The channel exists only when `--run-on-host` names the tool (§9.1). Without it the command is
absent, and its absence is what the agent sees.

Teardown is unresolved: §17.

---

## 7. macOS implementation

### 7.1 Backend

`sandbox-exec` with one parameterized Seatbelt profile shared by sbt and Mill.

The wrapper supplies:

```text
PROJECT
COURSIER_JDK_HOME
AGENT_CACHE_V1
TOOL
SBT_DISTRIBUTION
SESSION_TMP
WORKING_DIRECTORY
PROXY endpoint
```

`WORKING_DIRECTORY` carries no grant of its own: it is inside `PROJECT`, which already has one, and
it reaches the backend as the child's cwd rather than as a rule (§6.2).

`TOOL` is the launcher the build starts through: for sbt the Coursier-installed wrapper, with
`SBT_DISTRIBUTION` the home of the inner launcher it execs (§3.2, both required); for Mill the one
provisioned launcher file (§3.3), and no `SBT_DISTRIBUTION`. The bootstrap `PROJECT/mill` needs no
parameter: it is a project file, and the project runs.

### 7.2 Filesystem policy

Each §2.1 row as the profile parameter that carries it:

```text
PROJECT                           RWX
PROJECT/**/.git                   deny read, write and link, case-folded
PROJECT/**/.ko-agent-sandbox      deny read, write and link, case-folded
COURSIER_JDK_HOME                 RX
AGENT_CACHE_V1                    RW
TOOL                              RX
SESSION_TMP                       RWX
```

`SESSION_TMP` is the writable child of the wrapper's per-session directory (§4), not the user's
`TMPDIR`, and the session directory holding the lock is named in no rule.

**Every path in a rule is canonical.** SBPL resolves the path being *accessed* but matches the rule
as written, so a rule naming a non-canonical path matches nothing — and therefore **grants**. On
macOS `/tmp` is a symlink to `/private/tmp`, which is enough to make a whole deny silently
decorative. §4 requires canonicalization; this is why forgetting it fails in the permissive
direction rather than the safe one.

**Every wrapper-supplied path is a literal, never interpolated into a regex.** `(subpath …)` and
`(literal …)` for the parameters above; `(regex …)` only for the two name-pattern denies, which are
patterns by intent — and scoped to the project with `(require-all (subpath PROJECT) (regex …))`,
so even the guard's own scope is a literal. The scope is §2.1's: a `.git` a test builds in the
session temp is reclaimed with the session and no host git runs there, and this repository's
own suite makes such fixtures. The paths in play are not regex-safe — the Coursier JDK home
carries a percent-encoded `+`, a literal `+` and dots (§3.1), and the sbt install directory
contains a space — and a path interpolated into a pattern matches more than itself, silently and
in the permissive direction. `(subpath)` itself handles both characters correctly.

### 7.2.1 What SBPL actually does

Apple does not document the profile language for third-party use: `sandbox-exec` compiles it through
private `sandbox_compile_*` entry points, and the published write-ups are reverse-engineered and
date from 2011. Two sources are therefore authoritative here — measurement, and Apple's own shipped
profiles under `/System/Library/Sandbox/Profiles/`, which are current and were written against the
implementation. `probe/seatbelt-semantics.sh` and `probe/build-profile-iterate.sh` are the
measurements; `system.sb` is the profile worth reading first.

**What the guard rests on** (`probe/seatbelt-semantics.sh`):

| behaviour | consequence |
| --- | --- |
| the accessed path is canonicalized | `link -> .git`, then a write through the link, is denied |
| canonicalization normalizes case where the volume does | `.GIT` folds before matching |
| rules are evaluated at access time | a `.git` created *during* the build is covered |
| one regex spans every depth | `.git` at any nesting is one rule, not an enumeration |
| `file-write*` already refuses a hardlink to a denied target | the link clause is redundancy |

**What a profile must contain to start anything at all**
(`probe/build-profile-iterate.sh`, and `system.sb` where noted):

- **`(literal "/")` is required.** `(subpath "/x")` grants what is *under* `/x`; resolution
  authorizes `/` first and nothing covers it. `system.sb` grants it too.
- **Every ancestor directory needs its own literal** — the same rule one level down. A deep
  `(subpath …)` with no chain above it denies everything, `/dev` included, which is how
  `SecureRandom` fails as "NativePRNG not available" rather than as a path.
- **`/dev/tty` is the terminal, whatever stdin is.** Closing the child's stdin does not detach
  its controlling terminal; the profile grants `/dev/null` and the random devices only.
- **A literal `file-read*` on a directory is its listing.** The chain carries `file-read-metadata`
  and `file-test-existence`; granted as `file-read*` it listed all of `~/Library/Caches` (§7.4's
  gate). Only the root entry needs the wider read.
- **`(subpath "/")` is not the union of `(subpath "/child")`.** The difference is the root entry,
  and reaching for `(subpath "/")` because only it appears to work grants the whole disk.
- **A rule naming a non-canonical path grants rather than denies.** `/tmp` against `/private/tmp`
  is enough to disable an entire deny, silently.
- **An invalid profile fails exactly like a denial.** `sandbox-exec` aborts the child either way;
  the difference is only on its own stderr, so a search that discards it chases missing grants that
  were never missing.

**What this toolchain needs, measured per layer.** The JDK needs `sysctl-read`, the JDK home, and
`/System/Library/CoreServices/SystemVersion.plist` — without that one file `java` refuses to start
with `os.version malformed: -1.0`. It does **not** need `file-map-executable`, which Apple's
profiles do use for system frameworks; a JDK outside those paths loads without it.

`system.sb` also carries two things worth adopting rather than re-deriving: `file-test-existence`,
a narrower operation than `file-read*` for the ancestor chain, where only existence is in question;
and `(import "dyld-support.sb")`, Apple's own statement of what a process needs from the loader.

### 7.2.2 Prior art, and why this profile is shaped differently

Bazel sandboxes build actions on macOS with `sandbox-exec`, which is this feature's problem exactly.
Its generated profile is worth reading and worth *not* copying:

```text
(version 1)
(debug deny)
(allow default)
(deny file-write*)
(allow file-write* (subpath "…/execroot/__main__"))
(deny network*) …
```

It is a blacklist: everything is permitted, then writes and network are taken away. That is why
Bazel never meets §7.2.1's findings — with nothing denied by default, path resolution cannot fail,
so the root entry and the ancestor chain never arise. It is also why that shape cannot serve here:
a build under it reads the whole filesystem, and §2.1's "everything else user-owned inaccessible"
is the property this feature exists to provide. The difficulty of deny-by-default is the price of
that row, not evidence of a wrong turn — which is worth stating because the blacklist form is the
obvious simplification when the whitelist will not start.

`(debug deny)` is worth taking. It makes denials visible from inside the profile, without the
unified log's redaction or `(trace)`'s unavailability, and Bazel puts it at the top of every
generated profile. `probe/build-profile-iterate.sh` does the same.

The fold is a property of canonicalization, not of the regex: an SBPL pattern does not fold case by
itself, so a rule written to rely on that would not fold on a case-sensitive volume where it
happens to matter. `(deny file-link …)` is kept beside the write deny even though `file-write*`
covers it, because the guard is the reason this feature is safe to invoke from a sandbox and the
membership of a wildcard operation family is Apple's to change.

Do not pre-authorize broad paths such as `/System/**`, `/usr/**` or `/opt/homebrew/**` unless
testing proves a specific stable runtime read is required, and then add the narrowest rule that
testing justifies.

Runtime authority is discovered by running a real build under a deny-default profile and reading
the denials, never by listing what a host happens to have. The chain begins `#!/usr/bin/env sh` and
continues `#!/usr/bin/env bash`, so `bash` is in it as well as `sh`, alongside the `uname`,
`dirname`, `basename` and `readlink` the inner launcher calls — but that list is where the search
starts, not where it ends.

### 7.3 Network

Seatbelt permits connections only to this build's proxy ingress endpoint (§8), and UNIX-domain
sockets only inside `SESSION_TMP`. The proxy rule is `(remote ip "localhost:<port>")` — Bazel's
loopback spelling (`DarwinSandboxedSpawnRunner`, bazel#14828); an ip-literal host is refused by
the compiler ("host must be * or localhost"). The "localhost" class covers native `127.0.0.1` and
`::1` but not a JVM's dual-stack connect, which reaches `127.0.0.1` as v4-mapped
`::ffff:127.0.0.1` and dies with `EPERM`; §4's contract pins `-Djava.net.preferIPv4Stack=true`
for exactly this, all three measured by `probe/jvm-proxy-rule.sh` and `probe/loopback-rule.sh`.
The
UNIX-socket rule exists because Seatbelt counts a local socket as network: without it sbt's server
gets `EPERM` from `bind()` on its boot socket and its client waits for it forever, which is how
the gate first met it. `(local unix-socket (subpath …))` and `(remote unix-socket (subpath …))`
are the measured spelling, and a socket outside the subpath stays denied; `system-socket` plays no
part.

The JVM and Coursier are configured to use it, but proxy settings are not the security boundary:
Seatbelt must prevent bypass via direct sockets.

```text
-Dhttps.proxyHost=...
-Dhttps.proxyPort=...
-Dhttp.proxyHost=...
-Dhttp.proxyPort=...
```

### 7.4 Test gate

```text
java -version
sbt --version
sbt compile
sbt test
./mill --version          # with the launcher provisioned, which is the supported state
./mill __.compile
./mill __.test
```

Negative tests:

```text
read ~/Documents/...                         denied
read ~/.ssh/...                              denied
read the launcher state root                 denied
read the user's other Coursier arc entries   denied
write Coursier/jvm/...                       denied
write ~/.sbt/boot/...                        denied
write the Coursier-installed sbt launcher    denied
write PROJECT/.git/config                    denied
write PROJECT/sub/nested/.git/hooks/x        denied
write PROJECT/.GIT/config                    denied
create PROJECT/.git during the build         denied
link PROJECT/x -> PROJECT/.git/config        denied
write via PROJECT/link -> PROJECT/.git       denied
write PROJECT/.ko-agent-sandbox/...          denied
write the user's Coursier v1                 denied
write the user's Mill download folder        denied
read and execute the Mill launcher           allowed
write agent cache coursier/v1/...            allowed
write PROJECT/...                            allowed
write session temporary directory            allowed
connect directly to arbitrary Internet host  denied
fetch allowed Maven artifact via proxy       allowed
fetch non-allowlisted host via proxy         denied

two concurrent sessions                      both build, distinct directories
SIGKILL mid-session                          next start condemns and collects
orphan server                                ended by portfile attribution
after every wrapper row                      no proxy, server or session directory survives
```

`probe/build-profile-gate.sh [sbt|mill|all] [quick]` runs this matrix and reports PASS, FAIL or
SKIP with what it saw. The build rows run through the §4 wrapper (`RunOnHost`), which
scavenges, publishes a session, starts the build's proxy and ends what it started — driven as
plain java on the emitted classpath, because an `sbt Test/runMain` wrapper would find its own
server holding the project's portfile (§3.2). The negative matrix runs under the profile
`EmitBuildProfile` generates. There is no warm-up: a cold agent cache resolves through the proxy
inside the profile, and the allowed-fetch row makes itself cold by deleting an artifact first.
The sbt rows build this repository; the Mill rows build `probe/mill-fixture`, a one-module Mill
project that exists for them, since a Mill build of the launcher itself would be a second build
definition rather than a measurement; `probe/deny-fixture` exists for the non-allowlisted row,
whose resolution must reach a refused host and be reported by §8.4's diagnostic.
A "write" in the negative rows is an open for append that writes nothing, and every marker it
creates lives in a scratch tree it removes, so the matrix can run against a real repository.

The four `.git` rows after the first re-run under the real profile what `seatbelt-semantics.sh`
measured in isolation — access-time evaluation, case folding, link creation and symlink
canonicalization. Their answers are known (§7.2.1); what this gate adds is that the generated
profile, with every grant a build needs beside the guard, still gives them.

Two rows measure the ancestor chain: "list an ancestor of a granted path" and "read another
project's agent cache", whose parent is an ancestor of the granted `v1`. `file-read*` on a
directory is its listing, and the gate showed a chain granted that way listing all of
`~/Library/Caches`; the chain is `file-read-metadata`, and only the root entry carries the wider
read (§7.2.1).

---

## 8. Egress-proxy integration

Each build runs **its own proxy process**, from the same codebase as the container's.

### 8.1 Why not the session's proxy

The session's proxy is per run, on a network created `--internal`, and lives inside the podman
machine. There is no host route to it; reaching it would mean either publishing it — which hands
any host process the session's full `--egress` allowlist, `api.anthropic.com` and forges included —
or relaying each connection through `podman exec` into the VM, which pays the VM round trip on
exactly the path the build was moved out of the VM to avoid, ties the build's lifetime to a live
session, and gives the build a path into the sandbox container.

A JVM proxy client speaks TCP, so a loopback listener is unavoidable either way. What is worth
controlling is the policy behind it, and a proxy admitting one artifact repository is a prize barely
worth stealing.

### 8.2 Lifetime

Bind the proxy to the §4 session lock, not to the client process. A session is one wrapper
command — §3.2 ends the server before the lock is released, so no server spans invocations — but
the client is not its extent: the server the client forks is what resolves, and it lives past the
client until the wrapper ends it. The lock states the wrapper's liveness and the §4 records own
the children's; binding the proxy to the lock's session keeps the answer unchanged if a warm
server spanning invocations is ever added. Mill under `--no-daemon` (§3.3) needs only the
invocation, which the session also covers.

### 8.3 Artifact

The container's proxy is a GraalVM native image built for Linux inside `debian-coursier`; an
installed launcher is one self-contained jar or the README's native image of it, and the nested
proxy build's `target/dist` exists only in a checkout that has run it. So the proxy rides in the
launcher's own artifact: its sources share the launcher's Scala version and import nothing past
the JDK and the Scala library, and `dist` compiles them in beside their `/baseline` resources —
which load eagerly at class initialization even under `-**`, so what the tests must start is the
assembled artifact, and the native-image recipe's `-H:IncludeResources` widens to carry them. The
wrapper starts the proxy by re-invoking whichever vehicle it is running in — `java -jar` or the
native binary — under a private verb, so one spelling serves both and neither needs a JVM the
wrapper does not already have. §3.1's Coursier-managed-JVM requirement is about the build, not
about the wrapper's own process.

The host proxy runs unconfined, unlike the container's hardened copy of the same codebase — and
it is the one process that parses hostile bytes from the thing being sandboxed, holding the uid
whose files the build profile exists to deny. Its own small Seatbelt profile is Phase 5
hardening: read-only JDK and launcher jar, writes to its log alone, no `process-exec*`,
unrestricted `network-outbound` (host filtering is the proxy's own job, and SBPL cannot filter by
name) plus its loopback listener. Defense in depth for the enforcement point, not a §2.1 hole:
a JVM parse bug is an exception, the listener is loopback-only, and `HostileInputTest` covers the
surface — which is why it can wait for Phase 5.

Bind on an ephemeral port on `127.0.0.1`. That is proxy work, not launch configuration: the
codebase binds the wildcard address on the fixed port 3128 — safe in the container's own network
namespace, and wrong twice on the host, where it is reachable beyond loopback and collides between
the concurrent sessions §4 calls ordinary. The ready line already names the bound port, and the
container launcher gates on its exact spelling (`isProxyReadyLine`), so a bind option keeps 3128 as
the default and the wrapper reads the ephemeral port from the same line the container gates on.

### 8.4 Policy semantics

The wrapper selects `deny-unless-allowed` and composes the proxy's `allowed` input as `-**`, the
§2.2 baseline, then the project file's entries, validated first against §11's grammar — a complete
replacement, so the container's host catalog contributes nothing.

A denied CONNECT is an audit line naming the host — stderr, and with `EGRESS_LOG_FILE` a file the
wrapper reads — from which the wrapper produces:

```text
Build requested network access to:
  repo.example.org:443

This host is not permitted by the Scala build sandbox.
```

Do not automatically add it.

### 8.5 HTTPS

Run the proxy without inspection material: its no-material mode enforces the destination host and
port at CONNECT time and tunnels opaquely. Then the build needs no additional trust material, and
the Coursier-managed JDK's own trust store suffices — which matters here because §2.1 makes that
JDK read-only, so a merged truststore cannot be written into it the way `JdkTrust.scala` does for
the container image. If inspection is ever wanted, point the JVM at a wrapper-owned store with
`-Djavax.net.ssl.trustStore` rather than touching the JDK.

---

## 9. Launcher surface

### 9.1 `--run-on-host`

```text
--run-on-host=sbt,mill
```

Launch authority, like `--egress` and `--write`: rejected by management verbs, refused when given
twice, and refusing an unknown tool name. Absent, the channel does not exist.

Available on macOS only (§1.1, §1.2).

It composes with `--write=live` and `--write=reject`. That composition is not an escape — both are
authority the user typed — but under `reject` it does mean the project is no longer read-only to
the session, since a build writes `target/` and, through `sbt 'set …'`, anything else §2.1 permits.

It refuses a staged workspace. `PLAN-STAGED.md` ("Unresolved: a staged workspace under
`--run-on-host`") has the three candidate semantics and no chosen one; until one is chosen, a
staged session's agent would see the merged mount while its build compiled and wrote the host tree.
Whichever of the two features lands second implements the refusal and owns the choice.

### 9.2 What the session says

`authoritySection` gains a paragraph when the option is in force, in the same act mode as the
workspace and egress paragraphs. It states:

- `sandbox-run-on-host sbt …` as the command, and that it runs on the host at host speed;
- that container `sbt` still exists and runs in the container, over the **same** `target/` — one
  directory, seen from both sides. The two venues compile with different JVMs against different
  Coursier caches, so what one leaves there may not be usable by the other: a venue switch can cost
  a rebuild, and can need cleanup before a build succeeds (`AGENTS-SANDBOX.md`, "The host's own
  symlinks"; the host wrapper does its own entry sweep, §3.2);
- that a failed host build is reported to the user, never re-run in the container (§2.3);
- what the host build may write: the project, minus git control state and `.ko-agent-sandbox`.

The existing `--write=reject` paragraph needs correcting for this composition: its instruction to
"put results under `~` or `/tmp` and tell the user, who relaunches with `--write=live`" is false
once a host build can write the project.

### 9.3 Same-path mounting

Deferred, and its own launch option when it arrives. It aligns source paths and nothing else — the
host build's JVM is a macOS binary and the container's is Linux, and their Coursier cache roots
differ — so it does not establish compatibility between the venues' build state. That leaves
legible paths in build output as the benefit, which did not carry the increment.

The host path reaches the container regardless, because §6.2 injects it. `SECURITY.md`'s
low-bandwidth list is where that belongs.

### 9.4 `--stats`

A read-only report, because a size seen only while resetting is seen too late.

- projects by bytes across the state and cache roots, largest first, with the containing
  filesystem's free space, and a flag on any project whose cache exceeds 1% of that free space —
  the threshold exists so the report says which project to `--reset-cache`, rather than leaving a
  column of numbers to compare by eye;
- live sessions, from `podman stats --no-stream`.

Three constraints. Skip the live section when the podman machine is stopped rather than starting
it — a read-only report has no side effects. Degrade gracefully when `podman stats` fails. Walk the
directories last: a real Coursier cache is millions of inodes, and that walk is why this is a verb
and not a line printed at every launch.

### 9.5 Reset inventory

Three verbs now touch the cache root, and each needs its own answer and its own test:

| verb | cache root |
|---|---|
| `--reset` | untouched |
| `--reset-cache` | this project's cache directory, removed |
| `--reset-all` | the whole cache root, with everything else |

`--reset` leaves the cache alone because resetting is about a stuck session; silently discarding a
warm cache would cost a full re-download nobody asked for.

---

## 10. Diagnostics

Stable error categories:

```text
PREREQ_JVM_NOT_COURSIER
PREREQ_SBT_NOT_COURSIER
PREREQ_MILL_BOOTSTRAP_MISSING
PREREQ_MILL_VERSION_UNPINNED
PREREQ_MILL_LAUNCHER_MISSING
PREREQ_MILL_JVM_NOT_SYSTEM

FS_READ_DENIED
FS_WRITE_DENIED
FS_GUARD_DENIED          # .git or .ko-agent-sandbox

NET_DIRECT_DENIED
NET_PROXY_HOST_DENIED

BACKEND_UNAVAILABLE
BACKEND_SETUP_FAILED
CHANNEL_UNAVAILABLE
```

Where the platform exposes enough information, include the denied path or endpoint. Never turn a
denial into a retry with broader permissions.

`FS_GUARD_DENIED` is separate from `FS_WRITE_DENIED` because its remedy is different: the path is
not one the user can grant.

---

## 11. Configuration

The build's repository allowlist is a project file, in the directory that already holds reviewed
boundary configuration:

```text
.ko-agent-sandbox/host-command/<tool>/egress/allowed
```

One list per tool, so a repository that builds with both grants each only what it resolves. Neither
needs a GitHub release CDN: the only fetch that used one is the Mill bootstrap's own launcher
download, which §3.3 provisions on the host instead.

The file's grammar is its own, narrower than any the proxy has: `+host <host>` entries and
comments, nothing else — no tags, no treatment words, no providers, no removals — refused at
validation rather than passed through (§8.4), and tested as its own accepted subset. The full
`allowed` grammar would let one `+model-provider` line expand into endpoints that are no artifact
repository, against §2.2's explicit-repositories contract, and its allowances and treatment words
mean nothing to a proxy running without inspection (§8.5).

Each inherits that directory's properties: the filter freezes it at any depth, the launcher reads it
on the host, and it is reviewed in a pull request like any other file. It is a separate list from
`egress/allowed` deliberately — the small prize behind the loopback port is the argument for
binding one at all (§8.1).

Adding `host-command/` extends a **closed namespace**. `SECURITY.md` refuses a launch on an entry
the launcher does not read, so that a typo'd `egres/` cannot sit as ignored config; the rule cannot
tell a typo from a name a newer launcher owns, so a project carrying this file is refused outright
by an older launcher — no session at all, for every agent and every write mode. The remedy is to
update the launcher and the image, and the refusal message must say so, since a reader who is told
only "unknown entry" has nothing to check but spelling:

```text
a typo, or a policy file a newer launcher reads; update the launcher and image
```

The namespace rule and its tests change in the same commit as the new path.

Derived paths come from Coursier conventions and environment APIs. Advanced overrides
(`cache-root`, `jvm-root`, `install-root`) are not added until needed.

---

## 12. Documentation

This feature adds a host-side execution path to a product whose documents currently describe the
container as the whole boundary. Update each claim at its binding site; each row lands in the phase
that makes its claim true.

| claim | canonical site | dependent site |
| --- | --- | --- |
| option and verb syntax, and each one's venue | README Reference / `--help` | parser tests |
| the complete boundary, host side included | launcher diagram | README diagram, `SECURITY.md` |
| what the container→host channel grants | `SECURITY.md` | §6, README option warning |
| cache poisoning and its blast radius | `SECURITY.md` | §5.1 |
| the host project path reaching the container | `SECURITY.md`, low-bandwidth | §6.2, §9.3 |
| what a host build may write, and which venue to use | `authoritySection` | §2.1, §2.3, §9.2 |
| the build allowlist file and its namespace | `SECURITY.md`, closed namespace | §11, its tests |
| venue-switch cost and stale-artifact cleanup | `AGENTS-SANDBOX.md` | §9.2 |

### 12.1 The README's opening claim becomes mode-dependent

The README states that the sandbox reaches no user files except the project. With `--run-on-host`
that is a default-mode claim: the option adds host-native execution reaching the Coursier JVM root,
this project's agent cache root, and the build's own proxy. The opening names the exception, and the
diagram shows the host-side path as a branch that exists only under the option and only on macOS.
The threat analysis is not repeated there; it points to `SECURITY.md`.

### 12.2 `SECURITY.md` needs a section, not a line

The launcher's own diagram (`AgentSandboxLauncher.scala`, "This file is the canonical description of
what the boundary is made of") gains the same branch, and `SECURITY.md` gains the argument behind
it:

- the channel is a container→host **execution** path, and what bounds it is §2.1 as Seatbelt
  enforces it — not the container, which the build is not in;
- the payload that matters is not code running inside the build sandbox but code the *host user*
  runs later. This is the property `fuse/ko-agent-fs/doc/git-metadata.md` already defends, restated
  for a second producer: `ko-agent-fs` guards it for writes through `/workspace`, the Seatbelt
  profile guards it for writes by the build, and both must be named where the property is stated;
- cache poisoning, with its blast radius drawn precisely: a poisoned agent cache reaches later
  agent builds *of the same project*, which are themselves sandboxed; it does not reach the user's
  own cache or any other project, because the separation is by root. `PLAN-COURSIER.md` reaches the
  same property for the container by a Podman `:O` upper, and the two mechanisms differ only
  because Seatbelt has no mount namespace;
- the host project path, in the low-bandwidth channel list, since §6.2 injects it whether or not
  same-path mounting is ever adopted;
- that under `--write=reject` plus `--run-on-host` the project is no longer read-only to the
  session, and why that is composition rather than escape.

---

## 13. Implementation phases

### Phase 1 — Common policy and prerequisite validator

Project canonicalization; Coursier JDK-home resolution and validation; agent cache-root
construction and its outside-the-project check; sbt launcher validation; Mill bootstrap, pinned
version and provisioned launcher validation; the policy model; structured diagnostics.

No backend yet.

**Exit criterion:** unit tests classify supported and unsupported layouts correctly.

### Phase 2 — Seatbelt backend

Profile generation, the §7.2 guard rules, and proxy-only network rules.

**Exit criterion:** `probe/build-profile-gate.sh` reports no FAIL for both tools — sbt on this
repository, Mill on `probe/mill-fixture` — with only the Phase 3 proxy rows as SKIP; the client
sbt 2 runs under the profile is decided and §3.2 says which, as §3.3 says `--no-daemon` for Mill;
`probe/runtime-authority.txt` holds every grant the gate needed and nothing else. A negative
result on the four `.git` rows changes the design, not the code.

### Phase 3 — Session lifecycle and build egress proxy

The §4 wrapper: the session directory lifecycle — publish, lock, scavenge — the proxy on its
ephemeral loopback port (§8.3) bound to the session lock, the allowlist file with §11's
closed-namespace rule, and the environment contract handed to the build. Phase 2 left only the
emit harness's session temporary directory; every lock-dependent claim of §4 becomes code here,
because the proxy's lifetime and the exit criterion's concurrency both stand on it.

**Exit criterion:** §7.4's two proxy rows turn from SKIP to PASS — an allowed artifact resolves
through the proxy and a non-allowlisted host is refused with the wrapper's diagnostic — and the
gate's warm-up block goes with them, so resolution under the profile is what the positive rows
measure. Two concurrent sessions run with distinct ports and session directories; the scavenger
removes a stale session and leaves a live one; no proxy or sbt server survives its session under
normal exit, error and a handled signal; and with `SIGKILL` injected at each lifecycle
transition — the scavenger's own condemnation and termination steps included — the next start ends
every recorded group and the portfile-attributed server before removing anything, while a child
caught before registration exits on its failed record rename (§4). One row binds a live server,
condemns its session, and recovers — the shutdown reaches the socket at its moved pathname, is
accepted through the tokenless handshake, and ends in a confirmed server exit.

### Phase 4 — The channel

`sandbox-run-on-host`, the host-side broker, `--run-on-host`, and the authority-section paragraph.

**Exit criterion:** an agent-invoked `sbt test` runs on the host and returns its exit code; the
teardown cases of §17 have answers with tests; `SECURITY.md`'s section, the launcher boundary
diagram and the README opening and diagram (§12.1, §12.2) describe the path this phase creates.

### Phase 5 — Launcher surface and hardening

`--stats`, `--reset-cache`, the reset inventory, and: denial telemetry; the proxy's own Seatbelt
profile (§8.3); symlink and path-race tests; proxy bypass tests; forked-process tests; malicious
`build.sbt` / `build.mill` fixtures; the venue script of §14.9, and the coherence probes of §14.7.

Documentation: the README Reference and `--help` rows of §12, for every option and verb this plan
adds.

---

## 14. Security-focused test suite

A deliberately hostile sample Scala project, whose build definition attempts each of the following.

### 14.1 Channel requests

The working directory arrives from inside the sandbox (§6.2). Each of these must be refused before
any profile parameter is derived from it:

```text
working directory ../../..                        refused
working directory through a symlinked component   refused
working directory naming an unrelated host path   refused
```

### 14.2 Filesystem reads

```text
$HOME/.ssh/*
$HOME/.aws/*
$HOME/.gitconfig
the launcher state root
arbitrary sibling repository
```

Expected: denied.

### 14.3 Filesystem writes

```text
PROJECT/.git/config and .git/hooks/*, at the root and nested
PROJECT/.ko-agent-sandbox/egress/allowed, at any depth
Coursier/jvm/*
~/.sbt/boot/*
the Coursier-installed sbt launcher
the user's Coursier v1
the user's Mill download folder
arbitrary $HOME path
```

Expected: denied.

### 14.4 Allowed writes

```text
PROJECT/*
agent cache coursier/v1/*
session temporary directory/*
```

Expected: allowed.

### 14.5 Process inheritance

sbt and Mill launch a forked JVM, a shell command and a test process. Verify children retain
containment — in particular that the §7.2 guard rules apply to them.

### 14.6 Network bypass

```text
raw TCP to public IP                    denied
HTTPS request ignoring proxy variables  denied
DNS/direct socket access                denied
allowed Maven request through proxy     succeeds
denied host through proxy               proxy-denied
```

### 14.7 Workspace coherence

A host build writes `target/` on the host and the agent reads it back through `ko-agent-fs`. That
is the host-writer/session-reader axis, and `--run-on-host` turns it from an occasional human edit
into every build.

`TODO.md` ("`--self-test`'s share rows") defers exactly this: `probe/coherency-probe.py` and
`probe/lower-probe.py` are the only rows that reach the share, and they are hand-run. Fold them
into `--self-test` as part of this work, under the constraints recorded there — a scratch lower in
the host project directory, the host side driven by the launcher, the full venue recorded, the work
directory gone on success and kept on failure, `.git` and `.ko-agent-sandbox` untouched.

They are **not** gated on `--run-on-host`: the axis exists under `--write=live` whenever anyone
edits on the host, an editor or a `git checkout` included, and the probes would be right to fold in
even if this feature never shipped. What is gated on the flag is one further row — run a build
through the channel, then read `target/` back from the container.

### 14.8 The probes, and when to run them

Hand-run instruments under `probe/`, each with a distinct trigger, each carrying it in its own
header. They are not tests: a test that fails is a defect in this repository, while a probe that
answers differently is a finding about the host.

| probe | run it when |
| --- | --- |
| `host-layout.sh` | a new machine, or Coursier or the JDK is upgraded |
| `sbt-exec-chain.sh` | sbt is upgraded or reinstalled — the distribution path moves with it |
| `seatbelt-semantics.sh` | each new macOS release |
| `build-profile-iterate.sh` | a build stops under the profile and nothing names the missing grant |
| `build-profile-gate.sh` | the generator changes, and before each release: it is §7.4, both tools |
| `session-recovery.sh` | before Phase 3 encodes §4's recovery; when sbt or the proxy changes |
| `loopback-rule.sh` | each new macOS release: the §7.3 proxy rule's spellings and controls |
| `jvm-proxy-rule.sh` | each new macOS or JDK: the JVM's path to the proxy under the profile |

`seatbelt-semantics.sh` is the one with teeth. §7.2's table is what it measured, and the guard is
built on those answers; if E3, E4 or E5 stops answering DENIED, the profile no longer enforces what
§2.1 claims. That is a release blocker, not a probe to update.

### 14.9 Venue record

The suite is a script CI runs, run by hand on macOS until CI exists. `TODO.md` sets the standard it
must meet: a run with no venue recorded is not evidence for the next release. So it records macOS
version, podman version and machine provider, the Coursier JDK, sbt and Mill versions, and the
project filesystem's case sensitivity — the last because §2.1's fold rule depends on it.

---

## 15. Symlink and path-escape requirements

Do not rely on textual path prefixes. Before passing roots to the backend, canonicalize the project
root, the Coursier roots and the tool/JVM locations, and reject unexpected ancestor relationships.

Tests must cover symlinks from inside the project to `$HOME`, `/`, Coursier read-only state, another
repository, and — because §2.1's guard depends on it — to `.git` and `.ko-agent-sandbox` within the
project itself.

The channel's working directory (§6.2) is the one path arriving from inside the sandbox rather than
from the launcher, so it is canonicalized and proven to be the project root or beneath it before any
profile parameter is derived from it.

A symlink must not provide authority beyond the underlying filesystem policy.

---

## 16. Definition of done

1. sbt and Mill compile and test normal Scala projects.
2. Missing dependencies download into the project's agent Coursier cache.
3. The build cannot modify Coursier-managed JVMs.
4. The build cannot modify `~/.sbt/boot`.
5. The build cannot modify the user's own Coursier cache or Mill download cache.
6. The build cannot read or write git control state or `.ko-agent-sandbox`, at any depth, in any
   case, through a write, a link or a symlink.
7. The build cannot access unrelated user data, the launcher state root included.
8. Child processes inherit containment.
9. Direct network access is impossible; the build's own proxy is the only egress path.
10. The proxy restricts destination hosts, and exits with its session.
11. Denials fail closed, produce useful diagnostics, and never fall back to another venue.
12. The agent reaches the build through `sandbox-run-on-host`, the session says so, and no working
    directory the sandbox supplies changes the profile's `PROJECT` grant.
13. `--stats`, `--reset-cache` and the reset inventory hold.
14. Every §12 row is written at its canonical site, and no dependent site restates it.

---

## 17. Open questions

These are implementation experiments, not reasons to broaden the policy in advance. The first four
change the design if they answer badly, and §7.4 is where they are answered.

### Seatbelt semantics

Canonicalization, case folding, access-time evaluation and hardlinks are measured; §7.2 carries the
answers. What remains:

- What is the minimum set of non-user-data runtime reads the Coursier JVM needs on macOS 26.4+?
- What `sbtn` needs under the profile. Not a blocker — §3.2 pins `--jvm-client` — but a gate row
  keeps measuring it, and if it starts passing the pin becomes a choice.

- `mach-lookup` is granted unfiltered, and the system tool directories are executable (a build's
  scripts need `find`, `mount` and whatever else; `probe/runtime-authority.txt`). Together those
  let a build reach any Mach service — `open` through LaunchServices would start an application
  outside the profile. Measure the services a build actually needs, as `ops` measures operation
  families, and filter to them (`(allow mach-lookup (global-name …))`, the shape Apple's profiles
  use); §14.5's process-inheritance rows are where the answer is checked.

### The channel

- What kills a running host build when the user interrupts the agent, and what happens to it when
  the sandbox container dies? An orphaned sbt on the host is not plausible but measured: the
  probes left fifty servers running, some for two weeks, because `sbt shutdown` reaches only a
  server whose socket it can find. §4 ends by pid what it started and scavenges what a kill left;
  what remains open is who sends the signal when the interrupt arrives from inside the container.

### Claims to confirm rather than assume

- Coursier's cache layout, and whether a self-consistent artifact and checksum pair is accepted
  without revalidation. §5.1's decision does not depend on the details, but its text should not
  assert them.
- Whether zinc invalidates on JDK identity, and so whether a venue switch causes a rebuild, a
  failed build, or neither. §9.2 and §9.3 are worded to hold whichever it is; the measured answer
  sharpens them.
- Whether anything in the image reads `.bsp/sbt.json`. A host build writes one naming a host
  launcher, but with no BSP client installed nothing in the container acts on it, so it stays out
  of `AGENTS-SANDBOX.md` until one exists. §12's `AGENTS-SANDBOX.md` row is where that lands.

---

## 18. Source references

- Coursier managed JVMs and platform JVM-cache locations:
  https://get-coursier.io/docs/cli-java
- Coursier artifact cache and platform `v1` locations:
  https://get-coursier.io/upcoming/features-cache/
- Coursier installation/application directory behavior:
  https://get-coursier.io/docs/cli-installation
- Mill project-local bootstrap scripts:
  https://mill-build.org/mill/cli/installation-ide.html
- sbt server: domain-socket and TCP modes, the port file, discovery and the token (§3.2, §7.3):
  https://www.scala-sbt.org/1.x/docs/sbt-server.html

Same-path workspace mounting (§9.3), for whoever revisits it — both mount the project at its host
path, for path legibility rather than for shared build state:

- Gemini CLI sandboxing:
  https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/sandbox.md
- Docker Sandboxes, whose parent directories are empty scaffolding so only the workspace is real:
  https://www.docker.com/blog/building-ai-teams-docker-sandboxes-agent/
