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
appears mid-build is covered by the same rule. A Windows backend needs an equivalent — a filesystem
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
PROJECT/**                          read-write
PROJECT/**/.git/**                  inaccessible
PROJECT/**/.ko-agent-sandbox/**     inaccessible

resolved Coursier JDK home/**       read/execute       # §3.1, one home, never a root
agent cache root/coursier/v1/**     read-write         # §5

~/.sbt/boot/**                      read-only          # sbt only
Coursier-installed sbt launcher     read/execute       # sbt only
user Mill download folder/**        read/execute       # Mill only

session temporary directory         read-write         # fresh per session

everything else user-owned          inaccessible
```

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
sbt bootstrap artifacts missing    -> build fails; report ~/.sbt/boot is read-only
Mill bootstrap absent              -> fail before entering sandbox
Mill version unpinned              -> fail before entering sandbox
Mill launcher not provisioned      -> fail before entering sandbox; ask the user to run ./mill
repository not allowlisted         -> proxy denial; report requested host
filesystem path not allowed        -> sandbox denial; report path when observable
backend unavailable                -> fail; report; do not run in the container
```

---

## 3. Tool prerequisites

### 3.1 JVM

Only Coursier-managed JVMs are supported. The wrapper resolves one before entering the sandbox and
the profile grants that **one canonical JDK home**, not a root directory containing JDKs.

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

`~/.sbt/boot` is read-only. The sandbox does not provision missing sbt/Scala bootstrap state.

Disable sbt server state outside the project:

```text
-Dsbt.server.autostart=false
```

If a global sbt base is needed, redirect it into the project:

```text
-Dsbt.global.base=<PROJECT>/.sandbox/sbt-global
```

Do not grant `~/.sbt/1.0`, `~/.sbt/2.0`, `~/.ivy2`, or `~/.m2` by default.

### 3.3 Mill

Require a project-local bootstrap script:

```text
<PROJECT>/mill
```

Do not support a globally installed Mill.

Also require a **pinned version** and a launcher the user has already provisioned:

```text
./mill --version        # once, in a host terminal, whenever the pinned version changes
```

The sandbox does not fetch the launcher. Mill 1.x publishes native launchers — a real host's
download folder holds entries like `1.1.8-native-mac-aarch64` beside older jars — so fetching it
would need a writable *and* executable directory, the only one anywhere in §2.1. Provisioning it
instead makes Mill follow sbt's rule rather than its own.

That rule, stated once because it explains both tools: **the user provisions the launcher; the
sandbox fetches only artifacts.** sbt's launcher comes from `cs install sbt` and everything else it
needs is a jar the JDK reads, fetched into the writable agent cache through the proxy. Mill's
launcher *is* the fetched thing, and it is an executable. Provisioned, it is read/execute like
sbt's, out of `${XDG_CACHE_HOME:-$HOME/.cache}/mill/download` — or wherever
`MILL_FINAL_DOWNLOAD_FOLDER` or `MILL_USER_CACHE_DIR` redirects it.

Two consequences worth having: the build needs no GitHub release CDN, since only the bootstrap's
own download ever used one (§11); and a version bump becomes an explicit host step rather than
something a build definition performs on itself.

### Detecting that the host step is needed

Before entering the sandbox, resolve the pinned version the way the bootstrap does — four file
reads, in its order — and look for a download-folder entry whose name *starts with* it:

```text
MILL_VERSION → .mill-version → .config/mill-version
             → build.mill.yaml (mill-version:) → build.mill (//| mill-version:)
```

Prefix matching is what keeps this reliable: it never replicates `ARTIFACT_SUFFIX`'s per-platform,
per-version case logic, which is the half Mill changes between releases.

Unpinned is a refusal rather than a fallback. The bootstrap's own fallback is a
`DEFAULT_MILL_VERSION` assignment inside the committed script, and grepping project-controlled
shell source to decide which host executable to grant is the wrong shape.

The script's `MILL_TEST_DRY_RUN_LAUNCHER_SCRIPT=1` mode prints the exact launcher path without
downloading, which would remove the prefix match — and it is not used. Reading the version is a
read; asking the script is executing agent-authored shell on the host with full user authority,
which is what §2.1 exists to prevent.

The script stages a download at `${MILL_OUTPUT_DIR:-out}/mill-temp-download`, inside the project,
which `PROJECT` already covers. It needs no row of its own.

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
11. stop the proxy and remove the session directory
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

The session lock is also what the build's proxy binds to (§8), so the answer does not change when
an sbt server outlives a single invocation.

A JVM writes a preference store under `$HOME` on first use. Point that store and `java.io.tmpdir`
at the session temporary directory (`-Djava.util.prefs.userRoot`, `-Djava.io.tmpdir`), so a
read-only home costs no diagnostics.

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

Permissions, against §2.1:

```text
agent cache root/coursier/v1/**   RW      artifacts the build downloads
resolved Coursier JDK home/**     RX      §3.1
user Mill download folder/**      RX      §3.3, provisioned rather than fetched
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
MILL_DOWNLOAD
TOOL
SBT_BOOT
SESSION_TMP
WORKING_DIRECTORY
PROXY endpoint
```

`WORKING_DIRECTORY` carries no grant of its own: it is inside `PROJECT`, which already has one, and
it reaches the backend as the child's cwd rather than as a rule (§6.2).

For Mill, `TOOL` points inside `PROJECT`. For sbt, it points to the Coursier-installed launcher, and
the sbt-specific boot path can be omitted when conditional profile generation is easier than
supplying a dummy path.

### 7.2 Filesystem policy

Each §2.1 row as the profile parameter that carries it:

```text
PROJECT                           RW
PROJECT/**/.git                   deny read, write and link, case-folded
PROJECT/**/.ko-agent-sandbox      deny read, write and link, case-folded
COURSIER_JDK_HOME                 RX
AGENT_CACHE_V1                    RW
MILL_DOWNLOAD                     RX     # Mill
SBT_BOOT                          RO     # sbt
TOOL                              RX
SESSION_TMP                       RW
```

`SESSION_TMP` is the writable child of the wrapper's per-session directory (§4), not the user's
`TMPDIR`, and the session directory holding the lock is named in no rule.

**Every wrapper-supplied path is a literal, never interpolated into a regex.** `(subpath …)` and
`(literal …)` for the parameters above; `(regex …)` only for the two name-pattern denies, which are
patterns by intent. The paths in play are not regex-safe — the Coursier JDK home carries a
percent-encoded `+`, a literal `+` and dots (§3.1), and the sbt install directory contains a
space — and a path interpolated into a pattern matches more than itself, silently and in the
permissive direction.

Do not pre-authorize broad paths such as `/System/**`, `/usr/**` or `/opt/homebrew/**` unless
testing proves a specific stable runtime read is required, and then add the narrowest rule that
testing justifies.

### 7.3 Network

Seatbelt permits connections only to this build's proxy ingress endpoint (§8).

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
```

The four `.git` rows after the first are the ones that decide the design rather than the code: they
test access-time evaluation, case folding, link creation and symlink canonicalization. §17 records
them as unanswered until this gate runs.

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

Bind the proxy to the §4 session lock, not to one invocation. With `-Dsbt.server.autostart=false`
(§3.2) a session is one build and the two are the same; when a persistent sbt server is later
enabled for warm builds, the proxy must outlive each thin-client invocation and exit with the
server, or the server's next resolve fails against a proxy that has gone. Binding to the lock gives
one answer for both.

Enabling a server also makes a session a server's lifetime rather than a single build. §4's
guarantee — no session sees another's temporary state — still holds; the sentence that a session is
one build does not.

### 8.3 Artifact

The container's proxy is a GraalVM native image built for Linux inside `debian-coursier`. On macOS,
run `target/dist/agent-egress-proxy.jar` on the wrapper's own JVM — `sbt dist` already produces
it — or add a macOS native-image build later. §3.1's Coursier-managed-JVM requirement is about the
build, not about the wrapper's own process.

Bind on an ephemeral port on `127.0.0.1`.

### 8.4 Policy semantics

The proxy logs denied destinations with enough information for the wrapper to produce:

```text
Build requested network access to:
  repo.example.org:443

This host is not permitted by the Scala build sandbox.
```

Do not automatically add it.

### 8.5 HTTPS

Prefer ordinary HTTP CONNECT tunnelling, with the destination host and port enforced at CONNECT
time. Then the build needs no additional trust material, and the Coursier-managed JDK's own trust
store suffices — which matters here because §2.1 makes that JDK read-only, so a merged truststore
cannot be written into it the way `JdkTrust.scala` does for the container image. If inspection is
ever wanted, point the JVM at a wrapper-owned store with `-Djavax.net.ssl.trustStore` rather than
touching the JDK.

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
  symlinks");
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
PREREQ_SBT_BOOT_MISSING

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

**Exit criterion:** §7.4 passes complete — including the four rows that test access-time evaluation,
case folding, link creation and symlink canonicalization. A negative result there changes the
design, not the code.

### Phase 3 — Build egress proxy

The wrapper-owned proxy, its allowlist file, and its binding to the session lock.

**Exit criterion:** an allowed artifact resolves; a non-allowlisted host is refused with the
wrapper's diagnostic; the proxy exits with its session under normal exit, error and kill.

### Phase 4 — The channel

`sandbox-run-on-host`, the host-side broker, `--run-on-host`, and the authority-section paragraph.

**Exit criterion:** an agent-invoked `sbt test` runs on the host and returns its exit code; the
teardown cases of §17 have answers with tests; `SECURITY.md`'s section, the launcher boundary
diagram and the README opening and diagram (§12.1, §12.2) describe the path this phase creates.

### Phase 5 — Launcher surface and hardening

`--stats`, `--reset-cache`, the reset inventory, and: denial telemetry; symlink and path-race tests;
proxy bypass tests; forked-process tests; malicious `build.sbt` / `build.mill` fixtures; the venue
script of §14.8, and the coherence probes of §14.7.

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

### 14.8 Venue record

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

- Does SBPL canonicalize before matching? If a `file-write*` regex sees the path as given rather
  than as resolved, then `PROJECT/x -> .git` followed by a write to `x/config` walks through the
  `.git` deny, and §2.1's guard is not enforced.
- Can an SBPL regex fold case, to match `policy.rs`'s `folds_to` on a case-insensitive APFS volume?
- Is `file-link` the operation that covers a hardlink whose *target* is under a denied path?
- What is the minimum set of non-user-data runtime reads the Coursier JVM needs on macOS 26.4+?

### The channel

- What kills a running host build when the user interrupts the agent, and what happens to it when
  the sandbox container dies? An orphaned sbt on the host is a plausible failure mode, and §4's
  scavenger reclaims directories, not processes.

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

Same-path workspace mounting (§9.3), for whoever revisits it — both mount the project at its host
path, for path legibility rather than for shared build state:

- Gemini CLI sandboxing:
  https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/sandbox.md
- Docker Sandboxes, whose parent directories are empty scaffolding so only the workspace is real:
  https://www.docker.com/blog/building-ai-teams-docker-sandboxes-agent/
