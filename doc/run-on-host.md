# Run on Host — sbt, `mill` and Maven commands outside the container

`--run-on-host=<programs>` (macOS only, off by default) relays this project's sbt, `mill` and Maven
commands to the host, where each runs under a Seatbelt profile of its own. This document is the
reference for how host commands work and what they require; the table names the code that enforces
each part:

| concern | binding site |
| --- | --- |
| the security properties and their costs | `SECURITY.md` "Run on host" |
| the option, the command, what a command may write | README Reference, `--run-on-host` |
| the channel protocol and its teardown | `RunOnHostChannel.scala`, `sandbox-run-on-host` |
| the command lifecycle: publish, lock, scavenge | `RunOnHostSession.scala` |
| prerequisite validation and the paths it settles | `RunOnHostPrereqs.scala` |
| the wrapper and the broker's runtimes: proxy, sbt server, environment | `RunOnHostSandbox.scala` |
| the broker's mill daemon: its start, its port, a daemon of yours | `MillDaemons.scala` |
| the generated profile | `SeatbeltProfile.scala` |
| the exit criteria, measured | `src/probe/run-on-host-profile-gate.sh` |

The measurement behind the feature: an `sbt test` of this project takes about 2 GB inside the podman
machine, whose total is fixed when the machine is created and shared with every other session on it
— and whose resident memory, once grown to hold a build, macOS never gets back. On the host the same
build runs on memory reclaimed when it exits, at host speed.

A host command's recurring cost is startup. For sbt and `mill` the broker keeps one server or
daemon warm across the launch's commands from one build directory ("Where the broker deviates
from the stock tool"), so a start is paid by the first command from a directory, after
`sandbox-run-on-host <program> shutdown`, and after the tool's own idle exit — sbt's seven days,
Mill's thirty minutes; an sbt server keeps the `sbt.version` and options it started with until
`shutdown`, as in a terminal, and a cancelled sbt command leaves its server warm. A `mill` start
is also paid after a cancel, which ends the daemon as stock Mill does, and after an edit to what
Mill restarts the daemon on — its version pin, `mill-jvm-opts`, `mill-repositories`, or anything
in `build.mill.yaml`, the header Mill reads them from — and costs
the starter's connect retry, ten seconds, on top of the daemon's own start ("`mill`"). Maven runs
once, so every invocation starts a JVM and loads the build, while the on-disk state stays warm:
the caches, and the incremental-compile outputs under `target/`.

Out of scope, deliberately: arbitrary build programs (`scalafmt` and ad-hoc `scala` stay
in the container); arbitrary globally installed JVMs — Homebrew, SDKMAN and asdf JVMs included;
direct Internet access from the command; any automatic expansion of permissions when a command
fails, and any fallback to the container; implicit access to `~/.m2`, `~/.ivy2`, user git
credentials, SSH credentials or unrelated home-directory state; stdin — `sbt console`, `sbt shell`
and `sbtn`'s interactive modes; mounting the container's workspace at its host path (`TODO.md`,
"same-path mounting"); Gradle, whose processes talk over loopback TCP (`TODO.md`, "Gradle"). The
container keeps its toolchain: host commands are the fast path, not a replacement, and a session
without `--run-on-host` builds in the container as before.

## Why only macOS

The feature exists only where the guard's access-time name denies hold. What the alternatives
look like, for whoever revisits them:

On Linux, bubblewrap does the *positive* half better than Seatbelt: it starts with nothing mounted
and builds up, so the grant table holds by construction, and `--unshare-all` removes the network
namespace outright, making proxy bypass impossible rather than merely denied. But its mounts are
established once at start, so covering `.git` at any depth means binding over each one found then —
and a `.git` created during the command has no mount over it. Landlock is no better: its ruleset is
fixed at creation. With nothing to gain — a container command already runs at host speed on host
memory, reclaimed on exit — the feature would also cost Linux the one limit the container has that a
host command does not: the cgroup memory limit that kills a runaway build inside the sandbox instead
of taking the machine down.

On Windows, AppContainer expresses the grants perfectly well: a per-user profile with a derived
SID, inheritable ACEs on the granted roots, private profile storage, network confinement by
capability plus a WFP rule restricted to the proxy endpoint. What it cannot express is the denies.
ACL inheritance has no name patterns, so "deny `.git` at any depth" can only be an enumerated set
of deny ACEs placed by a launch-time scan, and a `.git` created *during* the command inherits the
project's allow — a race where the deny must hold at every access. A Windows backend needs an
equivalent of access-time path filters — a filesystem minifilter, or a design that does not put the
guard in ACLs at all — before it is worth reconsidering.

## The host command's filesystem rules

The filesystem rules define what a host command can access:

- **Commands can start programs they write in the project or their temporary directory.** A
  child inherits the profile, so running those programs adds no authority. Tests routinely write
  and run stubs. The run-on-host cache permits reads and writes but not direct process execution;
  the JVM can still load and execute code from cached JARs.
- **Seatbelt has no mount namespace**, so `$HOME` cannot be replaced with an empty directory the
  way a container image would. The profile denies it instead: a command cannot create
  `$HOME/.netrc`, a Coursier mirror file, or any other configuration a later step would read,
  because the write is denied rather than because the directory is bare.
- **Seatbelt matches the path after resolving it, and the pattern does not fold case.** On a
  case-insensitive volume an access through `.GIT` to an existing `.git` resolves to the lowercase
  path and is denied (`src/probe/seatbelt-semantics.sh`, E5). A `.GIT` the command creates where
  no `.git` exists keeps that spelling and is not denied, though host `git` run in that directory
  would open it as `.git`; the workspace filter refuses the name. `TODO.md` records the planned fix.
- **The `.git` and `.ko-agent-sandbox` denials cover link creation, not only writes.** Without them,
  a command could create `link(PROJECT/.git/config, PROJECT/x)` and write through `x` to modify
  `.git/config`.
  Both paths are on the host's project filesystem, so a filesystem boundary does not prevent this.
- **Commands can create a bare Git layout from ordinary names in the writable tree.** Neither the
  Seatbelt profile nor the workspace filter refuses those names. Running host `git` inside a
  directory the agent created is running the agent's output, the same gap `SECURITY.md` records
  for the workspace filter.
- **Each command gets a fresh temporary directory.** A killed command can leave one behind;
  the next command reclaims it rather than reusing it (`RunOnHostSession.scala`).

## Network

The command's only egress is its proxy (below); Seatbelt permits connections to that loopback
endpoint and nothing else, with UNIX-domain sockets only inside the command's temporary directory
and, for an sbt client, the broker's, where its server listens. Loopback reaches local services,
so no other loopback connect is granted, and no TCP listener but the mill daemon's: a test suite
that binds one — the proxy's wire-relay tests do — gets `EPERM` on the host under sbt and Maven
and runs in the container, while under `mill` it runs on the host, since the daemon's listener
grant covers every loopback port and everything the daemon forks inherits it (`SECURITY.md` "Run
on host" states that cost). Per program (`SeatbeltProfile.Network` is the typed input the dispatch
shows):

| process | network |
|---|---|
| sbt server | loopback to the proxy; UNIX sockets bound and connected under the broker's `tmp/` |
| sbt client | the same under the command's `tmp/`, plus connects under the broker's `tmp/` |
| `mill` daemon | loopback to the proxy; loopback listeners, any port, since it binds port 0 |
| `mill` client | loopback to the proxy, and to the daemon's one port |
| Maven | loopback to the proxy; UNIX sockets under the command's `tmp/` |

Five measured rules (`src/probe/loopback-rule.sh`, `src/probe/jvm-proxy-rule.sh`,
`src/probe/run-on-host-broker-session.sh`); none is chosen from documentation:

- The proxy rule is `(remote ip "localhost:<port>")`: an ip-literal host is refused by the
  compiler ("host must be * or localhost").
- The "localhost" class covers native `127.0.0.1` and `::1` but not a JVM's dual-stack connect,
  which reaches `127.0.0.1` as v4-mapped `::ffff:127.0.0.1` and dies with `EPERM`; the environment
  contract sets `-Djava.net.preferIPv4Stack=true` for exactly this.
- Seatbelt counts a local socket as network: without `(local unix-socket (subpath SESSION_TMP))`
  sbt's server gets `EPERM` from `bind()` on its boot socket and its client waits for it forever
  ("The channel and the command" has the client's wait).
- The mill daemon's `(local ip "localhost:*")` admits a port-0 bind and accept, and no rule
  confines a port-0 bind to one port (L1–L4).
- A client's `(remote ip "localhost:<port>")` reaches that port and is denied the neighboring
  one (L3, L4, M3), and only the JVM launcher connects under it: the native image's connect is
  dual-stack, for the reason above, and stays denied with the property on its command line (M2).
  That is why the wrapper runs the JVM launcher ("`mill`").

The proxy settings handed to the JVM are convenience, not the boundary: Seatbelt is what prevents
bypass via direct sockets, and the gate's bypass rows measure it.

Every command's proxy allows one host on its own: the program's Maven Central
(`RunOnHostPrereqs.centralHost`). For sbt and `mill`, which resolve through Coursier, that is
`repo1.maven.org`; for Maven, whose super POM names the alias, it is `repo.maven.apache.org`.
Each program resolves against its own host and never against the other's. `repo.scala-sbt.org` is
deliberately absent: it hosts the Ivy-style plugin repository and is not
part of sbt's bootstrap — an uncached sbt version named in `project/build.properties` resolves from
Maven Central. A command that needs more adds it explicitly ("Configuration", below); nothing is
inferred or silently permitted.

## Refusals

Missing prerequisites and denied accesses fail clearly, nothing expands authority, and nothing
falls back: a host command that cannot run is reported to the user, never re-run in the
container — the same rule the egress refusal follows.

Every refusal before the command starts is a `RunOnHostPrereqs.Refusal` value, one case per
category, so the wrapper and the channel word the same refusal for their own readers without the
tests matching on either wording. A denial while the command runs falls under no refusal category: a
filesystem denial reaches the command's own stderr as the OS error, and a network denial is the
proxy's audit line, which the wrapper reads and reports per host after the command ("Command
requested network access to: …") — from the log's length at the command's start, so a shared
proxy's earlier denials are not this command's. It never adds the host itself.

## Program prerequisites

The rule that explains all three programs: **the user provisions the executable; the sandbox fetches
only artifacts.** sbt's comes from `cs install sbt`, and everything else it needs is a jar the JDK
reads, fetched into the writable run-on-host cache through the proxy. `mill`'s executable *is* the
fetched artifact — so it is provisioned, not fetched, and a version bump
is an explicit host update rather than an automatic update performed by the build definition.
Maven's is the distribution the project's wrapper unpacked on the host.
`RunOnHostPrereqs.scala` validates all of the below before a command starts; a violation is a
refusal naming what to fix, and `src/probe/host-layout.sh` shows what a host actually has.

### The JVM

Only Coursier-managed JVMs. `JAVA_HOME` is the only source, and must resolve to one canonical JDK
home under the user's Coursier cache root — `java` on `PATH` is `/usr/bin/java`, a macOS stub that
resolves through `JAVA_HOME` or `/usr/libexec/java_home`, reporting the right JVM while being the
wrong path. Rejected: the stub, `/Library/Java/JavaVirtualMachines`, Homebrew and SDKMAN JVMs, and
a `JAVA_HOME` resolving outside the Coursier cache.

A current Coursier unpacks a JDK into its archive cache, so the home is a URL-derived path under
`arc/` with a percent-encoded `+` in it. The grant is that resolved home: granting the `arc` root
instead would hand the command every archive Coursier ever extracted. The JDK is read-only to the
command, so sharing the user's copy exposes no write path, and duplicating one per project would
cost hundreds of megabytes for nothing.

### sbt

`cs install sbt`, and no arbitrary `sbt` from `PATH`: the wrapper verifies the executable belongs to
the Coursier application-install directory — on macOS `~/Library/Application Support/Coursier/bin`,
whose space makes correct shell quoting necessary. That `sbt` is two files: the 1.2 KB script on
`PATH` execs a second `sbt` inside an unpacked distribution in the archive cache, and the profile
grants the distribution's *home* — the distribution's `sbt` reads `sbt-launch.jar` and `conf/`
relative to itself. The home is read from the script's text (`SeatbeltProfile.sbtDistribution`);
running the script to ask would execute what the profile exists to contain, on the host, unconfined.

sbt 2 is client/server by construction — there is no one-shot mode — so the broker starts the
server inside the server profile, with the build directory as its working directory, the broker's
own `tmp/` as its temporary and socket directory, the command line sbt's thin client uses when it
starts one, given the request's `-D` and `-J` arguments (`RunOnHostSandbox.serverCommand`), and
its stderr in a file under that `tmp/` ("The channel and the command"); each command's client then
attaches to it. The server's state follows `-Dsbt.global.base` into the project's run-on-host
cache. The base must persist across commands: sbt 2 leaves `target/` outputs as symlinks into its
content-addressed store, so removing that base when the command ends would leave the build's own
outputs dangling.
The same fact cuts the other way at entry: a tree the user's unconfined sbt built links into a store
the profile denies, so the broker sweeps `target/` symlinks that resolve outside the granted roots
before it starts an sbt server, after any foreign server for the directory is shut down — its
build finished — so a sweep never runs during the user's own build. `~/.sbt/boot` is not
granted and has no consumer — with the global base redirected, sbt boots from the run-on-host cache,
warm across sessions. `~/.sbt/1.0`, `~/.sbt/2.0` and `~/.m2` are not granted either.

The Ivy home follows `-Dsbt.ivy.home` into the run-on-host cache the same way, and `~/.ivy2` is not
granted. sbt uses that home for three things, read from the sources of sbt 1.12.13 and 2.0.8.
Resolving a dependency between the projects of one build goes through Ivy
(`projectDescriptors`), and Ivy takes the lock file `<ivy home>/.sbt.ivy.lock` first.
`<ivy home>/local` is the `local` resolver, which every resolution reads and `publishLocal`
writes. `updateSbtClassifiers` keeps its excludes file there. Without the redirect, an sbt
1.12.13 `packageBin` of a build with a `dependsOn` edge dies under the profile while
canonicalizing the denied `~/.ivy2` for that lock. This repository's own build has no such edge,
so the gate's sbt rows never reach that path; `src/probe/ivy-fixture` is such a build, on sbt 1.

sbt 2 releases after 2.0.8 have no Ivy library (sbt/sbt#9615, merged 2026-08-24) and take no
lock, so the fixture is not duplicated for sbt 2; it retires when sbt 1 does. Those releases
still take `local` and the excludes file from `sbt.ivy.home`, so the redirect and its grant stay
after the lock is gone. Retire them only when a released sbt stops deriving those two paths, and
check that by reading `Defaults.scala` again, not by a gate run.

The wrapper passes `--jvm-client`: sbt 2 defaults to `sbtn`, which under the profile prints that it
is starting the server and returns with no build run — a gate row keeps measuring it, and if it
starts passing, the wrapper can reconsider requiring `--jvm-client`. The distribution's `sbt`
resolves `java` from `PATH`, so the environment puts the granted JDK's `bin` first: the broker
starts the server by running the script, and `-java-home` reaches the client alone.

### `mill`

A project-local bootstrap script, the build directory's own `mill`; no globally installed `mill`.
The bootstrap is run with `MILL_VERSION` naming the JVM launcher of the pinned version, `<v>-jvm`
(`RunOnHostPrereqs.millLauncherVersion`), and that launcher must already be provisioned —
`MILL_VERSION=<v>-jvm ./mill version` once, in a host terminal, whenever the pinned version
changes — because `mill` 1.x fetches its launchers as executables, and fetching one would put an
executable the sandbox chose into a directory the user's own `./mill` runs from, outside any
sandbox. What is granted is that one file, `<download folder>/<v>`, never the download folder
around it, which holds every launcher the user ever ran. A version the user never provisioned the
JVM launcher for is a refusal naming the command to run.

The launcher is the JVM one, not the native image the bootstrap runs for a bare pin, because the
image takes no `JAVA_TOOL_OPTIONS`: the environment's `preferIPv4Stack` never reaches it, its
connect to the daemon is the dual-stack one the "localhost" class denies ("Network"), and the
property on its command line changes nothing (measured, `src/probe/run-on-host-broker-session.sh`
M2). A `<v>-native` pin asks for that image by name and is refused with the reason.

The wrapper resolves the version the way the bootstrap does, from the build directory —
`.mill-version`, `.config/mill-version`, `build.mill.yaml`, the build script's `//|` header, then
the script's own default (`RunOnHostPrereqs.millVersion`) — so a nested build directory with a
bootstrap of its own is another build. The script's `MILL_VERSION` and `DEFAULT_MILL_VERSION`
environment overrides are not read: the command's environment carries the wrapper's own
`MILL_VERSION` and no other, so the script and the wrapper resolve alike. Reading the version is a
read; asking the script by running it would execute agent-authored shell on the host.
`mill-jvm-version: system` is required in the build directory — its default provisions a JVM
through Coursier's index into a writable, executable place, which is what the JVM rule refuses —
and is what makes the daemon's JVM the granted JDK, the first `java` on the command's `PATH`.

Mill is client/daemon by construction: the launcher starts a daemon that binds a loopback port
of the kernel's choosing, writes it to `out/mill-daemon/socketPort`, and connects
(`Server.scala`, `ServerLauncher.scala`, Mill 1.1.9). The broker starts the daemon itself, before
the first `mill` command of a build directory, and every command from that directory attaches to
it (`MillDaemons.scala`, `RunOnHostSandbox.BrokerRuntimes`):

1. The **starter**: the build directory's `./mill version`, as a registered spawn in the broker's
   session (`records/daemon-mill-<hash>`) under the daemon profile — the profile with loopback
   listeners granted and no outbound but the proxy — with the closed environment and the
   broker's `tmp/` as its temporary directory. The launcher starts the daemon, the daemon binds
   its port, and the launcher's own connect is denied, so it retries for ten seconds, exits
   nonzero, and the daemon stays in the spawn's group (measured, M1). Its output goes to
   `daemon-mill-<hash>.log` in the session directory, the finding when a start fails; a starter
   that neither ends nor writes anything for two minutes, the proxy log not growing either, is a
   failed start.
2. The **daemon** is the member of that group whose command line names
   `mill.daemon.MillDaemonMain`, proved from then on by its pid and start time. `socketPort` is
   read as a candidate — an integer in port range, nothing more — and granted only after `lsof`
   shows that pid listening on it; the file is the build's to write and authorizes nothing, and a
   candidate the daemon does not listen on refuses the start.
3. Each command's **client** runs `./mill <args>` from the build directory under the client
   profile, which admits outbound to that one port and the proxy, with the broker's `tmp/` as
   its temporary directory ("The command's lifetime and environment" has why). The launcher
   reads `socketPort` and connects; a port planted there is one the profile denies, so the
   command fails and the daemon is untouched.

The daemon gets each command's environment through the protocol (`DaemonRpc.Initialize`), so the
closed environment reaches the build per command; the daemon JVM's own options, the proxy
settings included, are the starter's, fixed at its start. What Mill's launcher restarts the
daemon on — the launcher version, the resolved JVM, `mill-jvm-opts` and `mill-repositories`, each
from the source Mill reads it from, the build file's header taken whole
(`RunOnHostPrereqs.millDaemonConfig`) — the broker compares before each command and, on a
change, replaces the daemon under the same proxy, the launcher
assembled afresh since a changed pin grants another: the stock client meeting the mismatch would
end the daemon and start a replacement from its own profile, which cannot bind, and the command
would fail. A daemon gone on its own — Mill's idle exit, thirty minutes after its last client,
`sandbox-run-on-host mill shutdown`, or a client's disconnect mid-command, on which the daemon
shuts itself down (measured, M5), where an sbt server survives the same disconnect — is replaced
the same way before the next command; its starter's spawn stays as the group's provable leader
and is ended with the group first. `out/mill-daemon` is Mill's: the broker neither clears nor
writes it, and reads only the port candidate. A command is refused while `out`,
`out/mill-daemon` or an entry directly in it is a symlink or a file with a second name
(`MillDaemons.rendezvousIsOwn`), because the launcher acts on that directory as it finds it — it
removes a `processId` whose fingerprint differs, ending the daemon it names — and a link would
point it at another build directory's daemon, past the ownership and idleness checks, which this
directory keys. That catches a link already planted; one made after the check — by the bootstrap
script, or by build code running in the daemon, neither of which the build lock excludes — is not
caught, and no check before the command closes that. What bounds it is the profile: the launcher
writes only where the command may write, so the daemon it can end that way is one whose
`out/mill-daemon` lies under the command's writable roots — this project, its run-on-host caches,
the broker's `tmp/` — that is, this launch's for another build directory, another launch's on
this project, or yours; and the one-port rule keeps the client from attaching to it.
`MILL_OUTPUT_DIR` and `MILL_BSP_OUTPUT_DIR` are never forwarded, since every check looks under
`out/`. Mill's classpath memo there validates the paths it
names before use, and a memo from an unconfined run, naming paths the profile denies, fails that
validation and is re-resolved through the proxy.

A daemon of yours for the build directory — from a terminal, outside any launch — is ended
before the broker's starts, as your sbt server is shut down, and the channel log says so: found in
the process table by its command line and its working directory under `out/mill-daemon`, never
through `processId`, and ended by TERM then KILL behind its pid and start time, once idle — no
established connection on its port, observed through `lsof`, and the proof repeated immediately
before the signal. A daemon busy past two minutes is a refusal naming it. Between the observation
and the signal a terminal `./mill` can still connect, and its command then dies with the daemon;
no observation closes that window. A daemon another launch owns — its broker's session holds
`daemon-mill-<hash>` — is refused, never signalled, as its sbt server is. The reverse holds too:
while the launch's daemon lives, your own `./mill` with matching settings attaches to it and runs
your build under the profile and the launch's proxy, and one with different settings ends it, as
Mill does on a fingerprint mismatch, after which the broker ends yours once idle and starts its
own again. A daemon whose registered leader was killed on its own — the spawn, not the broker — is
no group the scavenger can prove and nothing a portfile attributes; it exits on Mill's idle
timeout.

### Maven

The project's own wrapper script, `<PROJECT>/mvnw`; a `mvn` installed globally is not used. Run
`./mvnw --version` once in a host terminal, and again whenever `distributionUrl` in
`.mvn/wrapper/maven-wrapper.properties` changes: that run downloads Maven into
`~/.m2/wrapper/dists`, and the command is granted that one Maven read-only — not the whole `dists`
directory, which holds every Maven the user ever ran a wrapper for. If the wrapper has not
downloaded it yet, the command is refused, and the refusal says what to run.

Only the `only-script` wrapper type is served, the default that `mvn wrapper:wrapper` generates;
a project with any other wrapper type is refused, and the refusal names the command that
converts it. The wrapper recognizes the type from the script's `hash_string` function, reading
the script and never running it. The other types run a jar that computes the distribution
directory from more inputs — `distributionBase`, `distributionPath`, a relative URL, the JVM's
`user.home` — which this launcher deliberately does not reproduce: a derivation that reproduced
some of them would grant a stale copy where the script selects another.

The command runs `bin/mvn --batch-mode` from that directory, not `mvnw`, which looks for Maven under
a home directory it computes itself. The wrapper computes the directory exactly as the script does
(`RunOnHostPrereqs.mvnDistributionDir`), from the script's inputs: `distributionUrl`, rewritten by
`MVNW_REPOURL` when the launcher's environment sets that mirror override, hashed as a string and
with `-bin` dropped from the directory name, under `$MAVEN_USER_HOME/wrapper/dists`, or
`~/.m2/wrapper/dists` when `MAVEN_USER_HOME` is unset. An mvnd distribution is refused: mvnd is a
daemon.

Maven runs once and exits: there is no daemon and no server, and Surefire's forked test JVMs talk
to it over pipes by default, so `mvn test` works under the network rule as it is. Maven's
resolver ignores the JVM proxy properties unless `aether.connector.http.useSystemProperties` is
set, and then warns at every download that it is using them. That property belongs to
resolver 1.9, which Maven 3.9 ships. Both properties are measured on Maven 3.9.16, the latest
release, by building `src/probe/mvn-fixture` through a proxy inside the container; the gate's mvn
rows measure them under the profile. Maven 4 is still a release candidate; it is provisioned the
same way and is unmeasured. The user's `~/.m2/settings.xml` and `toolchains.xml` are denied, and
Maven treats them as absent, so a mirror or credential there never reaches a confined command.
`.mvn/maven.config`, `jvm.config` and `extensions.xml` are project files the agent already
controls, like `sbt 'set …'`.

## The command's lifetime and environment

`RunOnHostSession.scala` tracks one wrapper invocation, which it calls a command session. Its
directory is published by rename so it is never seen half-made; a lock marks the wrapper as live,
and records identify its child processes. Cleanup moves the directory out of the active set before
ending those processes and any leaderless sbt server its portfile identifies. The broker holds a
session of the same kind for the launch's lifetime: its records name the launch's runtimes —
`proxy-<program>-<hash>`, `server-sbt-<hash>` and `daemon-mill-<hash>`, the hash the build
directory's — a `build-<hash>` file names the directory those serve, and its `tmp/` is where the
sbt server binds its sockets and where the server and the daemon keep their temporary files.
Each command the broker dispatches holds a build lock — one per program and build directory,
under `build-lock/` — for the command's life, and the broker's own
work on the runtime before a command runs under it, so two launches on one project queue behind
each other's commands; the waiting one says so on its stderr. The wrapper root is
`/private/tmp/ko-agent-<uid>`, short on purpose: sbt's boot socket path must fit a UNIX-domain
socket's `sun_path` (`RunOnHostPrereqs.SessionTmpMaxLength`), and the broker's `tmp/` is under the
same budget.

The command's environment is the contract, not its command line: a closed set the wrapper supplies
(`RunOnHostSandbox.commandEnvironment`), never the launcher's own; SECURITY.md, "Run on host", has
why. The gate's `command_env` supplies the same set, minus the proxy settings, since its rows run
without a proxy. What the wrapper supplies:

| Environment Variable | Value |
|---|---|
| `JAVA_HOME` | the canonical path of the host's `$JAVA_HOME` |
| `JAVA_TOOL_OPTIONS` | the `java -D` properties below, the one form a forked JVM inherits |
| `PATH` | `$JAVA_HOME/bin:/usr/bin:/bin:/usr/sbin:/sbin` |
| `TMPDIR` | `<command directory>/tmp`; under `mill` the broker's `tmp/` |
| `XDG_RUNTIME_DIR`, `SBT_GLOBAL_SERVER_DIR` | the broker's `tmp/`, or the command's under Maven |
| `COURSIER_CACHE` | `<run-on-host cache>/coursier/v1` |
| `USER`, `LOGNAME` | the account's name, the JVM's `user.name` |
| `HTTPS_PROXY`, `HTTP_PROXY` and their lowercase | `http://127.0.0.1:<port>`, the command's proxy |
| `NO_PROXY` and its lowercase | `localhost,127.0.0.1` |
| `MILL_FINAL_DOWNLOAD_FOLDER` | the launcher's, else `<cache home>/mill/download` |
| `MILL_VERSION` | under `mill`, the JVM launcher of the pinned version, `<v>-jvm` |
| a name `--env` gave | the value `--env` gave, unless a row above sets that name |
| `HOME`, `LANG`, `LC_ALL` | the launcher's, when set and `--env` gave none |

The `java -D` properties:

| Java Property | Value |
|---|---|
| `java.io.tmpdir`, `java.util.prefs.userRoot` | `$TMPDIR` |
| `https.proxyHost`, `http.proxyHost` | `127.0.0.1` |
| `https.proxyPort`, `http.proxyPort` | `<port>` |
| `java.net.preferIPv4Stack` | `true`: the loopback rule does not cover a v4-mapped IPv6 connect |
| `sbt.global.base` | `<run-on-host cache>/sbt-global` |
| `sbt.ivy.home` | `<run-on-host cache>/ivy-home` |
| `maven.repo.local` | `<run-on-host cache>/m2/repository` |
| `aether.connector.http.useSystemProperties` | `true`, else Maven's resolver ignores the proxy |

`<command directory>` is this invocation's directory under the wrapper root above — the broker's
sbt server, and every `mill` process, have the broker's `tmp/` for every row naming one — `<cache
home>` is
`${XDG_CACHE_HOME:-$HOME/.cache}` from the launcher's environment, and `<run-on-host cache>` the
project's own run-on-host cache root, `<cache home>/ko-agent-sandbox/cache/<projectId>` ("The
run-on-host cache" below). One environment serves every program. sbt's global base and Ivy home and
Maven's local repository are set for every command; a command of another program reads none of them,
and the wrapper neither creates nor grants them for it. The mill download folder, the one holding
the granted executable, is set for the other programs the same way, and they ignore it.

Why the rows are what they are. The host's `TMPDIR` names a directory the command is not granted,
so the command's replaces it for forked shell programs, as `java.io.tmpdir` does for JVMs. Under
`mill` that directory is the broker's `tmp/`, for two reasons
(`RunOnHostSandbox.temporaryDirectories`): a JVM the daemon forks — a `run`, a test — inherits the
daemon's profile, which grants the broker's `tmp/` and not the command's, yet gets the command's
environment (`RunModule.scala`, `ctx.env`); and with one directory the starter's environment and
every client's are one map, so an option file Mill interpolates from the environment
(`MillProcessLauncher.loadMillConfig`) yields the same value in both, and a client never meets a
fingerprint mismatch of the wrapper's own making. `HOME` is
passed because the programs' scripts derive paths from it, and nothing under it is granted. `--env`
is the same forward the sandbox gets, with the same refusal of `KO_AGENT_SANDBOX_*`; it replaces a
pass-through, and a name the wrapper sets keeps the wrapper's value: a forwarded
`JAVA_TOOL_OPTIONS` or `HTTPS_PROXY` does not replace the command's own. `MILL_VERSION` and
`DEFAULT_MILL_VERSION` are never the forwarded values, because the wrapper granted the launcher of
the version the build directory pins, and `MILL_VERSION` names that launcher; `MILL_OUTPUT_DIR`
and `MILL_BSP_OUTPUT_DIR` are not either, because the daemon's rendezvous is looked for under
`out/` ("`mill`"). Among what is not
supplied: `TERM`, `SBT_OPTS`, `JAVA_OPTS`, the other `COURSIER_*` variables, `SBT_CREDENTIALS`,
`ALL_PROXY`, `FTP_PROXY`, the launcher's own
`HTTPS_PROXY`, and whatever secret the launching shell exported. A command's own processes see this
set plus what the programs' shell scripts create on the way — `PWD`, `SHLVL`, `_`; a variable does
not come back merely because the launching shell exported it.

## The channel and the command

`sandbox-run-on-host <program> [args…]` is a named command, a sibling of `sandbox-apt-get`, rather
than a shim shadowing `sbt` on `PATH`: where each command ran is then visible in the transcript
the user reads. It cannot inherit `sandbox-apt-get`'s discoverability — `apt-get install` *fails*
in the sandbox and teaches the agent to look for the prefixed name, while `sbt test` in the
container *succeeds*, slower, and nothing prompts a reconsideration. So the "What this session may
do" section states the instruction, and only where it can be true: the launcher knows the platform,
so a macOS session launched without the option gets one discovery line, and Linux and Windows
sessions hear nothing about a command they can never have. That makes the host command a norm
rather than an enforcement: an agent that ignores the instruction gets a slower build, not a
refusal — a deliberate difference from the egress rule, where the proxy actually refuses.

The transport, its framing and its teardown are `RunOnHostChannel.scala`'s header and the shim's
own comments. One command runs at a time, serial by design rather than as a shortcut: a queued sbt
request attaches to the server the running one leaves, a queued `mill` request to the daemon, and
the runtime's selection, start and retirement never overlap a command; the per-transaction FIFOs
leave a concurrent broker open as later work if a program ever makes it worth having. Before
starting a server the broker checks who holds the build directory's portfile: the *user's own*
server — from a terminal, outside any launch — is shut down by protocol at the socket the broker
derives itself; a server *another launch* still owns — its broker's session names the directory —
is a refusal, never signalled, since ending it across launches needs a coordination this version
leaves to `TODO.md`; a live socket under this launch's own directory that no record proves is a
refusal naming it. Before starting a daemon it checks the process table the same way ("`mill`"):
the user's own daemon is ended by proof once idle, another launch's is refused.

Ending it is the only resolution available, because the portfile is not merely a rendezvous: its
one-server-per-build-directory exclusivity is also the lock over `target/`. A second rendezvous
on the same tree — a shadow base directory, a relocated portfile — would put two unsynchronized
compilers in one content-addressed store, which is why container and host commands coexist on the
source and never on the outputs. Nor can an invocation opt out: sbt's build directory is always
its working directory, and sbt 2 has no one-shot mode ("sbt", above), so every invocation either
attaches to the portfile's server or contends for it; the upstream request that would add one is
in `sbt-issues.md`. Mill's `out/mill-daemon` lock is the same exclusivity over `out/`.

The broker's cancel carries no reason: the shim's descriptor closes the same way whether the agent
changed its mind or gave up on a command that sat silent. Before removing that command's directory,
the wrapper appends the command's logs to the channel's log, the file the launch printed as
`host command log` (`RunOnHostSandbox.appendSessionLogs`): the tail of the proxy audit log, under
Maven, and of the stderr file a thin client leaves under `tmp/` when it forked a server of its
own, the client's answer to a socket it cannot reach. The wrapper runs unconfined and the
command wrote that directory, so the read comes after the rename and the ending of the
command's groups, refuses a link at any component, and takes the
tail by position rather than by the file's size. A command that completed leaves nothing there:
its output reached the agent. The broker's session ends the same way, at the launch's end or on
TERM: its proxies' audit logs and its servers' stderr files are appended before its directory is
removed. The broker starts each sbt server with stdout to `/dev/null` and stderr appended to
`server-sbt-<hash>.log` in its session directory — not under `tmp/`, which the server could
replace with a link or a FIFO before the broker opens the file for the next server — and waits
for the portfile with a bound on progress:
a server that has published none while neither that file nor the proxy log grew for two minutes
(`RunOnHostSandbox.ServerStartSilenceMillis`) is ended, and the command is refused with the
file's tail — sbt's own client waits with no bound at all. A server that exits on its own leaves
its stderr in the file, for the channel log to keep.

## Where the broker deviates from the stock tool

Everything else the broker does is what the stock tool does, or confinement the stock tool never
had. These deviate, and each names why:

- **Persistent processes end with the launch — confinement.** Stock sbt and Mill leave their
  server or daemon running when the terminal that started it closes. The broker's run against
  the launch's proxy and its forwarded environment, both of which die with the launch, so the
  server and the daemon must too; the next start scavenges what a killed broker left, and a later
  launch adopts none whose owner is gone.
- **The wait for the portfile has a bound — operability, not confinement.** sbt's thin client
  waits for a starting server with no deadline, which an interactive user can Ctrl-C; the agent
  cannot, so an unbounded wait would be an unrecoverable command. The broker fails the start when
  neither the server's stderr nor the proxy log grows and no portfile appears for two minutes
  (`RunOnHostSandbox.ServerStartSilenceMillis`), with the stderr tail; a mill starter that
  neither ends nor writes for as long, the proxy log still, fails the same way. A deliberate
  deviation not required by confinement, kept because the caller is not interactive
  (`doc/TODO.md`, "a bound on a silent host command", tracks the remaining generic bound).
- **A foreign server or daemon is never attached to — confinement.** Stock sbt attaches to
  whatever server holds the portfile, and stock Mill to whatever daemon holds `out/mill-daemon`
  unless its fingerprint differs; a client attached to one the broker did not start would run
  the build under that process's environment and confinement, or none. The user's own terminal
  server the broker shuts down by protocol at the socket it derives, and the user's own daemon it
  ends by proof once idle ("`mill`"); a server or daemon another launch still owns it refuses,
  never signalling another broker's process (`TODO.md`, "Cross-launch server takeover").
- **Mill runs through its JVM launcher — confinement.** The stock bootstrap runs the native image
  for a bare pin; the wrapper sets `MILL_VERSION` to `<v>-jvm` so that the client takes the
  environment's `preferIPv4Stack` and connects under the one-port rule, which the image cannot
  ("`mill`"). The user provisions that launcher, and a `-native` pin is refused with the reason.
- **A Mill configuration edit replaces the daemon before the command — operability.** Stock
  Mill's client ends a daemon whose fingerprint differs and starts a replacement itself; from a
  confined client that replacement cannot bind, so the command would fail once. The broker reads
  the same inputs before each command and replaces the daemon first
  (`RunOnHostPrereqs.millDaemonConfig`).

Two behaviors are the stock tool's, though they could be read as the broker's. It keeps one warm
server or daemon per build directory, not one per program, so visiting another directory leaves
the first warm. And a cancel does what the tool does, and the two tools differ: an sbt client's
disconnect cancels only the running exec (`CommandExchange.removeChannel`, `force = false`) and
leaves the warm server, so an interruption-ignoring test lingers in it exactly as it would in a
terminal and the next command reuses the server; a Mill client's disconnect mid-command makes the
daemon shut itself down (`Server.scala`), so the next `mill` command starts one. The broker
retires neither and revives neither on its own.

## The Seatbelt profile

Apple does not document SBPL for third-party use: `sandbox-exec` compiles it through private entry
points, and the published write-ups are reverse-engineered and date from 2011. Two sources are
authoritative here — measurement (`src/probe/seatbelt-semantics.sh`,
`src/probe/run-on-host-profile-iterate.sh`), and Apple's own shipped profiles under
`/System/Library/Sandbox/Profiles/`, current and written against the implementation; `system.sb` is
the one worth reading first. `SeatbeltProfile.scala` encodes the findings, the two that decide
everything in its header. The rest, measured:

- What the guard depends on (`src/probe/seatbelt-semantics.sh`): the accessed path is resolved —
  a write through `link -> .git` is denied, as is the case alias described in the filesystem rules;
  rules are evaluated at access time, so a `.git` created *during* the command is covered; one regex
  spans every depth; and `file-write*` already refuses a hardlink to a denied target, so the
  explicit link clause is redundancy — kept, because the membership of a wildcard operation family
  is Apple's to change.
- `/dev/tty` is the terminal, whatever stdin is: closing the child's stdin does not detach its
  controlling terminal. The profile grants `/dev/null` and the random devices only.
- An invalid profile fails exactly like a denial: `sandbox-exec` aborts the child either way, the
  difference only on its own stderr — a search that discards it looks for grants that were never
  missing.
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
the ancestor chain never arise. It is also why that design cannot serve here: a command under it
reads the whole filesystem, and "everything else user-owned inaccessible" is the property this
feature exists to provide. Deny-by-default makes the profile harder to construct and is what
provides that property, so the difficulty is no reason to change the design — worth stating because
the blacklist form is the obvious simplification when the whitelist will not start. One setting is
taken from Bazel: `(debug deny)`, which makes denials visible without the unified log's redaction,
and which `src/probe/run-on-host-profile-iterate.sh` puts at the top of every profile it iterates.

**Runtime authority** — the loader, libc, the CA bundle and the rest a toolchain needs from the
system — is discovered by running a real build under a deny-default profile and reading the denials,
never by listing what a host happens to have, and never as a way to reach a user path. The measured
set is one file, a resource of the launcher's own artifact
(`src/main/resources/agentsandbox/runtime-authority.txt`): what the production wrapper grants is
what the probes measured. The gate and host commands use that same set of grants.
`src/probe/run-on-host-profile-iterate.sh` is how candidate entries are measured. Do not
pre-authorize broad paths (`/System/**`, `/usr/**`, `/opt/homebrew/**`); add the narrowest rule
testing justifies.

## The command's egress proxy

The proxy is a process from the same codebase as the container's. Under sbt and `mill` it is the
broker's: started in the broker's session when the first command of that program arrives from a
build directory — the request's working directory, whose `project/target/active.json` or `out/`
the build owns — with the program's rule file as read then, and kept for the commands that
follow from that directory; a request from another build directory gets a proxy of its own, and
both stay. A proxy that is gone is replaced, with its server or daemon, before the next command.
Maven's is the command's, started by the wrapper in the command's session and ended with it, as
every program's is under the gate's test entry.

The sandbox session's proxy runs on a network created `--internal`, inside the podman machine.
There is no host route to it, and making one would either publish the sandbox session's full
`--egress` ruleset — `api.anthropic.com` and forges included — to any host process, or relay
each connection through `podman exec`, adding the VM round trip to exactly the path the command was
moved out of the VM to avoid. A JVM proxy client speaks TCP, so a loopback listener is unavoidable
either way; what is worth controlling is the rules behind it: an attacker who reaches a proxy
allowing one artifact repository can reach only that repository through it.

The proxy lives as long as the session holding its record: the broker's until it retires the
proxy or ends with the launch, the command's until the wrapper cleans up that invocation — past
the client process, since the server the client forks resolves artifacts and lives until the
wrapper ends it.

A rule-file edit takes effect when a proxy is next created, never by restarting a running one,
which holds the lines it was created with: at the first command from a build directory the
launch has not visited, after `sandbox-run-on-host <program> shutdown` followed by a proxy's own
end, or at the next launch, as the session's own rule file takes effect at the next launch. Until
then a host removed from the file stays reachable from that proxy, and one added is not.

It ships in the launcher's own artifact: the proxy sources share the launcher's Scala version,
`dist` compiles them in beside their `/defaults` resources, and the broker or the wrapper starts
the proxy by re-invoking its own executable — `java -jar` or the native binary — under a private
action. It binds an ephemeral port on `127.0.0.1` (the codebase's wildcard `:3128` default is safe
only in the container's own network namespace), and its starter reads the port from the same
ready line the container launcher gates on.

It runs unconfined, unlike the container's hardened copy of the same codebase — the one process
that parses hostile bytes from the command being sandboxed, holding the uid whose files the profile
exists to deny. This is an accepted risk: a JVM parse bug is an exception, the listener is
loopback-only, and `HostileInputTest` covers the parser; a Seatbelt profile of the proxy's own is
low-value defense in depth, deferred in `TODO.md`.

It runs without inspection material: no-material mode enforces the destination host and port at
CONNECT time and tunnels opaquely, so the command needs no extra trust material and the read-only
JDK's own trust store suffices. If inspection is ever wanted, point the JVM at a wrapper-owned
store with `-Djavax.net.ssl.trustStore` rather than touching the JDK.

It reads `HTTPS_PROXY` as the container's copy does (`egress-proxy.md`, "Through an upstream
proxy"): on a host behind an upstream proxy the command's artifact fetches leave through it, and a
loopback helper on the host is reachable from here, unlike from the container.

## Configuration

A command that resolves beyond Maven Central names its repositories in a project file, in the
directory that already holds reviewed boundary configuration:

```text
.ko-agent-sandbox/host-command/<program>/egress/rule
```

One file per program, so a repository that uses more than one grants each only what it
resolves. The grammar is its own, narrower than the proxy's: `allow https://<host>/ read` lines
and comments,
nothing else — no other grant, no path, no provider, no deny — refused at validation rather than
passed through. The full grammar would let one `allow model-provider` line expand into endpoints
that are no artifact repository, and a `tunnel` word means nothing to a proxy running without
inspection. The wrapper hands the proxy `deny defaults`, Maven Central, then the file's lines
(`RunOnHostPrereqs.egressRuleText`), so the container's catalog contributes nothing.

The file inherits the directory's properties: the workspace filter freezes it at any depth, the
launcher reads it on the host, and it is reviewed in a pull request like any other file.
`host-command/` accepts only recognized configuration entries, as does `.ko-agent-sandbox` — a stray
entry fails the launch instead of being ignored (`SandboxProject.boundaryDirError`,
`RunOnHostSandbox.hostCommandStray`).

No program needs a GitHub release CDN: the one download that would, the `mill` executable, is
provisioned on the host instead.

Derived paths come from Coursier conventions and environment APIs; advanced overrides
(`cache-root`, `jvm-root`, `install-root`) are not added until needed.

## The run-on-host cache

Agent-invoked commands get their own run-on-host cache root, per project:
`${XDG_CACHE_HOME:-$HOME/.cache}/ko-agent-sandbox/cache/<projectId>/`. It holds Coursier's
`v1`, sbt's global base and Ivy home, and Maven's local repository under one directory, so
`--reset-run-on-host` is a single removal, `--reset` takes it with the project's other state, and
a further cache kind can join without moving anything. It is discovered exactly as the launcher's
state root is, so the two answer alike on one machine; a relative override is refused because it
would resolve against the repository being sandboxed, and a root inside the project is refused
outright.

Why not the user's cache: `SECURITY.md` "Cache poisoning stops at the project" has the security
argument. The cost is a cold cache on a project's first agent command, warm from the second onward.

Why not the launcher state root: the state root is kind-first (`tls/<id>`, `log/<id>`, …) and the
proxy's audit log must not be stored beside the CA key. On the host the command runs as the user's
own uid, which owns that key, so file permissions protect nothing and only the profile denies
access; a separate root makes that denial structural — no path the command is ever granted has a
sensitive ancestor or sibling. `XDG_CACHE_HOME` is also where a reconstructible cache
belongs.

The command reaches its Coursier cache through one variable: the wrapper sets `COURSIER_CACHE` to
the `v1` directory, which the sbt script, sbt's own resolution and Coursier all honour. sbt's own
two caches and Maven's local repository travel as the `java -D` properties above, which sbt's
launcher and Maven's CLI read.

## Sources

- Coursier managed JVMs and platform JVM-cache locations: https://get-coursier.io/docs/cli-java
- Coursier artifact cache and platform `v1` locations:
  https://get-coursier.io/upcoming/features-cache/
- Coursier installation/application directory behavior:
  https://get-coursier.io/docs/cli-installation
- `mill` project-local bootstrap scripts: https://mill-build.org/mill/cli/installation-ide.html
- Mill 1.1.9's daemon and launcher — the port-0 bind, `socketPort` and `processId`, the shutdown
  on a client's disconnect mid-command, the idle timeout, the fingerprint the launcher restarts on
  and its ten-second connect retry:
  https://github.com/com-lihaoyi/mill/blob/1.1.9/libs/daemon/server/src/mill/server/Server.scala,
  https://github.com/com-lihaoyi/mill/blob/1.1.9/libs/daemon/client/src/mill/client/ServerLauncher.scala,
  https://github.com/com-lihaoyi/mill/blob/1.1.9/runner/launcher/src/mill/launcher/MillProcessLauncher.scala,
  https://github.com/com-lihaoyi/mill/blob/1.1.9/runner/launcher/src/mill/launcher/MillServerLauncher.scala
- sbt server — domain-socket and TCP modes, the port file, discovery and the token:
  https://www.scala-sbt.org/1.x/docs/sbt-server.html
- Maven Wrapper — the wrapper types and `MAVEN_USER_HOME`: https://maven.apache.org/wrapper/
- Surefire fork communication — process pipes by default, TCP by configuration:
  https://maven.apache.org/surefire/maven-surefire-plugin/examples/process-communication.html
- Maven Resolver configuration — `useSystemProperties`: https://maven.apache.org/resolver/configuration.html
