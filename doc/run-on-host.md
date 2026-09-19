# Run on Host — sbt, `mill`, Gradle and Maven commands outside the container

`--run-on-host=<programs>` (macOS only, off by default) relays this project's sbt, `mill`, Gradle
and Maven commands to the host, where each runs under a Seatbelt profile of its own.

    ┌─ macOS host ───────────────────────────────────────────────────────────────────────┐
    │                                                                                    │
    │  ┌─ sandbox container (inside the podman machine) ────────────────────────────┐    │
    │  │ agent → ko-sandbox-run-on-host sbt / mill / gradle / mvn                   │    │
    │  └────────────────────────────────────────────────────────────────────────────┘    │
    │                       │  command       ↑  stdout, stderr, and exit status          │
    │                       ↓                │                                           │
    │  ┌─ host broker (one per sandbox session) ────────────────────────────────────┐    │
    │  │ runs one command at a time; starts and stops the processes it owns         │    │
    │  └────────────────────────────────────────────────────────────────────────────┘    │
    │                       │                                     │                      │
    │                       ↓                                     ↓                      │
    │  ┌─ build processes: Seatbelt profiles ─────┐    ┌─ proxy: Seatbelt profile ────┐  │
    │  │ sbt client → sbt server                  │    │ listens on 127.0.0.1         │  │
    │  │ mill or gradle client → its daemon       │    │ allows only listed hosts     │  │
    │  │ Maven starts a JVM for each command      │    │ on port 443                  │  │
    │  │ dependency downloads                     ├───→│                              │  │
    │  │ writes project files, except             │    │ cannot read project or cache │  │
    │  │ .git and .ko-agent-sandbox;              │    │ logs allowed/denied requests │  │
    │  │ also writes its caches and temp files    │    │                              │  │
    │  └──────────────────────────────────────────┘    └──────────────────────────────┘  │
    │                                                             │                      │
    │  One sbt server or mill daemon per build directory, and     │                      │
    │  Gradle's own daemons, reused across this session's         │                      │
    │  commands. sbt/mill/gradle proxies also stay running        │                      │
    │  between commands; each Maven command starts and stops      │                      │
    │  its own proxy.                                             │                      │
    │                                                           HTTPS                    │
    └─────────────────────────────────────────────────────────────┼──────────────────────┘
                                                                  ↓
                                                 Maven Central + configured repositories

This document is the reference for how host commands work and what they require; the table names
the code that enforces each part:

| concern | binding site |
| --- | --- |
| the security properties and their costs | `SECURITY.md` "Run on host" |
| option syntax and write access | [README.md](../README.md#reference), `--run-on-host` |
| the channel protocol and its teardown | `RunOnHostChannel.scala`, `ko-sandbox-run-on-host` |
| the command lifecycle: publish, lock, scavenge | `RunOnHostSession.scala` |
| prerequisite validation and the paths it settles | `RunOnHostPrereqs.scala` |
| provisioning offered at the start prompt | `RunOnHostProvisioning.scala` |
| the wrapper and the broker's runtimes: proxy, sbt server, environment | `RunOnHostSandbox.scala` |
| the broker's mill daemon: its start, its port, a daemon of yours | `RunOnHostMillDaemons.scala` |
| the generated profile | `SeatbeltProfile.scala` |
| the exit criteria, measured | `src/probe/run-on-host-profile-gate.sh` |

The full gate (`all`) reports **230 PASS, 0 FAIL, 0 SKIP** on macOS 26.4.1 arm64 with
Temurin 25.0.4, sbt 2.0.8, Mill 1.1.9, Gradle 9.7.1 and Maven 3.9.16 (2026-09-15).

The measurement behind the feature: an `sbt test` of this project takes about 2 GB inside the podman
machine, whose total is fixed when the machine is created and shared with every other session on it
— and whose resident memory, once grown to hold a build, macOS never gets back. On the host the same
build runs on memory reclaimed when it exits, at host speed.

A host command's recurring cost is startup. When a start is paid, per program:

- sbt and `mill`: the launch keeps one server or daemon warm across its commands from one build
  directory ("Where a host command deviates from the stock program"), so a start is paid by the
  first command from a directory, after `ko-sandbox-run-on-host <program> shutdown`, and after the
  program's own idle exit — sbt's seven days (`TODO.md`, "an idle bound for the sbt server"),
  Mill's thirty minutes.
  - An sbt server keeps the `sbt.version` and options it started with until `shutdown`, as in a
    terminal, and a cancelled sbt command leaves its server warm.
  - A `mill` start is also paid after a cancel, which ends the daemon as stock Mill does, and
    after an edit to what Mill restarts the daemon on — its version pin, `mill-jvm-opts`,
    `mill-repositories`, or anything in `build.mill.yaml`, the header Mill reads them from — and
    costs the daemon's own start: the starter is ended as soon as the daemon listens ("`mill`").
- Gradle: the daemon is Gradle's own ("Gradle"): a start is paid by the first command and after
  Gradle's idle exit, three hours, and a client attaches to a compatible daemon in the launch's
  own registry.
- Maven runs once, so every invocation starts a JVM and loads the build, while the on-disk state
  stays warm: the caches, and the incremental-compile outputs under `target/`.

Out of scope, deliberately:

- arbitrary build programs (`scalafmt` and ad-hoc `scala` stay in the container);
- arbitrary globally installed JVMs — Homebrew, SDKMAN and asdf JVMs included;
- direct Internet access from the command;
- any automatic expansion of permissions when a command fails, and any fallback to the container;
- implicit access to `~/.m2`, `~/.ivy2`, user git credentials, SSH credentials or unrelated
  home-directory state;
- stdin — `sbt console`, `sbt shell` and `sbtn`'s interactive modes.

The container keeps its toolchain: host commands are the fast path, not a replacement, and a
session without `--run-on-host` builds in the container.

## Why only macOS

The feature exists only where the guard's access-time name denies hold. What the alternatives
look like, for whoever revisits them:

On Linux, bubblewrap does the *positive* half better than Seatbelt:

- it starts with nothing mounted and builds up, so the grant table holds by construction;
- `--unshare-all` removes the network namespace outright, making proxy bypass impossible rather
  than merely denied.

But the denies do not hold:

- its mounts are established once at start, so covering `.git` at any depth means binding over
  each one found then — and a `.git` created during the command has no mount over it;
- Landlock is no better: its ruleset is fixed at creation.

With nothing to gain — a container command already runs at host speed on host memory, reclaimed
on exit — the feature would also cost Linux the one limit the container has that a host command
does not: the cgroup memory limit that kills a runaway build inside the sandbox instead of taking
the machine down.

On Windows, AppContainer expresses the grants perfectly well:

- a per-user profile with a derived SID;
- inheritable ACEs on the granted roots;
- private profile storage;
- network confinement by capability plus a WFP rule restricted to the proxy endpoint.

What it cannot express is the denies. ACL inheritance has no name patterns, so "deny `.git` at any
depth" can only be an enumerated set of deny ACEs placed by a launch-time scan, and a `.git`
created *during* the command inherits the project's allow — a race where the deny must hold at
every access. A Windows backend needs an equivalent of access-time path filters — a filesystem
minifilter, or a design that does not put the guard in ACLs at all — before it is worth
reconsidering.

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
- **Seatbelt matches the path after resolving it, and on a case-insensitive volume the lowercase
  pattern matches the other spellings measured** (`src/probe/seatbelt-semantics.sh`, macOS 26.4.1).
  - An access through `.GIT` to an existing `.git` resolves to the lowercase path and is denied
    (E5).
  - A `.GIT` the command creates where no `.git` exists is denied too (E9).
  - The volume resolves `.ko-agent-sandbox` spelled with U+212A KELVIN SIGN or U+017F LONG S to
    the name (E11), and the lowercase pattern denies creating either (E12). The gate creates
    those spellings, `.GIT` and `.KO-AGENT-SANDBOX` under each command profile, and each is
    denied.
  - A spelling the volume resolves to the name and no row creates is unmeasured.
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

The command's only egress is its proxy (below):

- Seatbelt permits connections to the proxy's port — at every address of this host, the proxy
  listening on the loopback one — and nothing else, with UNIX-domain sockets only inside the
  command's temporary directory and, for an sbt client, the broker's, where its server listens.
- A port grant reaches this host's other services the same way, so no other port is granted.
- No listener but the mill daemon's and Gradle's: a test suite that binds one — the proxy's
  wire-relay tests do — gets `EPERM` on the host under sbt and Maven and runs in the container,
  while under `mill` and `gradle` it runs on the host, since the daemon's listener grant covers
  every port at every address of this host and everything the daemon forks inherits it
  (`SECURITY.md` "Run on host" states that cost).

Per program (`SeatbeltProfile.Network` is the typed input the dispatch shows):

| process | network |
|---|---|
| sbt server | the proxy's port; UNIX sockets bound and connected under the broker's `tmp/` |
| sbt client | the same under the command's `tmp/`, plus connects under the broker's `tmp/` |
| `mill` daemon | the proxy's port; listeners, any port, any address of this host (below) |
| `mill` client | the proxy's port, and the daemon's one port |
| `gradle`, client and daemon | the proxy's port; listeners and connects on any port of this host |
| Maven | the proxy's port; UNIX sockets under the command's `tmp/` |

Gradle's row is both grants, where `mill`'s client has one port: its daemon, its workers and its
file-lock socket (`DefaultFileLockCommunicator`, UDP) each bind port 0 and connect to each
other's, no supported Gradle setting fixes any of them, and confining them would mean patching
Gradle or instrumenting its JVMs, which this launcher does not take on.

Seven measured rules (`src/probe/loopback-rule.sh`, `src/probe/jvm-proxy-rule.sh`,
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
- The `localhost` class is this host's addresses, not loopback: under that rule a bind to the
  wildcard or to the LAN address is admitted, and the socket answers at the LAN address, TCP and
  UDP; `(remote ip "localhost:*")` connects there too. No spelling names loopback alone, since
  the compiler takes no other host (G1, G4–G10).
- A client's `(remote ip "localhost:<port>")` reaches that port at every address of this host
  (G11), is denied the neighboring one (L3, L4, M3), and only the JVM launcher connects under it:
  the native image's connect is
  dual-stack, for the reason above, and stays denied with the property on its command line (M2).
  That is why the wrapper runs the JVM launcher ("`mill`").
- The sbt client's `(remote unix-socket (subpath <broker tmp>))` must reach the boot socket and
  the server socket exactly: a client whose connect is denied does not fail but deletes the
  portfile and forks a server under its own profile
  (`NetworkClient.connectOrStartServerAndConnect`), which dies at its boot-socket bind, and the
  client takes that exit for a server still booting and waits without bound (S6).

The proxy settings handed to the JVM are convenience, not the boundary: Seatbelt is what prevents
bypass via direct sockets, and the gate's bypass rows measure it.

Every command's proxy allows one host on its own: the program's Maven Central
(`RunOnHostPrereqs.centralHost`).

- For sbt and `mill`, which resolve through Coursier, that is `repo1.maven.org`; for Gradle,
  whose `mavenCentral()` names the alias, and Maven, whose super POM does, it is
  `repo.maven.apache.org`. Each program resolves against its own host and never against the
  other's.
- A Gradle build that applies a plugin by id resolves it from `plugins.gradle.org`, which
  redirects artifact downloads to `plugins-artifacts.gradle.org`; a rule file naming the plugin
  portal names both.
- `repo.scala-sbt.org` is deliberately absent: it hosts the Ivy-style plugin repository and is not
  part of sbt's bootstrap — an uncached sbt version named in `project/build.properties` resolves
  from Maven Central.

A command that needs more adds it explicitly ("Configuration", below); nothing is inferred or
silently permitted.

## Refusals

Missing prerequisites and denied accesses fail clearly, nothing expands authority, and nothing
falls back: a host command that cannot run is reported to the user, never re-run in the
container — the same rule the egress refusal follows.

- Every prerequisite refusal before the command starts is a `RunOnHostPrereqs.Refusal` value, one
  case per category, so the wrapper, the channel and the launch word the same refusal for their
  own readers without the tests matching on any wording.
- A runtime the broker cannot prepare — a proxy, server or daemon that fails to start, the
  launcher's executable gone — is refused with its reason as text from the code that met it
  (`BrokerRuntimes.prepare`).
- A denial while the command runs falls under no refusal category:
  - a filesystem denial reaches the command's own stderr as the OS error;
  - a network denial is the proxy's audit line, which the wrapper reads and reports per host after
    the command ("Command requested network access to: …") — from the log's length at the
    command's start, so a shared proxy's earlier denials are not this command's. It never adds the
    host itself.

## Program prerequisites

The rule that explains all four programs: **the user provisions the executable; the sandbox fetches
only artifacts.**

- sbt's comes from `cs install sbt`, and everything else it needs is a jar the JDK reads, fetched
  into the writable run-on-host cache through the proxy.
- `mill`'s executable *is* the fetched artifact — so it is provisioned, not fetched, and a version
  bump is an explicit host update rather than an automatic update performed by the build
  definition.
- Gradle's and Maven's are the distributions the projects' wrappers unpacked on the host.

`RunOnHostPrereqs.scala` validates these prerequisites before a command starts; a violation is a
refusal naming what to fix, and `src/probe/host-layout.sh` shows what a host actually has.

The launch checks `mill`'s, Gradle's and Maven's before its start prompt
(`RunOnHostProvisioning.scala`), so a launcher or distribution not yet provisioned is met by you at
the launch, not by the agent at the first command. sbt has nothing to check: its executable is
the one `cs install sbt` produced, whatever the project pins.

- Every build directory of the selected programs is found — each directory holding a `mill`
  bootstrap or a Gradle wrapper's properties file, the files the wrapper keys a build directory
  on ("`mill`", "Gradle"), anywhere under the project except inside `.git`, `.ko-agent-sandbox`
  or a symlink, and for Maven the project alone, holding `mvnw` ("Maven") — and its executable
  resolved as its first command would resolve it; each refusal is printed in the command's
  wording. `gradlew` is only what the run below executes: a properties file without it is
  reported, with nothing to run.
- For the refusals a host run fixes, a launcher or distribution not yet provisioned, the prompt
  shows that run — `MILL_VERSION=<v>-jvm ./mill version`, `./gradlew --version` or
  `./mvnw --version` in the build directory — and runs it on an explicit `y`, unconfined and in
  the launcher's environment: the run the refusal asks you for, made one answer (`SECURITY.md`,
  "Run on host"). Each build directory is judged when its turn comes, so one run that provisions
  a version two directories share is asked once, and the check repeats after the run, so a
  script that exits zero without provisioning is reported at once.
- A launch that holds nothing — no terminal, or `KO_AGENT_SANDBOX_SESSION_START=immediate` —
  prints the refusals and runs nothing.
- What the launch cannot see — a pin changed during the session, a build directory created
  later — the first command refuses, naming the same run; a relaunch prompts for it.

### The JVM

Only Coursier-managed JVMs.

- `JAVA_HOME` is the only source, and must resolve to one canonical JDK home under the user's
  Coursier cache root.
- `java` on `PATH` is `/usr/bin/java`, a macOS stub that resolves through `JAVA_HOME` or
  `/usr/libexec/java_home`, reporting the right JVM while being the wrong path.
- Rejected: the stub, `/Library/Java/JavaVirtualMachines`, Homebrew and SDKMAN JVMs, and a
  `JAVA_HOME` resolving outside the Coursier cache.

A current Coursier unpacks a JDK into its archive cache, so the home is a URL-derived path under
`arc/` with a percent-encoded `+` in it.

- The grant is that resolved home: granting the `arc` root instead would hand the command every
  archive Coursier ever extracted.
- The JDK is read-only to the command, so sharing the user's copy exposes no write path, and
  duplicating one per project would cost hundreds of megabytes for nothing.

### sbt

`cs install sbt`, and no arbitrary `sbt` from `PATH`.

- The wrapper verifies the executable belongs to the Coursier application-install directory — on
  macOS `~/Library/Application Support/Coursier/bin`, whose space makes correct shell quoting
  necessary.
- That `sbt` is two files: the 1.2 KB script on `PATH` execs a second `sbt` inside an unpacked
  distribution in the archive cache, and the profile grants the distribution's *home* — the
  distribution's `sbt` reads `sbt-launch.jar` and `conf/` relative to itself.
- The home is read from the script's text (`SeatbeltProfile.sbtDistribution`); running the script
  to ask would execute what the profile exists to contain, on the host, unconfined.

sbt 2 is client/server by construction — there is no one-shot mode — so the broker starts the
server, and each command's client then attaches to it. The server runs:

- inside the server profile, with the build directory as its working directory;
- with the broker's own `tmp/` as its temporary and socket directory;
- with the command line sbt's thin client uses when it starts one, given the request's launcher
  flags as that client forwards them, less those naming a program ("Where a host command deviates
  from the stock program" lists both);
- with its output in a file in the broker's session directory ("The channel and the command").

The broker rather than the client, which forks a server itself when the portfile names none: a
server so forked inherits three things a server outliving the command must not:

- the client's profile, whose temporary-directory grant names a directory removed with the
  command;
- its environment, whose `java.io.tmpdir` and `XDG_RUNTIME_DIR` name that directory;
- its process group, which a cancel ends.

The server's state follows `-Dsbt.global.base` into the project's run-on-host cache.

- The base must persist across commands: sbt 2 leaves `target/` outputs as symlinks into its
  content-addressed store, so removing that base when the command ends would leave the build's
  own outputs dangling.
- The same fact cuts the other way at entry: a tree the user's unconfined sbt built links into a
  store the profile denies, so the broker sweeps `target/` symlinks that resolve outside the
  granted roots before it starts an sbt server, after any foreign server for the directory is
  shut down — its build finished — so a sweep never runs during the user's own build.
- `~/.sbt/boot` is not granted and has no consumer — with the global base redirected, sbt boots
  from the run-on-host cache, warm across sessions. `~/.sbt/1.0`, `~/.sbt/2.0` and `~/.m2` are not
  granted either.
- sbt 2 also registers each server under that base's `cache/proc` and, when a client disconnects,
  asks the servers registered there to exit if idle (`CommandExchange.notifyOtherServers`), so the
  redirect keeps your servers and the launch's out of each other's registry.

The Ivy home follows `-Dsbt.ivy.home` into the run-on-host cache the same way, and `~/.ivy2` is not
granted. sbt uses that home for three things, read from the sources of sbt 1.13.0 and 2.0.8:

- resolving a dependency between the projects of one build goes through Ivy
  (`projectDescriptors`), and Ivy takes the lock file `<ivy home>/.sbt.ivy.lock` first;
- `<ivy home>/local` is the `local` resolver, which every resolution reads and `publishLocal`
  writes;
- `updateSbtClassifiers` keeps its excludes file there.

Without the redirect, an sbt 1.12.13 `packageBin` of a build with a `dependsOn` edge dies under
the profile while canonicalizing the denied `~/.ivy2` for that lock. This repository's own build
has no such edge, so the gate's sbt rows never reach that path; `src/probe/ivy-fixture` is such a
build, on sbt 1.

sbt 2 releases after 2.0.8 have no Ivy library (sbt/sbt#9615, merged 2026-08-24) and take no
lock, so the fixture is not duplicated for sbt 2; it retires when sbt 1 does. Those releases
still take `local` and the excludes file from `sbt.ivy.home`, so the redirect and its grant stay
after the lock is gone. Retire them only when a released sbt stops deriving those two paths, and
check that by reading `Defaults.scala` again, not by a gate run.

- The wrapper passes `--jvm-client`: sbt 2 defaults to `sbtn`, which under the profile prints
  that it is starting the server and returns with no build run — a gate row keeps measuring it,
  and if it starts passing, the wrapper can reconsider requiring `--jvm-client`.
- The distribution's `sbt` resolves `java` from `PATH`, so the environment puts the granted JDK's
  `bin` first: the broker starts the server by running the script, and `-java-home` reaches the
  client alone.

### `mill`

A project-local bootstrap script, the build directory's own `mill`; no globally installed `mill`.

- The bootstrap is run with `MILL_VERSION` naming the JVM launcher of the pinned version,
  `<v>-jvm` (`RunOnHostPrereqs.millLauncherVersion`).
- That launcher must already be provisioned — `MILL_VERSION=<v>-jvm ./mill version` once, on the
  host, whenever the pinned version changes — because `mill` 1.x fetches its launchers as
  executables, and fetching one would put an executable the sandbox chose into a directory the
  user's own `./mill` runs from, outside any sandbox. The launch offers that run at its start
  prompt ("Program prerequisites").
- What is granted is that one file, `<download folder>/<v>`, never the download folder around it,
  which holds every launcher the user ever ran.
- A version the user never provisioned the JVM launcher for is a refusal naming the command to
  run.

The launcher is the JVM one, not the native image the bootstrap runs for a bare pin, because the
image takes no `_JAVA_OPTIONS`:

- the environment's `preferIPv4Stack` never reaches it;
- its connect to the daemon is the dual-stack one the "localhost" class denies ("Network");
- the property on its command line changes nothing (measured,
  `src/probe/run-on-host-broker-session.sh` M2).

A `<v>-native` pin asks for that image by name and is refused with the reason.

The wrapper resolves the version the way the bootstrap does, from the build directory —
`.mill-version`, `.config/mill-version`, `build.mill.yaml`, the build script's `//|` header, then
the script's own default (`RunOnHostPrereqs.millVersion`) — so a nested build directory with a
bootstrap of its own is another build.

- The script's `MILL_VERSION` and `DEFAULT_MILL_VERSION` environment overrides are not read: the
  command's environment carries the wrapper's own `MILL_VERSION` and no other, so the script and
  the wrapper resolve alike.
- Reading the version is a read; asking the script by running it would execute agent-authored
  shell on the host.
- `mill-jvm-version: system` is required in the build directory — its default provisions a JVM
  through Coursier's index into a writable, executable place, which is what the JVM rule
  refuses — and is what makes the daemon's JVM the granted JDK, the first `java` on the command's
  `PATH`.

Mill is client/daemon by construction: the launcher starts a daemon that binds a port of the
kernel's choosing on the loopback address, writes it to `out/mill-daemon/socketPort`, and connects
(`Server.scala`, `ServerLauncher.scala`, Mill 1.1.9). The broker starts the daemon itself, before
the first `mill` command of a build directory, and every command from that directory attaches to
it (`RunOnHostMillDaemons.scala`, `RunOnHostSandbox.BrokerRuntimes`):

1. The **starter**: the build directory's `./mill version`, as a registered spawn in the broker's
   session (`records/daemon-mill-<hash>`) under the daemon profile — the profile with listeners
   granted and no outbound but the proxy — with the closed environment and the broker's `tmp/`
   as its temporary directory.
   - The launcher starts the daemon, the daemon binds its port and writes `socketPort`, and the
     launcher's own connect is denied: the daemon inherits the starter's profile, and the only
     outbound that would admit the connect is outbound to every port of this host
     (`SeatbeltProfile.Network.MillDaemon` has the reasoning).
   - Once `lsof` shows the daemon listening on the port `socketPort` names, the broker ends the
     launcher — TERM to its pid alone, the daemon's parent in the group, behind its pid and start
     time.
   - Without that proof the launcher retries for ten seconds and exits nonzero, and a launcher
     the TERM does not end reaches that bound too; either way the daemon stays in the spawn's
     group (measured, M1 for the exit, M8 for the TERM: the daemon is spawned with
     `destroyOnExit = false`).
   - The group is three processes — the leader, the launcher JVM as its child, since
     `sandbox-exec`, the bootstrap and the assembly's shell prefix each `exec`, and the daemon as
     the launcher's — and after the TERM the daemon is reparented while the leader stays as the
     group's proof (M8).
   - The starter's output goes to `daemon-mill-<hash>.log` in the session directory, the finding
     when a start fails; a starter that neither ends nor writes anything for two minutes, the
     proxy log not growing either, is a failed start.
2. The **daemon** is the member of that group whose command line names
   `mill.daemon.MillDaemonMain`, proved from then on by its pid and start time.
   - `socketPort` is read as a candidate — an integer in port range, nothing more — and granted
     only after `lsof` shows that pid listening on it.
   - The file is the build's to write and authorizes nothing, and a candidate the daemon does not
     listen on refuses the start.
3. Each command's **client** runs `./mill <args>` from the build directory under the client
   profile, which admits outbound to that one port and the proxy, with the broker's `tmp/` as
   its temporary directory ("The command's lifetime and environment" has why). The launcher
   reads `socketPort` and connects; a port planted there is one the profile denies, so the
   command fails and the daemon is untouched.

The daemon gets each command's environment through the protocol (`DaemonRpc.Initialize`), so the
closed environment reaches the build per command; the daemon JVM's own options, the proxy
settings included, are the starter's, fixed at its start.

The broker replaces the daemon under the same proxy before the next command — its starter's spawn
staying as the group's provable leader and ended with the group first — when:

- what Mill's launcher restarts the daemon on has changed: the launcher version, the resolved
  JVM, `mill-jvm-opts` and `mill-repositories`, each from the source Mill reads it from, the
  build file's header taken whole (`RunOnHostPrereqs.millDaemonConfig`). The broker compares
  them before each command, the launcher assembled afresh since a changed pin grants another;
  the stock client meeting the mismatch would end the daemon and start a replacement from its own
  profile, which cannot bind, and the command would fail;
- the daemon is gone on its own: Mill's idle exit, thirty minutes after its last client;
  `ko-sandbox-run-on-host mill shutdown`; or a client's disconnect mid-command, on which the daemon
  shuts itself down (measured, M5), where an sbt server survives the same disconnect.

Mill's idle exit counts from the last client's disconnect, and a daemon no client has connected
to yet never expires (`Server.ConnectionTracker`): a starter's daemon whose first command never
comes lives until the launch ends.

`out/mill-daemon` is Mill's: the broker neither clears nor writes it, beyond the classpath memo
below, and reads only the port candidate and that memo.

- The `launcherLock` there names the ended starter until the next client: it is a pid lock
  (`PidLock`, `pid:start`) the launcher deletes on its own exit, which the TERM skips, and a
  client's launcher finds its pid dead and replaces it.
- A command is refused while `out`, `out/mill-daemon` or an entry directly in it is a symlink or
  a file with a second name (`RunOnHostMillDaemons.rendezvousIsOwn`), because the launcher acts
  on that directory as it finds it — it removes a `processId` whose fingerprint differs, ending
  the daemon it names — and a link would point it at another build directory's daemon, past the
  ownership and idleness checks, which this directory keys.
- That catches a link already planted; one made after the check — by the bootstrap script, or by
  build code running in the daemon, neither of which the build lock excludes — is not caught, and
  no check before the command closes that. What bounds it is the profile: the launcher writes
  only where the command may write, so the daemon it can end that way is one whose
  `out/mill-daemon` lies under the command's writable roots — this project, its run-on-host
  caches, the broker's `tmp/` — that is, this launch's for another build directory, another
  launch's on this project, or yours; and the one-port rule keeps the client from attaching to
  it.
- `MILL_OUTPUT_DIR` and `MILL_BSP_OUTPUT_DIR` are never forwarded, since every check looks under
  `out/`.
- Mill's classpath memo there, `out/mill-daemon/cache/mill-daemon-classpath`, is deleted before a
  start when it names a path outside the cache the profile grants
  (`RunOnHostMillDaemons.discardForeignMemo`, the read and the delete under the daemon profile, so
  a link planted under `out/` after the rendezvous check sends neither past what the build could
  write). Mill keeps a memo while every path it names exists, and Seatbelt answers an existence
  test for a path it denies reading — measured, `Files.exists` true and the open denied — so a
  memo from an unconfined run, or from this directory served as another project's build
  directory, would start a daemon on jars it cannot open, and the daemon dies before it listens.
  Deleted, the memo is resolved afresh through the proxy into the granted cache.

A daemon of yours for the build directory — from a terminal, outside any launch — is ended
before the broker's starts, as your sbt server is shut down, and the channel log says so.

- It is found in the process table by its command line and its working directory under
  `out/mill-daemon`, never through `processId`, and ended by TERM then KILL behind its pid and
  start time, once idle — no established connection on its port, observed through `lsof`, and the
  proof repeated immediately before the signal.
- A daemon busy past two minutes is a refusal naming it.
- Between the observation and the signal a terminal `./mill` can still connect, and its command
  then dies with the daemon; no observation closes that window.

A daemon another launch owns — its broker's session holds `daemon-mill-<hash>` — is attached to,
or ended by that record and replaced, as its sbt server is ("The channel and the command").

- Attaching needs the daemon alive under the build directory's present configuration, so after
  an edit, or the daemon's own exit, the command ends what the record still names — the starter's
  group — and starts its own.
- The reverse holds too: while the launch's daemon lives, your own `./mill` with matching
  settings attaches to it and runs your build under the profile and the launch's proxy, and one
  with different settings ends it, as Mill does on a fingerprint mismatch, after which the broker
  ends yours once idle and starts its own again.
- A daemon whose registered leader was killed on its own — the spawn, not the broker — is no
  group the scavenger can prove and nothing a portfile attributes; it exits on Mill's idle
  timeout.

### Gradle

The build directory's own wrapper properties, `gradle/wrapper/gradle-wrapper.properties` there,
as `./gradlew` run there would read them; a `gradle` installed globally is not used.

- A nested build directory with a wrapper of its own is another build, as under `mill`.
- Run `./gradlew --version` once on the host, and again whenever `distributionUrl` changes: that
  run downloads Gradle into `~/.gradle/wrapper/dists`. The launch offers it at its start prompt
  ("Program prerequisites").
- The command is granted that one Gradle read-only — not the whole `dists` directory, which holds
  every Gradle the user ever ran a wrapper for.
- If the wrapper has not downloaded it yet, the command is refused, and the refusal says what to
  run.

The command runs the distribution's `bin/gradle` in the working directory, not `gradlew`, which
would download. The wrapper computes the directory exactly as Gradle's wrapper does
(`RunOnHostPrereqs.gradleDistributionDir`, from Gradle 9.7.1's `PathAssembler`):

1. `distributionUrl` read as `java.util.Properties` reads the file, a value without a scheme
   resolved as a file against the properties file's directory;
1. the URL's file name without its extension, then the URL's MD5 as a base-36 number, under
   `$GRADLE_USER_HOME/wrapper/dists`, or `~/.gradle/wrapper/dists` when `GRADLE_USER_HOME` is
   unset in the launcher's environment;
1. the home is the one directory inside.

`distributionBase` and `distributionPath` must be the wrapper's defaults, and the build
directory's `gradle.properties` must not set `systemProp.gradle.user.home`: each moves the
distribution to a place the project chooses, and the executable is the user's to provision.

- The command's own `GRADLE_USER_HOME` is under the run-on-host cache ("The run-on-host cache"),
  so Gradle's caches are the project's own.
- The daemon registry is the launch's own, not the home's: `org.gradle.daemon.registry.base` on
  the command line names a directory under the broker's `tmp/`, which every Gradle process of the
  launch is granted and which ends with the launch (`RunOnHostSandbox.gradleCommand`).
  `gradle --stop` stops every daemon in a registry, whatever its JVM (`DaemonStopClient`), so a
  registry under the per-project home would let one launch's `--stop` end another launch's builds
  on the project.
- Attaching is the launch's own either way: the client's `java.io.tmpdir`, the broker's `tmp/`,
  is among the immutable properties Gradle's daemon compatibility compares
  (`InitialPropertiesConverter`, `DaemonCompatibilitySpec`), so a daemon started under another
  launch is never compatible.
- Your own daemons under `~/.gradle` are in neither registry.

The daemon is Gradle's: the first command's client starts it under the command's profile, and
later commands attach to it through Gradle's own matching, inside the profile.

- A client disconnected mid-build cancels the build, and a daemon still busy ten seconds later
  stops itself (`DaemonStateCoordinator`, `WatchForDisconnection`).
- The daemon detaches itself into a group of its own (`DaemonMain`, `setsid`), where its workers
  and test executors are forked, so ending the client's group leaves it alive; the broker ends it
  by proof (`RunOnHostGradleDaemons.scala`).
- After each command, and once more at the launch's end, the broker records every daemon started
  with the launch's environment by pid and start time, `records/daemon-gradle-<pid>`, forgetting
  the record of one gone; the launch's end signals the group behind each record as it does every
  recorded group.

The proof is the daemon's initial environment, which the client starts it with
(`DefaultProcessForkOptions`), read with `ps -E`: its `_JAVA_OPTIONS` names the broker's `tmp/`
as `java.io.tmpdir`, a value no process outside this launch's commands was started with.

- No path proves it: the build writes across `tmp/` and the project, and a file a daemon of yours
  holds open, renamed into the registry under any name — the daemon log's included — is reported
  by the kernel at that name.
- `ps -E` reads the strings from the daemon's own memory (`sysctl_procargsx`), so build code in
  the daemon can rewrite them and hide the daemon from its own launch, and nothing else.
- A daemon no observation reached — one started under a broker that died during the command, or
  one so hidden — is confined and holds nothing of the launch, and exits on Gradle's idle timeout,
  three hours, once idle; one hung in its build never becomes idle, and nothing bounds it.
- Its registry directory goes with the broker's `tmp/`, so no later launch finds it.

Three properties on the command line close the toolchain inventory to the launch's JDK —
`org.gradle.java.installations.auto-detect=false`, `auto-download=false` and `paths=<JDK>` —
where a `-D` outranks every `gradle.properties`, so a project asking for another toolchain fails
naming it rather than meeting a denial.

Gradle 9.7.1 is the release measured, the one `src/probe/gradle-fixture` pins; older lines are
out, since 8.14 does not run on the JDK 25 the launcher requires, and Gradle itself refuses a JDK
it cannot run on.

The gate's Gradle rows (`src/probe/run-on-host-profile-gate.sh`) measure:

- the distribution's grant;
- the build through the proxy;
- the daemon's reuse and record;
- the records following a cancel;
- the launch's end taking the daemon and the JVM its build forked — on TERM during the first
  build, the daemon still cancelling;
- a daemon of yours in a registry of your own left alone;
- the toolchain refusal;
- the native libraries mapped from the user home;
- the unrelated service of this host reached under `gradle` alone.

### Maven

The project's own wrapper script, `<PROJECT>/mvnw`; a `mvn` installed globally is not used.

- Run `./mvnw --version` once on the host, and again whenever `distributionUrl` in
  `.mvn/wrapper/maven-wrapper.properties` changes: that run downloads Maven into
  `~/.m2/wrapper/dists`. The launch offers it at its start prompt ("Program prerequisites").
- The command is granted that one Maven read-only — not the whole `dists` directory, which holds
  every Maven the user ever ran a wrapper for.
- If the wrapper has not downloaded it yet, the command is refused, and the refusal says what to
  run.

Only the `only-script` wrapper type is served, the default that `mvn wrapper:wrapper` generates.

- A project with any other wrapper type is refused, and the refusal names the command that
  converts it.
- The wrapper recognizes the type from the script's `hash_string` function, reading the script
  and never running it.
- The other types run a jar that computes the distribution directory from more inputs —
  `distributionBase`, `distributionPath`, a relative URL, the JVM's `user.home` — which this
  launcher deliberately does not reproduce: a derivation that reproduced some of them would grant
  a stale copy where the script selects another.

The command runs `bin/mvn --batch-mode` from that directory, not `mvnw`, which looks for Maven under
a home directory it computes itself. The wrapper computes the directory exactly as the script does
(`RunOnHostPrereqs.mvnDistributionDir`), from the script's inputs:

1. `distributionUrl`, rewritten by `MVNW_REPOURL` when the launcher's environment sets that
   mirror override;
1. hashed as a string, with `-bin` dropped from the directory name;
1. under `$MAVEN_USER_HOME/wrapper/dists`, or `~/.m2/wrapper/dists` when `MAVEN_USER_HOME` is
   unset.

An mvnd distribution is refused: mvnd is a daemon.

- Maven runs once and exits: there is no daemon and no server, and Surefire's forked test JVMs
  talk to it over pipes by default, so `mvn test` works under the network rule as it is.
- Maven's resolver ignores the JVM proxy properties unless
  `aether.connector.http.useSystemProperties` is set, and then warns at every download that it is
  using them. That property belongs to resolver 1.9, which Maven 3.9 ships.
- Both properties are measured on Maven 3.9.16, the latest release, by building
  `src/probe/mvn-fixture` through a proxy inside the container; the gate's mvn rows measure them
  under the profile. Maven 4 is still a release candidate; it is provisioned the same way and is
  unmeasured.
- The user's `~/.m2/settings.xml` and `toolchains.xml` are denied, and Maven treats them as
  absent, so a mirror or credential there never reaches a confined command.
- `.mvn/maven.config`, `jvm.config` and `extensions.xml` are project files the agent already
  controls, like `sbt 'set …'`.

## The command's lifetime and environment

`RunOnHostSession.scala` tracks one wrapper invocation, which it calls a command session.

- Its directory is published by rename so it is never seen half-made.
- A lock marks the wrapper as live, and records identify its child processes.
- Cleanup moves the directory out of the active set before ending those processes and any
  leaderless sbt server its portfile identifies.

The broker holds a session of the same kind for the launch's lifetime:

- its records name the launch's runtimes — `proxy-<program>-<hash>`, `server-sbt-<hash>` and
  `daemon-mill-<hash>`, the hash the build directory's, and `daemon-gradle-<pid>` for each Gradle
  daemon of the launch's one registry;
- a `build-<hash>` file names the directory those of a hash serve;
- a `runtime-<program>-<hash>` file describes each sbt server and mill daemon for another launch
  to attach to (`RunOnHostRuntimeDescriptor.scala`);
- a `run` file names the launch's sandbox container, by which `--stats` joins the broker to its
  session;
- its `tmp/` is where the sbt server binds its sockets and where the servers and daemons keep
  their temporary files.

Two locks:

- Each command the broker dispatches holds a build lock — one per program and build directory,
  under `build-lock/` — for the command's life, and the broker's own work on the runtime before a
  command runs under it, so two launches on one project queue behind each other's commands; the
  waiting one says so on its stderr.
- Ending a runtime's recorded group — the broker replacing or retiring its own, its teardown, the
  scavenger, another launch taking the runtime over — runs under a retirement lock,
  `retire-lock/<program>-<hash>`, held across the leader's proof and the signal alone, so no two
  processes signal one group; one not free within twenty seconds keeps the record for the next
  collection (`RunOnHostSession.retirementLockFile` has the rules).

The wrapper root is `/private/tmp/ko-agent-<uid>`, short on purpose: sbt's boot socket path must
fit a UNIX-domain socket's `sun_path` (`RunOnHostPrereqs.SessionTmpMaxLength`), and the broker's
`tmp/` is under the same budget.

The command's environment is the contract, not its command line: a closed set the wrapper supplies
(`RunOnHostSandbox.commandEnvironment`), never the launcher's own; SECURITY.md, "Run on host", has
why. The gate follows this closed environment contract; `command_env` documents its deviations
for rows without a proxy and with one temporary directory for clients and servers.
What the wrapper supplies:

| Environment Variable | Value |
|---|---|
| `JAVA_HOME` | the canonical path of the host's `$JAVA_HOME` |
| `_JAVA_OPTIONS` | the `java -D` properties below, inherited by forked JVMs |
| `PATH` | `$JAVA_HOME/bin:/usr/bin:/bin:/usr/sbin:/sbin` |
| `TMPDIR` | `<command directory>/tmp`; under `mill` and `gradle` the broker's `tmp/` |
| `XDG_RUNTIME_DIR`, `SBT_GLOBAL_SERVER_DIR` | the broker's `tmp/`, or the command's under Maven |
| `COURSIER_CACHE` | `<run-on-host cache>/coursier/v1` |
| `GRADLE_USER_HOME` | `<run-on-host cache>/gradle-user-home` |
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
| `sbt.ipcsocket.tmpdir` | `$TMPDIR`, for the client's native library extraction |
| `https.proxyHost`, `http.proxyHost` | `127.0.0.1` |
| `https.proxyPort`, `http.proxyPort` | `<port>` |
| `java.net.preferIPv4Stack` | `true`: the loopback rule does not cover a v4-mapped IPv6 connect |
| `sbt.global.base` | `<run-on-host cache>/sbt-global` |
| `sbt.ivy.home` | `<run-on-host cache>/ivy-home` |
| `maven.repo.local` | `<run-on-host cache>/m2/repository` |
| `aether.connector.http.useSystemProperties` | `true`, else Maven's resolver ignores the proxy |

- HotSpot reads `_JAVA_OPTIONS` directly, though OpenJDK calls it an undocumented feature. HotSpot
  applies these properties after command-line options.
- Path values use `RunOnHostSandbox.jvmProperty`'s HotSpot quoting syntax. This variable reaches
  HotSpot without the sbt script copying quoted values into argv;
  [sbt-issues.md](sbt-issues.md#quoted-jvm-options-are-copied-into-arguments) has the
  reproducer.
- Both sbt clients and servers also receive `sbt.global.base` as one argument for the script's
  preloaded-cache lookup (`RunOnHostSandbox.sbtCommand`).

The placeholders:

- `<command directory>` is this invocation's directory under the wrapper root above — the
  broker's sbt server, and every `mill` and `gradle` process, have the broker's `tmp/` for every
  row naming one;
- `<cache home>` is `${XDG_CACHE_HOME:-$HOME/.cache}` from the launcher's environment;
- `<run-on-host cache>` is the project's own run-on-host cache root,
  `<cache home>/ko-agent-sandbox/run-on-host/<projectId>` ("The run-on-host cache" below).

One environment serves every program:

- sbt's global base and Ivy home, Gradle's user home and Maven's local repository are set for
  every command; a command of another program reads none of them, and the wrapper neither creates
  nor grants them for it;
- the mill download folder, the one holding the granted executable, is set for the other programs
  the same way, and they ignore it;
- Gradle's toolchain properties are its command line's ("Gradle").

Why the rows are what they are:

- The host's `TMPDIR` names a directory the command is not granted, so the command's replaces it
  for forked shell programs, as `java.io.tmpdir` does for JVMs.
- Under `mill` that directory is the broker's `tmp/`, for two reasons
  (`RunOnHostSandbox.temporaryDirectories`); under `gradle` for the first, the daemon serving
  later commands with the profile and environment it was started with:
  - a JVM the daemon forks — a `run`, a test — inherits the daemon's profile, which grants the
    broker's `tmp/` and not the command's, yet gets the command's environment
    (`RunModule.scala`, `ctx.env`);
  - with one directory the starter's environment and every client's are one map, so an option
    file Mill interpolates from the environment (`MillProcessLauncher.loadMillConfig`) yields the
    same value in both, and a client never meets a fingerprint mismatch of the wrapper's own
    making.
- `HOME` is passed because the programs' scripts derive paths from it, and nothing under it is
  granted.
- `--env` is the same forward the sandbox gets, with the same refusal of `KO_AGENT_SANDBOX_*`; it
  replaces a pass-through, but cannot replace any setting supplied by the wrapper.
  `_JAVA_OPTIONS` and `HTTPS_PROXY` keep the wrapper's values; the launcher's own `HTTPS_PROXY` is
  replaced as above.
- `MILL_VERSION` and `DEFAULT_MILL_VERSION` are never the forwarded values, because the wrapper
  granted the launcher of the version the build directory pins, and `MILL_VERSION` names that
  launcher; `MILL_OUTPUT_DIR` and `MILL_BSP_OUTPUT_DIR` are not either, because the daemon's
  rendezvous is looked for under `out/` ("`mill`").
- Without explicit forwarding, `TERM`, `SBT_OPTS`, `JAVA_OPTS`, `JAVA_TOOL_OPTIONS`,
  `JDK_JAVA_OPTIONS`, the other `COURSIER_*` variables, `SBT_CREDENTIALS`, `ALL_PROXY`,
  `FTP_PROXY` and exported secrets are absent.
- A command's own processes see this set plus what the programs' shell scripts create on the
  way — `PWD`, `SHLVL`, `_`; a variable does not come back merely because the launching shell
  exported it.

## The channel and the command

`ko-sandbox-run-on-host <program> [args…]` is a named command, a sibling of `ko-sandbox-apt-get`,
rather than a shim shadowing `sbt` on `PATH`: where each command ran is then visible in the
transcript the user reads. It cannot inherit `ko-sandbox-apt-get`'s discoverability —
`apt-get install` *fails* in the sandbox and teaches the agent to look for the prefixed name, while
`sbt test` in the container *succeeds*, slower, and nothing prompts a reconsideration.

So the "What this session may do" section states the instruction, and only where it can be true:
the launcher knows the platform, so a macOS session launched without the option gets one discovery
line, and Linux and Windows sessions hear nothing about a command they can never have. That makes
the host command a norm rather than an enforcement: an agent that ignores the instruction gets a
slower build, not a refusal — a deliberate difference from the egress rule, where the proxy
actually refuses.

The transport, its framing and its teardown are `RunOnHostChannel.scala`'s header and the shim's
own comments. One command runs at a time, serial by design rather than as a shortcut:

- a queued sbt request attaches to the server the running one leaves, a queued `mill` request to
  the daemon;
- the runtime's selection, start and retirement never overlap a command;
- the per-transaction FIFOs leave a concurrent broker open as later work if a program ever makes
  it worth having.

Before starting a server the broker checks who holds the build directory's portfile:

- the *user's own* server — from a terminal, outside any launch — is shut down by protocol at the
  socket the broker derives itself;
- a server *another launch* still owns — its broker's session names the directory, and the
  recorded group is not proved gone — the command attaches to when the server this launch would
  start has the same confinement and environment, and otherwise ends by that record and replaces
  with its own (below);
- a live socket under this launch's own directory that no record proves is a refusal naming it.

Before starting a daemon it checks the process table the same way ("`mill`"): the user's own
daemon is ended by proof once idle, another launch's is attached to or taken over.

Attaching is decided per command from the owner's descriptor, `runtime-<program>-<hash>` in its
session directory (`RunOnHostRuntimeDescriptor.scala`). Two conditions:

- the fingerprint of the server's or daemon's confinement and environment — the profile's inputs
  and the closed environment, forwarded values included, so a launch forwarding a secret never
  serves one that does not, and the proxy's rule lines as read when that proxy was created, since
  a warm proxy keeps them — must equal the fingerprint of what this launch would start;
- the descriptor must name the owner's present records, whose processes live: for sbt the server
  behind the directory's portfile at the socket derived under the owner's `tmp/`, for `mill` the
  daemon by its start time under the build directory's present configuration.

The command then runs against the owner's session, proxy and daemon port, as the owner's own
commands do, and this launch records nothing of it. What the attaching launch gives up:

- a cancel is the program's own, since the server is not this launch's to retire — an
  interruption-ignoring sbt test runs on in the owner's server until the next command queues
  behind it, and a `mill` client's disconnect mid-command ends the shared daemon, as stock Mill
  does, so the owner's next command starts one;
- the owner's end takes the runtime with it, a build of this launch included, whose next command
  starts its own or attaches elsewhere;
- this launch's proxy audit lines land in the owner's proxy log.

An sbt request's own launcher flags — its `-D` properties and value flags — are not compared: the
warm server keeps the flags of the command that started it and every later command attaches
regardless, within a launch as across them (`RunOnHostRuntimeDescriptor.fingerprint`). Gradle's
daemons and Maven have nothing to attach to: the registry is the launch's own, and Maven runs
once.

A runtime the command cannot attach to is taken over. The reasons:

- the fingerprints differ;
- the owner is ending or died since the scavenge;
- its descriptor is missing or names other records;
- its server or daemon is gone, the portfile does not name its socket, or the daemon is not under
  the directory's present configuration.

The takeover: under the build lock the command holds, the broker ends the group the owner's record
names, under the retirement lock and by the same proof every ender uses, and starts its own server
or daemon under its own proxy, as a first command does.

- The owner's record stays the owner's, its proxy runs on, and its next command finds the group
  dead, replaces the runtime under that proxy, and decides the same way — attaching to this
  launch's, or taking it back — so two launches whose runtimes differ alternate restarts, and
  each restart loses the warm build the other left; the launcher's channel log names each
  takeover and the reason.
- Nothing is connected to and no portfile is read for the takeover: the record attributes the
  group, so neither a planted portfile nor a link under the owner's `tmp/` can send the signal to
  another directory's server.
- An owner tearing itself down holds the retirement lock through its own end of the group, so
  the command waits on the lock — twenty seconds at most — and then starts its own.
- The command is refused, naming the record, when the group is not proved ended: a member still
  listed after the KILL, a leaderless group, or the lock busy past its bound; retry once the
  group is gone, or use a different build directory.
- Your own `./mill` attached to the daemon taken over dies with it, as it does when its owner
  replaces it.

Ending it is the only resolution available, because the portfile is not merely a rendezvous: its
one-server-per-build-directory exclusivity is also the lock over `target/`. A second rendezvous
on the same tree — a shadow base directory, a relocated portfile — would put two unsynchronized
compilers in one content-addressed store, which is why container and host commands coexist on the
source and never on the outputs. Nor can an invocation opt out: sbt's build directory is always
its working directory, and sbt 2 has no one-shot mode ("sbt", above), so every invocation either
attaches to the portfile's server or contends for it; the upstream request that would add one is
in `sbt-issues.md`. Mill's `out/mill-daemon` lock is the same exclusivity over `out/`.

The broker's cancel carries no reason: the shim's descriptor closes the same way whether the agent
changed its mind or gave up on a command that sat silent.

Before removing that command's directory, the wrapper appends the command's logs to the channel's
log, the file the launch printed as `host command log` (`RunOnHostSandbox.appendSessionLogs`):

- the tail of the proxy audit log, under Maven, and of the stderr file a thin client leaves under
  `tmp/` when it forked a server of its own, the client's answer to a socket it cannot reach;
- the wrapper runs unconfined and the command wrote that directory, so the read comes after the
  rename and the ending of the command's groups, refuses a link at any component, and takes the
  tail by position rather than by the file's size;
- a command that completed leaves nothing there: its output reached the agent.

The broker's session ends the same way, at the launch's end or on TERM: its proxies' audit logs
and its servers' logs are appended before its directory is removed.

The broker starts each sbt server with stdout and stderr appended to `server-sbt-<hash>.log` in
its session directory — not under `tmp/`, which the server could replace with a link or a FIFO
before the broker opens the file for the next server — and waits for the portfile with a bound on
progress:

- a server that has published none while neither that file nor the proxy log grew for two minutes
  (`RunOnHostSandbox.ServerStartSilenceMillis`) is ended, and the command is refused with the
  file's tail — sbt's own client waits with no bound at all;
- a server that exits on its own leaves its output in the file, for the channel log to keep: sbt
  started where no build is asks on stdout whether to create one, and answers itself from the
  detached stdin.

## Where a host command deviates from the stock program

In everything else a host command behaves as the stock program run from a terminal. These
deviate, each with its why: confinement, the launch's ownership of what it starts, or operability,
where the caller is not interactive.

### Under every program

- **Persistent processes end with the launch — ownership.** Stock sbt, Mill and Gradle leave
  their server or daemon running when the terminal that started it closes, Gradle's for three
  idle hours. The broker's run against the launch's proxy and its forwarded environment, both of
  which die with the launch, so the server and the daemons must too; the next start scavenges
  what a killed broker left, and a later launch adopts none whose owner is gone.
- **A foreign server or daemon is never attached to — confinement.** Stock sbt attaches to
  whatever server holds the portfile, and stock Mill to whatever daemon holds `out/mill-daemon`
  unless its fingerprint differs; a client attached to one the broker did not start would run
  the build under that process's environment and confinement, or none.
  - The user's own terminal server the broker shuts down by protocol at the socket it derives,
    and the user's own daemon it ends by proof once idle ("`mill`").
  - A server or daemon another launch still owns it attaches to only when it would start one
    under the same confinement and environment, and otherwise ends by that launch's record, under
    the retirement lock, and replaces with its own ("The channel and the command").
- **The environment is a closed set — confinement.** The command sees the wrapper's set and not
  the launching shell's ("The command's lifetime and environment"): `HOME` passed and nothing
  under it granted, `preferIPv4Stack` set for the loopback rule ("Network"), no destination off
  this host but the proxy, and the project writable even under `--write=reject` (`SECURITY.md`,
  "Run on host").
- **The wait for a start has a bound — operability.** sbt's thin client waits for a starting
  server with no deadline, which an interactive user can Ctrl-C; the agent cannot, so an
  unbounded wait would be an unrecoverable command.
  - The broker fails the start when neither the server's log nor the proxy log grows and no
    portfile appears for two minutes (`RunOnHostSandbox.ServerStartSilenceMillis`), with the
    log's tail.
  - A mill starter that neither ends nor writes for as long, the proxy log still, fails the same
    way (`doc/TODO.md`, "a bound on a silent host command", tracks the remaining generic bound).

### Under sbt

- **The server is the broker's, not the client's — ownership.** The broker starts it, in its own
  directory for sockets and temporary files, and each command's client attaches; a server the
  client forked would inherit the command's profile, environment and group ("sbt").
- **The server receives the request's launcher flags as the thin client forwards them, less
  those naming a program — confinement.**
  - `-D` properties, the value flags and `--allow-empty` reach it.
  - `-J` does not, since the runner applies it to the client's own JVM, as the client itself
    forwards nothing of `-J`.
  - Dropped beyond the client: `-java-home`, `-sbt-jar`, `--sbt-script`, `--sbt-launch-jar` and
    `-Dsbt.script=`, each naming the JVM, the launcher jar or the runner script, which the
    profile's grants decide (`RunOnHostSandbox.serverCommand`).
- **`new` and `init` run through a server — the client model.** Stock sbt runs those two in the
  sbt process itself, in place, since a template is written where no build is, and every other
  command through its client; the broker has one path, a client to the server it starts, so
  `ko-sandbox-run-on-host sbt new` in an empty directory meets the runner's refusal of a directory
  with no build, and `--allow-empty` starts the server there as the stock client's flag would.
  Whether `new` then writes its template through that server the gate does not measure.
- **The JVM client, never `sbtn` — operability.** sbt 2 runs its native client by default, which
  under the profile prints that it is starting the server and returns with no build run; the
  wrapper passes `--jvm-client`, and a gate row keeps measuring `sbtn` ("sbt").
- **`target/` links into a denied store are swept before a server starts — confinement.** A tree
  the user's unconfined sbt built links into a store the profile denies ("sbt").
- **The global base and the Ivy home are the project's own — confinement.** Redirected into the
  run-on-host cache, where stock uses `~/.sbt` and `~/.ivy2` ("sbt", "The run-on-host cache").

### Under `mill`

- **The daemon is started by the broker's `./mill version`, not by the first client —
  ownership.** The starter's denied connect leaves the daemon in the broker's group, and the
  starter is ended once the daemon listens ("`mill`").
- **The JVM launcher, never the native image — confinement.** The stock bootstrap runs the
  native image for a bare pin; the wrapper sets `MILL_VERSION` to `<v>-jvm` so that the client
  takes the environment's `preferIPv4Stack` and connects under the one-port rule, which the
  image cannot ("`mill`"). The user provisions that launcher, and a `-native` pin is refused
  with the reason.
- **A configuration edit replaces the daemon before the command — operability.** Stock Mill's
  client ends a daemon whose fingerprint differs and starts a replacement itself; from a
  confined client that replacement cannot bind, so the command would fail once. The broker
  reads the same inputs before each command and replaces the daemon first
  (`RunOnHostPrereqs.millDaemonConfig`).
- **`mill-jvm-version: system` is required — confinement.** Stock Mill provisions a JVM through
  Coursier's index into a writable, executable place, which the JVM rule refuses ("`mill`").
- **A request's `MILL_VERSION`, `DEFAULT_MILL_VERSION`, `MILL_OUTPUT_DIR` and
  `MILL_BSP_OUTPUT_DIR` are not read — confinement.** The wrapper's `MILL_VERSION` names the
  granted launcher, and the daemon's rendezvous is looked for under `out/` ("The command's
  lifetime and environment").
- **A redirected `out/mill-daemon` is refused — confinement.** Mill's launcher would act on
  another build directory's daemon through it ("`mill`").
- **A classpath memo naming what the profile denies is deleted before a start — confinement.**
  Stock Mill keeps it, since the paths exist; under the profile the daemon could not open them
  ("`mill`").
- **Clients use the broker's temporary directory, not their own — confinement.** A JVM the
  daemon forks inherits the daemon's profile and gets the client's environment ("The command's
  lifetime and environment").

### Under Gradle

- **The daemon registry is the launch's, under the broker's `tmp/` — confinement.** Stock keeps
  it in the user home, where one launch's `gradle --stop` would end another launch's builds
  ("Gradle").
- **The distribution's `bin/gradle` runs, never `gradlew` — confinement.** The wrapper script
  downloads; a `distributionBase`, `distributionPath` or `systemProp.gradle.user.home` moving
  the distribution to a place the project chooses is refused ("Gradle").
- **The toolchain inventory is the launch's JDK alone — confinement.** Auto-detection and
  auto-provisioning are off on the command line, so a project asking for another toolchain
  fails naming it ("Gradle").
- **The user home is the project's own — confinement.** Under the run-on-host cache, where stock
  uses `~/.gradle` ("The run-on-host cache").

### Under Maven

- **The distribution's `bin/mvn` runs, never `mvnw` — confinement.** The wrapper script
  downloads ("Maven").
- **The local repository is the project's own, and the resolver is told to honor the proxy —
  confinement.** `maven.repo.local` under the run-on-host cache, where stock uses
  `~/.m2/repository`, and `aether.connector.http.useSystemProperties`, without which Maven's
  resolver ignores the proxy the profile leaves as the one route out ("The command's lifetime
  and environment").

Two behaviors are the stock program's, though they could be read as the broker's:

- It keeps one warm server or daemon per build directory, not one per program, so visiting
  another directory leaves the first warm.
- A cancel does what the program does, and the programs differ:
  - an sbt client's disconnect cancels only the running exec (`CommandExchange.removeChannel`,
    `force = false`) and leaves the warm server, so an interruption-ignoring test lingers in it
    exactly as it would in a terminal and the next command reuses the server;
  - a Mill client's disconnect mid-command makes the daemon shut itself down (`Server.scala`), so
    the next `mill` command starts one;
  - a Gradle client's disconnect cancels the build, and the daemon stops itself only if still
    busy ten seconds later (`DaemonStateCoordinator`), so the next `gradle` command attaches or
    starts one.

The broker retires none and revives none on its own.

## The Seatbelt profile

Apple does not document SBPL for third-party use: `sandbox-exec` compiles it through private entry
points, and the published write-ups are reverse-engineered and date from 2011. Two sources are
authoritative here:

- measurement (`src/probe/seatbelt-semantics.sh`, `src/probe/run-on-host-profile-iterate.sh`);
- Apple's own shipped profiles under `/System/Library/Sandbox/Profiles/`, current and written
  against the implementation; `system.sb` is the one worth reading first.

`SeatbeltProfile.scala` encodes the findings, the two that decide everything in its header. The
rest, measured:

- What the guard depends on (`src/probe/seatbelt-semantics.sh`): the accessed path is resolved —
  a write through `link -> .git` is denied, as are the folded spellings described in the filesystem
  rules; rules are evaluated at access time, so a `.git` created *during* the command is covered;
  one regex spans every depth; and `file-write*` already refuses a hardlink to a denied target, so
  the explicit link clause is redundancy — kept, because the membership of a wildcard operation
  family is Apple's to change.
- `/dev/tty` is the terminal, whatever stdin is: closing the child's stdin does not detach its
  controlling terminal. The profile grants `/dev/null` and the random devices only.
- An invalid profile fails exactly like a denial: `sandbox-exec` aborts the child either way, the
  difference only on its own stderr — a search that discards it looks for grants that were never
  missing.
- `mach-lookup` names its services (`SeatbeltProfile.MachServices`), in the command's profile and
  the proxy's: unfiltered it reaches every Mach service of the host, and a service may act for its
  caller outside the profile.
  - The one name is `com.apple.system.opendirectoryd.libinfo`, the service the system's resolver
    library asks. Without it the serving proxy dies of a segmentation fault; with it alone it
    serves a fetch. `java -version` and `sbt about` run with no name granted
    (`src/probe/run-on-host-profile-iterate.sh mach`, `mach-proxy`, macOS 26.4.1).
  - A command gets the same name unmeasured: which call of the proxy's JVM needs it is not
    known, a build's JVM may make the same call, and the failure is a crash, not an error a
    build could report.
  - `open` started nothing from under the command profile while `mach-lookup` was unfiltered
    (`mach-route`): `open -a` found no application, and a `.command` file the command wrote had
    no application claiming it. Under the named service the gate has a row for `open -a`, and
    one for a JVM asking the resolver.
- What this toolchain needs, per layer: the JDK needs `sysctl-read`, its home, and
  `/System/Library/CoreServices/SystemVersion.plist` — without that one file `java` refuses to
  start with `os.version malformed: -1.0`. It does *not* need `file-map-executable`, which Apple's
  profiles use for system frameworks; a JDK outside those paths loads without it.
- Adopted from `system.sb` rather than re-derived: `file-test-existence`, a narrower operation than
  `file-read*` for the ancestor chain; and `(import "dyld-support.sb")`, Apple's own statement of
  what a process needs from the loader.

Prior art: Bazel sandboxes build actions on macOS with `sandbox-exec` — this feature's problem
exactly — and its generated profile is worth reading and worth *not* copying.

- It is a blacklist (`(allow default)`, then writes and network taken away), which is why Bazel
  never meets the findings above: with nothing denied by default, path resolution cannot fail, so
  the root entry and the ancestor chain never arise.
- It is also why that design cannot serve here: a command under it reads the whole filesystem,
  and "everything else user-owned inaccessible" is the property this feature exists to provide.
  Deny-by-default makes the profile harder to construct and is what provides that property, so
  the difficulty is no reason to change the design — worth stating because the blacklist form is
  the obvious simplification when the whitelist will not start.
- One setting is taken from Bazel: `(debug deny)`, which makes denials visible without the
  unified log's redaction, and which `src/probe/run-on-host-profile-iterate.sh` puts at the top
  of every profile it iterates.

**Runtime authority** — the loader, libc, the CA bundle and the rest a toolchain needs from the
system:

- It is discovered by running a real build under a deny-default profile and reading the denials,
  never by listing what a host happens to have, and never as a way to reach a user path.
  `src/probe/run-on-host-profile-iterate.sh` is how candidate entries are measured.
- The measured set is one file, a resource of the launcher's own artifact
  (`src/main/resources/agentsandbox/SeatbeltProfile.RuntimeAuthority.txt`): what the production
  wrapper grants is what the probes measured. The gate and host commands use that same set of
  grants.
- Do not pre-authorize broad paths (`/System/**`, `/usr/**`, `/opt/homebrew/**`); add the
  narrowest rule testing justifies.

## The command's egress proxy

The proxy is a process from the same codebase as the container's.

- Under sbt, `mill` and `gradle` it is the broker's: started in the broker's session when the
  first command of that program arrives from a build directory — the request's working directory,
  whose `project/target/active.json` or `out/` the build owns — with the program's rule file as
  read then, and kept for the commands that follow from that directory.
- A request from another build directory gets a proxy of its own, and both stay.
- A proxy that is gone is replaced, with its server or daemon, before the next command.
- Maven's is the command's, started by the wrapper in the command's session and ended with it, as
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
which holds the lines it was created with:

- at the first command from a build directory the launch has not visited;
- after `ko-sandbox-run-on-host <program> shutdown` followed by a proxy's own end;
- at the next launch, as the session's own rule file takes effect at the next launch.

Until then a host removed from the file stays reachable from that proxy, and one added is not; to
apply an edit, relaunch, as for the session's rule file. A broker retiring a running proxy on an
edit is declined: what a launch may reach is decided at launch (`design.md`, "Design principles to
preserve"), and a relaunch is the one step that applies an edit to both proxies alike.

It ships in the launcher's own artifact: the proxy sources share the launcher's Scala version,
`dist` compiles them in beside their `/defaults` resources, and the broker or the wrapper starts the
proxy by re-invoking its own executable — `java -jar` or the native binary — under a private action.

- That executable must still exist at its launch path, as spelled at launch — the link, when
  launched through a symlink — in either form: each is one file built under `target/dist`, which
  `sbt clean` or `git clean` removes while a session runs.
- So the broker checks it before every command's wrapper is exec'd and before every proxy start,
  and refuses with the path and the remedies — rebuild at that path, or relaunch — rather than
  letting the JVM fail at its main class after the ready wait (`RunOnHostSandbox.selfPresent`).
- A rebuild at the same path is no removal, nor is a link's retargeting: the running processes
  keep their inode, and the next re-invocation runs the new file.
- It binds an ephemeral port on `127.0.0.1` (the codebase's wildcard `:3128` default is safe only
  in the container's own network namespace), with `preferIPv4Stack` on its command line as the
  command's environment contract sets it, since the dual-stack bind is the v4-mapped one the
  `localhost` class denies ("Network"); its starter reads the port from the same ready line the
  container launcher gates on.

It runs under a profile of its own (`SeatbeltProfile.renderProxy`), the same for every proxy the
launcher starts on the host, since one `startProxy` starts them all. The profile grants:

- its executable — the native image, or the JDK and each class-path entry of the jar form;
- the runtime authority as reads, and the devices;
- the network: outbound to every remote, since which hosts a client may reach is the proxy's own
  decision, by name, and SBPL filters by address; the resolver's socket,
  `/private/var/run/mDNSResponder`, which `InetAddress.getAllByName` reaches, with the root link
  `/var` its client spells the path through (measured: without that one link every lookup fails);
  and a listener of the `localhost` class for its port;
- nothing of the user's: no project, no cache, no write anywhere;
- of the operation families, `sysctl-read` and `mach-lookup` of the resolver's service alone
  ("The Seatbelt profile", the measured findings), measured with
  `src/probe/run-on-host-profile-iterate.sh ops` and the proxy under its profile with each family
  added in turn — no `process-fork`, since it forks nothing.

It runs from `/`, since the JVM asks for its working directory at start and the profile grants no
other directory's. Its log is its stderr, opened by its starter and inherited, which no rule
governs, so what `sandbox-exec` or the JVM says before the proxy prints anything lands where the
ready line is awaited. The proxy is the one launcher process that parses bytes the confined command
sends, as the user's uid; `HostileInputTest` covers the parser, and the profile is what a parse bug
meets.

It runs without inspection material: no-material mode enforces the destination host and port at
CONNECT time and tunnels opaquely, so the command needs no extra trust material and the read-only
JDK's own trust store suffices. If inspection is ever wanted, point the JVM at a wrapper-owned
store with `-Djavax.net.ssl.trustStore` rather than touching the JDK.

It reads `HTTPS_PROXY` as the container's copy does (`egress-proxy.md`, "Through an upstream
proxy"): on a host behind an upstream proxy the command's artifact fetches leave through it, and a
loopback helper on the host is reachable from here, unlike from the container.

## Configuration

To allow artifact downloads beyond Maven Central, add repository hosts to this project file:

```text
.ko-agent-sandbox/run-on-host/<program>/egress/rule
```

- One file per program, so a repository that uses more than one grants each only what it
  resolves.
- The grammar is its own, narrower than the proxy's: `allow https://<host>/ read` lines and
  comments, nothing else — no other grant, no path, no provider, no deny — refused at validation
  rather than passed through. The full grammar would let one `allow model-provider` line expand
  into endpoints that are no artifact repository, and a `tunnel` word means nothing to a proxy
  running without inspection.
- A launch selecting the program prints the file's hosts on a line of their own,
  `run-on-host egress rules (<file>) widen:`, and refuses a file outside the grammar, so a host
  that arrived with the repository is seen by you before the agent's first command.
- The wrapper hands the proxy `deny defaults`, Maven Central, then the file's lines
  (`RunOnHostPrereqs.egressRuleText`), so the container's catalog contributes nothing.

The file inherits the directory's properties:

- the workspace filter freezes it at any depth;
- the launcher reads it on the host;
- it is reviewed in a pull request like any other file;
- `run-on-host/` accepts only recognized configuration entries, as does `.ko-agent-sandbox` — a
  stray entry fails the launch instead of being ignored (`SandboxProject.boundaryDirError`,
  `RunOnHostSandbox.hostCommandStray`).

No program needs a GitHub release CDN: the one download that would, the `mill` executable, is
provisioned on the host instead.

Derived paths come from Coursier conventions and environment APIs; advanced overrides
(`cache-root`, `jvm-root`, `install-root`) are not added until needed.

## The run-on-host cache

Host commands get their own cache root, per project:
`${XDG_CACHE_HOME:-$HOME/.cache}/ko-agent-sandbox/run-on-host/<projectId>/`.

- It holds Coursier's `v1`, sbt's global base and Ivy home, Gradle's user home and Maven's local
  repository under one directory, so `--reset-run-on-host` is a single removal, `--reset` takes it
  with the project's other state, and a further cache kind can join without moving anything.
- It is discovered exactly as the launcher's state root is, so the two answer alike on one
  machine.
- A relative override is refused because it would resolve against the repository being sandboxed,
  and a root overlapping the project is refused outright.
- A cache directory whose canonical path lies over or under the launcher's state root is refused
  too: `XDG_STATE_HOME` or a symlinked `run-on-host` can nest the two, so the separation argued
  below is checked on every command and reset rather than assumed
  (`RunOnHostPrereqs.cachePathClearOfStateRoot`).

Why not the user's cache: `SECURITY.md` "Cache poisoning stops at the project" has the security
argument. The cost is a cold cache on a project's first agent command, warm from the second onward.

Why not the launcher state root:

- the state root is kind-first (`tls/<id>`, `log/<id>`, …) and the proxy's audit log must not be
  stored beside the CA key;
- on the host the command runs as the user's own uid, which owns that key, so file permissions
  protect nothing and only the profile denies access; a separate root makes that denial
  structural — no path the command is ever granted has a sensitive ancestor or sibling;
- `XDG_CACHE_HOME` is also where a reconstructible cache belongs.

How each program reaches its cache:

- the wrapper sets `COURSIER_CACHE` to the `v1` directory, which the sbt script, sbt's own
  resolution and Coursier all honour;
- sbt's own two caches travel as the `java -D` properties above, which sbt's launcher reads;
- Gradle's user home as `GRADLE_USER_HOME`;
- Maven's local repository as the `java -D` property Maven's CLI reads.

## Sources

- Mill 1.1.9's daemon and launcher — the port-0 bind, `socketPort` and `processId`, the shutdown
  on a client's disconnect mid-command, the idle timeout, the fingerprint the launcher restarts on
  and its ten-second connect retry:
  - https://github.com/com-lihaoyi/mill/blob/1.1.9/libs/daemon/server/src/mill/server/Server.scala
  - https://github.com/com-lihaoyi/mill/blob/1.1.9/libs/daemon/client/src/mill/client/ServerLauncher.scala
  - https://github.com/com-lihaoyi/mill/blob/1.1.9/runner/launcher/src/mill/launcher/MillProcessLauncher.scala
  - https://github.com/com-lihaoyi/mill/blob/1.1.9/runner/launcher/src/mill/launcher/MillServerLauncher.scala
- sbt server — domain-socket and TCP modes, the port file, discovery and the token:
  - https://www.scala-sbt.org/1.x/docs/sbt-server.html
- sbt 1.13.0 and 2.0.8 — the thin client's server fork and its denied-connect retry, the
  disconnect cancelling the channel's exec, the `proc` registry and `notifyOtherServers`, the
  server's idle timeout, the boot socket's path (the same paths at v1.13.0):
  - https://github.com/sbt/sbt/blob/v2.0.8/main-command/src/main/scala/sbt/internal/client/NetworkClient.scala
  - https://github.com/sbt/sbt/blob/v2.0.8/main/src/main/scala/sbt/internal/CommandExchange.scala
  - https://github.com/sbt/sbt/blob/v2.0.8/main/src/main/scala/sbt/Defaults.scala
  - https://github.com/sbt/sbt/blob/v2.0.8/main-command/src/main/java/sbt/internal/BootServerSocket.java
- Gradle 9.7.1's wrapper — the distribution directory, the properties it reads, the user home:
  - https://github.com/gradle/gradle/blob/v9.7.1/platforms/core-runtime/wrapper-shared/src/main/java/org/gradle/wrapper/PathAssembler.java
  - https://github.com/gradle/gradle/blob/v9.7.1/platforms/core-runtime/wrapper-shared/src/main/java/org/gradle/wrapper/WrapperExecutor.java
  - https://github.com/gradle/gradle/blob/v9.7.1/platforms/core-runtime/wrapper-shared/src/main/java/org/gradle/wrapper/Install.java
  - https://github.com/gradle/gradle/blob/v9.7.1/platforms/core-runtime/wrapper-main/src/main/java/org/gradle/wrapper/GradleWrapperMain.java
- Gradle 9.7.1's daemon — its detach at start, the client's fork with its own environment and
  the registry option, the compatibility check on the client's immutable properties, the cancel
  on a client's disconnect, `--stop`, and the file lock's UDP socket:
  - https://github.com/gradle/gradle/blob/v9.7.1/platforms/core-runtime/daemon-server/src/main/java/org/gradle/launcher/daemon/bootstrap/DaemonMain.java
  - https://github.com/gradle/gradle/blob/v9.7.1/platforms/core-runtime/client-services/src/main/java/org/gradle/launcher/daemon/client/DefaultDaemonStarter.java
  - https://github.com/gradle/gradle/blob/v9.7.1/platforms/core-runtime/process-services/src/main/java/org/gradle/process/internal/DefaultProcessForkOptions.java
  - https://github.com/gradle/gradle/blob/v9.7.1/platforms/core-runtime/daemon-protocol/src/main/java/org/gradle/launcher/daemon/context/DaemonCompatibilitySpec.java
  - https://github.com/gradle/gradle/blob/v9.7.1/platforms/core-runtime/launcher/src/main/java/org/gradle/launcher/cli/converter/InitialPropertiesConverter.java
  - https://github.com/gradle/gradle/blob/v9.7.1/platforms/core-runtime/launcher/src/main/java/org/gradle/launcher/daemon/server/DaemonStateCoordinator.java
  - https://github.com/gradle/gradle/blob/v9.7.1/platforms/core-runtime/launcher/src/main/java/org/gradle/launcher/daemon/server/exec/WatchForDisconnection.java
  - https://github.com/gradle/gradle/blob/v9.7.1/platforms/core-runtime/client-services/src/main/java/org/gradle/launcher/daemon/client/DaemonStopClient.java
  - https://github.com/gradle/gradle/blob/v9.7.1/platforms/core-execution/persistent-cache/src/main/java/org/gradle/cache/internal/locklistener/DefaultFileLockCommunicator.java
- Gradle toolchains — auto-detection, auto-provisioning and `installations.paths`:
  - https://docs.gradle.org/current/userguide/toolchains.html
- Gradle's configuration precedence — a `-D` over every `gradle.properties`:
  - https://docs.gradle.org/current/userguide/build_environment.html
- Surefire fork communication — process pipes by default, TCP by configuration:
  - https://maven.apache.org/surefire/maven-surefire-plugin/examples/process-communication.html
- Maven Resolver configuration — `useSystemProperties`:
  - https://maven.apache.org/resolver/configuration.html
