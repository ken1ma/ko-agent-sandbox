# Run on Host — sbt, Mill, Gradle and Maven commands outside the container

`--run-on-host=<programs>` sends the workspace's sbt, Mill, Gradle and Maven commands to the
host, where each command runs under a Seatbelt profile of its own. The option exists on macOS alone
and is off by default.

    ┌─ macOS host ───────────────────────────────────────────────────────────────────────┐
    │                                                                                    │
    │  ┌─ sandbox container (inside the podman machine) ────────────────────────────┐    │
    │  │ agent → ko-sandbox-run-on-host sbt / mill / gradle / mvn                   │    │
    │  └────────────────────────────────────────────────────────────────────────────┘    │
    │                       │  command       ↑  stdout, stderr, and exit status          │
    │                       ↓                │                                           │
    │  ┌─ host runner (one per sandbox session) ────────────────────────────────────┐    │
    │  │ runs one command at a time; starts and stops the processes it owns         │    │
    │  └────────────────────────────────────────────────────────────────────────────┘    │
    │                       │                                     │                      │
    │                       ↓                                     ↓                      │
    │  ┌─ build processes: Seatbelt profiles ─────┐    ┌─ proxy: Seatbelt profile ────┐  │
    │  │ sbt client → sbt server                  │    │ listens on 127.0.0.1         │  │
    │  │ mill or gradle client → its daemon       │    │ allows only listed hosts     │  │
    │  │ Maven starts a JVM for each command      │    │ on port 443                  │  │
    │  │ dependency downloads                     ├───→│ inspects: GET and HEAD only  │  │
    │  │ writes workspace files, except           │    │ reads no workspace or cache  │  │
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

This document tells you how to set up and use host commands. Other documents cover the rest:

- `SECURITY.md` "Run on host" states the security properties and their costs.
- [run-on-host-internals.md](run-on-host-internals.md) describes how host commands work.
- [seatbelt.md](seatbelt.md) records the Seatbelt behavior that the profiles depend on.
- [run-on-host-evidence.md](run-on-host-evidence.md) has the acceptance test's recorded results
  and the other measurements that a new release can change.

## Why use it

On macOS, the podman machine limits a build's memory, and keeps the memory that the build used:

- An `sbt test` of this project takes about 2 GB inside the podman machine.
- A session gets the machine's memory minus 1 GiB (README, `--memory`). podman's default machine
  has 2 GiB, which leaves the session about 1 GiB.
- containers.conf (`[machine]` `memory`) or `--memory` sets the machine's memory when the machine
  is created.
- The machine keeps the memory that a build grew until macOS runs short of memory
  ([run-on-host-evidence.md](run-on-host-evidence.md), "Memory").

On the host, the same build uses the host's memory, which macOS reclaims when the build exits. The
build also runs at host speed. Linux gains nothing from host commands. On Windows, the podman
machine is WSL's, which has half the host's memory by default and returns a build's memory to
Windows, so host commands would gain less. Windows also cannot enforce the denials that host
commands need (`run-on-host-internals.md`, "Why only macOS").

## Program prerequisites

One rule explains all four programs: **the user provisions each executable that the Seatbelt
profile grants; the host command sandbox fetches only artifacts.**

- sbt's executable comes from `cs install sbt`. Everything else sbt needs is a jar the JDK reads,
  fetched into the writable run-on-host cache through the proxy.
- `mill`'s bootstrap fetches an executable, the launcher, so the user provisions the launcher and
  the host command sandbox does not fetch it. A version bump then needs an explicit run on the host,
  and the build definition cannot update the launcher by itself.
- The JDK that a `mill` build's daemon runs on is an executable Mill would download, so the user
  provisions it too ("`mill`" below). The exception is a `mill-jvm-version` of `system`.
- Gradle's and Maven's executables are the distributions the workspace's wrappers unpacked on the
  host.

A command that misses a prerequisite is refused, and the refusal names what to fix.

The launcher checks `mill`'s, Gradle's and Maven's prerequisites before its start prompt. So you
see a Mill launcher, JDK or distribution that is not yet provisioned before the agent's first
command fails on it. The launcher checks nothing for sbt: its executable is the one
`cs install sbt` produced, whatever the workspace pins.

- The launcher finds every build directory of the selected programs, and resolves each directory's
  executable as the directory's first command would. The launcher prints each refusal in the
  command's wording.
  - A `mill` or Gradle build directory holds a `mill` bootstrap or a Gradle wrapper's properties
    file. The supervisor identifies a build directory by those files (`run-on-host-internals.md`,
    "`mill`", "Gradle").
  - The search covers the whole workspace, except inside `.git`, `.ko-agent-sandbox` or a symlink.
  - Maven's build directory is the workspace root alone, holding `mvnw` ("Maven" below).
  - A properties file without `gradlew` beside it is reported with no run offered, because the
    run below executes `gradlew`.
- A Mill launcher, JDK or distribution that is not yet provisioned is a refusal that a host run
  fixes.
  For such a refusal, the prompt shows the run and runs it on an explicit `y`, unconfined and in
  the launcher's environment. The prompt replaces the manual run that the refusal asks for with
  one answer (`SECURITY.md`, "Run on host").
  - The run is `MILL_VERSION=<v>-jvm ./mill version`, `./gradlew --version` or `./mvnw --version`
    in the build directory, shown in full.
  - The prompt tints the whole question orange, because answering it grants the run. The launcher's
    startup line tints `run-on-host: sbt` the same way.
  - The launcher checks each build directory in turn. So when two directories share a version, the
    launcher asks once, about one run.
  - The check repeats after the run, so a script that exits zero without provisioning is reported
    at once.
- Without a start prompt, the launcher prints the refusals and runs nothing. The launcher shows no
  start prompt when it has no terminal or runs with `--session-start=immediate`.
- The launcher cannot see a pin changed during the session, or a build directory created later. The
  first command there is refused, naming the same run. A relaunch offers the run.

### The JVM

In the launcher's environment on the host, set `JAVA_HOME` to a JDK that Coursier installed. Only
Coursier-managed JVMs are accepted.

- `JAVA_HOME` must resolve to one canonical JDK home under your Coursier cache root.
- The one other source is the JDK that Mill's launcher resolved for a `mill` build's daemon, from
  a pinned or unset `mill-jvm-version` ("`mill`" below). That JDK passes the same checks.
- `java` on `PATH` is `/usr/bin/java`, a macOS stub that resolves through `JAVA_HOME` or
  `/usr/libexec/java_home`. The stub reports the right JVM, but its path is not the JDK's.
- Rejected: the stub, `/Library/Java/JavaVirtualMachines`, Homebrew and SDKMAN JVMs, and a
  `JAVA_HOME` resolving outside the Coursier cache.

### sbt

Install sbt with `cs install sbt`. An `sbt` from elsewhere on `PATH` is not used.

### `mill`

The build directory's own `mill` bootstrap script runs. A globally installed `mill` is not used.

- Run `MILL_VERSION=<v>-jvm ./mill version` once on the host in the build directory, and again
  whenever the pinned version changes. The start prompt offers that run.
  - The run provisions Mill's JVM launcher, and the JDK for a pinned or unset
    `mill-jvm-version`.
  - A command refused for the launcher or the JDK names the same run.
- The host command runs the JVM launcher, not the native image. A `<v>-native` pin is refused with
  the reason.
- Set `mill-jvm-version` to `system`, to one JVM id such as `temurin:25`, or leave it unset.
  - `system` runs the daemon on `JAVA_HOME`'s JDK.
  - Before Mill 1.1.0, an unset `mill-jvm-version` is refused.
- From Mill 1.2 on, each command runs without a daemon and starts its own JVM. The command's
  stderr says so.
- A nested build directory with a bootstrap of its own is another build.

### Gradle

The Gradle that the build directory's wrapper names in `gradle/wrapper/gradle-wrapper.properties`
runs. A globally installed `gradle` is not used.

- Run `./gradlew --version` once on the host, and again whenever `distributionUrl` changes. That
  run downloads Gradle into `~/.gradle/wrapper/dists`. The start prompt offers that run.
- If the wrapper has not downloaded that Gradle yet, the command is refused, and the refusal says
  what to run.
- Keep `distributionBase` and `distributionPath` at the wrapper's defaults, and leave
  `systemProp.gradle.user.home` out of the build directory's `gradle.properties`. A build that
  sets any of them is refused.
- Use Gradle 8.14.4 or later: earlier releases fail on JDK 25, which the launcher requires
  ([run-on-host-evidence.md](run-on-host-evidence.md), "Gradle releases").
- A nested build directory with a wrapper of its own is another build.

### Maven

The Maven that the workspace root's `mvnw` names in `.mvn/wrapper/maven-wrapper.properties` runs.
A globally installed `mvn` is not used.

- Run `./mvnw --version` once on the host, and again whenever `distributionUrl` changes. That run
  downloads Maven into `~/.m2/wrapper/dists`. The start prompt offers that run.
- If the wrapper has not downloaded that Maven yet, the command is refused, and the refusal says
  what to run.
- Only the `only-script` wrapper type is served, the default that `mvn wrapper:wrapper`
  generates. A workspace with any other wrapper type is refused, and the refusal names the command
  that converts it.
- An mvnd distribution is refused, because mvnd is a daemon.
- Your `~/.m2/settings.xml` and `toolchains.xml` are denied, and Maven treats them as absent. So a
  mirror or credential there never reaches a confined command.
- Maven 4 is a release candidate. Maven 4 is provisioned the same way and is unmeasured.

## Configuration

To allow artifact downloads beyond Maven Central, add repository hosts to this workspace file:

```text
.ko-agent-sandbox/run-on-host/<program>/egress/rule
```

- Each program has its own file, so a workspace that builds with more than one program grants each
  program only the hosts that the program resolves from.
- The file takes a narrower grammar than the proxy's rule file: `allow https://<host>/ read` lines
  and comments, nothing else. Validation refuses any other grant, a path, a provider or a deny,
  rather than passing it through.
  - The full grammar would let one `allow model-provider` line expand into endpoints that serve no
    artifacts.
  - A `tunnel` or `method=` word would let a host command write to a host, and no host command may
    write to a host.
- When `--run-on-host` selects the program, the launcher prints, per file,
  `<file>: <count> widening lines`, then the file's hosts indented. Two or more hosts are joined
  into `allow read: <host>, <host>`.
  - The launcher refuses a file outside the grammar, or a file naming a host the proxy refuses, such
    as an IP literal.
  - So you see each host that the workspace's own file grants before the agent's first command.
- The proxy gets `deny defaults`, Maven Central, then the file's lines. So the proxy allows no
  host from the container's default catalog.

The file inherits the properties of `.ko-agent-sandbox`:

- the workspace policy freezes it at any depth;
- the launcher reads it on the host;
- it is reviewed in a pull request like any other file;
- `run-on-host/` accepts only recognized configuration entries, as does `.ko-agent-sandbox`. A
  stray entry fails the launch instead of being ignored.

No program needs a GitHub release CDN. The one download that would need it, the Mill launcher, is
provisioned on the host instead.

The launcher derives Coursier's paths from Coursier's conventions and the environment. The launcher
offers no overrides (`cache-root`, `jvm-root`, `install-root`) until a user needs one.

## The run-on-host cache

Host commands get their own cache root, per workspace:
`${XDG_CACHE_HOME:-$HOME/.cache}/ko-agent-sandbox/run-on-host/<workspaceId>/`. A poisoned artifact
there reaches only later host commands of the same workspace, never your own builds or another
workspace (`SECURITY.md`, "Cache poisoning stops at the workspace").

- The root holds Coursier's `v1`, sbt's global base and Ivy home, Gradle's user home and Maven's
  local repository under one directory.
  - So `--reset-run-on-host` removes one directory, and `--reset` removes the root with the
    workspace's other state.
  - Another kind of cache can be added under the root without moving the others.
- The cache starts cold at a workspace's first agent command, and is warm from the second onward.

## Startup cost

A host command's recurring cost is the program's start. Each program starts anew at these points:

- sbt and `mill`: the runner keeps one server or daemon warm across its commands from one build
  directory ("Where a host command deviates from the stock program"). Either program starts:
  - at the first command from a directory;
  - after `ko-sandbox-run-on-host <program> shutdown`;
  - after the program's own idle exit: seven days for sbt (`TODO.md`, "an idle bound for the sbt
    server"), thirty minutes for Mill.
- An sbt server keeps the `sbt.version` and options it started with until `shutdown`, as in a
  terminal. A cancelled sbt command leaves its server warm.
- `mill` also starts anew after a cancel, which ends the daemon as stock Mill does.
- `mill` starts anew after an edit to a setting that makes Mill restart its daemon: the version
  pin, `mill-jvm-opts`, `mill-repositories`, or anything in `build.mill.yaml`, the header Mill
  reads them from.
- A `mill` start costs only the daemon's start, because the runner ends the starter as soon as the
  daemon listens (`run-on-host-internals.md`, "`mill`").
- Gradle runs its own daemon (`run-on-host-internals.md`, "Gradle"). The daemon starts at the
  first command and after Gradle's idle exit, three hours. A client attaches to a compatible
  daemon in the launch's own registry.
- Maven runs once per command, so every command starts a JVM and loads the build. The caches and
  the incremental-compile outputs under `target/` stay on disk between commands.

## When a command fails

A failed command never gets more access than its profile grants:

- A host command that cannot run is reported and never rerun in the container. The one exception
  is a test suite that binds a listener under sbt or Maven, which runs in the container.
- A missing prerequisite is refused before the command starts, naming what to fix.
- A filesystem denial reaches the command's own stderr as the OS error.
- A host the proxy denied is reported after the command ("Command requested network access to:
  …"). To allow it, add the host to the program's rule file ("Configuration").
- A request the proxy refuses, such as a publishing `PUT`, is reported after the command
  ("Command sent requests the host command sandbox refuses: …"). Run that command yourself,
  outside any sandbox.

`run-on-host-internals.md`, "Refusals", describes each form.

## Where a host command deviates from the stock program

Apart from the deviations below, a host command behaves as the stock program run from a terminal.
Each deviation names its reason: confinement, the launch's ownership of what it starts, or
operability, since the caller is not interactive. A quoted section name in this list is in
[run-on-host-internals.md](run-on-host-internals.md), which describes the mechanism.

### Under every program

- **Persistent processes end with the launch — ownership.** Stock sbt, Mill and Gradle leave their
  server or daemon running when the terminal that started it closes, Gradle's for three idle hours.
  - The runner's servers and daemons run against the launch's proxy and its forwarded environment.
    Both die with the launch, so the servers and daemons must die too.
  - The next runner's start ends the processes that a killed runner left. A later launch adopts
    no server or daemon whose owner is gone.
- **A client attaches only to a server or daemon started under the same confinement and
  environment — confinement.** Stock sbt attaches to whatever server holds the portfile. Stock Mill
  attaches to whatever daemon holds `out/mill-daemon`, unless its fingerprint differs. A client
  attached to a process the runner did not start would run the build under that process's
  environment and confinement, or under none.
  - The runner shuts down the user's own terminal server by protocol, at the socket it derives. The
    runner ends the user's own daemon once idle, after its start-time check ("`mill`").
  - The runner attaches to a server or daemon another launch still owns only when it would start
    one under the same confinement and environment. Otherwise the runner ends that process by that
    launch's record, under the retirement lock, and replaces it with its own ("The channel and the
    command").
- **The command gets a closed environment — confinement.** The command sees the variables that the
  supervisor sets, not the launching shell's ("The command's lifetime and environment"):
  - `HOME` is passed, and nothing under it is granted;
  - `preferIPv4Stack` is set for the loopback rule ("Network");
  - the proxy is the command's only route off this host;
  - the workspace is writable even under `--workspace=read-only` (`SECURITY.md`, "Run on host").
- **Publishing to a repository is refused — confinement.** Stock sbt, Mill, Gradle and Maven
  publish to a repository with a `PUT`.
  - A host command's proxy refuses every request but a `GET` or `HEAD` without a body ("The
    command's egress proxy"), and the rule file takes no other grant. So you publish yourself,
    outside any sandbox.
  - The supervisor names the refused request ("Refusals").
  - By default, the JVM trusts the proxy's CA alone, with no public root ("The command's lifetime
    and environment").
- **The runner bounds the wait for a start — operability.** sbt's thin client waits for a starting
  server with no deadline, and an interactive user ends that wait with Ctrl-C. The agent cannot
  press Ctrl-C, so an unbounded wait would hang the command for good.
  - The runner fails the start, with the log's tail, when neither the server's log nor the proxy
    log grows and no portfile appears for two minutes.
  - A `mill` starter that neither ends nor writes for as long, while the proxy log stays still,
    fails the same way. `doc/TODO.md`, "a bound on a silent host command", tracks a bound for every
    silent host command.

### Under sbt

- **The runner starts the server, not the client — ownership.** The runner starts the server in its
  own directory for sockets and temporary files, and each command's client attaches. A server that
  the client forked would inherit the command's profile, environment and group ("sbt").
- **The server receives the request's sbt launcher flags as the thin client forwards them, less
  those naming a program — confinement.**
  - `-D` properties, the value flags and `--allow-empty` reach the server.
  - `-J` does not reach the server. The runner applies `-J` to the client's own JVM, and the stock
    client forwards no `-J` either.
  - The runner also drops flags that the client forwards: `-java-home`, `-sbt-jar`,
    `--sbt-script`, `--sbt-launch-jar` and `-Dsbt.script=`. Each names the JVM, the sbt launcher
    jar or the runner script, which the profile's grants decide.
- **`new` and `init` run through a server — the client model.** Stock sbt runs those two commands
  in its own process, because they write a template where no build exists yet. Stock sbt runs
  every other command through its client.
  - The runner runs every command through a client to the server it starts. So the runner refuses
    `ko-sandbox-run-on-host sbt new` in an empty directory, as it refuses any directory with no
    build.
  - `--allow-empty` starts the server there, as the stock client's flag would.
  - The acceptance test does not measure whether `new` then writes its template through that
    server.
- **The runner uses the JVM client, never `sbtn` — operability.** sbt 2 runs its native client by
  default. Under the profile, that client prints that it is starting the server and returns with no
  build run. The supervisor passes `--jvm-client`, and an acceptance-test row keeps measuring `sbtn`
  ("sbt").
- **The runner sweeps `target/` links into a denied store before a server starts —
  confinement.** A tree that the user's unconfined sbt built links into a store the profile denies
  ("sbt").
- **The global base and the Ivy home are the workspace's own — confinement.** The runner redirects
  both into the run-on-host cache, where stock sbt uses `~/.sbt` and `~/.ivy2` ("sbt", "The
  run-on-host cache").
- **While the launch's server lives, your terminal's `sbt` in the build directory runs on it, and
  `sbt shutdownall` does not end it — ownership.** Run `sbt shutdown` there first to end the
  server.
  - Stock sbt attaches to whatever server holds the portfile, so your command runs under the
    profile and the launch's environment. A test that runs podman fails there.
  - `sbt shutdownall` kills what `jps -v` lists as `sbt-launch`, which does not include a launch's
    server (sbt 2.0.9, macOS 26.4.1, 2026-09-28). The server ends with the launch anyway.

### Under `mill`

- **The runner's `./mill version` starts the daemon, not the first client — ownership.** The
  starter's denied connect leaves the daemon in the runner's group, and the runner ends the starter
  once the daemon listens ("`mill`").
- **The client is the JVM launcher, never the native image — confinement.** The stock bootstrap
  runs the native image for a version with no suffix.
  - The supervisor sets `MILL_VERSION` to `<v>-jvm`, so that the client takes the environment's
    `preferIPv4Stack` and connects under the one-port rule. The image cannot do either ("`mill`").
  - The user provisions that launcher, and a `-native` pin is refused with the reason.
- **After a configuration edit, the runner replaces the daemon before the command —
  operability.** Stock Mill's client ends a daemon whose fingerprint differs and starts a
  replacement itself.
  - A replacement that a confined client starts cannot bind, so the command would fail.
  - The runner reads the same inputs before each command and replaces the daemon first.
- **Under a pinned or unset `mill-jvm-version`, the daemon runs on the JDK that a host run
  provisioned — confinement.** Stock Mill resolves the id, or its default, and downloads the JDK
  itself. A command may not fetch a JDK ("A pinned JVM", "An unset `mill-jvm-version`").
  - Before Mill 1.1.0, an unset `mill-jvm-version` is refused.
- **The supervisor ignores a request's `MILL_VERSION`, `DEFAULT_MILL_VERSION`, `MILL_OUTPUT_DIR`
  and `MILL_BSP_OUTPUT_DIR` — confinement.** The supervisor's `MILL_VERSION` names the granted
  launcher, and the supervisor looks for the daemon's rendezvous under `out/` ("The command's
  lifetime and environment").
- **A redirected `out/mill-daemon` is refused — confinement.** Mill's launcher would act on another
  build directory's daemon through it ("`mill`").
- **Before a start, the runner deletes a `mill-daemon-classpath` file that names paths the profile
  denies — confinement.** Stock Mill keeps the file, since the paths exist. Under the profile the
  daemon could not open them ("`mill`").
- **Clients use the runner's temporary directory, not their own — confinement.** A JVM that the
  daemon forks inherits the daemon's profile and gets the client's environment ("The command's
  lifetime and environment").

### Under Gradle

- **The daemon registry is the launch's, under the runner's `tmp/` — confinement.** Stock Gradle
  keeps the registry in the user home, where one launch's `gradle --stop` would end another
  launch's builds ("Gradle").
- **The command runs the distribution's `bin/gradle`, never `gradlew` — confinement.** The wrapper
  script would download Gradle. A `distributionBase`, `distributionPath` or
  `systemProp.gradle.user.home` that moves the distribution to a place the workspace chooses is
  refused ("Gradle").
- **Gradle sees the launch's JDK as its only toolchain — confinement.** The command line turns off
  auto-detection and auto-provisioning, so a project asking for another toolchain fails naming it
  ("Gradle").
- **Gradle's user home is the workspace's own — confinement.** The user home is under the
  run-on-host cache, where stock Gradle uses `~/.gradle` ("The run-on-host cache").

### Under Maven

- **The command runs the distribution's `bin/mvn`, never `mvnw` — confinement.** The wrapper script
  would download Maven ("Maven").
- **The local repository is the workspace's own, and the resolver uses the proxy —
  confinement.**
  - `maven.repo.local` is under the run-on-host cache, where stock Maven uses `~/.m2/repository`.
  - `aether.connector.http.useSystemProperties` is set. Without it, Maven's resolver ignores the
    proxy, which the profile leaves as the one route out ("The command's lifetime and
    environment").

Two behaviors come from the stock program, not from the runner:

- The stock program keeps one warm server or daemon per build directory, not one per program. So
  visiting another directory leaves the first directory's server or daemon warm.
- A cancel acts as the program's own cancel does, and the programs differ:
  - An sbt client's disconnect cancels only the running command and leaves the warm server. So an
    interruption-ignoring test lingers in the server exactly as it would in a terminal, and the next
    command reuses the server.
  - A Mill client's disconnect mid-command makes the daemon shut itself down, so the next `mill`
    command starts a daemon.
  - A Gradle client's disconnect cancels the build, and the daemon stops itself only if still busy
    ten seconds later. So the next `gradle` command attaches or starts a daemon.

After a cancel, the runner neither ends nor restarts a server or daemon on its own.

## Out of scope

These are left out deliberately:

- arbitrary build programs (`scalafmt` and ad-hoc `scala` stay in the container);
- arbitrary globally installed JVMs, Homebrew, SDKMAN and asdf JVMs included;
- direct Internet access from the command;
- any automatic expansion of permissions when a command fails, and any fallback to the container;
- implicit access to `~/.m2`, `~/.ivy2`, user git credentials, SSH credentials or unrelated
  home-directory state;
- stdin: `sbt console`, `sbt shell` and `sbtn`'s interactive modes.

The container keeps its toolchain. Host commands are an alternative, not a replacement: a session
without `--run-on-host` builds in the container.
