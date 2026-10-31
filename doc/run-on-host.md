# Run on Host — sbt, `mill`, Gradle and Maven commands outside the container

`--run-on-host=<programs>` sends the workspace's sbt, `mill`, Gradle and Maven commands to the
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

This document is the reference for how host commands work and what they require. The table names
the document or code that specifies or enforces each part:

| concern | specified or enforced in |
| --- | --- |
| the security properties and their costs | `SECURITY.md` "Run on host" |
| option syntax and write access | [README.md](../README.md#reference), `--run-on-host` |
| the channel protocol and its teardown | `RunOnHostChannel.scala`, `ko-sandbox-run-on-host` |
| the command lifecycle: publish, lock, scavenge | `RunOnHostSession.scala` |
| prerequisite validation and the paths it settles | `RunOnHostPrereqs.scala` |
| provisioning offered at the start prompt | `RunOnHostProvisioning.scala` |
| the supervisor's steps and a command's environment | `RunOnHostSandbox.scala` |
| the runner's runtimes, kept across a launch's commands | `RunnerRuntimes.scala` |
| a host command's proxy and what its log reports after a command | `RunOnHostProxy.scala` |
| the runner's sbt server: its start, a server of yours | `RunOnHostSbtServer.scala` |
| the runner's mill daemon: its start, its port, a daemon of yours | `RunOnHostMillDaemons.scala` |
| the launch's Gradle daemons and their records | `RunOnHostGradleDaemons.scala` |
| what a runner publishes for another launch to attach to | `RunOnHostRuntimeDescriptor.scala` |
| sbt's local-socket shutdown | `RunOnHostSbtServerShutdown.scala` |
| a proxy's CA and leaf, and what a command trusts | `RunOnHostInspection.scala` |
| the generated profile | `SeatbeltProfile.scala` |
| the exit criteria, measured | `src/probe/run-on-host-acceptance-test.sh` |

The full acceptance test (`all`) has these recorded results:

- On macOS 26.6.2 arm64 with Temurin 25.0.4, sbt 2.0.9, Mill 1.3.0, Gradle 9.8.0 and Maven 3.9.16
  (2026-10-19), the test reports **285 PASS, 0 FAIL, 13 SKIP**. The skips are the rows of Mill's
  daemon, which Mill 1.3.0 runs without.
- A second run of the mill rows, on the copy pinned to Mill 1.1.10, reports **101 PASS, 0 FAIL, 16
  SKIP**. Each skip is a row of a program that the run does not select, or a row of Mill without a
  daemon.
- Neither run includes the row on a build through a mill daemon of yours. With that row, the
  `mill` selection reports **90 PASS, 0 FAIL, 28 SKIP** on Mill 1.3.0 and **101 PASS, 0 FAIL, 17
  SKIP** on Mill 1.1.10 (2026-10-19).

The measurement behind the feature: an `sbt test` of this project takes about 2 GB inside the
podman machine.

- The machine's total memory is fixed when the machine is created, and every other session on the
  machine shares it.
  - podman's built-in default for a macOS machine is 2048 MiB. containers.conf (`[machine]`
    `memory`) or `--memory` changes it.
  - A WSL machine has WSL's memory, half the host's by default.
- A session gets the machine's memory minus 1 GiB (README, `--memory`): about 1 GiB on podman's
  default, and 3 GiB on a 4 GiB machine. The agent, the build and the session's other processes
  share that memory.
- Whether the machine gives memory back to macOS depends on libkrun. From 1.19.0, libkrun frees
  the pages the guest reports free with MADV_FREE, which macOS reclaims under memory pressure
  (containers/libkrun pull 703).
- A measurement with libkrun 1.19.0 (podman 6.1.2, macOS 26.4.1) on a freshly restarted 12 GiB
  machine (`src/probe/machine-memory-return.sh`, 2026-09-22):
  - The build grew the machine's process by 6.8 GiB of resident memory, which stayed through the
    ten minutes after the build.
  - A minute of `memory_pressure -l warn` then compressed 6.6 GiB of the process's memory, and
    dropped 1.7 GiB more without compressing it.
  - Swap stayed level throughout.
- So the process keeps what a build grew until macOS is short of memory. Under pressure, growth in
  the process's compressed memory matched most of its resident decrease, and the remainder is
  consistent with discarded pages.
- On the host, the same build runs at host speed, on memory that macOS reclaims when the build
  exits.

A host command's recurring cost is startup. Each program starts anew at these points:

- sbt and `mill`: the launch keeps one server or daemon warm across its commands from one build
  directory ("Where a host command deviates from the stock program"). Either program starts:
  - at the first command from a directory;
  - after `ko-sandbox-run-on-host <program> shutdown`;
  - after the program's own idle exit: seven days for sbt (`TODO.md`, "an idle bound for the sbt
    server"), thirty minutes for Mill.
- An sbt server keeps the `sbt.version` and options it started with until `shutdown`, as in a
  terminal. A cancelled sbt command leaves its server warm.
- `mill` also starts anew after a cancel, which ends the daemon as stock Mill does.
- `mill` starts anew after an edit to what Mill restarts the daemon on: the version pin,
  `mill-jvm-opts`, `mill-repositories`, or anything in `build.mill.yaml`, the header Mill reads
  them from.
- A `mill` start costs the daemon's own start: the runner ends the starter as soon as the daemon
  listens ("`mill`").
- Gradle: the daemon is Gradle's own ("Gradle"). A start happens at the first command and after
  Gradle's idle exit, three hours. A client attaches to a compatible daemon in the launch's own
  registry.
- Maven runs once, so every invocation starts a JVM and loads the build. The on-disk state stays
  warm: the caches, and the incremental-compile outputs under `target/`.

Out of scope, deliberately:

- arbitrary build programs (`scalafmt` and ad-hoc `scala` stay in the container);
- arbitrary globally installed JVMs, Homebrew, SDKMAN and asdf JVMs included;
- direct Internet access from the command;
- any automatic expansion of permissions when a command fails, and any fallback to the container;
- implicit access to `~/.m2`, `~/.ivy2`, user git credentials, SSH credentials or unrelated
  home-directory state;
- stdin: `sbt console`, `sbt shell` and `sbtn`'s interactive modes.

The container keeps its toolchain. Host commands are the fast path, not a replacement, and a
session without `--run-on-host` builds in the container.

## Why only macOS

The feature exists only where the guard's name denies, such as `.git` at any depth, hold at every
access. What the alternatives look like, for whoever revisits them:

On Linux, bubblewrap does the *positive* half better than Seatbelt:

- bubblewrap starts with nothing mounted and builds up, so the grant table holds by construction;
- `--unshare-all` removes the network namespace outright, which makes proxy bypass impossible
  rather than merely denied.

But the denies do not hold:

- bubblewrap establishes its mounts once at start, so covering `.git` at any depth means binding
  over each `.git` found then. A `.git` created during the command has no mount over it.
- Landlock is no better: its ruleset is fixed at creation.

On Linux the feature would also gain nothing: a container command already runs at host speed on
host memory, reclaimed on exit. The feature would cost Linux the one limit that the container has
and a host command does not: the cgroup memory limit, which kills a runaway build inside the
sandbox instead of taking the machine down.

On Windows, AppContainer expresses the grants perfectly well:

- a per-user profile with a derived SID;
- inheritable ACEs on the granted roots;
- private profile storage;
- network confinement by capability, plus a WFP rule restricted to the proxy endpoint.

AppContainer cannot express the denies:

- ACL inheritance has no name patterns, so "deny `.git` at any depth" can only be a set of deny
  ACEs that a launch-time scan places.
- A `.git` created *during* the command inherits the workspace's allow. That is a race, where the
  deny must hold at every access.
- A Windows backend needs an equivalent of access-time path filters before it is worth
  reconsidering: a filesystem minifilter, or a design that does not put the guard in ACLs at all.

## The host command's filesystem rules

The filesystem rules define what a host command can access:

- **Commands can start programs they write in the workspace or their temporary directory.** A
  child inherits the profile, so running those programs adds no authority.
  - Tests routinely write and run stubs.
  - The run-on-host cache permits reads and writes but not direct process execution. The JVM can
    still load and execute code from cached JARs.
- **Seatbelt has no mount namespace**, so the profile cannot replace `$HOME` with an empty
  directory the way a container image would. The profile denies `$HOME` instead.
  - A command cannot create `$HOME/.netrc`, a Coursier mirror file, or any other configuration a
    later step would read. The denied write protects these files, not a bare directory.
- **Seatbelt matches the path after resolving it, and on a case-insensitive volume the lowercase
  pattern matches the other spellings measured** (`src/probe/seatbelt-semantics.sh`, macOS 26.4.1).
  - An access through `.GIT` to an existing `.git` resolves to the lowercase path and is denied
    (E5).
  - A `.GIT` that the command creates where no `.git` exists is denied too (E9).
  - The volume resolves `.ko-agent-sandbox` spelled with U+212A KELVIN SIGN or U+017F LONG S to
    the name (E11), and the lowercase pattern denies creating either spelling (E12).
  - The acceptance test creates those spellings, `.GIT` and `.KO-AGENT-SANDBOX` under each command
    profile, and each creation is denied.
  - A spelling that the volume resolves to the name and that no row creates is unmeasured.
- **Writes to what the file rules protect are denied the same way, in the rules' order**
  (`doc/file-rules.md`). The profile renders:
  - each `read-only` line as a deny and each `writable` line as an allow, as a regex anchored
    after the workspace root's path;
  - each directory a line passes through as a deny on the entry itself, at the line's position;
  - what the filter's guard added by path, after the lines;
  - below a directory that a symlink makes part of a listed name, the rest of each `read-only`
    line.
- **The deny on a directory a line passes through refuses renaming, exchanging and replacing the
  entry.**
  - SBPL has no operation of a rename's own. SBPL checks a rename's source as
    `file-write-unlink`, as it checks `rmdir` and `unlink`, and the rename's destination as
    `file-write-create`, as it checks `mkdir`. SBPL checks a `RENAME_SWAP` exchange as both, on
    either operand (`src/probe/seatbelt-semantics.sh` E13-E17, macOS 26.4.1).
  - So the deny covers `file-write-create`, `file-write-unlink` and `file-link` on the entry. It
    leaves the entry's contents, mode and attributes to the other rules, as the filter does.
  - The acceptance test's file-rule rows pass on macOS 26.4.1 (2026-09-27). A listed name created
    inside `node_modules` is among them.
  - No rule refuses moving a directory out of one that a `writable` line names while leaving
    npm's renames and `rmdir` inside it. `doc/file-rules.md`, "Under `--run-on-host`", states the
    limit.
  - The deny is stricter than the filter in one respect: it also refuses the entry's `mkdir`, and
    the entry's `rmdir` once empty, because SBPL checks those two as it checks a rename's two
    sides.
- **Below the target of a symlink that the rules reach, the profile keeps denying what a
  `writable` line lifts under the symlink's name**, where the filter allows it. An example target
  is `shared/claude` for `.claude -> shared/claude`.
  - Rendered as a later allow, the lift would also apply under the target's own name. With
    `.claude -> .vscode/claude`, the lift would open part of `read-only .vscode`.
- **The `.git` and `.ko-agent-sandbox` denials cover link creation, not only writes.** Without
  them, a command could create `link(WORKSPACE/.git/config, WORKSPACE/x)` and write through `x` to
  modify `.git/config`.
  - Both paths are on the workspace's host filesystem, so a filesystem boundary does not prevent
    this.
- **Commands can create a bare Git layout from ordinary names in the writable tree.** Neither the
  Seatbelt profile nor the workspace filter refuses those names.
  - Running host `git` inside a directory the agent created runs the agent's output. `SECURITY.md`
    records the same gap for the workspace filter.
- **Each command gets a fresh directory, which holds the command's temporary directory under sbt
  and Maven.** A killed command can leave its directory behind. The next command reclaims that
  directory rather than reusing it (`RunOnHostSession.scala`).
  - A mill or gradle command's `TMPDIR` is the runner's `tmp/` ("The command's lifetime and
    environment").

## Network

The command's only egress is its proxy (below):

- Seatbelt permits connections to the proxy's port and nothing else. The grant reaches the port at
  every address of this host, and the proxy listens on the loopback address.
- UNIX-domain sockets are permitted only inside the command's temporary directory. An sbt client
  is also permitted them inside the runner's temporary directory, where the sbt server listens.
- A port grant reaches this host's other services the same way, so no other port is granted.
- No listener is granted except the mill daemon's and Gradle's. A test suite that binds a listener
  gets `EPERM` on the host under sbt and Maven, and runs in the container. The proxy's wire-relay
  tests bind a listener.
  - Under `mill` and `gradle`, such a suite runs on the host. The daemon's listener grant covers
    every port at every address of this host, and everything the daemon forks inherits the grant
    (`SECURITY.md` "Run on host" states that cost).

Every profile grants binding and connecting UNIX sockets under the command's own `tmp/`, or under
the runner's `tmp/` for a server or daemon that the runner starts. The table lists each program's
grants beyond that (`SeatbeltProfile.Network` is the typed input the dispatch shows):

| process | network |
|---|---|
| sbt server | the proxy's port |
| sbt client | the proxy's port, plus connects under the runner's `tmp/` |
| `mill` daemon | the proxy's port; listeners, any port, any address of this host (below) |
| `mill` client | the proxy's port, and the daemon's one port |
| `gradle`, client and daemon | the proxy's port; listeners and connects on any port of this host |
| Maven | the proxy's port |

Gradle's row holds both grants, where `mill`'s client has one port:

- Gradle's daemon, its workers and its file-lock socket (`DefaultFileLockCommunicator`, UDP) each
  bind port 0 and connect to each other's ports.
- No supported Gradle setting fixes any of those ports.
- Confining them would mean patching Gradle or instrumenting its JVMs, which this launcher does not
  take on.

Seven rules are measured, and none is chosen from documentation (`src/probe/loopback-rule.sh`,
`src/probe/jvm-proxy-rule.sh`, `src/probe/run-on-host-runner-session.sh`):

- The proxy rule is `(remote ip "localhost:<port>")`. The compiler refuses an ip-literal host
  ("host must be * or localhost").
- The "localhost" class covers native `127.0.0.1` and `::1`, but not a JVM's dual-stack connect.
  - That connect reaches `127.0.0.1` as the v4-mapped `::ffff:127.0.0.1` and dies with `EPERM`.
  - The command's environment sets `-Djava.net.preferIPv4Stack=true` for exactly this case.
- Seatbelt counts a local socket as network. Without `(local unix-socket (subpath SESSION_TMP))`,
  sbt's server gets `EPERM` from `bind()` on its boot socket, and its client waits for the server
  forever ("The channel and the command" has the client's wait).
- The mill daemon's `(local ip "localhost:*")` admits a port-0 bind and accept, and no rule
  confines a port-0 bind to one port (L1–L4).
- The `localhost` class is this host's addresses, not loopback (G1, G4–G10):
  - under that rule, a bind to the wildcard or to the LAN address is admitted, and the socket
    answers at the LAN address, over TCP and UDP;
  - `(remote ip "localhost:*")` connects to the LAN address too;
  - no spelling names loopback alone, since the compiler takes no other host.
- A client's `(remote ip "localhost:<port>")` reaches that port at every address of this host
  (G11), and is denied the neighboring port (L3, L4, M3).
  - Only the JVM launcher connects under that rule. The native image's connect is dual-stack, for
    the reason above, and stays denied with the property on its command line (M2).
  - That is why the supervisor runs the JVM launcher ("`mill`").
- The sbt client's `(remote unix-socket (subpath <runner tmp>))` must reach the boot socket and
  the server socket exactly (S6).
  - A client whose connect is denied does not fail. The client deletes the portfile and forks a
    server under its own profile (`NetworkClient.connectOrStartServerAndConnect`).
  - That server dies at its boot-socket bind. The client takes the exit for a server still
    booting, and waits without bound.

The proxy settings handed to the JVM are a convenience, not the boundary. Seatbelt prevents bypass
through direct sockets, and the acceptance test's bypass rows measure that.

Every command's proxy allows one host without a rule line: the program's Maven Central
(`RunOnHostPrereqs.centralHost`).

- For sbt and `mill`, which resolve through Coursier, that host is `repo1.maven.org`. For Gradle,
  whose `mavenCentral()` names the alias, and for Maven, whose super POM names it, the host is
  `repo.maven.apache.org`. Each program resolves against its own host and never against the
  other's.
- A Gradle build that applies a plugin by id resolves the plugin from `plugins.gradle.org`, which
  redirects artifact downloads to `plugins-artifacts.gradle.org`. A rule file naming the plugin
  portal names both hosts.
- `repo.scala-sbt.org` is deliberately absent. That host serves the Ivy-style plugin repository
  and is not part of sbt's bootstrap: an uncached sbt version named in `project/build.properties`
  resolves from Maven Central.

A command that needs another host gets it only through an explicit rule line ("Configuration",
below). Nothing is inferred or silently permitted.

## Refusals

Missing prerequisites and denied accesses fail with a clear message. Nothing expands authority,
and nothing falls back:

- A host command that cannot run is reported to the user and never rerun in the container. The
  egress refusal follows the same rule.
- The one exception is a test suite that binds a listener under sbt or Maven, which runs in the
  container ("Network", above).

The refusals and denials take these forms:

- A prerequisite refusal before the command starts is a `RunOnHostPrereqs.Refusal` value, one
  case per category, or a sentence from the step that met it (`StepRefusal`).
  - The supervisor, the channel and the launch each word a `Refusal` for their own readers.
- A runtime that the runner cannot prepare is refused with its reason, as text from the code that
  met it (`RunnerRuntimes.prepare`). Examples are a proxy, server or daemon that fails to start,
  and the launcher's executable gone.
- A denial while the command runs falls under no refusal category:
  - A filesystem denial reaches the command's own stderr as the OS error.
  - A network denial is the proxy's audit line. After the command, the supervisor reads those
    lines and reports them per host ("Command requested network access to: …").
    - The supervisor reads the log from its length at the command's start, so a shared proxy's
      earlier denials are not reported as this command's.
    - The supervisor never adds the host itself.
  - A request that the proxy refuses inside a tunnel, such as a `PUT`, a `POST` or a `GET` with a
    body, gets a `403`. The programs need not print the `403`'s body, so the supervisor reports
    each request with the audit line's reason ("Command sent requests the host command sandbox
    refuses: …", `RunOnHostProxy.refusedRequests`).
    - Some refusals the command answers by changing the request: a body framing header on a
      `GET`, a `Host` header naming another host, `Upgrade`, an absolute target, or a path spelled
      with percent-encoding. Those refusals also get the step that the `403` body had
      (`RefusalAdvice.requestStep`).
    - A refusal for want of a grant gets the user's step: run the command yourself, outside the
      sandbox. The rule file takes no grant but `read`.
  - A proxy whose log write failed serves nothing (`SECURITY.md`, "Egress proxy"). That proxy
    cannot say so in its log, and the programs need not print the reason.
    - After a command that exits non-zero, the supervisor asks the proxy with `OPTIONS *` and
      `Max-Forwards: 0` (`RunOnHostProxy.unwritableProxyLog`).
    - The supervisor reads the reason from the response's `Proxy-Status` field, and reports it
      with the path of the proxy's file in the run's log directory.
    - A proxy still logging answers `400` and logs `deny - - OPTIONS non-CONNECT request`.
    - sbt 2.0.9 and mill 1.0.6 print the status line alone, measured against a proxy answering
      `403` with a marked `Proxy-Status` and body. Gradle and Maven are not measured:

          Unable to tunnel through proxy. Proxy returns "HTTP/1.1 403 Forbidden"

## Program prerequisites

One rule explains all four programs: **the user provisions the executable; the sandbox fetches only
artifacts.**

- sbt's executable comes from `cs install sbt`. Everything else sbt needs is a jar the JDK reads,
  fetched into the writable run-on-host cache through the proxy.
- `mill`'s executable *is* the fetched artifact, so the user provisions it and the sandbox does
  not fetch it. A version bump is then an explicit host update, not an automatic update that the
  build definition performs.
- The JDK that a `mill` build's daemon runs on is an executable Mill would download, so the user
  provisions it too ("`mill`"). The exception is a `mill-jvm-version` of `system`.
- Gradle's and Maven's executables are the distributions the workspace's wrappers unpacked on the
  host.

`RunOnHostPrereqs.scala` validates these prerequisites before a command starts. A violation is a
refusal naming what to fix. `src/probe/host-layout.sh` shows what a host actually has.

The launch checks `mill`'s, Gradle's and Maven's prerequisites before its start prompt
(`RunOnHostProvisioning.scala`). So you meet a launcher, JDK or distribution not yet provisioned at
the launch, and the agent does not meet it at the first command. sbt has nothing to check: its
executable is the one `cs install sbt` produced, whatever the workspace pins.

- The launch finds every build directory of the selected programs, and resolves each directory's
  executable as the directory's first command would. The launch prints each refusal in the
  command's wording.
  - A `mill` or Gradle build directory holds a `mill` bootstrap or a Gradle wrapper's properties
    file: the files the supervisor keys a build directory on ("`mill`", "Gradle").
  - The search covers the whole workspace, except inside `.git`, `.ko-agent-sandbox` or a symlink.
  - Maven's build directory is the workspace root alone, holding `mvnw` ("Maven").
  - `gradlew` is only what the run below executes: a properties file without `gradlew` is
    reported, with nothing to run.
- For the refusals a host run fixes, the prompt shows that run and runs it on an explicit `y`,
  unconfined and in the launcher's environment. Those refusals are a launcher, a JDK or a
  distribution not yet provisioned. The prompt turns the run that the refusal asks you for into
  one answer (`SECURITY.md`, "Run on host").
  - The run is `MILL_VERSION=<v>-jvm ./mill version`, `./gradlew --version` or `./mvnw --version`
    in the build directory, shown in full.
  - The whole question is tinted orange, because the question is the grant, as `run-on-host: sbt`
    is on the launch's line (`HostCommands.weakened`).
  - The launch judges each build directory when its turn comes, so one run that provisions a
    version two directories share is asked once.
  - The check repeats after the run, so a script that exits zero without provisioning is reported
    at once.
- A launch that does not wait at a start prompt, with no terminal or with
  `--session-start=immediate`, prints the refusals and runs nothing.
- The launch cannot see a pin changed during the session, or a build directory created later. The
  first command refuses such a case, naming the same run, and a relaunch prompts for the run.

### The JVM

Only Coursier-managed JVMs are accepted.

- `JAVA_HOME` names the JDK, and must resolve to one canonical JDK home under the user's Coursier
  cache root.
- The one other source is the JDK that Mill's launcher resolved for a `mill` build's daemon, from
  a pinned or unset `mill-jvm-version`. That JDK passes the same checks ("`mill`").
- `java` on `PATH` is `/usr/bin/java`, a macOS stub that resolves through `JAVA_HOME` or
  `/usr/libexec/java_home`. The stub reports the right JVM while being the wrong path.
- Rejected: the stub, `/Library/Java/JavaVirtualMachines`, Homebrew and SDKMAN JVMs, and a
  `JAVA_HOME` resolving outside the Coursier cache.

A current Coursier unpacks a JDK into its archive cache, so the home is a URL-derived path under
`arc/` with a percent-encoded `+` in it.

- The grant is that resolved home. Granting the `arc` root instead would hand the command every
  archive Coursier ever extracted.
- The JDK is read-only to the command, so sharing the user's copy exposes no write path.
  Duplicating the JDK per workspace would cost hundreds of megabytes for nothing.

### sbt

The executable comes from `cs install sbt`; an arbitrary `sbt` from `PATH` is not used.

- The supervisor verifies that the executable belongs to the Coursier application-install
  directory. On macOS that directory is `~/Library/Application Support/Coursier/bin`, whose space
  makes correct shell quoting necessary.
- That `sbt` is two files. The 1.2 KB script on `PATH` execs a second `sbt` inside an unpacked
  distribution in the archive cache.
  - The profile grants the distribution's *home*, because the distribution's `sbt` reads
    `sbt-launch.jar` and `conf/` relative to itself.
  - The supervisor reads the home from the script's text (`RunOnHostPrereqs.sbtDistribution`).
    Running the script to ask would execute, on the host and unconfined, what the profile exists to
    contain.

sbt 2 is client/server by construction and has no one-shot mode, so the runner starts the server,
and each command's client then attaches to it. The server runs:

- inside the server profile, with the build directory as its working directory;
- with the runner's own `tmp/` as its temporary and socket directory;
- with the command line sbt's thin client uses when it starts a server, given the request's
  launcher flags as that client forwards them, less those naming a program ("Where a host command
  deviates from the stock program" lists both);
- with its output in a file in the runner's session directory ("The channel and the command").

The runner starts the server, not the client, which forks a server itself when the portfile names
none. A server the client forks inherits three things that a server outliving the command must
not inherit:

- the client's profile, whose temporary-directory grant names a directory removed with the
  command;
- the client's environment, whose `java.io.tmpdir` and `XDG_RUNTIME_DIR` name that directory;
- the client's process group, which a cancel ends.

The server's state follows `-Dsbt.global.base` into the workspace's run-on-host cache.

- The base must persist across commands. sbt 2 leaves `target/` outputs as symlinks into its
  content-addressed store, so removing the base when the command ends would leave the build's own
  outputs dangling.
- The same fact causes the opposite problem: a tree that the user's unconfined sbt built links
  into a store the profile denies.
  - So the runner sweeps the `target/` symlinks that resolve outside the granted roots before it
    starts an sbt server.
  - The sweep runs after any foreign server for the directory is shut down, with that server's
    build finished, so a sweep never runs during the user's own build.
- `~/.sbt/boot` is not granted and has no consumer. With the global base redirected, sbt boots
  from the run-on-host cache, which stays warm across sessions.
- `~/.sbt/1.0`, `~/.sbt/2.0` and `~/.m2` are not granted either.
- sbt 2 also registers each server under the base's `cache/proc`. When a client disconnects, sbt
  asks the servers registered there to exit if idle (`CommandExchange.notifyOtherServers`). So the
  redirect keeps your servers and the launch's out of each other's registry.

The Ivy home follows `-Dsbt.ivy.home` into the run-on-host cache the same way, and `~/.ivy2` is not
granted. sbt uses that home for three things, read from the sources of sbt 1.13.0 and 2.0.9:

- resolving a dependency between the projects of one build goes through Ivy
  (`projectDescriptors`), and Ivy takes the lock file `<ivy home>/.sbt.ivy.lock` first;
- `<ivy home>/local` is the `local` resolver, which every resolution reads and `publishLocal`
  writes;
- `updateSbtClassifiers` keeps its excludes file there.

Without the redirect, an sbt 1.12.13 `packageBin` of a build with a `dependsOn` edge dies under
the profile, while canonicalizing the denied `~/.ivy2` for that lock.

- This repository's own build has no such edge, so the acceptance test's sbt rows never reach that
  path.
- `src/probe/ivy-fixture` is such a build, on sbt 1.

sbt 2.0.9 keeps the Ivy library and the lock. sbt 1.13.0 and 2.0.9 name the lock file by the same
steps, so the sbt 1 row measures the redirect for both, and the fixture has no sbt 2 copy:

1. `-Dsbt.ivy.home` sets `ivy-home` in the sbt launcher's `sbt.boot.properties`;
1. `Defaults.bootIvyHome` reads it from the sbt launcher into `ivyPaths`;
1. `IvySbt` passes `ivyPaths.ivyHome` to Ivy's `setDefaultIvyUserDir` and names
   `.sbt.ivy.lock` under `getDefaultIvyUserDir` (`Ivy.scala`: sbt's own `lm-ivy` at v2.0.9,
   librarymanagement-ivy 1.12.3 for sbt 1.13.0).

sbt 2.1.0-M1 has no Ivy library (sbt/sbt#9615, merged into `develop` 2026-08-24) and takes no lock.

- So the fixture retires when sbt 1 and sbt 2.0 do.
- sbt 2.1.0-M1 still takes `local` and the excludes file from `sbt.ivy.home`, so the redirect and
  its grant stay after the lock is gone.
- Retire the redirect and its grant only when a released sbt stops deriving those two paths.
  Check that by reading `Defaults.scala` again, not by an acceptance-test run.

Two more settings concern how sbt starts:

- The supervisor passes `--jvm-client`. sbt 2 defaults to `sbtn`, which under the profile prints
  that it is starting the server and returns with no build run.
  - An acceptance-test row keeps measuring `sbtn`. If that row starts passing, the supervisor can
    reconsider requiring `--jvm-client`.
- The distribution's `sbt` resolves `java` from `PATH`, so the environment puts the granted JDK's
  `bin` first. The runner starts the server by running the script, and `-java-home` reaches the
  client alone.

### `mill`

The executable is a workspace-local bootstrap script, the build directory's own `mill`; a globally
installed `mill` is not used.

- The supervisor runs the bootstrap with `MILL_VERSION` naming the JVM launcher of the pinned
  version, `<v>-jvm` (`RunOnHostPrereqs.millLauncherVersion`).
- That launcher must already be provisioned: run `MILL_VERSION=<v>-jvm ./mill version` once on the
  host whenever the pinned version changes. The launch offers that run at its start prompt
  ("Program prerequisites").
  - `mill` 1.x fetches its launchers as executables. A fetch from a command would put an
    executable that the sandbox chose into a directory that the user's own `./mill` runs from,
    outside any sandbox.
- The grant is that one file, `<download folder>/<v>`, never the download folder around it, which
  holds every launcher the user ever ran.
- A version whose JVM launcher the user never provisioned is a refusal naming the command to run.

The launcher is the JVM one, not the native image that the bootstrap runs for a version with no
suffix, because the image takes no `_JAVA_OPTIONS`:

- the environment's `preferIPv4Stack` never reaches the image;
- the image's connect to the daemon is the dual-stack one that the "localhost" class denies
  ("Network");
- the property on the image's command line changes nothing (measured,
  `src/probe/run-on-host-runner-session.sh` M2).

A `<v>-native` pin asks for that image by name, and is refused with the reason.

The supervisor resolves the version the way the bootstrap does, from the build directory
(`RunOnHostPrereqs.millVersion`): `.mill-version`, `.config/mill-version`, `build.mill.yaml`, the
build script's `//|` header, then the script's own default. So a nested build directory with a
bootstrap of its own is another build.

- The supervisor does not read the script's `MILL_VERSION` and `DEFAULT_MILL_VERSION` environment
  overrides. The command's environment carries the supervisor's own `MILL_VERSION` and no other,
  so the script and the supervisor resolve alike.
- Reading the version is a read. Asking the script by running it would execute agent-authored
  shell on the host.
- `mill-jvm-version` in the build directory is `system`, one JVM id such as `temurin:25`, or unset
  (`RunOnHostPrereqs.millJvm`).
  - `system` makes the daemon's JVM the granted JDK, the first `java` on the command's `PATH`.
  - An id runs the daemon on the JDK that a host run provisioned ("A pinned JVM" below).
  - From Mill 1.1.0 on, unset runs the daemon as an id does. Before Mill 1.1.0, unset is refused
    ("An unset `mill-jvm-version`" below).
  - Mill's launcher, the client, runs on the granted JDK in all three cases.

Mill is client/daemon by construction. The launcher starts a daemon, the daemon binds a port of the
kernel's choosing on the loopback address and writes the port to `out/mill-daemon/socketPort`, and
the launcher connects (`Server.scala`, `ServerLauncher.scala`, Mill 1.1.10). From Mill 1.2 on, a
command runs without a daemon ("Mill 1.2 and later: no daemon").

The runner starts the daemon itself, before the first `mill` command of a build directory, and
every command from that directory attaches to the daemon (`RunOnHostMillDaemons.scala`,
`RunnerRuntimes`):

1. The **starter** is the build directory's `./mill version`. The runner starts it through
   `registeredSpawn` in the runner's session (`records/daemon-mill-<hash>`), under the daemon
   profile, with the closed environment and the runner's `tmp/` as its temporary directory. The
   daemon profile grants listeners and no outbound but the proxy.
   - The launcher starts the daemon, and the daemon binds its port and writes `socketPort`. The
     launcher's own connect is denied: the daemon inherits the starter's profile, and the only
     outbound grant that would admit the connect is outbound to every port of this host
     (`SeatbeltProfile.Network.MillDaemon` has the reasoning).
   - Once `lsof` shows the daemon listening on the port that `socketPort` names, the runner ends
     the launcher. The runner sends TERM to the launcher's pid alone, after checking the pid and
     start time; the launcher is the daemon's parent in the group.
   - Without that observation, the launcher retries for ten seconds and exits nonzero. A launcher
     that the TERM does not end reaches that bound too. Either way the daemon stays in the
     leader's group (measured, M1 for the exit, M8 for the TERM: the daemon is spawned with
     `destroyOnExit = false`).
   - The group is three processes: the leader, the launcher JVM as the leader's child, and the
     daemon as the launcher's child. `sandbox-exec`, the bootstrap and the assembly's shell prefix
     each `exec`, so they add no process. After the TERM the daemon is reparented while the leader
     stays, and the runner checks the leader's start time before it ends the group (M8).
   - The starter's output goes to `daemon-mill-<hash>.log` in the session directory, which is the
     finding when a start fails. A starter that neither ends nor writes anything for two minutes,
     while the proxy log does not grow either, is a failed start.
2. The **daemon** is the member of that group whose command line names
   `mill.daemon.MillDaemonMain`. From then on, the runner checks the daemon by its pid and start
   time.
   - The runner reads `socketPort` as a candidate, an integer in port range and nothing more. The
     runner grants the port only after `lsof` shows that pid listening on it.
   - The file is the build's to write and authorizes nothing. A candidate that the daemon does not
     listen on refuses the start.
3. Each command's **client** runs `./mill <args>` from the build directory under the client
   profile, with the runner's `tmp/` as its temporary directory ("The command's lifetime and
   environment" explains why). The client profile admits outbound to that one port and to the proxy.
   - The launcher reads `socketPort` and connects. A port planted in the file is one the profile
     denies, so the command fails and the daemon is untouched.

The daemon gets each command's environment through the protocol (`DaemonRpc.Initialize`), so the
closed environment reaches the build per command. The daemon JVM's own options, the proxy settings
included, are the starter's, fixed at the daemon's start.

The runner replaces the daemon under the same proxy before the next command in the cases below.
The runner first ends the old daemon's group, including the starter's leader, which stays until
then.

- What Mill's launcher restarts the daemon on has changed (`RunOnHostPrereqs.millDaemonConfig`):
  - the launcher version and the resolved JVM;
  - `mill-jvm-opts` and `mill-repositories`, each from the source Mill reads it from;
  - the build file's header, taken whole;
  - under a pinned or unset `mill-jvm-version`, the text of Mill's `java-home` file.
- The daemon is gone on its own:
  - Mill's idle exit, thirty minutes after its last client;
  - `ko-sandbox-run-on-host mill shutdown`;
  - a client's disconnect mid-command, on which the daemon shuts itself down (measured, M5). An
    sbt server survives the same disconnect.

The runner compares what Mill's launcher restarts the daemon on before each command, with the
launcher assembled afresh, since a changed pin grants another launcher. The stock client meeting
the mismatch would end the daemon and start a replacement from its own profile. That replacement
cannot bind, and the command would fail.

Mill's idle exit counts from the last client's disconnect, and a daemon that no client has
connected to yet never expires (`Server.ConnectionTracker`). So a starter's daemon whose first
command never comes lives until the launch ends.

`out/mill-daemon` is Mill's. The runner neither clears nor writes it, beyond the classpath file
below, and reads only the port candidate and that file.

- The `launcherLock` there names the ended starter until the next client.
  - `launcherLock` is a pid lock (`PidLock`, `pid:start`) that the launcher deletes on its own
    exit, which the TERM skips.
  - A client's launcher finds that pid dead and replaces the lock.
- A command is refused while `out`, `out/mill-daemon` or an entry directly in it is a symlink or a
  file with a second name (`RunOnHostMillDaemons.rendezvousIsOwn`).
  - The launcher acts on that directory as it finds it. The launcher removes a `processId` whose
    fingerprint differs, which ends the daemon the `processId` names.
  - A link would point the launcher at another build directory's daemon, past the ownership and
    idleness checks, which this directory keys.
- That refusal catches a link already planted. No check before the command catches a link made
  after the check, by the bootstrap script or by build code running in the daemon; the build lock
  excludes neither.
  - The profile bounds that case: the launcher writes only where the command may write. So the
    daemon that such a link can end is one whose `out/mill-daemon` lies under the command's
    writable roots: this workspace, its run-on-host caches and the runner's `tmp/`.
  - That daemon is this launch's for another build directory, another launch's on this workspace,
    or yours. The one-port rule keeps the client from attaching to it.
- The supervisor never forwards `MILL_OUTPUT_DIR` or `MILL_BSP_OUTPUT_DIR`, since every check looks
  under `out/`.
- Mill's launcher writes the daemon's classpath to `out/mill-daemon/cache/mill-daemon-classpath`,
  and reuses that file while every path it names exists. The runner deletes the file before a
  start when it names a path outside the cache that the profile grants
  (`RunOnHostMillDaemons.discardForeignClasspath`).
  - Seatbelt answers an existence test for a path it denies reading: measured, `Files.exists` is
    true and the open is denied. A file from an unconfined run, or from this directory served as
    another workspace's build directory, would start a daemon on jars it cannot open, and the
    daemon dies before it listens.
  - With the file deleted, Mill's launcher resolves the classpath afresh through the proxy into the
    granted cache.
  - The read and the delete run under the daemon profile. So a link planted under `out/` after the
    rendezvous check sends neither past what the build could write.

A daemon of yours for the build directory, from a terminal outside any launch, is ended before the
runner's daemon starts, as your sbt server is shut down. The channel log says so.

- The runner finds the daemon in the process table by its command line and by its working
  directory under `out/mill-daemon`, never through `processId`.
- The runner ends the daemon once idle, by TERM then KILL, after checking its pid and start time.
  - Idle means no established connection on its port, observed through `lsof`.
  - The runner repeats the start-time check immediately before the signal.
- A daemon busy past two minutes is a refusal naming it.
- Between the observation and the signal a terminal `./mill` can still connect, and its command
  then dies with the daemon. No observation closes that window.

A daemon that another launch owns, whose runner's session holds `daemon-mill-<hash>`, is attached
to, or ended by that record and replaced, as that launch's sbt server is ("The channel and the
command").

- Attaching needs the daemon alive under the build directory's present configuration. So after an
  edit, or after the daemon's own exit, the command ends what the record still names, the
  starter's group, and starts its own daemon.
- The reverse holds too. While the launch's daemon lives, your own `./mill` with matching settings
  attaches to it and runs your build under the profile and the launch's proxy.
  - Your `./mill` with different settings ends the launch's daemon, as Mill does on a fingerprint
    mismatch. The runner then ends your daemon once idle and starts its own again.
- Suppose the registered leader alone was killed, not the runner. The daemon then remains in a
  group whose leader the scavenger cannot check, and no portfile attributes it. The daemon exits
  on Mill's idle timeout.

#### Mill 1.2 and later: no daemon

From Mill 1.2.0-RC1 on, the supervisor runs `./mill --no-daemon <args>`, and the runner starts no
daemon. The build directory's runtime is its proxy (`RunOnHostPrereqs.millRunsWithoutDaemon`).

- Mill's daemon reads each launcher's start time with `ProcessHandle.info()`
  (`LauncherOutFilesRecordStore.write`, com-lihaoyi/mill#6955). On macOS the JDK throws when the
  profile refuses `kern.procargs2.<pid>`, and every command fails with "Mill launcher failed"
  (`upstream-issues.md`, openjdk/jdk and com-lihaoyi/mill).
- The daemon's profile cannot allow that read. The profile is fixed when the daemon starts, before
  any launcher's pid exists. Allowing every pid would let the build read the arguments and
  environment of every process of the user ("The Seatbelt profile").
- Without a daemon the build runs as the launcher's child, inside the launcher's sandbox, where the
  rule allows the read.
- The command gets the daemon's network grant, listeners and no outbound but the proxy
  (`SeatbeltProfile.Network.MillDaemon`), so the build binds what it would bind under a daemon.
  The command gets no daemon port and no `kern.procargs2` exception.
- Mill reads `out/mill-daemon/cache/java-home` in this mode too (`CoursierClient.cacheDir`, 1.3.0),
  so "A pinned JVM" and "An unset `mill-jvm-version`" apply unchanged.
- Mill reads `out/mill-daemon/cache/mill-daemon-classpath` in this mode too, and a host run can
  rewrite the file between commands. So before each command the supervisor deletes a file naming
  paths outside the granted cache, as a daemon's start does
  (`RunOnHostSandbox.discardForeignClasspathWithoutDaemon`).
- Mill takes `out/mill-out-lock` for each command's build (`SharedOutLockManager`, 1.3.0). So an
  idle daemon of yours does not block the command, and the runner leaves that daemon alone.
- While a process holds that lock, such as a build of yours, the supervisor waits up to two
  minutes, the time a busy daemon of yours gets. The supervisor then refuses, naming the lock
  (`RunOnHostSandbox.awaitMillOutLock`).
  - Mill's own wait would read the start time of the launcher that a build through your daemon
    records, and that read throws here. A build of yours without a daemon records none.
  - The probe takes a shared lock and releases it at once, after the same no-follow, time-bounded
    open that the `java-home` file gets (`RunOnHostSandbox.millOutLockHeld`).
  - A build through your daemon that takes the lock after the probe, while the command starts,
    fails the command with "Operation not permitted". No probe before the command closes that
    window. The supervisor then names the lock's holder and says to retry
    (`reportMillOutLockTaken`).
- Each command starts its own JVM, and the supervisor says so on the command's stderr.
  - Measured on Mill 1.3.0 with the fixture through a launch's runner, under the client profile
    with the runner's daemon unused (2026-10-19): the first `__.compile` took 71 s, then
    `__.test` 4.0 s, and a `__.compile` with nothing to compile 5.8 s.
  - A warm daemon's times are unmeasured.

#### A pinned JVM

Run `MILL_VERSION=<v>-jvm ./mill version` once on the host in the build directory, the same run
that provisions the launcher. The start prompt offers it, and a command refused for the JDK names
that run.

- Mill's launcher resolves the id through Coursier's index, downloads the JDK into the user's
  Coursier archive cache, and writes the JDK's home to `out/mill-daemon/cache/java-home` with a
  key naming the id (`CoursierClient.resolveJavaHome`, Mill 1.1.10). A command may neither fetch a
  JDK nor write that cache, so the host run does both.
- The supervisor grants the home that the file records, read-only, when the home passes the checks
  `JAVA_HOME` passes ("The JVM"). The supervisor refuses the command when the file is absent or
  records another id (`RunOnHostPrereqs.millRecordedJdk`).
- A file recording a home that fails those checks is refused, with the instruction to delete the
  file first. Mill keeps a file whose key matches, so the run alone would change nothing.
- The launch, the supervisor and the runner read the file outside any profile, while a command may
  be writing under `out/` (`RunOnHostSandbox.millJavaHomeText`):
  - each directory below the build directory, then the file, is opened relative to the one before
    it and never through a symlink, whatever a command renames meanwhile;
  - the read stops at 256 KiB and is abandoned after two seconds, so neither a growing file nor a
    FIFO moved into the file's place holds the runner;
  - an abandoned read keeps a thread and its open directories, so at most four reads run or stay
    abandoned at once; past that, the file reads as absent until one read returns;
  - the text is never printed.

Measured under the command profile with no proxy running (`src/probe/mill-pinned-jvm.sh`, macOS
26.4.1, Mill 1.1.10, `temurin:21`, 2026-10-02):

- With the file present and its home granted, Mill runs that JDK, fetches nothing and leaves the
  file as it is.
- With the file absent, under another key, or with its home not granted, Mill resolves the id
  again and fails at its first fetch, the JVM index.
- Mill runs whatever directory the file names under the id's key: a file naming `JAVA_HOME`'s JDK
  runs that JDK.

What the supervisor's check leaves open:

- A command can write the file, so the command chooses which JDK in the user's Coursier cache the
  daemon runs on. The checks keep the grant to a JDK the user provisioned, read-only, and what
  runs on that JDK stays under the profile.
- The key also holds the JVM index version and `mill-repositories`. The index version is Mill's
  own default unless the build sets one.
  - The supervisor compares neither, so a file that Mill itself rejects on those passes the check,
    and the command fails at Mill's fetch. The host run rewrites the file.
- A module's own `jvmVersion` is resolved by a task inside the daemon (`JavaHomeModule`, read in
  Mill 1.1.10's source, not measured), so that JDK is neither fetched nor granted.

#### An unset `mill-jvm-version`

From Mill 1.1.0 on, "A pinned JVM" applies to a build directory that sets no `mill-jvm-version`.
The same host run provisions the JDK, and the supervisor grants the home that the `java-home` file
records, under the same checks.

- Before Mill 1.1.0, an unset version is refused: set `system` or an id
  (`RunOnHostPrereqs.millUnsetJvmAccepted`).
  - Mill 1.0.0 and 1.0.6 run `java` from `PATH` when `which java` finds one, and resolve their
    built-in id otherwise (read in their source). No file records which of the two a run took.
- Mill's launcher resolves an unset version to the id built into it, through the call that
  resolves a pin (`MillProcessLauncher.javaHome`, `BuildInfo.defaultJvmVersion`).
  - The id is `zulu:21` in Mill 1.1.0, 1.1.5 and 1.1.10, and `zulu:25` in 1.3.0, read in their
    source and the 1.1.0 changelog. An unset version is not measured under the profile.
- The supervisor does not read that id, so it accepts the `java-home` file under any key.
  - A file that an earlier pin or another Mill version wrote passes the check. Mill then resolves
    its built-in id again, and the command fails at Mill's fetch. The host run rewrites the file.

### Gradle

The executable comes from the build directory's own wrapper properties,
`gradle/wrapper/gradle-wrapper.properties` there, read as `./gradlew` run there would read them. A
globally installed `gradle` is not used.

- A nested build directory with a wrapper of its own is another build, as under `mill`.
- Run `./gradlew --version` once on the host, and again whenever `distributionUrl` changes. That
  run downloads Gradle into `~/.gradle/wrapper/dists`. The launch offers the run at its start
  prompt ("Program prerequisites").
- The command is granted that one Gradle, read-only. The command is not granted the whole `dists`
  directory, which holds every Gradle the user ever ran a wrapper for.
- If the wrapper has not downloaded that Gradle yet, the command is refused, and the refusal says
  what to run.

The command runs the distribution's `bin/gradle` in the working directory, not `gradlew`, which
would download. The supervisor computes the distribution directory exactly as Gradle's wrapper
does (`RunOnHostPrereqs.gradleDistributionDir`, from Gradle 9.8.0's `PathAssembler`):

1. `distributionUrl` read as `java.util.Properties` reads the file, a value without a scheme
   resolved as a file against the properties file's directory;
1. the URL's file name without its extension, then the URL's MD5 as a base-36 number, under
   `$GRADLE_USER_HOME/wrapper/dists`, or `~/.gradle/wrapper/dists` when `GRADLE_USER_HOME` is
   unset in the launcher's environment;
1. the home is the one directory inside.

`distributionBase` and `distributionPath` must be the wrapper's defaults, and the build directory's
`gradle.properties` must not set `systemProp.gradle.user.home`. Each of those settings moves the
distribution to a place the workspace chooses, and the executable is the user's to provision.

- The command's own `GRADLE_USER_HOME` is under the run-on-host cache ("The run-on-host cache"), so
  Gradle's caches are the workspace's own.
- The daemon registry is the launch's own, not the user home's
  (`RunOnHostSandbox.gradleCommand`).
  - `org.gradle.daemon.registry.base` on the command line names a directory under the runner's
    `tmp/`. Every Gradle process of the launch is granted that directory, and the directory ends
    with the launch.
  - `gradle --stop` stops every daemon in a registry, whatever its JVM (`DaemonStopClient`). A
    registry under the per-workspace home would let one launch's `--stop` end another launch's
    builds on the workspace.
- Attaching is the launch's own either way. The client's `java.io.tmpdir`, the runner's `tmp/`, is
  among the immutable properties that Gradle's daemon compatibility check compares
  (`InitialPropertiesConverter`, `DaemonCompatibilitySpec`). So a daemon started under another
  launch is never compatible.
- Your own daemons under `~/.gradle` are in neither registry.

The daemon is Gradle's own. The first command's client starts the daemon under the command's
profile, and later commands attach to it through Gradle's own matching, inside the profile.

- A client disconnected mid-build cancels the build, and a daemon still busy ten seconds later
  stops itself (`DaemonStateCoordinator`, `WatchForDisconnection`).
- The daemon detaches itself into a group of its own (`DaemonMain`, `setsid`), where its workers
  and test executors are forked. So ending the client's group leaves the daemon alive, and the
  runner ends the daemon by its recorded pid and start time (`RunOnHostGradleDaemons.scala`).
- After each command, and once more at the launch's end, the runner records every daemon started
  with the launch's environment, by pid and start time, as `records/daemon-gradle-<pid>`.
  - The runner forgets the record of a daemon that is gone.
  - The launch's end signals the group behind each record, as it does every recorded group.

A daemon's initial environment identifies it as the launch's. The client starts the daemon with
that environment (`DefaultProcessForkOptions`), and the runner reads it with `ps -E`: its
`_JAVA_OPTIONS` names the runner's `tmp/` as `java.io.tmpdir`. No process outside this launch's
commands was started with that value.

- No path identifies the daemon. The build writes across `tmp/` and the workspace. A file that a
  daemon of yours holds open, the daemon log included, can be renamed into the registry under any
  name, and the kernel then reports the file at that name.
- `ps -E` reads the strings from the daemon's own memory (`sysctl_procargsx`). So build code in the
  daemon can rewrite them and hide the daemon from its own launch, and from nothing else.
- Some daemons no observation reaches: one started under a runner that died during the command, or
  one hidden that way.
  - Such a daemon is confined, holds nothing of the launch, and exits on Gradle's idle timeout,
    three hours, once idle.
  - A daemon hung in its build never becomes idle, and nothing bounds it.
  - Such a daemon's registry directory goes with the runner's `tmp/`, so no later launch finds the
    daemon.

Three properties on the command line close the toolchain inventory to the launch's JDK:
`org.gradle.java.installations.auto-detect=false`, `auto-download=false` and `paths=<JDK>`. A `-D`
overrides every `gradle.properties`, so a project asking for another toolchain fails naming it,
rather than meeting a denial.

Gradle 9.8.0 is the release measured, the one that `src/probe/gradle-fixture` pins. Older lines are
out: 8.14 does not run on the JDK 25 the launcher requires, and Gradle itself refuses a JDK it
cannot run on.

The acceptance test's Gradle rows (`src/probe/run-on-host-acceptance-test.sh`) measure:

- the distribution's grant;
- the build through the proxy;
- the daemon's reuse and record;
- the records following a cancel;
- the launch's end taking the daemon and the JVM its build forked, on TERM during the first build,
  while the daemon is still cancelling;
- a daemon of yours in a registry of your own, left alone;
- the toolchain refusal;
- the native libraries mapped from the user home;
- the unrelated service of this host, reached under `gradle` alone.

### Maven

The executable comes from the workspace's own wrapper script, `<WORKSPACE>/mvnw`; a globally
installed `mvn` is not used.

- Run `./mvnw --version` once on the host, and again whenever `distributionUrl` in
  `.mvn/wrapper/maven-wrapper.properties` changes. That run downloads Maven into
  `~/.m2/wrapper/dists`. The launch offers the run at its start prompt ("Program prerequisites").
- The command is granted that one Maven, read-only. The command is not granted the whole `dists`
  directory, which holds every Maven the user ever ran a wrapper for.
- If the wrapper has not downloaded that Maven yet, the command is refused, and the refusal says
  what to run.

Only the `only-script` wrapper type is served, the default that `mvn wrapper:wrapper` generates.

- A workspace with any other wrapper type is refused, and the refusal names the command that
  converts it.
- The supervisor recognizes the type from the script's `hash_string` function, reading the script
  and never running it.
- The other types run a jar that computes the distribution directory from more inputs:
  `distributionBase`, `distributionPath`, a relative URL, and the JVM's `user.home`.
  - This launcher deliberately does not reproduce that computation. A derivation that reproduced
    some of those inputs would grant a stale copy where the script selects another.

The command runs `bin/mvn --batch-mode` from that directory, not `mvnw`, which looks for Maven
under a home directory it computes itself. The supervisor computes the directory exactly as the
script does (`RunOnHostPrereqs.mvnDistributionDir`), from the script's inputs:

1. `distributionUrl`, rewritten by `MVNW_REPOURL` when the launcher's environment sets that mirror
   override;
1. hashed as a string, with `-bin` dropped from the directory name;
1. under `$MAVEN_USER_HOME/wrapper/dists`, or `~/.m2/wrapper/dists` when `MAVEN_USER_HOME` is
   unset.

An mvnd distribution is refused, because mvnd is a daemon.

- Maven runs once and exits, with no daemon and no server. Surefire's forked test JVMs talk to
  Maven over pipes by default, so `mvn test` works under the network rule as it is.
- Maven's resolver ignores the JVM proxy properties unless
  `aether.connector.http.useSystemProperties` is set. With the property set, the resolver warns at
  every download that it uses the JVM properties. That property belongs to resolver 1.9, which
  Maven 3.9 ships.
- Both behaviors are measured on Maven 3.9.16, the latest release, by building
  `src/probe/mvn-fixture` through a proxy inside the container. The acceptance test's mvn rows
  measure them under the profile.
- Maven 4 is a release candidate. Maven 4 is provisioned the same way and is unmeasured.
- The user's `~/.m2/settings.xml` and `toolchains.xml` are denied, and Maven treats them as absent.
  So a mirror or credential there never reaches a confined command.
- `.mvn/maven.config`, `jvm.config` and `extensions.xml` are workspace files that the agent already
  controls, like `sbt 'set …'`.

## The command's lifetime and environment

`RunOnHostSession.scala` tracks one supervisor invocation, which it calls a command session.

- The session's directory is published by rename, so the directory is never seen half-made.
- A lock marks the supervisor as live, and records identify its child processes.
- Cleanup moves the directory out of the active set before ending those processes and any
  leaderless sbt server that the directory's portfile identifies.

The runner holds a session of the same kind for the launch's lifetime:

- The session's records name the launch's runtimes:
  - `proxy-<program>-<hash>`, `server-sbt-<hash>` and `daemon-mill-<hash>`, where the hash is the
    build directory's;
  - `daemon-gradle-<pid>` for each Gradle daemon of the launch's one registry.
- A `build-<hash>` file names the directory that the records of that hash serve.
- A `runtime-<program>-<hash>` file describes each sbt server and mill daemon for another launch
  to attach to (`RunOnHostRuntimeDescriptor.scala`).
- A `run` file names the launch's sandbox container, by which `--stats` joins the runner to its
  session.
- The session's `tmp/` is where the sbt server binds its sockets, and where the servers and daemons
  keep their temporary files.

Two locks order the work:

- Each command the runner dispatches holds a build lock for the command's life, one per program and
  build directory, under `build-lock/`. The runner's own work on the runtime before a command also
  runs under that lock.
  - So two launches on one workspace queue behind each other's commands, and the waiting launch
    says so on its stderr.
- Ending a runtime's recorded group runs under a retirement lock, `retire-lock/<program>-<hash>`
  (`RunOnHostSession.retirementLockFile` has the rules).
  - The enders are the runner replacing or retiring its own runtime, its teardown, the scavenger,
    and another launch taking the runtime over.
  - The lock is held across the leader's start-time check and the signal alone, so no two
    processes signal one group.
  - An ender that does not get the lock within twenty seconds keeps the record for the next
    collection.

The supervisor root is `/private/tmp/ko-agent-<uid>`, short on purpose. sbt's boot socket path must
fit a UNIX-domain socket's `sun_path` (`RunOnHostPrereqs.SessionTmpMaxLength`), and the runner's
`tmp/` is under the same budget.

The supervisor constructs the command's environment from the variables listed below
(`RunOnHostSandbox.commandEnvironment`), rather than inheriting the launcher's environment.
SECURITY.md, "Run on host", explains why.

- The acceptance test supplies the same closed environment.
- The test's `command_env` documents its deviations, for rows without a proxy and with one
  temporary directory for clients and servers.

What the supervisor supplies:

| Environment Variable | Value |
|---|---|
| `JAVA_HOME` | the canonical path of the host's `$JAVA_HOME` |
| `_JAVA_OPTIONS` | the `java -D` properties below, inherited by forked JVMs |
| `PATH` | `$JAVA_HOME/bin:/usr/bin:/bin:/usr/sbin:/sbin` |
| `TMPDIR` | `<command directory>/tmp`; under `mill` and `gradle` the runner's `tmp/` |
| `XDG_RUNTIME_DIR`, `SBT_GLOBAL_SERVER_DIR` | the runner's `tmp/`, or the command's under Maven |
| `COURSIER_CACHE` | `<run-on-host cache>/coursier/v1` |
| `GRADLE_USER_HOME` | `<run-on-host cache>/gradle-user-home` |
| `USER`, `LOGNAME` | the account's name, the JVM's `user.name` |
| `HTTPS_PROXY`, `HTTP_PROXY` and their lowercase | `http://127.0.0.1:<port>`, the command's proxy |
| `NO_PROXY` and its lowercase | `localhost,127.0.0.1` |
| `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `GIT_SSL_CAINFO` | the proxy's CA certificate, PEM (below) |
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
| `javax.net.ssl.trustStore`, `javax.net.ssl.trustStoreType` | the proxy's CA certificate as a store, `PKCS12` |
| `javax.net.ssl.trustStorePassword` | `changeit`, no secret: without it a JVM loads no certificate from a PKCS12 store |
| `sbt.global.base` | `<run-on-host cache>/sbt-global` |
| `sbt.ivy.home` | `<run-on-host cache>/ivy-home` |
| `maven.repo.local` | `<run-on-host cache>/m2/repository` |
| `aether.connector.http.useSystemProperties` | `true`, else Maven's resolver ignores the proxy |

- HotSpot reads `_JAVA_OPTIONS` directly, though OpenJDK calls the variable an undocumented
  feature. HotSpot applies these properties after command-line options.
- Path values use `RunOnHostSandbox.jvmProperty`'s HotSpot quoting syntax. This variable reaches
  HotSpot without the sbt script copying quoted values into argv;
  [upstream-issues.md](upstream-issues.md#quoted-jvm-options-are-copied-into-arguments) has the
  reproducer.
- sbt clients and servers also receive `sbt.global.base` as one argument, for the script's
  preloaded-cache lookup (`RunOnHostSandbox.sbtCommand`).

The proxy answers for every host it allows under a certificate of its own CA ("The command's egress
proxy"), so a program verifies that host only if the program trusts the CA.

- A JVM trusts the CA through the store.
- The five variables name the same certificate for the programs that `HTTPS_PROXY` serves, as the
  sandbox container's variables do (`SECURITY.md`, "Who holds the CA key").

Which program reads each variable, by each program's documentation:

| Environment Variable | Read by |
|---|---|
| `SSL_CERT_FILE` | OpenSSL's default verify file, so a program that loads OpenSSL's defaults; Node.js only under `--use-openssl-ca` |
| `CURL_CA_BUNDLE` | `curl`, unless its TLS backend is Schannel; Python's `requests`, when `REQUESTS_CA_BUNDLE` is unset |
| `REQUESTS_CA_BUNDLE` | Python's `requests` |
| `NODE_EXTRA_CA_CERTS` | Node.js, read once at start, and not by a client that sets its own `ca` option |
| `GIT_SSL_CAINFO` | `git`, over `http.sslCAInfo` |

- A GraalVM native image, such as the `cs` and `scala` launchers, reads neither `_JAVA_OPTIONS`
  nor the five variables.
  - The image takes the same three `javax.net.ssl.trustStore*` properties, and the proxy's, as
    `-D` options on its own command line.
  - A build that starts such an image passes those options itself, with the values that
    `_JAVA_OPTIONS` has.
- A program that reads none of these fails its certificate check on every host, and no setting of
  the launcher's or the build's reaches it. Examples are a program verifying through the macOS
  keychain alone, a binary with its roots compiled in, and a JVM client whose code names its own
  trust store.
- The `curl` and `git` that macOS ships fail under a command's profile before they verify any
  certificate, whatever the variables (macOS 26.4.1, the acceptance test's "CA bundle variables"
  rows). The table is for a program the build brings.
  - `/usr/bin/curl` stops at LibreSSL's `fopen('/private/etc/ssl/openssl.cnf')`, `Operation not
    permitted`, printed as `Auto configuration failed`. The file is not among the profile's system
    paths (`SeatbeltProfile.SystemPaths.txt`; `doc/TODO.md`, "read grants a user adds").
  - `/usr/bin/git`, Xcode's shim, ends with "See `man xcode-select` for more details".
- The CA is the whole store and the whole PEM file. No public root is beside it, since the proxy
  inspects every host it allows and no origin's own certificate reaches a command.
  - A program with roots of its own keeps them: `NODE_EXTRA_CA_CERTS` adds the CA to Node.js's
    roots.

The placeholders:

- `<command directory>` is this invocation's directory under the supervisor root above. The
  runner's sbt server, and every `mill` and `gradle` process, have the runner's `tmp/` for every
  row naming one.
- `<cache home>` is `${XDG_CACHE_HOME:-$HOME/.cache}` from the launcher's environment.
- `<run-on-host cache>` is the workspace's own run-on-host cache root,
  `<cache home>/ko-agent-sandbox/run-on-host/<workspaceId>` ("The run-on-host cache" below).

One environment serves every program:

- sbt's global base and Ivy home, Gradle's user home and Maven's local repository are set for every
  command. A command of another program reads none of them, and the supervisor neither creates nor
  grants them for that command.
- The mill download folder, the one holding the granted executable, is set for the other programs
  the same way, and they ignore it.
- Gradle's toolchain properties are on Gradle's command line ("Gradle").

Why the rows are what they are:

- The host's `TMPDIR` names a directory the command is not granted. So the command's `TMPDIR`
  replaces it for forked shell programs, as `java.io.tmpdir` does for JVMs.
- Under `mill` that directory is the runner's `tmp/`, for the two reasons below
  (`RunOnHostSandbox.temporaryDirectories`). Under `gradle` it is the runner's `tmp/` for the first
  reason, since the daemon serves later commands with the profile and environment it was started
  with.
  - A JVM that the daemon forks, such as a `run` or a test, inherits the daemon's profile, which
    grants the runner's `tmp/` and not the command's. Yet the JVM gets the command's environment
    (`RunModule.scala`, `ctx.env`).
  - With one directory, the starter's environment and every client's environment are one map. So
    an option file that Mill interpolates from the environment
    (`MillProcessLauncher.loadMillConfig`) yields the same value in both, and a client never meets
    a fingerprint mismatch of the supervisor's own making.
- `HOME` is passed because the programs' scripts derive paths from it. Nothing under `HOME` is
  granted.
- `--env` is the same forward the sandbox gets, with the same refusal of `KO_AGENT_SANDBOX_*`.
  - A forwarded name replaces a pass-through, but cannot replace any setting the supervisor
    supplies.
  - `--env-aws-cred`'s names travel the same way.
  - `_JAVA_OPTIONS` and `HTTPS_PROXY` keep the supervisor's values. The launcher's own
    `HTTPS_PROXY` is replaced as above.
- `MILL_VERSION` and `DEFAULT_MILL_VERSION` never take the forwarded values. The supervisor granted
  the launcher of the version that the build directory pins, and `MILL_VERSION` names that
  launcher.
- `MILL_OUTPUT_DIR` and `MILL_BSP_OUTPUT_DIR` are not forwarded either, because the supervisor looks
  for the daemon's rendezvous under `out/` ("`mill`").
- Without explicit forwarding, these are absent: `TERM`, `SBT_OPTS`, `JAVA_OPTS`,
  `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, the other `COURSIER_*` variables, `SBT_CREDENTIALS`,
  `ALL_PROXY`, `FTP_PROXY` and exported secrets.
- A command's own processes see this set, plus what the programs' shell scripts create on the way:
  `PWD`, `SHLVL` and `_`. A variable does not come back merely because the launching shell
  exported it.

## The channel and the command

`ko-sandbox-run-on-host <program> [args…]` is a named command, a sibling of `ko-sandbox-apt-get`,
rather than a shim shadowing `sbt` on `PATH`. The transcript the user reads then shows where each
command ran.

- The named command cannot inherit `ko-sandbox-apt-get`'s discoverability. `apt-get install`
  *fails* in the sandbox and teaches the agent to look for the prefixed name.
- `sbt test` in the container *succeeds*, slower, and nothing prompts the agent to reconsider.

So the "What this session may do" section states the instruction, and only where it can be true:

- The launcher knows the platform, so a macOS session launched without the option gets one
  discovery paragraph.
- Linux and Windows sessions hear nothing about a command they can never have.
- The host command is therefore a norm rather than an enforcement. An agent that ignores the
  instruction gets a slower build, not a refusal. That is a deliberate difference from the egress
  rule, where the proxy actually refuses.

`RunOnHostChannel.scala`'s header and the shim's own comments describe the transport, its framing
and its teardown. One command runs at a time, serial by design rather than as a shortcut:

- a queued sbt request attaches to the server that the running request leaves, and a queued
  `mill` request to the daemon;
- the runtime's selection, start and retirement never overlap a command;
- the per-transaction FIFOs leave a concurrent runner open as later work, if a program ever makes
  a concurrent runner worth having.

Before starting a server, the runner checks who holds the build directory's portfile:

- The *user's own* server, from a terminal outside any launch, is shut down by protocol at the
  socket the runner derives itself.
- A server that *another launch* still owns is one whose runner's session names the directory,
  and whose recorded group is not known to be gone.
  - The command attaches to that server when the server this launch would start has the same
    confinement and environment.
  - Otherwise the runner ends that server by its record and replaces it with its own (below).
- A live socket under this launch's own directory, while this launch has no record identifying
  that server, is a refusal naming the socket.

Before starting a daemon, the runner checks the process table the same way ("`mill`"). The user's
own daemon is ended once idle, after its start-time check. Another launch's daemon is attached to
or taken over.

The runner decides about attaching per command, from the owner's descriptor,
`runtime-<program>-<hash>` in the owner's session directory (`RunOnHostRuntimeDescriptor.scala`).
Two conditions must hold:

- The fingerprint of the server's or daemon's confinement and environment must equal the
  fingerprint of what this launch would start. The fingerprint covers:
  - the profile's inputs;
  - the closed environment, forwarded values included, so a launch forwarding a secret never
    serves a launch that does not;
  - the proxy's rule lines as read when that proxy was created, since a warm proxy keeps them.
- The descriptor must name the owner's present records, and those records' processes must live:
  - for sbt, the server behind the directory's portfile, at the socket derived under the owner's
    `tmp/`;
  - for `mill`, the daemon by its start time, under the build directory's present configuration.

The command then runs against the owner's session, proxy and daemon port, as the owner's own
commands do, and this launch records nothing of it. What the attaching launch gives up:

- A cancel is the program's own, since the server is not this launch's to retire.
  - An interruption-ignoring sbt test runs on in the owner's server until the next command queues
    behind it.
  - A `mill` client's disconnect mid-command ends the shared daemon, as stock Mill does, so the
    owner's next command starts a daemon.
- The owner's end takes the runtime with it, a build of this launch included. This launch's next
  command starts its own runtime or attaches elsewhere.
- This launch's proxy audit lines land in the owner's proxy log.

The fingerprint leaves out an sbt request's own launcher flags, its `-D` properties and value flags
(`RunOnHostRuntimeDescriptor.fingerprint`). The warm server keeps the flags of the command that
started it, and every later command attaches regardless, within a launch as across launches.

Gradle's daemons and Maven have nothing to attach to: the Gradle registry is the launch's own, and
Maven runs once.

A runtime that the command cannot attach to is taken over. The reasons:

- the fingerprints differ;
- the owner is ending, or died since the scavenge;
- the owner's descriptor is missing or names other records;
- the server or daemon is gone, the portfile does not name the server's socket, or the daemon is
  not under the directory's present configuration.

The takeover runs under the build lock the command holds. The runner ends the group that the
owner's record names, under the retirement lock and after the same start-time check every ender
makes. The runner then starts its own server or daemon under its own proxy, as for a first command.

- The owner's record stays the owner's, and the owner's proxy runs on.
  - The owner's next command finds the group dead, replaces the runtime under that proxy, and
    decides the same way: it attaches to this launch's runtime, or takes it back.
  - So two launches whose runtimes differ alternate restarts, and each restart loses the warm
    build the other launch left.
  - The launcher's channel log names each takeover and the reason.
- The takeover connects to nothing and reads no portfile. The record attributes the group, so
  neither a planted portfile nor a link under the owner's `tmp/` can send the signal to another
  directory's server.
- An owner tearing itself down holds the retirement lock through its own end of the group. So the
  command waits on the lock, twenty seconds at most, and then starts its own runtime.
- The command is refused, naming the record, when the group is not observed ended. That is a
  member still listed after the KILL, a leaderless group, or the lock busy past its bound. Retry
  once the group is gone, or use a different build directory.
- Your own `./mill` attached to the daemon taken over dies with the daemon, as it does when the
  owner replaces the daemon.

Ending the other launch's server is the only resolution available, because the portfile is not
merely a rendezvous:

- The portfile's one-server-per-build-directory exclusivity is also the lock over `target/`.
- A second rendezvous on the same tree, such as a shadow base directory or a relocated portfile,
  would put two unsynchronized compilers in one content-addressed store. That is why container and
  host commands coexist on the source and never on the outputs.
- An invocation cannot opt out either. sbt's build directory is always its working directory, and
  sbt 2 has no one-shot mode ("sbt", above). So every invocation either attaches to the portfile's
  server or contends for it. `upstream-issues.md` has the upstream request that would add the mode.
- Mill's `out/mill-daemon` lock is the same exclusivity over `out/`.

The runner's cancel carries no reason. The shim's descriptor closes the same way, whether the
agent changed its mind or gave up on a command that sat silent.

Before removing a command's directory, the supervisor appends the command's logs to the channel's
log, `run-on-host.log` in the directory that the launch printed as `log dir`
(`RunOnHostSandbox.appendSessionLogs`):

- The supervisor appends the tail of the proxy audit log, under Maven.
- The supervisor also appends the tail of the stderr file that a thin client leaves under `tmp/`
  when it forked a server of its own, the client's answer to a socket it cannot reach.
- The supervisor runs unconfined, and the command could write `tmp/` in that directory and replace
  `tmp/` itself. So the read comes after the rename and after the command's groups end. The read
  refuses a link at any component, and takes the tail by position rather than by the file's size.
- The proxy audit log's name in that directory is the launcher's own link to the file in the run's
  log directory. Both are outside what the command can write. The read follows that link when it
  names an audit log there, and no other link (`RunOnHostProxy.keptAuditLog`).
- A command that completed leaves nothing there, because its output reached the agent.

The runner's session ends the same way, at the launch's end or on TERM: the runner appends its
proxies' audit logs and its servers' logs before removing the session's directory.

The runner starts each sbt server with stdout and stderr appended to `server-sbt-<hash>.log` in its
session directory. The file is not under `tmp/`, because the server could replace a file there
with a link or a FIFO before the runner opens it for the next server. The runner waits for the
portfile with a bound on progress:

- A server that has published no portfile, while neither the log file nor the proxy log grew for
  two minutes (`RunOnHostSandbox.ServerStartSilenceMillis`), is ended. The command is refused with
  the file's tail. sbt's own client waits with no bound at all.
- A server that exits on its own leaves its output in the file, for the channel log to keep. For
  example, sbt started where no build is asks on stdout whether to create one, and answers itself
  from the detached stdin.

## Where a host command deviates from the stock program

In everything else, a host command behaves as the stock program run from a terminal. The
deviations below each name their reason: confinement, the launch's ownership of what it starts, or
operability, since the caller is not interactive.

### Under every program

- **Persistent processes end with the launch — ownership.** Stock sbt, Mill and Gradle leave their
  server or daemon running when the terminal that started it closes, Gradle's for three idle hours.
  - The runner's servers and daemons run against the launch's proxy and its forwarded environment.
    Both die with the launch, so the servers and daemons must die too.
  - The next start scavenges what a killed runner left, and a later launch adopts none whose owner
    is gone.
- **A foreign server or daemon is never attached to — confinement.** Stock sbt attaches to whatever
  server holds the portfile. Stock Mill attaches to whatever daemon holds `out/mill-daemon`, unless
  its fingerprint differs. A client attached to a process the runner did not start would run the
  build under that process's environment and confinement, or under none.
  - The runner shuts down the user's own terminal server by protocol, at the socket it derives. The
    runner ends the user's own daemon once idle, after its start-time check ("`mill`").
  - The runner attaches to a server or daemon another launch still owns only when it would start
    one under the same confinement and environment. Otherwise the runner ends that process by that
    launch's record, under the retirement lock, and replaces it with its own ("The channel and the
    command").
- **The environment is a closed set — confinement.** The command sees the supervisor's set and not
  the launching shell's ("The command's lifetime and environment"):
  - `HOME` is passed, and nothing under it is granted;
  - `preferIPv4Stack` is set for the loopback rule ("Network");
  - no destination off this host is reachable but the proxy;
  - the workspace is writable even under `--workspace=read-only` (`SECURITY.md`, "Run on host").
- **A repository takes reads alone — confinement.** Stock sbt, Mill, Gradle and Maven publish to a
  repository with a `PUT`.
  - A host command's proxy refuses every request but a `GET` or `HEAD` without a body ("The
    command's egress proxy"), and the rule file takes no other grant. So publishing is yours,
    outside the sandbox.
  - The supervisor names the refused request ("Refusals").
  - The JVM's default trust is the proxy's CA alone, with no public root ("The command's lifetime
    and environment").
- **The wait for a start has a bound — operability.** sbt's thin client waits for a starting server
  with no deadline, which an interactive user can end with Ctrl-C. The agent cannot, so an
  unbounded wait would be an unrecoverable command.
  - The runner fails the start, with the log's tail, when neither the server's log nor the proxy
    log grows and no portfile appears for two minutes
    (`RunOnHostSandbox.ServerStartSilenceMillis`).
  - A mill starter that neither ends nor writes for as long, while the proxy log stays still, fails
    the same way. `doc/TODO.md`, "a bound on a silent host command", tracks the remaining generic
    bound.

### Under sbt

- **The server is the runner's, not the client's — ownership.** The runner starts the server in its
  own directory for sockets and temporary files, and each command's client attaches. A server that
  the client forked would inherit the command's profile, environment and group ("sbt").
- **The server receives the request's launcher flags as the thin client forwards them, less those
  naming a program — confinement.**
  - `-D` properties, the value flags and `--allow-empty` reach the server.
  - `-J` does not, since the runner applies `-J` to the client's own JVM, and the client itself
    forwards nothing of `-J`.
  - Dropped beyond what the client drops: `-java-home`, `-sbt-jar`, `--sbt-script`,
    `--sbt-launch-jar` and `-Dsbt.script=`. Each names the JVM, the launcher jar or the runner
    script, which the profile's grants decide (`RunOnHostSbtServer.serverCommand`).
- **`new` and `init` run through a server — the client model.** Stock sbt runs those two commands
  in the sbt process itself, in place, since a template is written where no build is. Stock sbt
  runs every other command through its client.
  - The runner has one path, a client to the server it starts. So
    `ko-sandbox-run-on-host sbt new` in an empty directory meets the runner's refusal of a
    directory with no build.
  - `--allow-empty` starts the server there, as the stock client's flag would.
  - The acceptance test does not measure whether `new` then writes its template through that
    server.
- **The JVM client, never `sbtn` — operability.** sbt 2 runs its native client by default. Under
  the profile, that client prints that it is starting the server and returns with no build run.
  The supervisor passes `--jvm-client`, and an acceptance-test row keeps measuring `sbtn` ("sbt").
- **`target/` links into a denied store are swept before a server starts — confinement.** A tree
  that the user's unconfined sbt built links into a store the profile denies ("sbt").
- **The global base and the Ivy home are the workspace's own — confinement.** Both are redirected
  into the run-on-host cache, where stock sbt uses `~/.sbt` and `~/.ivy2` ("sbt", "The run-on-host
  cache").
- **While the launch's server lives, your terminal's `sbt` in the build directory runs on it, and
  `sbt shutdownall` does not end it — ownership.** Run `sbt shutdown` there first to end it.
  - Stock sbt attaches to whatever server holds the portfile, so your command runs under the
    profile and the launch's environment. A test that runs podman fails there.
  - `sbt shutdownall` kills what `jps -v` lists as `sbt-launch`, which does not include a launch's
    server (sbt 2.0.9, macOS 26.4.1, 2026-09-28). The server ends with the launch anyway.

### Under `mill`

- **The daemon is started by the runner's `./mill version`, not by the first client —
  ownership.** The starter's denied connect leaves the daemon in the runner's group, and the runner
  ends the starter once the daemon listens ("`mill`").
- **The JVM launcher, never the native image — confinement.** The stock bootstrap runs the native
  image for a version with no suffix.
  - The supervisor sets `MILL_VERSION` to `<v>-jvm`, so that the client takes the environment's
    `preferIPv4Stack` and connects under the one-port rule. The image cannot do either ("`mill`").
  - The user provisions that launcher, and a `-native` pin is refused with the reason.
- **A configuration edit replaces the daemon before the command — operability.** Stock Mill's
  client ends a daemon whose fingerprint differs and starts a replacement itself.
  - From a confined client that replacement cannot bind, so the command would fail once.
  - The runner reads the same inputs before each command and replaces the daemon first
    (`RunOnHostPrereqs.millDaemonConfig`).
- **A pinned or unset `mill-jvm-version` runs on the JDK a host run provisioned, and an unset one
  is refused before Mill 1.1.0 — confinement.** Stock Mill resolves the id, or its default, and
  downloads the JDK itself. A command may not fetch a JDK ("A pinned JVM", "An unset
  `mill-jvm-version`").
- **A request's `MILL_VERSION`, `DEFAULT_MILL_VERSION`, `MILL_OUTPUT_DIR` and
  `MILL_BSP_OUTPUT_DIR` are not read — confinement.** The supervisor's `MILL_VERSION` names the
  granted launcher, and the supervisor looks for the daemon's rendezvous under `out/` ("The
  command's lifetime and environment").
- **A redirected `out/mill-daemon` is refused — confinement.** Mill's launcher would act on another
  build directory's daemon through it ("`mill`").
- **A `mill-daemon-classpath` file naming what the profile denies is deleted before a start —
  confinement.** Stock Mill keeps the file, since the paths exist. Under the profile the daemon
  could not open them ("`mill`").
- **Clients use the runner's temporary directory, not their own — confinement.** A JVM that the
  daemon forks inherits the daemon's profile and gets the client's environment ("The command's
  lifetime and environment").

### Under Gradle

- **The daemon registry is the launch's, under the runner's `tmp/` — confinement.** Stock Gradle
  keeps the registry in the user home, where one launch's `gradle --stop` would end another
  launch's builds ("Gradle").
- **The distribution's `bin/gradle` runs, never `gradlew` — confinement.** The wrapper script
  downloads. A `distributionBase`, `distributionPath` or `systemProp.gradle.user.home` that moves
  the distribution to a place the workspace chooses is refused ("Gradle").
- **The toolchain inventory is the launch's JDK alone — confinement.** Auto-detection and
  auto-provisioning are off on the command line, so a project asking for another toolchain fails
  naming it ("Gradle").
- **The user home is the workspace's own — confinement.** The user home is under the run-on-host
  cache, where stock Gradle uses `~/.gradle` ("The run-on-host cache").

### Under Maven

- **The distribution's `bin/mvn` runs, never `mvnw` — confinement.** The wrapper script downloads
  ("Maven").
- **The local repository is the workspace's own, and the resolver is told to honor the proxy —
  confinement.**
  - `maven.repo.local` is under the run-on-host cache, where stock Maven uses `~/.m2/repository`.
  - `aether.connector.http.useSystemProperties` is set. Without it, Maven's resolver ignores the
    proxy, which the profile leaves as the one route out ("The command's lifetime and
    environment").

Two behaviors are the stock program's, though they could be read as the runner's:

- The stock program keeps one warm server or daemon per build directory, not one per program. So
  visiting another directory leaves the first directory's server or daemon warm.
- A cancel does what the program does, and the programs differ:
  - An sbt client's disconnect cancels only the running exec (`CommandExchange.removeChannel`,
    `force = false`) and leaves the warm server. So an interruption-ignoring test lingers in the
    server exactly as it would in a terminal, and the next command reuses the server.
  - A Mill client's disconnect mid-command makes the daemon shut itself down (`Server.scala`), so
    the next `mill` command starts a daemon.
  - A Gradle client's disconnect cancels the build, and the daemon stops itself only if still busy
    ten seconds later (`DaemonStateCoordinator`). So the next `gradle` command attaches or starts
    a daemon.

The runner retires none and revives none on its own.

## The Seatbelt profile

Apple does not document SBPL for third-party use. `sandbox-exec` compiles SBPL through private
entry points, and the published write-ups are reverse-engineered and date from 2011. Two sources
are authoritative here:

- measurement (`src/probe/seatbelt-semantics.sh`, `src/probe/run-on-host-profile-iterate.sh`);
- Apple's own shipped profiles under `/System/Library/Sandbox/Profiles/`, which are current and
  written against the implementation. `system.sb` is the one worth reading first.

`SeatbeltProfile.scala` encodes the findings, and its header states the two that decide everything.
The rest, measured:

- What the guard depends on (`src/probe/seatbelt-semantics.sh`):
  - Seatbelt resolves the accessed path, so a write through `link -> .git` is denied, as are the
    folded spellings described in the filesystem rules.
  - Seatbelt evaluates rules at access time, so the rules cover a `.git` created *during* the
    command.
  - One regex spans every depth.
  - `file-write*` already refuses a hard link to a denied target, so the explicit link clause is
    redundant. The clause stays, because the membership of a wildcard operation family is Apple's
    to change.
- `/dev/tty` is the terminal, whatever stdin is: closing the child's stdin does not detach its
  controlling terminal. The profile grants `/dev/null` and the random devices only.
- An invalid profile fails exactly like a denial. `sandbox-exec` aborts the child either way, and
  the difference shows only on `sandbox-exec`'s own stderr. A search that discards that stderr
  looks for grants that were never missing.
- `mach-lookup` names its services (`SeatbeltProfile.MachServices`), in the command's profile and
  the proxy's. Unfiltered, `mach-lookup` reaches every Mach service of the host, and a service may
  act for its caller outside the profile.
  - The one name is `com.apple.system.opendirectoryd.libinfo`, the service that the system's
    resolver library asks. Without it the serving proxy dies of a segmentation fault; with it alone
    the proxy serves a fetch. `java -version` and `sbt about` run with no name granted
    (`src/probe/run-on-host-profile-iterate.sh mach`, `mach-proxy`, macOS 26.4.1).
  - A command gets the same name, unmeasured. Which call of the proxy's JVM needs the name is not
    known, a build's JVM may make the same call, and the failure is a crash, not an error a build
    could report.
  - `open` started nothing from under the command profile while `mach-lookup` was unfiltered
    (`mach-route`). `open -a` found no application, and no application claimed a `.command` file
    the command wrote.
  - Under the named service, the acceptance test has rows for `open -a`, for a JVM asking the
    resolver, and for a lookup of an internet name, which must fail (SECURITY.md, "DNS").
- What this toolchain needs, per layer:
  - The JDK needs `sysctl-read`, its home, and `/System/Library/CoreServices/SystemVersion.plist`.
    Without that one file, `java` refuses to start with `os.version malformed: -1.0`.
  - The JDK does *not* need `file-map-executable`, which Apple's profiles use for system
    frameworks. A JDK outside those paths loads without it.
- Adopted from `system.sb` rather than re-derived: `file-test-existence`, a narrower operation than
  `file-read*`, for the ancestor chain.
- The profile denies a command reading another process's arguments and environment through
  `sysctl` `kern.procargs2`, the call behind `ps -E` (`SeatbeltProfile.ProcessReadRule`;
  `run-on-host-profile-iterate.sh procargs`, 2026-10-04):
  - The kernel answers for any process of the same user. The kernel withholds the environment, not
    the arguments, of a code-signing restricted target, as Apple's own binaries are, unless the
    caller is that target (xnu, `sysctl_procargsx`).
  - The call succeeds while either `sysctl-read` of its name or `process-info-pidinfo` is allowed.
    `(deny default)` does not cover `process-info*`, so a deny of either alone leaves the call
    succeeding.
  - A deny of both, with pidinfo allowed again for the same sandbox, refuses the call, arguments
    included, while the JDK runs and still lists processes. That is the rule of agent-safehouse's
    `profiles/10-system-runtime.sb`.
  - Under that rule, the same sandbox is the inherited one. The read succeeds for a child the
    reader starts, and is refused for a JDK under a `sandbox-exec` of its own with the same
    profile. `ProcessHandle.of` still finds every process, those outside included.
  - `ProcessHandle.info()` of a process outside throws "Operation not permitted". The JDK reads the
    process's arguments for it, and throws on any error but `EINVAL` and `EIO`
    (`ProcessHandleImpl_macosx.c`).
    - Mill 1.1.10's client checks its daemon that way (`PidLock`), and the acceptance test's mill
      rows fail under the rule without the exception below (2026-10-04).
  - `(allow sysctl-read (sysctl-name "kern.procargs2.<pid>"))` after the rule opens the read, and
    `info()`, for that one process. Every other target stays denied (the probe's last row,
    2026-10-04).
  - A mill client's profile allows that name for its daemon (`SeatbeltProfile.Network.MillClient`).
    The runner gave the daemon the client's own environment, so the read exposes nothing the client
    lacks.
  - The acceptance test's process rows read a JDK outside the profile and a child inside it, under
    every program's profile.

Prior art: Bazel sandboxes build actions on macOS with `sandbox-exec`, which is this feature's
problem exactly. Bazel's generated profile is worth reading, and worth *not* copying.

- Bazel's profile is a blacklist: `(allow default)`, then writes and network taken away. That is
  why Bazel never meets the findings above. With nothing denied by default, path resolution cannot
  fail, so the root entry and the ancestor chain never arise.
- That is also why the blacklist design cannot serve here. A command under it reads the whole
  filesystem, and "everything else user-owned inaccessible" is the property this feature exists to
  provide.
  - Deny-by-default makes the profile harder to construct, and is what provides that property. So
    the difficulty is no reason to change the design.
  - This is worth stating because the blacklist form is the obvious simplification when the
    whitelist will not start.
- One setting is taken from Bazel: `(debug deny)`, which makes denials visible without the unified
  log's redaction. `src/probe/run-on-host-profile-iterate.sh` puts it at the top of every profile
  it iterates.

**System paths** are the loader, libc, the CA bundle and the rest that a toolchain needs from the
system:

- The set is discovered by running a real build under a deny-default profile and reading the
  denials. The set is never discovered by listing what a host happens to have, and never used as
  a way to reach a user path. `src/probe/run-on-host-profile-iterate.sh` measures candidate
  entries.
- The measured set is one file, a resource of the launcher's own artifact
  (`src/main/resources/agentsandbox/SeatbeltProfile.SystemPaths.txt`). What the production
  supervisor grants is what the probes measured, and the acceptance test and host commands use that
  same set of grants.
- Do not pre-authorize broad paths (`/System/**`, `/usr/**`, `/opt/homebrew/**`). Add the narrowest
  rule that testing justifies.

## The command's egress proxy

The proxy is a process from the same codebase as the container's proxy.

- Under sbt, `mill` and `gradle`, the proxy is the runner's.
  - The runner starts it in the runner's session when the first command of that program arrives
    from a build directory: the request's working directory, whose `project/target/active.json` or
    `out/` the build owns.
  - The proxy takes the program's rule file as read then, and the runner keeps the proxy for the
    commands that follow from that directory.
- A request from another build directory gets a proxy of its own, and both proxies stay.
- A proxy that is gone is replaced, together with its server or daemon, before the next command.
- Maven's proxy is the command's. The supervisor starts it in the command's session and ends it
  with the session, as every program's proxy is under the acceptance test's entry (`RunOnHost`).

The sandbox session's proxy runs on a network created `--internal`, inside the podman machine.
There is no host route to it, and a route would cost either of two things:

- Publishing the route would expose the sandbox session's full `--egress` ruleset, with
  `api.anthropic.com` and forges included, to any host process.
- Relaying each connection through `podman exec` would add the VM round trip to exactly the path
  that the command was moved out of the VM to avoid.

A JVM proxy client speaks TCP, so a loopback listener is unavoidable either way. What is worth
controlling is the rules behind the listener: an attacker who reaches a proxy allowing one artifact
repository can reach only that repository through it.

A launch with `--egress-cred` gives each proxy its bindings on the proxy's standard input, under
`EGRESS_CREDS=stdin` (`RunOnHostSandbox.credentialsFor`; SECURITY.md, "Who holds a brokered
value"):

- The runner reads the launch's bindings on its own standard input, written by the launcher.
- A Maven supervisor reads its proxy's bindings after the runner's run word
  (`RunOnHostSession.runWord`), which carries `--credentials-on-stdin` and no value.
  - The lock holder reads the word a byte at a time, so the bindings stay in the pipe across its
    `exec` (`RunOnHostSession.LockScript`).
- A proxy reads the bindings once, at start, so a rule-file edit reaches them as it reaches the
  hosts (below).
- No proxy outlives the launch whose placeholders it holds, so a mill or Gradle daemon kept across
  commands never meets a stale binding.
- A binding widens no proxy's grants. A hostile build's route out is that proxy's hosts, as without
  a binding.

A proxy's audit log is a file in the run's log directory, where `--egress-log` lists it
(egress-proxy.md, "Audit what has been allowed or denied").

The proxy lives as long as the session holding its record:

- the runner's proxy, until the runner retires the proxy or ends with the launch;
- the command's proxy, until the supervisor cleans up that invocation. That is past the client
  process, since the server the client forks resolves artifacts and lives until the supervisor ends
  it.

A rule-file edit takes effect when a proxy is next created, never by restarting a running proxy,
which holds the lines it was created with. A proxy is next created:

- at the first command from a build directory the launch has not visited;
- after `ko-sandbox-run-on-host <program> shutdown` followed by a proxy's own end;
- at the next launch, as the session's own rule file takes effect at the next launch.

Until then, a host removed from the file stays reachable from that proxy, and a host added is not.
To apply an edit, relaunch, as for the session's rule file.

- The runner deliberately does not retire a running proxy on an edit. What a launch may reach is
  decided at launch (`design.md`, "Design principles to preserve").
- A relaunch is the one step that applies an edit to both proxies alike.

The proxy ships in the launcher's own artifact. The proxy sources share the launcher's Scala
version, and `dist` compiles them in beside their `/defaults` resources. The runner or the
supervisor starts the proxy by re-invoking its own executable, `java -jar` or the native binary,
under a private action.

- That executable must still exist at its launch path, as spelled at launch, in either form. When
  the launcher was launched through a symlink, the path is the link.
  - Each form is one file built under `target/dist`, which `sbt clean` or `git clean` removes while
    a session runs.
- So the runner checks the executable before it execs every command's supervisor and before every
  proxy start (`RunOnHostSandbox.selfPresent`). A missing executable is refused with the path and
  the remedies: rebuild at that path, or relaunch. The JVM would otherwise fail at its main class
  after the ready wait.
- A rebuild at the same path is no removal, and neither is a link's retargeting. The running
  processes keep their inode, and the next re-invocation runs the new file.
- The proxy binds an ephemeral port on `127.0.0.1`. The codebase's wildcard `:3128` default is safe
  only in the container's own network namespace.
  - `preferIPv4Stack` is on the proxy's command line, as the command's environment sets it, since
    the dual-stack bind is the v4-mapped one that the `localhost` class denies ("Network").
  - The proxy's starter reads the port from the same ready line that the container launcher waits
    for.

The proxy runs under a profile of its own (`SeatbeltProfile.renderProxy`). The profile is the same
for every proxy the launcher starts on the host, since one `startProxy` starts them all. The
profile grants:

- the proxy's executable: the native image, or the JDK and each class-path entry of the jar form;
- the system paths as reads, and the devices;
- the directory holding the proxy's leaf certificate and that leaf's key, as reads;
- the network:
  - outbound to every remote, since which hosts a client may reach is the proxy's own decision, by
    name, and SBPL filters by address;
  - the resolver's socket, `/private/var/run/mDNSResponder`, which `InetAddress.getAllByName`
    reaches, with the root link `/var` that the resolver's client spells the path through
    (measured: without that one link every lookup fails);
  - a listener of the `localhost` class for the proxy's port;
- nothing else of the user's: no workspace, no cache, and no write anywhere;
- of the operation families, only `sysctl-read`, and `mach-lookup` limited to the resolver's
  service ("The Seatbelt profile", the measured findings).
  - These were measured with `src/probe/run-on-host-profile-iterate.sh ops`, with the proxy under
    its profile and each family added in turn.
  - The profile grants no `process-fork`, since the proxy forks nothing.

The proxy runs from `/`, since the JVM asks for its working directory at start, and the profile
grants no other directory's.

- The proxy's log is its stderr, which its starter opens and the proxy inherits. No rule governs an
  inherited descriptor, so what `sandbox-exec` or the JVM says before the proxy prints anything
  lands where the ready line is awaited.
- The proxy is the one launcher process that parses bytes the confined command sends, and it runs
  as the user's uid. `HostileInputTest` covers the parser, and the profile is what a parse bug
  meets.

The proxy inspects every host it allows, so `read` in its rules is enforced as the sandbox
session's proxy enforces it (`SECURITY.md`, "Reading without being able to write"): a `GET` or
`HEAD` without a body, one request per connection, each logged with its target.

- No host is tunnelled, because the rule grammar has no other grant ("Configuration").
- A proxy without a leaf would forward its hosts uninspected, so the proxy's starter always
  supplies a leaf (`RunOnHostInspection.create`, called at every proxy start).

What the starter creates:

- The starter creates a CA for this proxy alone and signs one leaf naming the proxy's hosts: Maven
  Central, and the rule file's hosts as read then.
  - The proxy refuses to start unless the leaf names exactly the hosts its rules inspect
    (`SECURITY.md`, "Who holds the CA key").
  - So the names are the ones that the proxy's own resolution of those rules gives
    (`RunOnHostInspection.leafNames`), as the sandbox session's leaf takes its names. A rule
    spelling a host with a trailing dot, capitals or Unicode names a host that the certificate
    names in its resolved form.
- The CA's key is never written, and the starter drops it once the leaf is signed.
- The leaf and its key are in `<proxy log's name>.leaf/` beside the proxy's log, in the runner's or
  the command's session directory. That directory is the user's alone, and no command's profile
  grants it. The proxy holds the key because it answers the TLS handshake as each host.
- The CA certificate is in `<proxy log's name>.trust/`, as `ca.crt` and as `truststore.p12`.
  - The command's profile grants those two files as reads, not their directory, and the command's
    environment names them ("The command's lifetime and environment").
  - The files are outside `tmp/`, so no command replaces what the next command trusts.
- The sandbox container trusts none of these CAs, and a host command does not trust the
  workspace's CA. A leaf's key serves one proxy's host commands and nothing else.
- A launch attaching to another launch's runtime names that runtime's trust directory, as it names
  that runtime's `tmp/` and proxy port, so its commands trust the proxy they use
  (`RunnerRuntimes`, the attachment).

Measured by the acceptance test, whose recorded run is at the top of this document:

- The test's supervisor and channel rows start each proxy under a profile that reads the leaf's
  directory, and each command under a profile that reads the two trust files. "fetch allowed Maven
  artifact via proxy" passes only through both.
- A `PUT` to `repo1.maven.org` gets `403`, and the supervisor names the request.

Measured through a sandbox session's proxy, which inspects the same hosts with a handshake per
request:

| program | resolved | result |
|---|---|---|
| sbt 2.0.9 | `spark-sql` 3.5.1, `update`, empty Coursier cache | 1960 files, 240 MB, 36 s |
| mill 1.0.6, JVM launcher | the same, `app.resolvedMvnDeps`, its own runtime included | 4040 files, 336 MB, 55 s |
| Gradle 9.7.1 | `src/probe/gradle-fixture`, `test`, the distribution present | 32 files, 6 s |
| Maven 3.9.16 | `src/probe/mvn-fixture`, `test`, the distribution's download included | 418 files, 14 MB, 37 s |

- Gradle and Maven fail with `PKIX path building failed` under a `javax.net.ssl.trustStore` naming
  a store without the CA. The wrapper script's distribution download and the resolver fail alike,
  so both read the property.
- A JVM given a `PKCS12` store holding the CA alone, and the store's password, fetches through that
  proxy. Given no password, the JVM loads no certificate (`the trustAnchors parameter must be
  non-empty`).
- Not measured: a Gradle plugin applied by id, which resolves from `plugins.gradle.org`.

The proxy reads `HTTPS_PROXY` as the container's copy does (`egress-proxy.md`, "Through an
upstream proxy"). On a host behind an upstream proxy, the command's artifact fetches leave through
the upstream proxy. A loopback helper on the host is reachable from here, unlike from the
container.

## Configuration

To allow artifact downloads beyond Maven Central, add repository hosts to this workspace file:

```text
.ko-agent-sandbox/run-on-host/<program>/egress/rule
```

- Each program has its own file, so a repository that uses more than one program grants each
  program only what it resolves.
- The grammar is the file's own, narrower than the proxy's: `allow https://<host>/ read` lines and
  comments, nothing else. Validation refuses any other grant, a path, a provider or a deny, rather
  than passing it through.
  - The full grammar would let one `allow model-provider` line expand into endpoints that are no
    artifact repository.
  - A `tunnel` or `method=` word would let a host command write to a host, which no host command
    may.
- A launch selecting the program prints, per file, `<file>: <count> widening lines`, then the
  file's hosts indented. Two or more hosts are joined into `allow read: <host>, <host>`.
  - The launch refuses a file outside the grammar, or a file naming a host the proxy refuses, such
    as an IP literal.
  - So you see a host that arrived with the repository before the agent's first command.
- The supervisor hands the proxy `deny defaults`, Maven Central, then the file's lines
  (`RunOnHostPrereqs.egressRuleText`), so the container's catalog contributes nothing.

The file inherits the directory's properties:

- the workspace filter freezes it at any depth;
- the launcher reads it on the host;
- it is reviewed in a pull request like any other file;
- `run-on-host/` accepts only recognized configuration entries, as does `.ko-agent-sandbox`. A
  stray entry fails the launch instead of being ignored (`SandboxWorkspace.boundaryDirRefusal`,
  `RunOnHostPrereqs.readProgramRules`).

No program needs a GitHub release CDN. The one download that would need it, the `mill` executable,
is provisioned on the host instead.

Derived paths come from Coursier conventions and environment APIs. Advanced overrides
(`cache-root`, `jvm-root`, `install-root`) are not added until needed.

## The run-on-host cache

Host commands get their own cache root, per workspace:
`${XDG_CACHE_HOME:-$HOME/.cache}/ko-agent-sandbox/run-on-host/<workspaceId>/`.

- The root holds Coursier's `v1`, sbt's global base and Ivy home, Gradle's user home and Maven's
  local repository under one directory.
  - So `--reset-run-on-host` is a single removal, and `--reset` takes the root with the workspace's
    other state.
  - A further cache kind can join without moving anything.
- The root is discovered exactly as the launcher's state root is, so the two answer alike on one
  machine.
- A relative override is refused, because it would resolve against the repository being
  sandboxed. A root overlapping the workspace is refused outright.
- A cache directory whose canonical path lies over or under the launcher's state root is refused
  too (`RunOnHostPrereqs.cachePathClearOfStateRoot`).
  - `XDG_STATE_HOME` or a symlinked `run-on-host` can nest the two. So the separation argued below
    is checked on every command and reset, rather than assumed.

Why not the user's cache: `SECURITY.md` "Cache poisoning stops at the workspace" has the security
argument. The cost is a cold cache on a workspace's first agent command, warm from the second
onward.

Why not the launcher state root:

- The state root is kind-first (`tls/<id>`, `log/<id>`, …), and the proxy's audit log must not be
  stored beside the CA key.
- On the host, the command runs as the user's own uid, which owns that key. So file permissions
  protect nothing, and only the profile denies access.
  - A separate root makes that denial structural: no path the command is ever granted has a
    sensitive ancestor or sibling.
- `XDG_CACHE_HOME` is also where a reconstructible cache belongs.

How each program reaches its cache:

- the supervisor sets `COURSIER_CACHE` to the `v1` directory, which the sbt script, sbt's own
  resolution and Coursier all honour;
- sbt's own two caches travel as the `java -D` properties above, which sbt's launcher reads;
- Gradle's user home travels as `GRADLE_USER_HOME`;
- Maven's local repository travels as the `java -D` property that Maven's CLI reads.

## Sources

- Mill 1.1.10's daemon and launcher — the port-0 bind, `socketPort` and `processId`, the shutdown
  on a client's disconnect mid-command, the idle timeout, the fingerprint the launcher restarts
  on, its ten-second connect retry, and the `java-home` file of a pinned JVM:
  - https://github.com/com-lihaoyi/mill/blob/1.1.10/libs/daemon/server/src/mill/server/Server.scala
  - https://github.com/com-lihaoyi/mill/blob/1.1.10/libs/daemon/client/src/mill/client/ServerLauncher.scala
  - https://github.com/com-lihaoyi/mill/blob/1.1.10/runner/launcher/src/mill/launcher/MillProcessLauncher.scala
  - https://github.com/com-lihaoyi/mill/blob/1.1.10/runner/launcher/src/mill/launcher/MillServerLauncher.scala
  - https://github.com/com-lihaoyi/mill/blob/1.1.10/runner/launcher/src/mill/launcher/CoursierClient.scala
- Mill's JVM for an unset `mill-jvm-version` — the built-in id from 1.1.0 on, and 1.0's `java`
  from `PATH`:
  - https://github.com/com-lihaoyi/mill/blob/1.1.0/runner/launcher/src/mill/launcher/MillProcessLauncher.scala
  - https://github.com/com-lihaoyi/mill/blob/1.1.10/default-mill-jvm-version
  - https://github.com/com-lihaoyi/mill/blob/1.3.0/default-mill-jvm-version
  - https://github.com/com-lihaoyi/mill/blob/1.1.10/changelog.adoc
  - https://github.com/com-lihaoyi/mill/blob/1.0.6/runner/launcher/src/mill/launcher/MillProcessLauncher.java
- sbt server — domain-socket and TCP modes, the port file, discovery and the token:
  - https://www.scala-sbt.org/1.x/docs/sbt-server.html
- sbt 1.13.0 and 2.0.9 — the thin client's server fork and its denied-connect retry, the
  disconnect cancelling the channel's exec, the `proc` registry and `notifyOtherServers`, the
  server's idle timeout, the boot socket's path (the same paths at v1.13.0):
  - https://github.com/sbt/sbt/blob/v2.0.9/main-command/src/main/scala/sbt/internal/client/NetworkClient.scala
  - https://github.com/sbt/sbt/blob/v2.0.9/main/src/main/scala/sbt/internal/CommandExchange.scala
  - https://github.com/sbt/sbt/blob/v2.0.9/main/src/main/scala/sbt/Defaults.scala
  - https://github.com/sbt/sbt/blob/v2.0.9/main-command/src/main/java/sbt/internal/BootServerSocket.java
- sbt 1.13.0 and 2.0.9 — the Ivy home from `sbt.ivy.home` to the lock file; sbt 1.13.0 takes
  `Ivy.scala` from librarymanagement-ivy 1.12.3, which has no tag, so its sources jar is the link:
  - https://github.com/sbt/sbt/blob/v2.0.9/launch/src/main/input_resources/sbt/sbt.boot.properties
  - https://github.com/sbt/sbt/blob/v2.0.9/lm-ivy/src/main/scala/sbt/internal/librarymanagement/Ivy.scala
  - https://repo1.maven.org/maven2/org/scala-sbt/librarymanagement-ivy_2.12/1.12.3/librarymanagement-ivy_2.12-1.12.3-sources.jar
- Gradle 9.8.0's wrapper — the distribution directory, the properties it reads, the user home:
  - https://github.com/gradle/gradle/blob/v9.8.0/platforms/core-runtime/wrapper-shared/src/main/java/org/gradle/wrapper/PathAssembler.java
  - https://github.com/gradle/gradle/blob/v9.8.0/platforms/core-runtime/wrapper-shared/src/main/java/org/gradle/wrapper/WrapperExecutor.java
  - https://github.com/gradle/gradle/blob/v9.8.0/platforms/core-runtime/wrapper-shared/src/main/java/org/gradle/wrapper/Install.java
  - https://github.com/gradle/gradle/blob/v9.8.0/platforms/core-runtime/wrapper-main/src/main/java/org/gradle/wrapper/GradleWrapperMain.java
- Gradle 9.8.0's daemon — its detach at start, the client's fork with its own environment and
  the registry option, the compatibility check on the client's immutable properties, the cancel
  on a client's disconnect, `--stop`, and the file lock's UDP socket:
  - https://github.com/gradle/gradle/blob/v9.8.0/platforms/core-runtime/daemon-server/src/main/java/org/gradle/launcher/daemon/bootstrap/DaemonMain.java
  - https://github.com/gradle/gradle/blob/v9.8.0/platforms/core-runtime/client-services/src/main/java/org/gradle/launcher/daemon/client/DefaultDaemonStarter.java
  - https://github.com/gradle/gradle/blob/v9.8.0/platforms/core-runtime/process-services/src/main/java/org/gradle/process/internal/DefaultProcessForkOptions.java
  - https://github.com/gradle/gradle/blob/v9.8.0/platforms/core-runtime/daemon-protocol/src/main/java/org/gradle/launcher/daemon/context/DaemonCompatibilitySpec.java
  - https://github.com/gradle/gradle/blob/v9.8.0/platforms/core-runtime/launcher/src/main/java/org/gradle/launcher/cli/converter/InitialPropertiesConverter.java
  - https://github.com/gradle/gradle/blob/v9.8.0/platforms/core-runtime/launcher/src/main/java/org/gradle/launcher/daemon/server/DaemonStateCoordinator.java
  - https://github.com/gradle/gradle/blob/v9.8.0/platforms/core-runtime/launcher/src/main/java/org/gradle/launcher/daemon/server/exec/WatchForDisconnection.java
  - https://github.com/gradle/gradle/blob/v9.8.0/platforms/core-runtime/client-services/src/main/java/org/gradle/launcher/daemon/client/DaemonStopClient.java
  - https://github.com/gradle/gradle/blob/v9.8.0/platforms/core-execution/persistent-cache/src/main/java/org/gradle/cache/internal/locklistener/DefaultFileLockCommunicator.java
- Gradle toolchains — auto-detection, auto-provisioning and `installations.paths`:
  - https://docs.gradle.org/current/userguide/toolchains.html
- Gradle's configuration precedence — a `-D` over every `gradle.properties`:
  - https://docs.gradle.org/current/userguide/build_environment.html
- Surefire fork communication — process pipes by default, TCP by configuration:
  - https://maven.apache.org/surefire/maven-surefire-plugin/examples/process-communication.html
- Maven Resolver configuration — `useSystemProperties`:
  - https://maven.apache.org/resolver/configuration.html
