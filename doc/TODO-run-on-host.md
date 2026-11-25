# TODO — run on host

This file lists the remaining work on `--run-on-host` (`run-on-host.md`), under the criteria that
`TODO.md` states for its own items.

## Host process observations without helper processes

- [ ] Start no `ps`, `pgrep` or `lsof` under `--run-on-host`, where `RunOnHostSession.HostProcesses`
  starts them by absolute path. Make the kernel calls behind those programs through the JDK's
  foreign-function API instead, as `src/probe/ProcArgs.java` calls `sysctl`.
  - A helper inherits the environment of the runner or supervisor that starts it, and a call does
    not.
  - `ps` and `pgrep` read `sysctl` `kern.proc` and `kern.procargs2`; `lsof` reads libproc's
    `proc_pidinfo` and `proc_pidfdinfo`.
  - The registration script's `ps` runs inside the leader's perl and needs another form.

## What a host command reads of other processes

`seatbelt.md`, "Processes", has `SeatbeltProfile.ProcessReadRule` and its
measurement.

- [ ] Measure the older `kern.procargs` call under the rule; the probe reads `kern.procargs2`
  alone.
- [ ] Start what the launcher starts, the runner, each supervisor and `podman`, with a controlled
  environment: a fixed set of names and the `--env` forwards, and nothing else from the launching
  shell. The profile's rule is the boundary, and the controlled environment bounds what a miss in
  the rule exposes.
  - `podman`'s set starts from the variables its manual documents (podman(1), "Environment
    Variables"): `CONTAINERS_CONF`, `CONTAINER_CONNECTION`, `CONTAINER_HOST`,
    `CONTAINER_SSHKEY`, `PODMAN_CONNECTIONS_CONF`, `TMPDIR` and the `XDG_*` directories among
    them. `podman`'s client also reads `CONTAINER_PROXY` (`pkg/bindings/connection.go`), which
    that page does not list, so the page is not the whole set.
- [ ] Decide the operations, other than `process-info-pidinfo`, that `(deny default)` leaves
  allowed.
  - `(deny default)` leaves `process-info*`, `nvram*`, `iokit-get-properties` and
    `file-map-executable` allowed (Firefox's `SandboxPolicyContent.h`: "These are not included in
    (deny default)"; Chromium's `renderer.sb` denies the first three as "allowed by default").
  - The command profile names only `process-info-pidinfo`, which `ProcessReadRule` denies outside
    the command's sandbox.
  - The probe's `ops` mode measures a family by leaving the family's allow out under
    `(deny default)`. `(deny default)` denies none of these operations, so the mode cannot show
    that the JDK does without `file-map-executable` (`seatbelt.md`, "What the JDK needs") or
    `process-info*`.
- [ ] Measure under the rendered profile the other routes to another process's arguments,
  environment or memory. The profile grants none of these routes by name:
  - a task port (`task_for_pid` and its read, inspect and name flavors);
  - the process service `com.apple.sysmond` behind `pgrep`. The profile's one Mach service is the
    resolver's (`SeatbeltProfile.MachServices`), and `pgrep` fails under the profile with
    "sysmond service not found".

## The profile probe's confined sbt in this worktree

- [ ] `RunOnHostProfileIterate.scala`'s `runCommand` fails under the rendered profile after
  `emit`, which runs an unconfined sbt in the same worktree. The cause is not found.
  - `sbt about` stops at `Compile / previousCompile` with `Operation not permitted` on
    `target/out/jvm/scala-3.8.4/ko-agent-sandbox-build/zinc/inc_compile_3.zip`, then prints
    "failed to connect to server" (2026-10-03).
  - `narrow` runs the same function in this worktree; `mach` runs it in its fixture.

## A terminal's sbt in a launch's server

`SECURITY.md`, "Cache poisoning stops at the workspace", names the exception: while a launch's sbt
server holds a build directory's portfile, your terminal's `sbt` there attaches to that server and
builds from the run-on-host caches. On 2026-11-14 a terminal's `sbt testWithPodman` reached such a
server and was refused there (`project/KoAgentSandboxHelper.scala`). A build's own refusal covers
only the tasks that the build wraps.

- [ ] Keep a terminal's client off the launch's server, or have the launcher refuse or warn before
  that client's command runs. First read what sbt 2's server and thin client offer for choosing or
  authenticating a client, and how the runner's own clients find the server.
- [ ] Measure whether a terminal's `./mill` attaches to the launch's daemon the same way under Mill
  1.1 and earlier, and whether a terminal's `gradle` stays off the launch's daemon, whose registry
  is under the runner's `tmp/`.

## Forked sbt tests under `--run-on-host`

sbt 2 reaches a forked test JVM on JDK 16 or later through a Unix socket under `$XDG_RUNTIME_DIR`,
else `java.io.tmpdir`, which the command profile permits: ko-review's forked suites start on the
host. Two configurations bind a TCP listener for the fork instead, and the profile grants sbt no
listener (`run-on-host-internals.md`, "Network"):

- sbt 1, whose `ForkTests` binds a port on every address:
  https://github.com/sbt/sbt/blob/v1.13.1/main-actions/src/main/scala/sbt/ForkTests.scala#L82
- sbt 2.1 with `testPersistentWorker := true`:
  https://github.com/sbt/sbt/blob/v2.1.0/main-actions/src/main/scala/sbt/internal/WorkerExchange.scala#L205

- [ ] Add a forked-test row for each configuration to the run-on-host checks and run them on macOS.
  Record the outcome in "Network"; if the fork fails, say there what a build with
  `Test / fork := true` does instead.

## What the container allows and a host command's profile denies

A host command's profile starts from `(deny default)`. Comparing it with the container found three
denials with no recorded reason. The profile grants them, and SeatbeltCheck has rows for each:
reads under `.git` and `.ko-agent-sandbox`, running programs from the run-on-host caches, and
signals to the command's own processes. Writes to `.git`'s listed state have an entry of their own,
below. Listeners and other processes' arguments stay denied for the reasons in `SECURITY.md`, "Run
on host".

- [ ] Check every SBPL operation that the profile leaves under `(deny default)` against what the
  container allows. For each one the container allows, grant it with a SeatbeltCheck row, or record
  why it stays denied. Chromium's and WebKit's profiles name the operations in use.
  - Not yet checked: POSIX shared memory and semaphores (`ipc-posix-*`), pseudo-terminals,
    `file-ioctl`, and the Mach services beyond those that the profile grants.

## Writable Git state under `--run-on-host`

In the container, the agent writes the Git state that the workspace policy lists: refs, objects,
the index, HEAD and the like. A host command's profile denies every write under `.git`, so a build
or test that commits, tags or stages in the workspace's repository fails on the host and works in
the container.

- [ ] Grant a host command the writes that the workspace policy allows under `.git`, and keep
  config, hooks and the other frozen entries denied. Take the entries from the policy, not from a
  copy, and carry over its cases, such as a symlink at `objects` that leads back into the workspace
  (`SECURITY.md`, "The host's git executing what the sandbox wrote";
  `ko-agent-fs/policy/doc/git-metadata.md`). Add SeatbeltCheck rows for a granted write and a
  frozen one.

## Symlinks that host commands create

A host command can create a symlink in the workspace that leads outside it, which the session's
backends refuse (`SECURITY.md`, "Run on host"). sbt 2 does so by design: its `target/` outputs link
into its store in the run-on-host cache.

No profile of Chromium (`sandbox/policy/mac`), WebKit (`Source/WebKit/*/…sb.in`), Nix or Codex
filters on a link's target. WebKit's process profiles and Chromium's WebNN profile refuse every new
link with `(deny file-write-create (vnode-type SYMLINK))`, and Chromium's network profile does so
unless a parameter allows it. That rule would break sbt 2.

- [ ] After each command, remove the links that it created whose target resolves outside the
  workspace and the run-on-host caches, and report each one. Add a ChannelCheck row with a planted
  `x -> ~/.ssh`.
  - A walk of the whole workspace finds this repository's links in 0.3s, measured in a session
    over 6,773 entries. Two thirds of those entries are build output under `target/`, so the walk
    grows with a project's build output.
  - Per-file FSEvents events may limit the check to the paths that the command changed; whether
    their flags tell a created symlink apart is unread. Nothing in this repository uses FSEvents
    yet: the supervisor would need a binding to `FSEventStream`, through FFM or a library.

## Deferred — read grants a user adds to a host command's profile

The `curl` that macOS ships does not run under a command's profile: LibreSSL stops at
`fopen('/private/etc/ssl/openssl.cnf')`, `Operation not permitted` (`run-on-host-internals.md`, "The
command's lifetime and environment"). The launcher grants a system path only where a build
measurably needs it (`SeatbeltProfile.SystemPaths.txt`), and no build here runs `curl`.

- [ ] A way for a user to add a read grant, only once a build of theirs needs such a program:
  `/private/etc/ssl/openssl.cnf` is the first case.
  - Where the grant is stated decides who can widen a profile:
    - a file under `.ko-agent-sandbox/run-on-host/` arrives with the repository, as the program's
      rule file does, so the launch prints the file as it prints that rule file's hosts;
    - a launch option is the user's alone.
  - The grant covers reads of single files, never a write, an exec or a directory. A grant for a
    path under the user's home is refused: what a host command cannot read there is its
    confinement.
  - Before choosing the form, measure that `curl` fetches from an allowed host with that one file
    granted. `BuildsCheck`'s "CA bundle variables" rows print what `curl` does, and whether `curl`
    then reads `CURL_CA_BUNDLE` or `SSL_CERT_FILE`.

## Deferred — Node for ScalablyTyped and scalajs-bundler under `--run-on-host`

Both plugins run `npm install` from the sbt JVM, which a host command cannot do (read from the
code, not measured):

- The command's `PATH` is the JDK's `bin` and the system directories, and the profile executes
  nothing else, so no Homebrew, nvm or asdf `node` or `npm` is found or run
  (`RunOnHostSandbox.scala`, the command's environment; `SeatbeltProfile.SystemPaths.txt`).
- `HOME` passes through, so npm's cache is `~/.npm`, which the profile does not grant.
- The plugins, read at scalajs-bundler `2d9cbce` and ScalablyTyped Converter `c2c414f`:
  - scalajs-bundler runs `npm install` (or `yarn`) by name in its install directory under the target
    (`ExternalCommand.scala`). scalajs-bundler runs `node` for bundling (`JSBundler.scala`) and for
    tests under jsdom (`JSDOMNodeJSEnv.scala`), so it needs Node at every build, not only at
    install.
  - ScalablyTyped runs `npm install` (or `yarn`) by name in `<crossTarget>/scalablytyped-npm`
    (`NpmInstall.scala`). Under its external-npm plugin, it calls the project's own `externalNpm`
    task instead, which returns a directory holding `package.json` and `node_modules`
    (`docs/plugin-no-bundler.md`). ScalablyTyped publishes what it converts to the Ivy home's
    `local` (`Utils.IvyLocal`), which the run-on-host cache holds.

- [ ] Measure the workaround that needs no change here: ScalablyTyped's external-npm plugin with
  `externalNpm` returning a directory the session ran `npm install` in, in the container. Record
  whether the conversion then runs on the host without Node.
- [ ] A Node a host command may run, only once a build needs it on the host, in the shape of the
  mill launcher's grant:
  - a Node distribution the user provisions, read-only and executable, on the command's `PATH`,
    never the host's `PATH`;
  - npm's cache in the workspace's run-on-host cache (`npm_config_cache`), not `~/.npm`;
  - the registry allowed in the sbt program's egress rule. `HTTPS_PROXY` and `NODE_EXTRA_CA_CERTS`
    already reach Node (`run-on-host-internals.md`, the CA variables' table). npm's use of the proxy
    and of HTTP/1.1 through the inspecting proxy is still to be measured;
  - what `npm install` then runs on the host: the lifecycle scripts of every package, under the
    command's profile. SECURITY.md's "Run on host" should state that beside the limit that
    `node_modules` already has there.

## Deferred — a bound on a silent host command

The runner's progress bound limits the start of an sbt server and of a mill daemon
(`run-on-host-internals.md`, "The channel and the command", "`mill`"). A command that stalls after
its server or daemon is up, or a Maven command at any point, stays silent until the agent gives up.
Nothing bounds such a command: not the supervisor, not the runner, whose writers die only with
their requester, and not the shim, which reads output to EOF. One form would bound it, and that
form waits on a measurement:

- [ ] A generic bound in the runner: no output for N seconds ends the command through the same
  SIGTERM, so the command's logs are kept. A stderr line names the bound and the run's
  `run-on-host.log`.
  - Silence is measured where the command's bytes are read, and time the pump spends blocked on a
    slow requester does not count.
  - N must exceed a healthy silence: a module compiling, a large download (which the proxy logs
    once, at its start) or a slow test. A value below a healthy silence is not a one-off failure.
    The rerun hits the same silence, and the workspace cannot build on the host until the constant
    changes.
  - Five minutes is the smallest value defensible without measurement.

A time-to-first-output limit would miss stalls after the JVM prints its `_JAVA_OPTIONS` banner.

## Deferred — a container mill or gradle beside the host's daemon

Under `--run-on-host`, the host's mill daemon keeps its lock and `socketPort` in the workspace's
`out/mill-daemon`. A `./mill` run in the container without `MILL_OUTPUT_DIR` uses the same `out/`.
The rules allow the bootstrap's downloads by default, so an agent can run it.

- [ ] Measure, on a small mill build with a host daemon up, what the container's `./mill` does
  with the host's lock and port, and what the host's next command does with what the container
  left.
  - The same run measures a cold compile with and without `MILL_OUTPUT_DIR` under `~/.cache`.
    `../ko-agent-fs/fuse/doc/troubleshooting.md` ("Everything works but slowly") says that this is
    not measured.
  - If the two conflict, the run-on-host text that the launcher appends is the place to tell an
    agent to set the variable.
- [ ] Measure the same conflict for gradle. The two sides' daemon registries are separate: the
  host's registry is under the runner's temporary directory (`RunOnHostSandbox.gradleCommand`),
  and the container's registry is in its gradle user home. But both builds use the workspace's
  `build/` and the locks under its `.gradle/`, and the rules allow `./gradlew`'s download by
  default.

## Deferred — an idle bound for the sbt server

The runner sets no idle bound on its sbt server. The server lives until the launch ends, until
`ko-sandbox-run-on-host sbt shutdown`, or until sbt's own `serverIdleTimeout` of seven days
(`run-on-host.md`, "Startup cost"). A terminal user keeps a warm server on purpose, so
the server's heap is the price chosen. Mill's daemon exits after Mill's own thirty minutes.

The form, if a launch ever wants one:

- The runner keeps the bound, and a launch option selects it. An environment variable cannot
  select it, since the command's environment is closed by design.
- Thirty minutes, Mill's default, is the value to start from.
- Idle time counts from the end of the last sbt command, never from the server's start.
- The runner's serve loop blocks in the handshake reader between requests, so the bound needs a
  timer thread. That thread is the one thread that retires runtimes outside the serial dispatch,
  and it is fenced as follows:
  - one lock covers the runner's runtime state;
  - a request takes the lock, marks the runtime busy and cancels its pending expiry before the
    command receives the runtime, and re-arms the expiry when the command ends;
  - each re-arming increments an idle generation kept with the runtime;
  - an expiry carries the generation it was armed with. Under the lock, the expiry retires the
    runtime only if that instance is idle and its generation is still the expiry's own. So a
    cancelled callback that had left its sleep before a request re-armed the timer does nothing,
    and a timer that outlives a retired runtime does nothing to the replacement.

The bound's tests: a request arriving as the timer fires, that late callback, and a stale timer
after replacement, each leaving one consistent runtime.

## Deferred — readable session directory names under `--run-on-host`

- [ ] Name the sessions `runner-<random>` and `command-<random>` instead of `r<random>` and
  `s<random>` (`RunOnHostSession.Kind`), once the path length allows it.
  - The session's `tmp/` hosts sbt's boot socket. `RunOnHostPrereqs.SessionTmpMaxLength` leaves
    that path 53 characters, of which the root and Java's 20-digit temp-directory name take 51.
  - The longer names need one of two changes:
    - sbt's boot socket comes to need fewer than its 50 characters past the directory. The fix
      that the thin-client entry requests only turns the crash into a message, and lifts no length
      (`upstream-issues.md`, "The JVM thin client crashes instead of reporting a long boot-socket
      path").
    - The session names get a shorter random part of their own, with the collision retry that
      `Files.createTempDirectory` does.
- [ ] Name the root after the launcher and the feature,
  `/private/tmp/ko-agent-sandbox-run-on-host-<uid>` in place of `/private/tmp/ko-agent-<uid>`
  (`RunOnHostSession.root`), under the same budget. Otherwise a second host feature that keeps
  state under `/private/tmp` would land in a root that names neither feature.

## Deferred — the per-command supervisor process under `--run-on-host`

- [ ] Re-evaluate the supervisor, the `--run-command-on-host` process the runner starts for each
  request (`RunOnHostSandbox.runCommandMain`; `run-on-host-internals.md`, "The channel and the
  command").
  - What it buys:
    - the runner's cancel is a SIGTERM to one process, answered by that process's shutdown hook,
      which ends exactly the command's groups and directory;
    - a command's death, however it dies, is confined to its own process and never takes the
      runner and its warm servers with it;
    - the run-on-host checks drive one command's whole lifecycle as `RunOnHost` with no runner,
      which is how `BuildsCheck` and `CommandLifecycleCheck` measure the supervisor.
  - What it costs:
    - one more JVM start per command, about a third of a second in the jar form and tens of
      milliseconds as the native image;
    - a second code path for the command's runtime, the supervisor's own under Maven.
  - The alternative is the same work in a runner thread, with cancellation done by hand. Decide
    with the measured cost per command, and with what the run-on-host checks would drive instead.
