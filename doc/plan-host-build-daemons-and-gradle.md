# Plan: Persistent Host Build Runtimes and Gradle 7/8/9 Host Support

Date: 2026-09-10

Repository: `ken1ma/ko-agent-sandbox`

## Outcome

Implement two ordered phases:

1. Keep the sbt server and the Mill daemon alive across the `sandbox-run-on-host` commands of one
   `ko-agent-sandbox` launch.
2. Add Gradle 7/8/9 host execution using stock Gradle, under a Gradle-only Seatbelt profile that
   allows loopback TCP and UDP both ways, with a warning printed once per launch when that profile
   is first used.

No persistent process survives the launch that owns it. A launch never adopts a runtime whose
owning broker is dead, and tool-generated rendezvous state never establishes ownership.

First-pass acceptance versions:

- sbt 1.13.0 — `src/probe/ivy-fixture` pins 1.12.13 today and moves to 1.13.0 in the same change
- sbt 2.0.8 — this repository's own `project/build.properties`
- Mill 1.1.9 — `src/probe/mill-fixture`
- Gradle 7.6.6, 8.14.5, 9.7.1

Upstream release pages checked 2026-09-10: Mill 1.1.9 is the latest stable Mill 1.x; Gradle's
release page lists 7.6.6, 8.14.5 and 9.7.1 as the current releases of those lines; sbt 1.13.0 is
the current 1.x release.

The Gradle acceptance list is not a promise that every historical 7.x/8.x/9.x release works. The
implementation reads the exact wrapper version; the three above are what is tested and documented.

## Revision — step 3 scope (2026-09-11)

Step 3, as built, takes a deliberate scope reduction from the sections below, decided after
review:

1. **One runtime per canonical build directory and program, per broker — all kept warm.** Not one
   runtime per program. Visiting another build directory leaves the runtimes already made alive
   (`RunOnHostSandbox.BrokerRuntimes.live` is keyed by program and the directory's hash). A runtime
   ends with the launch or when its own proxy is gone — never on a cancel (a cancel follows stock
   sbt), and never because a command came from a different directory. This supersedes section 4's
   "one runtime per program at a time" and section 10's "one runtime per program".
2. **A broker never signals another live broker's server.** When another live broker's session
   owns a build directory's sbt server — its `build-<hash>` names the directory — a command for it
   is refused, not served by ending the other's server. This supersedes section 6.4's "another
   launch's server is ended by its record" and 11's "ended by default … two launches end each
   other's in turn." A dead owner is not live; the scavenger collects it by its own exclusive
   claim (section 2) before a fresh server starts, and a missing portfile alone never authorizes a
   start while a live owner holds the directory. The user's own terminal server is still shut down
   by protocol at the derived socket (section 6.4, unchanged).
3. **A cancel follows stock sbt.** The broker does not retire the server on a cancel: the
   client's disconnect cancels the running exec (`CommandExchange.removeChannel`, `force =
   false`) and the warm server survives for the next command, as it does for a terminal user.
   There is no cancel-retirement path, no background thread, and no pending-cancel marker. This
   drops the repository's earlier, stronger guarantee that nothing a cancelled command started
   survives — a deliberate change, since keeping it would deviate from stock sbt with no
   confinement basis (the lingering work is confined).
4. **Ending another live launch's server — takeover — is deferred** to `doc/TODO.md`,
   "Cross-launch server takeover", separately from sharing one server between launches (section
   11). It needs one exclusion covering identity validation through signalling across
   cancellation, replacement, teardown and scavenging, and deterministic concurrency tests; this
   version does not build that infrastructure.

Build locks and dead-session recovery are unchanged: build locks serialize admission, startup and
commands; the scavenger still collects dead owners through its exclusive condemn-by-rename claim.

## Revision — step 4, Mill as built (2026-09-11)

The Mill runtime reaches the same functions and inherits the step-3 model; where section 7 says
otherwise, the built behavior is:

1. **Another launch's daemon is refused, never signalled**, by its `daemon-mill-<hash>` record
   (`RunOnHostSession.runtimeOwner`), as its sbt server is. The user's own daemon is ended by
   proof once idle, as 7.2 step 0 and 7.3 say, with the idle observation on the daemon's own TCP
   table alone (`MillDaemons.endForeign`): the sbt-server peer argument of 7.3 was for UNIX
   sockets and is not needed here.
2. **A Mill configuration change replaces the daemon under the same proxy**, as section 4 says,
   the launcher assembled afresh since a changed version pin grants another. The key is the
   selected source's text, a superset of Mill's parsed value
   (`RunOnHostPrereqs.millDaemonConfig`).
3. **The daemon's liveness is its own pid and start time**, not its record's spawn: the starter
   exits by design once the daemon is up, so the record's exit file is no evidence.
4. **A daemon whose spawn leader was killed alone is not attributed** — there is no portfile
   analogue — and exits on Mill's idle timeout; `doc/run-on-host.md` "`mill`" states it.
5. The gate's Mill rows (7.6, and the regression tests of 7.3) run through the channel against
   `src/probe/mill-fixture`, whose `run` creates a temporary file, prints where, and sleeps on
   request.
6. **A mill client's temporary directory is the broker's `tmp/`**, not the command's own as
   6.2 has for sbt clients (`RunOnHostSandbox.temporaryDirectories` has why).
7. **A redirected `out/mill-daemon` is refused** before any mill command, with the residual a
   link made after the check leaves stated in `doc/run-on-host.md` "`mill`"
   (`MillDaemons.rendezvousIsOwn`); `MILL_OUTPUT_DIR` is never forwarded.
8. **The daemon configuration takes the build file's header whole**, each source under its own
   name (`RunOnHostPrereqs.millDaemonConfig` has why).

## Revision — Phase 2 scope (2026-09-11)

Re-read before step 6 against Gradle's current releases and sources (9.7.1, master at
2026-09-11) and Phase 1 as built; where sections 12–23 say otherwise, this binds:

1. **One fixture, 9.7.1, and no version check.** Superseded lines get no fixture or branch, as
   sbt's did; `doc/run-on-host.md` records 9.7.1 as the release measured and why older lines
   are out — 8.14 does not run on the JDK 25 the launcher requires, and 9.7.1 runs on JDK 17 to
   26 (Gradle's compatibility matrix) — and Gradle itself refuses a JDK it cannot run on. The
   JDK is the launcher's own JAVA_HOME check (`RunOnHostPrereqs.resolveJdkHome`), so section 17's
   Coursier inventory, its refusals and the per-line JDK column of section 14 are dropped.
2. **The client starts the daemon; the broker ends it by proof.** Gradle's daemon detaches
   itself at start (`DaemonMain` calls `ProcessEnvironment.maybeDetachProcess`, `setsid` on
   POSIX), so it leaves the command's group and session on its own, and ending the command's
   recorded group leaves it alive. Its pid is its group id, and its workers and test executors are
   forked into that group, so the `daemon-gradle-<hash>` record takes each daemon's
   `<pid> <start time>` once observed after every command, a cancelled one included — the
   process whose working directory is `<version>` under the launch's own daemon registry base,
   `org.gradle.daemon.registry.base` under the broker's `tmp/` (`RunOnHostSandbox.gradleCommand`),
   and whose command names `GradleDaemon` — and the launch's end signals the group behind that
   proof, daemon and
   descendants at once, as every recorded group. A daemon no observation reached — one started
   under a broker that died during the command — is confined, holds nothing, and exits on
   Gradle's idle timeout, three hours, once idle: the acceptance `SECURITY.md` "Run on host"
   makes for a Mill daemon whose leader is gone, stated there for Gradle too. One hung in its
   build never becomes idle (`getIdleMillis` is zero outside the idle state), so the residual is
   the daemon both unrecorded and hung. No `gradle --stop`.
3. **Reuse and cancel are Gradle's.** Gradle matches a compatible daemon in the launch's own
   registry and starts another on a mismatch, inside the profile; the broker keeps no reuse key
   beyond the proxy. On a client disconnect the daemon cancels the build and, still busy after
   its ten-second grace, stops itself (`WatchForDisconnection`, `DaemonStateCoordinator`); the
   next command attaches or starts one. Gate rows assert both; no mechanism.
4. **No warning.** `--run-on-host=gradle` is the opt-in, and the help and `SECURITY.md`'s
   per-program table carry the cost; section 13's warning and its test are dropped.
5. **The prerequisite is the provisioned distribution, nothing parsed.** The distribution
   directory Gradle's wrapper derives for the project's `distributionUrl` under the wrapper's own
   home — `$GRADLE_USER_HOME/wrapper/dists`, else `~/.gradle/wrapper/dists`, as Maven's is under
   `~/.m2/wrapper/dists` — holds `bin/gradle`, granted read and exec as Maven's distribution is,
   or the command is refused naming `./gradlew --version`. Not under the broker's own
   `GRADLE_USER_HOME`, which the build writes: a distribution there would be writable by the
   build under the home's grant, and removed with `--reset-run-on-host`. `distributionBase`,
   `distributionPath` and a `systemProp.gradle.user.home` in the project's `gradle.properties`
   move the wrapper's store to a place the project chooses, and are refused. The URL is not a
   boundary, since the user provisions it unconfined, so section 15's official-URL rule and
   version check are dropped
   — Gradle says when a version cannot run on the JDK, and `doc/run-on-host.md` records 9.7.1
   as the release measured. Section 18's three properties stay as three `-D`s on the command
   line, so a toolchain the profile would deny anyway fails naming the toolchain, not `EPERM`.
6. The UDP lock communicator (`DefaultFileLockCommunicator`) and the port-0 TCP listeners are in
   current master, so section 12's probes went first. Measured (G1–G10): SBPL's `localhost`
   class is this host's addresses, the wildcard bind included, and no spelling names loopback
   alone; the candidate rule set keeps other hosts out as destinations (G12) and cannot keep a
   wildcard-bound listener from the LAN. Decided on that measurement: Gradle runs on the host
   under Mill's daemon grant plus outbound to any port of this host, and `SECURITY.md`'s
   per-program table says what the user gives up (section 12, "Security model" and 7.4 carry
   the measured wording). The plan's earlier "loopback" wording rested on a premise the probe
   refuted.

The Phase 2 list under "Implementation order" is the revised one.

---

# Security model: one important exception

Do **not** force every build tool into one network profile. Each program gets the narrowest
profile a stock tool of that program can run under:

```text
sbt
  the proxy's port; UNIX-domain sockets under the broker's and the command's directories

Maven
  the proxy's port

Mill
  the daemon's group: the proxy's port, plus listeners on any port at any address of this
  host (the daemon binds port 0 on the loopback address; SBPL's "localhost" class admits the
  wildcard and the LAN address too — measured, G1, G9, G10)
  each client: the proxy's port, plus outbound to the daemon's one port

Gradle
  Mill's daemon grant, plus outbound to any port of this host, TCP and UDP
  other hosts stay denied as destinations, LAN and Internet; Internet only through the egress proxy
```

Gradle is deliberately different. Established for stock Gradle 9.7.1:

1. Gradle internal messaging uses TCP listeners bound to port 0, for daemon/client and
   worker-process communication.
2. Gradle file-lock communication uses a UDP listener bound to port 0.
3. Those ports are dynamically allocated; no supported Gradle setting constrains them to a range.
4. The UDP file-lock mechanism still matters under `--offline` and `--no-daemon`; disabling the
   daemon does not remove the problem.
5. Making stock Gradle obey a fixed-port policy would need Gradle patching, JVM instrumentation,
   OS-level ephemeral-port manipulation, or equivalent invasive machinery.

`ko-agent-sandbox` does not take on that maintenance burden. Instead:

> Gradle host execution is supported with broader host-loopback TCP/UDP authority than the other
> host build tools. This is a documented exception, not an accidental regression.

The Gradle profile is Gradle-specific in code and tests; the common profile is not weakened.

Mill's listener grant is the smaller exception of the same kind, and is stated the same way
(section 7.4): what the daemon's group can do, the build's own forked processes can do too.

---

# Current baseline to preserve

What the code does today, read from the sources named; the plan changes only what it names.

- One **broker** per launch (`RunOnHostChannel.serveMain`, `--serve-run-on-host`): a detached
  process of the launcher's own executable, spawned before the launcher hands over to podman. It
  serves the channel while `podman container inspect` reports the container running, exits when
  it stops, and on TERM its shutdown hook ends the command it is running. It is the process whose
  lifetime is the launch's.
- One **command session** per relayed command (`RunOnHostSession`, `RunOnHostSandbox.run`,
  `--run-command-on-host`): a directory under `/private/tmp/ko-agent-<uid>`, published by rename,
  locked while the wrapper lives, with `records/` naming each process group the wrapper spawned
  (`<pgid> <leader start time>`), a `tmp/` the profile grants, the command's own proxy
  (`records/proxy`), and the client (`records/client`) run under the generated profile.
- The **scavenger** (`RunOnHostSession.scavenge`) runs at every wrapper start: an unlocked session
  is dead, is condemned by rename, its recorded groups are ended only behind a live leader with
  the recorded start time, and its sbt server is ended by protocol at the socket the project's
  portfile names — only when that socket resolves inside the condemned directory.
- **sbt**: the wrapper runs `sbt --jvm-client -batch -java-home <jdk> <args>`. The thin client
  forks the server itself, as `<sbt script> <sbt args> --detach-stdio --server` with the project
  as its working directory (`NetworkClient.scala`, v1.13.0 and v2.0.8), so the server inherits the
  client's Seatbelt profile, its environment and its process group (`session-recovery.sh`, M3),
  and dies when the wrapper ends that group. A foreign live server holding the portfile is a
  refusal, or is shut down under `--auto-shutdown-foreign-sbt-on-host`.
- **Mill**: the wrapper runs `<project>/mill --no-daemon <args>`. Nothing in the wrapper reads,
  clears or writes `out/mill-daemon/`; the gate clears it once before its Mill rows.
- **Maven**: one-shot, and stays so.
- **The gate** (`src/probe/run-on-host-profile-gate.sh`) drives the wrapper directly through the
  test entry `RunOnHost`, never through a broker.
- Host-command failure never expands permissions or falls back to the container; only a
  Coursier-managed JDK is accepted; direct Internet access is denied in favor of the proxy; no
  loopback destination but the command's proxy is granted; no loopback listener is granted.

Files this plan touches: `doc/run-on-host.md`, `SECURITY.md`, `doc/TODO.md`, `README.md`, the
agent instructions in `AgentSandboxLauncher.scala` (the "Run on host" section), and
`RunOnHostChannel.scala`, `RunOnHostSession.scala`, `RunOnHostPrereqs.scala`,
`RunOnHostSandbox.scala`, `SeatbeltProfile.scala`, `SbtServerShutdown.scala`, the probes and
fixtures under `src/probe/`, and the test entry `src/test/scala/RunOnHost.scala`.

Preserve the project-scoped caches, the foreign-server protections, the filesystem rules, the
`.git` and `.ko-agent-sandbox` denials, the closed command environment and the egress-proxy policy
unless a section below changes them.

---

# Phase 1 — persistent sbt and Mill runtimes

## 1. Two sessions of the existing kind, one owner

The broker already has the launch's lifetime, so it becomes the owner of everything that must
outlive a command. The persistent state is a session of the kind `RunOnHostSession` already
implements — published by rename, locked while its owner lives, records naming its groups — held
by the broker rather than by a wrapper. The two kinds are told apart by who holds the lock:

```text
/private/tmp/ko-agent-<uid>/
├── b<random>/          the broker's session: one per launch, locked by the broker
│   ├── lock, project
│   ├── tmp/            XDG_RUNTIME_DIR and SBT_GLOBAL_SERVER_DIR of the sbt server and its clients
│   ├── records/        proxy-sbt-<hash>, server-sbt-<hash>, proxy-mill-<hash>, daemon-mill-<hash>
│   ├── build-<hash>    the canonical build directory the records of that hash serve
│   └── proxy-sbt-<hash>.log, proxy-mill-<hash>.log
├── s<random>/          a command's session: one per relayed command, locked by its wrapper
│   ├── lock, project, tmp/, records/client, profile.sb
│   └── proxy.log       Maven only: its proxy still has the command's lifetime
├── build-lock/         one file per build directory and program, held while a client runs
│   └── sbt-<hash>, mill-<hash>   (section 3)
└── staging/, condemned/, root-lock
```

Flat siblings, not a nesting: sbt's boot socket path must fit `sun_path`
(`RunOnHostPrereqs.SessionTmpMaxLength`), and the scavenger's flat scan stays as it is but for
one exclusion: `build-lock/` joins `staging/`, `condemned/` and `root-lock` in the names it skips,
since a directory without a `lock` file reads as a dead session to it, and a build lock deleted
and recreated would let two brokers hold different inodes of one lock; a unit test scavenges
with a build lock held. The build locks are the one other new entry, held by the command's own
process through `flock(2)` across its spawn's exec (section 3). The words are the repository's:
**the broker's session** and **the
command's session**; the processes are **the broker's proxy**, **the broker's sbt server** and
**the broker's mill daemon**; and **a runtime** is one program's proxy plus its server or daemon,
a word this document uses for that alone — the profile's *runtime authority* stays that phrase.

One broker holds one sbt runtime and one mill runtime per build directory it visits (see the
step-3 revision above) — each a proxy plus its server or daemon — and Maven stays one-shot with a
per-command proxy as today. A runtime's records and
its `build-<hash>` file carry the same hash of its canonical build directory, the hash the build
lock of section 3 is named by, and `build-<hash>` is published by rename before the first record
of that hash and removed after the last is retired. Another broker reading the pair for one hash
therefore reads one runtime's directory and one runtime's processes, never a directory of one
and a process of its successor; a record without its `build-<hash>` is unproven and skipped.

## 2. Lifetime is the broker's

- **Normal end.** The broker's serve loop returns when the container is gone; before exiting it
  ends its session with `RunOnHostSession.endSession`, the wrapper's own teardown: every recorded
  group ended, TERM then KILL behind its live leader, then a protocol shutdown to whatever still
  answers at the build directory's portfile, then the session removed. Nothing is added to that
  call: TERM is the clean end for a provable group — the server flushes its portfile on it — and
  the protocol step exists for the orphan the scavenger cannot prove.
- **TERM.** The broker's shutdown hook ends the running command and waits for the wrapper's
  teardown, then ends the runtimes the same way.
- **SIGKILL, or the machine dying under it.** The wrapper's stdin is the broker's pipe, so a
  broker gone by any death ends the running command the way the requester's closed `ctl` does,
  through the wrapper's own teardown, under the build lock the wrapper itself holds (section
  3). The broker's records stay, and the next start — the next launch's broker, or any
  wrapper — scavenges the session with the existing machinery: groups ended behind their live
  leaders, the sbt server ended by portfile attribution since its socket is under that session's
  `tmp/`. Until such a start, the orphaned server lives: today's window for a killed wrapper,
  unchanged in kind.
- **A command's end or cancel** ends the command's own session and group only. What that means to
  the server or daemon is per program (6.3, 7.5).
- **A record is reused only after its group is ended.** A registered spawn stays alive as its
  group's provable leader after its child exits, so a server or daemon that is gone — retired by
  key, exited on its own, ended by a cancel or by `shutdown` — still has a live leader and may have
  left a descendant. Before any replacement the broker ends that record's group
  (`endRecordedGroups` on the one record: TERM then KILL behind the live leader) and deletes the
  record; only then does a new spawn publish the same name. Overwriting the record first would
  strand whatever the old group still held.
- **A new launch** publishes a new broker session and, in Phase 1, reuses nothing: there is no
  path by which a broker adopts a session it did not publish, so the invariant holds by
  construction, and the regression test is that a planted `active.json`, `out/mill-daemon/*`,
  PID file or record names nothing the new broker connects to, signals or grants. Sharing a
  live launch's runtime, by that broker's own descriptor and never by rendezvous state, is the
  deferred design of section 11.

Tool-generated PID, port and rendezvous files are protocol state, never authorization.

## 3. Who does what: the broker prepares, the wrapper runs

Per request, before spawning the command wrapper, the broker:

1. runs today's steps 1–5 — `RunOnHostSandbox.assemble` and `readProgramRules` — for the
   requested program, and for Mill resolves the pinned version, from the **build directory**: the
   request's validated working directory, where the wrapper already runs the client. sbt's
   portfile is `<cwd>/project/target/active.json` and Mill's `out/` is the cwd's, so a nested
   build is another build: Mill's version files as the bootstrap reads them from its cwd, the
   foreign checks, the records' attribution and the reuse key all take the build directory, while
   the grants stay the project's;
2. compares the result with its live runtime for that program (section 4): reuse, or retire and
   recreate;
3. ensures the runtime exists: the proxy (section 5), then for sbt the server (section 6) and for
   Mill the daemon (section 7);
4. spawns `--run-command-on-host` with the runtime's parameters added to today's arguments: the
   broker's session directory, the proxy port, and for Mill the daemon's port.

The broker serves one request at a time — `RunOnHostChannel.cycle` reads the next handshake only
after `transact` returns, the serial-by-design rule `run-on-host.md` states — so within one launch
runtime selection, start, retirement and the commands themselves never overlap. That is an
invariant the tests keep, not an accident: concurrent host commands within one launch are out of
scope for Phase 1, and a request queued behind a running one sees the runtime the first left.

Across launches the same holds by a **build lock**: a file under `build-lock/`, named by the
program and a hash of the canonical build directory, that the command's own process holds for
its whole life. The spawn takes it through `flock(2)` before it execs the wrapper
(`RunOnHostSession.lockedSpawn`): the lock belongs to the open file description, so it survives
the exec, reaches none of the wrapper's children, and is released only when the wrapper exits,
its teardown included — a broker's death, which ends the wrapper through its pipe (section 2),
frees nothing the wrapper holds. A broker taking a foreign runtime over (6.4, 7.3) holds the
lock from its first observation until its own runtime is up, and the broker's own work under
it before a command — observing, starting or retiring a runtime (steps 2 and 3) — has the spawn
take the lock first and exec the wrapper on the broker's word (implementation step 2). So while
any launch's client runs or cleans up, no other launch observes, ends or starts anything for
that build; while one takes over, none dispatches a client to the runtime being ended. Two
launches on one project therefore queue behind each other's commands — the spawn says so on the
requester's stderr — and "never a broker's build in flight" is enforced, not observed. A spawn
blocked on the lock is ended when its requester leaves, as a running command is, and watches the
broker's pipe as the wrapper does, so a dead broker dispatches nothing. The lock covers clients
the brokers dispatch, and the gate takes it around its test entry through the same spawn, whose
exec keeps the wrapper's pid for the gate's kill rows; a client from the user's terminal is
covered by the idle observation of 7.3 alone.

The wrapper keeps its own session, its registered client group, its shutdown-hook teardown and its
exit-code protocol. Given no runtime parameters — the gate's test entry, section 9 — it creates
a runtime for the one command and ends it after, with the broker's own functions, which is
today's behavior; that is how the abstraction is introduced before any process persists
(implementation step 1).

## 4. Reuse, and what a runtime keeps from its start

A runtime is created from what the broker computed in step 1 — the whole `Assembled` (JDK
home, executable, distribution, cache paths), the program's rule lines, the forwarded name/value
pairs — and keeps all of it until it ends, the way a warm server keeps what it started with. The
reuse key, what makes the broker retire a runtime and create another before a command, is only
the build directory and the program's own start-time configuration, exactly where the stock tool
restarts on it:

- **sbt:** nothing. A warm server keeps the `sbt.version` and the options it started with —
  `.sbtopts`, `.jvmopts`, and the `-D` and `-J` arguments of the request that started it (6.1)
  — until it is shut down, as a warm server in a terminal does: the thin client attaches to
  whatever server the portfile names and compares no version, and `NetworkClient.serverCommand`
  forwards options only when it starts a server, so a later request's `-D` reaches nothing. The
  document says so, and `sandbox-run-on-host sbt shutdown` is how a changed version or option
  takes effect. A broker that restarted on such a change would restart where sbt does not; that
  is left out, at least initially.
- **Mill:** the inputs of Mill's own restart decision (`ServerLauncher.DaemonConfig`):
  `mill-version`, `mill-jvm-version`, `mill-jvm-opts` and `mill-repositories`, each from the three
  places Mill reads it — `.<key>`, `.config/<key>`, the build-file header
  (`MillProcessLauncher.loadMillConfig`). `JAVA_OPTS` and `JDK_JAVA_OPTIONS`, its other inputs,
  are absent by the closed environment. So Mill's launcher never sees a mismatch: it would remove
  the daemon's `processId` and start a replacement from the client's own profile, which cannot
  bind (7.4) — a failure closed, and a test proves no daemon ever runs in a client's group. The
  key spares the user that one failed command and its message, at the price of four small reads.

A key that differs from a live runtime's replaces that runtime's server — the recorded group
ended and its record deleted (section 2) — under the same proxy; nothing about a live server or
daemon is mutated in place. Per the step-3 revision above, the broker keeps one runtime per
build directory and program, all warm at once, so visiting another build directory adds a runtime
rather than retiring the current one.

So what actually triggers a runtime's replacement is its own proxy going, or — Mill only — a
Mill version or option file edited (a warm sbt server keeps the version and options it started
with until `shutdown`, as in a terminal). A request from another build directory retires nothing:
it adds a runtime, and both stay warm. The program's rule file is read when a runtime is created,
and an edit does not restart a running one: it takes effect at the next creation — after
`sandbox-run-on-host <program> shutdown`, a Mill idle exit or option change, or the next
launch — as the session's own rule file takes effect at the next launch. Until then the proxy admits
the lines it started with, so a host removed from the
file stays reachable from that runtime, as it stays reachable from the session until the next
launch. A distribution `cs install sbt` replaces mid-launch needs no
restart: the old files stay in Coursier's archive cache, the warm server runs on from them, and
each new client is validated against the new path as today. The broker's environment does not
change within a launch, so the rest of the assembly cannot differ between commands.

Deferred: `doc/TODO.md`, "a rule-file edit taking effect at the next command".

## 5. The broker's proxy

A warm JVM cannot depend on a proxy that dies with its first command: the server's Seatbelt rule
names the proxy port and its `JAVA_TOOL_OPTIONS` carry it, both fixed at exec. So each runtime gets
a proxy with the runtime's lifetime, started as a registered spawn in the broker's session
(`records/proxy-<program>-<hash>`), with the rules read at that start (section 4). Its clients
are the server or daemon and every foreground client of that program.

The denied-host report stays per command: the wrapper records the proxy log's length when the
command starts and reads `deny … CONNECT` lines from that offset when it ends. The broker's session
logs are appended to the channel log at teardown the way a signal-ended command's are today.

The runtime never gets direct Internet access.

---

## 6. sbt — the broker starts the server, the client attaches

Target: sbt 1.13.0 and 2.0.8. Local-socket mode only; never TCP server mode.

### 6.1 Why the owner starts it

A server the client forks inherits three things from the client that a persistent server must not
have: the client's profile, whose `tmp/` grant names a directory removed with that command; the
client's environment, whose `java.io.tmpdir` and `XDG_RUNTIME_DIR` name the same directory; and
the client's process group, which cancel ends. So the broker starts the server itself, with the
command line both clients use (`NetworkClient.serverCommand`, v1.13.0 and v2.0.8):

```text
<cs-installed sbt> -Dsbt.script=<that path> <the request's -D… and -J… arguments> \
    --detach-stdio --server
```

The request that starts a server gives it its `-D` and `-J` arguments, as `serverCommand`
forwards them from the client that starts one, so the first command's `-Dexample=value` reaches
the server exactly as it does in a terminal; later requests' options are kept out, as sbt keeps
them out of a running server (section 4). The launcher's other value options — `-mem`,
`-java-home`, `-sbt-version` and the rest of `launcherValueFlags` — are not forwarded: the
wrapper sets the JDK and the script, and the document says a request carries only `-D` and `-J`
to a server it starts. The server runs as a registered spawn in the broker's session
(`records/server-sbt-<hash>`), under `sandbox-exec` with the
**server profile**, working directory the build directory, stdin `/dev/null`, stdout `/dev/null`,
stderr to a file under the broker's session (the file the channel log gets at teardown), and the
closed environment with the broker's session `tmp/` as `TMPDIR`, `XDG_RUNTIME_DIR`,
`SBT_GLOBAL_SERVER_DIR` and `java.io.tmpdir`. It then waits for the portfile with a deadline — the
bound `TODO.md` "a bound on a silent host command" asks for, now possible because the broker, not
sbt's client, does the waiting — and fails the command with the server's stderr if the deadline
passes.

The foreground client then runs `sbt --jvm-client -batch …` as today. With a live portfile the
client connects and forks nothing (`connectOrStartServerAndConnect`).

### 6.2 Profiles and environment

- **Server profile:** today's sbt profile with the broker's session `tmp/` as the session
  directory: read-write-exec there, UNIX-domain sockets bound and connected there.
- **Client profile:** today's sbt profile with the command's `tmp/` as its session directory, plus
  `(remote unix-socket (subpath <broker tmp>))` for the boot socket and the server socket
  (`BootServerSocket.java`: `<XDG_RUNTIME_DIR>/.sbt/sbt-socket<hash>/sbt-load.sock`;
  `<SBT_GLOBAL_SERVER_DIR>/<hash>/sock`). Whether the connect also needs a read grant on the
  socket's ancestors is measured, not guessed. The grant has to be exact because a client whose
  connect is denied does not fail: it deletes the portfile and forks a server under its own
  profile (`NetworkClient.connectOrStartServerAndConnect`, both versions; probe S6). That server
  dies at its boot-socket bind with exit 2, which the client takes for a server still booting
  and waits for without a deadline (`waitForServer`, `existsValidProcess`), and the runtime's
  portfile is gone: the 1.13.0 server and its socket file stay, the 2.0.8 server exits with
  status 1 some 18 s later, with nothing logged after its detach and no actor found in its
  sources; the next command finds no server and starts one (6.3).
- **Client environment:** `XDG_RUNTIME_DIR` and `SBT_GLOBAL_SERVER_DIR` are the broker's `tmp/`;
  `TMPDIR` and `java.io.tmpdir` stay the command's own.
- `SessionTmpMaxLength` applies to the broker's `tmp/`, which is the socket budget now.

### 6.3 Cancel, idle exit, and what the build's processes belong to

- The build runs in the server, so a test JVM or a `run` process is the server's child, in the
  server's group. Cancelling a command ends the client's group; the server sees the channel close
  and `CommandExchange.removeChannel` (both versions) drops that channel's queued execs and
  cancels its running exec with `force = false`. The broker does no more — it follows stock sbt
  (revised in step 3; the repository's earlier stronger guarantee is dropped, the user's
  decision): the warm server survives, and the next command reuses it. Cancellation is
  cooperative, so a test that ignores interruption or a thread a task left keeps running in the
  server, exactly as it does for a terminal user, and the next command's exec queues behind it
  if it never yields — the tool's own behavior, not the broker's to override. Retiring the whole
  server on cancel would be a deviation from stock sbt with no confinement basis, since the
  lingering work is confined and writes only the project and its own caches (`SECURITY.md`,
  "Run on host"; `doc/run-on-host.md`, "Where the broker deviates from the stock tool"). The
  measurement (probe S4): after the client's TERM the server answers the next client in both
  versions, and a forked `run` JVM is ended by the cancel in 2.0.8 and outlives it in 1.13.0 —
  the tool's own difference, left as the tool leaves it.
- The server exits on its own after `serverIdleTimeout`, 7 days in both versions
  (`Defaults.scala`), and the broker adds no bound of its own (section 11). The broker treats
  "recorded leader alive, server gone" as "no server": it ends the old group and record
  (section 2), then starts one; the same handling covers a server the agent ended with
  `sandbox-run-on-host sbt shutdown`.
- sbt 2 registers each server in `<globalLocalCache>/proc/<pid>.json` and, when a client
  disconnects, asks the other registered servers to drop if idle for `secondaryIdleTimeout`
  (600 s) with no client (`CommandExchange.notifyOtherServers`, `SysProp.globalLocalCache`). With
  `-Dsbt.global.base` set, that directory is `<sbt global base>/cache`, inside the project's
  run-on-host cache, so only this project's confined servers see each other and a user's server
  never reaches ours; the confined server writes its entry there and nowhere else (probe S5).

### 6.4 The portfile and foreign servers

- The one-server-per-build-directory rule stays, and this broker signals only its own servers
  (revised in step 3; see the revision note). Before starting a server the broker checks who
  holds the build directory's portfile, under the build lock (section 3):
  - **This launch's own server.** A live socket that is exactly the socket sbt derives for the
    directory under this session's `tmp/` (`expectedServerSocket`), with neither the socket nor
    its parent a symlink, is this broker's own server: reused, not restarted. The exact,
    unredirected path — not merely a socket under `tmp/` — is what keeps a portfile copied from,
    or a socket directory linked to, another warm build directory from sending this client to the
    wrong server; the server profile grants the build write across `tmp/`, so the spelling alone
    is not enough. The same derived socket live but proved by no record is a server this launch
    left unaccounted, and is refused, to be ended by hand.
  - **The user's own server**, from a terminal outside any launch: shut down by protocol at the
    socket the broker derives (`shutdownForeignServer`), never at the one the portfile names —
    workspace content must not choose where an unconfined exchange goes — and refused when a
    command could have planted that derived path. The derivation is checked, not just computed.
  - **Another launch's server**: refused, never signalled. The broker reads whether another
    broker session — live under the root, just-crashed and not yet collected, or in `condemned/`
    mid-teardown — holds a `server-sbt-<hash>` record for the directory (`serverOwner`,
    `RunOnHostSession`), and if so refuses the command. It does not reach into that session's
    records to end the group: ending another launch's server across launches is the deferred
    takeover of `doc/TODO.md`. A just-crashed owner's record blocks admission this time and the
    next start's scavenge collects it, so its server is never left running beside a fresh one; a
    missing portfile never authorizes a start while such an owner exists.
- Keep the project-scoped caches, the `target/` symlink sweep before each command, and
  `--jvm-client`.

### 6.5 Acceptance

```text
sandbox-run-on-host sbt compile
  record the server's pid and start time from records/server-sbt-<hash>

sandbox-run-on-host sbt test
  same pid and start time; no second server; the client forked nothing

cancel the second command mid-test, the test unforked and ignoring interruption
  the client's group is gone; the warm server survives (stock sbt); the next command reuses it,
  the same server, and the lingering test runs on as it would in a terminal

edit sbt.version, then sandbox-run-on-host sbt compile
  the same server answers, on the old version, as it would in a terminal;
  sandbox-run-on-host sbt shutdown, then compile: a server of the new version

end the launch (container stopped)
  server, proxy and broker session gone, nothing left in ps

kill -9 the broker
  the next start collects the session: groups ended by proof, server by portfile attribution

start a new launch
  its broker publishes a new session; a planted active.json naming the old socket is never
  connected to, and a planted record naming an unrelated pid is skipped
```

---

## 7. Mill 1.1.9 — the daemon in its own group, clients confined to its port

Remove `--no-daemon`. Do **not** give Mill Gradle's profile.

### 7.1 Facts the design rests on (Mill 1.1.9 sources)

- The daemon binds `new ServerSocket(0, 0, InetAddress.getByName(null))` and writes the port to
  `out/mill-daemon/socketPort` (`libs/daemon/server/src/mill/server/Server.scala`). There is no
  fixed-port option.
- The launcher starts the daemon as a subprocess with `destroyOnExit = false`, so it survives the
  client that started it (`MillProcessLauncher.launchMillDaemon`), then reads `socketPort` and
  connects with `new Socket(loopback, port)`, retrying a failed connect for `serverInitWaitMillis`
  (10 s) before failing (`ServerLauncher.launchOrConnectToServer`, `retryWithTimeout`).
- If a client disconnects while its command runs, the daemon closes every connection and shuts
  itself down (`Server.scala`, "client interrupted while server was executing command").
- The daemon exits after `mill.server_timeout` without a connected client — 30 minutes by default,
  set through `MILL_SERVER_TIMEOUT_MILLIS` in the launcher's environment
  (`MillDaemonMain0.scala`, `MillProcessLauncher.millServerTimeout`), counted from the last
  client's disconnect: a daemon no client has connected to yet never expires
  (`Server.ConnectionTracker`, `inactiveTimestampOpt`), so a starter's daemon whose first command
  never came lives until the launch ends — and when
  `out/mill-daemon/processId` changes or disappears (`Server.watchProcessIdFile`), which the
  launcher itself uses to end a daemon whose `daemonLaunchFingerprint` mismatches.
- The client sends its environment to the daemon with each command (`DaemonRpc.Initialize`), so
  the closed command environment reaches the build per command; the daemon JVM's own options,
  the proxy settings included, are fixed at its start.
- The bootstrap fetches a GraalVM native image as the launcher for a bare version, and the JVM
  launcher — `mill-dist-<version>.exe`, an executable assembly run by the PATH's `java` — for a
  `-jvm` one (the `case "$MILL_VERSION"` block of the script). The image takes no
  `JAVA_TOOL_OPTIONS`, so the environment's `preferIPv4Stack` never reaches it, and
  `-Djava.net.preferIPv4Stack=true` on its command line changes nothing: its connect is the
  dual-stack one the "localhost" class refuses (`doc/run-on-host.md` "Network"), and a client
  under the exact-port rule fails. The JVM launcher takes the environment's options and connects;
  its daemon fingerprint equals the image's, since both compute it from the same inputs (probe
  M2, both measured).
- `ServerLauncher.launchOrConnectToServer` has an `openSocket = false` mode. Its `initServer` is
  `MillProcessLauncher.launchMillDaemon` with `CoursierClient.resolveMillDaemon`'s classpath, and
  the `DaemonConfig` it writes as the daemon's fingerprint is computed by `MillLauncherMain.main0`
  from `loadMillConfig`, `computeJvmOpts` and `javaHome`. A helper on that route is a class
  compiled against `mill-dist` 1.1.9's `mill.launcher` internals — not a published API — run as
  `java -cp <mill-dist jar>:<helper>` under the daemon profile, over the JVM launcher the
  prerequisites validate, and must
  reproduce `main0`'s preamble exactly: a fingerprint that differs from what the stock client
  computes is the mismatch that makes the next client end the daemon (7.2, step 0). The stock
  executable starts the daemon without connecting to it, with the fingerprint the clients will
  compare against, as the next section shows, and is the route taken (section 11).

### 7.2 Starting the daemon with the stock executable

0. The broker first ends a foreign daemon if one is alive: a process whose command names
   `mill.daemon.MillDaemonMain` and whose working directory is under
   `<build dir>/out/mill-daemon` (the daemon's cwd is `out/mill-daemon/<id>/sandbox`) and which
   is not in the broker's own group, ended as 7.3 says. The broker does this itself, by proof,
   rather than leaving it to the starter: Mill's launcher ends a daemon only when its
   `DaemonConfig` differs, by removing its `processId` before it probes the lock
   (`ServerLauncher.launchOrConnectToServer`), and would attach to one whose fingerprint matches
   — a daemon the broker did not start, running the build outside its ownership. A daemon that
   appears between this step and the starter's own lock is ended by the starter on a mismatch,
   or found by the broker after the starter, when its own group holds no daemon: then the broker
   ends it as here and runs the starter once more.
1. The broker runs the project's own `./mill` — with `MILL_VERSION` set to the launcher version
   in the closed environment, so the bootstrap runs the JVM launcher the prerequisites validate
   (7.1) — with an
   argument that does nothing (`version`), as a registered spawn in its session
   (`records/daemon-mill-<hash>`), under the **daemon profile** (7.4). The launcher starts the
   daemon; the daemon binds its port; the launcher's own connect is denied by that profile, so
   the launcher exits nonzero after its 10-second retry and the daemon stays, in the spawn's
   group.
2. The broker identifies the daemon as the member of that group whose command line is
   `mill.daemon.MillDaemonMain`, reads `out/mill-daemon/socketPort` as a candidate — an integer
   in port range, and nothing more — and grants it only after
   `lsof -a -p <pid> -iTCP -sTCP:LISTEN` shows that pid listening on that loopback port. The file
   supplies no authority: a candidate the owned daemon does not listen on is a refusal, and so is
   an absent or malformed file, since the client reads the same file and would fail anyway.
3. Each command's client runs `./mill <args>`, the same launcher, under the **client profile**
   with exactly that port.
   The launcher reads `socketPort` — agent-writable — and connects; a planted port is denied by the
   profile and fails the command, and grants nothing.

The starter fails on its own; ending it early is deferred (section 11).

### 7.3 `out/mill-daemon` is Mill's, not the broker's

> Superseded in part by the step-3 and step-4 revisions (the revision notes above): a broker
> never signals another launch's server or daemon, so the "ended by its record" and "two launches
> end each other's in turn" claims below are "another launch's is refused", and the idle
> observation is the daemon's own TCP table.


The broker neither clears `out/mill-daemon` nor takes authority from it: `socketPort` is a
candidate proved against the owned process (7.2, step 2), and nothing else in it is read. Mill's
own `daemonLock` probe decides whether a daemon runs, and its `cache/mill-daemon-classpath` memo
validates the paths it names before use. Ownership is the broker's records alone. A foreign
daemon (7.2, step 0) is ended before the broker starts its own, as a foreign sbt server is
(6.4): TERM then KILL to the pid the broker found in the process table and proved by start time
— never `./mill shutdown` through a profile, which would connect to an unconfined process, and
never a deletion of its `processId` file, which would write the user's file — and a line in the
command's transcript names what was ended. Ended only when idle, under the build lock (section
3), which keeps every other broker's client away while this one takes over: the user's own sbt
server is shut down by protocol, which runs after the exec the server is on, so a build in
flight is never killed there; another launch's sbt server is ended by its record (6.4), idle by
the build lock. A client from the user's terminal takes no lock, so for it idleness is
observed, not enforced: a daemon with an established connection on its port
(`lsof -a -p <pid> -iTCP -sTCP:ESTABLISHED`), or a confined sbt server with a live client on its
socket, is running a command, and the broker waits, bounded, until it has none, then proves
the pid, start time and port once more immediately before ending it. The sbt server's live
clients: XNU's `unp_connect` copies the listener's path onto each accepted socket and Apple's
`lsof` names a socket by that path, and by `->0x<peer pcb>` only when it has none, so a client
is a socket of this user, in `lsof -U`, named `->` the pcb of one of the server's path-named
rows. Counting the server's own rows would not do: an accepted socket outlives its client in
the server's table, and the server holds a `->` socket of its own from start to end. Probe S4
finds exactly one peer on a busy server, none after the client is gone, and one beside an
unrelated connection the server itself opened, in both versions. "No peer" is idle only when
the scan is known complete: Apple's lsof skips a process whose `proc_pidinfo` fails with
`EPERM` or `ESRCH` without a word; reports a process whose descriptors it cannot enumerate as
an entry whose fd is `err` (`dproc.c`); and reports one descriptor it cannot read under its
number as `<kind>: <reason>`, the kind from the kernel's descriptor listing, so
`socket: Operation not permitted` may hide a client where `vnode: FD unavailable`, a file
closed between listing and reading, cannot (`dproc.c`, `dfile.c` `err2nm`, `dsock.c`) —
entries a `-a -p <pid> -U` table drops and a `-u <user>` listing keeps, since every file of a
selected process inherits the selection (`proc.c`). So the observation is one full listing of
this user's processes, taken as complete only when lsof exits 0 with nothing on stderr, every
live process of this user — by effective uid, lsof's own notion, since a setuid `login` keeps
the real one; not a zombie, which holds no descriptor; in `ps` both before and after the
scan — has a process line in it, and no entry is an error that can hide a socket: an `err`
entry, a `socket:` one, or an `unknown file type`; the server's rows, by lsof's type field,
and their peers are read from that one listing. Anything else is unknown, not idle, and is
retried within the wait. Probe L5 measures that a scan on the host meets that, 737 processes,
and the S4 rows read their tables from it; Spotlight's indexer closes files during a scan, and
its `vnode: FD unavailable` entries appear in four of one run's nine scans, which is what the
kind rule is for. A foreign build that outlasts the
wait, and a scan that stays unknown, are a refusal naming it, and a retry.
Between that last observation and the TERM a terminal `./mill`, or a terminal sbt 2 client to
another launch's confined server, can still connect, and its build then dies with the process:
a residual window, stated in the document as such, and closed only by refusing every foreign
server and daemon, which section 11 decided against.
`--auto-shutdown-foreign-sbt-on-host` is deleted: the shutdown is the default for both
programs, and a launch naming the option is refused with a line saying so. What that means for
the user is documented in the same words for both programs: a server or daemon you have running
for this project on the host is ended, once idle, when the agent runs the same program, and two
launches on one project end each other's warm server or daemon in turn, each waiting for the
other's build to finish first.
The reverse holds too, and is documented beside it: while the launch's server or daemon lives,
your own sbt 2, or a `./mill` whose settings match, attaches to it and runs your build under the
profile and the agent's proxy — one command long today, the whole launch once the server is warm.

Regression tests: plant `processId` and `socketPort` naming an unrelated host process and port —
the broker adopts nothing, signals nothing, and the client profile it renders names no such port;
start a daemon unconfined, once with a `JAVA_OPTS` the closed environment lacks and once with
matching settings — each is ended by proof before the broker's own starts, with a transcript line,
and the broker's daemon is the one the command used.

### 7.4 The two profiles, and the widening they carry

```text
daemon profile   today's mill profile
                 + (allow network-bind network-inbound (local ip "localhost:*"))
                 outbound: the proxy only

client profile   today's mill profile
                 + (allow network-outbound (remote ip "localhost:<P>"))
```

Exact SBPL is measured (`src/probe/run-on-host-broker-session.sh`, L1–L4 and G1–G10), never
taken from documentation. The client rule confines outbound to one port, and `localhost:0` binds
cannot be confined to one, so the daemon's grant covers every port — at every address of this
host, since the "localhost" class admits a bind to the wildcard or to the LAN address (G1, G9,
G10). That grant is inherited by everything the daemon forks: a test suite under Mill can bind a
listener, which under sbt or Maven gets `EPERM`, and a LAN peer can reach it while it runs under
the profile. `SECURITY.md` states this as Mill's cost, in the same terms Gradle's is stated in
Phase 2; "no listener" stays true for sbt and Maven, and the agent instructions say which
programs it holds for.

### 7.5 Cancel, self-exit, restart

- Cancelling a Mill command ends the client's group; the daemon then shuts itself down (7.1). The
  next Mill command starts a new daemon. The acceptance says so; "the daemon survives a cancel" is
  not a property Mill 1.1.9 offers. The cancel rule of 6.3 applies unchanged: the broker retires
  the daemon's group before the next command whether or not the daemon ended itself, so a `run`
  JVM its shutdown did not reach ends with the group.
- After 30 idle minutes, or when the agent's build changes `processId`, the daemon is gone with
  its recorded leader still alive: the broker treats that as "no daemon", ends the old group and
  record (section 2), and starts one on the next command. `MILL_SERVER_TIMEOUT_MILLIS` is left at
  Mill's default (section 11).
- At the broker's end: the recorded group ended (section 2); Mill's own lock probe ignores the
  files a daemon ended that way leaves, and the next daemon overwrites them.

Keep the Mill prerequisites: the project-local bootstrap, `mill-jvm-version: system`, no
automatic provisioning, the agent's `MILL_VERSION` overrides dropped. The pre-provisioned
executable becomes the JVM launcher. One function derives the **launcher version** from the pin:
a bare `<v>` and a `<v>-jvm` pin both give `<v>-jvm`; a `<v>-native` pin is a refusal naming
7.1's reason, since the user asked for the one launcher that cannot connect. The prerequisites
look up `<download folder>/<v>`, as `millExecutableName` derives it for that launcher version;
the wrapper sets `MILL_VERSION` to it for the starter and every client (7.2); the documented
provisioning command is `MILL_VERSION=<v>-jvm ./mill version` on the host. The pin, as
written, is in the reuse key.

### 7.6 Acceptance

```text
sandbox-run-on-host mill __.compile
  record the daemon's pid, start time and port from the broker's records and lsof

sandbox-run-on-host mill __.test
  same pid and start time; the rendered client profile names that port and no other

cancel a command mid-build
  the daemon is gone (Mill's behavior); the next command starts one

plant socketPort naming another port
  the client fails with EPERM; nothing else is granted or signalled

end the launch
  daemon, proxy and broker session gone

second launch
  a new daemon in the new broker's group; the old daemon's files nominate nothing
```

Also verify that the daemon's build sees the closed command environment of each command, not the
starter's or the host's.

### 7.7 If the starter or the exact-port approach fails

If the daemon does not survive the denied starter — the gate row of section 11 — the helper over
`ServerLauncher(openSocket = false)` replaces the starter for that Mill version, under the same
daemon profile and with the same port verification, and this launcher's build takes the
compile-time dependency section 11 prices.

If Mill needs outbound loopback beyond the proxy and its own port — a probe row, not a guess — stop
the Mill work and record the blocker in `TODO.md`. Whether to keep `--no-daemon` or widen Mill's
profile is a separate decision, never a side effect of Gradle's.

---

## 8. Profile inputs: one typed network variant

`SeatbeltProfile.render` takes no extra rules from callers by design (its header). The network
authority therefore becomes a typed input of `ProfileInputs`, rendered inside `render`:

```scala
enum Network:
  case ProxyOnly                    // sbt server, Maven
  case SbtClient(serverTmp: Path)   // + remote unix-socket under the broker's tmp
  case MillDaemon                   // + loopback listeners
  case MillClient(port: Int)        // + outbound to one port
```

Phase 2 adds `Gradle`. A reviewer sees from the dispatch which program gets which
authority; no boolean, and no generic "localhost any" case reused casually.

---

## 9. Probes and tests

- `RunOnHost` (the gate's test entry) stays the one-command primitive it is: it creates a
  runtime, runs the command, and ends the runtime, through the same functions the broker calls
  across commands — one lifecycle, two callers, never a second owner that could drift. Every
  persistence row runs through the real broker, as the gate's channel rows already do: the
  broker served with the gate's stub `podman`, the real shim sending several commands to it, a
  shim killed mid-command for a cancel, the liveness file flipped for the launch's end, and the
  broker killed for the scavenge.
- `src/probe/run-on-host-broker-session.sh` measures, before any of this is implemented, what
  the sections above assume: the SBPL bind, accept and exact-port rules; the server started by
  the owner's
  command line and attached to by a client that forks nothing; the client's unix-socket rule; the
  client-disconnect cancel and its forked JVM; the sbt 2 `proc` registry; the Mill starter, the
  port from `lsof`, the exact-port and neighbor-port clients, the per-command environment, the
  daemon's end on a cancel and on its timeout; and a foreign daemon ended by the starter's
  fingerprint mismatch, the hazard 7.2 step 0 exists for. For Gradle and the reach of
  `localhost` (G1–G10): a UDP socket and a TCP listener bound to the wildcard address, as its
  file-lock socket is, or to the LAN address, under the Gradle candidate and under the mill
  daemon's rule, heard at the loopback and at the LAN address, inbound and outbound — the
  measurement "Security model" and section 12 rest on.
- Gate rows, extending the existing gate and its `--no-daemon`/`sbtn` INFO rows rather than a new
  framework: the acceptance blocks of 6.5 and 7.6; the proxy reused by the server across
  commands; the per-command denied-host report under the shared log; a `-Dprobe=1` on the
  request that starts the server visible to the build, and one on the next request not; Mill
  version or option-file changes retiring a runtime; a rule-file edit leaving the running
  runtime as it is, and the runtime created after the program's `shutdown` under the new rule;
  a request from a nested build directory leaving the root's runtime warm, and each reused;
  `.git`/`.ko-agent-sandbox` denials
  holding for the long-lived server and daemon; a descendant left sleeping by a build ending with
  the launch, and one left in a group whose server or daemon was cancelled, idle-exited or shut
  down ending before the replacement starts; a cancelled unforked `sbt test` that ignores
  interruption leaving the warm server alive, reused by the next command with its work still
  running (stock sbt, 6.3); a cancelled `mill app.run` (7.5, step 4); a second request queued
  behind a running one seeing the runtime the first left (section 3); a second launch on the same
  project refused a build directory the first still owns, and admitted once the first launch
  ends (6.4); no daemon ever in
  a client's group; a foreign daemon, of matching and of mismatched configuration, ended by
  proof with a transcript line before the broker's own starts, a foreign daemon mid-command left
  until its client disconnects and ended then, and one that outlasts the wait refused; a second
  broker taking over while the first's `app.run` runs: the run completes, the first's next
  request waits on the build lock and finds its daemon gone, and no client of either connects to
  a daemon being ended (section 3); another launch's sbt server never signalled — its
  `server-sbt-<hash>` record refuses the command, whether that session is live, just-crashed and
  uncollected, or in `condemned/` mid-teardown, and the record is found across the teardown
  rename (with the injected `betweenScan`); a portfile naming another build directory's socket,
  or a socket directory redirected there by a link, not reused as this directory's server; and a
  user's sbt 2 client attaching to the launch's server while it lives, recorded as the documented
  consequence it is;
  sbt and Maven still unable to
  reach an unrelated loopback port; the Mill client unable to reach a neighboring port; and the
  listener row for the daemon profile, reported as the widening it is.
- `RunOnHostSessionTest` covers the broker-session kind with the existing injected `Processes`:
  scavenging a broker session with server and daemon records, and a command session beside a live
  broker session.

## 10. Where the broker deviates from the stock tool

Everything else in Phase 1 does what the stock tool does, or enforces confinement the stock tool
never had. These six do neither, and `doc/run-on-host.md` lists them under the same heading so
that none is mistaken for the tool's own behavior later:

- **Persistent processes end with the launch** (section 2). Stock sbt and Mill leave their
  server or daemon running when the terminal that started it closes. The broker ends its server
  and daemon when the container is gone, and the next start scavenges what a killed broker left.
  This is the feature's requirement, not a cost: a confined process must have an owner, and a
  later launch never adopts one whose owner is gone.
- **A cancel follows stock sbt (dropped as a deviation in step 3).** The broker once ended the
  whole server group on a cancel, to keep the pre-broker guarantee that nothing a cancelled
  command started survives. That is dropped: the disconnect cancels the running exec
  (`CommandExchange.removeChannel`, `force = false`) and the warm server survives, as it does for
  a terminal user, so this is no longer a deviation. Retiring the server would have deviated from
  stock sbt with no confinement basis. (Mill's daemon, step 4: stock Mill ends its daemon on a
  mid-command disconnect; the broker leaves that to Mill too.)
- **The wait for the portfile has a deadline** (6.1). sbt's thin client waits for a starting
  server without one. The broker fails the command after its deadline, with the server's stderr:
  the bound `doc/TODO.md` "a bound on a silent host command" asks for.
- **One runtime per build directory and program, all kept warm** (section 4). Stock sbt keeps a
  server per build directory and they coexist; the broker does the same, keyed by directory and
  program, so alternating between a root and a nested build keeps both warm. A runtime ends with
  the launch, when its own proxy is gone, or — following stock sbt on a cancel — never on a
  directory switch. This is the design as built (the step-3 revision above), not a deferral.
- **Mill runs through its JVM launcher** (7.1, 7.2). The stock bootstrap picks the native image
  for a bare pinned version; the wrapper sets `MILL_VERSION` to the launcher version, `<v>-jvm`,
  so that the launcher takes the environment's `preferIPv4Stack` and connects under the
  exact-port rule, which the image cannot. The user provisions that launcher, and a `-native`
  pin is refused by the prerequisites with a line saying why.
- **A foreign server or daemon is ended, never attached to** (6.4, 7.2 step 0, 7.3). Stock sbt
  and Mill attach to whatever server or daemon holds the rendezvous; Mill ends one only when its
  fingerprint differs. The broker ends it first, always, and only once idle, for the reason the
  sbt foreign-server rule already gives: a client attached to a server the broker did not start
  would run the build with that server's environment and confinement, or none. The user's own
  warm server for that
  project is the one ended, and the document says so in those words.

## 11. Decisions taken

Decided 2026-09-10, with the reasons each rests on:

- **The sbt server has no idle bound of the broker's.** It lives until the launch ends,
  `sandbox-run-on-host sbt shutdown`, or sbt's own `serverIdleTimeout`, 7 days in `Defaults.scala`
  (https://github.com/sbt/sbt/blob/v2.0.8/main/src/main/scala/sbt/Defaults.scala): a warm server
  is what the user keeps on purpose, so its heap is the price chosen. The cost stated instead:
  a second launch is refused a build directory the first launch still owns (6.4, step-3 revision),
  until the first launch ends.

  Deferred: `doc/TODO.md`, "an idle bound for the sbt server".
- **Mill's timeout is Mill's default**, 30 minutes, with `MILL_SERVER_TIMEOUT_MILLIS` absent
  from the closed environment.
- **The Mill daemon is started by the stock executable (7.2)**, and a helper over
  `ServerLauncher(openSocket = false)` is the fallback. The starter writes the daemon's
  fingerprint with the same code the clients compare it with; the helper would reproduce that
  logic by hand against `mill.launcher` internals pinned to 1.1.9. The starter's costs are its
  connect retry — up to
  ten seconds per daemon start (7.2) — and its reliance on the daemon outliving it, which Mill
  states as intent (`destroyOnExit = false`).
  That reliance is a gate row per Mill version, a hard one: a version whose daemon does not
  survive the denied starter fails the row, and the helper replaces the starter for it (7.7).

  Deferred: `doc/TODO.md`, "ending the mill starter once the daemon listens".
- **The `--auto-shutdown-foreign-sbt-on-host` option is deleted, and the user's own server is
  shut down by default; another launch's is refused, not ended** (6.4, step-3 revision). The
  README already told every macOS launch to pass the option, so shutting the *user's own*
  terminal server down is what the recommended launch did, and it is now the default: a server
  the user runs from a terminal, holding the build directory's portfile, is shut down by protocol
  at the socket the broker derives. Another *launch's* server is never signalled — the command is
  refused while that launch owns the directory (cross-launch takeover is deferred, `doc/TODO.md`).
  The costs, documented rather than gated: the user's own terminal server for a directory is shut
  down when the agent runs sbt there; a second launch is refused a directory the first still owns;
  and the user's own client attaching to the launch's confined server while it lives.

  Mill (step 4) reaches the same rule: another launch's daemon is refused, not ended; the
  fingerprint/`processId` machinery of the earlier design is superseded there too, and 7.2–7.3
  are revised when Mill lands.

  Deferred: `doc/TODO.md`, "two launches sharing one server or daemon".

---

# The proxy's own profile

Independent of Gradle, ahead of it: the one launcher process that parses bytes the confined
command sends — every CONNECT line and host name — runs as the user. It gets a profile of its own.

**What must hold.** The host proxy runs under a Seatbelt profile that grants its executable, the
runtime authority and the network, and nothing of the user's files; the same profile for every
proxy the launcher starts on the host — the broker's per build directory and program, the
command's own under Maven, the gate's — since one `RunOnHostSandbox.startProxy` starts them all.

**The profile** (`SeatbeltProfile.renderProxy`, sharing `render`'s parts: the root component and
ancestor literals, `Devices`, the measured `RuntimeAuthority`):

```text
(deny default)
process-exec* file-read*   the launcher's own executable — the native image, or the JDK of the
                           jar form (RunOnHostSandbox.proxyInputs)
file-read*                 each class-path entry of the jar form
file-read*                 the runtime authority, reads alone: the proxy executes nothing but
                           itself
network-outbound           every remote, `(remote ip "*:*")`: host filtering is the proxy's own
                           job, and SBPL cannot filter by name
network-outbound           the resolver's socket, /private/var/run/mDNSResponder:
                           `InetAddress.getAllByName` is how it resolves — and metadata on
                           the root link /var its client spells the path through (measured)
network-bind, -inbound     `(local ip "localhost:*")`: the loopback address is the proxy's own
                           EGRESS_BIND, since no rule names loopback alone
```

No write, no project, no cache: nothing under the user's home is granted but what the jar form
loads; of the operation families `sysctl-read` and `mach-lookup`, measured (`iterate.sh ops` for
the JDK, then the proxy itself, which dies of a segmentation fault in a system library without
`mach-lookup`), and no `process-fork`. The proxy runs from `/`: the JVM asks for its working
directory at start, and the root is the one directory the profile grants (measured: the gate's
first run failed there). The log is the proxy's stderr, opened by the starter and inherited, which
no rule governs — the sbt server's stderr already lands in a directory its profile does not grant
(`RunOnHostSandbox.serverStderr`) — so what `sandbox-exec` or the JVM says before the proxy prints
anything lands where the ready line is awaited. The environment is already the closed one
`startProxy` builds. The upstream proxy variable, when forwarded, changes nothing: outbound is
unrestricted.

**Tests.** `SeatbeltProfileTest`: the grants, the network lines, a relative path refused.
The gate: its wrapper rows run every fetch through a proxy under this profile, so they prove the
confined one works, the resolver rule included; the rows under the emitted proxy profile prove the
JVM starts, a read of the user's home denied and a write denied — the probe is the granted java
alone, since the profile execs nothing else. A read the proxy needs and the command never did
shows there, and `src/probe/run-on-host-profile-iterate.sh` finds it as for any command. The gate
runs the jar form; the native image's first launch is what measures it, a denial landing in the
proxy's log.

**Documents.** `doc/run-on-host.md` "The command's egress proxy" states the profile, `SECURITY.md`
"Run on host" its one sentence; `doc/TODO.md`'s entry is deleted. The per-program table in
`SECURITY.md` is untouched: the proxy is not a build process.

---

# Phase 2 — Gradle 7/8/9

Start after the broker session and runtime ownership exist. Gradle does **not** depend on Mill's
exact-port technique; it shares the session, teardown, proxy and reuse-key infrastructure.

## 12. Explicit Gradle security exception

Gradle host execution uses stock Gradle under a Gradle-specific profile: Mill's daemon profile
plus outbound to any port of this host.

Do not attempt: daemon-port discovery followed by exact-port client confinement; TCP relay tricks;
patching Gradle; Java agents or `connect()` instrumentation; ephemeral-port range manipulation;
custom worker launch interception. None solves the stock-Gradle requirement, because Gradle also
creates dynamically allocated worker TCP endpoints and UDP file-lock endpoints.

The Gradle profile grants what the probes proved Gradle needs, and nothing else changes:

```text
Gradle host process/build code
  listeners, any port, any address of this host, TCP and UDP: YES (Mill's grant; G1, G9, G10)
  connections to any port of this host:                       YES (G7, G8)
  connections to other hosts, LAN or Internet:                NO (G12, TCP and UDP)
  Internet through egress proxy:      according to the normal Gradle egress rule
  arbitrary host filesystem:          NO
  .git mutation:                      NO
  survive owning launch:              NO
```

SBPL names no loopback alone: its `localhost` class is this host's addresses, the wildcard
included (`doc/run-on-host.md` "Network"; measured G1–G10 before this was written into code).
So the exception is not stated as "loopback": `SECURITY.md`'s per-program table states the two
things a Gradle build can do that an sbt build cannot — serve a LAN peer while it runs, as a Mill
build already can, and talk to every service listening on this host. Its row is there, marked
planned until the program lands.

In code, `Network.Gradle` joins the enum of section 8: SBPL names no loopback alone, so the
case is not named after one.

## 13. Warn when Gradle's profile is actually used

`--run-on-host=gradle` is already explicit opt-in; no second acknowledgement flag.

The broker prints a warning once per launch, to the user-visible diagnostic stream, immediately
before the first Gradle command runs under the profile:

```text
WARNING: Gradle host execution requires broader localhost networking than
other host build tools. Gradle build code can use dynamically allocated
loopback TCP and UDP ports and may communicate with other services listening
on the host loopback interface. Non-loopback/direct Internet access remains
restricted by the normal Seatbelt and egress-proxy policy.
```

Once per launch, not per command; nothing for sbt or Maven; Mill's own listener cost is worded on
its own (7.4), never with Gradle's wording. README, help and `SECURITY.md` carry the same substance.
A test proves the warning is printed exactly once when Gradle is first used.

## 14. Program surface and acceptance matrix

Add `gradle` to `--run-on-host`'s program enumeration.

| Gradle line | Tested release | Required Gradle runtime JDK |
| --- | --- | --- |
| 7.x | 7.6.6 | JDK 17 |
| 8.x | 8.14.5 | JDK 21 |
| 9.x | 9.7.1 | JDK 25 |

This is a `ko-agent-sandbox` policy, not Gradle's compatibility matrix: a release that could run
on another JDK still runs on the designated one. **A missing designated JDK is fatal**: no
automatic download, no Coursier invocation that can install one, no fallback to another compatible
JDK, to the current host JDK, or to container execution. The refusal names the required feature
version.

## 15. Determine the Gradle version without executing project code

Require `gradlew` and `gradle/wrapper/gradle-wrapper.properties`; read the properties as data and
derive the exact version from `distributionUrl`. First pass: accept official distribution URLs
whose basename is `gradle-<version>-bin.zip` or `gradle-<version>-all.zip`; require major 7, 8 or
9; reject an unparseable version; reject unsupported versions with a typed refusal. Never run
`gradlew --version` to discover the version. Custom distributions are out of scope.

## 16. Require Gradle distribution pre-provisioning

The wrapper must not bootstrap-download an executable distribution on the host. The exact
distribution must already be in the trusted run-on-host Gradle cache, validated before execution;
the command runs that distribution's `bin/gradle` directly, or another form that cannot trigger the
wrapper download; missing is a prerequisite refusal, never a fetch through the agent's egress path.
`GRADLE_USER_HOME` is project-scoped under the run-on-host cache; `~/.gradle` is not granted.

## 17. Installed Coursier JDK inventory

Identify **already installed** Coursier-managed JDKs without any operation that can install one:

```scala
def requireInstalledJdk(feature: Int): Either[Refusal, JdkHome]
```

Derive the trusted Coursier JVM roots by the repository's provenance rules; enumerate candidates
statically; canonicalize; require them beneath the approved roots; read the JDK `release` file as
data for the feature version; verify `bin/java` exists; never execute a candidate to discover it.
Gradle 7.6.6 → 17, 8.14.5 → 21, 9.7.1 → 25. None: fatal refusal. Several of one feature with no
deterministic trusted selection rule: an ambiguity refusal, never filesystem order. Never
Homebrew, `/Library/Java/JavaVirtualMachines`, SDKMAN, asdf, IDE or PATH JDKs.

## 18. Gradle Java toolchains: approved inventory only

Supply, and verify the precedence of on all three releases:

```text
-Dorg.gradle.java.installations.auto-detect=false
-Dorg.gradle.java.installations.auto-download=false
-Dorg.gradle.java.installations.paths=<approved Coursier JDK homes>
```

Seatbelt grants read-only the designated runtime JDK and the explicitly approved Coursier
toolchain JDKs. A project requesting an unavailable toolchain fails; Gradle never downloads it. A
project `gradle.properties` must not re-enable either behavior.

## 19. Gradle daemon and runtime lifetime

The broker's session owns the Gradle runtime — daemon, worker daemons, compiler workers, test
executors — and stock Gradle manages its daemon and endpoints inside the profile; no daemon-port
bootstrap machinery. The reuse key adds the exact Gradle version, the designated JDK, the relevant
daemon JVM arguments, the approved toolchain inventory and `GRADLE_USER_HOME`. Gradle's own daemon
compatibility matching operates only inside the broker's `GRADLE_USER_HOME`; a user's daemon is
never attached to. At the broker's end: `gradle --stop` with the matching distribution, JDK and
home may be attempted; every recorded group is ended regardless; the next launch adopts nothing.
Killing only the main daemon is not assumed sufficient.

What Phase 1 settled for sbt and Mill, to be answered for Gradle from its sources before any
mechanism is written, so that the broker builds no guarantee the stock tool does not give:

- **A cancel does what the tool does.** sbt's server survives a client's disconnect and keeps
  the running exec cancelled cooperatively; Mill's daemon shuts itself down on a disconnect
  mid-command, and the next command starts one. Step 3 first built a server retirement on
  cancel, a guarantee stock sbt does not give, and removed it. Read what Gradle's daemon does
  when its client disconnects mid-build, in its `launcher/daemon` sources, and follow it; the
  broker retires nothing on a cancel by its own rule.
- **A process the tool restarts on its own is restarted before the command, not left to fail.**
  Mill's client ends a daemon whose fingerprint differs and starts one itself, which a confined
  client cannot; the broker compares the same inputs first. Gradle's daemon compatibility
  matching starts a new daemon in the same `GRADLE_USER_HOME` on a mismatch, inside the profile,
  so nothing of the kind is needed unless a probe shows the start failing.
- **A daemon of the user's own is the tool's rendezvous problem, not the broker's.** sbt's
  portfile and Mill's `out/mill-daemon` live in the project, so the user's own server or daemon
  holds the rendezvous the broker's needs: the user's sbt server is shut down through sbt's own
  protocol, after its exec, and the user's Mill daemon — for which no safe protocol path exists,
  since a confined client would connect wherever `socketPort` says — is ended by proof once idle
  (`MillDaemons.endForeign`). Gradle's rendezvous is its daemon registry under
  `GRADLE_USER_HOME`, and the broker's home is its own, so the user's daemons under `~/.gradle`
  are never met: no ending, no refusal, and no window to document. Verify that with a probe
  row rather than assume it, since a project `gradle.properties` or `GRADLE_OPTS` cannot move the
  home once the wrapper sets it.

## 20. Gradle environment

From the same closed environment mechanism as the other programs, plus `JAVA_HOME` and `PATH` for
the designated JDK, `GRADLE_USER_HOME`, and the toolchain properties above. Nothing else of the
host environment reaches Gradle beyond the existing forwarding policy.

## 21. Gradle egress

Loopback only is the exception. Externally: Maven Central and the repositories named in the
Gradle rule file only; `plugins.gradle.org` when the file names it; no direct external or LAN
sockets; no expansion from build files or failure messages; no wrapper or JDK bootstrap download.
A missing host uses the existing audited refusal and report. Tests show the loopback grant does
not reach a non-loopback address.

## 22. Typed Gradle refusals

New `RunOnHostPrereqs.Refusal` cases: missing wrapper files; invalid wrapper properties; custom or
untrusted distribution URL; unsupported Gradle version; distribution not pre-provisioned; missing
designated Coursier JDK; ambiguous designated JDK; invalid Gradle user home; requested toolchain
unavailable; profile cannot express the loopback exception safely. Example wording:

```text
Gradle 8.14.5 host execution requires a pre-provisioned
Coursier-managed JDK 21.

No trusted JDK 21 is installed.

ko-agent-sandbox will not download a JDK, use another compatible
Java version, or fall back to container execution.
```

## 23. Gradle security and profile tests

Fixtures: Gradle 7.6.6 + JDK 17, 8.14.5 + JDK 21, 9.7.1 + JDK 25. Per release:

- **Version/JDK:** exact version from wrapper metadata; designated JDK used; missing designated
  JDK fatal; another compatible JDK not used; no download when the distribution is missing;
  toolchain auto-download and auto-detection off; approved toolchain works; unapproved fails.
- **Persistence:** first command starts an owned daemon; second reuses it; a changed version, JDK
  or authority retires it; clean exit kills daemon, workers and test executors; abrupt death is
  scavenged; the next launch adopts nothing.
- **Network**, with real tasks — daemon/client, process-isolated workers, tests that fork
  executors, file-lock contention exercising `DefaultFileLockCommunicator` UDP:

  ```text
  dynamic loopback TCP needed by Gradle: works
  dynamic loopback UDP needed by Gradle: works
  unrelated localhost service: reachable under the Gradle profile
  direct LAN endpoint: denied
  direct Internet endpoint: denied
  approved Internet endpoint through the egress proxy: works
  ```

  The "unrelated localhost service" row is intentional: it proves and documents the exact
  expansion instead of pretending it does not exist.
- **Warning:** printed on the first Gradle command, not on later ones, again in a new launch,
  never for sbt, Mill or Maven.
- **Filesystem:** every existing property holds; a fixture that leaves a long-sleeping descendant
  proves the broker's teardown ends it.

---

# Documentation changes

Each claim changes in the same change that makes it true.

- `doc/run-on-host.md`: the startup-cost paragraph (a warm server and daemon now span commands;
  what still costs a start: the first command, a cancel, an idle exit, a Mill version or option
  change; a Mill daemon start also costs the starter's connect retry, up to ten seconds, until
  the deferred early end of section 11 lands; and that an sbt server keeps the `sbt.version`
  and options it started with until `sandbox-run-on-host <program> shutdown`, as in a
  terminal); "The command's egress proxy" states when a rule edit takes effect — never by
  restarting a running runtime, whose proxy holds the rule file it was created with, but at the
  next creation of that runtime, with section 4's list of what ends one, as the session's own
  rule file takes effect at the next launch — as the policy it is, beside the file it governs; a
  heading listing where the broker
  deviates from the stock tool, with section 10's six entries;
  "The command's lifetime and environment" gains the broker's session, its `tmp/` in the client's
  `XDG_RUNTIME_DIR` and `SBT_GLOBAL_SERVER_DIR`, and the records; "Network" gains the per-program
  table of section "Security model"; the Mill prerequisites name the JVM launcher and the host
  command that provisions it, with 7.1's reason; the Mill section replaces `--no-daemon` and the
  false "`out/mill-daemon/` cleared before each command" with 7.2–7.5, the foreign daemon ended
  as the foreign server is; the channel section's "one server per project" argument stays, with the
  broker as the owner and the consented shutdown now the default; Phase 2 adds the Gradle
  section, with 9.7.1 as the release measured and the provisioning command.
- `SECURITY.md` "Run on host": "One sbt server per project, owned by the current command" becomes
  one per build directory, owned by the launch's broker and kept warm; a cancel follows stock sbt
  (the exec is cancelled, the warm server survives); the user's own terminal server is shut down
  by protocol at the derived socket, while another launch's is refused, never signalled; the
  costs stated are the user's terminal server shut down when the agent runs sbt there, a second
  launch refused a directory the first still owns, and the user's own client attaching to the
  confined server while the launch lives; the egress statement gains that a running
  runtime's proxy admits the rule file it was created with, so a host removed from the file is
  revoked when that runtime is next created, as the session's is at the next launch;
  "no listener" is qualified for Mill with the concrete widening of 7.4, and the per-program
  table states each program's reach and what the user gives up; "Teardown
  follows descriptor lifetime" gains the broker's own end, stated as the requirement it is: no
  server or daemon
  survives the launch that owns it, and a later launch adopts none whose owner is gone; Phase 2
  adds Gradle's
  exception in concrete terms — never
  "Gradle is insecure" or "reduced security".
- The agent instructions (`AgentSandboxLauncher`, "Run on host"): drop "Each sbt invocation starts
  and ends its own server, so batch commands into one"; keep the quoting advice; qualify "the host
  grants no TCP listener" per program.
- `README.md` and the launcher's help and option parsing: `--auto-shutdown-foreign-sbt-on-host`
  is deleted, a launch naming it refused with a line saying the shutdown is now the default, and
  the README's launch advice drops it; the `--run-on-host` text says that a terminal sbt server
  you have running is shut down when the agent runs sbt in that directory, that a second launch is
  refused a build directory the first still owns, and that your own sbt 2 attaches to the launch's
  confined server while it lives; Phase 2 adds `gradle`, no provisioning sentence — the refusal
  names `./gradlew --version`, as mill's names its command — the cost being `SECURITY.md`'s
  table row.
- `doc/TODO.md`: "a bound on a silent host command" is resolved for sbt by the broker's portfile
  deadline (6.1) and is rewritten to what remains, the generic no-output bound; "Gradle under
  `--run-on-host`" is removed when Phase 2 lands; a Mill blocker is added only if 7.7 triggers.
- `doc/sbt-issues.md`: unchanged; the one-shot-mode request still stands.

---

# Implementation order

Small patches, each with an independently testable invariant, in dependency order:

## Phase 1

1. The broker's session kind in `RunOnHostSession` (a second published, locked session with
   records), the build lock held around each dispatched command, and the wrapper's runtime as
   the value it creates for one command — today's behavior throughout, the gate green unchanged.
2. The broker's proxy: started in the broker's session with the rules read then, its port and
   session directory passed to the wrapper as the runtime parameters, the spawn taking the build
   lock before that preparation and execing the wrapper on the broker's word, the reuse key over
   the build directory, the per-command denied-host offset. Servers still per command.
3. The sbt server started by the broker under the server profile, the client profile's socket
   reach (`Network.SbtClient`), the own-server case in `livePortfileServer`, cancel, the
   broker's teardown on container end, TERM and scavenge. Gate rows of 6.5.
4. Mill: the prerequisites' JVM launcher and the wrapper's `MILL_VERSION`, the daemon profile
   and its bind/accept probe rows, the starter run, port from `lsof`, `Network.MillDaemon` and
   `Network.MillClient`, the foreign-daemon shutdown, the planted-file regression test. Gate
   rows of 7.6. Persistent Mill is enabled only after the narrow profile passes; on failure, 7.7.
5. Phase 1 documentation.

## Phase 2

Revised by "Revision — Phase 2 scope":

6. The SBPL rows for Gradle, G1–G10, measured: `localhost` is this host's addresses, so
   `Network.Gradle` encodes Mill's daemon grant plus outbound to any port of this host,
   and lands with step 8's `Program.Gradle`.
7. The proxy's own profile ("The proxy's own profile"): `SeatbeltProfile.renderProxy`,
   `startProxy` under `sandbox-exec`, the tests and the document paragraph.
8. `Program.Gradle` and its prerequisites: the provisioned distribution under the broker's
   `GRADLE_USER_HOME` or a refusal naming the provisioning command, the JDK from JAVA_HOME, the
   three toolchain properties on the command line.
9. The Gradle runtime under the broker: the client starts the daemon under the profile, the
   daemon's pid and start time recorded after each command, teardown by the recorded groups,
   reuse and cancel left to Gradle. Gate rows: persistence, teardown of workers and test
   executors, an unrelated service of this host reachable, other hosts denied as destinations,
   proxy egress works, the user's own `~/.gradle` daemons untouched, a toolchain the project asks
   for failing by name, the native libraries Gradle unpacks under its user home loading under
   the home's read-write grant.
10. Phase 2 documentation: README and help, `SECURITY.md`'s table row and teardown sentence,
    `doc/run-on-host.md`'s Gradle section with 9.7.1 as the release measured, the TODO entry
    removed.

Gradle consumes the broker session and runtime ownership of Phase 1; it never duplicates a
lifecycle.

---

# Non-goals

- daemon persistence across launches;
- Linux or Windows `--run-on-host`;
- arbitrary installed JVMs, automatic JDK installation;
- automatic Gradle distribution or toolchain installation;
- custom Gradle distributions in the first pass;
- support promises for every historical Gradle 7/8/9 minor;
- direct Internet access, automatic egress expansion;
- fallback to container execution after a host refusal;
- Gradle patching or instrumentation, fixed Gradle ephemeral-port ranges;
- a claim that Gradle, or Mill's daemon group, has the localhost isolation of sbt and Maven;
- concurrent host commands within one launch;
- a Mill dependency in this launcher's build, unless the starter's gate row fails (7.7).

---

# Evidence

Repository baseline, read 2026-09-10: `doc/run-on-host.md`, `SECURITY.md` "Run on host",
`doc/TODO.md`, `RunOnHostChannel.scala`, `RunOnHostSession.scala`, `RunOnHostSandbox.scala`,
`SeatbeltProfile.scala`, `SbtServerShutdown.scala`, `src/probe/session-recovery.sh`,
`src/probe/run-on-host-profile-gate.sh`.

sbt, read 2026-09-10 at tags v1.13.0 and v2.0.8:

- `main-command/src/main/scala/sbt/internal/client/NetworkClient.scala` — the server fork
  command line (`serverCommand` in 2.0.8, inline in 1.13.0), the stderr file, the connect-first
  path with a live portfile.
- `main/src/main/scala/sbt/internal/CommandExchange.scala` — `removeChannel` cancelling the
  disconnected channel's exec; in 2.0.8 `notifyOtherServers`, `handleDropIfIdle`.
- `main/src/main/scala/sbt/Defaults.scala` — `serverIdleTimeout` 7 days;
  `main/src/main/scala/sbt/internal/SysProp.scala` — `globalLocalCache`,
  `secondaryIdleTimeoutSec`.
- `main-command/src/main/java/sbt/internal/BootServerSocket.java` — the boot socket path.
- https://www.scala-sbt.org/1.x/docs/sbt-server.html

Darwin, read 2026-09-10: XNU `bsd/kern/uipc_usrreq.c` `unp_connect` copies the listener's address
onto the accepted socket; Apple lsof `dialects/darwin/libproc/dsock.c` names a UNIX socket by its
path, else `->0x<peer pcb>`, else `->(none)`, and prints its own pcb as DEVICE; `dproc.c` skips
a process on `EPERM`/`ESRCH` silently, enters an enumeration failure as an `err` entry, and
reads each descriptor under the kind the kernel's listing gives it; `dfile.c` `err2nm` names
one unreadable descriptor `<kind>: <reason>` under that kind; `proc.c` `alloc_lfile`
gives every file of a process selected by `-u`/`-p` that selection.

Measured 2026-09-10 on macOS 26.4.1, arm64, JDK 25.0.4, by
`src/probe/run-on-host-broker-session.sh`:

- SBPL: `(local ip "localhost:*")` admits a port-0 bind and accept; an exact-port
  `network-outbound` rule reaches its port and denies the neighboring one.
- sbt 1.13.0 and 2.0.8: the owner's command line publishes the portfile under the owner's
  directory within 10 s; a client with its own `tmp/` attaches to the same process, forking
  nothing, under `(remote unix-socket (subpath <owner tmp>))`; the detector of 7.3; the cancel
  and the proc entry of 6.3; the denied client of 6.2.
- Mill 1.1.9: the starter's connect under the daemon profile is denied and the daemon stays in
  the starter's group, listening on one port, the one `socketPort` names, with no established
  connection while idle; a client confined to the neighboring port is denied and the daemon
  stays; the starter ends a foreign daemon whose fingerprint differs; the launcher facts of 7.1.
  With the JVM launcher as the client: each command's environment reaches the build; a running
  command is one established connection on the daemon's port; after a client's TERM
  mid-`app.run` the daemon is gone within 30 s and so is the forked JVM; a daemon started with
  `MILL_SERVER_TIMEOUT_MILLIS=5000` exits 5 s after its first client's disconnect. With the JVM
  launcher as the starter: the daemon survives its denied connect, and the starter ends a
  foreign daemon whose fingerprint differs.

Mill, read 2026-09-10 at tag 1.1.9 — each file below, and the bootstrap script, byte-identical
to 1.1.8's:

- `runner/launcher/src/mill/launcher/MillLauncherMain.scala`, `MillProcessLauncher.scala`,
  `MillServerLauncher.scala` — daemon start with `destroyOnExit = false`, `mill.server_timeout`
  from `MILL_SERVER_TIMEOUT_MILLIS`, the per-command `Initialize` carrying the client environment.
- `libs/daemon/client/src/mill/client/ServerLauncher.scala` — `launchOrConnectToServer`, the
  10-second connect retry, `openSocket`, `DaemonConfig` and the `processId` removal that ends a
  mismatched daemon.
- `libs/daemon/server/src/mill/server/Server.scala` — port 0 bind, `socketPort`,
  `watchProcessIdFile`, the shutdown on a client disconnect mid-command, the accept timeout.
- `runner/launcher/src/mill/launcher/CoursierClient.scala` — the self-validating classpath memo.
- https://mill-build.org/mill/cli/installation-ide.html

Gradle:

- https://gradle.org/releases/
- https://docs.gradle.org/current/userguide/compatibility.html
- https://docs.gradle.org/current/userguide/gradle_daemon.html
- https://docs.gradle.org/current/userguide/toolchains.html
- Prior Gradle source analysis: https://chatgpt.com/share/6aa1770d-ba30-83ee-b7b0-72ceaa317ea0 —
  dynamic TCP port-0 listeners in Gradle's messaging; the UDP port-0 listener of
  `DefaultFileLockCommunicator`; no supported fixed-port control.

---

# Must verify during implementation

- The client profile's exact grants for the boot socket and the server socket under the broker's
  `tmp/`, with today's sbt profile rather than the probe's allow-default one.
- `src/probe/run-on-host-broker-session.sh` measured everything else Phase 1 rests on, in
  its Evidence entry; a change to a rule or a command line is a rerun of it.
- Exact Seatbelt rules for Gradle 7.6.6, 8.14.5 and 9.7.1 loopback TCP **and** UDP with
  non-loopback still denied; real tasks exercising worker TCP and file-lock UDP; the toolchain
  property precedence on all three; static discovery of installed Coursier JDKs; lookup of a
  pre-provisioned distribution without triggering the wrapper download.
