# Issues to report upstream

Each entry is written as the report to submit and holds only what upstream needs. Each group says
where this project's own handling is.

## sbt/sbt

Found while measuring the `--run-on-host` build sandbox. What this project does about each is in
`run-on-host.md` and the code it points to.

### Quoted JVM options are copied into arguments

**Versions:** sbt runner 2.0.8, Temurin 25.0.4 on macOS; also reproduced on Linux.

**Reproducer:** from an sbt project, print the JVM properties without starting the build:

```sh
JAVA_TOOL_OPTIONS='-Djava.io.tmpdir="/tmp"' \
    sbt --server -J-XshowSettings:properties -J--dry-run
```

**What happens:** `java.io.tmpdir` is `"/tmp"`, including the quotes. An actual build fails when
ipcsocket loads its native library because the quoted path is not absolute. A value containing
spaces can prevent JVM startup. `--jvm-client` and `JDK_JAVA_OPTIONS` have the same problem.

**Why:** the runner assigns `java_tool_options=($JAVA_TOOL_OPTIONS)` and
`jdk_java_options=($JDK_JAVA_OPTIONS)`, then passes the arrays to Java. Shell expansion splits
words without interpreting quotes within them. These arguments override the values the JVM
already parsed correctly from its environment. The script's `findProperty` also splits quoted
environment values without unquoting them when selecting the preloaded cache directory.

**Expected:** preserve the JVM's parsing of its environment options, including quoted paths;
the script's cache lookup should agree with the JVM's value.

### The JVM thin client crashes instead of reporting a long boot-socket path

**Title:** `--jvm-client` dies with `Trace/BPT trap: 5` when `java.io.tmpdir` is over 52 characters
on macOS

**Versions:** sbt 2.0.7, Temurin 25.0.4, macOS 26 on Apple silicon.

**Reproducer:**

```sh
t=/private/tmp/$(printf 'y%.0s' $(seq 43)); mkdir -p "$t"      # 56 characters
JAVA_TOOL_OPTIONS="-Djava.io.tmpdir=$t" sbt --jvm-client -batch about
echo "exit $?"                                                  # 133
```

With 43 `y`s replaced by 39 (52 characters) the same command runs. With the 56-character value and
`XDG_RUNTIME_DIR=/private/tmp/kt` it runs, which isolates the boot socket.

**What happens:** the `java` process exits on `SIGTRAP`. The crash report names
`libsystem_c.dylib: detected buffer overflow` in `__memcpy_chk`, with no Java frames.

**Why:** `BootServerSocket.socketLocation` builds
`<XDG_RUNTIME_DIR or java.io.tmpdir>/.sbt/sbt-socket<farmHash>/sbt-load.sock`, about 50
characters past the directory. A UNIX-domain socket path on macOS is at most 104 bytes including
the terminator. `Server.scala` checks the *server* socket against `maxSocketLength` and fails with
"socket file absolute path too long … define a short SBT_GLOBAL_SERVER_DIR"; the boot socket, and
the client's connect to it through `ipcsocket`'s JNI, have no such check, so the overrun is
caught by the C library's fortified `memcpy` and kills the process.

**Expected:** the message the server socket already gives, naming `XDG_RUNTIME_DIR` as the setting,
from whichever side sees the path first.

**Related:** #3932 (`SBT_GLOBAL_SERVER_DIR` for long server-socket paths), #6887 / #6907
(`XDG_RUNTIME_DIR` for the boot socket).

### sbtn exits 0 with nothing run when it cannot start its server

**Title:** sbtn reports success and runs nothing when the server fork dies

**Versions:** sbt 2.0.7, Temurin 25.0.4, macOS 26 on Apple silicon.

**Reproducer:** run `sbt -batch compile` (sbtn, the default client) in an environment where the
forked server cannot start — a `sandbox-exec` profile that denies the `java` the re-invoked sbt
script resolves from `PATH` reproduces it deterministically:

```text
[info] entering thin client - BEEP WHIRR
[info] starting sbt server in the background
[info] use 'sbt shutdown' to shutdown the server
[info]
```

The client then exits 0. Nothing was compiled, nothing more is printed, no server log exists, and
`sbt --jvm-client -batch shutdown` afterwards says no server is running.

**Expected:** a nonzero exit and a message naming the failed server start. `--jvm-client` in the
same environment either completes the command or fails with output; success with no work is the
one behavior automation cannot detect.

### No one-shot mode: every invocation is a server rendezvous

**Title:** Feature: a one-shot mode that runs the build in-process and touches no server

**Versions:** sbt 2.0.7.

**Context:** a wrapper that confines builds (CI sandbox, `sandbox-exec` profile) cannot safely
build a project whose portfile is held by a developer's live server: the thin client attaches to
whatever server `project/target/active.json` names and the build then runs with *that* server's
environment, outside the wrapper's confinement. The rendezvous cannot be relocated — the build
directory is always the working directory, `project/target/active.json` is fixed
(`NetworkClient.scala`, `CommandExchange.scala`), and `--no-server` still requires a server to
connect to — so the wrapper's only safe options are refusing the build or shutting the
developer's server down.

**Request:** a mode that runs the command queue in-process, holds the project exclusively for the
duration, and writes no portfile — the property `mill --no-daemon` provides. Confining wrappers
could then coexist with a developer's live server instead of ending it.

**Related:** #8030 (a one-shot-style `sbt "show scalaVersion"` leaving a hanging server
surprises users; a true one-shot mode would answer it too).

## scalameta/munit

What this project does about it is the test listener in `build.sbt`.

### A skipped test's `assume` clue is not printed

**Title:** The clue of a failed `assume` is not shown for the skipped test

**Versions:** munit 1.3.6, sbt 2.0.8, Scala 3.9.0 and 3.7.3.

**Reproducer:**

```scala
class BodyTest extends munit.FunSuite:
  test("body assumption")(assume(false, "needs lychee on PATH"))

class FixtureTest extends munit.FunSuite:
  private val directory = FunFixture[String](
    setup = _ => { assume(false, "needs python3 with wcwidth"); "x" },
    teardown = _ => (),
  )
  directory.test("fixture assumption")(_ => ())
```

**What happens:** `sbt test` prints that each test was skipped and not why:

```text
==> s BodyTest.body assumption skipped 0.001s
==> s FixtureTest.fixture assumption skipped 0.006s
```

A reader cannot tell a skip that belongs to the platform from a missing prerequisite, or learn
which command would run the test.

**Why:** `EventDispatcher.testAssumptionFailure` receives the `Failure` and logs the test's name
and ` skipped`, without the exception's message:
https://github.com/scalameta/munit/blob/v1.3.6/junit-interface/src/main/java/munit/internal/junitinterface/EventDispatcher.java

The exception is not lost: the `ErrorEvent` passed to sbt carries it, and an sbt `TestsListener`
reading `event.detail.throwable` prints the clue in both cases above.

**Expected:** the clue on the skipped test's line, or on a line after it:

```text
==> s BodyTest.body assumption skipped 0.001s: needs lychee on PATH
==> s FixtureTest.fixture assumption skipped 0.006s: needs python3 with wcwidth
```

The test stays skipped and the run's totals do not change.

**Not verified:** reproduced under sbt only, not under Mill, Gradle or Maven.

## openai/codex, anthropic-experimental/sandbox-runtime, google-gemini/gemini-cli

One report for each project's macOS Seatbelt profile. This project's own profile has the same
gap: `TODO.md`, "A host command reads other processes' environments", and `run-on-host.md`, "The
Seatbelt profile".

### A sandboxed command reads other processes' environment through `KERN_PROCARGS2`

**Title:** The macOS Seatbelt profile lets a sandboxed command read the arguments and environment
of processes outside the sandbox

**Versions:** macOS 26 on Apple silicon, Temurin 25.0.4. Profiles as read on 2026-10-04: Codex's
`codex-rs/sandboxing/src/seatbelt_base_policy.sbpl`, sandbox-runtime's
`src/sandbox/macos-sandbox-utils.ts`, Gemini CLI's `packages/cli/src/utils/sandbox-macos-*.sb`.

**Reproducer:** `ProcArgs.java` is `src/probe/ProcArgs.java` of this repository. It calls
`sysctl` with `{CTL_KERN, KERN_PROCARGS2, pid}` and prints variable names, never values.

```sh
KO_AGENT_PROCARGS_PROBE=1 "$JAVA_HOME/bin/java" ProcArgs.java --hold &      # a process outside
printf '%s\n' '(version 1)' '(allow default)' \
    '(deny sysctl-read (sysctl-name-regex #"procargs"))' > procargs.sb
sandbox-exec -f procargs.sb "$JAVA_HOME/bin/java" --enable-native-access=ALL-UNNAMED \
    ProcArgs.java "outside=$!"
```

**What happens:** the sandboxed process reads the other process's environment, though the
profile denies the sysctl by name:

```text
outside (pid 48275): ENVIRONMENT READ arguments=3 variables=39 names=KO_AGENT_PROCARGS_PROBE,…
```

A token in the environment of any process of the user whose binary is not Apple's is readable:
the kernel omits the environment only for a code-signing restricted target (xnu,
`sysctl_procargsx`). Arguments are readable for every process.

**Why:** the call succeeds while either `sysctl-read` of its name, `kern.procargs2.<pid>`, or
`process-info-pidinfo` is allowed, and `(deny default)` does not cover `process-info*`
(Firefox's `SandboxPolicyContent.h`: "These are not included in (deny default)"; WebKit's
`com.apple.WebProcess.sb.in`: "process-info* defaults to allow"). Each of the three profiles
starts from `(deny default)` and allows `sysctl-read` for a list of names without this one, and
none denies `process-info*`, so the second route stays open. Codex's and sandbox-runtime's
`(allow process-info* (target same-sandbox))` narrows nothing without a deny before it.

**Expected:** the rule of agent-safehouse's `profiles/10-system-runtime.sb`, which refuses the
read here while a JDK runs, lists processes and still reads a child it started:

```scheme
(deny sysctl-read (sysctl-name-regex #"procargs"))
(deny process-info-pidinfo)
(allow process-info-pidinfo (target same-sandbox))
```

**Not verified:** the reproducer ran under `sandbox-exec` with the profile above, not under any
of the three projects' own sandboxes. Run its last command under each before submitting. No
public report of it for these projects was found by a web search without GitHub code search.
