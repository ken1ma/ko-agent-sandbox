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

## containers/libkrun

Found when MicrophoneRelayTest, run in a sandbox session, kept FIFOs in the workspace, which on
the macOS podman machine is the `/Users` share. This project keeps the test's FIFOs out of the
workspace; what a session can do with a FIFO of its own is open (doc/TODO.md).

### Setting a FIFO's times blocks the macOS virtio-fs server

**Title:** macOS passthrough `setattr` opens the file without `O_NONBLOCK`, so a time change on a
FIFO hangs the whole share

**Versions:** podman 6.1.2 with the libkrun provider (krunkit), macOS on Apple silicon; libkrun's
`main` read on 2026-10-14.

**Reproducer (inferred, not run, since it hangs every process that touches the share):** in the
guest, on a virtio-fs share of a macOS directory:

```sh
mkfifo f && touch f
```

**What happens:** a test that created FIFOs on the share and wrote through one hung the machine,
four times out of four: every process touching `/Users` blocked unkillably, `podman kill` timed
out waiting for the container's exit file, and `podman machine stop` fell back to a hard stop.
The timing matches the guest writing back the FIFO's changed times, as the source below explains;
the request itself was not traced.

**Why:** `setattr` (`src/devices/src/virtio/fs/macos/passthrough.rs`) changes times on an inode
it holds by path with `libc::open(c_path, O_SYMLINK | O_CLOEXEC)` and `futimens`. On macOS a
read-only open of a FIFO waits for a writer; the guest's readers and writers use the guest's own
pipe, so none ever opens the host's FIFO. One `fs worker` thread serves each share (`worker.rs`),
so every later request on the share waits behind it.

**Expected:** open with `O_NONBLOCK` there, as `grab_unlinked_fd` and the truncate path already
do, or change the times by path (`utimensat` with `AT_SYMLINK_NOFOLLOW`) without opening.

## openai/codex, anthropic-experimental/sandbox-runtime, google-gemini/gemini-cli

One report for each project's macOS Seatbelt profile. This project's own profile closes the gap
with the rule below (`SeatbeltProfile.ProcessReadRule`; `run-on-host.md`, "The Seatbelt profile").

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

## openjdk/jdk

Found when the `--run-on-host` acceptance test ran its mill rows on Mill 1.3.0, whose daemon reads
each launcher's start time (the com-lihaoyi/mill entry below). This project runs Mill 1.2 and later
without a daemon (`run-on-host.md`, "Mill 1.2 and later: no daemon").

### `ProcessHandle.info()` throws on macOS when `KERN_PROCARGS2` returns `EPERM`

**Title:** On macOS, `ProcessHandle.info()` throws `RuntimeException: Operation not permitted` for
a process whose arguments the caller may not read, and drops the start time it already read

**Versions:** Temurin 25.0.4, macOS 26.6.2 on Apple silicon. Source read on 2026-10-19:
`src/java.base/macosx/native/libjava/ProcessHandleImpl_macosx.c` at jdk-25+36 and `master`.

**Reproducer:** `Info.java`:

```java
public class Info {
    public static void main(String[] args) {
        var process = ProcessHandle.of(Long.parseLong(args[0])).orElseThrow();
        System.out.println(process.info().startInstant());
    }
}
```

```sh
sleep 600 & outside=$!
printf '%s\n' '(version 1)' '(allow default)' \
    '(deny sysctl-read (sysctl-name-regex #"procargs"))' \
    '(deny process-info-pidinfo)' '(allow process-info-pidinfo (target same-sandbox))' > info.sb
sandbox-exec -f info.sb "$JAVA_HOME/bin/java" Info.java "$outside"
```

**What happens:**

```text
java.lang.RuntimeException: Operation not permitted
    at java.base/java.lang.ProcessHandleImpl$Info.info0(Native Method)
    at java.base/java.lang.ProcessHandleImpl$Info.info(ProcessHandleImpl.java:562)
    at java.base/java.lang.ProcessHandleImpl.info(ProcessHandleImpl.java:479)
```

**Why:** `info0` (`ProcessHandleImpl_unix.c`) stores the start time from `kern.proc`, then calls
`os_getCmdlineAndUserInfo`. When its `sysctl` of `{CTL_KERN, KERN_PROCARGS2, pid}` fails with an
errno other than `EINVAL` or `EIO`, it throws, and the caller loses the start time with the
arguments. Linux's `os_getCmdlineAndUserInfo` returns quietly when it cannot open
`/proc/<pid>/cmdline`. A sandbox refuses the read with `EPERM`; the profile above has the rule of
agent-safehouse's `profiles/10-system-runtime.sb`.

**Expected:** treat `EPERM` as `EINVAL` and `EIO` are treated, leaving the arguments empty. The
`ProcessHandle.Info` Javadoc says the information "is limited by the operating system privileges
of the process making the request", and `info()` declares no exception. JDK-8276651 (fixed in 20,
backported to 17u and 11u) added `EIO` for the same reason; its review (openjdk/jdk#9946) reads:
"The spec for `ProcessHandle.info()` does not declare any exceptions so there is little risk
changing the behavior by quietly returning in the case of EINVAL or EIO".

**Not verified:** the reproducer was not run. The stack trace is Mill 1.3.0's daemon under this
project's command profile, which has the same three rules; `run-on-host.md`, "The Seatbelt
profile", has the measurement that allowing `kern.procargs2.<pid>` after them makes `info()` of
that process succeed. That the start time survives the fix is read from the source. No report of
`EPERM` was found on bugs.openjdk.org (searched for `ProcessHandle` with `EPERM`, "Operation not
permitted" and `KERN_PROCARGS2`, 2026-10-19).

## com-lihaoyi/mill

Found with the openjdk/jdk entry above, which is the cause; this report asks Mill to tolerate the
JDK releases that throw. This project's handling is the openjdk/jdk entry's.

### The daemon fails every command when it cannot read the launcher's start time

**Title:** `LauncherOutFilesRecordStore` lets `ProcessHandle.info()`'s exception fail the command
when the daemon may not read the launcher's process information

**Versions:** Mill 1.3.0, Temurin 25.0.4, macOS 26.6.2 on Apple silicon. The code is the same in
2.0.0-M2 and `main` (read on 2026-10-19); it came with #6955 and is absent from 1.1.10.

**Reproducer:** start the daemon inside a Seatbelt sandbox that refuses reading other processes'
arguments, then run a launcher outside it. `info.sb` is the openjdk/jdk entry's profile.

```sh
sandbox-exec -f info.sb ./mill version     # the daemon inherits the sandbox and stays
./mill __.compile                          # the launcher is outside it
```

**What happens:** every command fails with `Mill launcher failed. See out/mill-launcher/log for
details.`, and the daemon reports:

```text
java.lang.RuntimeException: Operation not permitted
    at java.base/java.lang.ProcessHandleImpl$Info.info0(Native Method)
    …
    at mill.internal.LauncherOutFilesRecordStore$.write(LauncherOutFilesRecordStore.scala:25)
    at mill.internal.LauncherOutFilesImpl.writeLauncherRunFile(LauncherOutFilesImpl.scala:55)
    at mill.daemon.MillMain0$.createLauncherResources$1(MillMain0.scala:323)
```

**Why:** `processStartMillis` calls `info()` outside any `try`, and the JDK on macOS throws there
(the openjdk/jdk entry). `liveProcess` in `readActiveRecord` calls `info()` the same way for a
record with a start time, which a launcher waiting for `out/mill-out-lock` reaches while wording
its wait (`SharedOutLockManager.activeOtherProcessPrefix`). The record format already allows no
start time: `write` stores `null`, and `liveProcess` checks such a record by pid alone.

**Expected:** treat an exception from `info()` as an unknown start time in both places, as a
record without one already is.

**Not verified:** the reproducer was not run; the failure is the `--run-on-host` acceptance test's,
where the daemon and each launcher run under separate `sandbox-exec` profiles with the rule
(2026-10-19). No report was found in Mill's issues (searched for `LauncherOutFilesRecordStore`,
`info0` and "Operation not permitted", 2026-10-19).
