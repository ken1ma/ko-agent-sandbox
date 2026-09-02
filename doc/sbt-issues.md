# Issues to report upstream to sbt/sbt

Found while measuring the `--run-on-host` build sandbox, each written as the report to submit.
What this project does about each is in `run-on-host.md` and the code it points to; the row here
is only what upstream needs.

## The JVM thin client crashes instead of reporting a long boot-socket path

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

**Expected:** the message the server socket already gives, naming `XDG_RUNTIME_DIR` as the knob,
from whichever side sees the path first.

**Related:** #3932 (`SBT_GLOBAL_SERVER_DIR` for long server-socket paths), #6887 / #6907
(`XDG_RUNTIME_DIR` for the boot socket).

## sbtn exits 0 with nothing run when it cannot start its server

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

## No one-shot mode: every invocation is a server rendezvous

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
