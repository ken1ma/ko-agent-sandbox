# Issues to report upstream to sbt/sbt

Found while measuring PLAN-SBT-ON-HOST.md, each written as the report to submit. What this
project does about each is in the plan; the row here is only what upstream needs.

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
