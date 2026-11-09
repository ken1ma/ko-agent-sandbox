# Seatbelt — the behavior that the host command profiles depend on

Under `--run-on-host`, each host command and its proxy run under a Seatbelt profile that
`SeatbeltProfile.scala` generates ([run-on-host-internals.md](run-on-host-internals.md)). This
document records the Seatbelt behavior that those profiles depend on.

Apple does not document SBPL for third-party use. `sandbox-exec` compiles SBPL through private
entry points, and the published write-ups are reverse-engineered and date from 2011. Two sources
are authoritative here:

- measurement (`src/probe/seatbelt-semantics.sh`, `src/probe/run-on-host-profile-iterate.sh`);
- Apple's own shipped profiles under `/System/Library/Sandbox/Profiles/`, which are current and
  written against the implementation. `system.sb` is the one worth reading first.

`SeatbeltProfile.scala` encodes the findings, and its header states the two that shape the whole
profile. The sections below record the rest, measured.

## Paths

Measured with `src/probe/seatbelt-semantics.sh` on macOS 26.4.1:

- Seatbelt resolves the accessed path before matching, so a write through `link -> .git` is
  denied.
- On a case-insensitive volume, a lowercase pattern matches the other spellings measured:
  - An access through `.GIT` to an existing `.git` resolves to the lowercase path and is denied
    (E5).
  - A `.GIT` that the command creates where no `.git` exists is denied too (E9).
  - The volume resolves `.ko-agent-sandbox` spelled with U+212A KELVIN SIGN or U+017F LONG S to
    the name (E11), and the lowercase pattern denies creating either spelling (E12).
- Seatbelt evaluates rules at access time, so the rules cover a `.git` created *during* the
  command.
- One regex matches a name at every depth.
- `file-write*` already refuses a hard link to a denied target, so the explicit link clause is
  redundant. The clause stays, because the membership of a wildcard operation family is Apple's
  to change.
- SBPL has no operation of a rename's own (E13–E17):
  - SBPL checks a rename's source as `file-write-unlink`, as it checks `rmdir` and `unlink`.
  - SBPL checks the rename's destination as `file-write-create`, as it checks `mkdir`.
  - SBPL checks a `RENAME_SWAP` exchange as both, on either operand.

Seatbelt answers an existence test for a path it denies reading: `Files.exists` is true and the
open is denied. No row of that probe measures this. The runner met it with Mill's classpath file
([run-on-host-internals.md](run-on-host-internals.md), "`mill`").

## Network

Measured, and none chosen from documentation (`src/probe/loopback-rule.sh`,
`src/probe/jvm-proxy-rule.sh`, `src/probe/run-on-host-runner-session.sh`):

- A network rule's host is `*` or `localhost`. The compiler refuses an ip-literal host ("host must
  be * or localhost"), so a rule for one port of this host is `(remote ip "localhost:<port>")`.
- The `localhost` class covers native `127.0.0.1` and `::1`, but not a JVM's dual-stack connect.
  That connect reaches `127.0.0.1` as the v4-mapped `::ffff:127.0.0.1` and dies with `EPERM`.
- Seatbelt counts a local socket as network: a UNIX-domain `bind()` or `connect()` needs a
  `unix-socket` rule.
- `(local ip "localhost:*")` admits a port-0 bind and accept, and no rule confines a port-0 bind to
  one port (L1–L4).
- The `localhost` class is this host's addresses, not loopback (G1, G4–G10):
  - under `(local ip "localhost:*")`, a bind to the wildcard or to the LAN address is admitted, and
    the socket answers at the LAN address, over TCP and UDP;
  - `(remote ip "localhost:*")` connects to the LAN address too;
  - no spelling names loopback alone, since the compiler takes no other host.
- `(remote ip "localhost:<port>")` reaches that port at every address of this host (G11), and is
  denied the neighboring port (L3, L4, M3).

## Devices and failures

- `/dev/tty` is the terminal, whatever stdin is: closing the child's stdin does not detach its
  controlling terminal. The profile grants `/dev/null` and the random devices only.
- An invalid profile fails exactly like a denial. `sandbox-exec` aborts the child either way, and
  the difference shows only on `sandbox-exec`'s own stderr. A search that discards that stderr
  looks for grants that were never missing.

## Mach services

`mach-lookup` names its services (`SeatbeltProfile.MachServices`), in the command's profile and the
proxy's. Unfiltered, `mach-lookup` reaches every Mach service of the host, and a service may act
for its caller outside the profile.

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
- Under the named service, `SeatbeltCheck` has rows for `open -a`, for a JVM asking the
  resolver, and for a lookup of an internet name, which must fail (SECURITY.md, "DNS").

## What the JDK needs

- The JDK needs `sysctl-read`, its home, and `/System/Library/CoreServices/SystemVersion.plist`.
  Without that one file, `java` refuses to start with `os.version malformed: -1.0`.
- The JDK does *not* need `file-map-executable`, which Apple's profiles use for system
  frameworks. A JDK outside those paths loads without it.
- Adopted from `system.sb` rather than re-derived: `file-test-existence`, a narrower operation than
  `file-read*`, for the ancestor chain.

## Processes

The profile denies a command reading another process's arguments and environment through `sysctl`
`kern.procargs2`, the call behind `ps -E` (`SeatbeltProfile.ProcessReadRule`;
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
- Under that rule, "the same sandbox" means the inherited one. The read succeeds for a child the
  reader starts, and is refused for a JDK under a `sandbox-exec` of its own with the same
  profile. `ProcessHandle.of` still finds every process, those outside included.
- `ProcessHandle.info()` of a process outside throws "Operation not permitted". The JDK reads the
  process's arguments for it, and throws on any error but `EINVAL` and `EIO`
  (`ProcessHandleImpl_macosx.c`).
  - Mill 1.1.10's client checks its daemon that way (`PidLock`), and the mill channel rows fail
    under the rule without the exception below (2026-10-04).
- `(allow sysctl-read (sysctl-name "kern.procargs2.<pid>"))` after the rule opens the read, and
  `info()`, for that one process. Every other target stays denied (the probe's last row,
  2026-10-04).
- A mill client's profile allows that name for its daemon (`SeatbeltProfile.Network.MillClient`).
  The runner gave the daemon the client's own environment, so the read exposes nothing the client
  lacks.
- `SeatbeltCheck`'s process rows read a JDK outside the profile and a child inside it, under every
  program's profile.

## System paths

The system paths are the loader, libc, the CA bundle and the rest that a toolchain needs from the
system:

- The set is discovered by running a real build under a deny-default profile and reading the
  denials. The set is never discovered by listing what a host happens to have, and never used as
  a way to reach a user path. `src/probe/run-on-host-profile-iterate.sh` measures candidate
  entries.
- The measured set is one file, a resource of the launcher's own artifact
  (`src/main/resources/agentsandbox/SeatbeltProfile.SystemPaths.txt`). What the production
  supervisor grants is what the probes measured, and the run-on-host checks and host commands use
  that same set of grants.
- Do not pre-authorize broad paths (`/System/**`, `/usr/**`, `/opt/homebrew/**`). Add the narrowest
  rule that testing justifies.

## Prior art: Bazel

Bazel sandboxes build actions on macOS with `sandbox-exec`, which is the host commands' problem
exactly. Bazel's generated profile is worth reading, and worth *not* copying. `writeConfig` in
https://github.com/bazelbuild/bazel/blob/9.3.1/src/main/java/com/google/devtools/build/lib/sandbox/DarwinSandboxedSpawnRunner.java
writes it.

- Bazel's profile is a blacklist: `(allow default)`, then writes and network taken away. That is
  why Bazel never meets the findings above. With nothing denied by default, path resolution cannot
  fail, so the root entry and the ancestor chain never arise.
- That is also why the blacklist design cannot serve here. A command under it reads the whole
  filesystem, and "everything else user-owned inaccessible" is the property `--run-on-host` exists
  to provide.
  - Deny-by-default makes the profile harder to construct, and is what provides that property. So
    the difficulty is no reason to change the design.
  - This section records that, because the blacklist form is the obvious simplification when the
    whitelist will not start.
- One setting is taken from Bazel: `(debug deny)`, which makes denials visible without the unified
  log's redaction. `src/probe/run-on-host-profile-iterate.sh` puts it at the top of every profile
  it iterates.
