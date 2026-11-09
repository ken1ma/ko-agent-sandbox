# Run on Host — recorded measurements

This document records the measurements that a new release of a program, of macOS or of podman can
change. [run-on-host-internals.md](run-on-host-internals.md) keeps each measurement that a
mechanism depends on beside that mechanism.

## The run-on-host checks

The four checks under `src/test/run-on-host/` measure the exit criteria. On macOS 27.2 arm64 with
Temurin 25.0.4, sbt 2.0.12, Mill 1.3.1 and 1.1.10, Gradle 9.8.2 and 8.14.6, Maven 3.9.16 and
podman 6.1.4 on libkrun (2026-11-09), every row passes and none is skipped:

| Check | Rows | Time |
|---|---|---|
| `SeatbeltCheck.scala` | 346 | 24 s |
| `BuildsCheck.scala` | 40 | 55 s |
| `CommandLifecycleCheck.scala` | 6 | 42 s |
| `ChannelCheck.scala` | 45 | 6 min |

- Each time runs from the machine block to the totals, the setup's emitting included. Scala CLI's
  compile of the driver comes before it.
- In `ChannelCheck`, the mill 1.1.10 group is the longest: Mill's bound for a busy daemon of
  yours (`RunOnHostMillDaemons.ForeignIdleDeadlineMillis`) holds one of its rows for two minutes.

## Memory

An `sbt test` of this project takes about 2 GB inside the podman machine. That measurement is why
`--run-on-host` exists ([run-on-host.md](run-on-host.md), "Why use it").

- The machine's total memory is fixed when the machine is created, and every other session on the
  machine shares it.
  - podman's built-in default for a macOS machine is 2 GiB. containers.conf (`[machine]`
    `memory`) or `--memory` changes it.
  - A WSL machine has WSL's memory, half the host's by default.
- A session gets the machine's memory minus 1 GiB (README, `--memory`): about 1 GiB on podman's
  default, and 3 GiB on a 4 GiB machine. The agent, the build and the session's other processes
  share that memory.
- Whether the machine gives memory back to macOS depends on libkrun. From 1.19.0, libkrun frees
  the pages the guest reports free with MADV_FREE, which macOS reclaims under memory pressure
  (containers/libkrun pull 703).
- A measurement with libkrun 1.19.0 (podman 6.1.4, macOS 26.4.1) on a freshly restarted 12 GiB
  machine (`src/probe/PodmanMachineMemoryReclaim.scala`, 2026-11-02):
  - The build grew the machine's process from 5.5 GiB to 13.7 GiB of resident memory. The
    process held 14.3 GiB at the end of the ten minutes after the build.
  - A minute of `memory_pressure -l warn` then lowered the resident size to 4.8 GiB. The process's
    compressed memory rose from 0 to 8.3 GiB of that 9.5 GiB decrease, and the remaining 1.2 GiB
    is consistent with discarded pages.
  - Swap stayed level at 1.4 GiB throughout.
  - In the guest, `Cached` grew from 2.2 GiB to 4.9 GiB and `MemFree` fell from 9.1 GiB to
    6.1 GiB, so the guest kept the build's page cache.
- A measurement with podman 6.1.2 on the same machine size (2026-09-22) showed the same pattern:
  6.8 GiB grown, 6.6 GiB compressed under pressure, and 1.7 GiB dropped.
- So the process keeps what a build grew until macOS is short of memory. Under pressure, growth in
  the process's compressed memory matched most of its resident decrease, and the remainder is
  consistent with discarded pages.
- A measurement with WSL 3.0.3.0 (kernel 6.18.54.1, podman 6.1.4, Windows Server 2025,
  `autoMemoryReclaim` unset) on a freshly started machine
  (`src/probe/PodmanMachineMemoryReclaim.scala`, 2026-11-03):
  - The guest had 7.6 GiB, WSL's default, while `podman machine inspect` reported 2 GiB.
  - The build grew the VM process's working set from 1.0 GiB to a peak of 7.8 GiB, and the
    process held 7.0 GiB when the build exited.
  - Within the ten minutes after the build, the working set fell back to 1.0 GiB, and Windows'
    free memory rose from 2.5 GiB to 9.4 GiB.
  - In the guest, `Cached` fell from 4.4 GiB to 0.2 GiB and `MemFree` rose from 2.6 GiB to
    7.1 GiB over the same ten minutes.
  - The control run with `autoMemoryReclaim=disabled` is not measured, so this run does not
    attribute the return to that setting.
- So WSL returned the build's memory to Windows without host pressure, and the guest dropped its
  page cache.

## Fetches through an inspecting proxy

Measured through a sandbox session's proxy, which inspects the same hosts as a host command's proxy
does, with a handshake per request:

| program | resolved | result |
|---|---|---|
| sbt 2.0.9 | `spark-sql` 3.5.1, `update`, empty Coursier cache | 1960 files, 240 MB, 36 s |
| mill 1.0.6, JVM launcher | the same, `app.resolvedMvnDeps`, its own runtime included | 4040 files, 336 MB, 55 s |
| Gradle 9.7.1 | `src/test/run-on-host/fixtures/gradle`, `test`, the distribution present | 32 files, 6 s |
| Maven 3.9.16 | `src/test/run-on-host/fixtures/mvn`, `test`, the distribution's download included | 418 files, 14 MB, 37 s |

## Mill without a daemon

Measured on Mill 1.3.0 with the fixture through a launch's runner, under the client profile with
the runner's daemon unused (2026-10-19): the first `__.compile` took 71 s, then `__.test` 4.0 s,
and a `__.compile` with nothing to compile 5.8 s. A warm daemon's times are unmeasured.

## Gradle releases

`src/test/run-on-host/fixtures/gradle` pins Gradle 9.8.2, and the run-on-host checks also run the
Gradle rows on a copy pinned to the last Gradle 8 release, 8.14.6. "The run-on-host checks" above
has the totals.

- Gradle 8.14 through 8.14.3 fail on JDK 25, the JDK the launcher requires. Each fails compiling
  the build script with "Unsupported class file major version 69", so releases before 8.14.4 are
  out.
- Gradle's compatibility matrix lists Java 25 only from 9.1.0
  (https://docs.gradle.org/current/userguide/compatibility.html). 8.14.4 supports Java 25 only in
  part: it moves Groovy to 3.0.25 and ASM to 9.8, and leaves full support out of scope
  (https://github.com/gradle/gradle/issues/36420).
