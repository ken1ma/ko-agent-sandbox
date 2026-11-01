# Verification log

This file holds the measured runs the design's claims rest on, each with the machine that produced
it.

- `TODO.md` ("Platform verification") says what each row is meant to settle, why a pass without
  its machine is not evidence, and which rows are still open.
- `../../policy/doc/security-research.md` has the outside research the same claims draw on.

## The `.git` name rule on real filesystems

### Verified: APFS case-insensitive (macOS 26.4.1, build 25E253; 2026-08-14)

This is the empirical run `../../policy/doc/security-research.md` calls for. It ran on the default
macOS volume (File System Personality: APFS, the case-insensitive variant), through the full
production stack (FUSE backend session → `ko-agent-fs-fuse` → virtiofs → APFS), using
`probe/apfs-name-rule-probe.py`:

- All 14 denied spellings failed with exactly `EPERM`: `.git` itself, the four ASCII case
  variants, the Turkish i-family, the four forms with ignorable code points, and the three forms
  with trailing punctuation.
- All six allowed names were created. Afterwards the host's `lstat(".git")` found nothing, and
  `git status` found no repository. This is the property itself, on the real fold table.
- An extra observation: the NFC and NFD spellings of `.gít` collapsed into **one** file.
  - This is APFS's normalization-insensitivity, seen live through the whole stack.
  - It confirms both halves of the normalization finding in
    `../../policy/doc/security-research.md` ("Real-filesystem case-folding"): the filesystem really
    treats the forms as one name, and neither resolves anywhere near `.git`.

Fold tables are specific to an OS version. So this verifies **this** release against macOS 26.4.1.
Rerun the probe when either side changes.

### Verified: APFS case-sensitive (macOS 26.4.1, build 25E253; 2026-08-18)

The same corpus ran on the case-sensitive variant, through the same production stack, against a
case-sensitive sparse-image volume mounted under `$HOME`. `probe/name-rule-cs-apfs.sh` drives the
whole run, the checks on the host included:

- All 14 denied spellings failed with exactly `EPERM`, and all six allowed names were created.
- Afterwards the host's `lstat(".git")` found nothing, and git found no repository in the
  workspace. This is the property itself, on this variant's fold table.

### Verified: NTFS (Windows Server 24H2; 2026-08-19)

The corpus ran through the full Windows production stack: FUSE backend session → `ko-agent-fs-fuse`
in the WSL2 podman machine → the host's `C:` NTFS volume served at `/mnt/c`.

- Every denied spelling failed with exactly `EPERM`, and every allowed name was created.
- Afterwards the host's `dir .git` and git discovery found nothing.
- The 8.3 row met `EEXIST`.
  - Short-name generation is active on the volume, and an existing allowed name had already been
    given `GIT~1` as its short name. So nothing was created.
  - The row therefore says nothing about what a created `GIT~1` would become. "Verified: NTFS 8.3
    short names", below, does.
  - Host git found no repository afterwards.
- NTFS kept the NFC and NFD spellings of `.gít` as two files: it is normalization-sensitive where
  APFS collapsed them. Neither resolves anywhere near `.git` on either backing.

### Measured: two letters APFS resolves to `.ko-agent-sandbox`'s (macOS 26.4.1; 2026-09-19)

On the workspace's case-insensitive volume, beside an existing `.ko-agent-sandbox`, two spellings
resolve to it (`src/probe/seatbelt-semantics.sh` E11, the launcher's probe):
`.<U+212A>o-agent-sandbox` (KELVIN SIGN) and `.ko-agent-<U+017F>andbox` (LONG S).

Through a FUSE backend session whose daemon folds neither letter:

- `mkdir` of each spelling succeeds, and `.ko-agent-sandbox` then resolves to the new directory;
- `.KO-AGENT-SANDBOX` meets `EPERM`.

### Verified: the `.ko-agent-sandbox` rows, APFS case-insensitive (macOS 26.4.1; 2026-09-19)

`probe/apfs-name-rule-probe.py` ran through the production stack (FUSE backend session →
`ko-agent-fs-fuse` → virtiofs → APFS), in a subdirectory of a workspace, since the rule holds at
any depth:

- All 21 denied spellings failed with exactly `EPERM`: the 14 `.git` rows, and `.ko-agent-sandbox`
  itself, its two ASCII case variants, the KELVIN SIGN and LONG S spellings, the soft-hyphen form
  and the trailing dot.
- All seven allowed names were created, `.ko-agent-sandbox-notes` among them.
- Afterwards the host's `ls .git` and `ls .ko-agent-sandbox` found nothing there, and git found
  only the repository of the enclosing workspace.
- The mounted suite's rows for both letters pass (`--self-test`, `probe/rig.sh`).

### Verified: the `.ko-agent-sandbox` rows, NTFS (Windows Server 2025, 10.0.26100.32522; 2026-09-19)

The same probe ran through the Windows production stack: FUSE backend session → `ko-agent-fs-fuse`
in the WSL2 podman machine → the host's `C:` NTFS volume served at `/mnt/c`, podman 6.1.0.

- All 21 denied spellings failed with exactly `EPERM`, and all seven allowed names were created.
- Afterwards the host's `dir /a .git` and `dir /a .ko-agent-sandbox` found nothing, and
  `git rev-parse --git-dir` found no repository.
- NTFS kept the NFC and NFD spellings of `.gít` as two files, as in the `.git` run above.
- Whether NTFS resolves the KELVIN SIGN or LONG S spelling to the name is not measured. The FUSE
  backend refuses both, so neither reached the volume.

### Verified: NTFS 8.3 short names (Windows Server 2025, podman 6.1.0; 2026-09-19)

The volume: `C:` with 8.3 name generation on (`fsutil 8dot3name query C:`). In a scratch workspace,
the host created `.git` (`git init`) and `.ko-agent-sandbox/egress/rule`. `cmd /c dir /x /a` shows
their short names `GIT~1` and `KO-AGE~1`.

The WSL drive mount resolves a short name to the entry, and gives it the long name's identity. In
the podman machine, `stat -c '%d:%i'` at `/mnt/c/<workspace>` prints:

- one pair for `.git` and `GIT~1` (`69:5910974511087336`);
- one for `.ko-agent-sandbox` and `KO-AGE~1`;
- one for `.git/config` and `GIT~1/config`.

1000 `stat` processes over `.git` and `.ko-agent-sandbox` took 6.7 s where both exist, and 2.6 s
in a directory with neither.

Inside a FUSE backend session over that workspace (`../../policy/doc/security-research.md`, "Windows
8.3 short names", has the check):

- `echo x >> GIT~1/config`, `echo x >> KO-AGE~1/egress/rule` and
  `echo y > KO-AGE~1/egress/planted` each fail with `Operation not permitted`;
- `mv GIT~1 moved` and `mv KO-AGE~1 moved2` fail with `Operation not permitted`;
- `ls GIT~1` succeeds: reads through the short name work, as they do through `.git`;
- `echo one > scratch-file; echo two >> scratch-file; cat scratch-file` prints both lines. That is
  a create through the backing `O_EXCL` (`fs.rs`, `create`), then a reopen of the file it made.
  - The run has no host create between a lookup and the backing open, so it does not reach the
    `ESTALE` retry. `tests/mounted_races.rs` does, on the rig's kernel.
- Afterwards the host's `Get-Content` shows `.git\config` and `egress\rule` as the host wrote them,
  and `cmd /c dir /x /a .ko-agent-sandbox\egress` lists `rule` alone.

The create side, in a FUSE backend session over a new, empty workspace: `mkdir GIT~1` exits 0. The
host's `cmd /c dir /x /a` afterwards lists one directory with the long name `GIT~1`, no short name,
and no `.git`.

### Verified: a listed name's NTFS 8.3 short name (Windows Server 2025, podman 6.1.0; 2026-09-27)

The volume: `C:` with 8.3 name generation on. In a workspace, the host created
`.vscode/tasks.json`, `.claude/settings.json` and `node_modules/p`. `cmd /c dir /x /a` shows the
short names `VSCODE~1`, `CLAUDE~1`, `NODE_M~1` and `GIT~1`. In a FUSE backend session under the
default file rules:

- `: >> VSCODE~1/tasks.json`, `: >> VSCODE~1/new.json`, `mv VSCODE~1 moved`,
  `: >> CLAUDE~1/settings.json`, `mv CLAUDE~1 moved2` and `mv NODE_M~1/p apps/p` each fail. A short
  name takes the context of the long name it stands for (`fs.rs`, `policy_name`);
- `echo x > CLAUDE~1/notes.md` succeeds, as it does beside the long name.

The host follows a symlink the session makes:

- `ln -s GIT~1 gitlink` in the session gave an NTFS `SymbolicLink` whose target is `GIT~1`.
- The host's `Get-Content gitlink\HEAD` printed `ref: refs/heads/master`.
- So a symlink target that spells a short name is refused, whatever the name holds when the link is
  made (`fs.rs`, `allow_symlink_target`).
- With that check, in a session over a workspace whose `.git` and `node_modules` show `GIT~1` and
  `NODE_M~1`: `ln -s GIT~1 gitlink`, `ln -s NODE_M~1 nm` and `ln -s .git gitlink2` each fail, and
  `ln -s src srclink` succeeds.

## End-to-end coherency through the host share

### Verified: end-to-end coherency, FUSE backend stack (macOS 26.4.1, podman 6.0.2; 2026-08-22)

A coherency probe ran by hand, on the same machine and stack as the name-rule run. Its checks are
`--self-test`'s share rows (the launcher's `SelfTestShare.scala`).

- A write on the host became visible to a fresh `read()` inside the FUSE backend session within the
  10 ms polling window.
- A page **mapped before the write** showed the new bytes 0 ms after `read()` did:
  `AUTO_INVAL_DATA` invalidated the cached page as designed.
- The direction from sandbox to host holds on the same stack, and the rig suite tests it at the
  FUSE backend's own layer.

The virtiofs premise, as observed on the same machine:

- The host shares (`/Users`, `/private`, `/var/folders`; workspace roots are under the first) mount
  in the VM as `virtiofs (rw,relatime,context=system_u:object_r:nfs_t:s0)`.
- **No `cache=` option appears.** So the hypervisor (vfkit/applehv) decides the caching mode on the
  host side, and the guest cannot inspect it.
- The premise is therefore about behavior, not a declaration: the coherency result above, and the
  guest-layer measurement below.
- Rerun the measurement, the launcher's `--self-test` share rows, after a podman or macOS upgrade.
  The measurement notices a changed default; the mount table does not.
- The `nfs_t` SELinux context is also why the launcher never applies `:Z` relabeling to sources the
  machine shares.

### Verified: the same coherency, launcher-driven (same machine, libkrun, fc44 kernel; 2026-09-01)

`--self-test`'s own share rows (the launcher's `SelfTestShare.scala`) repeated the run above, with
the launcher writing as the host over a scratch lower in the workspace:

- the guard's refusal held through the whole stack;
- the host write was visible to `read()` 1 ms after it was written;
- the established mmap showed it 0 ms behind `read()`.

Every later rerun follows this procedure.

### Measured: the virtiofs layer itself (same machine; 2026-08-25)

Polled from inside the machine (`podman machine ssh`), below the FUSE mount, while the host wrote to
the share:

- A file's creation, its deletion, and an append each became visible within 30 ms, the resolution
  of the host's timestamp. For the append, the file's size was polled continuously, so the guest's
  attributes were hot.
- Resolving one more path component in the guest costs ~56 µs (2,000 `[ -e ]` of a depth-8 path
  against a depth-2 one). That is a hypervisor round trip. A hit in the dentry cache would take
  microseconds.
- So the guest kernel caches neither virtiofs names nor attributes for any time that matters.
- The speed of the plain bind mount, which the perf control measures, is the hypervisor
  answering fast.
- Coherency from host to session rests on the hypervisor's behavior alone. The FUSE backend's TTL 0
  is the only cache policy in the path.

### Measured: coherency on Windows — fresh when unheld; a hold refuses some writers (Server 24H2)

On a Windows host (podman 6.1.0, machine on WSL2, kernel 6.18.33.2-microsoft-standard-WSL2),
measured against what the host observed at every step:

- A file the host created, and a host rewrite of a file nothing held open, both reached a
  `read()` in the session promptly. 2026-08-19.
  - Visibility from host to session holds for files nothing holds open. Visibility from session to
    host held already (the NTFS name-rule run).
- A file a session holds open refuses some host writers and not others.
  - The daemon's backing fd reaches NTFS through the machine's 9p server, whose handle follows
    Windows sharing rules.
  - With `tail -f held.txt` in a FUSE backend session over `C:\work\tmp1` (2026-09-27):
    - PowerShell's `Set-Content` fails with "used by another process";
    - .NET's `[IO.File]::WriteAllText` and Notepad's save succeed, and the session's `tail -f`
      prints the new bytes;
    - Java's `Files.write`, the `--self-test` writer, succeeds against a read-only open with a
      read-only `mmap` of the same file.
- Below the FUSE mount, a bare 9p hold (`tail -f` in the machine) refused a host write, whose writer
  was not recorded. The write succeeded the moment the hold ended. 2026-08-19.

So a host write to a mapped file succeeds on Windows too.

- Whether the mapping shows the write is `--self-test`'s `mmap` row, which has not run there
  (`TODO.md`, "End-to-end coherency through the real host share").
- The lock costs co-editing with the writers it refuses. SECURITY.md ("The workspace") records
  this.

The Windows 8.3 short name `GIT~1` is in the empirical corpus to be *confirmed* rather than
assumed. It is not there as evidence of a gap in git: the 8.3 part of CVE-2014-9390 was
**Mercurial's**, not git's. The Windows Server 24H2 run met `EEXIST` creating `GIT~1`. "Verified:
NTFS 8.3 short names" has the creation, and the short names of an existing `.git` and
`.ko-agent-sandbox`.


## The cost of a path walk

### Measured: cost per operation and per component (macOS 26.4.1, podman 6.1.1; 2026-09-19)

`../../bench/walk-cost.py` ran from inside a FUSE backend session over this repository's tree, on an
arm64 Mac (container → FUSE → daemon → virtiofs), warm, 200 iterations per point. `lstat` of a
file by absolute path, by the file's depth under the mount:

    depth   1     2     3     4     5     6     7     8     9
    ms      0.64  1.24  2.00  2.73  3.62  4.60  5.92  7.12  8.11

One file at depth 11, three ways:

- by absolute path: 10.81 ms;
- by the same name relative to a `chdir` into its directory: 2.04 ms;
- through a directory fd: 1.95 ms.

The kernel walks one component in the last two. So the difference is the kernel asking the daemon
again for each component. The ~1.9 ms left is one FUSE operation, including the daemon's own
resolution of the full path.

### Measured: the FUSE backend's ratio over a bind mount (macOS 26.4.1, podman 6.1.1; 2026-09-19)

`../../bench/entry-cost.py`, 2,101 entries of 4 KB files, container → FUSE → daemon → virtiofs,
against the same corpus over a plain bind mount of the same directory
(`../../bench/plain-bind.sh`).

| operation                       | plain   | FUSE backend | ratio |
| ------------------------------- | ------- | ------------ | ----- |
| `find` (readdir only)           | 73 µs   | 419 µs       | 5.7×  |
| `find -printf` (readdir + stat) | 147 µs  | 1361 µs      | 9.3×  |
| `rm -rf`                        | 288 µs  | 2356 µs      | 8.2×  |
| `cp -r` (create + write)        | 1143 µs | 8819 µs      | 7.7×  |
| `ls -lR` (stat + xattr probes)  | 707 µs  | 12712 µs     | 18.0× |

The identity checks (`fs.rs`, `policy_name` and `open_ino`) are in these figures.

- Against a run of a FUSE backend without them on the same machine, the FUSE backend column is
  29–69 % higher.
- It is least higher where directory fds are held (`find`, +32 %), and most where every entry is
  resolved by path (`rm -rf`, +69 %; `ls -lR`, +63 %).
- This bounds the checks' cost. The two runs do not separate the checks from the daemon's other
  changes between them.

`find` batches reads per directory. `find -printf` needs about one lookup and one getattr round trip
per entry. `ls -lR` needs about 4–8 round trips, since each path-based syscall resolves every
component again.

The plain bind mount is fast because the hypervisor answers a guest lookup in ~56 µs, and the
guest caches nothing ("the virtiofs layer itself", above). So the ratio measures this layer's cost
alone.

### Measured: the same ratio on Windows (Server 2025 10.0.26100.32522, podman 6.1.0; 2026-09-19)

The same probe ran through the Windows production stack (container → FUSE → daemon in the WSL2
machine → the machine's drive mount of NTFS), on an EC2 m7i-flex.xlarge, against the same corpus
over a plain bind mount of the same directory (the command in `../../bench/plain-bind.ps1`):

| operation                       | plain    | FUSE backend | ratio |
| ------------------------------- | -------- | ------------ | ----- |
| `find` (readdir only)           | 674 µs   | 3989 µs      | 5.9×  |
| `find -printf` (readdir + stat) | 1720 µs  | 14454 µs     | 8.4×  |
| `rm -rf`                        | 1949 µs  | 23145 µs     | 11.9× |
| `cp -r` (create + write)        | 14694 µs | 78822 µs     | 5.4×  |
| `ls -lR` (stat + xattr probes)  | 3382 µs  | 102428 µs    | 30.3× |

- The share itself is 5–13× slower than the macOS machine's virtiofs, and the FUSE backend
  multiplies that: each of its round trips ends in lookups on that share.
- The ratios are within 1.5× of the macOS ones, except `ls -lR`, the workload with the most
  path-based syscalls per entry.
- The host is of a different class from the macOS rows' host. Compare the columns within this
  table, not across the two tables.

### Measured: a real tree (macOS 26.4.1, podman 6.1.1; 2026-09-19)

`../../bench/walk-cost.py` ran on the machine and stack of the depth table above, over a shallow
clone of sbt/sbt: 4,249 tracked files at mean depth 7.0 among 7,524 entries, warm:

| operation                              | per file      | total                                   |
| -------------------------------------- | ------------- | --------------------------------------- |
| `git status`                           | 16.8 ms       | 71.5 s (38.8 s, `--untracked-files=no`) |
| `lstat` of each tracked file, by path  | 5.97 ms       | 25.4 s                                  |
| the same files through a directory fd  | 1.56 ms       | 6.6 s                                   |
| `find . -type f`                       | 1.95 ms/entry | 14.7 s                                  |

- A depth-1 `lstat` costs 0.64 ms, of which the guest's own resolution is ~0.06 ms.
- Each further component adds one more LOOKUP round trip: ~0.9 ms up to depth 9 (the depth table
  above), and ~1.6 ms beyond it. In this tree, an `lstat` costs 8.38 ms at depth 9 and 18.04 ms at
  depth 15.
- The two `lstat` rows are two workloads, and the 3.8× between them is the whole cost of the path
  walk:
  - git stats every tracked file by its full path from the root, and pays for the depth;
  - `find` and the other `fts` walkers hold directory fds, and pay for depth 1.
- Claude Code runs `git status` at startup. On the host, the same command takes 0.13 s.
- The walk over untracked files is 32.7 s of the `git status` total: 4.3 ms per entry, where `find`
  pays 1.95 ms over the same entries.

`find . -type f` over the same tree at each layer:

- macOS: 0.19 s (0.025 ms per entry);
- the guest over virtiofs: 1.65 s (0.22 ms);
- the container through the FUSE backend: 14.7 s (1.95 ms). The FUSE backend is 89 % of the
  total.

### Measured: an sbt build, by where its output goes (macOS 26.4.1, podman 6.1.1; 2026-09-20)

`sbt 'testOnly *SandboxTextWidthTest'` on this repository, on the machine of the tables above:
sbt 2.0.8 compiling 35 main and 41 test sources from nothing, then running one suite of 10 tests.

| where sbt runs, and its `rootOutputDirectory`            | from nothing | rerun |
| -------------------------------------------------------- | ------------ | ----- |
| the host                                                 | 12 s         | 0 s   |
| the container, `target/out` through the FUSE backend     | 604 s        | —     |
| the container, `~/.cache/sbt-out` outside the FUSE mount | 28 s         | 21 s  |

- The 604 s run also downloaded its dependencies. The same run with the output outside the FUSE
  mount took 43 s with those downloads, and 28 s without them.
- The image sets the third row's directory
  (`container/ko-agent-sandbox/config/sbt/2/ko-sandbox-output.sbt`).
- The host rows compile and do not test: that host has no `wcwidth`, so the suite skips its 10
  tests.

Two measurements from inside a session explain why the output dominates:

- Throughput does not rise with client threads. `lstat` at depth 4 serves 328, 363 and 372
  operations a second from 1, 4 and 8 threads. So a parallel compiler shares one request stream
  (`fs.rs`, `mount_config`).
- A class file sits at depth 9, about 8 ms per path operation in the depth table above.

A rerun of the third row under `-Dsbt.task.timings=true`, with nothing to compile, took 23.7 s.
sbt reports two evaluations of the task graph for one `testOnly`, of 6.8 s and 16.7 s, and each
repeats the first two rows:

| what                                                              | total   |
| ----------------------------------------------------------------- | ------- |
| `managedResources`: `build.sbt` copies 64 files out of the mount  | 9.9 s   |
| listing, stamping and hashing sources and resources in the mount  | ~5.5 s  |
| the suite, which starts a Python script about 30 times            | 8.4 s   |

- The copy costs 77 ms a file.
- One run of the script costs 261 ms from the mount, and 177 ms from a copy outside it. So the
  FUSE backend's share of the suite is about a third, and Python's start is the rest.
- About 18 s of the 23.7 s is operations in the mount.
- The copy and the script runs issue their operations one after another, so threads in the daemon
  would not shorten their 12 s. A shorter path per operation would (`TODO.md`, "Performance").

### Measured: a gradle build, by where its output goes (macOS 26.4.1, podman 6.1.1; 2026-09-20)

A generated build in a session, under gradle 9.7.1 and Java 25:

- two `java-library` projects of 100 one-method classes each, a `buildSrc`, and an included build
  of one class each, with no dependencies to download;
- each row is `gradle build :included:build` on a fresh copy with no daemon running, after one
  discarded run that pays gradle's first-use setup.

| the build's files | `build/` | the project's `.gradle/` | time |
|---|---|---|---|
| in the mount | in the mount | in the mount | 75 s |
| in the mount | `~/.cache`, by an init script | in the mount | 44 s |
| in the mount | `~/.cache`, by an init script | `~/.cache`, by `--project-cache-dir` | 41 s |
| under `~` | under `~` | under `~` | 4.5 s |

- The init script sets `layout.buildDirectory` in `allprojects`, keyed by each project's absolute
  path, and reaches `buildSrc` and the included build. None of the four projects keeps a `build/`
  in the mount.
- Moving the output takes 31 s off.
- After the run that also uses `--project-cache-dir`, the mount holds only the 202 sources and 7
  build scripts. No `.gradle/` directory remains, including under `buildSrc` or the included build.
- That run still takes 36 s more than the build outside the mount. So for gradle, most of the extra
  build time remains after the persistent output moves outside the mount. For sbt, moving the output
  outside the mount removed most of the extra build time.
- What gradle spends its remaining time on is not measured: operations on the inputs, or files
  gradle creates in the mount and removes during the build.

### Measured: a Maven build, by where its output goes (macOS 26.4.1, podman 6.1.1; 2026-09-20)

The gradle entry's 202 classes as two Maven modules under a parent POM, in a session, under
Maven 3.9.16 and Java 25. Each row is `mvn -q -B package` on a fresh copy, with the plugins
already in `~/.m2`.

| the build's files | `target/` | time |
|---|---|---|
| in the mount | in the mount | 85 s |
| in the mount | in the mount, with `-Dproject.build.directory=<a path under ~/.cache>` | 81 s |
| in the mount | `~/.cache`, by `<build><directory>` in the parent POM | 47 s |
| under `~` | under `~` | 1.9 s |

- Maven ignores the property: each module keeps its `target/` in the workspace, and nothing appears
  at the path given.
- The POM's `<directory>`, keyed by `${project.artifactId}`, moves both modules' output, and no
  `target/` remains in the mount.
- That run still takes 45 s more than the build outside the mount. As with gradle, most of the
  extra build time remains after the persistent output moves outside the mount.
- What the remaining time is spent on is not measured.

### Measured: sbt over dangling cache links (macOS 26.4.1, podman 6.1.1, sbt 2.0.8; 2026-09-20)

The project: one source, sbt 2.0.8, with its output kept in the workspace.

- On the host: a build, then `rm -rf target project/target`, then a build again. The second build
  is a build-cache hit.
- It leaves 35 symlinks under `target/` into `~/Library/Caches/sbt/v2/cas`, the 5 class files among
  them. A build that compiles leaves class files as regular files.
- In a FUSE backend session, all 35 dangle.

`sbt package` there, with the image's `rootOutputDirectory` setting turned off
(`-Dsbt.global.base=<an empty directory>`, which also gives the run its own cache):

| sources   | the session's sbt cache | result                                                   |
| --------- | ----------------------- | -------------------------------------------------------- |
| unchanged | empty                   | exit 1, `error writing … .class: NoSuchFileException`    |
| unchanged | populated               | the same                                                 |
| changed   | populated               | the same                                                 |

- Each run leaves 16 of the 35 dangling.
- Afterwards the host compiles a changed source over what the session left, and succeeds. The
  FUSE backend refuses the session's own absolute links, so sbt left copies (`fs.rs`, `symlink`).

The failure is a write through a link whose target *directory* does not exist. Dangling links
planted by hand in a session show this:

- with targets in a directory that does not exist, the build fails in the same words;
- with targets beside the link, the build succeeds, and a file with the target's name appears
  there;
- on xfs, links into sbt's own store succeed once sbt has recreated that store's directory.

After `find … -type d -name target -exec find {} -xtype l -delete \;`, the failing build succeeds.

## What a staged lower can represent

### Measured: the staged lower on APFS (macOS 26.4.1, podman 6.0.2; 2026-08-22)

`probe/lower-probe.py` and its host half ran in a FUSE backend session over a workspace on
case-insensitive APFS (host Darwin 25.4.0 arm64, machine kernel 7.1.3-200.fc44.aarch64):

- **Hard-link identity does not survive the FUSE backend, and the FUSE backend alone is the
  reason.**
  - A pair the host made reads back through the mount as two inode numbers with `st_nlink` 2. A pair
    the session made reads on the host as one inode with `st_nlink` 2.
  - `to_file_attr` replies with the number `InodeTable` allocated per `(parent, name)`
    (`src/fs.rs`, `src/inode.rs`). So two names for one object are two inodes, by how the path
    inode model is built, under any share, not only this one.
  - The plain control run settles the cause rather than leaving it to the code. With the FUSE
    backend out of the path, the same pair the host made reads back as one inode, so virtiofs
    carries identity end to end.
  - The lower keeps the relationship, which is the half apply depends on.
- **Atomic exchange exists on both sides.** `RENAME_EXCHANGE` through the mount and
  `renamex_np(RENAME_SWAP)` on APFS both succeed. `RENAME_NOREPLACE` and `RENAME_EXCL` both refuse a
  name that is taken.
- **Symlinks round-trip in both directions**: created through the mount and resolved on the host,
  and the reverse.
- **Two names that differ only by case are one name**, through the mount and on the host alike. The
  default APFS volume folds case, so an upper entry and a lower entry cannot differ by case alone.
- **A descriptor held in the session blocks nothing on the host.** Write, rename and unlink all
  succeed against a held path, whether it is held for reading or for writing. Windows is where this
  matters.

FUSE backend and plain runs agree on every row but the first. So on this stack, the FUSE backend
costs nothing in exchange support, symlink round-tripping, case behavior or the reach of a hold.

## Extended attributes

### Measured: xattrs through the FUSE backend (podman machine, virtiofs over APFS; 2026-08-14)

`probe/xattr-probe.py` compared the FUSE backend session with a plain bind mount as the control:

| operation   | plain bind mount (control) | FUSE backend          |
| ----------- | -------------------------- | --------------------- |
| `setxattr`  | OK                         | `ENOTSUP`             |
| `listxattr` | OK                         | `ENOTSUP`             |
| `cp -a`     | exit 0, xattr kept         | exit 0, xattr dropped |

`cp -a` carries no attribute across and says nothing about it. coreutils reads `ENOTSUP` as "the
destination does not do xattrs", not as a failure.

## Mount privilege: what a container grants

### Measured: a container needs `CAP_SYS_ADMIN`, setuid notwithstanding (podman 6.0.2; 2026-08-22)

In a podman machine on macOS (machine kernel 7.1.3-200.fc44.aarch64, aarch64), dropping
`--cap-add SYS_ADMIN` from `probe/rig.sh` fails at the mount probe, before a test runs:

    Error: Custom { kind: Other, error: "fusermount3: mount failed: Operation not permitted\n" }

- The message names the helper. So the fallback was reached and refused, not skipped.
- A setuid-root binary does not escape the container's capability bounding set. `fusermount3`
  becomes uid 0 in the container's user namespace, and still cannot `mount(2)` without
  `CAP_SYS_ADMIN` in that namespace.
- The bounding set decides the result, not the setuid bit.

The rig's container ran inside the same machine the daemon mounts in. That holds the kernel
constant, and leaves the namespace as the only difference between the two results.

- In the machine, the daemon is an ordinary user in the initial namespace. There, the same setuid
  `fusermount3` reaches real root with a full bounding set.
- `--self-test` exercises that route at every install, on every platform.

### Measured: a non-root container user keeps the bounding set (podman 6.0.2; 2026-08-22)

`--self-test` mounts and passes every suite as the sandbox image's `nonroot` (uid 65532), in a
container given `--cap-add SYS_ADMIN`, in a podman machine on macOS.

- So podman keeps the capability in the *bounding* set for a container whose `USER` is not root,
  and the setuid `fusermount3` reaches it.
- An unprivileged uid holds no effective `CAP_SYS_ADMIN` and cannot `mount(2)`, and the mount
  succeeds anyway.

This container is therefore the only one that exercises the route a real session takes. The dev rig
runs as root, where `mount(2)` succeeds directly, and the helper is reached only at teardown.

### Measured: without `allow_other` no container starts (podman 6.1.2; 2026-10-06)

The machine: a podman machine on macOS (machine kernel 7.1.8-200.fc44.aarch64, libkrun, virtiofs
share).

- A FUSE backend built with fuser's `SessionACL::Owner` instead of `SessionACL::All` mounts, and
  passes every suite `--self-test` runs inside its container, where the daemon and the tests are one
  uid.
- The share probe's container, run with `--userns=keep-id:uid=65532,gid=65532`, fails before the
  probe starts:

      crun: cannot stat `self/fd/5`: Permission denied: OCI permission denied

- A session launched on the same FUSE backend fails with the same error, at `self/fd/16`.

The kernel refuses the stat:

- A mount without `allow_other` admits a process only when all its uids and gids are the mounting
  process's (`fs/fuse/dir.c`, `fuse_allow_current_process`).
- crun stats a bind's source after it sets its uid to the root of the container's user namespace
  (`src/libcrun/linux.c`, `set_id_init` and `do_mounts`). keep-id maps that root to a subordinate
  uid of the daemon's user.
