# Verification log

The measured runs the design's claims rest on, each with the machine that produced it. What a row is
meant to settle, why a pass without its machine is not evidence, and which rows are still open is
`TODO.md` ("Platform verification"); the external research the same claims draw on is
`security-research.md`.

## The `.git` name rule on real filesystems

### Verified: APFS case-insensitive (macOS 26.4.1, build 25E253; 2026-08-14)

The empirical run `security-research.md` calls for, on the default macOS volume (File System
Personality: APFS, the case-insensitive variant), through the full production stack — filtered
sandbox session → FUSE filter → virtiofs → APFS — using `probe/apfs-name-rule-probe.py`:

- All 14 denied spellings (`.git` itself, the four ASCII case variants, the Turkish i-family, the
  four ignorable-code-point forms, the three trailing-punctuation forms) failed with exactly
  `EPERM`.
- All six allowed names were created, and afterwards the host's `lstat(".git")` found nothing and
  `git status` discovered no repository — the property itself, on the real fold table.
- Bonus observation: the NFC and NFD spellings of `.gít` collapsed to **one** file — APFS's
  normalization-insensitivity seen live through the whole stack, confirming both halves of the
  normalization finding in `security-research.md` ("Real-filesystem case-folding"): the filesystem
  really does treat the forms as one name, and neither resolves anywhere near `.git`.

Fold tables are OS-version-specific, so this verifies **this** release against macOS 26.4.1;
re-run the probe when either side moves.

### Verified: APFS case-sensitive (macOS 26.4.1, build 25E253; 2026-08-18)

The same corpus on the case-sensitive variant, through the same production stack, against a
case-sensitive sparse-image volume mounted under `$HOME` — `probe/name-rule-cs-apfs.sh` drives
the whole run, host-side checks included:

- All 14 denied spellings failed with exactly `EPERM`, and all six allowed names were created.
- Afterwards the host-side `lstat(".git")` found nothing and git discovered no repository at the
  project — the property itself, on this variant's fold table.

### Verified: NTFS (Windows Server 24H2; 2026-08-19)

The corpus through the full Windows production stack — filtered session → FUSE filter in the WSL2
podman machine → the host's `C:` NTFS volume served at `/mnt/c`: every denied spelling failed with
exactly `EPERM`, every allowed name was created, and the host-side `dir .git` and git discovery
found nothing afterwards.

- The 8.3 row met `EEXIST`: short-name generation is active on the volume, and an existing
  allowed name had already been given `GIT~1` as its short name, so nothing was created and the
  row answers nothing about what a created `GIT~1` would become ("Verified: NTFS 8.3 short
  names", below, does). Host git discovered no repository afterwards.
- NTFS kept the NFC and NFD spellings of `.gít` as two files — normalization-sensitive where APFS
  collapsed them — and neither resolves anywhere near `.git` on either backing.

### Measured: two letters APFS resolves to `.ko-agent-sandbox`'s (macOS 26.4.1; 2026-09-19)

On the case-insensitive project volume, beside an existing `.ko-agent-sandbox`, the spellings
`.<U+212A>o-agent-sandbox` (KELVIN SIGN) and `.ko-agent-<U+017F>andbox` (LONG S) resolve to it
(`src/probe/seatbelt-semantics.sh` E11, the launcher's probe). Through a filtered session whose
filter folds neither letter, `mkdir` of each spelling succeeds and `.ko-agent-sandbox` then
resolves to the new directory, while `.KO-AGENT-SANDBOX` meets `EPERM`.

### Verified: the `.ko-agent-sandbox` rows, APFS case-insensitive (macOS 26.4.1; 2026-09-19)

`probe/apfs-name-rule-probe.py` through the production stack — filtered session → FUSE filter →
virtiofs → APFS — in a subdirectory of a project, the rule holding at any depth:

- All 21 denied spellings failed with exactly `EPERM`: the 14 `.git` rows, and
  `.ko-agent-sandbox` itself, its two ASCII case variants, the KELVIN SIGN and LONG S spellings,
  the soft-hyphen form and the trailing dot.
- All seven allowed names were created, `.ko-agent-sandbox-notes` among them, and afterwards the
  host's `ls .git` and `ls .ko-agent-sandbox` found nothing there and git discovered only the
  enclosing project's repository.
- The mounted suite's rows for both letters pass (`--self-test`, `probe/rig.sh`).

### Verified: the `.ko-agent-sandbox` rows, NTFS (Windows Server 2025, 10.0.26100.32522; 2026-09-19)

The same probe through the Windows production stack — filtered session → FUSE filter in the WSL2
podman machine → the host's `C:` NTFS volume served at `/mnt/c`, podman 6.1.0:

- All 21 denied spellings failed with exactly `EPERM`, and all seven allowed names were created.
- Afterwards the host's `dir /a .git` and `dir /a .ko-agent-sandbox` found nothing, and
  `git rev-parse --git-dir` found no repository.
- NTFS kept the NFC and NFD spellings of `.gít` as two files, as in the `.git` run above.
- Whether NTFS resolves the KELVIN SIGN or LONG S spelling to the name is not measured: the filter
  refuses both, so neither reached the volume.

### Verified: NTFS 8.3 short names (Windows Server 2025, podman 6.1.0; 2026-09-19)

On a `C:` volume with 8.3 name generation on (`fsutil 8dot3name query C:`), a scratch project
whose `.git` (`git init`) and `.ko-agent-sandbox/egress/rule` the host created shows, in
`cmd /c dir /x /a`, the short names `GIT~1` and `KO-AGE~1`.

The WSL drive mount resolves a short name to the entry and gives it the long name's identity: in
the podman machine, `stat -c '%d:%i'` at `/mnt/c/<project>` prints one pair for `.git` and
`GIT~1` (`69:5910974511087336`), one for `.ko-agent-sandbox` and `KO-AGE~1`, and one for
`.git/config` and `GIT~1/config`. 1000 `stat` processes over `.git` and `.ko-agent-sandbox` took
6.7 s where both exist and 2.6 s in a directory with neither.

Inside a filtered session over that project (`security-research.md`, "Windows 8.3 short names",
has the check):

- `echo x >> GIT~1/config`, `echo x >> KO-AGE~1/egress/rule` and
  `echo y > KO-AGE~1/egress/planted` each fail with `Operation not permitted`;
- `mv GIT~1 moved` and `mv KO-AGE~1 moved2` fail with `Operation not permitted`;
- `ls GIT~1` succeeds: reads through the short name work, as they do through `.git`;
- `echo one > scratch-file; echo two >> scratch-file; cat scratch-file` prints both lines: a
  create through the backing `O_EXCL` (`fs.rs`, `create`) and a reopen of the file it made. The
  run holds no host create between a lookup and the backing open, so it does not reach the
  `ESTALE` retry; `tests/mounted_races.rs` does, on the rig's kernel.
- Afterwards the host's `Get-Content` shows `.git\config` and `egress\rule` as the host wrote
  them, and `cmd /c dir /x /a .ko-agent-sandbox\egress` lists `rule` alone.

The create side, in a filtered session over a new, empty project: `mkdir GIT~1` exits 0, and the
host's `cmd /c dir /x /a` afterwards lists one directory, long name `GIT~1`, no short name, and
no `.git`.

## End-to-end coherency through the host share

### Verified: end-to-end coherency, filtered stack (macOS 26.4.1, podman 6.0.2; 2026-08-22)

`probe/coherency-probe.py` on the same machine and stack as the name-rule run: a host-side write
became visible to a fresh `read()` inside the filtered session within the 10 ms polling window, and
a page **mapped before the write** showed the new bytes 0 ms after `read()` did — `AUTO_INVAL_DATA`
invalidating the cached page as designed. The sandbox→host direction holds on the same stack, and
is tested at the filter's own layer by the rig suite.

The virtiofs premise, as observed on the same machine: the host shares (`/Users`, `/private`,
`/var/folders` — the first is the one project directories are under) mount in the VM as
`virtiofs (rw,relatime,context=system_u:object_r:nfs_t:s0)` — **no `cache=` option appears**, so
the caching mode is decided host-side by the hypervisor (vfkit/applehv) and is not introspectable
from the guest. The premise is therefore behavioral, not declarative: the coherency result above,
and the guest-layer measurement below. Re-run the measurement — the launcher's `--self-test` share
rows — after a podman or macOS upgrade: it, not the mount table, is what notices a changed
default. (The `nfs_t` SELinux context is also why the launcher never applies `:Z` relabeling to
machine-shared sources.)

### Verified: the same coherency, launcher-driven (same machine, libkrun, fc44 kernel; 2026-09-01)

The run above repeated by `--self-test`'s own share rows (the launcher's `SelfTestShare.scala`),
with the launcher playing the host writer over a scratch lower in the project directory: the
guard's refusal held through the whole stack, the host write was visible to `read()` 1 ms after
it was written, and the established mmap showed it 0 ms behind `read()`. Every later re-run
follows this procedure.

### Measured: the virtiofs layer itself (same machine; 2026-08-25)

Polled from inside the machine (`podman machine ssh`), below the filter, while the host wrote to the
share: a file's creation, its deletion, and — with its size polled continuously, so the guest's
attributes were hot — an append each became visible within 30 ms, the resolution of the host-side
timestamp. Resolving one further path component in the guest costs ~56 µs (2,000 `[ -e ]` of a
depth-8 path against a depth-2 one): a hypervisor round trip, not a dentry-cache hit, which would be
microseconds. The guest kernel therefore caches neither virtiofs names nor attributes at any window
that matters, and the unfiltered bind mount speed the perf control measures is the hypervisor
answering fast. Host→session coherency rests on the hypervisor's behavior alone; the filter's TTL 0
is the only cache policy in the path.

### Measured: coherency on Windows — fresh when unheld, locked when held (Server 24H2; 2026-08-19)

On a Windows host (podman 6.1.0, machine on WSL2, kernel 6.18.33.2-microsoft-standard-WSL2),
measured against host-side observations at every step:

- A host-created file, and a host rewrite of a file nothing held open, both reached an in-session
  `read()` promptly — host→session visibility holds for unheld files, and session→host held
  already (the NTFS name-rule run).
- A host write to a file a live session held open failed with a sharing violation ("used by
  another process") until the session released it: the daemon's backing fd reaches NTFS through
  the machine's 9p server, whose handle follows Windows sharing rules. Isolated below the
  filter: a bare 9p hold (`tail -f` in the machine, no session involved) reproduces the refusal,
  and the write succeeds the moment the hold ends.

Together they close the mmap question by construction: a mapped file cannot go stale under a host
write, because the write is refused while the mapping holds — the coherency measurement's mmap
half therefore cannot and need not run there. What the lock costs is co-editing, and SECURITY.md
("The project directory") records it: a host editor's save is refused while a session holds that
file open.

The Windows 8.3 short name `GIT~1` is in the empirical corpus to be *confirmed* rather than assumed,
not because it is evidence of a git-side gap: the 8.3 leg of CVE-2014-9390 was **Mercurial's**, not
git's. The Windows Server 24H2 run met `EEXIST` creating `GIT~1`; "Verified: NTFS 8.3 short
names" has the creation, and the short names of an existing `.git` and `.ko-agent-sandbox`.


## The cost of a path walk

### Measured: cost per operation and per component (macOS 26.4.1, podman 6.1.1; 2026-09-19)

`probe/walk-probe.py`, from inside a filtered session over this repository's tree on an arm64 Mac
(container → FUSE → daemon → virtiofs), warm, 200 iterations per point. `lstat` of a file by
absolute path, by the file's depth under the mount:

    depth   1     2     3     4     5     6     7     8     9
    ms      0.64  1.24  2.00  2.73  3.62  4.60  5.92  7.12  8.11

One file at depth 11, three ways: absolute path 10.81 ms; the same name relative to a `chdir`
into its directory 2.04 ms; through a directory fd 1.95 ms. The kernel walks one component in the
latter two, so the difference is the kernel re-asking the daemon per component, and the ~1.9 ms
left is one FUSE operation including the daemon's own full-path resolution.

### Measured: the filter's ratio over a bind mount (macOS 26.4.1, podman 6.1.1; 2026-09-19)

`probe/perf-probe.py`, 2,101 entries of 4 KB files, container → FUSE → daemon → virtiofs, against
the same corpus over an unfiltered bind mount of the same directory (`probe/unfiltered.sh`).

| operation                       | unfiltered | filtered | ratio |
| ------------------------------- | ---------- | -------- | ----- |
| `find` (readdir only)           | 73 µs      | 419 µs   | 5.7×  |
| `find -printf` (readdir + stat) | 147 µs     | 1361 µs  | 9.3×  |
| `rm -rf`                        | 288 µs     | 2356 µs  | 8.2×  |
| `cp -r` (create + write)        | 1143 µs    | 8819 µs  | 7.7×  |
| `ls -lR` (stat + xattr probes)  | 707 µs     | 12712 µs | 18.0× |

The identity checks (`fs.rs`, `policy_name` and `open_ino`) are in these figures. Against a run
of a filter without them on the same machine, the filtered column is 29–69 % higher — least where
directory fds are held (`find`, +32 %), most where every entry is resolved by path (`rm -rf`,
+69 %; `ls -lR`, +63 %) — which bounds their cost: the two runs do not separate the checks from
the daemon's other changes between them.

`find` batches reads per directory; `find -printf` needs about one lookup and one getattr round
trip per entry. `ls -lR` needs about 4–8 round trips: each path-based syscall re-resolves every
component.

The unfiltered bind mount is fast because the hypervisor answers a guest lookup in ~56 µs and the
guest caches nothing ("the virtiofs layer itself", above), so what the ratio measures is this
layer's cost alone.

### Measured: the filter's ratio on Windows (Server 2025 10.0.26100.32522, podman 6.1.0; 2026-09-19)

The same probe through the Windows production stack — container → FUSE → daemon in the WSL2
machine → the machine's drive mount of NTFS — on an EC2 m7i-flex.xlarge, against the same corpus
over an unfiltered bind mount of the same directory (the command in `probe/unfiltered.ps1`):

| operation                       | unfiltered | filtered  | ratio |
| ------------------------------- | ---------- | --------- | ----- |
| `find` (readdir only)           | 674 µs     | 3989 µs   | 5.9×  |
| `find -printf` (readdir + stat) | 1720 µs    | 14454 µs  | 8.4×  |
| `rm -rf`                        | 1949 µs    | 23145 µs  | 11.9× |
| `cp -r` (create + write)        | 14694 µs   | 78822 µs  | 5.4×  |
| `ls -lR` (stat + xattr probes)  | 3382 µs    | 102428 µs | 30.3× |

The share itself is 5–13× slower than the macOS machine's virtiofs, and the filter multiplies it:
each of its round trips ends in lookups on that share. The ratios are within 1.5× of the macOS ones
except `ls -lR`, the workload with the most path-based syscalls per entry. The host is of a
different class from the macOS rows': compare the columns within this table, not across the two.

### Measured: a real tree (macOS 26.4.1, podman 6.1.1; 2026-09-19)

`probe/walk-probe.py` on the machine and stack of the depth table above, over a shallow clone of
sbt/sbt: 4,249 tracked files at mean depth 7.0 among 7,524 entries, warm:

| operation                              | per file      | total                                   |
| -------------------------------------- | ------------- | --------------------------------------- |
| `git status`                           | 16.8 ms       | 71.5 s (38.8 s, `--untracked-files=no`) |
| `lstat` of each tracked file, by path  | 5.97 ms       | 25.4 s                                  |
| the same files through a directory fd  | 1.56 ms       | 6.6 s                                   |
| `find . -type f`                       | 1.95 ms/entry | 14.7 s                                  |

A depth-1 `lstat` costs 0.64 ms, of which the guest's own resolution is ~0.06 ms; each further
component adds one more LOOKUP round trip, ~0.9 ms to depth 9 (the depth table above) and ~1.6 ms
beyond it: this tree's `lstat` costs 8.38 ms at depth 9 and 18.04 ms at depth 15. The two `lstat`
rows are two workloads — git stats every tracked file by its full path from the root and pays the
depth, `find` and the other `fts` walkers hold directory fds and pay depth 1 — and the 3.8×
between them is the whole path-walk term. Claude Code runs `git status` at startup; on the host
the same command takes 0.13 s. The untracked walk is 32.7 s of it, 4.3 ms per entry where `find`
pays 1.95 ms over the same entries.

`find . -type f` over the same tree at each layer: macOS 0.19 s (0.025 ms per entry), the guest
over virtiofs 1.65 s (0.22 ms), the container through the filter 14.7 s (1.95 ms) — the filter is
89 % of the total.

### Measured: an sbt build, by where its output goes (macOS 26.4.1, podman 6.1.1; 2026-09-20)

`sbt 'testOnly *SandboxTextWidthTest'` on this repository — sbt 2.0.8 compiling 35 main and 41
test sources from nothing, then one suite of 10 tests — on the machine of the tables above:

| where sbt runs, and its `rootOutputDirectory`            | from nothing | rerun |
| -------------------------------------------------------- | ------------ | ----- |
| the host                                                 | 12 s         | 0 s   |
| the container, `target/out` through the filter           | 604 s        | —     |
| the container, `~/.cache/sbt-out` outside the filter     | 28 s         | 21 s  |

The 604 s run also downloaded its dependencies; the same run with the output outside the filter
took 43 s with those downloads and 28 s without. The image sets the third row's directory
(`container/ko-agent-sandbox/config/sbt/2/ko-sandbox-output.sbt`). The host rows compile and do
not test: that host has no `wcwidth`, so the suite skips its 10 tests.

Two measurements from inside a session say why the output dominates. Throughput does not rise
with client threads — `lstat` at depth 4 serves 328, 363 and 372 operations a second from 1, 4
and 8 threads — so a parallel compiler shares one request stream (`fs.rs`, `mount_config`). And a
class file sits at depth 9, about 8 ms per path operation in the depth table above.

A rerun of the third row under `-Dsbt.task.timings=true`, nothing to compile: 23.7 s. sbt reports
two evaluations of the task graph for one `testOnly`, 6.8 s and 16.7 s, and each repeats the
first two rows:

| what                                                              | total   |
| ----------------------------------------------------------------- | ------- |
| `managedResources`: `build.sbt` copies 64 files out of the mount  | 9.9 s   |
| listing, stamping and hashing sources and resources in the mount  | ~5.5 s  |
| the suite, which starts a Python script about 30 times            | 8.4 s   |

The copy costs 77 ms a file. One run of the script costs 261 ms from the mount and 177 ms from a
copy outside it, so the filter's share of the suite is about a third and Python's start is the
rest. About 18 s of the 23.7 s is operations in the mount. The copy and the script runs issue
theirs one after another, so threads in the daemon would not shorten their 12 s; a shorter
per-operation path would (`TODO.md`, "Performance").

### Measured: sbt over dangling cache links (macOS 26.4.1, podman 6.1.1, sbt 2.0.8; 2026-09-20)

A one-source sbt 2.0.8 project that keeps its output in the project. On the host, a build, then
`rm -rf target project/target`, then a build again: the second is a build-cache hit, and it leaves
35 symlinks under `target/` into `~/Library/Caches/sbt/v2/cas`, the 5 class files among them; a
build that compiles leaves class files as regular files. In a filtered session all 35 dangle.
`sbt package` there, with the image's `rootOutputDirectory` setting turned off
(`-Dsbt.global.base=<an empty directory>`, which also gives the run its own cache):

| sources   | the session's sbt cache | result                                                   |
| --------- | ----------------------- | -------------------------------------------------------- |
| unchanged | empty                   | exit 1, `error writing … .class: NoSuchFileException`    |
| unchanged | populated               | the same                                                 |
| changed   | populated               | the same                                                 |

Each run leaves 16 of the 35 dangling. Afterwards the host compiles a changed source over what
the session left and succeeds: the filter refuses the session's own absolute links, so sbt left
copies (`fs.rs`, `symlink`).

The failure is a write through a link whose target *directory* is absent. Planting dangling links
by hand in a session: with targets in a directory that does not exist, the build fails in the
same words; with targets beside the link, it succeeds and a file of the target's name appears
there; and on xfs, links into sbt's own store succeed once sbt has recreated that store's
directory. After `find … -type d -name target -exec find {} -xtype l -delete \;` the failing
build succeeds.

## What a staged lower can represent

### Measured: the staged lower on APFS (macOS 26.4.1, podman 6.0.2; 2026-08-22)

`probe/lower-probe.py` and its host half, in a filtered session over a case-insensitive APFS project
directory (host Darwin 25.4.0 arm64, machine kernel 7.1.3-200.fc44.aarch64):

- **Hardlink identity does not survive the filter, and the filter is the whole of why.** A
  host-made pair reads back through the mount as two inode numbers with `st_nlink` 2, while a
  session-made pair reads on the host as one inode with `st_nlink` 2. `to_file_attr` replies with
  the number `InodeTable` allocated per `(parent, name)` (`src/fs.rs`, `src/inode.rs`), so two names
  for one object are two inodes by construction of the path inode model — under any share, not this
  one. The unfiltered control settles the attribution rather than leaving it to the code: with the
  filter out of the path the same host-made pair reads back as one inode, so virtiofs carries
  identity end to end. The lower keeps the relationship, which is the half apply depends on.
- **Atomic exchange exists on both sides.** `RENAME_EXCHANGE` through the mount and
  `renamex_np(RENAME_SWAP)` on APFS both succeed, and `RENAME_NOREPLACE` and `RENAME_EXCL` both
  refuse a taken name.
- **Symlinks round-trip in both directions**, created through the mount and resolved on the host,
  and the reverse.
- **Two names differing only by case are one name**, through the mount and on the host alike: the
  default APFS volume folds, so an upper entry and a lower entry cannot differ by case alone.
- **A descriptor held in the session blocks nothing on the host.** Write, rename and unlink all
  succeed against a held path, read-held and write-held alike. Windows is where this matters.

Filtered and unfiltered runs agree on every row but the first, so on this stack the filter costs
nothing in exchange support, symlink round-tripping, case behavior or the reach of a hold.

## Extended attributes

### Measured: xattrs through the filter (podman machine, virtiofs over APFS; 2026-08-14)

`probe/xattr-probe.py`, comparing the filtered session with an unfiltered bind mount as the control:

| operation   | unfiltered bind mount (control) | filtered              |
| ----------- | ------------------------------- | --------------------- |
| `setxattr`  | OK                              | `ENOTSUP`             |
| `listxattr` | OK                              | `ENOTSUP`             |
| `cp -a`     | exit 0, xattr kept              | exit 0, xattr dropped |

`cp -a` carries no attribute across and says nothing about it, because coreutils reads `ENOTSUP` as
"the destination does not do xattrs" rather than as a failure.

## Mount privilege: what a container grants

### Measured: a container needs `CAP_SYS_ADMIN`, setuid notwithstanding (podman 6.0.2; 2026-08-22)

In a podman machine on macOS (machine kernel 7.1.3-200.fc44.aarch64, aarch64), dropping
`--cap-add SYS_ADMIN` from `probe/rig.sh` fails at the mount probe, before a test runs:

    Error: Custom { kind: Other, error: "fusermount3: mount failed: Operation not permitted\n" }

The message names the helper, so the fallback was reached and refused rather than never tried. A
setuid-root binary does not escape the container's capability bounding set: `fusermount3` becomes
uid 0 in the container's user namespace and still cannot `mount(2)` without `CAP_SYS_ADMIN` in that
namespace. The bounding set is the variable, not the setuid bit.

The rig's container ran inside the very machine the daemon mounts in, which holds the kernel
constant and leaves the namespace as the only difference between the two results. In the machine the
daemon is an ordinary user in the initial namespace, where that same setuid `fusermount3` reaches
real root with a full bounding set — what `--self-test` exercises at every install, on every
platform.

### Measured: a non-root container user keeps the bounding set (podman 6.0.2; 2026-08-22)

`--self-test` mounts and passes every suite as the sandbox image's `nonroot` (uid 65532), in a
container given `--cap-add SYS_ADMIN`, in a podman machine on macOS. So podman keeps the capability
in the *bounding* set for a container whose `USER` is not root, and the setuid `fusermount3` reaches
it: an unprivileged uid holds no effective `CAP_SYS_ADMIN` and cannot `mount(2)`, and the mount
succeeds anyway.

This container is therefore the only one that exercises the route a real session takes. The dev
rig runs as root, where `mount(2)` succeeds directly and the helper is reached only at teardown.
