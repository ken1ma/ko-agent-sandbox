# Verification log

The measured runs the design's claims rest on, each with the venue that produced it. What a row is
meant to settle, why a pass without its venue is not evidence, and which rows are still open is
`TODO.md` ("Platform verification"); the external research the same claims draw on is
`security-research.md`.

## The `.git` name rule on real filesystems

### Verified: APFS case-insensitive (macOS 26.4.1, build 25E253; 2026-08-14)

The empirical run the posture calls for, on the default macOS volume (File System Personality:
APFS, the case-insensitive variant), through the full production stack — filtered sandbox session →
FUSE filter → virtiofs → APFS — using `probe/apfs-name-rule-probe.py`:

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

- The 8.3 row answered on a live table: short-name generation is active on the volume — creating
  `GIT~1` through the mount met `EEXIST`, an existing allowed name having already generated it as
  its short name — and host git still discovered no repository, which is the aliasing question
  confirmed rather than assumed.
- NTFS kept the NFC and NFD spellings of `.gít` as two files — normalization-sensitive where APFS
  collapsed them — and neither resolves anywhere near `.git` on either backing.

## End-to-end coherency through the host share

### Verified: end-to-end coherency, filtered stack (macOS 26.4.1, podman 6.0.2; 2026-08-22)

`probe/coherency-probe.py` on the same machine and stack as the name-rule run: a host-side write
became visible to a fresh `read()` inside the filtered session within the 10 ms polling window, and
a page **mapped before the write** showed the new bytes 0 ms after `read()` did — `AUTO_INVAL_DATA`
invalidating the cached page as designed. The sandbox→host direction holds on the same stack, and
is pinned at the filter's own layer by the rig suite.

The virtiofs premise, as observed on the same machine: the host shares (`/Users`, `/private`,
`/var/folders` — the first is the one project directories live under) mount in the VM as
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
it landed, and the established mmap showed it 0 ms behind `read()`. This is the form every
later re-run takes.

### Measured: the virtiofs layer itself (same machine; 2026-08-25)

Polled from inside the machine (`podman machine ssh`), below the filter, while the host wrote to
the share: a file's creation, its deletion, and — with its size polled continuously, so the guest's
attributes were hot — an append each became visible within 30 ms, the resolution of the host-side
timestamp. Resolving one further path component in the guest costs ~56 µs (2,000 `[ -e ]` of a
depth-8 path against a depth-2 one): a hypervisor round trip, not a dentry-cache hit, which would be
microseconds. The guest kernel therefore caches neither virtiofs names nor attributes at any window
that matters, and the raw-bind speed the perf control measures is the hypervisor answering fast.
Host→session coherency rests on the hypervisor's behavior alone; the filter's TTL 0 is the only
cache policy in the path.

### Measured: coherency on Windows — fresh when unheld, locked when held (Server 24H2; 2026-08-19)

On a Windows host (podman 6.1.0, machine on WSL2, kernel 6.18.33.2-microsoft-standard-WSL2),
measured with host-side ground truth at every step:

- A host-created file, and a host rewrite of a file nothing held open, both reached an in-session
  `read()` promptly — host→session visibility holds for unheld files, and session→host held
  already (the NTFS name-rule run).
- A host write to a file a live session held open failed with a sharing violation ("used by
  another process") until the session released it: the daemon's backing fd reaches NTFS through
  the machine's 9p server, whose handle carries Windows sharing semantics. Isolated below the
  filter: a bare 9p hold (`tail -f` in the machine, no session involved) reproduces the refusal,
  and the write succeeds the moment the hold ends.

Together they close the mmap question by construction: a mapped file cannot go stale under a host
write, because the write is refused while the mapping holds — the coherency measurement's mmap
half therefore cannot and need not run there. What the lock costs is co-editing, and SECURITY.md
("The project directory") carries it: a host editor's save is refused while a session holds that
file open.

The Windows 8.3 short name `GIT~1` is in the empirical corpus to be *confirmed* rather than assumed,
not because it is evidence of a git-side gap: the 8.3 leg of CVE-2014-9390 was **Mercurial's**, not
git's, and an 8.3 short name should not be able to alias a dot-leading name like `.git` — which the
NTFS run above confirmed on a volume with generation active.


## The cost of a path walk

### Measured: per-operation and per-component cost through the filter (same machine; 2026-08-25)

From inside a session over this repository's tree (3,856 entries), warm, 200 iterations per point.
`lstat` of a file by absolute path, by the file's depth under the mount:

    depth   1     2     3     4     5     6     7     8
    ms      0.44  0.74  1.16  1.67  2.36  3.10  3.82  5.05

One file at depth 9, three ways: absolute path 8.07 ms; the same name relative to a `chdir` into
its directory 1.74 ms; through a directory fd 1.67 ms. The kernel walks one component in the
latter two, so the difference is the kernel re-asking the daemon per component, and the ~1.7 ms
left is one FUSE operation including the daemon's own full-path resolution.

`find . -type f` over the same tree at each layer: macOS 0.14 s (0.036 ms per entry), the guest
over virtiofs 0.98 s (0.25 ms), the container through the filter 8.1 s (2.1 ms) — the filter is
88 % of the total. The 8,858-entry tree of `TODO.md`'s real-tree table gives 0.24 s / 1.63 s /
12.2 s, 87 %.

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

## Mount privilege: what a venue grants

### Measured: a container needs `CAP_SYS_ADMIN`, setuid notwithstanding (podman 6.0.2; 2026-08-22)

In a podman machine on macOS (machine kernel 7.1.3-200.fc44.aarch64, aarch64), dropping
`--cap-add SYS_ADMIN` from `probe/rig.sh` fails at the venue probe, before a test runs:

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

This venue is therefore the only one that exercises the route a real session takes. The dev rig runs
as root, where `mount(2)` succeeds directly and the helper is reached only at teardown.
