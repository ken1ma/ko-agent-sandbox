# TODO

What `ko-agent-fs` still needs, ordered by what separates it from a first release anyone should
trust. The open security gap comes first.

- Items under **P1 — platform verification** *cannot* be settled by reasoning at all. Only the
  backing filesystem answers them, and until a row runs, the claim it would confirm is an
  assumption.
- Which machine settles a row depends on the backing: the dev rig already reaches ext4 and the two
  Linux architectures; APFS and NTFS need a real macOS or Windows host.
- Everything below them is ordinary work.

Decisions that research has already closed are in **Non-TODOs**, so they stop coming back.


## P1 — A second name arriving during a name-based mutation (open)

`rename`, `unlink` and `rmdir` act on the name the policy decided about. A concurrent host change
can put a second name of a guarded entry there first (`../../policy/doc/security-research.md`,
"Windows 8.3 short names"; `SECURITY.md` states the exception to its claims).

- [ ] A deterministic reproducer, with its outcome recorded. It places the host's change between
  `allow_child` or `allow_create` and the backing syscall:
  - for a rename source, a rename destination, a `RENAME_EXCHANGE` operand and a removal;
  - with a hard link, and with an NTFS short name.
- [ ] A design in which the decision holds through the mutation. Candidates, none examined yet:
  - a backing-name resolution that cannot select a second name of a guarded entry;
  - enforcement inside the backing filesystem;
  - coordination that covers every writer of the backing tree, which a lock in the daemon does
    not;
  - refusing `--workspace=live` where second names can arise.

  What does not qualify, and what else needs it:
  - A scan at launch does not qualify: the host can create a second name mid-session.
  - Turning 8.3 name generation off leaves the existing short names (`fsutil 8dot3name strip`
    removes those).
  - Staged mode keeps session mutations off the host tree. Its apply step needs the same protection
    against a concurrent replacement.
- [ ] `a_create_never_reopens_a_guarded_entry_that_arrives_under_a_second_name`
  (`tests/mounted_races.rs`) failed in two of three `--self-test` runs on Windows Server 24H2
  (x86_64, WSL2 kernel 6.18.33.2; 2026-09-27), the second at `ac405d2`: "SECURITY: a create opened
  the host's pointer file".
  - It passed in the first run, and on the macOS rig.
  - A failed suite ends `--self-test` before its share rows, so Windows's `mmap` row waits on this
    item.
  - Unverified cause: an entry's identity is `(st_dev, st_ino)` (`fs.rs`, `identity`), and
    `lookup` reads the entry and its guarded siblings in separate `fstatat` calls (`policy_name`).
    One inode-number reuse suffices, in this interleaving:
    1. `lookup`'s `fstatat` of `GIT~1` finds the host's link, inode Y. The host removes `GIT~1`
       and `.git`. `policy_name`'s `fstatat` of `.git` finds nothing, so the node is recorded as
       ordinary with identity Y.
    2. The host writes `.git` again, which gets inode Y back, and links `GIT~1`. The kernel's
       `OPEN` for the ordinary node opens that name, `open_ino_compared` finds Y equal to Y, and
       the pointer file is open for writing.

    The test's backing is the container's temporary directory, where a freed number returns at
    once. Why the macOS rig passes is unmeasured.
  - Next steps:
    - the failure rate, from repeated `--self-test a_create_never_reopens` and
      `probe/rig.sh a_create_never_reopens`;
    - the test records the inode number of every `.git` the host writes and of every `GIT~1` the
      sandbox creates, in shared state that the failing assertion's message prints. A failure
      without a repeated `.git` number refutes the interleaving above; a failure with one supports
      it; a pass shows nothing. The identity the daemon recorded is not visible to the test; a
      debug build that logs it is the step after an inconclusive record;
    - a check that holds whatever the identity's strength, written up before it changes the core:
      `open_ino_compared` compares the opened descriptor's identity with the parent's guarded
      siblings, as `policy_name` does, and answers `ESTALE` on a match, so the kernel's re-walk
      records the guarded context and `allow_ino` refuses the write. The open descriptor pins its
      inode, so no later `.git` takes the number during the check. It costs the two `fstatat`
      calls `lookup` pays, for nodes recorded as ordinary under a parent outside git metadata, and
      covers `open`, `setattr` and `link`, not the name-based `rename`, `unlink` and `rmdir` above.
      - Its window: the host removes `GIT~1` and `.git` after the backing open and before the
        comparison. No sibling matches, and the descriptor still holds the pointer file, which the
        test's read then detects. The descriptor's `st_nlink` is 0 at that point, so answering
        `ESTALE` to a descriptor without a name closes the window as far as the test's host goes:
        that host never leaves the pointer file a name other than `.git` and `GIT~1`. A host that
        renames `.git` to an ordinary name has made the entry ordinary. Reasoned from `fs.rs` and
        `tests/mounted_races.rs`, not run;
    - a stronger identity (change or birth time beside the number), the alternative.

## P1 — Platform verification (needs real filesystems)

Record every run in `verification-log.md` with the machine that produced it: OS, podman, kernel
and filesystem versions.

- A pass with no machine recorded is not evidence for the next release.
- Only running again notices a platform default changing underneath a row.

### The `.git` name rule per backing filesystem

The deciding question is not "what do our name-matching rules cover", but the property itself:

> After the sandbox creates a name `N` through the mount, does host `git` — `lstat("<dir>/.git")`
> on the real backing filesystem — find a repository?

Reasoning cannot settle this:

- The fold tables are per volume on NTFS, and tied to a Unicode version on APFS
  (`../../policy/doc/git-metadata.md`, "The name rule").
- Reasoning limits the candidate list. Only the filesystem settles it.
- `probe/apfs-name-rule-probe.py` creates each candidate *through the mount*, inside a FUSE backend
  session. Its header has the host-side checks, run by hand or by `probe/name-rule-cs-apfs.sh`, and
  the cleanup.

The corpus:

- `.git` itself (the base case must be refused).
- Case variants: `.GIT`, `.Git`, `.gIt`, `.giT`.
- Turkish i-family: `.gıt` (U+0131), `.gİt` (U+0130).
- Ignorable code points: `.gi<U+200C>t`, `.g<U+200B>it`, `<U+FEFF>.git`, `.git<U+00AD>`,
  `.gi<U+200E>t`, `.g<U+202E>it`, `.git<U+206F>`.
- Trailing punctuation: `.git.`, `.git ` (space), `.git. `.
- A Windows 8.3 short name, `GIT~1`, on NTFS: creating it where no `.git` exists must not make one.
  - The short names that an existing `.git` and `.ko-agent-sandbox` have, `GIT~1` and `KO-AGE~1`,
    are rows of their own, run by hand.
  - A write, a create and a rename through them must fail with `EPERM`, and the host's files must
    be unchanged afterwards.
- `.ko-agent-sandbox`, matched through the same fold:
  - refused: the name itself, `.KO-AGENT-SANDBOX`, `.Ko-Agent-Sandbox`,
    `.<U+212A>o-agent-sandbox` (KELVIN SIGN), `.ko-agent-<U+017F>andbox` (LONG S),
    `.ko-agent<U+00AD>-sandbox`, `.ko-agent-sandbox.`;
  - allowed: `.ko-agent-sandbox-notes`.
- Names that must stay **allowed**, so the superset has not reached into ordinary use:
  `.gitignore`, `.gitattributes`, `.gitmodules`, `.github`, and an accented non-ASCII name in both
  NFC and NFD (the normalization control: it must stay creatable).

Pass criterion:

- For every refused spelling, the create fails with `EPERM`.
- For every allowed spelling, it succeeds, *and* host `lstat` of `.git` and of `.ko-agent-sandbox`
  still finds nothing.
- A failure on any row means the fold rule needs widening in `policy::folds_to`. Fix the code, not
  the test.
- Fold tables depend on the version, which is why the recorded versions matter here.

The `.git` rows in the recorded runs pass on APFS (both variants, macOS 26.4.1) and on NTFS
(Windows Server 24H2; the 8.3 rows on Windows Server 2025). `verification-log.md` has the runs.
`probe/name-rule-cs-apfs.sh` drives the case-sensitive APFS one end to end. What is left:

- [ ] The `.git` rows for U+200E, U+202E and U+206F, on every backing: the recorded runs hold four
  of the seven ignorable forms.
- [ ] The `.ko-agent-sandbox` rows on case-sensitive APFS. Case-insensitive APFS and NTFS pass
  (`verification-log.md`, which also has the measurement that added the U+212A and U+017F folds).
- [ ] ext4, the control.
- [ ] The NTFS 8.3 short-name rows with the identity comparisons of the resolver, of `setattr` and
  of `link` (`fs.rs`, `open_ino`, `apply_setattr`, `link`). The run `verification-log.md` records
  ("Verified: NTFS 8.3 short names") has the check in `lookup` and the `O_EXCL` in `create`, and
  none of those.
  - `sbt dist`, `--build`, then the entry's commands over a host-created workspace.
  - Add `chmod`, `touch` and `ln` on an ordinary file. Every metadata change and hard link of a
    file goes through an `O_PATH` descriptor and its `/proc` path. The rig shows that on its own
    backing, not on the WSL drive mount.

### End-to-end coherency through the real host share

TTL 0 covers our layer only. End to end, the host share beneath must also show host writes
promptly (`architecture.md`).

- The launcher's `--self-test` share rows measure both paths a write can take, `read()` and an
  established `mmap`, across the whole stack. The launcher drives them, and the machine is
  recorded.
- macOS 26.4.1 passes.
- Windows measures fresh while the file is not held. A file the session holds refuses some host
  writers and not others.
- `verification-log.md` records both, and why the premise is about behavior, not about what a
  setting declares.

- [ ] Run `--self-test` on Windows for its first `mmap` row: whether a host write reaches a mapping
  the session holds. Git's mapped `.git/index` and packfiles depend on it.
- [ ] Run `--self-test` on Linux, and after a podman or macOS upgrade. The measurement, not the
  mount table, is what notices a changed hypervisor default.

### A path that survives deletion and refuses every child (unexplained)

Observed on 2026-08-30 on macOS 26.4.1, in a live-mode session, after `rm -rf` of a directory an
sbt server still held open. One path became unusable, while it stayed visible:

```sh
mkdir -p target/out  && mkdir target/out/anything    # ENOENT
mkdir -p target/out3 && mkdir target/out3/anything   # ok
```

- The error was `ENOENT`, not `EPERM`, so no policy rule is involved. `out` is no reserved name.
- `ls` and `stat` both showed an ordinary empty directory.
- `rmdir` succeeded, and creating the directory again at the same path reproduced the failure. So
  it is not a stale entry for that inode: the path itself stayed unusable, for every child name.
- A sibling created moments later behaved normally.
- It lasted for the rest of the session.
- A fresh container and mount cleared it: the same path accepted children again, with no repair on
  the host. So it is state in this layer, not anything that reaches the backing share. A session
  that hits it can be told to launch again. That is worth an entry in `troubleshooting.md` once the
  trigger is understood well enough to name.

- [ ] Reproduce it on purpose: delete a directory through the mount while a process holds it open,
  then create it again. If it reproduces, it belongs in the launcher's `--self-test` share rows,
  which already exercise the case: a host-shared tree changed under a live reader.

The launcher's `--run-on-host` makes a host process writing the shared `target/` the ordinary case,
not an occasional one.

### What the staged lower can do, per share

A stage's lower is the workspace root as it arrives inside the machine. The stage reads its
baseline there, checks it again there, and applies back onto it.

- Each row below decides a representation choice, so the rows run before the stage format is
  fixed, not after. The root `doc/plan-staged.md` has which machine settles which part of the
  contract.
- Every row has two parties: `probe/lower-probe.py` runs in a session, and
  `probe/lower-probe-host.py` on the host beside it. The pair reports all five rows in one run.

The rows:

- Hard-link identity: two names for one file, created on the host and through the mount. Does the
  lower keep the relationship, and can a session see it?
- `RENAME_EXCHANGE` and `RENAME_NOREPLACE` on the lower, and on the host path that apply replaces.
  Without exchange, an apply by that route cannot be atomic.
- Symlinks: can the daemon create one on the lower, and does the host then resolve it as a
  symlink? Windows makes symlink creation privileged, so this may be a refusal to plan around, not
  a behavior to test.
- Case folding between the layers: an upper name and a lower name that differ only by case.
  Whether they collide decides how whiteouts and upper entries may be named.
- The reach of an open-file hold: host write, rename and unlink against a path a session holds
  open, held for reading and for writing, and whether releasing it restores what was refused.
  Apply's write-back depends on this.

APFS answers all five (`verification-log.md` has the run):

- the lower keeps hard-link relationships;
- exchange is available on both sides;
- symlinks round-trip;
- two names that differ only by case are one name;
- a descriptor the session holds blocks no host change.

One answer was never the share's to give. A session cannot see a hard-link relationship at all,
because the FUSE backend assigns an inode per `(parent, name)`. What that costs a stage is for the
root `doc/plan-staged.md` to settle.

What is left:

- [ ] ext4 and NTFS, the same five rows. On NTFS, symlink creation is privileged, and a descriptor
  the session holds already refuses some host writers (the coherency row above). Rename and unlink
  of a held path are the unmeasured half.

### A symlink target spelled with Windows separators

On Linux, the symlink targets `..\..\x`, `..\.git` and `C:\Windows` are each one ordinary name. So
the FUSE backend judges each as a name in the link's directory, not as a path:

- `target_has_portable_syntax` (`fs.rs`), which refuses an absolute or climbing target, accepts all
  three;
- `allow_symlink_target`, which refuses a target into a Git directory or a writable region, finds
  neither.

- [ ] On Windows, make a symlink with each of those targets in a session, on the WSL drive mount.
  Record in `verification-log.md` what the host holds for each: whether it is an NT symbolic link,
  and the path Windows resolves it to.
- [ ] If Windows resolves any of them as a path, decide whether to refuse `\` and `:` in every
  target. The refusal would apply on macOS and Linux too, where such a target is an ordinary name.
  Which programs write one is unmeasured.

### The platform matrix itself

- [ ] linux-x86_64 and linux-aarch64 (the two architectures every image here builds for).
- [ ] The macOS podman machine on x86_64, if it still matters. The rows above ran on aarch64.

On Windows, the name rule, coherency and performance rows are measured (`verification-log.md`):

- fold tables are per volume, so the name-rule run verifies the volume it ran on;
- coherency's `mmap` row waits on the run above;
- `ls -lR` costs ~100 ms per entry ("Performance", below).


## Test infrastructure

`../../doc/testing.md` says what the suites cover and how to run them, the self-test image and the
privileged rig included.

- [ ] Add xattr attempts to the adversarial set when xattrs are implemented. They are `ENOSYS`
  today, so there is nothing to bypass yet.


## P1 — Performance (the measurements say the target workload would hurt)

The FUSE backend enforces every `--workspace=live,fuse` session, which native Linux and the
nesting modes need, so its cost is those sessions' own.

- `../../bench/entry-cost.py` builds its own corpus, so two runs compare across machines. It
  reports the time per entry for each workload.
- Run it once in a FUSE backend session and once under `../../bench/plain-bind.sh`
  (`plain-bind.ps1` beside it on Windows). The ratio between the columns is the answer; the control
  separates the FUSE backend's cost from the backing share's.
- The runs are in `verification-log.md`, "The cost of a path walk".
- For the profiling rows below, a daemon started with `--trace` logs each request and the time it
  took (`troubleshooting.md`, "Tracing requests").

The margin over the plain bind mount is **~6–18×**:

- It is this layer's cost alone: one FUSE round trip through the daemon per path component, which
  TTL 0 makes unavoidable.
- On Windows it is ~5–30×, over a share that is itself 5–13× slower.

The cost grows with the number of syscalls. Extrapolated linearly to a 100k-file tree:

- a readdir walk: ~40 s (tolerable);
- a walk with a stat: ~2.3 min;
- a stat per entry, as `ls -lR` does: ~21 min. That is the `sbt`/`metals` stat storm, this
  project's own stated target workload.
- The Windows figures for the same tree are ~7 min, ~24 min and ~2.8 h.
- The main term is the LOOKUPs per syscall. Entry TTL 0 makes every path component of every
  syscall a new round trip, which no batching further down can spread.

On the real tree, the path-walk term is the 3.8× between the two `lstat` rows
(`verification-log.md`, "a real tree"). `git status`, which Claude Code runs at startup, is where a
user meets it.

- [ ] **Run it on Linux.** There, no virtiofs is under the FUSE backend, and the ratio should
  differ in kind, not degree. That number is unknown today, and the FUSE backend is mandatory on
  Linux.
- [ ] **Profile git's untracked walk.** It is 32.7 s of the real tree's 71.5 s `git status`
  (`verification-log.md`, "a real tree"): 4.3 ms per entry, where `find` pays 1.95 ms over the
  same entries. What git asks per directory that `find` does not is unmeasured.
- [ ] **Profile a javac build whose output is outside the mount.**
  - A 202-class build then takes 41 s under gradle and 47 s under Maven, against 4.5 s and 1.9 s
    outside the mount altogether (`verification-log.md`, "a gradle build", "a Maven build").
  - That is 36 s and 45 s with some 210 input files as all the mount holds afterwards: some 0.2 s
    per source file, where a path operation at that depth costs milliseconds.
  - Which operations the build sends, on the inputs or on files it creates and removes during the
    build, is unmeasured.
- [ ] **Profile where the millisecond goes.** ~0.6 ms of a depth-1 `lstat`'s 0.64 ms is the FUSE
  hop from container to daemon plus the daemon's own work per operation, not yet split between the
  two. The guest resolves a component in ~0.06 ms.
  - The candidates:
    - the path inode model's full-path `openat2` per operation;
    - opening and closing an fd per operation;
    - the inode-table lock;
    - the single-threaded session serializing round trips.
  - Candidate fix, if the daemon's share dominates: reuse the parent directory's fd *within one
    operation*. It is the only gain available to programs like `find`, which hold directory fds and
    never pay the walk.
  - It combines with the cache-TTL option below, which helps only programs that walk paths. Reuse
    *across* operations is the directory-fd cache row below.
- [ ] **A directory-fd cache for the requests that change nothing.** Every request walks its full
  path again (`fs.rs`, `open_ino`), so its cost grows with depth.
  - Counted from the code, in path components resolved plus stat calls:
    - a `lookup` at depth k costs k + 3: the walk, the identity `fstat`, the `fstatat` of the name,
      and `policy_name`'s two, of `.git` and `.ko-agent-sandbox`;
    - a `getattr` costs k + 1: the walk and the identity `fstat`, which is also the reply.
  - An `lstat` adds up to 31 at depth 4, and 116 at depth 9. At one virtiofs request each and the
    ~56 µs of a guest lookup, the 31 are 1.7 ms of the 2.73 ms measured at depth 4
    (`verification-log.md`, "cost per operation and per component"). How many requests the guest
    kernel sends for them is unmeasured.
  - The design:
    - The daemon keeps an `O_PATH` descriptor per *directory* inode, bounded in number, and walks
      as today on a miss.
    - `lookup`, `getattr`, `readdir`, `readlink` and a read-only `open` go through the parent's
      descriptor, without the walk and without the identity `fstat`: a descriptor never comes to
      name another object.
    - `policy_name`'s two stay; without them, a second name of a guarded entry is classified as
      ordinary. So a `lookup` costs 3 at any depth, and a `getattr` 1: 15 for the `lstat` at depth
      4, 35 at depth 9.
    - Measure the gain. The counts predict how it scales with depth, not how large it is.
    - Every mutation, an `open` for writing included, keeps the full walk and the identity
      comparison. The policy then decides on exactly what it decides on today.
    - A path the sandbox walks stays fresh. Under TTL 0, the kernel asks for each component, and
      `fstatat(parent_fd, name)` answers from the live tree. So a directory the host replaced
      (`rm -rf`, then create again: `npm install`, `cargo clean`) gets a new inode at the next
      walk.
  - Accepted (2026-09-20): through a directory the sandbox *holds* (its working directory, an open
    descriptor), reads follow the object when the host moves it. Today they fail with `ESTALE` or
    `ENOENT`.
    - A mutation through it fails as it does today: it walks the stored names.
    - A local filesystem behaves differently: a create through a held descriptor lands in the moved
      directory (measured on xfs). The difference keeps a directory the host moved into a gitdir
      from being written under its old classification.
  - Accepted (2026-09-20), on condition that it is documented: when the host moves a held
    directory *out of* the workspace, the sandbox can still read that subtree through it. Today
    `RESOLVE_IN_ROOT` refuses that.
    - A plain bind mount behaves the same.
    - `..` does not climb from there, since the kernel resolves it.
  - [ ] Docs, in the change that adds the cache. The second acceptance depends on them:
    - `SECURITY.md`, "Not defended": a directory the session holds stays readable after the host
      moves it out of the workspace, and what that lets a session read;
    - `architecture.md`, "Inode model": a held directory follows the object the host moved, reads
      through the descriptor and mutations through the walk, and why that split keeps the policy's
      decisions as they are;
    - `troubleshooting.md`: a write that fails with `ESTALE` or `ENOENT` in a directory that still
      lists — the host moved it; `cd` to it again by its path.
  - Verify first:
    - that a host move of a directory held in the guest over virtiofs behaves as on xfs;
    - how many held descriptors the hypervisor's virtiofs can bear, which sets the bound.
  - What the argument rests on, each with a test:
    - every `Filesystem` method has an explicit route, asserted over all of them. `open` with
      `O_TRUNC` on a read-only access mode, and `link`'s source, are mutations;
    - a child looked up through a moved directory carries that directory's old context. So the
      identity comparison in `open_ino` is what refuses a mutation on it: the stored names lead to
      nothing, or to another object;
    - a descriptor leaves the cache under the lock that drops its inode, so a reused inode number
      never meets an old descriptor;
    - files are opened with `openat(parent_fd, name, O_NOFOLLOW)` and one identity `fstat`, not by
      reopening a cached descriptor through `/proc/self/fd`, which is a magic link.
  - Live mode only, for the reason `FUSE_PASSTHROUGH` below gives.
- [ ] READDIRPLUS: it batches lookup and getattr for the walk itself.
  - gocryptfs measured it with attribute caching on: a walk that only lists entries ran 6.5× and
    18.2× slower with it, and a walk that stats each entry, as `ls -lR` does, 1.36× and 1.82×
    faster (https://github.com/rfjakob/gocryptfs/issues/1026). The per-entry lookup is the cost;
    the saved `getattr` round trips are the gain.
  - Under TTL 0 the attributes it returns expire at once, so follow-up stats per file still make
    the round trip, and the gain is unmeasured here.
  - Measure before and after.
  - It would also align `readdir`'s `d_ino` with the synthetic `st_ino`, since each entry would
    carry a real lookup (Non-TODOs, inode-number reuse).
- [ ] Multi-threading (`Config::n_threads`, `clone_fd`), so parallel clients stop serializing.
  Throughput is flat from 1 to 8 client threads (`verification-log.md`, "an sbt build").
  - `fs.rs`, `mount_config`, lists what relies on one request at a time. The list is not shown to
    be complete, and each entry needs its own answer first.
  - The host races every such interval today, and is trusted. Threads would let the sandbox time
    them, so each needs an argument with the sandbox as the second party.
  - A narrower form leaves less to prove: one reader/writer lock for the session.
    - Shared by `lookup`, `getattr`, `read`, `readdir`, `readlink` and a read-only `open`;
      exclusive for every mutation, `write` included.
    - What `mount_config` says of `write` and of a mutation's interval stays true as written: no
      request of the session's own runs inside either.
    - Unproven: `lookup` against `lookup`, and `lookup` against `forget`, on the inode table.
    - Writes stay serialized. A build whose output is outside the mount sends mostly the shared
      operations.
  - Measure first what the kernel serializes. Without `FUSE_PARALLEL_DIROPS`, it admits one lookup
    per directory at a time, which limits the gain of either form.
- [ ] `FUSE_PASSTHROUGH` for bulk data, checked for in the kernel, with a userspace fallback.
  - A backing fd registered with the kernel cannot be rebound across the staged generation barrier
    in `doc/plan-staged.md`.
  - Restrict passthrough to live mode, unless research first establishes a safe protocol to revoke
    and register again.
  - Do not let staged mode inherit a live-only optimization by accident.
- [ ] Push-invalidation: the option below, kept *correct* by the daemon watching the backing
  (inotify inside the VM) and sending `notify_inval_entry`/`notify_inval_inode`. Its window then
  closes at the host write, not at T.
  - It is sound only if a watch in the guest sees a host-side virtiofs write, which nothing has
    shown.
  - Verify that premise first. If it fails, this row is closed.

Every one of these keeps the default coherency guarantee intact: performance is bought with
parallelism, batching, push-invalidation and a shorter path per operation. The one exception is
explicit, opt-in and off by default:

### The cache-TTL option (decided 2026-08-25, not started)

A per-workspace TTL for the kernel's cache of *directory names and attributes*, default 0.

- It was chosen over an always-on value because the break-even point moves with the host. A
  component costs ~0.9 ms over virtiofs and far less on native Linux, so the right T is measured
  per machine, not designed.

What it caches, and why exactly that:

- The path-walk term is the kernel asking again for each component. A TTL on entries alone does
  not remove it.
- Under `DefaultPermissions`, the kernel's `fuse_permission` refreshes a directory's attributes
  before each permission check on the walk. With attribute TTL 0, every component still costs a
  GETATTR in place of the LOOKUP.
- So the unit to cache is a directory's name *and* attributes, together.
- A file's attribute TTL stays 0. `AUTO_INVAL_DATA` therefore stays whole, and file `stat` and
  data are as fresh as today. Every `open` also drops the file's cached pages, since no
  `FOPEN_KEEP_CACHE` is granted.
- fuser 0.18's `ReplyEntry::entry_with_ttls` keeps the two TTLs apart, so choosing per reply needs
  no patch.

What it exposes, exactly:

- A directory's mode, owner and mtime, and a name, may be up to T old.
- The worst consequence found: git's untracked cache keys on directory mtime. So a file the host
  created within the last T can be missing from one `git status`.
- The policy is untouched. An inode's git context is computed once, at creation (`inode.rs`,
  `lookup`), so it already outlives any kernel cache. Every mutation reaches the daemon, whatever is
  cached.

Expected gain:

- The 3.8× measured above on git's stat pass: about 40 % of `git status` on the real tree, more if
  the untracked walk gains too.
- Nothing for programs like `find`; the profiling row is what would help them.
- The bursts that pay set the break-even point: a cached component is asked again once per T, while
  a walk stays under it.
- How much of the gain a given T keeps is unmeasured. The sweep below decides.

- [ ] Daemon: `--cache-ttl <ms>`. In `lookup` and `getattr`, a directory replies `(T, T)`, anything
  else `(0, T)`. A pure `ttls(mode, ttl)` with a test over every mode and option value: every mode
  that is not a directory gets attribute TTL 0.
- [ ] Rig: the coherency suite at T = 0 and T = 5 s. A host append, delete and create are visible
  at once under both. `--self-test` stays at 0, which is what "every mount is the same mount"
  (`fs.rs`, `mount_config`) is there to prove.
- [ ] Launcher: `--fuse-ttl=<ms>`, printed at every start beside the workspace line.
  - The mount is per workspace, shared by its live sessions, and reused on a matching source-id. T
    joins that key, recorded beside `source-id`.
  - A launch asking for a different value while sessions are live *refuses*, naming the live value
    and the sessions. It never silently gives a looser or stricter mount than asked.
- [ ] The sweep: 0 / 10 / 100 / 1000 ms against `git status` on the real tree, recorded in
  `verification-log.md`. Only then a persisted value.
- [ ] `.ko-agent-sandbox/fuse.conf` (`ttl-ms = N`, `#` comments), overridden by the flag, allowed by
  the unknown-filename rule (doc/egress-proxy.md, "The rule file").
  - A workspace sets its own coherency window, and a session cannot edit the file.
  - Deferred until the sweep has a value worth persisting.
- [ ] Docs:
  - `architecture.md` "Coherency" states the guarantee with the option in it: file attributes and
    data always fresh, directory names and attributes at most T old, default 0;
  - `troubleshooting.md` "Everything works but slowly" names the flag and the sentence on what it
    exposes;
  - the launcher's `README.md` reference block documents the flag.


## P2 — Launcher and deployment integration

The FUSE backend is native Linux's only backend ahead of that verification (`SECURITY.md`, "Not
defended"). That leaves:

- [ ] After Linux verification, remove the unverified-platform qualification from `SECURITY.md`.
  - Keep the mount-time guard's scope and snapshot limits. Platform evidence does not resolve those
    separate limits.
  - Move the explanation of build trust beside the verified guarantee.
- [ ] The guard's scope gap (`SECURITY.md`, "Not defended"): a nested repository's relocated hooks
  or redirected gitdir stay writable. The default `read-only .husky` covers husky's `.husky/`.
  Decide whether to close the gap or keep recording it:
  - a walk of the whole tree at every mount, `node_modules` and `target/` included, checking each
    repository and bare layout it finds. It costs mount time on large workspaces, and still misses
    a repository the host creates mid-session;
  - a check when a lookup first meets a `.git`. No walk, but a hook directory can be looked up and
    written before its repository's `.git` is. So every directory lookup needs a `stat` for `.git`,
    and read-only roots added mid-session invalidate cached contexts.
- [ ] A symlink the session makes that later resolves outside the workspace on the host
  (`SECURITY.md`, "The workspace"; `fs.rs`, `target_has_portable_syntax`).
  - Three routes:
    - moving the link, or a directory above it, to a shallower depth;
    - a hard link of it in a shallower directory;
    - a target through another symlink followed by `..` (`x -> d1/d2/a/..` with `a -> ../..`).
  - A host program that follows it reads or writes outside the workspace. A `--run-on-host`
    command does not, since Seatbelt matches the resolved path.
  - Ways to close it for the session's own links:
    - refuse `..` after a named component in a target. npm's and pnpm's links climb only at the
      start, but which tools write `a/../b` is unmeasured, and it refuses links that work today;
    - judge again the targets below a directory renamed to a shallower depth, and a symlink
      hard-linked there. One walk per such rename, none for npm's renames within one depth;
    - refuse a target through a host-made symlink whose own target is absolute or climbs. One
      lookup per component at creation.


## Deferred research

Timed to the work that needs it, so the findings are fresh when they are used.

- [ ] `fuse-backend-rs` (virtiofsd, Cloud Hypervisor) versus `fuser`, before investing in
  passthrough: it is the more battle-tested passthrough implementation.
- [ ] gVisor's gofer and virtiofsd, as prior art for fd-relative, TOCTOU-safe passthrough at scale.
- [ ] The podman machine's virtiofs cache modes, alongside the coherency premise above.
- [ ] Landlock to confine the daemon itself, so a bug in `ko-agent-fs` can reach only the backing
  directory. Defense in depth, not a boundary: the boundary is the policy.
- [ ] An optional no-symlink profile, only if staged review proves insufficient or users need a
  strict live view.
  - A complete profile must define existing links, and moves of directories that contain them.
  - It must then measure npm and pnpm bins, Python virtual environments, Bazel, Git-tracked links
    and native-library layouts. sbt falling back to copies settles only one consumer.


## Non-TODOs — settled, do not reopen without new evidence

- **Extended attributes.** Unimplemented, so the daemon answers `ENOSYS`.
  - The kernel rewrites that to `ENOTSUP` for the caller, and then never sends the operation again.
  - So programs read the mount as a filesystem with no extended attributes, an answer every
    xattr-aware program already knows how to take.
  - The cost is cosmetic: `cp -a` drops them silently (`verification-log.md`, "Extended
    attributes", has the run and why).
  - Implementing xattrs is a compatibility feature to schedule, not a regression to repair. The new
    evidence that reopens this is a program that complains, and the probe is what measures again
    then.

  Constraints before picking it up:
  - `setxattrat` arrived in Linux 6.13, and `f*xattr` on an `O_PATH` fd is `EBADF`. So whether a
    fd-relative call exists at all depends on the *daemon's* kernel.
  - This project's Debian 13 and podman floor (the README names it) do not set that kernel. They
    govern the container userspace, which the FUSE backend does not run in.
  - On a podman machine that kernel is Fedora CoreOS's: 7.1 as measured on 2026-08-14, so the call
    is present.
  - On native Linux it is the user's own, and nothing here bounds it. Debian 13 as a *host* is
    6.12, just under.
  - One path that works on both is `/proc/self/fd/<fd>` with the `l*xattr` calls, which is what
    libfuse's `passthrough_hp` does.
    - That is a magic-link path, in the one file that sets `RESOLVE_NO_MAGICLINKS` on purpose.
    - It is safe, because the fd is the daemon's own and never attacker-supplied. But the call
      site must justify it, so it does not look like an oversight.
  - `policy::Mutation` gains its xattr variants that day, which its doc comment already reserves.
    The adversarial tests follow ("Test infrastructure").
- **A supervisor watching the daemon.** A daemon that dies mid-session makes every access fail with
  `ENOTCONN` at `stat`.
  - There is no partial listing, no cached tree, and no fallback to an empty directory or the raw
    one.
  - It affects the workspace mount alone. Even shells die at spawn, because their working directory
    is inside the dead mount.
  - The failure is already total, loud and fail-closed. An outside program would only turn one
    obvious dead session into another. The user exits, and the reaper cleans up.
- **A Unicode normalization library in the policy core, or a mirrored case-fold table.** Settled by
  `../../policy/doc/security-research.md`, "Real-filesystem case-folding": the conservative superset
  plus the empirical test above, instead.
- **`RESOLVE_NO_XDEV`.** A mount the host placed inside the workspace should stay visible. Crossing
  into it is lateral, and `RESOLVE_IN_ROOT` already blocks escaping above the root.
- **A guard against inode-number reuse for *classification*.** Reusing a number for a recreated
  `(parent, name)` is safe for the policy.
  - The context comes from the names. The resolver serves a node only while it leads to the object
    recorded for it, without following a symlink (`fs.rs`, `open_ino`).
  - The one place identity enters classification is a second name of `.git` or
    `.ko-agent-sandbox`. There, a changed answer takes a new number (`fs.rs`, `policy_name`;
    `inode.rs`, `lookup`).
  - The stale-handle tests hold their handle one level below a recreated name. So what they measure
    is the FUSE backend's own `RESOLVE_NO_SYMLINKS` refusal, not a kernel or table artifact
    (`tests/mounted_mutate.rs`).
  - Reuse for *coherency* is a different question, and it is guarded: `lookup` gives a replaced
    object a new number, so it does not inherit the old one's page cache (`architecture.md`, "Inode
    model").
  - What stays advisory is `readdir`'s `d_ino`: the backing number, which differs from the
    synthetic `st_ino` that `getattr` returns. Aligning the two needs the per-entry lookup that
    READDIRPLUS would do (Performance).
  - The entry *type* is not advisory: a `DT_UNKNOWN` entry is stat'd for its real type, not assumed
    regular (`fs.rs`, `opendir`).
- **`FOPEN_DIRECT_IO` for coherency.** It would work, but it disables shared `mmap`, which git needs
  for `.git/index` and packfiles. `AUTO_INVAL_DATA` gets coherency without that cost.
- **An always-on nonzero cache TTL.** Real-time visibility in both directions is the defining
  requirement, so the default is 0 and there is no built-in value. "The cache-TTL option" above is
  the one exception, per workspace and opt-in, and it states what it exposes.
- **Blocking executable-bit changes.** This prevents only accidental direct POSIX execution.
  - Explicit interpreters and Windows bypass the bit, so it adds little beside read-only-by-default
    and staged review.
  - The mutation journal and apply plan report new executable bits and other mode changes.
  - Reopen enforcement only if those reports show a recurring accident worth the compatibility
    cost.
- **Making `ko-agent-fs` a general sandbox filesystem.** The narrow boundary is what makes it
  auditable (`architecture.md`, "What stays out of the audited core").
