# TODO

What `ko-agent-fs` still needs, ordered by what separates it from a first release anyone should
trust. The open security gap comes first. Items under **P1 — platform verification** are the ones
that *cannot* be settled by reasoning at all — only the backing filesystem answers them, and until a
row runs, the claim it would confirm is an assumption. Which machine settles a row depends on the
backing: ext4 and the two Linux architectures the dev rig already reaches, APFS and NTFS a real
macOS or Windows host. Everything below them is ordinary work.

Decisions that research has already closed are in **Non-TODOs** so they stop resurfacing.


## P1 — A second name arriving during a name-based mutation (open)

`rename`, `unlink` and `rmdir` act on the name the policy decided about, and a concurrent host
change can put a second name of a guarded entry there first (`security-research.md`, "Windows 8.3
short names"; `SECURITY.md` states the exception to its claims).

- [ ] A deterministic reproducer with its recorded outcome: the host's change placed between
  `allow_child` or `allow_create` and the backing syscall, for a rename source, a rename
  destination, a `RENAME_EXCHANGE` operand and a removal, with a hard link and with an NTFS short
  name.
- [ ] A design in which the decision holds through the mutation. Candidates, none examined: a
  backing-name resolution that cannot select a second name of a guarded entry; enforcement inside
  the backing filesystem; coordination that covers every writer of the backing tree, which a lock
  in the daemon does not; refusing `--write=live` where second names can arise. A scan at launch
  does not qualify, since the host can create a second name mid-session, and turning 8.3 name
  generation off leaves the existing short names (`fsutil 8dot3name strip` removes those).
  Staged mode keeps session mutations off the host tree, and its apply step needs the same
  protection against a concurrent replacement.

## P1 — Platform verification (needs real filesystems)

Every run belongs in `verification-log.md` with the machine that produced it: OS, podman, kernel and
filesystem versions. A pass with no machine recorded is not evidence for the next release, and
only re-running notices a platform default changing underneath a row.

### The `.git` name rule per backing filesystem

The decisive question is not "what do our name-matching rules cover" but the property itself:

> After the sandbox creates a name `N` through the mount, does host `git` — `lstat("<dir>/.git")` on
> the real backing filesystem — find a repository?

This cannot be reasoned to a conclusion: the fold tables are per-volume on NTFS and tied to a
Unicode version on APFS (`git-metadata.md`, "The name rule"). Reasoning bounds the candidate list;
only the filesystem settles it. `probe/apfs-name-rule-probe.py` creates each candidate *through the
mount* inside a filtered session and runs the host-side checks (its header has the procedure and the
cleanup). The corpus:

- `.git` itself (the base case must be refused).
- Case variants: `.GIT`, `.Git`, `.gIt`, `.giT`.
- Turkish i-family: `.gıt` (U+0131), `.gİt` (U+0130).
- Ignorable code points: `.gi<U+200C>t`, `.g<U+200B>it`, `<U+FEFF>.git`, `.git<U+00AD>`.
- Trailing punctuation: `.git.`, `.git ` (space), `.git. `.
- A Windows 8.3 short name, `GIT~1`, on NTFS: creating it where no `.git` exists must not make
  one. The short names an existing `.git` and `.ko-agent-sandbox` have, `GIT~1` and `KO-AGE~1`,
  are rows of their own, run by hand: a write, a create and a rename through them must fail
  with `EPERM`, and the host's files must be unchanged afterwards.
- `.ko-agent-sandbox`, matched through the same fold: the name itself, `.KO-AGENT-SANDBOX`,
  `.Ko-Agent-Sandbox`, `.<U+212A>o-agent-sandbox` (KELVIN SIGN), `.ko-agent-<U+017F>andbox`
  (LONG S), `.ko-agent<U+00AD>-sandbox`, `.ko-agent-sandbox.`; allowed,
  `.ko-agent-sandbox-notes`.
- Names that must stay **allowed**, so the superset has not over-reached into ordinary use:
  `.gitignore`, `.gitattributes`, `.gitmodules`, `.github`, and an accented non-ASCII name in both
  NFC and NFD (the normalization control — it must remain creatable).

Pass criterion: for every denied spelling the create fails with `EPERM`; for every allowed spelling
it succeeds *and* host `lstat` of `.git` and of `.ko-agent-sandbox` still finds nothing. A failure
on any row means the fold rule needs widening in `policy::folds_to` — fix the code, not the test.
Fold tables are version-specific, which is why the recorded versions matter here.

The `.git` rows pass on APFS (both variants, macOS 26.4.1) and NTFS (Windows Server 24H2; the
8.3 rows on Windows Server 2025) — `verification-log.md` has the runs;
`probe/name-rule-cs-apfs.sh` drives the case-sensitive APFS one end to end. What is left:

- [ ] The `.ko-agent-sandbox` rows on case-sensitive APFS; case-insensitive APFS and NTFS pass
  (`verification-log.md`, which also has the measurement that added the U+212A and U+017F folds).
- [ ] ext4, the control.
- [ ] The NTFS 8.3 short-name rows with the identity comparisons of the resolver and of `setattr`
  and `link` (`fs.rs`, `open_ino`, `apply_setattr`, `link`): the run `verification-log.md` records
  ("Verified: NTFS 8.3 short names") has the check in `lookup` and the `O_EXCL` in `create`, and
  none of those.
  - `sbt dist`, `--build`, then the entry's commands over a host-created project.
  - Add `chmod`, `touch` and `ln` on an ordinary file: every file's metadata change and hard link
    go through an `O_PATH` descriptor and its `/proc` path, which the rig shows on its own backing
    and not on the WSL drive mount.

### End-to-end coherency through the real host share

TTL 0 covers our layer only; end to end also needs the virtiofs share beneath to reflect host
writes promptly (`architecture.md`). The launcher's `--self-test` share rows measure both paths a
write can travel, `read()` and an established `mmap`, across the whole stack, launcher-driven and
machine-recorded. macOS 26.4.1 passes, and Windows measures fresh-when-unheld with host writes to
session-held files refused by a share lock; `verification-log.md` records both, and why the
premise is behavioral rather than declarative.

- [ ] Run `--self-test` on Linux, and after a podman or macOS upgrade — the measurement, not the
  mount table, is what notices a changed hypervisor default.

### A path that survives deletion and refuses every child (unexplained)

Observed 2026-08-30 on macOS 26.4.1, in a live-mode session, after `rm -rf` of a directory an sbt
server still held open. One path became unusable while remaining visible:

```sh
mkdir -p target/out  && mkdir target/out/anything    # ENOENT
mkdir -p target/out3 && mkdir target/out3/anything   # ok
```

`ENOENT`, not `EPERM`, so no policy rule is involved, and `out` is no reserved name. `ls` and
`stat` both showed an ordinary empty directory. `rmdir` succeeded, and recreating the directory at
the same path reproduced the failure, so it is not a stale entry for that inode — the path itself
stayed unusable, for every child name, while a sibling created moments later behaved normally. It
persisted across the rest of the session.

- [ ] Reproduce deliberately: delete a directory through the mount while a process holds it open,
  then recreate it. If it reproduces, this belongs in the launcher's `--self-test` share rows,
  which already exercise it — a host-shared tree mutated under a live reader.
A fresh container and mount cleared it: the same path accepted children again with no host-side
repair. So it is state in this layer rather than anything reaching the backing share, and a session
that hits it can be told to relaunch — which is worth an entry in `troubleshooting.md` once the
trigger is understood well enough to name.

The launcher's `--run-on-host` makes a host process writing the shared `target/` the ordinary
case rather than an occasional one.

### What the staged lower can do, per share

A stage's lower is the host project directory as it arrives inside the machine, and it is where the
stage reads its baseline, revalidates it and applies back onto it. Each row below decides a
representation choice, so they run before the stage format is fixed rather than after — the root
`doc/plan-staged.md` has which machine settles which part of the contract. Every row is two-party:
`probe/lower-probe.py` runs in a session and `probe/lower-probe-host.py` on the host beside it, and
the pair reports all five in one run.

The rows:

- Hardlink identity: two names for one file, created host-side and through the mount. Does the lower
  keep the relationship, and can a session see it?
- `RENAME_EXCHANGE` and `RENAME_NOREPLACE` on the lower, and on the host path apply replaces. An
  absent exchange is an apply that cannot be atomic by that route.
- Symlinks: can the daemon create one on the lower, and does the host then resolve it as a symlink?
  Windows makes symlink creation privileged, so this may be a refusal to plan around rather than a
  behavior to test.
- Case folding between the layers: an upper name and a lower name differing only by case. Whether
  they collide decides how whiteouts and upper entries may be named.
- The reach of an open-file hold: host write, rename and unlink against a path a session holds open,
  read-held and write-held, and whether releasing restores what was refused. Apply write-back
  depends or falls on this.

APFS answers all five (`verification-log.md` has the run): the lower keeps hardlink relationships,
exchange is available on both sides, symlinks round-trip, two names differing only by case are one
name, and a session-held descriptor blocks no host mutation. One answer was never the share's to
give — a session cannot see a hardlink relationship at all, because the filter assigns an inode per
`(parent, name)` — and what that costs a stage is the root `doc/plan-staged.md`'s to settle.

What is left:

- [ ] ext4 and NTFS, the same five rows. NTFS is where symlink creation is privileged and where a
  session-held descriptor already refuses host writes (the coherency row above); rename and unlink
  of a held path are the unmeasured half.

### The platform matrix itself

- [ ] linux-x86_64 and linux-aarch64 (the two architectures every image here builds for).
- [ ] macOS Podman machine on x86_64, if it still matters — aarch64 is where the rows above ran.

Windows stays **experimental**: the name rule and coherency rows are measured
(`verification-log.md` — fold tables are per-volume, so the name-rule run verifies the volume it
ran on, and coherency comes with the share-lock cost recorded there), and the performance row is
unmeasured.


## Test infrastructure

What the suites cover and how to run them, the self-test image and the privileged rig included, is
`testing.md`.

- [ ] Add xattr attempts to the adversarial set when xattrs are implemented (they are `ENOSYS`
  today, so there is nothing to bypass yet).


## P1 — Performance (the measurements say the target workload would hurt)

The filter enforces the default mode, `--write=live` under `WORKSPACE_GUARD=fuse`, so its cost is
the sandbox's own; `WORKSPACE_GUARD=none` selects the weaker read-only bind mount boundary without
that cost. `probe/perf-probe.py` builds its own corpus, so two runs are comparable across machines,
and reports per-entry times per workload. Run it once in a filtered session and once with the guard
off — the ratio between the columns is the answer, and the control isolates the filter's cost from
the backing share. The runs are `verification-log.md`, "The cost of a path walk".

The margin over the unfiltered bind mount is **~5–12×**, and it is this layer's cost alone: one FUSE
round trip through the daemon per path component, which TTL 0 makes unavoidable.

Cost scales with syscall count, so linear extrapolation to a 100k-file tree: a readdir walk ~30 s
(tolerable); walk+stat ~1.8 min; a stat per entry as `ls -lR` does, ~13 min — the `sbt`/`metals`
stat storm, this project's own stated target workload. The dominant term is per-syscall LOOKUPs:
entry TTL 0 means every path component of every syscall is a fresh round trip, which no batching
downstream can amortize.

On the real tree the path-walk term is the 2.2× between the two `lstat` rows (`verification-log.md`,
"a real tree"), and `git status` — which Claude Code runs at startup — is where a user meets it.

- [ ] **Run it on Linux**, where there is no virtiofs under the filter and the ratio should differ
  in kind rather than degree — that number is unknown today, and Linux is a platform the filter is
  mandatory on.
- [ ] **Run it on Windows/WSL**, same reason, lowest priority.
- [ ] **Measure what the identity checks add.** A lookup of an ordinarily named entry outside a
  gitdir makes two more `fstatat` calls (`fs.rs`, `policy_name`), an operation on a parent and a
  name one more, and every resolution an `fstat` of the descriptor it opened (`open_ino`). The
  recorded runs (`verification-log.md`, "The cost of a path walk") have none of them; rerun
  `probe/perf-probe.py` on the same machine and record the new ratio.
- [ ] **Profile where the millisecond goes.** The guest resolves a component in ~0.06 ms, so ~0.4 ms
  of a depth-1 `lstat`'s 0.44 ms is the container→daemon FUSE hop plus the daemon's own work per op
  — still unattributed between the two: the path inode model's full-path `openat2` per op, per-op fd
  open/close, the inode-table lock, and the single-threaded session serializing round trips.
  Candidate fix if the daemon's share dominates: parent-directory fd reuse *within one operation*.
  This is the only gain available to programs like `find`, which hold directory fds and never pay
  the walk; it composes with the cache-TTL option below, which reaches only path-walking ones. A
  directory-fd cache *across* operations is excluded: it holds the directory open, so one the host
  replaces (`rm -rf` then recreate — `npm install`, `cargo clean`) keeps serving its old contents
  through the stale fd, unbounded in time, which is worse than any TTL.
- [ ] READDIRPLUS — batches lookup+getattr for the walk itself. Expect it to help a walk that only
  lists entries, not one that stats each as `ls -lR` does: under TTL 0 the attributes it returns
  expire immediately, so follow-up per-file stats still round-trip. Measure before and after. It
  would also align `readdir`'s `d_ino` with the synthetic `st_ino`, since each entry would carry a
  real lookup (Non-TODOs, inode-number reuse).
- [ ] Multi-threading (`Config::n_threads`, `clone_fd`) — parallel clients stop serializing.
  `fs.rs`, `mount_config`, has what rests on one request at a time; each needs its own answer
  first.
- [ ] `FUSE_PASSTHROUGH` for bulk data, capability-checked with a userspace fallback. A backing fd
  registered with the kernel cannot be rebound across the staged generation barrier in
  `doc/plan-staged.md`; restrict passthrough to live mode unless research first establishes a safe
  revoke and re-register protocol. Do not make staged mode inherit a live-only optimization by
  accident.
- [ ] Push-invalidation: the option below kept *correct* by the daemon watching the backing (inotify
  inside the VM) and issuing `notify_inval_entry`/`notify_inval_inode`, so its window closes at the
  host write rather than at T. Only sound if a watch in the guest sees a host-side virtiofs write,
  which nothing has shown — verify that premise first; if it fails, this row is closed.

Every one of these keeps the default coherency guarantee intact: performance is bought with
parallelism, batching, push-invalidation and a shorter per-op path. The one exception is explicit,
opt-in and off by default:

### The cache-TTL option (decided 2026-08-25, not started)

A per-project TTL for the kernel's cache of *directory names and attributes*, default 0. Chosen over
an always-on value because the break-even point moves with the host: a component costs ~0.6 ms over
virtiofs and far less on native Linux, so the right T is measured per machine, not designed.

What it caches, and why exactly that. The path-walk term is the kernel re-asking per component,
and an entry-only TTL does not remove it: under `DefaultPermissions` the kernel's `fuse_permission`
refreshes a directory's attributes before each permission check on the walk, so with attribute TTL
0 every component still costs a GETATTR in place of the LOOKUP. The cacheable unit is therefore a
directory's name *and* attributes, together. A file's attribute TTL stays 0, so `AUTO_INVAL_DATA`
stays whole and file `stat` and data are as fresh as today (every `open` also drops the file's
cached pages: no `FOPEN_KEEP_CACHE` is granted). fuser 0.18's `ReplyEntry::entry_with_ttls`
keeps the two TTLs separately, so the per-reply choice needs no patch.

What it exposes, exactly: a directory's mode, owner and mtime, and a name, may be up to T old. The
worst consequence found: git's untracked cache keys on directory mtime, so a file the host
created within the last T can be missing from one `git status`. Policy is untouched — an inode's
git context is computed once at creation (`inode.rs`, `lookup`), so it already outlives any kernel
cache, and every mutation reaches the daemon whatever is cached.

Expected gain: the 2.2× measured above on git's stat pass, so roughly half of Claude Code's startup
on the real tree; nothing for programs like `find` (the profiling row is what would help them). The
bursts that pay set the break-even point: a cached component is re-asked once per T while a walk
stays under it, so from the measured component cost T = 100 ms keeps ~96 % of the gain at a tenth of
the window and T = 10 ms loses a third of it. Those are derived, not measured; the sweep below
decides.

- [ ] Daemon: `--cache-ttl <ms>`; in `lookup`/`getattr` a directory replies `(T, T)`, anything
      else `(0, T)`. A pure `ttls(mode, ttl)` with a population test: every non-directory mode
      yields attribute TTL 0 for every option value.
- [ ] Rig: the coherency suite at T = 0 and T = 5 s — host append, delete and create visible at
      once under both. `--self-test` stays at 0, which is what "every mount is the same mount"
      (`fs.rs`, `mount_config`) is there to prove.
- [ ] Launcher: `--fuse-ttl=<ms>`, printed at every start beside the workspace line. The mount is
      per project and shared by its live sessions, reused on matching source-id; T joins that key,
      recorded beside `source-id`, and a launch asking a different value while sessions are live
      *refuses*, naming the live value and the sessions — never a looser or stricter mount than
      asked, silently.
- [ ] The sweep: 0 / 10 / 100 / 1000 ms against `git status` on the real tree, recorded in
      `verification-log.md`. Only then a persisted value.
- [ ] `.ko-agent-sandbox/fuse.conf` (`ttl-ms = N`, `#` comments), overridden by the flag, allowed
      by the unknown-filename rule (doc/egress-proxy.md, "The rule file"). A project sets its own
      coherency window, and a session cannot edit the file. Deferred until the sweep has a value
      worth persisting.
- [ ] Docs: `architecture.md` "Coherency" states the guarantee with the option in it — file
      attributes and data always fresh, directory names and attributes ≤ T, default 0;
      `troubleshooting.md` "Everything works but slowly" names the flag and the exposure sentence;
      the launcher’s `README.md` reference block documents the flag.


## P2 — Diagnostics

What exists is what `troubleshooting.md` reads from: the banner, the `DENY` line, the previous
daemon's log, the bounded deny log (`fs.rs`, `deny_log_action`), and a reasoned message on every
launch gate. The gap:

- [ ] Op-level tracing behind a flag (`--trace`?), for the performance profiling above and for
  diagnosing hangs — off by default, never in the launcher's normal invocation.


## P2 — Launcher and deployment integration

The filter is the default on every platform ahead of that verification (`SECURITY.md`, "Not
defended"), which leaves:

- [ ] After Linux verification, remove the unverified-platform qualification from `SECURITY.md`.
  Retain the mount-time guard's scope and snapshot limits, and move the explanation of build trust
  beside the verified guarantee. Platform evidence does not resolve those separate limits.
- [ ] The guard's scope gap (`SECURITY.md`, "Not defended"): decide whether to extend the
  checks to the repositories and bare layouts a pre-mount walk finds, or to keep recording it.


## Deferred research

Timed to the work that needs it, so the findings are fresh when they are used.

- [ ] `fuse-backend-rs` (virtiofsd, Cloud Hypervisor) versus `fuser` — before investing in
  passthrough, since it is the more battle-tested passthrough implementation.
- [ ] gVisor's gofer and virtiofsd as prior art for fd-relative, TOCTOU-safe passthrough at scale.
- [ ] Podman-machine virtiofs cache modes, alongside the coherency premise above.
- [ ] Landlock to confine the daemon itself, so a bug in `ko-agent-fs` can reach only the backing
  directory. Defense in depth, not a boundary — the boundary is the policy.
- [ ] An optional no-symlink profile, only if staged review proves insufficient or users need a
  strict live view. A complete profile has to define existing links and moves of directories that
  contain them, then measure npm and pnpm bins, Python virtual environments, Bazel, Git-tracked
  links and native-library layouts; sbt falling back to copies settles only one consumer.


## Non-TODOs — settled, do not reopen without new evidence

- **Extended attributes.** Unimplemented, so the daemon answers `ENOSYS` — which the kernel
  rewrites to `ENOTSUP` for the caller and then latches, never sending the op again. The mount
  therefore reads to programs as a filesystem that has no extended attributes, and that is an
  answer every xattr-aware program already knows how to take. The cost is cosmetic: `cp -a` drops
  them silently (`verification-log.md`, "Extended attributes", has the run and why).
  Implementing xattrs is a compatibility feature to schedule, not a regression to repair; the new
  evidence that reopens this is a program that complains, and the probe is what re-measures then.

  Constraints before picking it up: `setxattrat` arrived in Linux 6.13 and `f*xattr` on an
  `O_PATH` fd is `EBADF`, so whether a fd-relative call is available at all depends on the
  *daemon's* kernel — not on this project's Debian 13 or podman floor (README names it), which
  govern the container userspace the filter does not run in. On a podman machine that kernel is
  Fedora CoreOS's (7.1 as measured on 2026-08-14, so present); on native Linux it is the user's own
  and is not bounded by anything here — Debian 13 as a *host* is 6.12, just under. One path that
  works on both is `/proc/self/fd/<fd>` with the `l*xattr` calls, which is what libfuse's
  `passthrough_hp`
  does; that is a magiclink path in the one file that sets `RESOLVE_NO_MAGICLINKS` deliberately —
  safe, because the fd is the daemon's own and never attacker-supplied, but it has to be justified
  at the call site rather than left to look like an oversight. And `policy::Mutation` gains its
  xattr variants that day, which its doc comment already reserves; the adversarial tests follow
  ("Test infrastructure").
- **A supervisor watching the daemon.** A daemon that dies mid-session makes every access
  fail `ENOTCONN` at `stat` — no partial listing, no cached tree, no fallback to an empty
  directory or the raw one — scoped to the project mount alone, and even shells die at spawn
  because their cwd is inside the dead mount. The failure is already total, loud and
  fail-closed, so an outside program would only convert one obvious dead session into
  another; the user exits and the reaper cleans up.
- **A Unicode normalization library in the policy core, or a mirrored case-fold table.** Settled
  by `security-research.md`, "Real-filesystem case-folding": the conservative superset plus the
  empirical test above, instead.
- **`RESOLVE_NO_XDEV`.** A mount the host placed inside the workspace should stay visible; crossing
  into it is lateral, and `RESOLVE_IN_ROOT` already blocks escaping above the root.
- **A guard against inode-number reuse for *classification*.** Reusing a number for a recreated
  `(parent, name)` is safe for the policy: the context derives from the names, and the resolver
  serves a node only the object recorded for it, without following a symlink (`fs.rs`, `open_ino`).
  The one place identity enters classification is a second name of `.git` or `.ko-agent-sandbox`,
  and there a changed answer takes a fresh number (`fs.rs`, `policy_name`; `inode.rs`, `lookup`).
  The stale-handle tests hold their handle one level below a recreated name so that the filter's own
  `RESOLVE_NO_SYMLINKS` refusal, not a kernel or table artifact, is what they measure
  (`tests/mounted_mutate.rs`). Reuse for *coherency* is a different question and is guarded:
  `lookup` gives a replaced object a fresh number so it does not inherit the old one's page cache
  (`architecture.md`, "Inode model"). What stays advisory is `readdir`'s `d_ino` — the backing
  number, which differs from the synthetic `st_ino` `getattr` returns; aligning the two needs the
  per-entry lookup READDIRPLUS would do (Performance). The entry *type* is not advisory: a
  `DT_UNKNOWN` entry is stat'd for its real type rather than assumed regular (`fs.rs`, `opendir`).
- **`FOPEN_DIRECT_IO` for coherency.** It would work, and it disables shared `mmap`, which git needs
  for `.git/index` and packfiles. `AUTO_INVAL_DATA` gets coherency without that cost.
- **An always-on nonzero cache TTL.** Real-time bidirectional visibility is the defining
  requirement, so the default is 0 and no built-in value exists; "The cache-TTL option" above is
  the one exception, per project and opt-in, and its exposure is stated there.
- **Blocking executable-bit changes.** This prevents only accidental direct POSIX execution;
  explicit interpreters and Windows bypass the bit, so it adds little beside read-only-by-default
  and staged review. The mutation journal and apply plan report new executable bits and other mode
  changes. Reopen enforcement only if those reports show a recurring accident worth the
  compatibility cost.
- **Making `ko-agent-fs` a general sandbox filesystem.** The narrow boundary is what makes it
  auditable (`architecture.md`, "What stays out of the audited core").
