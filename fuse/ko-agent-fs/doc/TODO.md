# TODO

What `ko-agent-fs` still needs, ordered by what stands between it and a first release anyone should
trust. Items under **P1 — platform verification** are the ones that *cannot* be settled by reasoning
at all — only the backing filesystem answers them, and until a row runs, the claim it would confirm
is an assumption. Which machine settles a row depends on the backing: ext4 and the two Linux
architectures the dev rig already reaches, APFS and NTFS a real macOS or Windows host. Everything
below them is ordinary work.

Decisions that research has already closed are in **Non-TODOs** so they stop resurfacing.


## P1 — Platform verification (needs real filesystems)

Every run belongs in `verification-log.md` with the venue that produced it: OS, podman, kernel and
filesystem versions. A pass with no venue recorded is not evidence for the next release, and
re-running is the only thing that notices a platform default changing underneath a row.

### The `.git` name rule per backing filesystem

The decisive question is not "what does our fold rule cover" but the property itself:

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
- A Windows 8.3 short name, `GIT~1`, on NTFS — to **confirm rather than assume** that an 8.3 name
  cannot alias a dot-leading long name.
- Names that must stay **allowed**, so the superset has not over-reached into ordinary use:
  `.gitignore`, `.gitattributes`, `.gitmodules`, `.github`, and an accented non-ASCII name in both
  NFC and NFD (the normalization control — it must remain creatable).

Pass criterion: for every denied spelling the create fails with `EPERM`; for every allowed spelling
it succeeds *and* host `lstat` of `.git` still finds nothing. A failure on any row means the fold
rule needs widening in `policy::is_dotgit_name` — fix the code, not the test. Fold tables are
version-specific, which is what makes the recorded versions load-bearing here.

APFS (both variants, macOS 26.4.1) and NTFS (Windows Server 24H2, the 8.3 row included) pass —
`verification-log.md` has the runs; `probe/name-rule-cs-apfs.sh` drives the case-sensitive APFS
one end to end. What is left:

- [ ] ext4, the control.

### End-to-end coherency through the real host share

TTL 0 covers our layer only; end to end also needs the virtiofs share beneath to reflect host
writes promptly (`architecture.md`). `probe/coherency-probe.py` measures both paths a write can
travel, `read()` and an established `mmap`, across the whole stack. macOS 26.4.1 passes, and
Windows measures fresh-when-unheld with host writes to session-held files refused by a share lock;
`verification-log.md` records both, and why the premise is behavioural rather than declarative.

- [ ] Re-run it on Linux, and after a podman or macOS upgrade.

### What the staged lower can do, per share

A stage's lower is the host project directory as it arrives inside the machine, and it is where the
stage reads its baseline, revalidates it and applies back onto it. Each row below decides a
representation choice, so they run before the stage format is fixed rather than after — the root
`doc/PLAN-STAGED.md` has which venue settles which part of the contract. Every row is two-party:
`probe/lower-probe.py` runs in a session and `probe/lower-probe-host.py` on the host beside it, and
the pair reports all five in one run.

The rows:

- Hardlink identity: two names for one file, created host-side and through the mount. Does the lower
  keep the relationship, and can a session see it?
- `RENAME_EXCHANGE` and `RENAME_NOREPLACE` on the lower, and on the host path apply replaces. An
  absent exchange is an apply that cannot be atomic by that route.
- Symlinks: can the daemon create one on the lower, and does the host then resolve it as a symlink?
  Windows makes symlink creation privileged, so this may be a refusal to plan around rather than a
  behaviour to test.
- Case folding between the layers: an upper name and a lower name differing only by case. Whether
  they collide decides how whiteouts and upper entries may be named.
- The reach of an open-file hold: host write, rename and unlink against a path a session holds open,
  read-held and write-held, and whether releasing restores what was refused. Apply write-back stands
  or falls on this.

APFS answers all five (`verification-log.md` has the run): the lower keeps hardlink relationships,
exchange is available on both sides, symlinks round-trip, two names differing only by case are one
name, and a session-held descriptor blocks no host mutation. One answer was never the share's to
give — a session cannot see a hardlink relationship at all, because the filter mints an inode per
`(parent, name)` — and what that costs a stage is the root `doc/PLAN-STAGED.md`'s to settle.

What is left:

- [ ] ext4 and NTFS, the same five rows. NTFS is where symlink creation is privileged and where a
  session-held descriptor already refuses host writes (the coherency row above); rename and unlink
  of a held path are the unmeasured half.

### The platform matrix itself

- [ ] linux-x86_64 and linux-aarch64 (the two architectures every image here builds for).
- [ ] macOS Podman machine on x86_64, if it still matters — aarch64 is where the rows above ran.

Windows stays **experimental**: the name rule and coherency rows are measured
(`verification-log.md` — fold tables are per-volume, so the name-rule run verifies the volume it
ran on, and coherency comes with the share-lock cost recorded there), while the performance row is
still unmeasured.


## Test infrastructure

What the suites cover and how to run them, the self-test image and the privileged rig included, is
`testing.md`.

- [ ] Add xattr attempts to the adversarial set when xattrs are implemented (they are `ENOSYS`
  today, so there is nothing to bypass yet).


## Correctness

`opendir` reads the entry names once into the handle, so a scan cannot skip or duplicate entries
when the directory changes under it, and a large directory costs one read rather than one per
`readdir` call. `a_directory_scan_is_stable_while_the_host_changes_the_directory` covers it.
`setattr` applies times through `utimensat`, so `touch -t` and archive extraction round-trip, with
`UTIME_OMIT` keeping one of the pair from clobbering the other.

The mount shape is `allow_other` + `default_permissions` (`architecture.md`, "Who may reach the
mount"). The tests run as a single uid, so they cannot tell that choice from the alternative; only
the launcher mounting for a real container can.


## P1 — Performance (the measurements say the target workload would hurt)

The filter is every session's enforcement, so this cost is not chosen by whoever sets a variable —
it is what the sandbox is. `probe/perf-probe.py` is the measurement: it
builds its own corpus, so two runs are comparable across machines, and reports per-entry times for
the five shapes below. Run it once in a filtered session and once with the guard off — the ratio
between the columns is the answer, and the control is the half that matters, since the raw bind is
fast for precisely the reason the invariant forbids.

Measured on a macOS Podman machine, 2,101 entries of 4 KB files, container → FUSE → daemon →
virtiofs, against the same corpus over a plain bind mount:

| operation                       | raw bind | filtered | ratio | shape                            |
| ------------------------------- | -------- | -------- | ----- | -------------------------------- |
| `find` (readdir only)           | 65 µs    | 317 µs   | 4.9×  | batched per directory            |
| `find -printf` (readdir + stat) | 147 µs   | 1052 µs  | 7.2×  | ≈ a lookup + getattr round trip  |
| `rm -rf`                        | 277 µs   | 1391 µs  | 5.0×  |                                  |
| `cp -r` (create + write)        | 1149 µs  | 5842 µs  | 5.1×  |                                  |
| `ls -lR` (stat + xattr probes)  | 644 µs   | 7793 µs  | 12.1× | ≈ 4–8 round trips: each          |
|                                 |          |          |       | *path-based* syscall re-resolves |
|                                 |          |          |       | every component                  |

The margin over that honest baseline is **~5–12×**. The raw bind is fast because the hypervisor
answers a guest lookup in ~56 µs and the guest caches nothing (`verification-log.md`, "the
virtiofs layer itself"), so what the ratio prices is this layer alone: one FUSE round trip through
the daemon per path component, which TTL 0 makes unavoidable.

Cost scales with syscall count, so linear extrapolation to a 100k-file tree: a readdir walk ~30 s
(tolerable); walk+stat ~1.8 min; `ls -lR`-shaped traffic ~13 min — the `sbt`/`metals` stat-storm
shape, on this project's own stated target workload. The dominant term is per-syscall LOOKUPs: entry
TTL 0 means every path component of every syscall is a fresh round trip, which no batching
downstream can amortize.

Measured on a real tree (2026-08-25, the same macOS machine; 3,190 tracked files at mean depth 6.6
among 8,858 entries), warm:

| operation                              | per file     | total                               |
| -------------------------------------- | ------------ | ----------------------------------- |
| `git status`                           | 4.7 ms       | 18 s (15 s, `--untracked-files=no`) |
| `lstat` of each tracked file, by path  | 3.6 ms       | 11.6 s                              |
| the same files through a directory fd  | 1.7 ms       | 5.4 s                               |
| `find . -type f`                       | 1.4 ms/entry | 12 s                                |

A depth-1 `lstat` costs 0.44 ms, of which the guest's own resolution is ~0.06 ms; each further
component adds ~0.6 ms, one more LOOKUP round trip (`verification-log.md`, "The cost of a path
walk"). git stats every tracked file by its full path
from the root and pays the depth; `find` and the other `fts` walkers hold directory fds and pay
depth 1 — the two `lstat` rows are those two shapes, and the 2.2× between them is the whole
path-walk term. Claude Code runs `git status` at startup: in that project it answers `pwd` in 51 s
from `/workspace` and 4.4 s from `/tmp` of the same container, against 5.4 s on the host.

- [ ] **Run it on Linux**, where there is no virtiofs under the filter and the ratio should differ
  in kind rather than degree — that number is unknown today, and Linux is a platform the filter is
  mandatory on.
- [ ] **Run it on Windows/WSL**, same reason, lowest priority.
- [ ] **Profile where the millisecond goes.** The guest resolves a component in ~0.06 ms, so
  ~0.4 ms of a depth-1 `lstat`'s 0.44 ms is the container→daemon FUSE hop plus the daemon's own
  work per op — still unattributed between the two: model B's full-path `openat2` per op, per-op fd
  open/close, the inode-table lock, and the single-threaded session serializing round trips.
  Candidate fix if the daemon's share dominates: parent-directory fd reuse *within one operation*.
  This is the only lever for `find`-shaped tools, which hold directory fds and never pay the walk;
  it composes with the cache-TTL knob below, which reaches only path-walking ones.
  A directory-fd cache *across* operations is excluded: it pins the directory, so one the host
  replaces (`rm -rf` then recreate — `npm install`, `cargo clean`) keeps serving its old contents
  through the stale fd, unbounded in time, which is worse than any TTL.
- [ ] READDIRPLUS — batches lookup+getattr for the walk itself. Expect it to help getdents-shaped
  traffic and not `ls -lR`-shaped: under TTL 0 the attributes it returns expire immediately, so
  follow-up per-file stats still round-trip. Measure before and after.
- [ ] Multi-threading (`Config::n_threads`, `clone_fd`) — parallel clients stop serializing.
- [ ] `FUSE_PASSTHROUGH` for bulk data, capability-checked with a userspace fallback. A backing fd
  registered with the kernel cannot be rebound across the staged generation barrier in
  `doc/PLAN-STAGED.md`; restrict passthrough to live mode unless research first establishes a safe revoke
  and re-register protocol. Do not make staged mode inherit a live-only optimization by accident.
- [ ] Push-invalidation: the knob below kept *correct* by the daemon watching the backing (inotify
  inside the VM) and issuing `notify_inval_entry`/`notify_inval_inode`, so its window closes at the
  host write rather than at T. Only sound if a watch in the guest sees a host-side virtiofs write,
  which nothing has shown — verify that premise first; if it fails, this row is closed.

Every one of these keeps the default coherency guarantee intact: performance is bought with
parallelism, batching, push-invalidation and a shorter per-op path. The one exception is explicit,
opt-in and off by default:

### The cache-TTL knob (decided 2026-08-25, not started)

A per-project TTL for the kernel's cache of *directory names and attributes*, default 0. Chosen
over an always-on value because the knee moves with the host: a component costs ~0.6 ms over
virtiofs and far less on native Linux, so the right T is measured per venue, not designed.

What it caches, and why exactly that. The path-walk term is the kernel re-asking per component,
and an entry-only TTL does not remove it: under `DefaultPermissions` the kernel's `fuse_permission`
refreshes a directory's attributes before each permission check on the walk, so with attribute TTL
0 every component still costs a GETATTR in place of the LOOKUP. The cacheable unit is therefore a
directory's name *and* attributes, together. A file's attribute TTL stays 0, so `AUTO_INVAL_DATA`
stays whole and file `stat` and data are as fresh as today (every `open` also drops the file's
cached pages: no `FOPEN_KEEP_CACHE` is granted). fuser 0.18's `ReplyEntry::entry_with_ttls`
carries the two TTLs separately, so the per-reply choice needs no patch.

What it exposes, exactly: a directory's mode, owner and mtime, and a name, may be up to T old. The
sharpest consequence found: git's untracked cache keys on directory mtime, so a file the host
created within the last T can be missing from one `git status`. Policy is untouched — an inode's
git context is computed once at creation (`inode.rs`, `lookup`), so it already outlives any kernel
cache, and every mutation reaches the daemon whatever is cached.

Expected gain: the 2.2× measured above on git's stat pass, so roughly half of Claude Code's startup
on the real tree; nothing for `find`-shaped tools (the profiling row is their lever). The bursts
that pay set the knee: a cached component is re-asked once per T while a walk stays under it, so
from the measured component cost T = 100 ms keeps ~96 % of the gain at a tenth of the window and
T = 10 ms loses a third of it. Those are derived, not measured; the sweep below decides.

- [ ] Daemon: `--cache-ttl <ms>`; in `lookup`/`getattr` a directory replies `(T, T)`, anything
      else `(0, T)`. A pure `ttls(mode, knob)` with a population test: every non-directory mode
      yields attribute TTL 0 for every knob value.
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
- [ ] `.ko-agent-sandbox/fuse.conf` (`ttl-ms = N`, `#` comments), overridden by the flag, admitted
      by the unknown-filename rule (README, "Modifying the egress policy"). A project sets its own
      coherency window, and a session cannot edit the file. Deferred until the sweep has a value
      worth persisting.
- [ ] Docs: `architecture.md` "Coherency" states the guarantee with the knob in it — file
      attributes and data always fresh, directory names and attributes ≤ T, default 0;
      `troubleshooting.md` "Everything works but slowly" names the flag and the exposure sentence;
      README's reference block carries the flag.


## P2 — Diagnostics

What exists: the symptom-keyed guide (`troubleshooting.md`); a startup banner and `t=<unix-secs>`
on every `DENY` line in `daemon.log`; the previous daemon's log kept as `daemon.log.1`; reasoned
messages on every launch gate; and a bounded deny log — full lines up to 10,000, then a cap notice,
then a counted summary every thousandth denial, so a hostile agent's refusal spam costs a few MB and
the trail loses detail past the cap, never magnitude (`fs.rs`, `deny_log_action`). The gap:

- [ ] Op-level tracing behind a flag (`--trace`?), for the performance profiling above and for
  diagnosing hangs — off by default, never in the launcher's normal invocation.


## P2 — Launcher and deployment integration

The filter is the **default** enforcement on every platform, ahead of that verification;
`KO_AGENT_SANDBOX_WORKSPACE_GUARD=none` is the way back to the pin. What that leaves:

- [ ] `SECURITY.md` carries a **Not defended** entry for the filter on the platforms where it is
  unverified — verified on macOS, reasoned elsewhere. When Linux and Windows have their rows that
  entry has nothing left to say and goes; the claim it qualifies already sits under **Defended**.
- [ ] The guard refuses to serve a repository whose control bytes resolve through the writable
  workspace under the binding rule — a redirected gitdir or commondir, an aliased config, hooks or
  an individual hook entry resolving back in, a bare layout at the root — and refuses the configs
  it cannot read faithfully: a `~`, a backslash, an unterminated quote, a bare `path` key, a
  non-UTF-8 or unreadable file (`git-metadata.md`, "Relocated hook directories"). As the default
  enforcement that means a project which launched yesterday does not launch today, and the remedy
  is to edit one's own `.git/config`. Decide whether that is acceptable, or whether the undecidable
  cases should fall back to the pin rather than refuse.
- [ ] The guard checks only the workspace root — the repository standing there, or the root
  itself as a bare layout — and only at mount. Two residues remain (SECURITY.md names both): a
  repository the host nested deeper keeps its `.git`-rooted control state frozen, but control
  bytes its owner had already routed into the worktree — relocated hooks, a redirected gitdir —
  are served as ordinary writable data, a shape the sandbox cannot create; and a bare layout the
  sandbox *can* create from ordinary names — below the root, or at the root itself after the
  mount-time check. Decide whether to extend the checks to the repositories and bare layouts a
  pre-mount walk finds, or to keep recording the residue.


## Deferred research

Timed to the increment that needs it, so the findings are fresh when they are used.

- [ ] `fuse-backend-rs` (virtiofsd, Cloud Hypervisor) versus `fuser` — before investing in
  passthrough, since it is the more battle-tested passthrough implementation.
- [ ] gVisor's gofer and virtiofsd as prior art for fd-relative, TOCTOU-safe passthrough at scale.
- [ ] Podman-machine virtiofs cache modes, alongside the coherency premise above.
- [ ] Landlock to confine the daemon itself, so a bug in `ko-agent-fs` can reach only the backing
  directory. Defense in depth, not a boundary — the boundary is the policy.
- [ ] An optional no-symlink profile, only if staged review proves insufficient or users need a
  strict live view. A truthful profile has to define existing links and moves of directories that
  contain them, then measure npm and pnpm bins, Python virtual environments, Bazel, Git-tracked
  links and native-library layouts; sbt falling back to copies settles only one consumer.


## Non-TODOs — settled, do not reopen without new evidence

- **Extended attributes.** Unimplemented, so the daemon answers `ENOSYS` — which the kernel
  rewrites to `ENOTSUP` for the caller and then latches, never sending the op again. The mount
  therefore reads to tools as a filesystem that simply has no extended attributes, and that is an
  answer every xattr-aware tool already knows how to take.

  Measured 2026-08-14 on a podman machine (virtiofs over APFS) with `probe/xattr-probe.py`, the
  filtered session against the raw bind as control:

  | operation   | raw bind (control)   | filtered              |
  | ----------- | -------------------- | --------------------- |
  | `setxattr`  | OK                   | `ENOTSUP`             |
  | `listxattr` | OK                   | `ENOTSUP`             |
  | `cp -a`     | exit 0, xattr kept   | exit 0, xattr dropped |

  The cost is cosmetic: `cp -a` carries no attribute across and says nothing about it, because
  coreutils reads `ENOTSUP` as "the destination does not do xattrs" rather than as a failure.
  Implementing xattrs is a compatibility feature to schedule, not a regression to repair; the new
  evidence that reopens this is a tool that complains, and the probe is what re-measures then.

  Two things to know before picking it up. `setxattrat` arrived in Linux 6.13 and `f*xattr` on an
  `O_PATH` fd is `EBADF`, so whether a fd-relative call is available at all depends on the
  *daemon's* kernel — not on this project's Debian 13 or podman floor (README names it), which
  govern the container userspace the filter does not run in. On a podman machine that kernel is Fedora
  CoreOS's (7.1 as measured on 2026-08-14, so present); on native Linux it is the user's own and is
  not bounded by anything here — Debian 13 as a *host* is 6.12, just under. One path that works on
  both is `/proc/self/fd/<fd>` with the `l*xattr` calls, which is what libfuse's `passthrough_hp`
  does; that is a magiclink path in the one file that sets `RESOLVE_NO_MAGICLINKS` deliberately —
  safe, because the fd is the daemon's own and never attacker-supplied, but it has to be justified
  at the call site rather than left to look like an oversight. And `policy::Mutation` gains its
  xattr variants that day, which its doc comment already reserves; the adversarial tests follow
  ("Test infrastructure").
- **A supervisor watching the daemon.** A daemon that dies mid-session makes every access
  fail `ENOTCONN` at `stat` — no partial listing, no cached tree, no fallback to an empty
  directory or the raw one — scoped to `/workspace` alone, and even shells die at spawn
  because their cwd is inside the dead mount. The failure is already total, loud and
  fail-closed, so outside machinery would only convert one obvious dead session into
  another; the user exits and the reaper cleans up.
- **A Unicode normalization library in the policy core.** `.git` is pure ASCII, so a
  normalization-insensitive backing creates no collision (`git-metadata.md`, "The name rule").
  Settled by research, pinned by a test.
- **Mirroring a filesystem's case-fold table.** NTFS's is per-volume; the exact set is not
  statically knowable. Conservative superset plus the empirical test above, instead.
- **`RESOLVE_NO_XDEV`.** A mount the host placed inside the workspace should stay visible; crossing
  into it is lateral, and `RESOLVE_IN_ROOT` already blocks escaping above the root.
- **Guarding against inode reuse.** Model B reuses an inode number for a recreated
  `(parent, name)`, which is safe because context and resolution derive from the *same* names
  rather than from the backing inode's identity — `RESOLVE_NO_SYMLINKS` is what keeps the two from
  parting company (`fs.rs`, `open_ino`). Reuse while the old object is still referenced — a name
  recreated with a different file type — is the kernel's to police and it does, invalidating the
  inode it held so operations on the old handle fail `EIO`; the stale-handle tests hold their
  handle one level below the recreated name precisely so that the filter's own refusal is what
  they measure. A backing mount point makes `readdir`'s reported `d_ino` cosmetic; harmless.
- **`FOPEN_DIRECT_IO` for coherency.** It would work, and it disables shared `mmap`, which git needs
  for `.git/index` and packfiles. `AUTO_INVAL_DATA` gets coherency without that cost.
- **A cache TTL as a performance knob.** Real-time bidirectional visibility is the defining
  requirement; a nonzero TTL trades correctness for speed. Invariant, not a tunable.
- **Blocking executable-bit changes.** This prevents only accidental direct POSIX execution;
  explicit interpreters and Windows bypass the bit, so it adds little beside read-only-by-default
  and staged review. The mutation journal and apply plan report new executable bits and other mode
  changes. Reopen enforcement only if those reports show a recurring accident worth the
  compatibility cost.
- **Making `ko-agent-fs` a general sandbox filesystem.** The narrow boundary is what makes it
  auditable (`architecture.md`, "What stays out of the audited core").
