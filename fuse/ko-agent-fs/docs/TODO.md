# TODO

What `ko-agent-fs` still needs, ordered by what stands between it and a first release anyone should
trust. Items under **P1 — platform verification** are the ones that *cannot* be settled by reasoning
at all — only the backing filesystem answers them, and until a row runs, the claim it would confirm
is an assumption. Which machine settles a row depends on the backing: ext4 and the two Linux
architectures the dev rig already reaches, APFS and NTFS a real macOS or Windows host. Everything
below them is ordinary work.

Decisions that research has already closed are in **Non-TODOs** so they stop resurfacing.


## P1 — Platform verification (needs real filesystems)

### The `.git` name rule on a case-insensitive backing

The decisive question is not "what does our fold rule cover" but the property itself:

> After the sandbox creates a name `N` through the mount, does host `git` — `lstat("<dir>/.git")` on
> the real backing filesystem — find a repository?

This cannot be reasoned to a conclusion: the fold tables are per-volume on NTFS and tied to a
Unicode version on APFS (`git-metadata.md`, "The name rule"). Reasoning bounds the candidate list;
only the filesystem settles it.

Run on each supported backing — APFS case-insensitive (the default macOS variant), APFS
case-sensitive, NTFS, and ext4 as the control — creating each candidate *through the mount* and
asserting the host sees no repository. `probes/apfs-name-rule-probe.py` runs the candidate rows
inside a filtered session (its header has the procedure, the host-side checks, and cleanup):

- [ ] `.git` itself (the base case must be refused).
- [ ] Case variants: `.GIT`, `.Git`, `.gIt`, `.giT`.
- [ ] Turkish i-family: `.gıt` (U+0131), `.gİt` (U+0130).
- [ ] Ignorable code points: `.gi<U+200C>t`, `.g<U+200B>it`, `<U+FEFF>.git`, `.git<U+00AD>`.
- [ ] Trailing punctuation: `.git.`, `.git ` (space), `.git. `.
- [ ] A Windows 8.3 short name, `GIT~1` — to **confirm rather than assume** that an 8.3 name cannot
  alias a dot-leading long name.
- [ ] Names that must stay **allowed**, so the superset has not over-reached into ordinary use:
  `.gitignore`, `.gitattributes`, `.gitmodules`, `.github`, and an accented non-ASCII name in both
  NFC and NFD (the normalization control — it must remain creatable).

Pass criterion: for every denied spelling the create fails with `EPERM`; for every allowed spelling
it succeeds *and* host `lstat` of `.git` still finds nothing. A failure on any row means the fold
rule needs widening in `policy::is_dotgit_name` — fix the code, not the test.

Status by backing: **APFS case-insensitive — all rows pass** (macOS 26.4.1; recorded with versions
in `security-research.md`). APFS case-sensitive, ext4 and NTFS remain; the 8.3 row is NTFS-only.

Every run's result belongs in `security-research.md` with the OS and filesystem versions: the fold
tables are version-specific, so a bare pass with no version recorded is not evidence for the next
release.

### End-to-end coherency through the real host share

TTL 0 covers our layer only; end to end also needs the virtiofs share beneath to reflect host
writes promptly (`architecture.md`). `probes/coherency-probe.py` measures both paths a write can
travel, `read()` and an established `mmap`, across the whole stack. It passes on macOS 26.4.1, and
`security-research.md` records the result and why the premise it rests on is behavioural rather than
declarative — which is what makes re-running it the only thing that notices a changed default.

- [ ] Re-run it on each remaining backing, and after a podman or macOS upgrade.

### The platform matrix itself

- [ ] linux-x86_64 and linux-aarch64 (the two architectures every image here builds for).
- [ ] macOS Podman machine (aarch64, and x86_64 if it still matters).

Windows is **decided: experimental, NTFS unverified.** The name-rule candidates for NTFS (the
per-volume `$UpCase` fold, the 8.3 row above) stay untested until someone runs them on a real
volume; until then the release says plainly that the filter on Windows is experimental, rather than
claiming a verification nobody ran.


## Relocated hooks — closed by refusing to serve (residue below)

Where the **host** relocated its hook directory into the worktree, the files host `git` executes
sit at an ordinary worktree path the filter calls writable. Closed by a startup refusal
(`src/guard.rs`, `git-metadata.md`) covering the symlink form, the `core.hooksPath` form, a
symlinked `.git`, and the two undecidable cases (a `~`-relative path, a config carrying an
`include`) — and firing only when the target resolves *inside* the workspace.

**Nested host-created repositories are documented, not walked.** Only the workspace-root repository
is scanned, matching the launcher pin's root-only precedent: the sandbox cannot create a nested
repository (the filter denies `.git` at every depth), so one can only be host residue, and
SECURITY.md's "The project checkout" already tells the user a nested repository is the agent's
output to distrust. A startup walk over a 100k-file workspace would contradict the perf posture for
a case the docs already own. `guard.rs`'s header records the scope.

**The guard is a startup snapshot, and stays one.** A host that relocates its hooks into the
worktree *mid-session* is not caught. Recorded rather than polled: a scheduled re-read of `config`
and re-`lstat` of `hooks` buys a guarantee only as fresh as its last poll, and puts that work on the
hot path the performance section is already fighting. The window is one the **host** opens — the
sandbox cannot cause the relocation, since `.git/config` is frozen and the `.git/hooks` node is
control state. `git-metadata.md` ("Relocated hook directories") carries the reasoning, `SECURITY.md`
tells the user, and `guard.rs`'s header says it where the check runs.


## Test infrastructure

What the suites cover and how to run them, the privileged rig included, is `testing.md`.

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

- [ ] **Extended attributes.** Unimplemented, so the daemon answers `ENOSYS` — which the kernel
  rewrites to `ENOTSUP` for the caller and then latches, never sending the op again. The mount
  therefore reads to tools as a filesystem that simply has no extended attributes, and that is an
  answer every xattr-aware tool already knows how to take.

  Measured 2026-08-14 on a podman machine (virtiofs over APFS) with `probes/xattr-probe.py`, the
  filtered session against the raw bind as control:

  | operation   | raw bind (control)   | filtered              |
  | ----------- | -------------------- | --------------------- |
  | `setxattr`  | OK                   | `ENOTSUP`             |
  | `listxattr` | OK                   | `ENOTSUP`             |
  | `cp -a`     | exit 0, xattr kept   | exit 0, xattr dropped |

  So the cost is cosmetic, and that settles what this entry used to leave open. `cp -a` carries no
  attribute across and says nothing about it, because coreutils reads `ENOTSUP` as "the destination
  does not do xattrs" rather than as a failure — the earlier worry that `ENOSYS` was a regression
  from the raw bind was wrong about what callers see. `ENOSYS` stays; implementing xattrs is a
  compatibility feature to schedule, not a regression to repair. Re-run the probe if a tool ever
  does complain.

  Two things to know before picking it up. `setxattrat` arrived in Linux 6.13 and `f*xattr` on an
  `O_PATH` fd is `EBADF`, so whether a fd-relative call is available at all depends on the
  *daemon's* kernel — not on this project's Debian 13 or podman 6.0.2 bar, which govern the
  container userspace the filter does not run in. On a podman machine that kernel is Fedora CoreOS's
  (7.1 as measured on 2026-08-14, so present); on native Linux it is the user's own and is not
  bounded by anything here — Debian 13 as a *host* is 6.12, just under. One path that works on both
  is `/proc/self/fd/<fd>` with the `l*xattr` calls, which is what libfuse's `passthrough_hp` does;
  that is a magiclink path in the one file that sets `RESOLVE_NO_MAGICLINKS` deliberately — safe,
  because the fd is the daemon's own and never attacker-supplied, but it has to be justified at the
  call site rather than left to look like an oversight. And `policy::Mutation` gains its xattr
  variants that day, which its doc comment already reserves.


## P1 — Performance (the measurements say the target workload would hurt)

Now that the filter is every session's enforcement rather than an opt-in, this cost is not chosen by
whoever sets a variable — it is what the sandbox is. The numbers below are one ad-hoc run on one
machine; a feature that everybody pays for is owed a repeatable measurement on every platform it
ships to.

- [ ] **Turn the run below into a repeatable benchmark**, checked in beside the probes so a
  before/after is a command rather than a reconstruction: the same corpus, the same five commands,
  filtered and raw-bind, reporting per-entry times and the ratio.
- [ ] **Re-run it on macOS** — the numbers here predate the flip and were taken by hand, yet they
  are the baseline every later optimisation is measured against, so they should come from the
  benchmark instead.
- [ ] **Run it on Linux**, where there is no virtiofs under the filter and the ratio should differ
  in kind rather than degree — that number is unknown today, and Linux is now a platform the filter
  is mandatory on.
- [ ] **Run it on Windows/WSL**, same reason, lowest priority.

Measured 2026-08-14, in a live filtered session on a macOS Podman machine — 1,796 entries,
8.7 MB, container → FUSE → daemon → virtiofs, runs stable to ±3%:

| operation                        | per entry | shape                                    |
| -------------------------------- | --------- | ---------------------------------------- |
| `find` (readdir only)            | 0.09 ms   | batched per directory — already cheap    |
| `find -printf` (readdir + stat)  | 0.76 ms   | ≈ one lookup + getattr round trip        |
| `rm -rf`                         | 1.25 ms   |                                          |
| `cp -r` (create + write)         | 2.35 ms   |                                          |
| `ls -lR` (stat + xattr probes)   | 6.13 ms   | ≈ 4–8 round trips: each *path-based*     |
|                                  |           | syscall re-resolves every component      |

One round trip costs ~0.7–1.4 ms, and cost scales linearly with syscall count. Linear extrapolation
to a 100k-file tree: readdir walk ~9 s (fine); walk+stat ~76 s; `ls -lR`-shaped traffic ~10 min —
the `sbt`/`metals` stat-storm shape, on this project's own stated target workload. The dominant term
is per-syscall LOOKUPs: entry TTL 0 means every path component of every syscall is a fresh round
trip, which no batching downstream can amortize.

The control, same corpus and commands over a plain bind mount: readdir 21 µs, walk+stat 57 µs,
`ls -lR` 627 µs, `cp` 648 µs, `rm` 280 µs per entry. The raw bind is fast because the VM kernel
caches virtiofs metadata across processes (first and second `find` identical — observed, not
assumed), so virtiofs is not the ceiling; the filter's margin over that honest baseline is
**~4–13×** (walk+stat 760 vs 57 µs; `ls -lR` 6.1 vs 0.63 ms), and the invariant forbids precisely
the caching the raw bind enjoys.

- [ ] **Profile where the ~700 µs goes.** With the VM's virtiofs cache warm underneath the daemon,
  the backing syscalls should be tens of µs, yet a filtered stat costs ~760 µs. Suspects: the
  container→daemon FUSE hop itself, model B's full-path `openat2` re-resolution per op, per-op fd
  open/close, and the single-threaded session serializing round trips. Candidate fix if resolution
  dominates: parent-directory fd reuse *within one operation*, never a cache across operations.
- [ ] READDIRPLUS — batches lookup+getattr for the walk itself. Expect it to help getdents-shaped
  traffic and not `ls -lR`-shaped: under TTL 0 the attributes it returns expire immediately, so
  follow-up per-file stats still round-trip. Measure before and after.
- [ ] Multi-threading (`Config::n_threads`, `clone_fd`) — parallel clients stop serializing.
- [ ] `FUSE_PASSTHROUGH` for bulk data, capability-checked with a userspace fallback.
- [ ] The control puts the gap in the invariant rather than the backing, so research
  push-invalidation coherency: nonzero kernel TTLs kept *correct* by the daemon watching the backing
  (inotify inside the VM) and issuing `notify_inval_entry`/`notify_inval_inode` — the control
  numbers show what caching buys (57 µs stats). Only sound if watches see host-side virtiofs
  writes — verify that premise first; if they do not, this path is closed and the invariant's cost
  is the price of correctness.

Every one of these must keep the coherency invariant intact: performance is bought with parallelism,
batching, push-invalidation and a shorter per-op path, never with an unrevalidated cache TTL.


## P2 — Diagnostics

What exists: the symptom-keyed guide (`troubleshooting.md`); a startup banner and `t=<unix-secs>`
on every `DENY` line in `daemon.log`; the previous daemon's log kept as `daemon.log.1`; reasoned
messages on every launch gate; and a bounded deny log — full lines up to 10,000, then a cap notice,
then a counted summary every thousandth denial, so a hostile agent's refusal spam costs a few MB and
the trail loses detail past the cap, never magnitude (`fs.rs`, `deny_log_action`). The gap:

- [ ] Op-level tracing behind a flag (`--trace`?), for the performance profiling above and for
  diagnosing hangs — off by default, never in the launcher's normal invocation.


## P2 — Launcher and deployment integration

The pipeline runs end to end. `--build` compiles the binary from bundled source in a pinned
`rust:slim` container (static musl, `cargo-deny` as the licence gate in the same build), stamps it
with the digest of that source, installs it where the daemon must run, and proves the whole stack
there with `--self-test`; each launch re-checks the digest and re-runs the self-test before mounting
the project. Every failure path — absent binary, wrong version, failed self-test, failed mount,
non-empty mountpoint — aborts the launch, and no fallback to an unfiltered bind mount exists in the
code. `architecture.md` ("Build and install") and `AgentSandboxLauncher` ("The workspace-filter
mount lifecycle") carry the mechanics; the static-musl link constraint that forces the raw
`SYS_renameat2` syscall is recorded where it binds, in `fs.rs`.

Two delivery decisions, so they are not relitigated:

- **Install into the VM rather than run a FUSE sidecar container.** Rootless podman cannot propagate
  a container-made mount up to where the sandbox's bind source resolves, while an ordinary VM user
  can mount through the setuid `fusermount3` (fuser's pure-Rust fallback).
- **No supervisor watching the daemon.** A daemon that dies mid-session makes every access fail
  `ENOTCONN` at `stat` — no partial listing, no cached tree, no fallback to an empty directory or
  the raw one — scoped to `/workspace` alone, and even shells die at spawn because their cwd is
  inside the dead mount. The failure is already total, loud and fail-closed, so outside machinery
  would only convert one obvious dead session into another; the user exits and the reaper cleans up.

The filter became the **default** enforcement on every platform ahead of that verification, so the
opt-in wording is gone from `README.md`, `SECURITY.md`, `architecture.md` and the probes, and
`KO_AGENT_SANDBOX_NO_FUSE_FILTER` is the way back to the pin. What that leaves:

- [ ] `SECURITY.md` still carries the filter under **Not defended**, now headed by the honest
  caveat — verified on macOS, reasoned elsewhere. When Linux and Windows have their rows, the
  passage moves under **Defended** and replaces the mount-pin entry it supersedes.
- [ ] The guard refuses to serve a repository whose hooks resolve inside the workspace, and refuses
  two undecidable configs with them: a `core.hooksPath` beginning with `~`, and a repository-local
  `include`/`includeIf`. As an opt-in that refusal only reached people who asked for it; as the
  default it means a project that launched yesterday does not launch today, and the remedy is to
  edit one's own `.git/config`. Decide whether that is acceptable, or whether those two cases should
  fall back to the pin rather than refuse.


## Deferred research

Timed to the increment that needs it, so the findings are fresh when they are used.

- [ ] `fuse-backend-rs` (virtiofsd, Cloud Hypervisor) versus `fuser` — before investing in
  passthrough, since it is the more battle-tested passthrough implementation.
- [ ] gVisor's gofer and virtiofsd as prior art for fd-relative, TOCTOU-safe passthrough at scale.
- [ ] Podman-machine virtiofs cache modes, alongside the coherency premise above.
- [ ] Landlock to confine the daemon itself, so a bug in `ko-agent-fs` can reach only the backing
  directory. Defense in depth, not a boundary — the boundary is the policy.


## Non-TODOs — settled, do not reopen without new evidence

- **A Unicode normalization library in the policy core.** `.git` is pure ASCII, so a
  normalization-insensitive backing creates no collision (`git-metadata.md`, "The name rule").
  Settled by research, pinned by a test.
- **Mirroring a filesystem's case-fold table.** NTFS's is per-volume; the exact set is not
  statically knowable. Conservative superset plus the empirical test above, instead.
- **`RESOLVE_NO_XDEV`.** A mount the host placed inside the workspace should stay visible; crossing
  into it is lateral, and `RESOLVE_IN_ROOT` already blocks escaping above the root.
- **Guarding against inode reuse under `forget`.** Model B reuses an inode number for a recreated
  `(parent, name)`, which is safe because context and resolution are path-derived rather than tied
  to the backing inode's identity. A backing mount point makes `readdir`'s reported `d_ino`
  cosmetic; harmless.
- **`FOPEN_DIRECT_IO` for coherency.** It would work, and it disables shared `mmap`, which git needs
  for `.git/index` and packfiles. `AUTO_INVAL_DATA` gets coherency without that cost.
- **A cache TTL as a performance knob.** Real-time bidirectional visibility is the defining
  requirement; a nonzero TTL trades correctness for speed. Invariant, not a tunable.
- **Making `ko-agent-fs` a general sandbox filesystem.** The narrow boundary is what makes it
  auditable (`architecture.md`, "What stays out of the audited core").
