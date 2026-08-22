# `ko-agent-fs` architecture

How the filter is built, and the alternatives weighed on the way. The *what* it must enforce is
`git-metadata.md` — plus one rule that is not about git: since the host reads this directory too,
`symlink` refuses to *create* a link whose target is absolute or climbs above the workspace root.
That is a conservative shape rather than a judgement about meaning, and it binds at creation rather
than over links in the tree — `rename` and `link` do not re-judge one already created (`fs.rs`,
`target_has_portable_shape`, which states both limits and measures the cost on sbt 2). This is the
*how*. Decisions here were taken with the workload in mind: a sandbox compiling large Scala
projects — hundreds of thousands of files, `sbt`/`bloop`/`metals` stat-storming the tree — over a
workspace the host edits concurrently.


## Mediation mechanism: a FUSE view

The filter presents the workspace to the container as a FUSE mount and enforces policy on the
operations the kernel forwards. Three other mechanisms were considered and rejected:

- **AppArmor on the container** — its path-based rules express the policy naturally: allow normal
  read/write on the bind-mounted workspace while denying creation of `.git` entries and writes to
  Git hook and configuration paths. Rejected for environment, not expressiveness: on macOS and
  Windows the containers run inside the default Podman machine, whose Fedora-based images do not
  provide AppArmor, so using it would require a dedicated machine with an AppArmor-capable kernel
  and the policy loaded — not the user's normal default machine.
- **fanotify pre-content permission events** (Linux 6.14) — gate access on the real mount, no FUSE.
  Its permission model gates *access to existing content*; it does not cleanly express the invariant
  we most need, *refusing creation of an entry named `.git`*. Partial fit.
- **BPF-LSM** — hook `security_inode_create`/`rename`/`link`/`setattr` and deny by name in-kernel.
  Elegant and native-speed, and the alternative to revisit if constraints change. Rejected for the
  three reasons below.

The deciding requirement is the **host/container asymmetry**: the container's view is filtered, the
host's direct writes to the same files are not (`git-metadata.md`, "Host modifications bypass the
filter"). FUSE delivers this natively — the filtered view is a *separate mount only the container
binds*, while the host reaches the backing tree by another path the filter never sees. fanotify and
BPF-LSM instead hook the backing objects for every accessor in the VM, so preserving the asymmetry
means carving the container out by cgroup/mount-namespace scoping — surface for a property FUSE
gives for free. FUSE also keeps the "works wherever the VM does" portability `SECURITY.md` ("The
workspace filter") rests the choice on, and stays plain auditable Rust rather than a BPF policy
program whose enablement (`CONFIG_BPF_LSM`, the active LSM list) is itself an environment risk. So
FUSE is the mechanism — chosen against the alternatives, not defaulted into.


## Inode model: path + `openat2(RESOLVE_IN_ROOT)` (model B)

FUSE addresses objects by inode number and `(parent_ino, name)`, never by path, so an inode table is
unavoidable. The table is the minimum that reconstructs a position:

```
Inode { parent: u64, name: OsString, nlookup: u64, git: GitContext }
```

- **Resolution.** To act on an inode, walk its parent chain to the root collecting names (depth is
  small — tens at most), then `openat2(root_fd, relative_path, RESOLVE_IN_ROOT | O_PATH)` for the
  parent directory, and perform the final-component operation with an `*at` call on that parent fd +
  name. The final component is never resolved by the kernel walk, so a final symlink is not followed
  and the `.git` name rule sees the exact name.
- **Why this is TOCTOU-safe, not a naive path join.** `RESOLVE_IN_ROOT` makes the kernel resolve the
  intermediate walk atomically with escape-proof containment — `..` is clamped to the backing root,
  no `backing_root.join(user_path)` string is ever handed to an ordinary syscall. It
  is the sanctioned primitive for this (`security-research.md`, "FUSE correctness & openat2
  semantics"). The remaining resolve flags, and the bounded `EAGAIN` retry a
  concurrent rename forces, are stated where they are set: `fs.rs`, `open_ino`.
- **Coherency.** Re-resolving against the live backing tree every op means the filter never serves a
  stale view of what the host wrote — matching "correctness over caching". Its cost is a stored
  path that stops naming its inode once the tree moves, which either side may do and no later
  lookup repairs: the kernel goes on addressing a renamed directory by the inode it holds rather
  than looking the new name up. `RESOLVE_NO_SYMLINKS` is what makes that merely stale instead of
  wrong — the chain then resolves to whatever now bears those names, which those same names
  classify, or it fails (`fs.rs`, `open_ino`). The fd-per-inode alternative trades the staleness for
  its own mirror quirk (an fd to a renamed-away subtree keeps operating on the moved inode) plus one
  open fd per live inode, which at 100k files is real fd pressure. Model B holds one fd for the root
  and transient fds per op.

### Bounded memory and the O(1) policy fast-path (the scale constraints)

At hundreds of thousands of files the two risks are table growth and per-op policy cost:

- **`forget` is honored.** Each `lookup`/`entry` reply increments `nlookup`; `forget(ino, n)`
  decrements and drops the entry at zero. The live table stays bounded to what the kernel caches —
  tens of MB, not a leak that grows with every file the compiler ever stat'd.
- **`git` is a cached, incremental context.** `GitContext` is computed once at `lookup` from the
  parent's context plus this name (O(1)), never by re-walking. The overwhelming majority of files in
  a Scala build are outside any `.git`, so their context is a single "not in a gitdir" tag and every
  mutation on them takes an immediate allow — no classification, no path scan. The policy core only
  does real work inside a gitdir, which is a vanishing fraction of the op stream.


## Data path: userspace first, `FUSE_PASSTHROUGH` later

Reads and writes are served from userspace in the first correct version. Once mediation is proven,
**`FUSE_PASSTHROUGH`** (Linux 6.9; present in fuser 0.18 as `FUSE_DEV_IOC_BACKING_OPEN` /
`ReplyOpen::opened_passthrough`, pure Rust, no libfuse) registers an *allowed* file's backing fd
with the kernel at `open`, after which bulk read/write bypass the daemon at native speed.

- **It would not weaken the boundary.** The security decision is made at `open`/`create`/`rename`
  time, all of which stay mediated; a passthrough fd would be handed back only for an open the
  policy authorized, in the mode it authorized. A hooks or config target is denied at open, so it
  would never get one.
- **It is an accelerator, not a correctness requirement.** The mount would capability-check
  passthrough and fall back to userspace I/O where the kernel lacks it, so mediation is unaffected
  either way and fails closed regardless.
- **It does not address the dominant cost.** At Scala-compile scale the bottleneck is metadata
  op-rate (`lookup`/`getattr`), which passthrough does not touch — see caching below.


## Coherency: zero-cache is a correctness invariant

Real-time bidirectional visibility is the project's defining requirement — a copy-back overlay was
rejected at the outset. A FUSE attribute/entry cache with a nonzero TTL lets the kernel answer from
a stale attribute without re-asking the daemon, so a host edit stays invisible until the TTL
expires. A build tool keying on mtime would then miss the change and compile stale content — a
correctness failure, not a slow path. Therefore, as invariants and not tunables:

- entry, attribute, and negative-entry TTLs are **0**, always;
- writeback caching is **off** (it would let the kernel hold writes the host cannot see);
- **`AUTO_INVAL_DATA`** is negotiated at `init`, and a kernel that cannot offer it gets no mount:
  `init` returns `ENOTSUP`, the daemon dies at the handshake, and the launch fails with the daemon
  log rather than serving a view that can go stale. Zero metadata TTL keeps *attributes* fresh, but
  a file's cached *data* pages (a `read` served from the page cache, or an `mmap`) could still lag a
  host write. `AUTO_INVAL_DATA` makes the kernel drop cached pages when it sees mtime change — which
  the zero-TTL getattrs surface — so data stays coherent while shared `mmap` keeps working.
  Negotiating it is not the same as it working: `--self-test` measures the invalidation itself, and
  `probe/coherency-probe.py` measures it across the real host share.

The invariant has a measured price: with entry TTL 0, every path component of every syscall is a
fresh LOOKUP round trip. `TODO.md`, "Performance", carries the measurements and what is left to
profile.

Performance at 100k-file scale is recovered only by means that keep every answer fresh:

- **READDIRPLUS** — a directory scan returns each entry's attributes in one round-trip, collapsing
  the walk's lookup+getattr storm into one op per directory, each attribute freshly `fstatat`'d at
  scan time. Under TTL 0 its attributes expire as they arrive, so it accelerates the walk itself,
  not the per-file stats a tool issues afterwards — those still round-trip by design.
- **A directory snapshot per `opendir`** — the entry *names* are read once into the handle rather
  than the directory being re-read on every `readdir` call. This is a correctness fix first (a scan
  can no longer skip or duplicate entries when the tree moves under it, and POSIX leaves the
  visibility of concurrent additions unspecified for exactly this reason), and it removes an O(n²)
  re-read besides. It is not a cache: the next `opendir` sees the new state, and attributes stay
  live at TTL 0.
- **A multi-threaded daemon** (fuser `Config::n_threads` / `clone_fd`) — concurrent ops run in
  parallel; parallelism, never caching.
- **A minimal per-op path** — a getattr is one `fstatat` on the live backing, and the O(1)
  git-context fast-path keeps non-`.git` ops free of policy work.
- **FUSE_PASSTHROUGH** for bulk read/write *data* (not metadata), later.

The layer beneath matters: the backing tree is itself the host share (virtiofs on a Podman machine).
TTL 0 makes *our* view re-read the backing on every access, but end-to-end coherency also needs that
backing to reflect host writes promptly — the virtiofs mount's own cache mode. TTL 0 is necessary;
the backing's coherency is a dependency to verify, not assume.


## Who may reach the mount

The mount is made with `allow_other` (fuser's `SessionACL::All`) and `default_permissions`.

FUSE otherwise confines a mount to the uid that made it, and the daemon and the sandbox are
different uids by construction — the daemon runs in the Podman machine, the container's uid is
namespace-mapped — so the default would make every access `EACCES`. The alternative, running the
daemon as whatever uid the container will present, would tie the daemon's identity to a container
that does not exist yet when the mount is made.

Widening *who may reach* the mount does not widen *what they may do*. `default_permissions` keeps
the kernel applying ordinary uid/gid/mode checks against the real backing metadata, and the Git
policy is enforced whoever is asking. Exposure is bounded by the machine running only this
project's containers.

Reach includes concurrency: a project has **one** daemon and one mount, and every session of that
project — concurrent ones included — binds the same mountpoint. The sharing semantics is exactly
the raw bind's (same files, live, racing like any two processes on one directory); what is new is
the shared fate — the daemon dying turns `/workspace` into `ENOTCONN` for all of that project's
sessions at once, fail-closed for each of them.

The staged workspace also has one view per project: attached sessions share its merged view, upper
layers, locks, cache and failure domain. Reject mode starts no `ko-agent-fs` process and creates no
FUSE mount. The staged view is not implemented yet; the root `doc/PLAN-STAGED.md` defines its
increment and the root `doc/TODO.md` keeps the deferred work. This topology is nevertheless
fixed before that work starts: per-session mounts would make a cheap restart expensive and give
collaborating sessions incoherent locks and caches.

`allow_other` from an unprivileged user additionally requires `user_allow_other` in
`/etc/fuse.conf`, which stock images do not set. Getting it there is consent-gated and never
silent: `SECURITY.md`, "Silent changes to what you own", carries the rule, and
`ensureUserAllowOther` is what runs it.


## Build and install

The trust rationale — what an auditor relies on, and how the identity check closes each link — is
the repository's `SECURITY.md` ("The workspace filter"); what a machine admin sees `--build` do,
and how to undo it, is its `README.md` ("`--build`"). This section is the mechanics:

1. **`sbt dist`** bundles `fuse/ko-agent-fs/**` into the jar next to the container build contexts,
   minus this `doc/` directory and `probe/`, neither of which is a build input or distribution
   (`build.sbt`) — so editing either cannot change the digest below. A jar's resource tree cannot be
   enumerated at runtime, so an `INDEX` lists what is there.
2. **`--build`** unpacks that bundle to a temporary directory and runs `podman build` from it
   (`AgentSandboxLauncher.unpackBuildContext`, `buildCommands`; the ko-agent-fs half is
   `KoAgentFs.scala`). For this image the launcher first
   digests the bundled source and passes the digest in:

       podman build --target build --build-arg KO_AGENT_FS_SOURCE_ID=<digest> \
           -t ko-agent-fs-build:cache ko-agent-fs
       podman build --build-arg KO_AGENT_FS_SOURCE_ID=<digest> \
           -t ko-agent-fs:latest ko-agent-fs

   The build gates on licences (`deny.toml`) before it produces a binary. The test suite runs in
   the separately built `ko-agent-self-test` image (`testing.md`).
3. **Extract the binary.** The image's final stage is `scratch` holding only `/ko-agent-fs`, so
   there is exactly one thing to take:

       podman create --name <tmp> ko-agent-fs:<tag>
       podman cp <tmp>:/ko-agent-fs <install-path>
       podman rm <tmp>

4. **Put it where the daemon must run.** The destination is
   `~/.local/share/ko-agent-sandbox/ko-agent-fs`, relative to the home of whoever the daemon runs
   as — relative on purpose, so no per-platform absolute path needs to be known. *Whose* home
   differs by platform, and is the step worth understanding:
   - *native Linux* — there is no VM; the filter runs on the host, so the extraction above writes
     straight into the host user's home.
   - *macOS / Windows* — the filter runs **inside the Podman machine**, because that is where the
     workspace's backing filesystem is. The image already lives in the VM's image storage, so the
     extraction is run *there*, through `podman machine ssh` (which lands in the VM user's home,
     whoever that is), rather than on the host where a plain `podman cp` would land it.
5. **Verify what was installed.** The launcher runs the installed binary's `--version`, reporting
   the source id stamped in at step 2, and compares it with the digest of the source it bundles. A
   binary that is not the one this launcher would build is replaced, not trusted.

The digest's construction, and why the algorithm exists only on the launcher side, live with the
code: `KoAgentFs.koAgentFsSourceId`.

**Wired up through step 5** (`AgentSandboxLauncher`: `koAgentFsSourceId`, `buildCommands`,
`installKoAgentFs` — all run by `--build`), **plus the mount lifecycle every session runs**
(unless `KO_AGENT_SANDBOX_WORKSPACE_GUARD` says otherwise — exactly `fuse` or `none`, so an
unclear value is a refused launch, never a silently weaker boundary): each launch gates on the
installed binary's identity and self-test, then mounts the project through a per-project daemon
shared by its sessions and binds the mountpoint at `/workspace`. The lifecycle's shape and
reasoning live with the code — `KoAgentFs.scala`, "The workspace FUSE filter's mount lifecycle".

The daemon needs no privileges to mount: fuser's pure-Rust mode falls back to the setuid
`fusermount3` when direct `mount(2)` is denied, so an ordinary VM user's mount lands in their
session namespace — exactly where rootless podman resolves bind sources. This is also why the
filter is installed into the VM rather than run as a FUSE sidecar container: under rootless podman
a mount made *inside* a container does not propagate up to where the sandbox's bind could see it.


## What stays out of the audited core

The policy decisions live in `src/policy.rs`, dependency-free and position-only. This document's
machinery — the inode table, the resolver, the fuser glue, passthrough, cache tuning — is the
untrusted plumbing around it. The plumbing decides *where* an op is; `policy.rs` alone decides
*whether* it is allowed. Keeping that line sharp is what makes the security surface auditable at
100k-file scale, where the plumbing is necessarily busy.

The line is worth reading precisely, because *where* is not always a function of the names. Under
`<gitdir>/modules` it is not: a submodule's name defaults to its path, so the same path can be a
gitdir root or a namespace above one, and only the tree can say (`git-metadata.md`, "Positional,
not string-based"). The plumbing answers that one question — `fs.rs`, `is_gitdir_root`, a single
`fstatat` for a `HEAD` — and hands the answer over; every rule that consumes it stays in
`policy.rs` and stays exhaustively unit-testable. An error, or no answer, leaves the strict
reading, so the plumbing can only ever narrow what the core would otherwise permit.
