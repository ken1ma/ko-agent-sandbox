# `ko-agent-fs` architecture

How the filter is built, and the alternatives weighed on the way. This document is the *how*.

- The *what* it must enforce is `../../policy/doc/git-metadata.md`, plus one rule that is not
  about git: since the host reads this directory too, `symlink` refuses to *create* a link whose
  target is absolute or climbs above the workspace root.
  - That rule tests syntax conservatively; it does not judge meaning.
  - It applies when a link is created, not to links already in the tree: `rename` and `link` do
    not judge an existing link again (`fs.rs`, `target_has_portable_syntax`, which states both
    limits and measures the cost on sbt 2).
- The decisions here were taken for one workload: a sandbox that compiles large Scala projects
  over a workspace the host edits at the same time. Such a project has hundreds of thousands of
  files, and `sbt`, `bloop` and `metals` stat them in storms.


## Mediation mechanism: a FUSE view

The filter shows the workspace to the container as a FUSE mount, and enforces the policy on the
operations the kernel forwards. Three other mechanisms were considered and rejected:

- **AppArmor on the container** — its path-based rules express the policy naturally: allow normal
  reads and writes on the bind-mounted workspace, deny creating `.git` entries and writing Git hook
  and configuration paths.
  - Rejected for the environment, not for what it can express. On macOS and Windows the
    containers run inside the default podman machine, and its Fedora-based images do not provide
    AppArmor.
  - Using it would need a dedicated machine with an AppArmor-capable kernel and the policy loaded,
    not the user's normal default machine.
- **fanotify pre-content permission events** (Linux 6.14) — allow or deny access on the real mount,
  with no FUSE. A partial fit:
  - Its permission model decides *access to existing content*.
  - It does not cleanly express the rule we need most: *refusing to create an entry named `.git`*.
- **BPF-LSM** — hook `security_inode_create`/`rename`/`link`/`setattr` and deny by name in the
  kernel. Elegant, and at native speed.
  - Rejected for the filter's design, for the three reasons below.
  - `../../../doc/bpf-lsm-cgroup.md` ("The recorded decisions this answers") has since answered
    each of them:
    - `BPF_LSM_CGROUP` programs attached to the session's own cgroup give the asymmetry in the
      kernel;
    - a probe at every launch answers the configuration risk;
    - the C classifier is compiled for the host and run through the policy package's corpus
      (`../../policy/tests/bpf_equivalence.rs`).
  - That backend is `--workspace=live,bpf` on the podman machines. The filter stays the default of
    both modes until the release decision `../../../doc/TODO.md` plans ("The BPF backend as the
    default").

The deciding requirement is the **host/container asymmetry**: the container's view is filtered, and
the host's direct writes to the same files are not (`../../policy/doc/git-metadata.md`, "What this
intentionally does *not* protect, and why that is safe").

- FUSE gives this natively. The filtered view is a *separate mount that only the container
  binds*. The host reaches the backing tree by another path, which the filter never sees.
- fanotify and BPF-LSM instead hook the backing objects for every process in the VM. To keep the
  asymmetry, they must leave the host out by cgroup or mount-namespace scoping: code to write for
  a property FUSE gives for free.
- FUSE also keeps the portability `SECURITY.md` ("The workspace filter") rests the choice on: it
  "works wherever the VM does".
- FUSE stays plain, auditable Rust. A BPF policy program needs `CONFIG_BPF_LSM` and the active LSM
  list, and whether those are enabled is itself an environment risk.

So FUSE is the mechanism: chosen against the alternatives, not taken by default.


## Inode model: path + `openat2(RESOLVE_IN_ROOT)`

FUSE addresses objects by inode number and `(parent_ino, name)`, never by path, so an inode table
is unavoidable. The table holds the minimum needed to rebuild a position:

```
Inode { parent: u64, name: OsString, nlookup: u64, git: GitContext, rule: RuleContext,
        dev: u64, ino_id: u64 }
```

- **Resolution.** To act on an inode, the filter:
  - walks its parent chain to the root, collecting names (the depth is small: tens at most);
  - opens the parent directory with `openat2(root_fd, relative_path, RESOLVE_IN_ROOT | O_PATH)`;
  - performs the last component's operation with an `*at` call on that parent fd and the name.

  The kernel walk never resolves the last component. So a final symlink is not followed, and the
  `.git` name rule sees the exact name.
- **Why this is TOCTOU-safe, not a naive path join.** `RESOLVE_IN_ROOT` makes the kernel resolve
  the walk in between atomically, with containment that cannot be escaped: `..` stops at the
  backing root. No `backing_root.join(user_path)` string is ever passed to an ordinary syscall.
  - It is the primitive meant for this (`../../policy/doc/security-research.md`, "FUSE correctness
    & openat2 semantics").
  - `fs.rs`, `open_ino`, states the remaining resolve flags where it sets them, with the bounded
    `EAGAIN` retry that a concurrent rename forces.
- **Coherency.** The filter resolves against the live backing tree on every operation. So a name
  resolves as the host's tree has it at the moment of the call, which matches "correctness over
  caching".
  - "Coherency: zero-cache is a correctness requirement", below, has the guarantee for attributes
    and data, with its two exceptions.
  - The cost: a stored path stops naming its inode once the tree moves. Either side can move it,
    and no later lookup repairs it, because the kernel keeps addressing a renamed directory by the
    inode it holds instead of looking up the new name.
  - `RESOLVE_NO_SYMLINKS` and an identity comparison make that merely stale, not wrong. The chain
    resolves to the object the node was classified as, or it fails (`fs.rs`, `open_ino`):
    - with `ELOOP` through a symlink;
    - with `ESTALE` at another object. Without the check, a second name of a guarded entry would let
      an ordinary chain reach that object.
  - The alternative, one fd per inode, trades the staleness for a quirk of its own: an fd to a
    subtree renamed away keeps operating on the moved inode. It also holds one open fd per live
    inode, which at 100k files is real fd pressure. The path model holds one fd for the root, and
    short-lived fds per operation.
- **Backing identity, so a replacement is a new inode.** `dev`/`ino_id` are the
  `(st_dev, st_ino)` that the position named when the entry was allocated. `lookup` stats the name
  again, and reuses the entry only when the identity still matches. When the host replaces the
  object, leaving a different object at the same name, the name moves to a newly allocated inode
  number for the new object (`inode.rs`, `lookup`).
  - This keeps the FUSE inode identity following the *object*, not just the name.
  - Without it, the kernel keeps one inode, and one page cache, across the replacement.
    `AUTO_INVAL_DATA` cannot help: it invalidates on a change of size or mtime. A replacement with
    equal size and mtime (`tar -x`, `cp -p` and `touch -r` all make one) would serve the old
    object's cached pages to a reader of the new one.
  - A new inode gets a new, empty page cache, so the read shows the new object.
  - A descriptor opened before the replacement is not affected. It keeps addressing the object it
    opened, as POSIX open-file semantics require:
    - it reads and writes through its own backing fd (`fs.rs`, `read`/`write`);
    - an attribute or truncate request carrying its handle acts on that fd too (`fs.rs`,
      `getattr`/`setattr`).
  - The old number is only detached from the name, not dropped. That descriptor, and any child it
    holds, still rebuild the path they always did (the stale-path resolution `RESOLVE_NO_SYMLINKS`
    guards). The kernel forgets the number in its own time.

### Bounded memory and the O(1) policy fast-path (the scale constraints)

At hundreds of thousands of files the two risks are the table's growth and the policy's cost per
operation:

- **`forget` is honored.** Each `lookup` or `entry` reply increments `nlookup`. `forget(ino, n)`
  decrements it and drops the entry at zero. The live table stays bounded by what the kernel
  caches: tens of MB, not a leak that grows with every file the compiler ever stat'd.
- **`git` and `rule` are cached, incremental contexts.** `lookup` computes both once, from the
  parent's context and this name, never by walking again. Every mutation is checked against both:
  the Git policy first, then the file rules (`fs.rs`, `allow_child` and `allow_ino`).
  - `GitContext` is O(1). Nearly all files in a Scala build are outside any `.git`. Their context
    is a single "not in a gitdir" tag, and the Git policy allows every mutation on them without a
    path scan. The Git policy does real work only inside a gitdir, a tiny fraction of the
    operations.
  - `RuleContext` costs a lookup one name comparison per file-rule line (`policy.rs`,
    `child_rule_context`). A mutation reads the cached context (`authorize_rule`).
  - The name is not always the one the session used. An entry that is the same backing object as
    the `.git` or `.ko-agent-sandbox` beside it takes that name's context (`fs.rs`, `policy_name`;
    `../../policy/doc/security-research.md`, "Windows 8.3 short names", explains why).
    - Outside a gitdir, that costs a lookup two `fstatat` calls, and an operation on a parent and a
      name one more.


## Data path: userspace I/O, and the `FUSE_PASSTHROUGH` accelerator it does not use

The daemon serves reads and writes from userspace. **`FUSE_PASSTHROUGH`** could take over once the
mediation is proven:

- It exists in Linux 6.9, and in fuser 0.18 as `FUSE_DEV_IOC_BACKING_OPEN` /
  `ReplyOpen::opened_passthrough`, in pure Rust with no libfuse.
- At `open`, it registers an *allowed* file's backing fd with the kernel. Bulk reads and writes
  then bypass the daemon at native speed.

- **It would not weaken the boundary.** The security decision is made at `open`, `create` and
  `rename`, and all of them stay mediated. The daemon would hand back a passthrough fd only for an
  open the policy allowed, in the mode it allowed. A hooks or config target is refused at open, so
  it would never get one.
- **It is an accelerator, not a correctness requirement.** The mount would check the kernel for
  passthrough, and fall back to userspace I/O where the kernel lacks it. Mediation is the same
  either way, and fails closed either way.
- **It does not address the main cost.** At Scala-compile scale, the bottleneck is the rate of
  metadata operations (`lookup`, `getattr`), which passthrough does not touch. See the caching
  section below.


## Coherency: zero-cache is a correctness requirement

Real-time visibility in both directions is the project's defining requirement. A copy-back overlay
was rejected at the start.

- A FUSE attribute or entry cache with a nonzero TTL lets the kernel answer from a stale attribute
  without asking the daemon. A host edit then stays invisible until the TTL expires.
- A build program that keys on mtime would miss the change and compile stale content: a
  correctness failure, not a slow path.
- The guarantee has a scope. An answer inside the sandbox is the *backing's* state at the moment of
  the call: never older, and never fresher than the backing itself. Two data-cache exceptions
  remain that the mechanism below cannot reach; it states them.

So these are fixed, not settings:

- The entry, attribute and negative-entry TTLs are **0**, always.
- Writeback caching is **off**: it would let the kernel hold writes the host cannot see.
- **`AUTO_INVAL_DATA`** is negotiated at `init`. A kernel that cannot offer it gets no mount:
  `init` returns `ENOTSUP`, the daemon dies at the handshake, and the launch fails with the daemon
  log. The filter never serves a view that can go stale.
  - Zero metadata TTL keeps *attributes* fresh. But a file's cached *data* pages could still lag
    behind a host write: a `read` served from the page cache, or an `mmap`.
  - `AUTO_INVAL_DATA` makes the kernel drop cached pages when a `GETATTR` reports a change of size
    or mtime. Data then stays coherent, and shared `mmap` keeps working, when the change moves an
    attribute and a `GETATTR` looks.
  - A *replacement* with equal size and mtime moves no attribute. But it is a different object, so
    the identity check above gives it a new inode and an empty cache.
  - Two cases remain that nothing here reaches. Both come with `AUTO_INVAL_DATA`, and both are
    narrow:
    - an *in-place* edit of one object that restores its size and mtime (a same-length overwrite,
      then `touch -r`). It is the same object, so no new inode, and no attribute changes, so no
      invalidation. A cached `read` can serve the old bytes.
    - a mapping read purely through memory, with no `read` or `stat` in between. The invalidation
      depends on a `GETATTR`, and a page fault sends none, so an already-cached page can lag until
      some call does. The self-test's share probe reads before it checks the mapping. Its `mmap`
      row therefore measures invalidation after a read, not a mapping left entirely to itself.
  - Negotiating it is not the same as it working. `--self-test` measures the invalidation itself in
    the self-test container, and its share rows measure it across the real host share.

Zero cache has a measured price: with entry TTL 0, every path component of every syscall is a new
LOOKUP round trip.

Performance comes back only by means that keep every answer fresh: batching, parallelism and a
shorter path per operation, never a cache. `verification-log.md` ("The cost of a path walk") has
the measurements, and `TODO.md`, "Performance", the open rows. In place:

- **A directory snapshot per `opendir`** — `fs.rs`, `opendir`: a stable scan, not a cache.
- **A minimal path per operation** — a path-based getattr is one `openat2` from the root and one
  `fstat` on the live backing, the one the identity comparison makes (`fs.rs`, `open_ino`). The
  cached Git and rule contexts keep a mutation's policy check free of a path scan.

The layer beneath matters too. The backing tree is itself the host share (virtiofs on a podman
machine).

- TTL 0 makes *our* view read the backing again on every access. Coherency end to end also needs
  that backing to show host writes promptly: that is the virtiofs mount's own cache mode.
- TTL 0 is necessary. On macOS it is also the only cache policy in the path: the guest kernel
  caches nothing over virtiofs (`verification-log.md`, "the virtiofs layer itself").
- That is a measurement of one hypervisor, to repeat after a podman or macOS upgrade, not a
  property of the design.


## Who may reach the mount

The mount is made with `allow_other` (fuser's `SessionACL::All`) and `default_permissions`.

Otherwise FUSE admits only a process whose uids and gids all equal those of the process that
mounted (`fs/fuse/dir.c`, `fuse_allow_current_process`). The container runtime is not such a
process:

- keep-id maps the session's user onto the daemon's, but the container runtime reaches the mount
  first, and as another uid.
- crun stats the workspace bind as the root of the container's user namespace, which keep-id maps
  to a subordinate uid of the daemon's user.
- Without `allow_other` that stat is refused, and no container starts (`verification-log.md`,
  "Mount privilege: what a container grants").

Widening *who may reach* the mount does not widen *what they may do*:

- `default_permissions` keeps the kernel applying ordinary uid/gid/mode checks against the real
  backing metadata.
- The Git policy and the file rules are enforced whoever asks.
- Where the mount is bound limits the exposure. The launcher binds a workspace's mount into that
  workspace's sessions only, so another workspace's session on the same machine has no path to it.

A workspace has one daemon and one mount, shared by all its sessions:

- Concurrent sessions read and write the same files, and can overwrite each other's changes.
- If the daemon dies, the workspace mount returns `ENOTCONN` in every attached session, so none
  can keep using the files through the mount.
- When the workspace's last session ends, the daemon unmounts and exits.

The other two modes:

- Staged mode also has one view per workspace. Attached sessions share its merged view, upper
  layers, locks, cache and failure domain.
  - The staged view is not implemented. The root `doc/plan-staged.md` plans it, and the root
    `doc/TODO.md` keeps the deferred work.
  - This topology is fixed before that work starts all the same. Per-session mounts would make a
    cheap restart expensive, and give collaborating sessions incoherent locks and caches.
- Read-only mode creates no FUSE mount and runs no filter daemon. With `--run-on-host` it runs
  `ko-agent-fs --resolve` once, for the file rules the host commands observe (the launcher's
  `KoAgentFs.koAgentFsResolveScript`).

`allow_other` from an unprivileged user also needs `user_allow_other` in `/etc/fuse.conf`, which
stock images do not set. The launcher adds it only with the user's consent, never silently:
`SECURITY.md`, "Silent changes to what you own", has the rule, and `ensureUserAllowOther` runs it.


## Build and install

Elsewhere:

- The trust rationale is the repository's `SECURITY.md` ("The workspace filter"): what an auditor
  relies on, and how the identity check closes each link.
- What a machine admin sees `--build` do, and how to undo it, is its `README.md` ("`--build`").

This section is the build and installation steps:

1. **`sbt dist`** bundles `ko-agent-fs/**` into the jar next to the container build contexts.
   - It leaves out the `doc/` and `probe/` directories and `bench/`. None of them is a build input
     or distribution (`build.sbt`), so editing one cannot change the digest below.
   - A jar's resource tree cannot be listed at runtime, so an `INDEX` lists what is there.
2. **`--build`** unpacks that bundle to a temporary directory and runs `podman build` from it
   (`ImageBuilds.unpackBuildContext`, `buildCommands`; the ko-agent-fs half is `KoAgentFs.scala`).
   For this image, the launcher first digests the bundled source the image copies (the workspace's
   files, `policy/` and `fuse/`), and passes the digest in:

       podman build --target build --build-arg KO_AGENT_FS_SOURCE_ID=<digest> \
           -t ko-agent-fs-build:cache ko-agent-fs
       podman build --build-arg KO_AGENT_FS_SOURCE_ID=<digest> \
           -t ko-agent-fs:latest ko-agent-fs

   - One image builds both binaries under that one digest. The filter links the policy package, so
     a policy edit rebuilds both either way.
   - The build checks licenses (`../../deny.toml`) before it produces the binaries.
   - The test suites run in the separately built `ko-agent-self-test` image
     (`../../doc/testing.md`).
3. **Extract the binaries.** The image's final stage is `scratch`, holding only `/ko-agent-fs`, the
   policy's, and `/ko-agent-fs-fuse`, the filter's. So nothing else is taken:

       podman create --name <tmp> ko-agent-fs:<tag>
       podman cp <tmp>:/ko-agent-fs <install-dir>/ko-agent-fs
       podman cp <tmp>:/ko-agent-fs-fuse <install-dir>/ko-agent-fs-fuse
       podman rm <tmp>

4. **Put them where the daemon must run.** The destination is `~/.local/share/ko-agent-sandbox/`,
   relative to the home of whoever the daemon runs as. It is relative on purpose, so no
   per-platform absolute path is needed. *Whose* home it is differs by platform, and is the part
   worth understanding:
   - *native Linux* — there is no VM. The filter runs on the host, so the extraction above writes
     straight into the host user's home.
   - *macOS / Windows* — the filter runs **inside the podman machine**, because the workspace's
     backing filesystem is there. The image is already in the VM's image storage, so the extraction
     runs *there*, through `podman machine ssh`, which writes to the VM user's home, whoever that
     is. A plain `podman cp` on the host would put it on the host.
5. **Verify what was installed.** The launcher compares each installed binary's `--version` with
   the digest of the source it bundles (`../../Containerfile`, header).

The digest's construction, and why the algorithm exists only on the launcher side, are with the
code: `LauncherImages.bundleSourceId`.

**All steps run from `--build`** (`ImageBuilds.buildCommands`, `KoAgentFs.koAgentFsSourceId` and
`installKoAgentFs`). **The mount lifecycle runs in every `--workspace=live` session**;
`--workspace=read-only` binds the tree read-only without it.

- Each launch checks the installed filter's identity and self-test.
- It then mounts the workspace through a per-workspace daemon that its sessions share, and binds
  the mountpoint at the workspace root's own path.
- The lifecycle's design and reasoning are with the code: `KoAgentFs.scala`, "The workspace FUSE
  filter's mount lifecycle".

The daemon needs no privileges to mount:

- fuser's pure-Rust mode falls back to the setuid `fusermount3` when a direct `mount(2)` is
  refused. An ordinary VM user's mount then appears in their session namespace, exactly where
  rootless podman resolves bind sources.
- This is also why the filter is installed into the VM, not run as a FUSE sidecar container. Under
  rootless podman, a mount made *inside* a container does not propagate up to where the sandbox's
  bind could see it.


## What stays out of the audited core

The policy decisions are in `../../policy/src/policy.rs`, which has no dependencies and judges
positions only.

- Everything else here is the untrusted FUSE layer around it: the inode table, the resolver, the
  fuser bindings, passthrough, cache tuning.
- The FUSE layer decides *where* an operation is. `policy.rs` decides *whether* it is allowed,
  except for the symlink-target refusals that `fs.rs` makes itself (`allow_symlink_target`,
  `symlink`).
- Keeping that split strict keeps the authorization rules auditable at 100k-file scale, where the
  FUSE layer is necessarily busy.
- `../../policy/src/bpf_records.rs` decides nothing either. It renders the resolved rules and the
  guard's findings as the map records of the BPF backend (`../../bpf/doc/architecture.md`, "The
  policy").

The line is worth reading precisely, because *where* is not always a function of the names:

- Under `<gitdir>/modules` it is not. A submodule's name defaults to its path, so the same path can
  be a gitdir root or a namespace above one, and only the tree can tell
  (`../../policy/doc/git-metadata.md`, "Positional, not string-based").
- The FUSE layer answers that one question, with `fs.rs`, `is_gitdir_root`: a single `fstatat` for
  a `HEAD`. It hands the answer over.
- Every rule that uses the answer stays in `policy.rs`, where it can be unit-tested exhaustively.
- An error, or no answer, leaves the strict reading. So the FUSE layer can only ever narrow what
  the core would otherwise allow.
