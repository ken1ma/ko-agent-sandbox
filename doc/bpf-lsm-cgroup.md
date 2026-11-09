# The BPF cgroup-LSM backend

The FUSE backend makes metadata operations 6–18× slower than a plain bind mount on macOS
and 5–30× slower on Windows (`../ko-agent-fs/fuse/doc/verification-log.md`, "The cost of a path
walk"). Sessions through it have also frozen the podman machine.

The backend that `--workspace=<mode>,bpf` selects binds the workspace directly, and the kernel that
runs the containers enforces the policy:

- The policy is a set of BPF programs of type `BPF_LSM_CGROUP`, attached to the sandbox's own
  cgroup.
- The host and every other container keep unrestricted access to the same files.

This document states what the backend promises. `../ko-agent-fs/bpf/doc/architecture.md` says how
it keeps each promise, and `../ko-agent-fs/bpf/doc/evidence.md` what the suites measured on both
machines. The three documents use distinct section names, so a quoted section name without a
document refers to whichever of the three holds it.

What the first version covers:

- `NESTING=none` sessions on the podman machines, launched with the launcher's own seccomp profile.
  The kernel there is the machine's.
- A `--workspace=read-only` session there gets a policy that records no root ("The hooks",
  `file_receive`, explains why).
- `NESTING=same-uid` and `NESTING=user-namespace` sessions (`../SECURITY.md`, "No containers inside
  the sandbox by default") and native Linux hosts need `fuse` stated (`TODO.md`, "The BPF
  backend's later versions").
- `bpf` is the default of both modes ("Launches").
- No launch binds the workspace writable unless the policy is attached and verified.


## What the backend must hold

- The property `../ko-agent-fs/policy/doc/git-metadata.md` states: no sandbox write makes a later
  host `git` run a program the sandbox chose, or open an object directory it chose.
  - The backend takes that document's immutable set, its name rule, and its rename and link rules,
    which judge both sides.
  - One exception: a directory may be created and removed at any name, under the rules in
    "Directories".
- No non-directory entry is created inside a `.ko-agent-sandbox` at any depth, and nothing under
  one is written (`../SECURITY.md`, "A workspace loosening its own confinement"). "Directories"
  explains why directories may be created there.
- The file rules keep the files the host executes read-only, including the `read-only-path` lines
  the launcher resolves for relocated hooks and symlink aliases (`file-rules.md`).
- The policy applies to the sandbox's cgroup before any program of the image runs in the
  container: the entrypoint, `podman exec` processes, and OCI hooks that run in the container's
  namespaces. The container runtime's own processes are trusted, as the FUSE backend's daemon is.
- The threat is a process inside the sandbox. A VM administrator, a compromised podman or runtime,
  and whoever runs the controller are trusted; pinned links do not resist them.
- On Windows, the policy is what the WSL kernel enforces on container processes. It changes nothing
  about WSL as a boundary toward the Windows host
  (https://wsl.dev/technical-documentation/security/).

"What is gained and what is lost" lists what else the backend changes, in both directions.


## What a session can and cannot do

Under `--workspace=live,bpf` on a podman machine:

- Two sandboxes share the hook slots and have different policies. The policy never judges a third
  container, the egress proxy or the machine's own processes ("The mechanism").
- A `.git` or `.ko-agent-sandbox`, in any folded spelling, cannot appear at any depth through
  `creat`, `mknod`, `symlink`, `link`, `rename` or an exchange. For the ones `mkdir` makes
  ("Directories"):
  - such a `.git` never gets a `HEAD`;
  - a `read-only` line still covers what lies below it;
  - nothing but directories enters a `.ko-agent-sandbox`, at any position.
- A protected entry cannot be changed through any name, descriptor or mapping. The session cannot:
  - open it for writing, or truncate it;
  - change its owner, mode, times, xattrs, ACLs or `chattr` flags, or change it with a filesystem
    ioctl;
  - unlink it, or remove it unless it is an empty directory;
  - rename it, exchange it, hard-link it elsewhere, or replace it.

  Two limits:
  - The machines' shares answer the filesystem ioctls before any hook runs. A share or kernel that
    implements them reopens that route ("Attributes, flags and ioctls").
  - A second name the host gives a guarded file after launch is ordinary data to the policy. So is
    a second name it gives a nested repository's `.git` pointer file that belongs to no submodule
    ("The policy", the second-name rule).
- The file rules hold at any depth, with the resolved `read-only-path` lines. Git's everyday
  commands work, and the commands the FUSE backend blocks stay blocked and listed.
- Under `NESTING=none` with the launcher's profile ("Attributes, flags and ioctls", "Mounts"):
  - the session creates no user namespace, and no mount syscall succeeds;
  - no xattr or ACL is set, and no `file_setattr` call succeeds, anywhere in the container, `~`
    included;
  - the ioctls that set file flags fail only on the share, which answers them itself.
- No FIFO on the share is created, opened, given new times or, under `unix-socket`, received ("The
  policy").
- By default no socket inode comes to exist in the workspace or beneath the persistent volume, by
  creation, rename or link, so the session opens no channel to another container.
- Under `unix-socket` ("The hooks", `file_receive`):
  - the receiver's policy judges a descriptor that one sandbox passes to another;
  - a descriptor from another container is refused on arrival, unless it is a non-directory of the
    share, beneath a recorded root, that the receiver could open the same way by path; a file of
    the receiver's own volume; or a file of a type that reaches no share. Every directory is
    refused;
  - what passes within one container passes unchanged;
  - a sandbox of another workspace and a `--workspace=read-only` session get nothing on the share;
  - no socket inode enters a gitdir directly.


## Directories

The policy judges neither `mkdir` nor `rmdir`: a session creates and removes directories at any
name, `.git` and `.ko-agent-sandbox` included. What stays judged:

- Every non-directory put into a new directory is judged where it lands, by `inode_create`,
  `inode_mknod`, `inode_symlink`, `inode_link` or `inode_rename`.
- A directory filled elsewhere cannot be renamed to a guarded name: `inode_rename` refuses a rename
  onto one (`authorize_create`).
- A directory that has a guarded name cannot be renamed away from it: the rename rules refuse a
  guarded source (`authorize`, `Mutation::RenameFrom`).

So a `.git` that the session makes is created and removed in place, never moved.

A new `.git` or `.ko-agent-sandbox` would still change how the classifier judges what lands below
it, so three rules differ from `policy.rs`:

- **No non-directory `HEAD` comes to exist directly in a directory whose folded name is `.git`, at
  any position, unless it replaces a non-directory `HEAD`.** Git's own update, which renames
  `HEAD.lock` over `HEAD`, stays allowed.
  - A directory placeholder does not count: `mkdir sub/.git/HEAD` followed by a `RENAME_EXCHANGE`
    with a `HEAD.lock` file is refused, since the entry replaced is a directory (rename(2) lets the
    two operands of an exchange differ in type).
  - Git v2.51 accepts a gitdir only when its `HEAD` is a regular file or a symlink naming a ref
    (`setup.c`, `is_git_directory`, `validate_headref`). It walks past a `.git` directory that
    fails this, to the parent (`setup_git_directory_gently_1`). So a `.git` the session makes never
    becomes a repository.
  - Without the rule, a planted `sub/.git` holding `HEAD`, `objects/` and `refs/` would be a
    repository for host `git` in `sub/`. A global relative `core.hooksPath` would then point to a
    writable `sub/` path and run a hook the session wrote, even on a host whose
    `safe.bareRepository=explicit` refuses a bare layout there.
  - Applying the rule at any position covers a `.git` inside a gitdir's operational trees, such as
    `.git/objects/x/.git`, where `classify_within_gitdir` admits every name, `config` included.
  - Cost: a session that removes a `HEAD` cannot restore it. The commands that create one,
    `git init`, `git clone` and `git worktree add`, are already blocked.
- **A `read-only` line keeps applying below a `.git` entry.** `policy.rs` applies no line in git
  state (`file-rules.md`). Without this rule, a `.git` made under `read-only locked` would make
  `locked/.git/objects/payload` writable. Cost: a host repository below a `read-only` line is
  read-only to the session's `git`.
- **A `.ko-agent-sandbox` component protects everything below it in git state too.**
  `child_context` recognizes the name only outside git state, so `.git/objects/x/.ko-agent-sandbox`
  would otherwise accept files. No name that git writes collides with it: `git check-ref-format`
  refuses a ref component that begins with a dot, and the other operational trees hold git's own
  names.

What else a session can do with directories, and why each is safe:

- Create an empty `.git` or `.ko-agent-sandbox`, or a tree of empty directories in one. No file can
  be created in it except what the classifier admits, and a `.git` without `HEAD` is not a
  repository.
- Create an empty directory at a name whose existence a host program acts on:
  - `rr-cache` turns rerere on in host merges (`classify_within_gitdir`). Every entry under it
    stays protected, so rerere replays only resolutions the host recorded.
  - A directory at a hook's name passes git's `access(X_OK)` test and then fails to start, which
    counts as a failed hook (git v2.51, `hook.c`, `find_hook`, `notify_start_failure`): a `pre-*`
    hook's command stops, and a `post-*` hook's failure is reported.
  - In `.ko-agent-sandbox`, a directory at a rule file's name, or at a name the launcher does not
    read, makes the next launch fail. A directory holding no rule reads as absent
    (`SandboxWorkspace.readBoundaryRuleFiles`).
  - The last two fail closed and cost availability, which `../SECURITY.md` ("Resource exhaustion")
    does not bound.
- Remove a protected directory after removing everything inside it. "Protected" here means what
  `policy.rs` protects at the commit "Inventory" pins. A directory that holds a protected
  non-directory stays, since unlinking that file is refused. So the directories a session can
  remove are:
  - `.git/hooks` holding no hook, only empty directories at most;
  - a gitdir whose protected entries are all such directories, once the session empties it. A
    gitdir's root can be emptied because it is the one protected directory whose entries can be
    operational (`classify_within_gitdir`);
  - a `read-only` directory whose non-directories later `writable` lines all lift
    (`child_rule_context`).

  Only `mkdir` can bring the name back, and it starts the directory empty, which returns it to the
  cases above. A removed gitdir's `HEAD` stays refused. `objects` and `objects/info` are pinned, not
  protected: the FUSE backend lets the session remove them too, since only `mkdir` can create them
  again (`is_pinned_within_gitdir`).


## Launches

Besides the mode, `--workspace` takes comma-separated values for the backend and for sockets (the
user's decisions of 2026-10-26):

- The backend is `bpf`, or `fuse` for the FUSE backend. `bpf` is the default of both modes, by the
  user's decision of 2026-11-02.
  - A launch that the backend cannot serve is refused, and the refusal names `fuse`: native Linux,
    the nesting modes other than `none`, and a live session on a machine that lacks what the
    backend needs.
  - The user's reasons: few users run those combinations, and the FUSE backend's overhead on macOS
    and Windows is unbearable.
- `unix-socket` allows Unix sockets in the workspace and beneath the persistent volume, at the cost
  of the ninth hook ("The hooks", `file_receive`). `no-unix-socket`, the default, allows none. With
  `fuse`, `unix-socket` is a fatal error, since the FUSE backend cannot honor it.
- The values are accepted in any order, and each part is optional. The command line's parts replace
  the options file's parts, by the user's decision of 2026-11-02 (`CommandLine.WorkspaceValue`).
- One source may give the parts in one `--workspace` or across several, each part once, by the
  user's decision of 2026-11-02, matching `--model-provider` (`CommandLine.joinWorkspace`).
- The container label holds one canonical spelling, so the refusal beside a live session compares
  settings, not spellings.

What a launch under `bpf` does and refuses:

- A capability probe runs at every launch ("The launcher's side"). Where it fails, a live launch is
  refused and a read-only launch keeps only the raw `ro` bind. Both print what the machine lacks,
  with the remedy for each provider. The launch line names the backend, and the steps' times go to
  the run's `ko-agent-bpf.log`.
- The launch refuses an installation from another launcher build. It also refuses one whose tags
  were recorded under a kernel other than the one the machine runs, as after
  `podman machine os upgrade` or `wsl --update`. The refusal names `--build`.
- No container process runs before the policy ("Lifecycle", step 3). Two checks prove this, and a
  controller that attached nothing, a subset, another build or wrong records cannot pass them:
  - the read-back of every attachment, program tag and map record;
  - the fixture suite, run in the attach cgroup.

  A failure at any step before the container starts ends the launch. The launcher prints which step
  failed and never binds the workspace writable.
- During a session, the policy cannot lapse unless a trusted actor ends it:
  - a link is detached only when its cgroup is removed;
  - a cgroup with the container's scope or tasks in it cannot be removed;
  - so only root detaching the link ends the enforcement, and root is trusted ("What the backend
    must hold").

  The policy outlives the controller. The lifecycle suite measures both ("Lifecycle on macOS", the
  policy cannot lapse).
- A launch is refused, whichever launched first and also when both launch at once ("The hooks",
  `file_receive`), when:
  - its backend or `unix-socket` setting differs from that of a live session sharing its volume or
    a raw mount, a linked worktree's main gitdir included;
  - a live container of an earlier launcher, without the labels, runs beside it;
  - a live container beside it has a recorded root path that no longer names its recorded identity.
- The sessions the first version does not serve are refused, and the refusal names `fuse`.


## What is gained and what is lost

Neither list includes the git property, the file rules or the blocked git commands: the hooks hold
them as the FUSE backend does. The hooks hold the name rule too, except for directories, which
"Lost" lists. The lists show what else changes.

Gained:

- **The FUSE backend's whole cost.** The most the backend can save is measured
  (`../ko-agent-fs/fuse/doc/verification-log.md`, "The cost of a path walk"):

  | operation                            | direct bind | bpf     | fuse    |
  | ------------------------------------ | ----------- | ------- | ------- |
  | `ls -lR`, per entry                  | 0.69 ms     | 0.69 ms | 12.7 ms |
  | `git status`, 4,475 files at depth 7 | 3.8 s       | 3.8 s   | 72 s    |
  | `sbt` build of this repository       | 87 s        | 84 s    | 604 s   |

  - The `sbt` row's direct-bind and bpf figures keep the build output in the workspace, as the
    fuse figure does. The 43 s of "an sbt build, by where its output goes" had it outside.
  - "Benchmark on macOS" and "Benchmark on WSL" measure the policy's own cost over the direct bind:
    - `entry-cost.py`'s rounds overlap the bind's in three rows on each machine. On macOS `cp -r`
      runs 1.09 times the bind's and `rm -rf` 1.07 times, above it in each round; on WSL `find`
      and `ls -lR` run 1.08 times, and the program judges neither;
    - the single runs of the walk and the build lie within 5 % of the bind's on macOS, on the
      per-file rows, `find`, `git status` and the build, and within 15 % either way on WSL;
    - on the depth rows, 200 `lstat` calls of 0.08 to 12 ms each, the policy runs 1.00 to 1.15
      times the bind;
    - the program itself takes 10 to 13 µs per judged call on either kernel, and 33 to 83 µs at
      the build's depth of 20.
  - The program runs on mutations and opens, never on `lookup` or `getattr`, the operations that
    dominate those columns.
- **The daemon's share of the machine's hangs.** `git status` in a worktree of hundreds of files
  has frozen the podman machine for over an hour, while memory was not short and
  `podman machine ssh` failed throughout. The daemon and its requests go away with the FUSE backend.
  - What the bind keeps is the share server's one worker thread per share: one blocked request
    stalls every later one (`upstream-issues.md`, "Setting a FIFO's times blocks the macOS
    virtio-fs server").
  - A FIFO on the share is refused by type, under the decision of 2026-10-25 ("The policy"): its
    creation in `inode_mknod`, its open in `file_open`, its time change in `inode_setattr` and,
    under `unix-socket`, its descriptor in `file_receive`. The program holds the rules, and the
    measured sections of the policy to benchmark suites measure them.
- **No window between resolving and acting.** The decision is taken inside the syscall, on the
  dentry the kernel acts on; the FUSE backend's resolver and its `ESTALE` rules only approximate
  this. A held directory handle follows a directory the host moved, and is judged by its current
  position. The walk reads `d_parent` and `d_name` without `rename_lock`, so it can see a concurrent
  `d_move` of an ancestor half done, half old and half new (`fs/dcache.c`, `__d_move`). Three things
  keep that harmless:
  - A walk that overlaps a rename is discarded, and no property of the classifier could replace
    that:
    - `d_move`, `d_exchange` and `__d_unalias` hold `rename_lock` across the parent change and the
      name change.
    - For inline names, a rename copies the new name over the old one (`fs/dcache.c`, `__d_move`,
      `copy_name`, a struct assignment), and an exchange swaps the two a word at a time
      (`swap_names`).
    - So a walk that is not validated can read a name that is neither: `node_modules` out of
      `node_modAAAA` and `BBBBBBBBules`. The defaults' `writable` line would then lift a `.vscode`
      below it, which both real names protect.
    - `policy.rs` allows that rename, since a directory is pinned only as an interior component of
      a line (`RuleContext::pinned`), and the move leaves no region (`authorize_region_move`). The
      policy suite runs it as a race.
  - The program validates each walk with the dentries' own sequence counts:
    - It reads each dentry's count, `d_seq`, before and after reading its parent, name and inode
      (`fs/dcache.c`: `__d_move` and `d_exchange` hold it odd across the parent and name change).
    - After the last level, it reads every level's count again, as the RCU path walk revalidates
      the dentry it came from after reading the next (`fs/namei.c`, `lookup_fast`).
    - It reads each count through the address the level was read at, a scalar the probe helper
      returned, under the caller's RCU read lock, which keeps a dentry's memory a dentry
      (`fs/dcache.c`, `__d_free`).
    - The chain counts only when each first value is even and every later read equals it. The
      chain is then the object's position over one interval of the walk, not a mix of two moments.
    - A barrier separates each count read from the field reads, as `read_seqbegin` and
      `read_seqretry` have (`include/linux/seqlock.h`, `smp_rmb`); two plain reads have none.
    - Otherwise the walk is discarded and made again, and the operation is denied after a bound.
    - The one-hook and every-hook suites instead read the global `rename_lock` sequence around the
      whole walk, as `d_path` does. That discards a walk at any rename in the VM: sixteen renaming
      processes made 35 of 11,891 walks give up after four retries and deny permitted operations
      ("Policy on macOS"). `d_path` takes the write lock on its second try; a program cannot.
    - Clang emits no barrier instruction for BPF: a fence outside the single-thread scope is a
      fatal error in LLVM's BPF backend (`BPFISelLowering.cpp`, `LowerATOMIC_FENCE`). So the
      barrier is an atomic fetch-add on a map word between the reads:
      - the arm64 JIT emits `ldaddal`, or `ldxr`/`stlxr` with `dmb ish` without LSE
        (`arch/arm64/net/bpf_jit_comp.c`, `emit_lse_atomic`, `emit_ll_sc_atomic`);
      - the x86 JIT emits a `lock`-prefixed `xadd` (`arch/x86/net/bpf_jit_comp.c`,
        `emit_atomic_rmw`);
      - both verifiers accept it, and the JIT dumps show those instructions ("One hook on macOS",
        "One hook on WSL").
  - A host rename moves a guest dentry too. When the session next looks up the new name, the
    lookup returns the inode the old dentry holds (`fs/dcache.c`, `d_splice_alias` to
    `__d_unalias`, which FUSE, virtiofs, overlayfs, ext4, xfs and 9p reach; 9p without metadata
    caching makes a new inode instead). On native Linux, `rename(2)` itself moves it.
    - A write the walk judges at the old position is one the session could make until the guest
      noticed the host's rename: the race `git-metadata.md`, "Races", lists for the FUSE backend.
    - The host is trusted.
- **Data coherency is the share's own.** The FUSE backend's two remaining cache cases
  (`../ko-agent-fs/fuse/doc/architecture.md`, "Coherency") have no layer to occur in.
- **No daemon.** No `ENOTCONN` failure that all of a workspace's sessions share, no serialized
  round trips, no inode table.

Lost, stated as what becomes possible that the FUSE backend does not allow:

- **A privileged controller in the path.** The enforcement is the verified program in the kernel.
  The controller that installs it runs with the `bpf` syscall's privileges, as root for the launch,
  in the machine or on a native Linux host ("Native Linux"). The FUSE backend's daemon runs as an
  ordinary user throughout.
  - The controller parses no text from the workspace: the unprivileged guard folds and compiles
    the rules into fixed-size records ("The policy"), and the controller installs them and
    attaches links.
  - What becomes possible is a defect in that installing step. Only the launcher reaches it, since
    the sandbox has no path to the controller: the controller exits before the container starts and
    listens on nothing.
- **A mistake in the kernel-facing glue, which no host test reaches.** The classifier itself is
  unit-tested on the host: the C program is compiled a second time into a test binary and run
  through `policy.rs`'s corpus ("The recorded decisions this answers"). The folding, the parsing
  and the map compilation stay in the guard's Rust and reuse `policy.rs`.
  - What the host cannot run is the glue around the classifier: the `d_parent` walk, its CO-RE
    reads and its bounds. An LSM program has no `BPF_PROG_TEST_RUN` (`kernel/bpf/bpf_lsm.c`,
    `lsm_prog_ops` is empty).
  - A wrong bound or read there lets a write to a protected entry through, until the policy suite's
    corpus, run through real syscalls against the attached program, catches it. `--self-test` runs
    that corpus on the user's machine, whose kernel the suite may not have measured.
- **No writable session on a kernel without the LSM.** The probe fails, and the launch binds
  nothing writable and says what the host lacks. The session is lost, never weakened.
- **No session write through an NTFS short name on Windows.** The policy refuses that form of name
  ("The policy"), and no project is known to use it. No protection is weakened.
- **No Unix socket in the workspace or beneath the persistent volume, by default.** Of the
  installed software, only Codex's app-server daemon binds one there ("Environment evidence").
  `unix-socket` allows them at the cost of a ninth hook ("The hooks", `file_receive`).
  - On the Windows machine the option reaches only the volume: the 9p share answers a socket bind
    with `ENOTSUP` after the hook admits it ("Every hook on WSL", share).
    - A `live,bpf,unix-socket` session measured this again on 2026-10-27.
    - In that session a bind beneath the volume, the refusals under `.git` and `.ko-agent-sandbox`,
      and a share descriptor passed inside the session behaved as on macOS.
  - Under the option, a `--workspace=read-only` session can connect to a socket a live session
    binds on the share or the volume, and send it data.
    - No hook judges `connect` or a socket's `sendmsg`, and the bytes do not touch the socket's
      inode.
    - The read-only session cannot bind a socket, change the socket's file or receive a share file.
      So what it writes is what the live session's process then writes, under its own policy.
  - Refusing the data would take `socket_sendmsg` as a tenth hook, the last slot, walking from the
    peer's bound dentry (`net/unix/af_unix.c`, `unix_sk(peer)->path`).
    - It would close nothing while the two sessions share the persistent volume, which a read-only
      session writes: the live session's configuration under `~` is directly reachable there.
    - Not built. The case to revisit is two sessions launched with different volumes.
- **No write by a `--workspace=read-only` session through a descriptor a live session passes; and
  the controller runs for a read-only launch.**
  - The FUSE backend admits the write, since the live session's mount judged the open.
  - Here nothing arrives by default. Under the option, `file_receive` refuses what another
    container passes, except a share file the session could open itself, a file of its own volume,
    or a file of another type, which reaches no share ("The hooks").
  - The session's policy records no root, so nothing on the share can be opened for writing ("The
    hooks", `file_receive`).
  - No protection is weakened.
- **No socket inode inside a gitdir under `unix-socket`, by creation, rename or link.** Git binds
  its one socket there at the root, under a name the FUSE backend already refuses. No protection is
  weakened.
- **Three answers stricter than `policy.rs`'s.** The BPF backend is meant to replace the FUSE
  backend, so its policy may refuse more, by the user's decision of 2026-11-09. No protection is
  weakened, and git writes none of these names:
  - a `.lock` name in a gitdir's `objects/info` other than `commit-graph.lock` and `packs.lock`, and
    a doubled `.lock` suffix such as `HEAD.lock.lock`, which `policy.rs` classifies by recursion;
  - an alias context that would make a third at one position, where `policy.rs` merges two that
    became equal; the program refuses it as an alias overflow;
  - a symlink target of more than 64 components when its `.` and empty components count, which
    `Path::components` drops.
- **A directory at any name, `.git` and `.ko-agent-sandbox` included.** The session can create and
  remove empty directories at a guarded name or position, which the FUSE backend refuses.
  "Directories" has the rules that keep this from weakening any protection.
- **Under `NESTING=none`, nothing in the container sets xattrs (`setfattr`) or ACLs (`setfacl`), or
  calls `file_setattr`.** The seccomp rule ("Attributes, flags and ioctls") refuses them under `~`
  too, where the FUSE backend refuses them only in the workspace, and `cp -a` drops xattrs and ACLs
  there. On the machines the share answers `chattr` and the filesystems' own ioctl commands, such as
  `FS_IOC_SET_ENCRYPTION_POLICY` and `FS_IOC_ENABLE_VERITY` ("Inventory"). No protection is
  weakened.


## The recorded decisions this answers

`../ko-agent-fs/fuse/doc/architecture.md` ("Mediation mechanism") rejected BPF-LSM for three
reasons. `design.md` ("Read-only mounts over the protected entries are not a backend") measured why
a direct bind with read-only mounts over the protected entries is not a backend either. Each
reason, and its answer here:

- A global LSM hook sees every accessor in the VM, so filtering the container while leaving the
  host unfiltered needs cgroup scoping written by hand. `BPF_LSM_CGROUP` is that scoping, in the
  kernel: a program attached to a cgroup runs only for tasks in that cgroup and its descendants
  ("The mechanism").
- BPF-LSM depends on how the VM's kernel is built and booted, while the FUSE backend runs on any VM.
  The backend is a capability the launcher probes, and a failed probe binds nothing writable.
  - Both podman machines show the LSM active and the BTF readable as shipped ("Environment
    evidence").
  - A native Linux host passes the probe within a stated supported set, after host changes the user
    consents to ("Native Linux").
- A BPF program is less auditable than Rust. The answer:
  - The classifier is the C program the suites measured. It is compiled a second time into a host
    test binary, against headers that stand in for the kernel's types and helpers
    (`../ko-agent-fs/bpf/test/host/`).
  - `policy.rs`'s corpus runs through both classifiers
    (`../ko-agent-fs/policy/tests/bpf_equivalence.rs`): every path of the conformance table and of
    the git corpus, written, unlinked, created and moved, under the rules as the guard's compiler
    writes them. This shows the two classifiers agree, apart from the three rules "Directories"
    adds, and unit-tests the C one on the host.
  - The inode table, the resolver and the FUSE layer do not exist here.
  - The user, 2026-10-22: "Let's proceed with C, but I will definitely want to migrate to Rust when
    CO-RE becomes stable in Rust." The migration is a later version (`TODO.md`, "The BPF backend's
    later versions").

  What the language costs in the program, and where it costs instead:
  - A memory-safety bug of the C kind cannot ship in the program:
    - The verifier refuses the object at load when any instruction reads or writes outside the
      bounds it has proven for the register, a map value, the stack or a helper's argument; uses a
      scalar as a pointer; reads a stack slot before it is written; or loops without a proven bound
      (`kernel/bpf/verifier.c`, `check_mem_access`, `check_stack_read`, `check_helper_call`).
    - The CO-RE reads of kernel structures go through `bpf_probe_read_kernel`, which answers an
      unmapped address with `-EFAULT` and a zeroed destination. A field the running kernel lacks
      fails the relocation at load.
    - So an overflow, a use after free or a null dereference in the program's own memory is a load
      failure, never a running program, and the launch then binds nothing writable ("Lifecycle").
    - The verifier does not prove that a kernel address the program hands the probe helper points
      to the intended object or field. A wrong relocation or a wrong offset reads unrelated mapped
      kernel memory and returns success (a loader was reported to resolve a relocation against the
      wrong one of two same-named types, Aya issue 1727).
    - The loader's correctness and the classifier's are checked separately: the loader by the
      relocation suite that the Rust port's item in `TODO.md` names, the classifier by the corpus.
  - The verifier does not catch a wrong decision: an allow where the FUSE backend denies, or a name
    folded differently. The corpus checks that through both classifiers, in either language.
  - Where C does cost is the controller: an ordinary process running as root, parsing the guard's
    records and calling libbpf. A memory bug there is a privileged one, which only the launcher
    reaches ("What is gained and what is lost", the privileged controller). A memory-safe language
    would harden that piece; the controller stays C over libbpf until the classifier's port
    ("Sources", loaders).
- Read-only mounts protect a path, not a name:
  - a host rename over the file takes the protection away;
  - a nested repository has none;
  - an NTFS short name passes beside the mount;
  - an absent `.git` needs a mount target created in the workspace.

  The hooks here judge the name and the object at every mutation except a directory's creation and
  removal, at any depth, and create nothing in the workspace. The proof's fixture lives under the
  launcher's state directory ("Lifecycle").

`design.md`'s principle "Do not trade security for performance" stands:

- The backend is built to hold the same property and the same file rules.
- Every route that "Inventory" lists is held by the hooks, by the launcher's seccomp rules
  ("Attributes, flags and ioctls", "Mounts"), or by "Directories", as the every-hook suite's gate
  required.
- No protection is dropped for speed. "What is gained and what is lost" has what else changes. A
  route that neither a hook nor the rules hold is the user's decision, taken in "Directories" or
  pending in `TODO.md` for the version that opens the route, never a recorded loss.


## Native Linux

A later version (`TODO.md`, "The BPF backend's later versions") runs the backend on a native Linux
host's own kernel, without a podman machine, within a supported set the launcher states rather than
discovers.

- A host outside the set gets `--workspace=read-only` and a message naming the missing
  requirement. The launcher never creates a podman machine for it.
- The set is chosen so that the host's launch is the machine's launch: one `sudo -n` of the
  controller under the same cgroup manager, with no mechanism of its own.

The requirements, each checked at launch:

- **`bpf` in the active LSM list**, read from `/sys/kernel/security/lsm`.
  - Every default list in `security/Kconfig` ends in `bpf`, and the machine's Fedora kernel lists
    it ("Environment evidence").
  - This document does not record which distributions drop it: the probe answers per host.
  - Where a kernel lacks it, the message names the boot parameter, `lsm=` with `bpf` appended, and
    the reboot.
- **A sudoers drop-in for the controller**, granting the launcher's user `sudo -n` of the
  root-owned controller binary and nothing else.
  - The host is never prompted for sudo (`../SECURITY.md`, "Silent changes to what you own"). So
    `--build` prints the drop-in and its install command, as it prints the `fuse.conf` change for a
    machine, and the user runs them once.
  - Two limits that any binary granted through sudo needs, both checked by the lifecycle suite: the
    controller loads the object installed beside it and takes no object path; and it attaches only
    under the invoking user's slice, `/user.slice/user-<uid>.slice/`, with the uid from
    `SUDO_UID`. Either refusal fails the launch.
  - Loading an LSM program needs `CAP_BPF` with `CAP_PERFMON`, or `CAP_SYS_ADMIN`
    (`kernel/bpf/syscall.c`, `is_perfmon_prog_type`). A BPF token on a delegated `bpffs` satisfies
    those two checks for an unprivileged process (`bpf_prog_load`, `bpf_token_capable`). Whether
    the attach also works unprivileged is unverified, so the version builds the drop-in, and the
    token may reduce the privilege later.
- **Under SELinux enforcing, `label=disable` for the sandbox container.** Podman's default,
  `label=true` in `containers.conf`, labels the container `container_t`, which cannot read a plain
  bind of the workspace. The option is ignored where SELinux is disabled, so a host under AppArmor
  needs nothing here and keeps podman's `container-default` profile on the container.
  - The sandbox container then runs outside SELinux confinement, as nested containers already do
    (`../SECURITY.md`, "No containers inside the sandbox by default"). What confines it is the
    cgroup-LSM policy, its namespaces, seccomp and capabilities.
  - The alternatives, each rejected:
    - Relabeling the workspace to a shared container type (`semanage fcontext`, then `restorecon`)
      keeps the container confined. But it writes every file's metadata, takes confined host
      services' access to the tree away, and `../SECURITY.md` records that the workspace's labels
      are never changed.
    - Leaving enforcing hosts out of the set excludes the host family both podman machines are
      built from.
- **Rootless podman with the systemd cgroup manager**, as on the machines.

Landlock would need no privilege and no kernel option, and is active on both machines' kernels. But
a Landlock rule's object is a file hierarchy named by an open descriptor
(https://man7.org/linux/man-pages/man7/landlock.7.html). So it cannot refuse a `.git` file, or the
`config` of a new `.git` directory before that exists, at any depth. It is not a backend for this
policy.


## Out of scope

A kernel or distribution that drops the BPF LSM or BTF, restricts what the program needs, or
changes a hook the program attaches to. The capability probe or the program's load then fails and
the launch is refused ("Launches"). Such a kernel costs the session, never its protection: the user
updates the machine's kernel and runs `--build` again.
