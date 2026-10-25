# Plan: a BPF cgroup-LSM backend for `--workspace=live`

The workspace filter costs 6–18× on metadata operations over an unfiltered bind mount on macOS and
5–30× on Windows (`../fuse/ko-agent-fs/doc/verification-log.md`, "The cost of a path walk"), and
sessions through it have frozen the podman machine. This plan replaces the filter on every platform
with a direct bind of the workspace and a policy the kernel running the containers enforces: BPF
programs of type `BPF_LSM_CGROUP`, attached to the sandbox's own cgroup, so the host and every
other container keep unfiltered access to the same files.

The first version serves `NESTING=none` sessions launched with the launcher's own seccomp profile
on the podman machines, where that kernel is the machine's, and gives a `--workspace=read-only`
session there a policy recording no root ("The hooks", `file_receive`, has why).
`NESTING=same-uid` sessions, sessions launched with the profile's loosening option (`TODO.md`,
"Refuse user namespaces and mounts under `NESTING=none`", which ships both) and native Linux
hosts keep the filter until "Later versions" admits them.

Status: the environment prerequisites and the cgroup placement are measured on both machines
("Environment evidence"), Phase 0 is done ("Inventory"), and Phase 1's probe
(`../bpf/probe/phase1/`) passes every row measured on both machines ("Phase 1 on macOS", "Phase
1 on WSL"), where one hook denies; Phase 2's probe (`../bpf/probe/phase2/`) passes on both
("Phase 2 on macOS", "Phase 2 on WSL"); Phase 3's probe (`../bpf/probe/phase3/`) passes every
row on both ("Phase 3 on macOS", "Phase 3 on WSL"), the nine programs loading within the gate's
budget within 0.6 s on macOS and 1.7 s on WSL; the guard compiles the policy's records
(`../fuse/ko-agent-fs/src/bpf_records.rs`); the classifier's host build runs the corpus through
both classifiers (`../fuse/ko-agent-fs/tests/bpf_equivalence.rs`); Phase 4's probe
(`../bpf/probe/phase4/`) passes every row on both machines ("Phase 4 on macOS", "Phase 4 on
WSL"), its gate met, and `../bpf/probe/check-evidence.sh` passes for every measured section;
Phase 5's probe (`../bpf/probe/phase5/Phase5.scala`) passes every row on both machines ("Phase 5
on macOS", "Phase 5 on WSL"), its gate met: on `perf-probe.py`'s repeated rows the policy's rounds
overlap the unfiltered bind's on both machines, its single runs of the walk and the build lie
within a tenth of the bind's on the per-file rows, `git status` and the build and scatter either
way on the walk's depth rows, and the filter costs the bind 5 to 31 times. The filter stays the
default until "Acceptance" passes, and no launch ever binds the workspace writable without the
policy attached and verified.

The reader acting on this plan starts at "Phases" and "What is gained and what is lost". The
sections before them are what the phases rest on.


## What the backend must hold

- The property `../fuse/ko-agent-fs/doc/git-metadata.md` states: no sandbox write makes a later
  host `git` run a program the sandbox chose or open an object directory it chose. The immutable
  set, the name rule and the double-sided rename and link rules are that document's, except that
  a directory may be created and removed at any name, under the rules "Directories" adds.
- No non-directory entry is created inside a `.ko-agent-sandbox` at any depth, and nothing under
  one is written (`../SECURITY.md`, "A workspace loosening its own confinement"; "Directories" has
  why directories there may be created).
- The file rules keep the host-executed files read-only, with the launcher-resolved
  `read-only-path` lines for relocated hooks and symlink aliases (`file-rules.md`).
- The policy is effective for the sandbox's cgroup before any program of the image runs in the
  container: entrypoint, `podman exec` processes and OCI hooks that run in the container's
  namespaces. The container runtime's own processes are trusted, as the filter daemon is.
- The threat is a process inside the sandbox. A VM administrator, a compromised podman or runtime,
  and whoever runs the controller are trusted; pinned links do not resist them.
- On Windows the policy is what the WSL kernel enforces on container processes. It changes nothing
  about WSL as a boundary toward the Windows host
  (https://wsl.dev/technical-documentation/security/).

What else the backend changes, each way, is "What is gained and what is lost".


## Later versions

What the first version leaves to the versions after it, each behind the gates the phases name
for it; until then Phase 6's backend selector launches those sessions with the filter, and on
the podman machines their `--workspace=read-only` sessions under the no-root policy, which
denies the share wholly and needs none of the routes the first item names:

- `NESTING=same-uid` sessions and `NESTING=none` sessions with the profile loosened, where the
  session mounts and creates user namespaces: the routes a nested podman needs and the free slots,
  overlayfs's `user.overlay.*` names ("Decisions still open"), Phase 2's nested-podman measurement,
  Phase 3's alias and overlay rows, among them a copy-up that moves a protected object to a new
  inode in the overlay's upper layer, written during the copy and right after it, which must stay
  protected by its position alone and by nothing that waits on a notification from user space,
  and a key for `file_receive` other than the mount namespace, which a nested container of such a
  session would fail ("The hooks").
- Native Linux hosts: "Native Linux", the controller's two refusals and the mount under the
  bind source there, with a nested mount holding a `.git` (Phase 4 measures them in the
  machines), and the host's own mount topology under the workspace ("Mounts").
- The classifier in Rust, once `rustc` emits the CO-RE field relocations the walk's reads need
  (https://github.com/aya-rs/aya/issues/349): the port keeps the shape the verifier accepted in
  C, the numeric-iterator loops with their state in map memory, the masks `barrier_var` keeps
  and the global functions verified once per program, each to be found under Rust's BPF target
  and measured on both kernels as Phases 2 and 3 measured the C program. The user: "Rust should
  give us fewer vulnerabilities and fewer things to harden with great efforts." What the
  language can and cannot cost in the program is under "The recorded decisions this answers".
  A loader other than libbpf, for the controller or the port, is shown first to resolve the
  object's CO-RE relocations as libbpf does on both kernels, with a fixture whose BTF holds two
  types of one name, since a loader that picks the wrong one reads the wrong field without
  an error (reported against Aya as its issue 1727, not verified here).


## The recorded decisions this answers

`../fuse/ko-agent-fs/doc/architecture.md` ("Mediation mechanism") rejected BPF-LSM for three
reasons, and `design.md` ("Read-only mounts over the protected entries are not a backend")
measured why a direct bind with read-only mounts over the protected entries is not one. Each
reason, and its answer here:

- A global LSM hook sees every accessor in the VM, so the host/container asymmetry needs cgroup
  scoping written by hand. `BPF_LSM_CGROUP` is that scoping, in the kernel: a program attached to
  a cgroup runs only for tasks in it and its descendants ("The mechanism").
- The filter works wherever the VM does, while BPF-LSM depends on the kernel's configuration.
  The backend is a probed capability, and a failed probe binds nothing writable. Both podman
  machines show the LSM active and the BTF readable as shipped ("Environment evidence"); a
  native Linux host passes the probe within a stated supported set, after host changes the user
  consents to ("Native Linux").
- A BPF policy program is less auditable than Rust. The classifier is the C program the phases
  measured, compiled a second time into a host test binary against headers standing in for the
  kernel's types and the helpers (`../bpf/probe/phase3/host/`), with `policy.rs`'s corpus run
  through both (`../fuse/ko-agent-fs/tests/bpf_equivalence.rs`: every path of the conformance
  table and of the git corpus, written, unlinked, created and moved, under the rules as the
  guard's compiler writes them), so the two classifiers are shown to agree, the three rules
  "Directories" adds apart, and the C one is unit-tested on the host; the inode table, resolver
  and FUSE layer do not exist. The user, 2026-10-22: "Let's proceed with C, but I will
  definitely want to migrate to Rust when CO-RE becomes stable in Rust." The migration is a
  later version ("Later versions").
  What the language costs in the program, and where it costs instead:
  - A memory-safety bug of the C kind cannot ship in the program. The verifier refuses the
    object at load when any instruction reads or writes outside the bounds it has proven for the
    register, a map value, the stack or a helper's argument, uses a scalar as a pointer, reads a
    stack slot before it is written, or loops without a proven bound (`kernel/bpf/verifier.c`,
    `check_mem_access`, `check_stack_read`, `check_helper_call`); the CO-RE reads of kernel
    structures go through `bpf_probe_read_kernel`, which answers an unmapped address with
    `-EFAULT` and a zeroed destination, and a field the running kernel lacks fails the
    relocation at load. So an overflow, a use after free or a null dereference in the program's
    own memory is a load failure, never a running program, and the launch then binds nothing
    writable ("Lifecycle"). What the verifier does not prove is that a kernel address the
    program hands the probe helper denotes the object or field meant: a wrong relocation or a
    wrong offset reads unrelated mapped kernel memory and returns success (a loader was
    reported to resolve a relocation against the wrong one of two same-named types, Aya issue
    1727, "Later versions"). The loader's correctness and the classifier's are validated
    apart, the one by the relocation suite "Later versions" names, the other by the corpus.
  - What the verifier does not catch is a wrong decision: an allow where the filter denies, or a
    name folded differently. That is the corpus's job through both classifiers, in either
    language.
  - Where C does cost is the controller: an ordinary process running as root, parsing the
    guard's records and calling libbpf. A memory bug there is a privileged one, reached through
    the launcher alone ("What is gained and what is lost", the privileged controller). A
    memory-safe language hardens that piece; the controller stays C over libbpf until the
    classifier's port ("Sources", loaders).
- Read-only mounts protect a path, not a name: a host rename over the file takes the protection
  away, a nested repository has none, an NTFS short name passes beside the mount, and an absent
  `.git` needs a mount target created in the workspace. The hooks here judge the name and the
  object at every mutation but a directory's creation and removal, at any depth, and create
  nothing in the workspace; the proof's fixture lives under the launcher's state directory
  ("Lifecycle").

`design.md`'s principle "Do not trade security for performance" stands: the backend is built to hold
the same property and the same file rules, and Phase 2's gate is where every route of the inventory
is shown covered by the hooks, the launcher's seccomp rules ("Attributes, flags and ioctls",
"Mounts") or "Directories". What else it changes is "What is gained and what is lost", and no
protection is dropped for speed: a route neither a hook nor the rules hold is the user's decision,
taken in "Directories" or pending in "Decisions still open", never a recorded loss that a gate
passes. The change that adds the backend updates the two documents above, and the statements that
refuse a directory at a guarded name: `../SECURITY.md`, "A workspace loosening its own confinement"
and "The host's git executing what the sandbox wrote", `git-metadata.md`, "The immutable set" and
"The name rule", and `file-rules.md`, where no line applies in a Git directory's operational state.
It also names what the seccomp rules refuse in `../container/ko-agent-sandbox/AGENTS-SANDBOX.md`.


## The mechanism

Read in Linux 7.2.5 (`linux-7.2.tar.xz` with `patch-7.2.5.xz` from
https://cdn.kernel.org/pub/linux/kernel/v7.x/), which the podman machine on macOS runs as
Fedora's `7.2.5-200.fc44.aarch64`. The WSL kernel is Microsoft's `6.18.54.1`, where each fact
below is to be re-read before Phase 2 relies on it; the sleepable bullet names the one difference
read so far.

- `include/linux/bpf-cgroup-defs.h`: `CGROUP_LSM_NUM` is 10. `kernel/bpf/cgroup.c`,
  `bpf_cgroup_atype_find`, gives one slot per distinct hook, refcounted across every cgroup that
  attaches it, and `-E2BIG` for an eleventh hook, which `__cgroup_bpf_attach` folds into the
  `EINVAL` the attach answers (measured, "Phase 1 on macOS"). Ten hooks serve any number of
  sandboxes. The pool is shared by everything in the VM, so the controller reads it before
  attaching rather than assuming it free.
- `cgroup.c`, `bpf_prog_run_array_cg`: a program's nonzero return grants, and zero becomes
  `-EPERM` on a hook that returns an errno alone (`cgroup_bpf_hook_returns_errno`), which the
  eight hooks all do. A program on a void hook must return 1 (`kernel/bpf/verifier.c`,
  `return_retval_range`). The `lsm/` convention of returning a negative errno does not apply.
- `cgroup.c`, `cgroup_bpf_link_attach`, adds `BPF_F_ALLOW_MULTI` to every link attach, so every
  descendant cgroup runs the program (`compute_effective_progs`). A descendant may attach programs
  of its own, which needs the `bpf` syscall privileges the sandbox lacks: inside a session
  `CapEff` is zero, `/sys/fs/cgroup` is mounted read-only, and the cgroup namespace's root is the
  container's cgroup, so no task can move itself out.
- `cgroup.c`, `__cgroup_bpf_run_lsm_current`: filesystem hooks run the programs of the calling
  task's cgroup. The host's writes arrive through the hypervisor's share, not from a VM task, so
  they are never judged.
  - The first attach of a hook installs one shim on that hook for the whole VM
    (`kernel/bpf/trampoline.c`, `bpf_trampoline_link_cgroup_shim`); every task in the VM then
    pays one effective-array lookup per call of that hook, and only tasks under an attached
    cgroup run a program.
- `kernel/bpf/btf.c`, `prog_args_trusted`: an LSM program's arguments are trusted pointers unless
  its hook is in `bpf_lsm.c`'s `untrusted_lsm_hooks`, which holds none of the hooks below. A
  `struct dentry` or `struct file` argument is usable as such, and `dentry->d_parent` walks are
  CO-RE reads.
- Sleepable programs: the two kernels differ. `verifier.c`, `can_be_sleepable`, refuses a
  sleepable `BPF_LSM_CGROUP` program at load; Microsoft's 6.18.54.1 lacks the check, admits
  every sleepable LSM program by its hook alone and runs it under the shim's `rcu_read_lock`
  (`trampoline.c`). The design needs no sleepable program, and the controller never sets
  `BPF_F_SLEEPABLE`: `fs/bpf_fs_kfuncs.c` tags `bpf_path_d_path` without `KF_SLEEPABLE`, and the
  policy below does not call it.
- The hooks below are outside every `#ifdef` of `include/linux/lsm_hook_defs.h`, so they need no
  `CONFIG_SECURITY_PATH`; both kernels' BTF lists them ("Inventory").

### The hooks

Eight hooks take eight of the ten slots `CGROUP_LSM_NUM` gives, a ninth under `unix-socket`, a
value of `--workspace` ("Phases", 6; `file_receive` below), and hold the writes and the names of
everything but directories at the VFS, whatever the backing. The name hooks are the `inode_*` hooks,
not the `path_*` hooks the syscalls call first, because overlayfs, which a session can mount where
"Mounts" allows it, changes its upper layer through the `inode_*` hooks alone ("Inventory", row 20);
each hook judges row 20's changes of its kind as well. Slots 9 and 10 stay free for what "Decisions
still open" may give them.

| slot | hook            | decides                                                   | rows      |
| ---- | --------------- | --------------------------------------------------------- | --------- |
| 1    | `inode_create`  | a new file's name and parent: `creat`, `O_CREAT`, `mknod` | 1         |
| 2    | `inode_mknod`   | a new FIFO's, socket's or device's name and parent; a     | 2         |
|      |                 | FIFO or a socket by type                                  |           |
| 3    | `inode_symlink` | a new symlink's name, parent and target syntax            | 4         |
| 4    | `inode_link`    | the source object and the new name                        | 5         |
| 5    | `inode_rename`  | both names and parents, each way for `RENAME_EXCHANGE`    | 6, 7      |
| 6    | `inode_unlink`  | removal of a protected entry                              | 8         |
| 7    | `file_open`     | an open for writing of a protected object; any open of a  | 10–13, 19 |
|      |                 | FIFO by type                                              |           |
| 8    | `inode_setattr` | `chmod`, `chown`, times, `truncate`, `O_TRUNC`; a FIFO's  | 11, 14    |
|      |                 | times by type                                             |           |
| 9    | `file_receive`  | a writable share file, or a FIFO of the share in any mode, | —         |
|      |                 | arriving by IPC, `unix-socket`                           |           |

`inode_create` judges a `mknod` of a regular file; the other types reach `inode_mknod`
(`fs/namei.c`, `filename_mknodat`).

`inode_symlink` judges the target as the filter does (`fs.rs`, `target_has_portable_syntax`,
`allow_symlink_target`): an absolute target or one climbing above the workspace root is refused on
its syntax; with rules, each path the target passes, resolved lexically from the link's directory,
is refused when its last component has the NTFS short-name form, when it enters a gitdir from the
workspace, or when it is in a writable region the link is not in. The program reads the target
from the hook's kernel copy, bounded: a target of 1024 bytes or more, or of more than 64
components, is denied.

### Directories

The plan judges neither `mkdir` nor `rmdir` (rows 3 and 9): a session creates and removes
directories at any name, `.git` and `.ko-agent-sandbox` included. Every non-directory put into a
new directory is still judged at the position it lands at, by `inode_create`, `inode_mknod`,
`inode_symlink`, `inode_link` or `inode_rename`. A directory filled elsewhere cannot take a guarded
name, since `inode_rename` refuses a rename onto one (`authorize_create`), and one at a guarded
name cannot leave it, since the rename rules refuse the guarded source (`authorize`,
`Mutation::RenameFrom`): a session-made `.git` is created and removed in place, never moved.

A new `.git` or `.ko-agent-sandbox` would still change how the classifier judges what lands below
it, so three rules depart from `policy.rs`:

- **No non-directory `HEAD` comes to be directly in a directory whose folded name is `.git`, at any
  position, unless it replaces a non-directory `HEAD`.** Git's own update, renaming `HEAD.lock`
  over `HEAD`, stays allowed.
  - A directory placeholder does not count: `mkdir sub/.git/HEAD` followed by a
    `RENAME_EXCHANGE` with a `HEAD.lock` file is refused, since the entry replaced is a directory
    (rename(2) lets the two operands of an exchange differ in type).
  - Git v2.51 accepts a gitdir only when its `HEAD` is a regular file or a symlink naming a ref
    (`setup.c`, `is_git_directory`, `validate_headref`), and walks past a `.git` directory that
    fails, to the parent (`setup_git_directory_gently_1`). A `.git` the session makes therefore
    never becomes a repository.
  - Without the rule, a planted `sub/.git` holding `HEAD`, `objects/` and `refs/` would be a
    repository for host `git` in `sub/`: a global relative `core.hooksPath` would then resolve to
    a writable `sub/` path and run a hook the session wrote, also on a host whose
    `safe.bareRepository=explicit` refuses a bare layout there.
  - Applying it at any position covers a `.git` inside a gitdir's operational trees, such as
    `.git/objects/x/.git`, where `classify_within_gitdir` admits every name, `config` included.
  - Cost: a session that removes a `HEAD` cannot restore it. The commands that create one,
    `git init`, `git clone` and `git worktree add`, are already blocked.
- **A `read-only` line keeps applying below a `.git` entry.** `policy.rs` lets no line apply in git
  state (`file-rules.md`), so without the rule a `.git` made under `read-only locked` would make
  `locked/.git/objects/payload` writable. Cost: a host repository below a `read-only` line is
  read-only to the session's `git`.
- **A `.ko-agent-sandbox` component protects everything below it in git state too.**
  `child_context` recognizes the name only outside git state, so `.git/objects/x/.ko-agent-sandbox`
  would otherwise accept files. No name git writes collides: `git check-ref-format` refuses a ref
  component that begins with a dot, and the other operational trees hold git's own names.

What else a session can do with directories, and why each is safe:

- An empty `.git` or `.ko-agent-sandbox`, or a tree of empty directories in one: no file can be
  created in it but what the classifier admits, and a `.git` without `HEAD` is no repository.
- An empty directory where a host program acts on a name's existence:
  - `rr-cache` switches rerere on in host merges (`classify_within_gitdir`); every entry under it
    stays protected, so rerere replays only resolutions the host recorded;
  - a directory at a hook's name passes git's `access(X_OK)` test and then fails to start, which
    counts as a failed hook (git v2.51, `hook.c`, `find_hook`, `notify_start_failure`): a `pre-*`
    hook's command stops, and a `post-*` hook's failure is reported;
  - in `.ko-agent-sandbox`, a directory at a rule file's name or at a name the launcher does not
    read refuses the next launch, and a directory holding no rule reads as absent
    (`SandboxWorkspace.readBoundaryRuleFiles`).
  - The last two fail closed and cost availability, which `../SECURITY.md` ("Resource
    exhaustion") does not bound.
- The removal of a protected directory the session can empty, leaves first, read in `policy.rs`
  at the commit "Inventory" pins. One holding a protected non-directory stays, since unlinking it
  is refused.
  - Such a directory is `.git/hooks` holding no hook, empty directories at most; a gitdir whose
    protected entries are such directories, which the session empties first, since in the git
    rules a gitdir's root is the one protected directory whose entries can be operational
    (`classify_within_gitdir`); or a `read-only` directory whose non-directories later `writable`
    lines all lift (`child_rule_context`).
  - Only `mkdir` refills the name, and it starts the directory empty, which returns it to the
    cases above; a removed gitdir's `HEAD` stays refused.
  - `objects` and `objects/info` are pinned, not protected: the filter removes them too, since
    only `mkdir` can create them again (`is_pinned_within_gitdir`).

### Attributes, flags and ioctls

No taken slot holds rows 15–18. The filter refuses each under the whole workspace, since it does
not implement the operation ("Inventory", filter column `none`; for xattrs,
`../fuse/ko-agent-fs/doc/verification-log.md`, "Extended attributes"). The routes:

- xattrs, row 15: `inode_setxattr` and `inode_removexattr`. The macOS share forwards xattrs:
  through an unfiltered bind `setxattr` succeeds.
- POSIX ACLs, row 16: `inode_set_acl` and `inode_remove_acl`.
  - `fs/xattr.c`, `do_setxattr` and `removexattr`, route the `system.posix_acl_*` names to
    `do_set_acl` and `vfs_remove_acl` before `vfs_setxattr`'s `security_inode_setxattr`, so the
    xattr hooks never see an ACL.
  - `fs/posix_acl.c`, `vfs_set_acl`, calls `security_inode_set_acl`, and
    `posix_acl_update_mode` rewrites `i_mode`, a `chmod` that `inode_setattr` never sees.
  - A FUSE superblock, virtiofs included, carries `SB_POSIXACL` (`fs/fuse/inode.c`,
    `fuse_fill_super`), and `fuse_set_acl` forwards the ACL to the server as an xattr, so whether
    the macOS share stores one is the server's to answer; ext4, xfs and btrfs store both routes
    (`fs/{ext4,btrfs}/acl.c`, `fs/xfs/xfs_acl.c`).
- File flags, the inode flags `chattr` sets, row 17: `inode_file_setattr`. `file_setattr`,
  `FS_IOC_SETFLAGS` and `FS_IOC_FSSETXATTR` change the flags and `fsxattr` fields of a file the
  caller owns through a read-only descriptor, which `file_open` admits.
- Filesystem ioctls, row 18: `file_ioctl` and `file_ioctl_compat`. The commands read take a
  read-only descriptor and set a file's generation, set an empty directory's encryption policy,
  or make a file permanently read-only.

`inode_permission` would not hold them in one slot: it sees neither an ACL change, whose
`may_write_xattr` checks only the immutable and append flags and the id mapping (`fs/xattr.c`),
nor a `security.` or `system.` xattr, for which `xattr_permission` returns before any permission
check, nor a flag change, which `vfs_fileattr_set` admits by ownership (`fs/file_attr.c`,
`inode_owner_or_capable`). What holds them:

- Under `NESTING=none`, a seccomp rule added to the launcher's profile ("Mounts"), which takes no
  slot and refuses:
  - the `setxattr` and `removexattr` syscall families, `setxattrat` and `removexattrat`
    included;
  - `file_setattr`;
  - `ioctl` by its command argument: `FS_IOC_SETFLAGS`, its 32-bit `FS_IOC32_SETFLAGS`
    (`fs/ioctl.c`, `compat_sys_ioctl`), `FS_IOC_FSSETXATTR`, and the commands row 18 lists,
    32-bit forms included. The rule compares the argument's low 32 bits (`SCMP_CMP_MASKED_EQ`
    in the OCI profile): seccomp sees the whole 64-bit register while the kernel reads `cmd` as
    `unsigned int`, so an equality over 64 bits is passed by a command with a high bit set
    (seccomp(2)). Phase 2 runs each refused command with high bits set, on both architectures.
- Under `NESTING=same-uid` ("Later versions"), whether a nested podman's storage needs the xattr
  syscalls, `file_setattr` or the refused ioctl commands is a Phase 2 measurement. The rule
  cannot refuse a family the nested podman needs; the free slots can hold two of its hooks,
  and which routes stay open on such sessions is a user decision in "Decisions still open", with
  each route's consequence stated there. That version's gate stays unmet until it is taken.

What the seccomp rule reaches and what it misses:

- Every xattr, ACL and flag change a process requests enters through those syscalls;
  `io_uring_setup` already answers `ENOSYS` in a session ("Inventory", row 22).
- Row 18 is a list of commands, not a syscall family: the rule refuses the commands the row lists.
  xfs's and btrfs's are listed there, and a kernel change reopens the row ("Environment
  evidence").
- The rule refuses those calls everywhere in the container, under `~` as well. It answers
  `ENOTSUP` to the xattr syscalls, so that `cp -a` drops attributes silently as through the
  filter, and `ENOTTY` to the ioctl commands, as FUSE answers for the filter (`fs/fuse/ioctl.c`).
- overlayfs's own writes to its upper layer reach `inode_setxattr` without those syscalls
  (row 20). Where "Mounts" refuses the overlay mount, none is made; elsewhere neither a slot nor
  the rule holds them, a pending decision in "Decisions still open".
  - overlayfs sets its `user.overlay.*` names on existing directories of the upper layer,
    protected ones included: `uuid` on the upper root at its first mount and `impure` on a
    parent (`fs/overlayfs/util.c`, `ovl_init_uuid_xattr`, `ovl_set_impure`).
  - A `trusted.overlay.*` name needs `CAP_SYS_ADMIN` in the initial user namespace
    (`fs/xattr.c`, `xattr_permission`).

Hooks the plan does not need, and the fact that excuses each:

- `path_mknod`, `path_symlink`, `path_link`, `path_rename`, `path_unlink`: each syscall of rows
  1, 2 and 4–8 also calls the `inode_*` hook of its row, and overlayfs's changes to its upper layer
  call the `inode_*` hook alone (row 20).
- `inode_mkdir`, `inode_rmdir`, `path_mkdir`, `path_rmdir`: directories are not judged
  ("Directories").
- `path_truncate`, `file_truncate`, `path_chmod`, `path_chown`: `fs/open.c` routes `do_truncate`,
  `chmod_common` and `chown_common` through `notify_change`, whose one security call is
  `security_inode_setattr`.
- `mmap_file`, `file_mprotect`: a shared writable mapping needs a descriptor opened for writing
  (`mm/mmap.c`, `FMODE_WRITE`), which `file_open` refuses.
- `file_permission`: judges descriptors that predate the policy or were passed in. The policy is
  attached before the container's first process ("What the backend must hold"), so none
  predates it, and the launcher passes no host descriptor into the container: it never uses
  `--preserve-fds`. A descriptor another container passes is `file_receive`'s case.
- `file_receive`: judges a descriptor arriving by `SCM_RIGHTS` or `pidfd_getfd`, both through
  `receive_fd` (`fs/file.c`), which the seccomp notifier's add-descriptor ioctl and io_uring's
  fixed-file install also call. The hook's isolation rests on io_uring staying refused: a
  transfer into another ring's fixed-file table by `IORING_OP_MSG_RING` was reported to skip
  the hook (a report to the io_uring list of 2026-05-21, not verified here on either kernel),
  and `io_uring_setup` answers `ENOSYS` under the launcher's profile ("Inventory", row 22),
  which Phase 6 tests under the profile it installs; a configuration that admits io_uring
  reopens this hook. `pidfd_getfd` needs a pid visible in the session's pid namespace, which
  holds the container's processes alone. A descriptor is judged where it is
  used: an `openat` through a received directory descriptor runs the receiver's hooks, and the
  sender's see nothing, since an `O_PATH` open returns before `security_file_open` (`fs/open.c`,
  `do_dentry_open`) and no hook is on the send; a descriptor already open for writing takes the
  receiver's `write` with `file_permission` alone, which is not attached. So the receiver's
  policy over the share is what counts, and the sandboxes that can exchange descriptors are
  those reaching one socket's inode: each launch has its own podman network and pid namespace,
  and a pathname socket is found by its inode (`net/unix/af_unix.c`, `unix_find_bsd`,
  `unix_find_socket_byinode`) through any mount of its superblock, a read-only mount included,
  since the permission check there (`include/linux/fs.h`, `path_permission`; `fs/namei.c`,
  `sb_permission`) refuses a regular file, a directory or a symlink on a read-only superblock
  and reads no mount flag. A socket bound in the workspace is thus reached through a direct
  bind of the tree and not through a FUSE mount of it; the launcher binds no socket into the
  container (`AgentSandboxLauncher`, the `podman create` arguments); and the clipboard and
  run-on-host relays speak through FIFOs that `podman exec` processes, which are in the cgroup,
  create. What two containers have in common is a volume, the raw tree where a
  `--workspace=read-only` session binds it (`AgentSandboxLauncher`, `workspaceBind`), and a
  linked worktree's main gitdir, bound read-only into its container.
  - By default the session opens no channel to another container: the policy refuses a socket
    inode on a superblock of the root's type, beneath a recorded root and beneath the
    persistent volume's root, by `inode_mknod`, `inode_rename` and `inode_link` ("The policy").
    The hook is then not attached. What else could carry a descriptor does not reach another
    container: an abstract socket stays in the launch's own network namespace, a socket pair in
    the processes holding it, and no socket is bound before the policy, which precedes the
    container's first process. A socket the host binds under the workspace is a listener in the
    host's kernel, which the VM's lookup does not find; on a native Linux host it would be, a
    question for that version ("Later versions"). Sockets under `/tmp` and the rest of `~`,
    each container's own, stay allowed. What binds where is measured in "Environment
    evidence": the one program with a socket on shared storage is Codex's app-server daemon,
    under `~/.codex`, and whether `codex exec` works without it is a Phase 3 row.
  - `unix-socket` lifts the refusal and attaches
    `file_receive` as a ninth hook, run on the receiver's cgroup since the hook's argument is a file
    (`kernel/bpf/bpf_lsm.c`, `bpf_lsm_find_cgroup_shim`). Of a file whose mount belongs to
    another mount namespace (`fs/mount.h`, `real_mount`, `mnt_ns`; the task's in `nsproxy`), or
    to none, because the sender's container ended before the receiver read the message and its
    namespace was torn down with it (`fs/namespace.c`, `umount_tree` clears `mnt_ns`), it
    refuses a directory, whatever it names; it passes a non-directory on a superblock of the
    root's type only beneath a recorded root and, when it has `FMODE_WRITE`, only where the
    receiver's `file_open` would admit opening it for writing, which the sender's may have, since
    two sessions of one workspace run under the rule files of their own launches ("The policy",
    the maps); one on a superblock of the volume's type only beneath the recorded volume root, so
    another workspace's volume file does not arrive; and one of any other type, which reaches no
    share and starts no lookup. Under `NESTING=none` another mount namespace is
    another container: the profile refuses a user namespace, `CLONE_NEWNS` needs `CAP_SYS_ADMIN`,
    which `CapEff` zero lacks ("Environment evidence"), and `podman exec` joins the container's
    namespaces; the mounts inside the container, `/tmp`, the volumes and the bind, are its
    namespace's own, and a pipe, a socket or an anonymous inode sits on a kernel-internal mount of
    no namespace (`fs/namespace.c`, `kern_mount`, `MNT_NS_INTERNAL`) and passes, reaching no
    filesystem, as does a file of the runtime's own namespaces: one whose root is the receiver's
    own root directory, which is the host's root for the runtime's processes, the container's
    init before it pivots into the container's root among them, and a container's root for every
    session process, whose own namespace alone has it (`fs/namespace.c`, `pivot_root`); the one
    the controller runs in, by the inode number of its own `/proc/self/ns/mnt`; and an anonymous
    one, told by its flag on 7.2 and by the one inode number, 0xEFFFFFF7, that every anonymous
    namespace carries on 6.18 (measured: `crun` 1.28 passes the volume as such a clone whose root
    is the volume directory, "Phase 3 on WSL"), which `open_tree`
    with `OPEN_TREE_CLONE` makes (`fs/namespace.c`, `is_anon_ns`): the session has neither under
    the profile, and the runtime passes the container's mount sources into it as it starts
    (measured: a directory descriptor of the volume's mountpoint, refused as a directory, ended
    `crun`'s start, "Phase 3 on macOS"; on WSL the same descriptor came from a namespace that was
    neither the controller's nor pid 1's, which are one there, so the runtime's namespaces are
    not knowable by number, "Phase 3 on WSL"). What keeps that exception the runtime's: a descriptor
    of those namespaces can be sent only by a process holding one, the runtime's own processes,
    which pass them to the container's init before it execs the first process and leave none
    open across that exec (Phase 3's row on the first process's descriptors), and to which the
    session has no socket, since the sockets a session can reach are its own and, under the
    option, those of other sessions in the volume; so what processes of one container pass each
    other passes as today. A directory
    descriptor from another namespace is refused whatever it names: a lookup through it starts at
    its own path and mount (`fs/namei.c`, `path_init`), descends the mounts beneath, found by parent
    mount and dentry whatever the caller's namespace (`fs/namespace.c`, `__lookup_mnt`), and ascends
    by `..` past the receiver's root and the sender's bind (`follow_dotdot`, `choose_mountpoint`),
    so a descriptor of the sender's container root reaches its writable workspace bind, and one of
    `/repo/sub` passed to a sandbox of `/repo/sub` by a sandbox of `/repo` reaches `/repo`, where
    `mkdirat` and `unlinkat` with `AT_REMOVEDIR` are judged by no hook ("Directories") and, under a
    profile without the seccomp rules, a read-only open takes `fsetxattr` and `ioctl` ("Attributes,
    flags and ioctls"). A non-directory descriptor starts no lookup (`path_init` answers `ENOTDIR`
    to a name through one), and a reopen of it by an empty name is a `file_open`. `scm_detach_fds`
    (`net/core/scm.c`) installs a message's descriptors in order and stops at the refusal: the
    earlier ones arrive, the later ones are dropped, and the message carries `MSG_CTRUNC` with no
    error from `recvmsg`.
    - Under the option a socket inode does not enter a gitdir directly, by `inode_mknod`, by
      `inode_rename` of one bound elsewhere, each way for an exchange, or by `inode_link`, each
      judged on the inode the hook holds (`S_ISSOCK` of `old_dentry` for the last two): a
      filter-backed worktree session reaches the main checkout's gitdir bind with no policy,
      and the filter admits a socket under `objects`, judging only the name and the destination
      (`fs.rs`, `allow_create`). A symlink adds no reach: `connect` follows it
      (`unix_find_bsd`, `LOOKUP_FOLLOW`) in the connecting container's own mount namespace,
      where a filter-backed session has no raw host inode but the gitdir bind's and the
      volumes'. Git binds one socket in a gitdir, `fsmonitor--daemon.ipc` at its root
      (`compat/fsmonitor/fsm-ipc-unix.c`, `fsmonitor_ipc__get_path`), a name outside the root's
      allowlist (`policy.rs`, `OPERATIONAL_FILES`) that the filter refuses today, so the rule
      costs nothing. It sees the moved inode alone: a directory holding a bound socket, renamed
      into `objects`, carries it in, and the launch refusal below is what the pair of a main
      checkout and a filter-backed worktree rests on, this rule narrowing the direct routes.
    - A second sandbox of the workspace under this backend judges its use of the descriptor by
      the same policy, and a sandbox of another workspace allows nothing on the share outside
      its own roots ("The policy") and receives no writable file of it, so a descriptor into
      this workspace gives it nothing. Both are Phase 3 rows.
  - A `--workspace=read-only` session shares the raw tree and the volume with a live one, and
    its `ro` mount judges only what it opens by path: an `openat` through a received directory
    descriptor resolves on the sender's writable mount, so without a policy of its own the
    session could open the live session's `.git/config` for writing, judged by nothing. So it
    runs under a policy recording no root ("The policy"), and that is why its launch runs the
    controller as a live launch does. The filter admits what a passed descriptor widens, since
    the live session's mount judged the open; here nothing arrives by default, and under the
    option `file_receive` refuses the writable file. Where the probe fails, no session of the
    host has a policy, and the mode keeps the raw `ro` bind alone ("Native Linux"). A Phase 3
    row.
  - A filter-backed session has no policy over the share, and a session without the option has no
    `file_receive`, so the launcher refuses a launch whose backend or option differs from that of a
    live session it shares a raw mount with, naming that session. The raw mounts are the volume, the
    workspace tree and a linked worktree's main gitdir (`SandboxWorkspace.linkedGitdirBind`): a
    linked worktree may mount its main checkout's own volume (`LauncherState.mainWorktreeVolume`),
    `--persistent-volume` names one for any workspace, two sessions of one workspace may name two, a
    workspace root above or below another's binds the same directories, and the gitdir bind lies
    under the main checkout's root, so a worktree session under the other backend or setting is
    refused beside the main checkout's whatever its volume. Each sandbox container carries labels
    naming its backend, its option, its volume and, for each raw mount, the host path and the
    `(superblock, inode)` identity the controller's `stat` in the VM gave before the container was
    created ("The policy"); a path alone goes stale, since a host rename leaves a live session's
    mount on the renamed directory (the Phase 1 identity test) while a new launch spells the new
    name. The launcher lists every sandbox container by the name pattern each of its versions has
    used (`sandboxRunContainer`; `podman ps --all --filter name=`,
    https://docs.podman.io/en/latest/markdown/podman-ps.1.html), reads the labels, and compares the
    volumes for equality and the raw mounts by identity for equality; for ancestry it first re-reads
    each live session's recorded paths in the VM and refuses beside one whose path no longer names
    its recorded identity, then compares the paths. A listing or a `stat` that fails refuses the
    launch, as does a live container without the labels, from a launcher that predates them, each
    named. The launcher holds one launch lock per machine (`FileHelper.withFileLock`, as the
    per-workspace `.lock` under the TLS state directory) from the listing until its container
    exists, so of two launches racing, one sees the other's container; a host rename inside that
    window is the one case the comparison does not see, the host's own act, which the trust model
    leaves to the host ("What the backend must hold") as the filter leaves it the renames and
    coherency races it admits ("What is gained and what is lost").

### Mounts

Under `NESTING=none`, the launcher's seccomp profile refuses creating a user namespace and every
mount syscall (`TODO.md`, "Refuse user namespaces and mounts under `NESTING=none`"). That item
ships before this backend, and the backend does not ship without it.

- It removes row 20's overlay mount, whose `user.overlay.*` writes no taken slot holds, and row
  21's bind of the workspace at a second path: without a user namespace the session holds no
  capability to mount with.
- The profile has neither rule under `NESTING=same-uid`, where a nested podman creates user
  namespaces and mounts, nor on a `NESTING=none` session launched with the profile's loosening
  option. On both, a later version's sessions ("Later versions"), the hooks judge rows 20 and 21
  ("The policy"), and overlayfs's `user.overlay.*` names are the decision "Decisions still open"
  holds for them.


## The policy

The program classifies by object and position, never by a path string:

- The sandbox's policy names its workspace root as `(superblock, inode)`, recorded by the
  controller from the VM's own `statx` of the bind source, with the root's filesystem type name;
  a `--workspace=read-only` session's policy records the type and no root. The program walks
  `d_parent` from the target dentry, bounded, folding each name as `policy.rs` folds
  (`git-metadata.md`, "The name rule"), until it meets a recorded workspace or volume root or
  the filesystem root. A recorded gitdir root or guarded object met on the way is marked and
  the walk goes on, so that the file rules and a symlink target's depth keep the workspace's
  ancestry above it; it is the walk's root only when the walk reached the filesystem root with
  no workspace root above it, while a walk that reaches the bound denies whatever it marked.
  An object on a superblock of another type, `~`, the volumes and the container's own
  filesystems, is outside before any walk and allowed. On a superblock of the root's type, a
  mutation is allowed only beneath a recorded root: a walk that meets none, or reaches the
  bound, which stays above the deepest path Phase 2 measures, denies. Every workspace a machine
  serves is on its one share type, which Phase 1's `findmnt` row records (on Windows the
  launcher takes `/mnt/<drive>` paths alone, `SandboxWorkspace`), so another workspace's object
  is of the root's type.
  - Nothing the session may write lies there: the container's one other host bind, a linked
    worktree's main gitdir (`SandboxWorkspace.linkedGitdirBind`), is read-only, and the rest is
    volumes and its own filesystems. What the rule denies is another workspace's directory
    reached through a descriptor a sandbox passed ("The hooks", `file_receive`), the whole
    share for a read-only session, and the same type's unrecorded superblocks: a submount the
    guest mounts mid-session ("Mounts" below) is one and in no table, while a FUSE mount the
    session makes is of type `fuse`, not `virtiofs`.
  - The identity's encoding, one on both sides: the program reads the inode's `i_ino` and its
    superblock's `s_dev`, a `dev_t` the kernel lays out as `MKDEV` does (`include/linux/kdev_t.h`,
    `MINORBITS` 20); the controller records `statx`'s `stx_ino` and `MKDEV` of its
    `stx_dev_major` and `stx_dev_minor`, which `fs/stat.c` (`cp_statx`, `generic_fillattr`)
    fills from the same two fields, while a plain `stat`'s `st_dev` is `new_encode_dev`'s other
    layout. FUSE fills the inode's number and the attribute from the server's one number
    (`fs/fuse/inode.c`, `fuse_squash_ino`, the identity on a 64-bit kernel; `fs/fuse/dir.c`,
    `fuse_fillattr`). Phase 1 compares the two readings of one object on both kernels.
- No socket inode comes to be on a superblock of the root's type, beneath a recorded root, or
  beneath the persistent volume's root, recorded as `(superblock, inode)` like a workspace root
  since the volume shares its superblock with `~` ("Environment evidence"): `inode_mknod`
  refuses the creation, and `inode_rename`, each way for an exchange, and `inode_link` refuse a
  source whose inode is a socket. The walk from the new name's parent that meets the volume's
  root, or the bound, denies. The three hooks see the moved inode alone, so a directory holding
  a bound socket, moved whole, would carry it; what stops that is the mount layout, which Phase
  4 tests: a socket is bound under `~`, the volume and the share are other mounts, and `rename`
  across mounts answers `EXDEV` before any hook (`fs/namei.c`, `do_renameat2`), while beneath
  the volume no socket comes to be in the first place. A version that binds another mount into
  the container reopens this. `unix-socket` lifts the rule and keeps a socket out of a
  gitdir by the same three hooks ("The hooks", `file_receive`, has the channel each closes).
- No FIFO comes to be on a superblock of the root's type beneath a recorded root, none there is
  opened, and none has its times changed: `inode_mknod` refuses the creation by type,
  `file_open` any open of one by the inode's type, for reading as for writing, before the hook's
  early exit for reads, and `inode_setattr` a time change on one, by type and `ATTR_ATIME` or
  `ATTR_MTIME` in the attribute's `ia_valid` (`include/linux/fs.h`), so that `chmod` and `chown`
  of one stay as they are, as in the filter; on every platform. The user's decision of
  2026-10-25, taken against documenting the hazard and waiting for libkrun: on the macOS machine
  a FIFO's times reaching libkrun's passthrough `setattr` block the share's one worker thread,
  and with it every session on the machine (`../doc/upstream-issues.md`, "Setting a FIFO's times
  blocks the macOS virtio-fs server"; `../doc/TODO.md`, "A FIFO in the workspace hangs the podman
  machine"). Why three hooks: a write through a FIFO makes the guest kernel flush its times to
  the share itself (`fs/pipe.c`, `pipe_write`, `file_update_time`; `fs/fuse/file.c`,
  `fuse_write_inode`, `fuse_flush_times`), past `security_inode_setattr`, which `fs/attr.c`
  calls from `notify_change` alone, so the time rule holds `touch` and not use; the open rule
  holds use, of a FIFO the host made included, since every open but `O_PATH` passes
  `security_file_open` before the file's own open (`fs/open.c`, `do_dentry_open`) and an
  `O_PATH` open opens no pipe. Under `unix-socket`, `file_receive` refuses a FIFO of the
  share's type by inode type too, whatever its mode: a container on the machine outside any
  policy can open one and pass the descriptor, and a write through it would flush the times as
  the session's own open would. A `--workspace=read-only` session needs none of these: its bind
  is read-only, which still lets a FIFO be opened for writing, since `do_dentry_open` takes the
  mount's write access for no special file (`fs/open.c`), but a write or a read through it
  changes no time on the share, since `file_update_time` and `touch_atime` take that write
  access first and skip the update where the mount refuses it (`fs/inode.c`,
  `mnt_get_write_access_file`), and FUSE flushes `mtime` and `ctime` alone (`fs/fuse/dir.c`,
  `fuse_flush_times`). What stays is the host's own use of a FIFO it made, and a container
  outside any policy using one, neither of which a session's hook sees. The filter, whose
  daemon receives the flush as a `SETATTR` request, refuses it instead (`fs.rs`, `setattr`),
  since the kernel opens a FIFO on a FUSE mount without asking the daemon. The rules wait for
  the program's next build (Phase 6): the measured sections of Phases 3 to 5 name the present
  sources' hash, which they change.
    Each share is one superblock (`fs/fuse/virtio_fs.c`, `virtio_fs_test_super`), so a second
    share bound into a disposable container is Phase 3's stand-in for a submount made after
    attach.
- A string from `bpf_path_d_path` is not an identity: where "Mounts" allows them, unprivileged user
  namespaces work inside a session, so a task can bind the workspace at a second path
  in a mount namespace of its own.
- Inside the root, the walk's names give the position the filter's classifier uses: a `.git`
  component, the entries under it, `modules/<name>` and `worktrees/<name>`, `.ko-agent-sandbox`,
  and a file-rule line. The sandbox's policy also names the proof fixture's root as a second
  root ("Lifecycle"), judged by the same rules.
  - The line set is the launcher's resolved rules, the same text the filter receives, which the
    unprivileged guard (`ko-agent-fs --resolve --bpf-records`, `bpf_records.rs`) folds and
    compiles into fixed-size map records before attach, in the layout of the C header it
    generates (`../fuse/ko-agent-fs/include/records.h`). The controller loads those records and
    parses no text from the workspace.
    The records are bounded, and the guard refuses a launch whose rules exceed a bound: 128
    lines of at most 7 components of 63 bytes, 16 alias contexts (the context of a symlink whose
    end an anchored `pinned-path` line names, which every entry below the end also stands as,
    `RuleContext::also`), and at most 2 alias contexts live at one position, a third denying
    the mutation. The program keeps the alias contexts as the filter does: activated at the
    line's end, advanced with each name below it, dropped once they can decide nothing.
- The gitdir allowlist (`git-metadata.md`, "The classifier") is the policy here too. The filter
  finds a nested gitdir's root by the `HEAD` it holds, a lookup a program cannot make, so the
  controller records the roots under `modules/` at launch; a namespace without a recorded root
  stays wholly protected, the filter's own strict default, and the sandbox cannot add a root
  since the `.git` pointer its worktree needs is refused.
- "Directories" adds three rules to the classifier: no new `HEAD` in a `.git`, a `read-only` line
  applying below a `.git`, and a `.ko-agent-sandbox` protected in git state too; "The policy"
  and "The hooks", `file_receive`, the socket rules.
- A second name of a guarded entry, a hard link to a `.git` pointer file or an NTFS short name,
  is the same object, which the filter recognizes by comparing every ordinary entry with its
  guarded siblings on each lookup (`fs.rs`, `policy_name`), a lookup a program cannot make.
  Here two rules replace it:
  - the controller records the identity of the workspace root's `.git` and `.ko-agent-sandbox`,
    of every gitdir the guard finds under `.git/modules`, and of each submodule worktree's `.git`
    pointer file, which the guard finds through that gitdir's `core.worktree` (`guard.rs`,
    `collect_guarded`; a gitdir whose config names no such file records none, and that pointer
    file is then guarded by its name alone), so any name of those objects is judged as the object: a
    walk meeting a `.git` object's identity is at the gitdir entry, one meeting the
    `.ko-agent-sandbox` object's is in the launcher's directory, at whatever depth and name;
  - on Windows, a mutation whose ancestry holds a component of NTFS's generated short-name form,
    uppercase, a tilde and a digit within the 8.3 lengths, is denied whatever the component is,
    which covers a `.git` the host creates mid-session. Cost: no session write through a name of
    that form on Windows, a form no project is known to use. The exact form is a Phase 3 row.
  - What neither covers, a residual the change adding the backend records beside
    `git-metadata.md`'s for host-made hard links to protected inodes: a hard link the host makes
    to the `.git` pointer file of a nested repository that is not a submodule, or to any guarded
    file after launch, is ordinary data to the walk, and a rewrite of the pointer through it is
    within the property. The session cannot make such a link, since `inode_link` refuses a
    guarded source; the filter catches only a link beside its target, by comparing siblings; a
    scan of the whole tree at launch would cover the launch-time half at the cost of a walk of
    the tree per launch, the cost the backend removes, and nothing a program can do covers the
    mid-session half. The residual narrows the property, and the host's trust does not restore
    it: a host program that hard-links such a file for its own reasons, a backup or `cp -al`,
    gives the session a write path to the pointer that the host did not intend, so the
    statement of the property excludes a host-made second name the policy cannot recognize.
    The user, 2026-10-22, on recording the submodule pointer files and accepting the rest: "Add
    the third option as recommended one, as you recommend."
- A mount inside the workspace, a filesystem the host mounted at `<workspace>/vendor`, has dentries
  whose `d_parent` chain ends at that filesystem's root, never at the workspace root, so a walk
  by dentry alone would allow everything in it; a bind mount of a directory of the workspace's
  own filesystem has dentries whose chain passes the bind's source, not its mountpoint. The
  filter crosses such mounts and classifies their contents (`fs.rs`, `open_ino`, no
  `RESOLVE_NO_XDEV`). Here:
  - the first version refuses the launch when the VM shows a mount under the bind source, and
    names it. The session makes none ("Mounts"), the launcher binds nothing under the workspace
    (`SandboxWorkspace.linkedGitdirBind` refuses a target inside the workspace mount or holding
    it), and a mount the host adds mid-session does not propagate into the container under
    podman's default `rprivate`; what remains is the share. Whether the macOS and Windows virtiofs
    servers present a host-side mount as one tree or as a nested superblock, one present at
    launch and one the host makes after attach, is a Phase 2 row, with the launch refused for the
    former and the mutations beneath the latter denied: only virtiofs auto-mounts a directory
    its server flags with `FUSE_ATTR_SUBMOUNT` (`fs/fuse/virtio_fs.c`, `auto_submounts`), as a
    new superblock of the parent's type at the guest's next lookup (`fs/fuse/dir.c`,
    `fuse_dentry_automount`, `fs_context_for_submount`), and a 9p share never does. Apple does
    not document whether its server flags one; neither rule depends on the answer;
  - native Linux's version ("Later versions"), where the host's own `git` reads a tree with the
    user's binds and tmpfs mounts under it, records them instead. The bind is recursive, so the
    sandbox sees them: `--mount type=bind` binds recursively by default, while `--volume` does
    not and needs `rbind` (https://docs.podman.io/en/latest/markdown/podman-run.1.html). The
    controller lists the mounts under the bind source at launch and records each mount's root as
    `(superblock, inode)`, as it records the workspace root, with the classification context of
    its mountpoint; the walk stops at the first recorded root it meets and resumes from that
    context. A superblock alone would not do: it does not tell a bind of a subdirectory from the
    filesystem's root, and it does not see a bind from the workspace's own filesystem at all. No
    hook follows a mount: a superblock and its dentries are the same objects through every mount
    of them, so a bind the session makes in a mount namespace of its own, of the workspace or of
    a nested filesystem, at any other path, gets the same answer, and the host's `git` never
    sees that namespace. A mount root that is the same as, an ancestor of or a descendant of
    another recorded root, or of the workspace root, refuses the launch, since its dentries
    would have two positions: two binds of one source directory, and a bind of a workspace
    directory at a second workspace position, are that case; a bind from outside the workspace
    at one position is recorded like a nested filesystem.
- Each sandbox has its own programs and maps: the controller loads the eight programs per launch
  with that sandbox's maps, so a program references its own sandbox's records and no other's,
  which is what the read-back in "Lifecycle" compares. The maps are written before attach and
  never after: a rule change is a relaunch, as with the filter, so no record changes under a
  running program. The slots are per hook, not per program
  (`bpf_cgroup_atype_find` keys them by `attach_btf_id`), so this takes no slot; its cost is the
  verifier's time per program set, paid ahead of the launch ("Lifecycle", the spare set).
- An error in the walk, a name too long for the bound, or a missing map entry denies.


## Lifecycle

The programs enforce; the controller only loads them. It is an ordinary process making the
`bpf` syscalls that need `CAP_BPF` with `CAP_PERFMON`, or `CAP_SYS_ADMIN`, beside the kernel
that enforces: in a podman machine the launcher runs it for the launch through
`podman machine ssh` under the machine's `sudo`, and on native Linux directly under the host's
(the sudoers drop-in "Native Linux" names); it exits once the links are pinned. The session never
has those privileges, and the controller never reads the workspace: its input is the launcher's
fixed-size records, made by the unprivileged guard ("The policy"), and its output is links and
maps.

`--build` installs the BPF object and the controller into the machine, as it installs the
filter. The controller then runs at every launch, restart and recreate, since each attaches to a
new cgroup and only a privileged caller can: one `sudo -n` per launch, in the machine or on the
host. The verifier checks a sandbox's nine programs within 0.6 s on the macOS machine and 1.85 s
on the WSL one ("Phase 4 on macOS", "Phase 4 on WSL"), time no launch waits for: the controller
keeps one spare set per machine, loaded and pinned with empty maps and attached to nothing, which
a launch takes by renaming its pin directory to the session's name, fills and attaches (step 2),
and the controller prepares the next spare afterwards, in the background, as a boot-time unit
prepares the first. Without a spare, a launch loads as the spare would and is slow once. A restart
or recreate attaches the programs the launch pinned (step 5). A spare is used once, dies with the
boot as every pin does, and fails the read-back's tag check when `--build` installed another
object since, as a stale pin does; the fill through the pinned programs' map ids is the one step
Phase 4 did not run, which Phase 6 measures. The pins outlive the controller, and a pin in `bpffs`
does not survive a machine restart.
For each session:

1. Create the attach cgroup before any container process exists, and keep it alive: under the
   systemd manager, a transient slice held by a VM-side unit, under which `podman create
   --cgroup-parent=<slice>` places the container; under the cgroupfs manager, the WSL machine's
   ("Environment evidence"), a directory the launcher makes under the user's delegated subtree,
   which podman takes as an absolute `--cgroup-parent` and which stays until removed ("Phase 1
   on WSL").
   - A link whose cgroup is removed is detached without an error (`cgroup.c`,
     `bpf_cgroup_link_release`, "auto-detached by dying cgroup"), so what removes the slice
     decides whether the hold unit is needed: systemd left the empty slice and the link in place
     for the 60 s Phase 1 watched after the hold unit and a container below had stopped, and a
     stop of the slice unit removed it within 1 ms and detached the link ("Phase 1 on macOS").
     Whether systemd ever removes the empty slice by itself is unmeasured beyond those 60 s, so
     the hold unit stays until a longer watch says otherwise, and teardown stops the slice unit.
   - Rejected: the container's own cgroup, a scope under systemd and a directory under cgroupfs,
     attached between `podman init`, which performs every step short of starting the container
     (https://docs.podman.io/en/latest/markdown/podman-init.1.html), and `podman start`. It
     works: on both machines the cgroup exists after `podman init`, holds the runtime's process
     alone, and a policy attached there refuses the started command ("Phase 1 on macOS",
     "Phase 1 on WSL"). It fails "What the backend must hold": the `createContainer` hooks run
     in the container's namespaces during create, before any attach there is possible (OCI
     runtime spec, `config.md`, "CreateContainer Hooks").
   - In which cgroup a `createContainer` hook runs is what the spec leaves open: a hook may
     expect the mounts and nothing about cgroups (the same section, and
     https://github.com/opencontainers/runtime-spec/issues/1039). crun, 1.30 on macOS and 1.28
     on WSL, runs it inside the container's own cgroup below the attach cgroup, where the policy
     refused its write ("Phase 1 on macOS", "Phase 1 on WSL"); a crun that ran a hook outside
     would reopen this step.
2. Take the spare set, or load the sandbox's programs and maps where none is ready; fill the
   records, attach every program by link, pin the links and the programs where the session cannot
   reach, and read them back. A pinned link holds its program and the program its maps
   (`kernel/bpf/syscall.c`, `bpf_link_free`), so the maps need no pin; the programs are pinned for
   step 5 and for the spare, so that a restart, a recreate or a launch attaches them without the
   verifier's time again.
   The controller attaches only below the invoking user's slice, in the machine as on native
   Linux ("Native Linux"); any other cgroup is refused before the attach.
3. Prove the enforcement without trusting step 2's report, in two parts, both before any
   container process runs.
   - A read-back by a separate program, with the controller's privileges and none of its code:
     for each hook of the session's set, the eight of "The hooks", the ninth under
     `unix-socket` and those a decision in "Decisions still open" adds, `BPF_PROG_QUERY` on
     the attach cgroup with `BPF_LSM_CGROUP`
     lists the attached programs by id, as the kernel's own test does
     (`prog_tests/lsm_cgroup.c`, `query_prog_cnt`), with the attach-flags buffer the query of
     this type requires beside the id buffer (`__cgroup_bpf_query`, `EINVAL` without it).
     - One query lists the programs of every hook together (`kernel/bpf/cgroup.c`,
       `__cgroup_bpf_query`, `CGROUP_LSM_START` to `CGROUP_LSM_END`). For each program,
       `BPF_OBJ_GET_INFO_BY_FD` gives its `attach_btf_id`, tag and `map_ids`
       (`kernel/bpf/syscall.c`, `bpf_prog_get_info_by_fd`): the ids must name each hook of the
       set once and nothing else, the tag must equal the installed object's, and every map,
       opened by id (`BPF_MAP_GET_FD_BY_ID`, which needs `CAP_SYS_ADMIN`), must have the record
       format's type, key and value sizes and entry count, and the records the guard produced
       as its contents; the string literals' read-only map must hold the installed object's
       bytes, since the tag covers instructions alone and a build differing in data alone keeps
       every tag.
     - The tag alone proves nothing about the maps: the kernel zeroes map references before
       computing it (`kernel/bpf/core.c`, `bpf_prog_calc_tag`).
   - A fixture the kernel judges, under the launcher's state root on the machine's share, so a
     missing hook costs nothing in the workspace. It must be on the share: an object on a
     superblock of another type is allowed before any walk ("The policy"), and a fixture there
     would fail every expected refusal. The controller records the fixture root's filesystem
     type as it records the workspace root's and refuses the launch when the two differ.
     - The guard writes a tree laid out as a workspace, with a `.git` holding `config` and a
       hook, a `.ko-agent-sandbox`, and one entry per resolved rule line, and the sandbox's
       policy records that tree's root as a second root. It writes the tree once and lays its
       entries out again, the root keeping its identity, only after a failed proof or when the
       resolved rules changed: a passed proof changes nothing in it but the writable entries'
       content, and each entry costs a round trip of the share.
     - The launcher places a process of its own in the attach cgroup and runs one refused
       operation per hook of that set against the fixture: `creat`, `mkfifo`, `symlink`, `link`
       and `rename` to a guarded name, an `unlink` of a guarded entry, an open for writing and a
       `chmod` of a guarded file, a `bind` of a socket in the fixture or, with `unix-socket`,
       in its `.git`, and one operation per hook a decision adds; then one write per rule-line
       entry and one write to an ordinary entry.
     - Each write's expected answer is derived from the whole ordered rule set, as the filter
       decides it (`file-rules.md`, "The rule file"): refused under a `read-only` line, allowed
       under a `writable` line such as the defaults' `writable node_modules`, and the later
       line's answer where lines overlap; the fixture holds an overlapping pair on purpose.
       Every answer must be the expected one.
   A difference in either part ends the launch. Together they catch a controller that attached
   nothing, attached a subset, attached another build, loaded the wrong records, or whose
   program uses another map; what they do not catch is a defect the program shares with the
   fixture's expectations, which Phase 3's corpus is for.
4. Create and start the container; its scope, or its directory under cgroupfs, lands below the
   proven cgroup.
5. A restart or recreate repeats 1–4 with step 2 attaching the pinned programs to the new cgroup
   by link, loading nothing, when step 3's read-back of the pinned programs finds the installed
   object's tag and the records the guard produces for this launch; a pinned program of another
   tag or over other records, as after `--build` or a rule change, is unpinned and the step loads
   and verifies fresh ones as at launch. Step 3 then proves the attached set as at launch; a stop
   of the container does not detach. `podman exec`
   joins the container's cgroup and needs nothing. No container with a writable workspace is
   started by anything but the launcher's steps 1–4: the launcher creates it with `--restart=no`,
   so that `podman-restart.service`, which starts containers under `always` or `unless-stopped`
   when the machine boots, never starts one whose pins the restart lost, and a start by a unit
   or by hand outside the launcher is outside the supported lifecycle.
6. On teardown, end every task under the cgroup, then detach and unpin the sandbox's links and
   programs, whose release frees the programs and maps, and remove the cgroup.
7. Reconcile at every launcher start, under the per-machine launch lock ("The hooks",
   `file_receive`): list the pinned links, programs and attach cgroups beside podman's
   containers. The spare's pin directory is kept while its tags are the installed object's and
   unpinned otherwise; a directory named for a session the lock holder is not launching and no
   container names is a launch that died after taking the spare, and goes as an orphan. A pin
   and its cgroup are removed only when no container, a stopped or initialized one included,
   names the cgroup, no launch or restart holds the lock, and the cgroup's
   `cgroup.events` reads `populated 0`, which counts the descendants' tasks as `cgroup.procs`
   does not
   (`Documentation/admin-guide/cgroup-v2.rst`, "Core Interface Files"); under systemd the hold
   unit is stopped first, once the cgroup has no container, so that it does not count. A stopped
   container keeps its pins (step 5), so an empty cgroup alone is no orphan. A listing or a
   label that cannot be read leaves every pin in place and is reported, each named. The reconcile
   removes only cgroups below the user's slice and pins below the controller's own directory,
   each by the identity the launcher recorded, and refuses a symlink, another filesystem or a
   path outside those roots, as a cleanup guard elsewhere has admitted `.` and volume roots as
   safe to remove (https://github.com/kubearmor/KubeArmor/issues/2822).

A failure at any step before 4 ends the launch; the launcher prints which step and never binds
the workspace writable. During a session the policy cannot lapse without a trusted hand: a link
is detached only when its cgroup is removed, and a cgroup with the container's scope or
tasks in it cannot be removed, so only root detaching the link ends the enforcement, and root
is trusted ("What the backend must hold"). Phase 4 proves both.


## Environment evidence

Both machines were measured on 2026-10-10 and 2026-10-11 with a plain container and no BPF
program: the placement below is settled, the enforcement is not. Repeat a row only after a
change in the component it names: a kernel, WSL, podman, crun or cgroup-manager change reopens
the placement and hook rows of that platform; nothing else does.

macOS, the default podman machine, measured on 2026-10-19 and 2026-10-20:

| item          | observed                                                                       |
| ------------- | ------------------------------------------------------------------------------ |
| machine       | Fedora CoreOS 44.20260913.3.2, aarch64, kernel 7.2.5-200.fc44                  |
| LSMs          | `lockdown,capability,yama,selinux,bpf,landlock,ipe,ima,evm`                    |
| BPF           | BTF readable with every hook of "Inventory", `kptr_restrict` 0 (from a         |
|               | session); bpffs `/sys/fs/bpf` mode 700, `libbpf` 1.6.3, no compiler            |
| podman        | rootless, `cgroupManager=systemd`, cgroup v2, crun 1.30; `sudo -n`             |

Windows, an EC2 Server instance, build 10.0.26100.32522:

| item          | observed                                                                       |
| ------------- | ------------------------------------------------------------------------------ |
| WSL           | 3.0.3.0 (`wsl --update --pre-release`), kernel 6.18.54.1                       |
| LSMs          | `capability,landlock,yama,safesetid,selinux,bpf,ima`, `securityfs` mounted first |
| BPF           | BTF readable; `sudo -n` works; the machine mounts no bpffs and no securityfs   |
|               | (measured 2026-10-21: a pin under `/sys/fs/bpf` fails until one is mounted)    |
| podman        | 6.1.4, rootless, cgroup v2, provider `wsl`; its manager is cgroupfs (measured  |
|               | 2026-10-21), which refuses a slice as `--cgroup-parent` and places a container |
|               | at `user@1000.service/app.slice/<id>`; 6.1.0 reported systemd on 2026-10-11    |

WSL 3.0.1.0 ran kernel 6.18.40.1, whose published `CONFIG_LSM` lacks `bpf`; 3.0.3 was installed
for its kernel, a release since 2026-10-09, with 3.0.4 of 2026-10-20 the pre-release
(https://github.com/microsoft/WSL/releases).

The placement under the systemd manager, measured on both machines on 2026-10-10 and 2026-10-11,
macOS on its earlier kernel 7.1.8: after
`systemd-run --user --unit=ko-agent-probe-hold --slice=ko-agent-probe.slice /usr/bin/sleep 180`,
the cgroup of a container run with `--cgroup-parent=ko-agent-probe.slice` was, with uid 501 on
macOS and 1000 on Windows,

```text
/user.slice/user-<uid>.slice/user@<uid>.service/ko.slice/ko-agent.slice/
    ko-agent-probe.slice/libpod-<id>.scope/container       (one path, wrapped here)
```

The Windows placement needs `%UserProfile%\.wslconfig` holding `[wsl2]` and
`isolateDistroCgroup=false`, after `wsl --shutdown`. With the default, `podman run` fails with
`crun: controller pids is not available`; `--cgroups=disabled` makes it run but places the
container in no cgroup of its own, which this backend cannot use. The setting applies to every
WSL2 distribution of that Windows user, and the launcher neither writes nor removes it: the
setup note for Windows names it. References:
https://learn.microsoft.com/windows/wsl/wsl-config,
https://github.com/microsoft/WSL/issues/41492,
https://github.com/podman-container-tools/podman/issues/29749.

### Phase 1 on macOS

Measured on 2026-10-21 with `../bpf/probe/phase1/phase1.sh` on the machine above, podman 6.1.2,
clang 19.1.7, no other `lsm_cgroup` link in the VM. The probe's transcript holds the raw lines.

| row                      | measured                                                              |
| ------------------------ | --------------------------------------------------------------------- |
| share                    | `/Users` virtiofs, `rw,relatime,context=system_u:object_r:nfs_t:s0`   |
| verifier, per program    | 10,880 to 11,382 insns, at most 4 states per insn, 118 to 131 ms      |
| verifier, all eleven     | 159 ms in one load: the time is the load's, not the programs'         |
| jited `file_open`, arm64 | 1,808 bytes holding two `ldaddal`, one per fetch-add                  |
| walk, under the slice    | 1,379 calls, 1,379 settled, 0 retries, depth 19 at most               |
| slice shape              | the marker refused for writing with `EPERM`, readable, its sibling   |
|                          | written; a container outside the slice writes the marker             |
| identity                 | the program's `(s_dev, i_ino)` equals statx's `(mkdev, ino)`,         |
|                          | `(41, 242960587)`, type `virtiofs`; unchanged after a host rename of  |
|                          | the file and of an ancestor, after `drop_caches`, and for both names |
|                          | of a host-made hard link; a directory's likewise, after its own      |
|                          | rename too, and read by the program on `opendir` as statx reads it   |
| replacement              | after the host's `rm` and create at the same name, the guest answered |
|                          | `ENOENT` to statx for about 3 s, for the file and for the directory, |
|                          | then gave the new inode; a container's open of the file failed the   |
|                          | same way, and the program then read the file's new inode as statx did |
| slots                    | `file_open` on two slices takes one hook; ten distinct hooks attach,  |
|                          | the eleventh answers `EINVAL`                                         |
| populated                | with a container below it the slice holds no task of its own and     |
|                          | `cgroup.events` reads `populated 1`, still 1 after the hold unit     |
|                          | stopped, 0 after the container stopped                               |
| empty slice              | present with its link 60 s after the hold unit and the container     |
|                          | stopped; a stop of the slice unit removed it within 1 ms, and the    |
|                          | link's cgroup id read 0                                              |
| scope shape              | after `podman init`, `libpod-<id>.scope/container` exists under the  |
|                          | user manager's `user.slice` holding one process, `crun`; attached    |
|                          | there, `podman start` runs the command under the policy, and after   |
|                          | `podman rm` the link's cgroup id reads 0                              |
| fail-closed              | a launch whose controller attaches and then exits 1 starts no        |
|                          | container: it stays `initialized` and prints nothing                 |
| create hook              | crun 1.30 ran the `createContainer` hook in                          |
|                          | `<slice>/libpod-<id>.scope/container`, the container's own cgroup    |
|                          | below the attach slice, and its write of the marker got `EPERM`      |

### Phase 1 on WSL

Measured on 2026-10-21 with `../bpf/probe/phase1/phase1.ps1` on the Windows machine above, podman
6.1.4 under the cgroupfs manager, clang 19.1.7, no other `lsm_cgroup` link in the VM. The rows
below name what differs from macOS; every other row passed as there.

| row                      | measured                                                              |
| ------------------------ | --------------------------------------------------------------------- |
| mounts                   | no securityfs and no bpffs until the probe mounted them               |
| share                    | `/mnt/c` 9p, `aname=drvfs`, `cache=0x5`, `access=client`              |
| verifier, per program    | 16,168 to 16,670 insns, at most 4 states per insn, 95 to 112 ms       |
| verifier, all eleven     | 165 ms in one load                                                    |
| jited `file_open`, x86   | 1,362 bytes holding two `lock xadd`, one per fetch-add                |
| walk                     | 245 calls, 245 settled, 0 retries, depth 14 at most                   |
| identity                 | the program's `(s_dev, i_ino)` equals statx's, type `9p`, with NTFS's |
|                          | 64-bit file ids, for the file and for a directory; unchanged after    |
|                          | the host renames, the cache drop and for the hard link's two names   |
| replacement              | the file's and the directory's replacement differ from the first     |
|                          | inode, and the guest saw each at once                                 |
| attach cgroup            | a directory under `user@1000.service/app.slice`, made by the user,    |
|                          | taken by podman as an absolute `--cgroup-parent`; `populated 1` with  |
|                          | a container below and no task of its own, 0 after its stop; present  |
|                          | 60 s after the container stopped; `rmdir` removed it and the link    |
|                          | read cgroup id 0                                                      |
| container's own cgroup   | after `podman init`, `app.slice/<id>` holding `crun`; attached        |
|                          | there, the started command is refused                                 |
| create hook              | crun 1.28 ran the `createContainer` hook in `<attach>/libpod-<id>`,  |
|                          | the container's own directory below the attach cgroup, and its write |
|                          | of the marker got `EPERM`                                             |
| `rename_lock`            | in kallsyms as a `T` symbol; libbpf resolved it                       |

Build the BPF objects and the controller in a builder container with clang and libbpf, outside
the machine; the machine keeps its images and installs no toolchain. The builder pins clang's
version: the stack depth and instruction count the verifier admits ("Phases", 2) are the
compiler's output, so a compiler change reopens that gate with the kernel unchanged.

### Phase 2 on macOS

Measured on 2026-10-21 with `../bpf/probe/phase2/phase2.sh` on the machine of "Phase 1 on macOS",
podman 6.1.2, clang 19.1.7, `classify.bpf.o` of SHA-256
`3fd866407d2d007c5f6ab550d5e3af9eddc146356b8bd4a7147940ae99746e70`. The exerciser's containers
run without podman's seccomp profile,
which answers `file_setattr` and `io_uring_setup` with `ENOSYS` and refuses a mount in a user
namespace before the kernel does; rows 20 and 21 run with `label=disable` besides, as the
sandbox's nesting mode does. The transcript holds the raw lines.

| row                      | measured                                                              |
| ------------------------ | --------------------------------------------------------------------- |
| verifier, inventory      | 33 programs, 16 to 596 insns each, at most 4 states per insn, 9 to    |
|                          | 16 ms each, 35 ms for all 33 in one load                              |
| verifier, representative | the walk, the fold and the rule match are one global function         |
|                          | (`judge_position`, `__noinline`, scalar arguments) that each          |
|                          | program's load verifies once, 19,213 insns and 192 bytes of stack,    |
|                          | the second walk of `inode_link` and `inode_rename` included; the      |
|                          | hooks' own bodies are 477 to 913 insns and 56 to 88 bytes of stack;   |
|                          | 19,690 to 20,126 insns per program, at most 12 states per insn, 147   |
|                          | to 154 ms each, 316 ms for all eight; jited 19,952 to 22,896 bytes    |
| convergence              | a loop converges only when every value it carries between iterations  |
|                          | is read back from the map at each iteration: a counter kept in a      |
|                          | register and used as an index unrolled the fold's loop 204 iterations |
|                          | deep and the program was "too large" at one million insns; with the   |
|                          | loop state in the per-CPU map, the function verifies as above         |
| masks                    | a mask the compiler proves redundant is dropped, and the verifier,    |
|                          | which does not follow the range check that proved it, reports an      |
|                          | "unbounded memory access": such an offset passes a `barrier_var`      |
|                          | before its mask                                                       |
| barrier                  | the jited `file_open`, 20,120 bytes, holds two `ldaddal`, one per     |
|                          | fetch-add, with the fetched value kept live; with that value unused,  |
|                          | `__sync_fetch_and_add` compiles to the plain atomic add, without      |
|                          | `BPF_FETCH`, and the jited program held no `ldaddal`                  |
| inventory                | every row's hooks called and each refusing on its own, where the      |
|                          | row's macOS column says `yes`: a hook is attached apart from the      |
|                          | hooks the operation reaches before it, and its refusal is its         |
|                          | program's denied count with the operation's `EPERM` in its batch      |
| share                    | `mknod` of a regular file: `EPERM` after `inode_create`; `O_TMPFILE`  |
|                          | and `FICLONE`: `EOPNOTSUPP`, the latter after `file_ioctl`; the four  |
|                          | row 18 commands and the two of row 17: `ENOTTY` after `file_ioctl`,   |
|                          | a command with a high bit set arriving as its 32-bit value            |
|                          | (`0x40086602`); `file_setattr`: `EOPNOTSUPP` before                   |
|                          | `inode_file_setattr`, since `vfs_fileattr_set` reads the attributes   |
|                          | first (`fs/file_attr.c`) and virtiofs fails that read; `user.`        |
|                          | xattrs, ACLs and a `security.capability` set from a user namespace    |
|                          | stored, the last read back outside and removed; a socket bound        |
| FIFO                     | `mkfifo` gets `EACCES` after `path_mknod` and before `inode_mknod`,   |
|                          | and the kernel log holds no `fifo_file` AVC: between the two hooks    |
|                          | lie the parent's permission check, which the socket bind passed on    |
|                          | the same directory, and the earlier LSMs' `inode_mknod` handlers      |
| overlay, row 20          | with `userxattr` and the three layers on the share, overlayfs fails   |
|                          | to create its work directory there (errno 13, kernel log) and mounts  |
|                          | read-only, `inode_setxattr` seeing two `user.overlay.` names on the   |
|                          | way; a create in the merged tree then gets `EROFS` before any hook    |
| bind alias, row 21       | a create through a bind mount of the tree in a user namespace reaches |
|                          | `path_mknod`, `inode_create` and `file_open`, refused by the deny     |
|                          | name; `name_to_handle_at` works and `open_by_handle_at` gets `EPERM`  |
|                          | without `CAP_DAC_READ_SEARCH`                                         |
| io_uring, row 22         | `io_uring_setup` gets `EACCES` under `container_t` with               |
|                          | `io_uring_disabled` 0 and no AVC logged, and succeeds with            |
|                          | `label=disable`: SELinux refuses it                                   |
| corpus                   | 51 cases under 128 rule lines and three roots: 0 mismatches; the two  |
|                          | FIFO cases are the share's `EACCES`; a folded `.GiT` beside an        |
|                          | existing `.git` would be the case-insensitive host's `EEXIST` before  |
|                          | any hook, so the case stands where no `.git` is                      |
| git                      | status, add, commit, a branch, log and gc in a clone of this          |
|                          | repository under the policy; `git config` and `git init` refused      |
| walk cost, syscall       | 2,000 opens for writing: depth 11, 0.81 ms under the policy against   |
|                          | 0.78 ms bare; depth 32, 1.97 against 1.91; depth 63, 3.82 against     |
|                          | 3.53 (virtiofs's own cost is the rest)                                |
| walk cost, in program    | means over the calls that walked: `file_open` over 6,059 walks at     |
|                          | depths 11, 32 and 63, 174 µs mean, 2.0 ms at most; `inode_unlink` at  |
|                          | depth 5 or less, 24 µs; `inode_setattr` at depth 4 or less, 23 µs;    |
|                          | `inode_link`, two walks, 41 µs; `inode_rename`, two walks, 39 µs      |
| walks                    | 7,374 walks settled, 0 retries, 0 gave up, depth 64 at most           |
| host-side mount          | an APFS image `hdiutil` attached at a directory inside the tree, the  |
|                          | recorded root, before the attach and after it: a superblock of its    |
|                          | own, `mkdev` 78 and 89 against the tree's 41, type `virtiofs`; a      |
|                          | write inside it under the policy gets `EPERM` while a write in an     |
|                          | ordinary directory beside it is allowed: the walk meets the image's   |
|                          | root before the recorded root, as "Mounts" designs                    |
| nested podman            | a pull, run, exec and removal of `alpine:3.22` under the loosenings   |
|                          | with storage on a tmpfs: `inode_setattr` 1,066 calls,                 |
|                          | `inode_setxattr` 31 (`user.overlay.origin`), `inode_removexattr` 6    |
|                          | (`user.overlay.opaque`), `inode_remove_acl` 12                        |
|                          | (`system.posix_acl_access`), `file_ioctl` 34 (`FIONBIO`, `TCGETS`),   |
|                          | no `inode_set_acl`, `inode_file_setattr` or `file_ioctl_compat`; with |
|                          | those hooks refusing everything in the cgroup, podman fails at its    |
|                          | first step, the `O_TRUNC` open of `/proc/<pid>/setgroups`, which      |
|                          | `inode_setattr` refuses                                               |

### Phase 2 on WSL

Measured on 2026-10-21 with `../bpf/probe/phase2/phase2.ps1` on the Windows machine of "Phase 1
on WSL", podman 6.1.4, clang 19.1.7, `classify.bpf.o` of SHA-256
`aba2e8b1be6ad42e3540474b221370238e281c7c363e6cc06c56478fd0d9c256`, built against that kernel's
BTF. The containers run as on macOS. The rows below name what differs from macOS; every other row
passed as there.

| row                      | measured                                                              |
| ------------------------ | --------------------------------------------------------------------- |
| verifier, inventory      | 33 programs, 16 to 596 insns each, at most 4 states per insn, 12 to   |
|                          | 29 ms each, 29 ms for all 33 in one load                              |
| verifier, representative | 6.18 verifies the global function in 228,755 insns, twelve times      |
|                          | 7.2's count, at most 44 states per insn; 229,232 to 229,689 insns per |
|                          | program, the stack as on macOS, 500 to 1,141 ms each, 3,421 ms for    |
|                          | all eight; jited x86 15,451 to 17,739 bytes, `file_open` holding two  |
|                          | `lock xadd`                                                           |
| global function          | with the walk inlined into each hook, 6.18 needed 638,813 to 793,033  |
|                          | insns for each of the six single-walk hooks and refused `inode_link`  |
|                          | and `inode_rename` at the million; 7.2 verified the same programs in  |
|                          | 14,458 to 43,504. The global function, verified once per program,     |
|                          | is what keeps 6.18 under the limit                                    |
| share                    | FIFO and socket bind: `EOPNOTSUPP` after `inode_mknod`;               |
|                          | `RENAME_WHITEOUT` and `RENAME_EXCHANGE`: `EINVAL` after               |
|                          | `inode_rename`, called twice for the exchange; `fallocate`:           |
|                          | `EOPNOTSUPP` after `file_permission`; `FICLONE`: `EOPNOTSUPP` after   |
|                          | `file_ioctl`; an ACL set and removal: `EOPNOTSUPP` after              |
|                          | `inode_set_acl` and `inode_remove_acl`; `name_to_handle_at`:          |
|                          | `EOPNOTSUPP`; `mknod` of a regular file stored, as a `user.` xattr    |
|                          | and a `security.capability` set from a user namespace are; the ioctl, |
|                          | `O_TMPFILE` and `file_setattr` answers are macOS's                    |
| overlay, row 20          | with `userxattr` and the three layers on the share, the mount is      |
|                          | writable, the kernel log warning that the upper supports neither      |
|                          | `RENAME_WHITEOUT` nor `tmpfile`; a create in the merged tree reaches  |
|                          | `path_mknod`, `inode_create`, `file_open`, `inode_setxattr` and       |
|                          | `file_permission`, refused by the deny name at `path_mknod`,          |
|                          | `inode_create` and `file_open`                                        |
| io_uring, row 22         | `io_uring_setup` succeeds in a plain container, `io_uring_disabled`   |
|                          | 0, no AVC logged                                                      |
| corpus                   | 51 cases: 0 mismatches; the two FIFO cases are the share's            |
|                          | `EOPNOTSUPP`                                                          |
| walk cost, syscall       | 2,000 opens for writing: depth 11, 9.5 ms under the policy against    |
|                          | 10.8 ms bare; depth 32, 25.5 against 27.5; depth 63, 56.2 against     |
|                          | 55.1: the policy's share lies within the run's spread, and 9p's own   |
|                          | cost is about fourteen times virtiofs's                               |
| walk cost, in program    | means over the calls that walked: `file_open` over 6,059 walks at     |
|                          | depths 11, 32 and 63, 89 µs mean, 0.92 ms at most; `inode_unlink` and |
|                          | `inode_setattr` 15 µs; `inode_create` 16 µs; `inode_link` 23 µs and   |
|                          | `inode_rename` 24 µs, two walks each                                  |
| walks                    | 6,272 walks settled, 0 retries, 0 gave up, depth 64 at most           |
| host-side mount          | a second mount point of the `C:` volume (`mountvol`) at a directory   |
|                          | inside the tree, the recorded root, before the attach and after it:   |
|                          | 9p presents it as a symlink (`statx` mode `0120000`) on the tree's    |
|                          | device 69, not as a superblock of its own, and a write through it     |
|                          | under the policy gets `EACCES` while a write in an ordinary directory |
|                          | beside it is allowed                                                  |
| nested podman            | `inode_setattr` 1,002 calls, `inode_setxattr` 31, `inode_removexattr` |
|                          | 6, `inode_remove_acl` 12, `file_ioctl` 25 (`TCGETS`), the same names  |
|                          | as on macOS, and the same first failure with the hooks refusing       |


### Phase 3 on macOS

Measured on 2026-10-24 with `../bpf/probe/phase3/phase3.sh` on the machine of "Phase 1 on macOS",
podman 6.1.2, crun 1.30, clang 19.1.7, `policy.bpf.o` of SHA-256
`7a23c6fc79cd63e3993c7750bb981a2dcea2beb7f6e56a3f0c4b0d742baa71f0`, built from sources of SHA-256
`d22bb1e73c457fa48f57ec2e539142218cfcdfe0c7fa90308eddfebc371265fa` (`sources.txt` lists them in
hashing order; `../bpf/probe/check-evidence.sh` recomputes it): the program after the host
corpus run (`../fuse/ko-agent-fs/tests/bpf_equivalence.rs`) admitted the scratch names' locks,
the bisect state, `filter-repo/` and `lfs/`, and after the review of the first runs altered it in
three places, the walk going on past a gitdir root, a bound hit denying under a mark, and a mount
in no namespace judged as another namespace's, with each walk loop's body a global function. The
containers run as in Phase 2. Every one of the 48 rows passes, in three runs of this object, the
later two with the walk cost in pairs and the last with the program's own timer over them; the rows
give the last run's figures and the transcript holds its raw lines. Rows of the first runs of
2026-10-22, under the program as first written, are kept as the reason for two rules, and the
verifier row keeps the walk's counts of the three revisions before beside this one's.

| row                      | measured                                                              |
| ------------------------ | --------------------------------------------------------------------- |
| preemption               | `full (lazy)`, 10 CPUs                                                |
| verifier, per program    | 45,217 to 47,873 insns, stack 352 to 384 of 512 bytes, at most 25     |
|                          | states per insn, 69 to 168 ms each, 533 ms for all nine (73 to 86 and |
|                          | 581 in the first run); the walk and position 40,584 insns (39,476     |
|                          | before the scratch locks' admission, 33,135 with the loop bodies      |
|                          | inlined, 16,758 before the review's three changes), each level of the |
|                          | walk 248 and of its snapshot 39, the rule match 2,524, the alias      |
|                          | activation 634 and the symlink judgment 2,797, each a global function |
|                          | verified once                                                         |
| barrier                  | the jited `file_open`, 30,184 bytes, holds three `ldaddal`, one per   |
|                          | fetch-add: before and after a level's reads, and before the snapshot  |
| records                  | 128 rule lines, eleven roots (three workspaces, a submodule's gitdir, |
|                          | four guarded `.git`, two guarded `.ko-agent-sandbox` and the volume), |
|                          | the alias context of `.claude` holding the five `.claude` lines as    |
|                          | partial matches, which the guard's compiler reproduces                |
|                          | (`bpf_records.rs`, its first test)                                    |
| corpus                   | 252 cases: 238 under the default flags, 6 under the short-name flag   |
|                          | and 8 under `unix-socket`, 0 mismatches each; 5 of the 238, the      |
|                          | `mkfifo` cases, answered by the share's `EACCES` before any hook,     |
|                          | counted apart                                                         |
| git                      | status, add, commit, a branch, log and gc in the clone; `git config`  |
|                          | and `git init` refused; git outside the policy in `sub/`, whose       |
|                          | session-made `.git` has no `HEAD`, finds the workspace's gitdir       |
| race                     | 3,618 moves of the outer directory, 1,487 moves and 635 exchanges of  |
|                          | the inner, against 12,192 writes by path and through held             |
|                          | descriptors: 7,382 refused, 4,810 absent, 0 succeeded; 9 walks read a |
|                          | torn name and were made again (15, 8, 6, 2, 11 and 12 in the runs     |
|                          | before), none gave up                                                 |
| race, global sequence    | the first run, validating the walk by `rename_lock`: 167 walks        |
|                          | overlapped a rename and 35 of 11,891 gave up after four retries       |
| storm                    | 16 processes, 29,498 decisions, 0 wrong, 0 denied for want of a slot, |
|                          | no nesting on any CPU; walk means 19 to 31 µs, 204 µs at most (the    |
|                          | runs before: 25,312 and 30,394 decisions, means 19 to 35 µs, 478 µs   |
|                          | at most but for one `inode_unlink` walk of 1.22 ms)                   |
| slots exhausted          | with four marked taken a write on the share is refused and counted    |
|                          | once as reentry; with three it runs in the fourth; freed, in the      |
|                          | first                                                                 |
| storm, global sequence   | the first run: 16 walks gave up and 17 permitted operations in four   |
|                          | processes were denied                                                 |
| sockets by default       | `bind` beneath the volume `EPERM` and under its superblock's `~`      |
|                          | stand-in allowed, from where `mv` and `ln` beneath the volume and     |
|                          | `mv` into the workspace are refused                                   |
| second share             | a directory under `/private/tmp`, virtiofs, bound into the container: |
|                          | a write inside gets `EPERM`                                           |
| walk cost, in program    | `file_open` over the 10,000 opens for writing of the pairs below, all |
|                          | walked to depth 11: 61.6 µs mean, 163 µs at most; the storm's walks   |
|                          | at depth 3 average 19 µs and the race's at depth 5, 33 µs             |
| walk cost, syscall       | five pairs of 2,000 opens at depth 11, a container under the policy   |
|                          | then one bare, in that order in every pair of these runs, policy      |
|                          | minus bare: the open for writing +100, +60, +64, +11 and +56 µs,      |
|                          | median +60, the program's own figure; the open for reading, which the |
|                          | hook leaves before any walk, −22 to +140, median +22; `lstat`, which  |
|                          | no hook sees, −61 to +62, median +3; the bare write open at 712 to    |
|                          | 796 µs. The run before, with the bare open at 949 to 1,791 µs, spread |
|                          | the write open's difference from −640 to +443 and `lstat`'s to        |
|                          | +1,224, so the syscall figure holds on a quiet share only, and the    |
|                          | program's timer is the one to read. The single-shot runs before read  |
|                          | policy 784, 868, 831 and 1,282 µs against bare 920, 698, 778 and      |
|                          | 1,125                                                                 |
| container start          | with `file_receive` attached, the runtime passes 15 descriptors of    |
|                          | its own namespaces into the starting container, all passed, and the   |
|                          | first process holds no descriptor beyond the standard three; the      |
|                          | controller's namespace is pid 1's, 0xEFFFFFF8, the initial one        |
| container start, refused | the first run, with every other namespace's descriptor judged: a      |
|                          | directory descriptor of the volume's mountpoint, `_data`, refused,    |
|                          | and `crun` failed with `write to sync socket: Connection reset`       |
| slots                    | four sandboxes with nine hooks each hold nine of the ten              |
| descriptors              | every row of "Phases", 3 as listed; B's `file_receive` over the rows: |
|                          | 126 calls, 120 of the runtime's namespaces, 4 allowed, 2 denied       |
| seccomp                  | under the generated profile `unshare` with `CLONE_NEWUSER` and the    |
|                          | twelve mount syscalls answer `EPERM`, and a child process runs        |


### Phase 3 on WSL

Measured on 2026-10-24 with `../bpf/probe/phase3/phase3.ps1` on the Windows machine of "Phase 1
on WSL", podman 6.1.4 under the cgroupfs manager, crun 1.28, clang 19.1.7, `policy.bpf.o` of
SHA-256 `6e2e7dc5112c8498b03c8ce7933e4f0e2ba2fcb559ed8b810f5bd80a5ac0abd1`, the revision "Phase 3
on macOS" measures, from the same sources of SHA-256
`d22bb1e73c457fa48f57ec2e539142218cfcdfe0c7fa90308eddfebc371265fa`, built against that kernel's
BTF. Every one of the 49 rows passes, in three runs
of this object as on macOS, the rows giving the last run's figures. A run of the revision with the
loop bodies inlined failed the race's sanity row under the row's first criterion, a walk that read
a torn name and was made again, of which that run had none and the macOS run of the day two; the
row asks since for what the race shows, both renamers moving while the writer is refused under one
name and finds none under the other. The rows below name what differs from macOS; every other row
passed as there.

| row                      | measured                                                              |
| ------------------------ | --------------------------------------------------------------------- |
| preemption               | `none`, 4 CPUs                                                        |
| verifier, per program    | 113,101 to 118,558 insns of the 1,000,000 limit, the walk and         |
|                          | position 109,037 of them, 2.7 times the count on 7.2.5 (107,929       |
|                          | before the scratch locks' admission; 919,220 with the loop bodies     |
|                          | inlined, 24.7 s for all nine; 121,408 before the review's three       |
|                          | changes); each level of the walk 248 and of its snapshot 39, the rule |
|                          | match 1,955, the alias activation 634 and the symlink judgment 4,665; |
|                          | stack 352 to 384 bytes; at most 46 states per insn; 195 to 647 ms     |
|                          | each, 1.67 s for all nine (192 to 325 and 1.73 s in the first run)    |
| barrier                  | the jited `file_open`, 22,977 bytes, holds three `lock xadd`, the     |
|                          | scan matching the instruction under any `REX` prefix                  |
| corpus                   | 236 of the 238 default cases run, 0 mismatches: two names NTFS cannot |
|                          | hold, a newline and non-UTF-8 bytes, skipped; 3 answered by the share |
|                          | before any hook, two `mkfifo` with `EOPNOTSUPP` and the exchange with |
|                          | `EINVAL`; of the socket group 4 of 8 run, the rest needing a bound    |
|                          | socket, which 9p refuses after the hook                               |
| race                     | no descriptor held, since 9p refuses to move a directory with an open |
|                          | handle below it, and no exchange; 1,026 moves of the outer directory  |
|                          | and 120 of the inner against 3,296 writes: 271 refused, 3,025 absent, |
|                          | 0 succeeded; 2 walks read a torn name and were made again (1, 4, 1,   |
|                          | 0, 2 and 4 in the runs before); in one run the outer renamer's first  |
|                          | failed move answered `EACCES`                                         |
| storm                    | 16 processes, 6,678 decisions in the 5 s a 9p operation's 10 ms       |
|                          | allows, 0 wrong, 0 reentry; walk means 29 to 49 µs, 4.1 ms at most    |
| short name, real volume  | NTFS serves `.vscode` as `VSCODE~1`; under the flag a write through   |
|                          | it is refused and the host sees no file in `.vscode`                  |
| walk cost, in program    | `file_open` over the pairs' 10,000 opens for writing at depth 11:     |
|                          | 37.3 µs mean, 1.21 ms at most                                         |
| walk cost, syscall       | five pairs as on macOS, policy minus bare: the open for writing −721, |
|                          | +86, −202, +807 and −849 µs, median −202; the open for reading −173   |
|                          | to +951, median +58; `lstat` −140 to +978, median +307; the bare      |
|                          | write open 10.05 to 10.82 ms (the run before: −704 to +334 µs, median |
|                          | −564, bare 9.52 to 10.01 ms), so 9p's jitter within a pair exceeds    |
|                          | the walk's cost in every run and the program's timer alone gives it.  |
|                          | The single-shot runs before read policy 11.13, 11.51, 10.48 and 11.06 |
|                          | ms against bare 8.88, 9.58, 10.76 and 10.59                           |
| container start          | with `file_receive` attached, the runtime passes 10 descriptors;      |
|                          | the volume mountpoint arrives as an `open_tree` clone, an anonymous   |
|                          | namespace whose root is the volume directory and whose inode number   |
|                          | is 0xEFFFFFF7, the receiver `crun` still at the host's root           |
| container start, refused | the runs before that number was known: the clone's namespace was      |
|                          | neither the controller's nor pid 1's, which are one on this machine,  |
|                          | and carried neither anonymity field the program looked for            |
| second share             | no `D:` drive on the machine; not measured                            |
| descriptors              | every row as on macOS; B's `file_receive` over the rows: 87 calls, 80 |
|                          | of the runtime's, 4 allowed, 3 denied                                 |


### Phase 4 on macOS

Measured on 2026-10-25 with `../bpf/probe/phase4/phase4.sh` on the machine of "Phase 1 on macOS",
podman 6.1.2, crun 1.30, clang 19.1.7, `policy.bpf.o` of SHA-256
`7a23c6fc79cd63e3993c7750bb981a2dcea2beb7f6e56a3f0c4b0d742baa71f0`, the object "Phase 3 on macOS"
measures, built again byte for byte, beside `other.bpf.o` of SHA-256
`5777797e27ae80ded9625d30fa72ebd06632cce659f9caab2b1698adbf9a0275`, the same source counting each
call twice in its statistics, which stands for another build, and `other-data.bpf.o` of SHA-256
`8a47bc034f432a97f753585af6eedb2176e432b1a1e3f49d8705b04a2090f26b`, the source with one string
literal of the same length changed, whose instructions and tags equal the installed object's; all
from sources of SHA-256 `58d057f9e769f634be9768bb4599f746894aca931cadfb2cff79bd5117b00d55`. Every
one of the 63 rows passes in one run of these sources, the four machine-restart rows declined in
it and measured in the run before, under the sources the independent review then changed (the
read-back's read-only data comparison, the reconcile's check of every pin before removal); the
runs before found defects of the driver and of the proof fixture alone, and one fact kept below
(the FIFO row). The containers run as in Phase 2; twenty-two launches ran, each through the
launcher's steps 1 to 4.

| row                      | measured                                                              |
| ------------------------ | --------------------------------------------------------------------- |
| install                  | the read-back loads the nine programs once and records their tags    |
|                          | and the read-only data's 758 bytes: 535 ms                            |
| step 2 at launch         | over the twenty-two launches the controller's load took 421 to 671    |
|                          | ms, once 937, filling the maps 0.1 ms, the eight or nine attaches     |
|                          | 8.5 to 18 ms in ten launches and 0.3 to 0.6 ms in the rest            |
| step 2 at a recreate     | the pinned programs checked in 16 ms and attached to the new cgroup   |
|                          | in 9 ms, nothing loaded; the old links read cgroup_id 0 after their   |
|                          | cgroup went, the programs stayed pinned                               |
| step 3                   | the read-back 13 to 17 ms: eight programs, nine maps (the eight of    |
|                          | the policy and the string literals' read-only map, its bytes the      |
|                          | installed object's), five roots, 56 rules; the proof's 68 operations  |
|                          | (69 under `unix-socket`) 33 to 44 ms, 0 mismatches, in a scope       |
|                          | under the slice                                                       |
| the session              | the first process is refused `.git/config` and writes an ordinary     |
|                          | file; `podman exec` is refused; after `podman restart` the first      |
|                          | process is refused again; after `podman kill` the container is exited |
|                          | and the eight programs stay attached, the link naming the cgroup;     |
|                          | the restart policy reads `no`                                         |
| identity                 | each link's cgroup_id is the attach cgroup's inode number             |
| the controller           | exited before the container started; no process of it remains        |
| sockets and mounts       | a socket bound under the container's `/tmp`; `rename` of that        |
|                          | directory into the volume and into the workspace answers `EXDEV`      |
| the policy cannot lapse  | `rmdir` of the attach cgroup with the container in it: `EBUSY`;       |
|                          | root's unpin of the links: 0 programs attached and the protected      |
|                          | write succeeds                                                        |
| defective controllers    | seven hooks: `hook-set attached=7 expected=8`; the other build:       |
|                          | `tag` on `file_open`; the build differing in data alone: `rodata`,    |
|                          | its 758 bytes differing from the installed object's under equal tags; |
|                          | another rule file's records: `map-contents rules index=55`; no        |
|                          | container exists after any; the proof alone catches the records too,  |
|                          | one mismatch (`.vscode/settings.json`)                                |
| `unix-socket`           | nine hooks attached and verified; the proof's `bind` in `.git`        |
|                          | refused, and a directory descriptor sent from a mount namespace of    |
|                          | the sender's own refused on arrival                                   |
| pins across a rule       | the check finds `map-contents rules index=55`, the pins go and fresh  |
| change                   | programs load with new ids                                            |
| pins across a new build  | with the other object installed and its tags recorded, the check      |
|                          | finds `tag`; fresh programs of the new build load and verify; the pin |
|                          | directory holds this launch's eight links and eight programs alone    |
| the controller's         | an object given as a path, a cgroup outside the user's slice, a       |
| refusals                 | tmpfs mounted at `tree/vendor` under the bind source, a proof fixture |
|                          | on tmpfs: each `refused reason=...`, status 3, nothing pinned         |
| the reconcile            | a listing that fails (`podman ps` made to fail) is reported and keeps |
|                          | all five sessions; the launcher killed before `podman create` and a   |
|                          | `podman create` that failed: pins and slices removed; a created, a    |
|                          | stopped and a live container keep theirs; the created one's go once   |
|                          | it is removed                                                         |
| contradicting identities | a container whose label names another cgroup: kept, unassociated; a   |
|                          | cgroup recreated at its path (inode 48288, then 49203): refused; a    |
|                          | pin directory renamed to another session's name: refused by its       |
|                          | links' cgroup id; nothing removed                                     |
| cleanup refusals         | a session name and a cgroup path with `..`; a symlink in place of     |
|                          | the pin directory (`ELOOP`); a tmpfs mounted on it (`EXDEV`); a       |
|                          | recorded identity off by one; each refused, nothing removed. cgroup2  |
|                          | refuses a symlink in place of a cgroup directory with `EPERM`         |
| refusals found late      | one foreign link among a session's eight: refused, its 9 links and 8  |
|                          | programs all surviving; a programs directory that is a symlink:       |
|                          | refused after the links were checked, all 8 links surviving           |
| machine restart          | the run before: `podman machine stop` 61 s, `start` 11 s; the pin     |
|                          | root is gone with bpffs, the attach cgroups are gone, the two         |
|                          | containers stay exited and the reconcile keeps both, since their      |
|                          | containers name them                                                  |
| bpffs                    | holds symlinks and renames of pin directories                         |
| FIFO                     | the first run: a `mkfifo` at an ordinary name of the fixture passed   |
|                          | `inode_mknod`, which judges a socket by type and any node by name;    |
|                          | the proof's `mkfifo` targets `.git/ko-fifo` since, and the FIFO left  |
|                          | on the share preceded a `podman machine stop` that did not return     |


### Phase 4 on WSL

Measured on 2026-10-25 with `../bpf/probe/phase4/phase4.ps1` on the Windows machine of "Phase 1 on
WSL", podman 6.1.4 under the cgroupfs manager, crun 1.28, clang 19.1.7, `policy.bpf.o` of SHA-256
`6e2e7dc5112c8498b03c8ce7933e4f0e2ba2fcb559ed8b810f5bd80a5ac0abd1`, the object "Phase 3 on WSL"
measures, built again byte for byte, beside `other.bpf.o` of SHA-256
`fac0fb9b520c760629957bd0a3d82b0ad76d927ad9a6013dc82ceee5d3cb9404` and `other-data.bpf.o` of
SHA-256 `1adad44441f677cca904f0b9705166112b72712956d8fc6930479fe5389c4079`; all built from the
sources of SHA-256 `58d057f9e769f634be9768bb4599f746894aca931cadfb2cff79bd5117b00d55` that "Phase
4 on macOS" measures. Every one of the 63 rows passes, in one run of these sources, the four
machine-restart rows declined in it and measured in the run before as on macOS; the runs before
found defects of the driver alone. The rows below name what differs from macOS; every other row
passed as there, the reconcile removing the cgroup directories itself under cgroupfs.

| row                      | measured                                                              |
| ------------------------ | --------------------------------------------------------------------- |
| install                  | the tags and the read-only data recorded in 1.82 s                    |
| step 2 at launch         | the load 1.47 to 1.84 s over the twenty-two launches, filling 0.1 ms, |
|                          | the attaches 13 to 23 ms in ten launches and 0.2 to 0.4 ms in the     |
|                          | rest                                                                  |
| step 2 at a recreate     | the pins checked in 43 ms and attached in 17 ms                       |
| step 3                   | the read-back 35 to 50 ms; the proof's 68 operations 327 to 373 ms    |
|                          | on 9p, 0 mismatches                                                   |
| the proof's cgroup       | a process of the ssh session could not join the leaf below the attach |
|                          | cgroup: writing its `cgroup.procs` answered `EACCES` (the run         |
|                          | before), since the move needs write access to the common ancestor's   |
|                          | `cgroup.procs` and the session's cgroup shares no ancestor the user   |
|                          | owns with the delegated subtree; from a transient scope of the user   |
|                          | manager, `app.slice/run-*.scope`, the join into `app.slice/<attach>/  |
|                          | proof` works, on every launch. A launcher reaching the machine over   |
|                          | ssh takes that step                                                   |
| sockets and mounts       | `rename` of the socket's directory into the volume (ext4) and into    |
|                          | the workspace (9p) answers `EXDEV`                                    |
| machine restart          | the run before: `podman machine stop` 2 s, `start` 9 s; the rows as   |
|                          | on macOS                                                              |


### Phase 5 on macOS

Measured on 2026-10-25 with `../bpf/probe/phase5/Phase5.scala` on the machine of "Phase 1 on macOS",
podman 6.1.2, crun 1.30, clang 19.1.7, `policy.bpf.o` of SHA-256
`7a23c6fc79cd63e3993c7750bb981a2dcea2beb7f6e56a3f0c4b0d742baa71f0`, the object "Phase 3 on macOS"
and "Phase 4 on macOS" measure, built again byte for byte, from sources of SHA-256
`bc6b5a5bfb82b2bc3e48228afa16c2c29acc641ac37ab0a7ad03c7097c02f2f1`. The tree is sbt/sbt at
`8a8a17c4`, 4,475 tracked files at mean depth 7.0 among 7,946 entries, the corpus `perf-probe.py`'s
2,101 entries, and the build a clone of this repository at the tree's root, under the launcher's
default rules, 55 lines. Every one of the 26 rows passes in one run, the fourth: the first failed
its filter rows on the launcher's refusal of a workspace below `~/.cache`, the second passed its 23
rows before the bare round and the build were added, and the third's build under the policy read as
absent the clone the driver had removed and made again at one name within a second, the dentry the
machine keeps ("Phase 1 on macOS", the replacement row). The three stacks run the sandbox image
with the session's user mapping, the policy's containers below the attach cgroup, the filter's
through the launcher; `perf-probe.py` ran three rounds a stack, interleaved, after one round on the
bare bind before the launch; the figures are the mean, with the range, over the rounds.

| row                      | measured                                                              |
| ------------------------ | --------------------------------------------------------------------- |
| the launch               | load 438 ms, attach 8.7 ms, read-back 15.9 ms, the proof's 67         |
|                          | operations 38.4 ms, 0 mismatches; a hook file in `.git/hooks` made on |
|                          | the bare bind, refused under the policy and through the filter        |
| the bare bind, µs an     | before the launch, with nothing under the probe's pin root (whether   |
| entry                    | another process held an attachment was not checked in this run; the   |
|                          | driver now lists all of `bpffs` and counts `bpftool`'s programs of    |
|                          | type `lsm` where it has one): `find` 76, `find -printf` 167, `ls -lR` |
|                          | 719, `cp -r` 1,258, `rm -rf` 342, each inside the range of the bind's |
|                          | rounds beside the policy: the shim the first attach installs costs    |
|                          | tasks outside the cgroup nothing the rounds' spread shows             |
| `perf-probe.py`, µs an   | `find`: bind 82 (63 to 107), policy 73 (71 to 78), filter 402;        |
| entry, bind / policy /   | `find -printf`: 165 (134 to 204), 179 (160 to 190), 1,291;            |
| filter                   | `ls -lR`: 724 (640 to 870), 765 (697 to 894), 12,289;                 |
|                          | `cp -r`: 1,421 (1,194 to 1,636), 1,401 (1,244 to 1,674), 9,128;       |
|                          | `rm -rf`: 419 (334 to 547), 358 (355 to 362), 2,602. Policy over bind |
|                          | 0.86 to 1.09 times over overlapping ranges in every row; filter over  |
|                          | bind 4.9 to 17.0 times, as "The cost of a path walk" measured in      |
|                          | 2026-09                                                               |
| the program's share of a | 3,600 judged calls each of `file_open`, `inode_create` and            |
| `perf-probe.py` round    | `inode_unlink` (the corpus's 1,800 files made, copied and removed     |
|                          | twice over), 123, 32 and 36 more answered at the superblock check,    |
|                          | every walk 4 deep and none retried, denied or without a slot; 15.4 to |
|                          | 17.8 µs mean from entry to decision, 0.17 ms at most: the three       |
|                          | hooks' 10,800 judged calls take 167 to 182 ms of a round's 9 to 12 s  |
| the build                | `sbt 'testOnly *SandboxTextWidthTest'`, output in the workspace:      |
|                          | bind 102 s wall, sbt's own 72 s; policy 104 s, 67 s; 10 of 10 tests   |
|                          | under both. The policy judged 1,691 opens, 1,349 creates, 214 renames |
|                          | (428 walks, source and destination), 108 unlinks and 514 attribute    |
|                          | changes, walks up to 20 deep, 40 to 47 µs mean a call and 93 for a    |
|                          | rename, 0.21 ms at most; it refused 4 symlinks at depth 7, the        |
|                          | absolute targets "The policy" refuses as the filter refuses sbt's     |
|                          | links into its cache, under which sbt writes copies ("sbt over        |
|                          | dangling cache links"); the machine 18 to 21 % busy mean, 47 to 49 %  |
|                          | max, memory used rising from 2.8 to 4.8 GB under both                 |
| `walk-probe.py`, bind /  | `lstat` by path: depth 1 0.08 / 0.17 / 0.76 ms, depth 7 0.48 / 0.48 / |
| policy / filter          | 6.52 ms, depth 15 0.76 / 1.02 / 20.5 ms; every tracked file by path   |
|                          | 0.42 / 0.42 / 7.31 ms a file, through a directory fd 0.11 / 0.11 /    |
|                          | 1.76 ms; `find . -type f` 1.8 / 2.2 / 16.9 s; `git status` 4.7 / 4.3  |
|                          | / 71.2 s, `--untracked-files=no` 1.2 / 1.1 / 40.5 s. The depth rows,  |
|                          | 200 `lstat` each of 0.1 to 1 ms, scatter 1.0 to 2.1 times policy over |
|                          | bind in this run and 0.7 to 1.4 in the run before, the per-file rows  |
|                          | 1.00 in both; the policy judged 4 opens, 4 creates and 4 unlinks in   |
|                          | the whole run, git's lock at depth 2, 15 to 22 µs each; the filter's  |
|                          | figures match "a real tree" of 2026-09-19 (5.97 ms a file, 71.5 s)    |
| the machine during the   | `/proc/stat` over the run, ten CPUs: bind 13 % busy mean, 27 % max    |
| stat storm               | over 34 s; policy 12 %, 26 % over 29 s; filter 8 %, 32 % over 541 s;  |
|                          | iowait at most 2 %; memory used 3.0 to 3.3 GB of 11.9 GB under each,  |
|                          | memory pressure `some avg10` 0.00 throughout, io at most 0.32         |
| the machine during       | bare, bind and policy 6 to 7 % busy mean, 6 to 10 % max over 8 to 12  |
| `perf-probe.py`          | s a round; filter 7 % mean, 23 to 24 % max over 78 to 80 s a round    |
| the probe's own label    | `perf-probe.py` reported `unfiltered bind mount` under the policy     |
|                          | too, telling the stacks apart by a `.git` directory, which the policy |
|                          | allows ("Directories"); it now also tries a hook file inside that     |
|                          | directory, which the policy refuses by name, and reports `BPF policy` |
| the attach cgroup        | under the systemd manager the slice `ko-agent-bpf5-policy.slice` lies |
|                          | below `ko.slice/ko-agent.slice/ko-agent-bpf5.slice`, the hierarchy    |
|                          | systemd reads from a slice name's dashes                              |

### Phase 5 on WSL

Measured on 2026-10-25 with `../bpf/probe/phase5/Phase5.scala` (`scala shebang`) on the Windows
machine of "Phase 1 on WSL", podman 6.1.4 under the cgroupfs manager, crun 1.28, clang 19.1.7,
`policy.bpf.o` of SHA-256 `6e2e7dc5112c8498b03c8ce7933e4f0e2ba2fcb559ed8b810f5bd80a5ac0abd1`, the
object "Phase 3 on WSL" and "Phase 4 on WSL" measure, built again byte for byte, from the
sources of SHA-256 `bc6b5a5bfb82b2bc3e48228afa16c2c29acc641ac37ab0a7ad03c7097c02f2f1` that "Phase 5
on macOS" measures, over the same tree and corpus, the machine of four CPUs and 7.8 GB on the 9p
share. Every one of the 23 rows passes in one run of 2 h 10 min, of which the filter's
`walk-probe.py` took 82 min. The rows below name what differs from macOS; the stacks and the
`perf-probe.py` and `walk-probe.py` rounds are the same, and the bare round and the build, added
to the driver after this run, are not measured there.

| row                      | measured                                                              |
| ------------------------ | --------------------------------------------------------------------- |
| the launch               | load 1,667 ms, attach 15.9 ms, read-back 49.3 ms, the proof's 67      |
|                          | operations 323 ms on 9p, 0 mismatches; the attach cgroup a directory  |
|                          | under `app.slice`, the proof joined from a transient scope            |
| `perf-probe.py`, µs an   | `find`: bind 584 (559 to 598), policy 623 (560 to 659), filter 3,486; |
| entry, bind / policy /   | `find -printf`: 1,493 (1,440 to 1,576), 1,606 (1,478 to 1,749),       |
| filter                   | 11,710; `ls -lR`: 3,064 (2,759 to 3,220), 3,019 (2,690 to 3,198),     |
|                          | 95,301; `cp -r`: 13,671 (12,980 to 14,551), 13,662 (12,981 to         |
|                          | 14,039), 71,470; `rm -rf`: 1,988 (1,918 to 2,079), 2,007 (1,877 to    |
|                          | 2,132), 19,717. Policy over bind 0.99 to 1.08 times over overlapping  |
|                          | ranges in every row; filter over bind 5.2 to 31.1 times, each column  |
|                          | within 20 % of "the filter's ratio on Windows" of 2026-09-19          |
| the program's share of a | the same 3,600 judged calls a hook, 6, 10 and 0 answered at the       |
| `perf-probe.py` round    | superblock check, every walk 4 deep; 12.6 to 15.0 µs mean from entry  |
|                          | to decision, 3.6 ms at most once, no retry, denial or missing slot    |
| `walk-probe.py`, bind /  | `lstat` by path: depth 1 0.96 / 0.91 / 4.19 ms, depth 7 5.10 / 4.97 / |
| policy / filter          | 55.5 ms, depth 15 11.0 / 10.4 / 184.7 ms; every tracked file by path  |
|                          | 5.17 / 5.01 / 53.0 ms a file, through a directory fd 1.00 / 0.93 /    |
|                          | 16.9 ms; `find . -type f` 14.6 / 14.1 / 169.5 s; `git status` 23.0 /  |
|                          | 20.7 / 738.2 s, `--untracked-files=no` 11.0 / 11.0 / 423.4 s. The     |
|                          | policy judged 4 opens, 4 creates and 4 unlinks, 16 to 21 µs each; the |
|                          | bare 9p bind costs 10 times the macOS virtiofs bind on every row, and |
|                          | the filter 4.4 to 38 times the bind on top                            |
| the machine during the   | four CPUs: bind 14 % busy mean, 35 % max over 359 s; policy 17 %,     |
| stat storm               | 35 % over 230 s; filter 14 %, 55 % over 4,928 s; iowait at most 5, 4  |
|                          | and 12 %; memory used 0.57 to 0.79 GB of 7.8 GB under each, memory    |
|                          | pressure `some avg10` 0.00 under the bind and the policy, 0.36 under  |
|                          | the filter; io pressure at most 1.7, 1.1 and 4.6                      |
| the machine during       | bind and policy 13 to 14 % busy mean, 16 to 18 % max, over 70 to 78 s |
| `perf-probe.py`          | a round; filter 14 to 15 % mean, 55 to 59 % max over 603 to 620 s a   |
|                          | round, with iowait peaks of 36 and 58 % and memory pressure up to 2.7 |
|                          | in two of its rounds, where the other stacks' rounds stay at 0.00 but |
|                          | for the first round after the clone (io pressure 13.0, iowait 5 %)    |


## Inventory

The policy transcribes `fuse/ko-agent-fs` at commit `0fe166a159c1f3cc75dd966a8b0e2d4faae5aa31`,
the last to change `src/{policy,fs,guard,rulefile}.rs`. A later change to those files reopens the
rows it touches. The macOS and WSL columns hold the answer under the attached programs: `yes`,
the hooks listed are called and a program there refuses the operation; `none`, the share
answers before any hook; `note`, the row of "Phase 2 on macOS" or "Phase 2 on WSL" named by the
row's number.

| #  | syscalls                  | filter            | hooks 7.2.5 calls            | macOS | WSL  |
| -- | ------------------------- | ----------------- | ---------------------------- | ----- | ---- |
| 1  | open* O_CREAT, creat      | name              | path_mknod, inode_create     | yes   | yes  |
| 2  | mknod*, Unix socket bind  | name              | path_mknod, inode_mknod      | yes   | yes  |
| 3  | mkdir*                    | name              | path_mkdir, inode_mkdir      | yes   | yes  |
| 4  | symlink*                  | name, syntax      | path_symlink, inode_symlink  | yes   | yes  |
| 5  | link*                     | entry, name, move | path_link, inode_link        | yes   | yes  |
| 6  | rename*, RENAME_WHITEOUT  | entry, name, move | path_rename, inode_rename    | yes   | yes  |
| 7  | renameat2 RENAME_EXCHANGE | row 6 both ways   | row 6, inode_rename twice    | yes   | yes  |
| 8  | unlink*                   | entry             | path_unlink, inode_unlink    | yes   | yes  |
| 9  | rmdir, AT_REMOVEDIR       | entry             | path_rmdir, inode_rmdir      | yes   | yes  |
| 10 | open* O_WRONLY, O_RDWR    | entry             | file_open                    | yes   | yes  |
| 11 | open* O_TRUNC, any mode   | entry             | file_open, inode_setattr     | yes   | yes  |
| 12 | write*, splice, mmap, ... | row 10's open     | row 10's open                | yes   | yes  |
| 13 | fallocate, FICLONE*       | none              | row 10's open                | yes   | yes  |
| 14 | chmod*, chown*, truncate  | entry             | inode_setattr                | yes   | yes  |
| 15 | setxattr*, removexattr*   | none              | inode_{set,remove}xattr      | yes   | yes  |
| 16 | row 15 on ACL names       | none              | inode_{set,remove}_acl       | yes   | yes  |
| 17 | file_setattr, 2 ioctls    | none              | inode_file_setattr           | note  | note |
| 18 | other ioctl commands      | none              | file_ioctl{,_compat}         | yes   | yes  |
| 19 | open* O_TMPFILE           | none              | file_open                    | none  | none |
| 20 | overlayfs upper layer     | not measured      | inode_*, file_open           | note  | yes  |
| 21 | a second path             | as by the first   | as by the first              | yes   | yes  |
| 22 | io_uring_*                | not reached       | not reached                  | none  | none |

The filter column names `fs.rs`'s checks:

- `name`: the new name's classification and the name rule (`allow_create`);
- `entry`: the existing entry's classification (`allow_child`, `allow_ino`);
- `move`: a directory or symlink leaving a writable region or a gitdir (`allow_region_move`);
- `syntax`: the target-syntax, region, gitdir and short-name refusals of `symlink`;
- `none`: the operation is unimplemented, so nothing reaches the backing store.

The rows, where the table does not say it all:

- Row 1: `may_o_create` calls both hooks, for `atomic_open` filesystems too (`fs/namei.c`).
- Row 5: `AT_EMPTY_PATH`, a `/proc/self/fd` source and an `O_TMPFILE` file (row 19) included.
- Row 7: `security_inode_rename` calls the hook twice for `RENAME_EXCHANGE`, operands swapped
  (`security/security.c`); `path_rename` receives the flags.
- Row 9: "Directories" has what removing a protected directory allows; read in `policy.rs`.
- Row 11: `do_dentry_open` calls `security_file_open` before it clears `O_TRUNC` from `f_flags`
  (`fs/open.c`), so `file_open` sees an `O_RDONLY | O_TRUNC` open, which has no `FMODE_WRITE`;
  `handle_truncate` then reaches `inode_setattr`. The filter counts it as a write.
- Rows 12 and 13: each operation needs a descriptor with `FMODE_WRITE`
  (`fs/{read_write,open,splice,remap_range}.c`, `mm/mmap.c`).
  - Row 12 is `write*`, `copy_file_range`, `splice` and `sendfile` to the file, and a shared
    writable `mmap`. The filter implements no `copy_file_range`; FUSE then copies through
    `splice_copy_file_range`, which writes through the open (`fs/fuse/file.c`).
  - Row 13 is `fallocate`, `FICLONE` and `FICLONERANGE`. FUSE answers a server's `ENOSYS` to
    `fallocate` with `EOPNOTSUPP` and has no `remap_file_range` (`fs/fuse/file.c`).
  - `FIDEDUPERANGE` accepts a read-only destination the caller may write, and changes no
    content (`may_dedupe_file`).
- Row 14: `ftruncate`, `fchmod`, `fchmodat2`, `lchown`, `utimensat`, `utimes` and `futimesat`
  too; each reaches `notify_change` (`fs/attr.c`).
- Row 17: no slot holds it; "Attributes, flags and ioctls" names the seccomp rule that does.
  - `FS_IOC_SETFLAGS` and `FS_IOC_FSSETXATTR` take a read-only descriptor
    (`fs/file_attr.c`, `ioctl_fssetxattr`), and `vfs_fileattr_set` admits the owner.
  - Only the append-only and immutable flags need `CAP_LINUX_IMMUTABLE` in the initial user
    namespace, and a project id is refused outside it.
  - Seccomp can refuse `file_setattr`, and the two ioctl commands by their command argument.
- Row 18: commands a filesystem implements itself, outside `vfs_fileattr_set`; the seccomp rule
  "Attributes, flags and ioctls" names refuses those listed here. The ones read take a read-only
  descriptor:
  - ext4's `EXT4_IOC_SETVERSION` and `EXT4_IOC_SETVERSION_OLD`, refused under `metadata_csum`,
    set the generation and ctime directly; `ext4_compat_ioctl` maps `EXT4_IOC32_SETVERSION` and
    `EXT4_IOC32_SETVERSION_OLD` to them. They, `EXT4_IOC_MIGRATE` and `EXT4_IOC_ALLOC_DA_BLKS`
    check the owner (`fs/ext4/ioctl.c`).
  - `FS_IOC_SET_ENCRYPTION_POLICY` sets a policy on an empty directory the caller owns
    (`fscrypt_ioctl_set_policy`).
  - `FS_IOC_ENABLE_VERITY` makes a file permanently read-only, checking write permission through
    `inode_permission` (`fsverity_ioctl_enable`).
  - xfs: none changes a file through a read-only descriptor. `XFS_IOC_ALLOCSP` and
    `XFS_IOC_FREESP` answer `ENOTTY`; `XFS_IOC_EXCHANGE_RANGE`, `XFS_IOC_START_COMMIT`,
    `XFS_IOC_COMMIT_RANGE` and `XFS_IOC_SWAPEXT` need the files open for reading and writing
    (`fs/xfs/xfs_exchrange.c`, `fs/xfs/xfs_ioctl.c`); `XFS_IOC_FREE_EOFBLOCKS`,
    `XFS_IOC_GETPARENTS` and the scrub, growfs, label and reserved-blocks commands need
    `CAP_SYS_ADMIN`.
  - btrfs (`fs/btrfs/ioctl.c`): `BTRFS_IOC_SUBVOL_SETFLAGS` makes a subvolume read-only and
    `BTRFS_IOC_SET_RECEIVED_SUBVOL` sets its received fields, each for the owner;
    `BTRFS_IOC_SNAP_CREATE`, `BTRFS_IOC_SNAP_CREATE_V2`, `BTRFS_IOC_SUBVOL_CREATE` and
    `BTRFS_IOC_SUBVOL_CREATE_V2` create a subvolume, a snapshot's whole tree among them, at a
    new name under the descriptor's directory through `btrfs_mksubvol` and `may_create_dentry`
    (`fs/namei.c`, `inode_permission` alone), calling no `inode_*` hook; `BTRFS_IOC_SNAP_DESTROY`
    and `BTRFS_IOC_SNAP_DESTROY_V2` remove one through `may_delete_dentry`, under
    `CAP_SYS_ADMIN` or the `user_subvol_rm_allowed` mount option. The rule lists these eight.
    `BTRFS_IOC_DEFRAG` changes the layout alone, and `BTRFS_IOC_ENCODED_WRITE` needs
    `CAP_SYS_ADMIN` and a writable descriptor.
  - FUSE answers a server's `ENOSYS` with `ENOTTY` (`fs/fuse/ioctl.c`).
- Row 19: `vfs_tmpfile` calls no hook before the inode exists, and the file has no name until
  row 5 links it. The filter implements no `tmpfile`, and FUSE answers a server's `ENOSYS` there
  with `EOPNOTSUPP` (`fs/fuse/dir.c`).
- Row 20: no `path_*` hook runs. Measured in a session on 2026-10-15: after `unshare -Urm`,
  `mount -t overlay` with `userxattr` and layers on `tmpfs` succeeds, and `mkdir merged/.git`
  lands in the upper layer. "Mounts" refuses the mount under `NESTING=none` unless the session
  loosens the profile.
  - overlayfs changes the upper layer through `vfs_create`, `vfs_mkdir`, `vfs_rename` and
    their siblings, `notify_change` and `vfs_setxattr` (`fs/overlayfs/overlayfs.h`), which call
    the `inode_*` hooks only; `fs/namei.c` calls the `path_*` hooks from the syscalls' paths.
  - It opens an upper file through `backing_file_open`, which reaches `file_open`.
  - It accepts an upper layer whose dentries revalidate, FUSE's and virtiofs's among them, only
    with `d_type`, `RENAME_WHITEOUT` and xattrs, and one whose dentries do not with a warning
    for each it lacks (`fs/overlayfs/super.c`, `ovl_make_workdir`). By that reading the filter,
    which implements no xattrs, cannot be one. Measured in Phase 2: on virtiofs the mount is
    read-only, since the work directory cannot be created there; on drvfs, whose `cache=0x5`
    selects 9p's dentry operations without `d_revalidate` (`fs/9p/vfs_super.c`), it is
    writable with the warning for `RENAME_WHITEOUT` ("Phase 2 on macOS", "Phase 2 on WSL").
- Row 21: a bind mount in a mount namespace of the session's own, which "Mounts" refuses where it
  refuses row 20's, or `open_by_handle_at`. The hooks judge dentries ("The policy"). Without
  `CAP_DAC_READ_SEARCH` in the initial user namespace, `open_by_handle_at` decodes directories only
  (`fs/fhandle.c`, `may_decode_fh`); 9p answers `name_to_handle_at` with `EOPNOTSUPP`.
- Row 22: `io_uring_setup` answers `ENOSYS` in a session, from the seccomp profile, and `EACCES`
  from SELinux to a plain container on the macOS machine ("Phase 2 on macOS"); on the WSL machine
  it succeeds in a plain container.

The source read is Linux 7.2.5. Upstream v6.18 makes the same calls for rows 1, 11 and 17, has
row 20's check of an upper layer, and its `bpf_lsm_disabled_hooks` lacks only
`file_alloc_security`; of Microsoft's `6.18.54.1`, `verifier.c` is read for the sleepable check
("The mechanism") and nothing else.

Both kernels' BTF lists every hook named in the table. The macOS kernel's is read from a session
on 2026-10-19 with `grep -aoE 'bpf_lsm_[a-z0-9_]+' /sys/kernel/btf/vmlinux` for the table's names
with `file_receive` and `file_permission`; the WSL kernel's through `podman machine ssh` on
2026-10-16, with a `grep -aoE` for the table's 24 names.

Sockets, measured in a sandbox session on 2026-10-21 with Codex 0.163.0, from `/proc/net/unix`
and a `find -type s` over the container: the one pathname socket bound was Claude Code's under
`/tmp`; the one socket file on shared storage was Codex's app-server daemon's,
`~/.codex/app-server-daemon/daemon-updater.sock` on the persistent volume, its daemon not
running; none in the workspace. sbt 2's server socket is under `~/.config/sbt/2/server`
(`project/target/active.json`); Mill's daemon listens on the TCP port it writes to
`out/mill-daemon/socketPort`, and Gradle's daemon and workers on TCP ports (`../SECURITY.md`).
`~` and the persistent volume are two mounts of one xfs superblock, `/dev/vda4`.


## Phases

Each phase ends at its gate; a failed gate leaves the launcher as it is.

0. **Inventory.** Pin the repository commit the policy transcribes. Produce one table: operation,
   its syscalls, the filter's behavior, the hook above, the measured result on each kernel. Read
   both kernels' BTF. Confirm the rmdir reading against `policy.rs`. Done in "Inventory",
   whose measured results Phase 2 fills.
1. **One hook, one denial.** A `lsm_cgroup/file_open` program denying the open for writing of
   one marker name, the controller attaching it to a disposable cgroup of the shape in
   "Lifecycle" and of the rejected one, then a disposable container under it: the marker is
   refused, other files are not, a sibling container outside the cgroup opens the marker, a
   second attached cgroup shares the slot, and a deliberately failed attach starts no container.
   Also, on each share, the identity test: a directory's and a file's `(superblock, i_ino)` in
   the guest stay the same after a host rename of it and of an ancestor, after the guest drops
   its caches, and for the two names of a host-made hard link, and differ from a host-made
   replacement at the same name, and the identity the controller's `statx` records equals the
   one an attached program reads from the object's inode ("The policy"), on both kernels;
   `findmnt` records the share's backend and options first, since 9p without metadata caching
   makes a new inode per lookup and keeps `i_ino` from the QID alone (`fs/9p/vfs_inode.c`,
   `v9fs_get_new_inode_from_fid`). And the verifier's time to load the eight programs, nine with
   `unix-socket`, with the `rename_lock` read and its fetch-add barrier ("What is gained and what
   is lost") in the walk, and `bpftool prog dump jited` showing the barrier instruction on each
   architecture. And, under the attach cgroup, a `createContainer` hook (`podman --hooks-dir`)
   that records its `/proc/self/cgroup` and opens the marker for writing: the open must fail
   with `EPERM` and the recorded cgroup must lie below the attach cgroup, with the installed
   crun ("Lifecycle", 1); the attach cgroup's `cgroup.events` reading `populated 1` with a
   container below it and no task of its own, and `populated 0` after the container's stop
   ("Lifecycle", 7); and whether the manager removes the empty slice within 60 s.
   On macOS first, then WSL. The probe is `../bpf/probe/phase1/phase1.sh`, `phase1.ps1` on
   Windows, run on the host; its transcript is this phase's record, and its programs are C with
   libbpf, not the classifier's Rust, since the phase measures the kernel and not the port.
   Gate: inheritance, denial, isolation, fail-closed start, stable identities and the hook's
   refused open below the attach cgroup, both kernels.
2. **Every hook.** The candidate programs on a disposable tree of the real share, exercising
   each syscall of the inventory, `openat2`, descriptor-relative calls, `RENAME_EXCHANGE`,
   `setfacl`, `setxattr`, `chattr` and row 18's commands, an overlay mount whose upper layer is
   in the tree, a host-side mount inside the tree, and ordinary git. Record
   the verifier's answer per hook per kernel, which attribute routes and ioctl commands each
   share accepts, and the cost of the bounded ancestry walk at the real tree's depths on both
   kernels, so the policy's price is known before the classifier and the lifecycle are built.
   Also a representative program holding the bounded walk, twice as `inode_rename` walks its
   source and its destination, the folding, the ordered rule match over a rule map filled to
   its `max_entries`, the git-context transitions and the `rename_lock` read together, loaded
   on both kernels and run at the real tree's depth and at the walk's bound, with the verifier's
   log, its instruction count and stack depth, clang's version and the object's hash recorded:
   the verifier's instruction budget and 512-byte stack (`include/linux/bpf.h`,
   `BPF_COMPLEXITY_LIMIT_INSNS`; `include/linux/filter.h`, `MAX_BPF_STACK`) are met by
   loading, not by reading, and
   `policy.rs`'s `fold` and `child_context` allocate, so the port is written allocation-free
   with bounded loops before Phase 3 ports the rest.
   The probe is `../bpf/probe/phase2/phase2.sh`, `phase2.ps1` on Windows, run on the host, and its
   transcript is this phase's record: `inventory.bpf.c` records which of 33 hooks each operation
   of the exerciser (`mutate.c`) reaches and refuses the operation on a deny name, attached in
   batches of eight that keep a hook whose refusal a row claims apart from the hooks the same
   operation reaches first; `classify.bpf.c` is the representative program, its loops the kernel's
   numeric-iterator loops (`bpf_iter_num_*`, Linux 6.4), which the verifier checks by the
   convergence of the loop's state rather than by simulating each iteration
   (`kernel/bpf/verifier.c`, `process_iter_next_call`), deciding a corpus of 51 cases on a
   fixture laid out as a workspace, under the defaults' rules and filler lines filling the
   128-line rule map, and ordinary git in a clone of this repository; the exerciser's open loops
   give the walk's cost at the clone's deepest file, at depth 32 and at depth 63, under the
   policy and on the bare bind. What the program leaves to Phase 3 is listed at its end.
   xfs's and btrfs's ioctl commands are read into row 18. For the later version, measure whether
   a nested podman under `NESTING=same-uid` needs the xattr syscalls, `file_setattr` or the
   refused ioctl commands while it pulls and extracts an image, creates, runs and execs into a
   container, and removes both, and whether each share stores a `security.capability` set and
   removed from a user namespace the session creates, before the decisions on open routes are
   put.
   Gate: the inventory's macOS and WSL columns are complete; every route of the first version's
   sessions, row 20's `user.overlay.*` names included, is held by its slot or by the seccomp rules
   "Attributes, flags and ioctls" and "Mounts" name, or covered by a decision taken for it, such
   as "Directories"; and the walk's cost is recorded beside the unfiltered bind's, and the
   representative program loads on both kernels.
3. **The policy.** The classifier in the programs, with what Phase 2 left to it ("The policy"):
   the guarded objects' identities, the alias contexts, the short-name form, the symlink target
   rules, `file_receive` and the walk's state against reentry; its host build and the corpus run
   through both classifiers ("What is gained and what is lost"); the map compiler in the
   guard (`../fuse/ko-agent-fs/src/bpf_records.rs`), producing the records "The policy" describes
   in one layout, from which it generates the C header `../fuse/ko-agent-fs/include/records.h`
   that a test compares with the committed file; and the filter's test corpus
   transcribed into the probe's corpus, each case naming the test it transcribes
   (`git-metadata.md`, "Test list"; `tests/mounted_*.rs`), since those tests mount a FUSE filter
   over a backing tree they write directly, which under the policy is a process outside the
   cgroup, and read `mkdir` as judged, which "Directories" does not.
   The walk's state across its loops, per CPU in the Phase 2 program, is per CPU and per slot
   here: the kernel runs a cgroup's programs under `rcu_read_lock` and `migrate_disable` with no
   recursion count (`kernel/bpf/cgroup.c`, `bpf_prog_run_array_cg`), so under full preemption a
   second task on the CPU enters the program over the first's state. Each call on an object of
   the share's type takes the lowest free of four slots by an atomic or on a per-CPU word and
   releases it at its decision; a fifth such task at once is denied and counted (`reentry`),
   while a call on another type, the runtime's and the container's own files, takes no slot and
   passes. Task-local storage would allocate the 28 KB of state inside the hook. Each kernel's
   preemption mode is read from `/sys/kernel/debug/sched/preempt` (the macOS kernel is
   `PREEMPT_DYNAMIC`, `dynamic_preempt_schedule` in its kallsyms, so a boot parameter sets the
   mode).
   The rows, each run with the policy attached, on both machines:
   - the corpus, in groups:
     - the name rule, the launcher's directory, hooks in the gitdir, a submodule's and a
       worktree's, a `hooks` that is itself a symlink, config, the redirections, alternates and
       operational state, with the region rules of a gitdir;
     - the file rules: a freed file, a pinned component, the writable region, a relocated hook
       directory and the symlinked `.claude`;
     - the "Directories" rules: a `HEAD` by each creating syscall in a `.git` the session makes
       in `sub/` and in `.git/objects/x/`, and by an exchange over a directory placeholder (a
       rename over one answers `EISDIR` before any hook); an exchange of a filled directory with
       a session-made `.git`; writes below a `.git` made under a `read-only` line; a file in
       `.git/objects/x/.ko-agent-sandbox`;
     - the symlink target rules, the walk's bound, in the workspace and below the recorded
       `.git`, and sockets;
     - a workspace whose `.git` is a pointer file with a host hard link to it and to
       `.ko-agent-sandbox` (`tests/mounted_mutate.rs`,
       `a_second_name_of_a_guarded_entry_is_guarded_like_it`), and a submodule worktree's
       pointer file with a host hard link to it in another directory, each judged by its name
       and by its second name;
   - ordinary git in a clone, and host git in `sub/`, whose session-made `.git` has no `HEAD`,
     finding the workspace's gitdir;
   - the torn-name race of "What is gained and what is lost", at two levels: one process renames
     `node_modAAAA`, holding `.vscode/tasks.json`, to `BBBBBBBBules` and back in a loop, by
     `rename` and by `RENAME_EXCHANGE` with a directory of the other name, another moves their
     parent `outerAAAA` to `BBBBouter` and back, and a third writes that file and creates beside
     it by path under every combination of the names and through directory descriptors of both
     `.vscode` directories held from the start, with the writes, refusals, walks and retries
     counted as the Phase 1 probe's stats row counts them, no write succeeds, and both renamers
     moved while the writer was refused under one name and found none under the other, without
     which the race did not run; the walks that read a torn name and were made again are
     reported, 0 to 12 a run, since each dentry is validated over the read of its own name;
   - the storm: sixteen processes creating, writing, renaming, linking and symlinking at once,
     permitted and refused names mixed, every decision counted and none wrong, with the reentry
     count and the deepest slot taken recorded; then the slots exhausted by hand through the
     per-CPU guard word: with four taken a write is refused and counted, with three it runs in
     the fourth, and freed it runs in the first, the word set while a container already up
     sleeps, so that no call of the runtime's is in flight;
   - sockets by default: a `bind` beneath the persistent volume's root refused and one under
     a directory on the volume's superblock standing for `~` allowed, from where the socket can
     be neither renamed nor linked beneath the volume, nor moved into the workspace, which
     recreates it by `mknod`;
   - a second host share bound into a disposable container, on which a write is denied;
   - the walk's cost at the clone's deepest file: `file_open`'s own timer over five interleaved
     pairs of a container under the policy and one beside it, in alternating order, and each
     pair's difference for the open for writing beside two the policy does not walk, the open for
     reading, which the hook leaves first, and `lstat`, which no hook sees; and the jited barrier;
   - the NTFS short-name form under its flag: a mutation whose ancestry or own name has the form
     denied, a name with a `~` outside the form allowed; the form on a real NTFS volume is the
     Windows driver's row;
   - under `unix-socket`, four sandboxes with their own policies, a live session, a second
     session of the workspace launched under a later rule file, a session of another workspace
     and a `--workspace=read-only` session, holding nine hooks of the ten slots and differing in
     policy:
     - a socket in the workspace allowed, and one under `.git/objects`, at the gitdir's root
       (`fsmonitor--daemon.ipc`) and under a `read-only` line refused, by `bind`, by `rename`
       and `RENAME_EXCHANGE` of one bound elsewhere and by `link`; a symlink there to a socket
       outside allowed;
     - a container starting with `file_receive` attached, the runtime's descriptors passing,
       and its first process holding no descriptor beyond the standard three;
     - a pipe, a socket pair's end and a workspace file passed between two processes of one
       container, which arrive;
     - to the later session one message of three descriptors, a read-only one of an ordinary
       file, a writable one of a file its rule file refuses and the sender's allows, and a
       read-only one again, of which it gets the first alone and `MSG_CTRUNC`; a writable
       descriptor of a file both allow, which it writes, beside a read-only one of the refused
       file, which it cannot reopen for writing;
     - directory descriptors of the sender's container root, of its `/tmp` and of the
       receiver's own root, which no receiver gets; a pipe after a refused directory dropped
       with it, and one before it arriving; a sender whose container ends and is removed
       before the receiver reads, the receiver waiting for the driver's marker of that, whose
       writable file and directory do not arrive, the hook's record showing the file's mount in
       no namespace, and whose read-only share file does arrive;
     - a file descriptor into the other workspace's session and into the read-only session,
       which get nothing; the read-only session itself writing nothing on the share, writing
       `/tmp` and reading the workspace;
   - the seccomp profile "Mounts" relies on, derived from the machine's default as `TODO.md`
     plans it: `unshare` and each mount syscall answer `EPERM` and a child process still starts.
   For the later version, under `NESTING=same-uid` and with the profile loosened, the session
   binds the workspace and a nested filesystem at other paths in a mount namespace of its own and
   mutates through the aliases, and through an overlay mount; and a host hard link to a nested
   `.git` pointer file, made before and after launch, the residual "The policy" records under
   the second-name rule.
   The probe is `../bpf/probe/phase3/phase3.sh`, `phase3.ps1` on Windows, run on the host, and
   its transcript is this phase's record: `policy.bpf.c` is Phase 2's program with the additions
   above, the walk, each level of it and of its snapshot, the rule match, the alias activation and
   the symlink judgment each a global function verified once per program, since the verifier
   checks a loop's inlined body at every iteration until its states converge and 6.18 converges
   slowly ("Phase 3 on WSL"); `exercise.c` lays out the fixtures, decides the corpus of
   252 cases in seventeen groups, runs the race and the storm, and binds, serves and receives
   sockets and descriptors; `controller.c` is Phase 2's with the records, computing an alias
   context in user space as the guard does. The runs settled the record layout, which the
   guard's compiler writes. The host build (`../bpf/probe/phase3/host/`) runs the filter's own
   corpus through the program before any host run, and a program it has not passed is not run
   on the machines.
   Gate: each row ENFORCED, or an existing filter residual, or covered by a decision the user has
   taken, "Directories" or one in "Decisions still open"; and the policy program loads on both
   kernels, its verifier figures recorded as Phase 2's are, each program within 500,000
   instructions, half the limit, on each kernel, since 6.18 processes many times 7.2's
   instructions for one loop ("Phase 3 on WSL", 28 times for the walk) and a program near the
   limit fails to load at the next change of the walk. A listed loss passes nothing.
4. **Lifecycle.** The ordering of "Lifecycle" on rootless podman: first-process denial, restart,
   recreate, `podman exec`, stop and kill, controller exit, machine restart, link loss; and the
   proof's catches, a controller that attaches a subset of the hooks, one that attaches another
   build's program, one whose build differs in data alone, and one that loads wrong records, each
   of which must end the launch. The
   reconcile of "Lifecycle", 7: a launcher killed between the pins and `podman create`, and a
   `podman create` that fails after the pins, each leave a cgroup and pins the next start
   removes; a launcher killed between `podman create` and `podman start` leaves a container
   that names the cgroup, whose pins stay until the container is removed; a stopped session's
   and a live session's stay, and a listing that fails removes nothing. The restart invariant
   of "Lifecycle", 5: the created container's restart policy reads `no`, and after a machine
   restart with a stopped container present, nothing starts it. The socket rule's dependence on
   the mounts ("The policy"): a directory under `~` holding a bound socket, moved into the
   volume or the workspace, fails with `EXDEV`. The controller's two refusals: one given an
   object path, and one asked for a cgroup outside the invoking user's slice, in the machine;
   and its third, a mount under the bind source, which it lists in the VM before the attach
   ("The policy"). The launch cost of steps 2 and 3 on both machines, the verifier's 0.6 s and
   1.7 s for the nine programs among it ("Phase 3 on macOS", "Phase 3 on WSL"), and a restart's
   with the pinned programs ("Lifecycle", 5). Two decisions rested on those figures. Whether
   the fixture runs at every launch or after installation and changes alone, for which the
   controller keeps the two parts of step 3 separable, is open; it runs at every launch until
   decided. The verifier's time leaves the launch through the spare set ("Lifecycle"), the user's
   decision of 2026-10-25 over the alternative of one program set per machine, verified once per
   boot, whose hooks would find the session's records in inner maps of a map-of-maps keyed by
   the attach cgroup, found through the task's cgroup ancestry: that would cost the per-sandbox
   programs "The policy" relies on, the invariant that no record changes under a running program,
   and the read-back's showing that a cgroup's programs read that cgroup's records, where the
   spare costs an idle set per machine and a background preparation.
   The rows the reuse of pins, the reconcile's identities and the cleanup add, on both machines:
   - a restart after `--build` installed another object, and one after a rule change, each
     loading and verifying fresh programs and attaching none of the old pins, which are
     unpinned; the launch's own pins attached only when the read-back finds the installed tag
     and this launch's records ("Lifecycle", 5);
   - the reconcile under identities that contradict: a container whose labels name another
     session's cgroup, a cgroup directory whose recorded identity no longer matches its path,
     and a pin under another session's name; it associates no pin or cgroup with a session it
     cannot establish, removes nothing for them, and reports each;
   - the cleanup's refusals, one each: a pin path with a relative component, a symlink in place
     of a pin directory or of a cgroup directory, a mount on the pin directory, and a cgroup
     directory whose identity changed since the launcher recorded it; each refused, nothing
     removed; and a refusal found late, one foreign link among a session's pins and a programs
     directory that cannot be opened once the links were checked, each leaving every pin in
     place, since the reconcile checks all of a session's pins before it removes any.
   Phase 4 also binds the evidence to the program it measured: the drivers of Phases 3 and 4
   record the SHA-256 of the probe's sources beside the object's, the measurement sections name
   it, and `bpf/probe/check-evidence.sh` fails when a source differs from the hash its section
   names, so that a section cannot stand as evidence for a program it did not measure.
   Gate: no container process runs before the policy, on either machine, each of the three
   defective controllers is caught, the stale pins and the contradicting identities are refused,
   the reconcile removes the two orphans and nothing else, and the evidence check passes.
5. **Measurement.** `probe/perf-probe.py` and the real-tree rows of `verification-log.md` on the
   bind with the policy, beside the filter and the unfiltered bind; the machine's CPU and memory
   during the stat storm under each, the stat storm being `walk-probe.py`'s rows over the real
   tree, `lstat` of every tracked file by path and `git status`.
   The probe is `../bpf/probe/phase5/Phase5.scala`, one Scala CLI script for both hosts, run on
   the host, and its transcript and tables are this phase's record: it builds Phase 4's controller,
   read-back and fixture over Phase 3's program, with `stats.c` reading the program's counters
   beside them, clones the real-tree rows' tree (sbt/sbt, shallow) into a scratch workspace on the
   share, launches the policy over it through steps 1 to 3 of "Lifecycle" under the launcher's
   default rules, and runs the two probes over that one tree in three containers: the sandbox
   image over a writable bind of the workspace (`probe/unfiltered.sh`'s command), the same
   command below the attach cgroup, and the launcher's session through the filter, and before the
   launch one `perf-probe.py` round on the bind with no program attached, the control for the shim
   the first attach installs for every task in the VM ("The mechanism"). `perf-probe.py` runs in
   interleaved rounds, three by default; the `sbt` build of "an sbt build, by where its output goes"
   runs once on the bind and once under the policy, on a clone of this repository made inside the
   tree with its output there, the filter's 604 s standing from that log; `walk-probe.py` runs once
   per stack. A sampler in the machine reads `/proc/stat`, `/proc/meminfo` and the pressure files
   each second during each run, and the program's counters are read after each run under the
   policy, so that each figure comes with the calls each hook judged. A hook file's creation in
   `.git/hooks`, refused under the policy and through the filter and made over the bare bind, shows
   each stack is what it claims before the figures are taken.
   Gate: the numbers are recorded; the default changes only by a release decision.
6. **Integration.** Beside the mode, `--workspace` takes comma-separated values for the backend
   and for sockets, the user's decisions of 2026-10-26. The backend is `bpf` or `fuse`, the
   filter; `fuse` stays the default of both modes until the release decision. `unix-socket`
   allows Unix sockets in the workspace and beneath the persistent volume at the cost of the
   ninth hook ("The hooks", `file_receive`), and is a fatal error with `fuse`, since the filter
   cannot honor it. The parser accepts the values in any order, and the container label holds
   one canonical spelling, so that the refusal below compares settings, not spellings.
   The backend selector with a capability probe, run at every launch: `bpf` in
   the active LSM list, cgroup v2 with the user's delegated subtree under the manager podman
   reports, `bpffs` and `securityfs` mounted, which the launcher mounts where the machine does
   not ("Environment evidence", Windows), the share's type among the measured ones, and a
   container placed below the attach cgroup, with the WSL setting named where that fails; the
   reconcile of "Lifecycle", 7, at the launcher's start; the no-root policy for
   `--workspace=read-only` where the probe passes and the raw `ro` bind with the printed host
   requirements where it fails, the launch line naming the backend and the accepted differences, the
   removal of the filter from the first version's sessions, with the selector keeping it for the
   rest ("Later versions") and refusing a launch whose backend or `unix-socket` setting differs
   from a live session's sharing its volume or a raw mount, or that of an unlabelled or renamed one
   ("The hooks", `file_receive`), and the documentation changes "The recorded decisions this
   answers" names. It needs the profile "Mounts" relies on to have shipped. Its rows, which
   need the launcher:
   - under the profile the launcher installs, `io_uring_setup` answers `ENOSYS` from the
     container's first process and from a `podman exec` process ("The hooks", `file_receive`);
   - a launch under the other backend or the other setting of `unix-socket` while a session
     sharing its volume or a raw mount is live, refused in either order: for a main checkout and
     a linked worktree sharing its volume, for two sessions of one workspace naming two volumes,
     for a workspace below another's root, for a linked worktree with its own volume beside its
     main checkout, after a host rename of the workspace between the two launches, which name
     two volumes, beside a live container of an earlier launcher without the labels too, and of
     two such launches racing, one refused;
   - a linked git worktree, whose main gitdir the launcher binds read-only (`TODO.md`,
     "Deferred — writable git from a linked worktree"), and a symlink under its main checkout's
     `.git/objects` to a socket outside, through which the worktree's container cannot connect;
   - `codex exec` run with the daemon directory unwritable ("The hooks", `file_receive`);
   - the spare set ("Lifecycle"): a launch taking it by rename and filling its maps through the
     pinned programs' ids, passing the read-back and the proof, its step 2 at a recreate's cost;
     two launches racing for one spare, one loading; a spare of a build `--build` replaced,
     unpinned by its tags; a launch that died after taking the spare, removed by the reconcile;
     and the first spare prepared at boot; a live session's records, read back before and after
     another launch takes the spare and the next spare is prepared, unchanged, and the two
     sessions' program and map ids disjoint;
   - the sessions' cost in the kernel: the programs, links and maps and their memory at one,
     four and eight live sessions, and the same after their teardown, so that the per-sandbox
     sets "The policy" relies on have a measured price. The kernel charges a map's and a
     program's memory to the memory cgroup of the process that made them, and the charge
     outlives the process (`kernel/bpf/syscall.c`, `bpf_map_save_memcg`, the map's `objcg`), so
     every load, the launch's, the boot-time spare's and each replenishment's, runs in a cgroup
     kept for the measurement and summed by it, whose `memory.current` is read after the loader
     exits: under systemd a scope holding a sleeping process beside it, since a scope ends with
     its last process (`systemd.scope(5)`), under cgroupfs a directory of the delegated subtree,
     which stays until removed; a set loaded elsewhere, the spare's preparer's cgroup for one, is
     charged there and missing from the sum. The machine's root offers no reading, `memory.current`
     being a file of non-root cgroups alone (`Documentation/admin-guide/cgroup-v2.rst`), and
     `bpftool`'s `memlock` is each map's own estimate (`kernel/bpf/syscall.c`,
     `bpf_map_memory_usage`), not the charge;
   - on WSL, the proof run by the launcher itself: its process enters the leaf below the attach
     cgroup through a transient scope of the user manager ("Phase 4 on WSL"), and a scope that
     cannot be created or a migration that fails ends the launch before any container;
   - the FIFO rules ("The policy"): `mknod` of a FIFO refused by type in `inode_mknod`, its
     open in `file_open`, a time change on one in `inode_setattr` and, under `unix-socket`,
     its descriptor in `file_receive`, each a corpus case over a FIFO the host made, opened with
     `O_NONBLOCK` so that the test itself never waits, and the proof's `mkfifo` at an ordinary
     name, under which the measured sections of Phases 3 to 5 name a sources hash the tree no
     longer has: the three probes rerun on the changed program on both machines, the FIFO cases
     in Phase 3's corpus and the `mkfifo` in Phase 4's fixture, and their sections are rewritten
     from the reruns. `check-evidence.sh` gets no marker for a superseded section, the user's
     decision of 2026-10-26: a section stands for the program in the tree alone, so that no later
     change of the program, the Rust port among them, leaves the plan's evidence describing
     another program.


## What is gained and what is lost

The git property, the file rules and the blocked git commands are in neither list: the hooks
hold them as the filter does. The name rule is held too, except for directories, which "Lost"
lists. The lists are what else changes.

Gained:

- **The filter's whole cost.** The ceiling is measured
  (`../fuse/ko-agent-fs/doc/verification-log.md`, "The cost of a path walk"):

  | workload                             | through the filter | unfiltered bind | under the policy |
  | ------------------------------------ | ------------------ | --------------- | ---------------- |
  | `ls -lR`, per entry                  | 12.7 ms            | 0.72 ms         | 0.77 ms          |
  | `git status`, 4,475 files at depth 7 | 72 s               | 4.7 s           | 4.3 s            |
  | `sbt` build of this repository       | 604 s              | 102 s           | 104 s            |

  The `sbt` row's bind and policy figures keep the output in the workspace as the filter's does; the
  43 s of "an sbt build, by where its output goes" had it outside. The policy's own cost over the
  unfiltered bind is measured in "Phase 5 on macOS" and "Phase 5 on WSL": `perf-probe.py`'s
  rounds overlap the bind's in every row on both machines; the single runs of the walk and the
  build lie within a tenth of the bind's on the per-file rows, `git status` and the build, and
  scatter up to 1.2 times on `find` and 2.1 times on the depth rows, 200 `lstat` of 0.1 to 1 ms
  each, either way across runs; the program itself takes 13 to 18 µs a judged call on either
  kernel, 40 to 47 µs at the build's depth of 20. It runs on mutations and opens, never on
  `lookup` or `getattr`, the operations that dominate those columns.
- **The daemon's share of the machine's hangs.** `git status` in a worktree of hundreds of
  files has frozen the podman machine for over an hour, with memory not short and
  `podman machine ssh` failing throughout. The daemon and its requests go with the filter.
  - What the bind keeps is the share server's one worker thread per share, which one blocked
    request stalls for every later one (`upstream-issues.md`, "Setting a FIFO's times blocks
    the macOS virtio-fs server").
  - A FIFO on the share is refused by type, its creation in `inode_mknod`, its open in
    `file_open`, its time change in `inode_setattr` and, under `unix-socket`, its descriptor
    in `file_receive` ("The policy"), the decision of 2026-10-25; the measured program has none
    of these yet, and a FIFO at an ordinary name passes it ("Phase 4 on macOS").
- **No window between resolving and acting.** The decision is taken inside the syscall, on the
  dentry the kernel acts on, which the filter's resolver and its `ESTALE` rules exist to
  approximate. A held directory handle follows a directory the host moved and is judged by its
  current position. The walk reads `d_parent` and `d_name` without `rename_lock`, so a concurrent
  `d_move` of an ancestor can be seen mid-move, half old and half new (`fs/dcache.c`, `__d_move`).
  What keeps that harmless:
  - a walk that overlaps a rename is discarded, and no property of the classifier stands in for
    that: `d_move`, `d_exchange` and `__d_unalias` hold `rename_lock` across the parent change
    and the name change, which for inline names copies the new name over the old on a rename
    (`fs/dcache.c`, `__d_move`, `copy_name`, a struct assignment) and swaps the two a word at a
    time on an exchange (`swap_names`), so an unvalidated walk can read a name that is neither,
    `node_modules` out of `node_modAAAA` and `BBBBBBBBules`, and the defaults' `writable` line
    would lift a `.vscode` below it that both real names protect. `policy.rs` allows that rename,
    since a directory is pinned only as an interior component of a line (`RuleContext::pinned`) and
    the move leaves no region (`authorize_region_move`). Phase 3 runs it as a race;
  - the program reads each dentry's own sequence count, `d_seq`, before and after reading its
    parent, name and inode (`fs/dcache.c`, `__d_move` and `d_exchange` hold it odd across the
    parent and name change), and reads every level's count again after the last level, as the
    RCU path walk revalidates the dentry it came from after reading the next (`fs/namei.c`,
    `lookup_fast`), through the address each level was read at, a scalar the probe helper
    returned, under the caller's RCU read lock, which keeps a dentry's memory a dentry
    (`fs/dcache.c`, `__d_free`): the chain counts only when each first value is even and every
    later read equals it, so it is the object's position over one interval of the walk and not
    a composition of two moments, and a barrier separates each count read from the field reads,
    as `read_seqbegin`
    and `read_seqretry` have (`include/linux/seqlock.h`, `smp_rmb`) and two plain reads do not;
    otherwise the walk is discarded and made again, and denied after a bound. Phases 1 and 2
    read the global `rename_lock` sequence around the whole walk instead, as `d_path` does,
    which discards a walk at any rename in the VM: sixteen renaming processes made 35 of 11,891
    walks give up after four retries and denied permitted operations ("Phase 3 on macOS"),
    where `d_path` takes the write lock on its second try and a program cannot. Clang emits no
    barrier instruction for
    BPF: a fence outside the single-thread scope is a fatal error in LLVM's BPF backend
    (`BPFISelLowering.cpp`, `LowerATOMIC_FENCE`). The barrier is an atomic fetch-add on a map
    word between the reads: the arm64 JIT emits `ldaddal`, or `ldxr`/`stlxr` with `dmb ish`
    without LSE (`arch/arm64/net/bpf_jit_comp.c`, `emit_lse_atomic`, `emit_ll_sc_atomic`), and
    the x86 JIT a `lock`-prefixed `xadd` (`arch/x86/net/bpf_jit_comp.c`, `emit_atomic_rmw`);
    both verifiers accept it and the jited dumps show those instructions ("Phase 1 on macOS",
    "Phase 1 on WSL");
  - a host rename moves a guest dentry too, when the session's next lookup of the new name
    returns the inode the old dentry holds (`fs/dcache.c`, `d_splice_alias` to `__d_unalias`,
    which FUSE, virtiofs, overlayfs, ext4, xfs and 9p reach; 9p without metadata caching makes a
    new inode instead), and on native Linux by `rename(2)` itself. A write the walk judges at the
    old position is one the session could make until the guest noticed the host's rename, the
    race `git-metadata.md`, "Races", lists for the filter; the host is trusted.
- **Data coherency is the share's own.** The filter's two residual cache cases
  (`../fuse/ko-agent-fs/doc/architecture.md`, "Coherency") have no layer to occur in.
- **No daemon.** No `ENOTCONN` failure domain shared by a workspace's sessions, no serialized
  round trips, no inode table.

Lost, stated as what becomes possible that the filter does not allow:

- **A privileged controller in the path.** The enforcement is the verified program in the
  kernel; the controller that installs it runs with the `bpf` syscall's privileges, as root for
  the launch, in the machine or on a native Linux host ("Native Linux"), where the filter daemon
  runs as an ordinary user throughout.
  - It parses no text from the workspace: the unprivileged guard folds and compiles the rules into
    fixed-size records ("The policy"), and the controller installs them and attaches links.
  - What becomes possible is a defect in that installing, reached only through the launcher,
    since the sandbox has no path to the controller: it exits before the container starts and
    listens on nothing.
- **A mistake in the kernel-facing glue, which no host test reaches.** The classifier itself is
  unit-tested on the host, the C program compiled a second time into a test binary and run
  through `policy.rs`'s corpus ("What is gained and what is lost"), and the folding,
  parsing and map compilation stay in the guard's Rust and reuse `policy.rs`.
  - What the host cannot run is the glue around it, the `d_parent` walk, its CO-RE reads and
    its bounds: an LSM program has no `BPF_PROG_TEST_RUN` (`kernel/bpf/bpf_lsm.c`,
    `lsm_prog_ops` is empty).
  - A wrong bound or read there passes a write to a protected entry until Phase 3's corpus, run
    through real syscalls against the attached program, catches it.
- **No writable session on a kernel without the LSM.** The probe fails, the launch binds nothing
  writable and says what the host lacks. A lost session, never a weaker one.
- **No session write through an NTFS short name on Windows.** Refused by form ("The policy"), a
  form no project is known to use. No protection is weakened.
- **No Unix socket in the workspace or beneath the persistent volume, by default.** Of the
  installed software, Codex's app-server daemon alone binds one there ("Environment evidence");
  `unix-socket` allows them at the cost of a ninth hook ("The hooks", `file_receive`).
  - Under the option a `--workspace=read-only` session can connect to a socket a live session
    binds on the share or the volume and send it data: no hook judges `connect` or a socket's
    `sendmsg`, and the bytes do not touch the socket's inode. It cannot bind one, mutate the
    socket's file or receive a share file, so what it writes is what the live session's
    process then writes under its own policy.
  - Refusing the data would take `socket_sendmsg` as a tenth hook, the last slot, walking from
    the peer's bound dentry (`net/unix/af_unix.c`, `unix_sk(peer)->path`), and would close
    nothing while the two sessions share the persistent volume, which a read-only session
    writes: the live session's configuration under `~` is reachable there directly. Not built;
    the case to revisit is two sessions launched with different volumes.
- **No write by a `--workspace=read-only` session through a descriptor a live session passes, and
  the controller's run for a read-only launch.** The filter admits the write, since the live
  session's mount judged the open; here nothing arrives by default, `file_receive` refuses under the
  option what another container passes but a share file it could open itself, a file of its own
  volume or a file of another type, which reaches no share ("The hooks"), and the session's
  policy recording no root lets nothing on the share be opened for writing ("The hooks",
  `file_receive`). No protection is weakened.
- **No socket inode inside a gitdir under `unix-socket`, by creation, rename or link.** Git
  binds its one there at the root, a name the filter refuses already. No protection is
  weakened.
- **A directory at any name, `.git` and `.ko-agent-sandbox` included.** The session can create
  and remove empty directories at a guarded name or position, which the filter refuses.
  "Directories" has the rules that keep this from weakening any protection.
- **Under `NESTING=none`, nothing in the container sets xattrs (`setfattr`), ACLs (`setfacl`) or
  `chattr` flags, or runs row 18's ioctl commands.** The seccomp rule ("Attributes, flags and
  ioctls") refuses them under `~` too, where the filter refuses them in the workspace alone, and
  `cp -a` drops xattrs and ACLs there. No protection is weakened.

Decisions still open, each the user's, taken after Phase 2's table:

- **The routes under `NESTING=same-uid` whose syscalls a nested podman needs, a later version.**
  The seccomp rule cannot refuse those syscalls, and the two free slots ("The hooks") can hold
  two of their hooks. Which two, and so which routes stay open on such sessions, is this decision.
  - A `NESTING=none` session attaches eight hooks and such a session ten, so both fit the
    machine's ten slots at once, unless something else in the VM holds one ("The mechanism") or
    a `unix-socket` session holds the ninth, when one route's hook has no slot.
  Each route's consequence:
  - `inode_set_acl` open: an ACL set on a protected file rewrites its mode bits
    (`posix_acl_update_mode`), a `chmod` the hooks never see;
  - `inode_remove_acl` open: an ACL the host set on a protected file can be removed; the mode
    bits stay, since `fuse_set_acl`, `ext4_set_acl`, `xfs_set_acl` and `btrfs_set_acl` update
    the mode only for a non-null ACL;
  - `inode_setxattr` open: a `user.` xattr can be set on a protected file, which no host
    program here reads (`xattr_permission`; `cap_inode_setxattr` needs `CAP_SYS_ADMIN` for the
    other `security.` names);
  - `inode_setxattr` open, from a user namespace the session creates ("The policy"):
    `security.capability` can be set on a protected file, since `cap_inode_setxattr` exempts
    it and `cap_convert_nscap` admits it with `CAP_SETFCAP` in the caller's namespace for a
    file whose owner is mapped there (`security/commoncap.c`), as the session's own files are.
    The capability written is namespaced to that user namespace, and no host process is in it;
  - `inode_removexattr` open: a `user.` xattr the host set can be removed, and so can a
    `security.capability` the host set, from a user namespace the session creates
    (`cap_inode_removexattr`, `capable_wrt_inode_uidgid(..., CAP_SETFCAP)`);
  - `inode_file_setattr` open: a flag other than the append-only and immutable ones, or an `fsxattr`
    field other than the project id, can be set on a protected file the session owns
    ("Inventory", row 17);
  - `file_ioctl` and `file_ioctl_compat` open: row 18's commands reach a protected entry, which
    can have its ext4 generation and ctime set, get an encryption policy if it is an empty
    directory, or be made permanently read-only.
  Nothing is pre-accepted.
- **overlayfs's `user.overlay.*` names on protected directories, where the session can mount:
  under `NESTING=same-uid`, and on a `NESTING=none` session with the profile loosened
  ("Mounts"), a later version.** No taken slot holds `inode_setxattr`, and the seccomp rule does
  not see overlayfs's own writes ("Attributes, flags and ioctls"). Pending, between:
  - accepting them: a `user.` xattr on a protected directory, which no host program here reads;
  - `inode_setxattr` in a free slot on such sessions, which holds row 15 there too and leaves one
    free slot to the decision above.
- **A hard link the host makes to a guarded file** is taken ("The policy", the second-name
  rule): the submodule pointer files are recorded, the rest is a residual. Refusing every write
  through a file with `i_nlink > 1` was not among the options: pnpm installs by hard-linking
  from a store on the installation's filesystem, which in a session is the workspace's
  (https://pnpm.io/faq, "Does pnpm work across multiple drives or filesystems?"), so
  hard-linked files in a workspace are ordinary.
- **Denylist inside a gitdir.** Only if Phase 3 finds the allowlist too large for the program:
  a denylist of the executable state (`config*`, `hooks`, `commondir`, `gitdir`,
  `objects/info`, the rebase, sequencer and `rr-cache` state) is smaller and fails open
  on a future git file that executes. Not recommended before that finding.


## Native Linux

A later version ("Later versions") runs the backend on a native Linux host's own kernel, without
a podman machine, within a supported set the launcher states rather than discovers. A host
outside it gets `--workspace=read-only` and a message naming the missing requirement; a podman
machine is never created for it. The set is chosen so that the host's launch is the machine's
launch, one `sudo -n` of the controller under the same cgroup manager, with no mechanism of its
own. The requirements, each checked at launch:

- **`bpf` in the active LSM list**, read from `/sys/kernel/security/lsm`. Every default list in
  `security/Kconfig` ends in `bpf`, and the machine's Fedora kernel lists it ("Environment
  evidence"); which distributions drop it is not something this plan records, since the probe
  answers per host. Where a kernel lacks it, the message names the boot parameter, `lsm=` with
  `bpf` appended, and the reboot.
- **A sudoers drop-in for the controller**, granting the launcher's user `sudo -n` of the
  root-owned controller binary and nothing else.
  - The host is never prompted for sudo (`../SECURITY.md`, "Silent changes to what you own"), so
    `--build` prints the drop-in and its install command, as it prints the `fuse.conf` change
    for a machine, and the user runs them once.
  - What any sudo-granted binary needs, and Phase 4 runs: the controller loads the object
    installed beside it and takes no object path, and it attaches only under the invoking user's
    slice, `/user.slice/user-<uid>.slice/`, with the uid from `SUDO_UID`; either refusal fails
    the launch.
  - Loading an LSM program needs `CAP_BPF` with `CAP_PERFMON`, or `CAP_SYS_ADMIN`
    (`kernel/bpf/syscall.c`, `is_perfmon_prog_type`). A BPF token on a delegated `bpffs`
    satisfies those two checks for an unprivileged process (`bpf_prog_load`,
    `bpf_token_capable`); whether the attach also works unprivileged is unverified, so the
    drop-in is what the plan builds and the token a later reduction.
- **Under SELinux enforcing, `label=disable` for the sandbox container.** Podman's default,
  `label=true` in `containers.conf`, labels the container `container_t`, which cannot read a
  plain bind of the workspace; the option is ignored where SELinux is disabled, so a host under
  AppArmor needs nothing here and keeps podman's `container-default` profile on the container.
  - The sandbox container then runs outside SELinux confinement, as nested containers already do
    (`../SECURITY.md`, "No containers inside the sandbox by default"); what confines it is the
    cgroup-LSM policy, its namespaces, seccomp and capabilities.
  - The alternatives, each rejected: relabeling the workspace to a shared container type
    (`semanage fcontext`, then `restorecon`) keeps the container confined, but writes every
    file's metadata, takes confined host services' access to the tree away, and `../SECURITY.md`
    records that the workspace's labels are never changed; leaving enforcing hosts out of the set
    excludes the host family both podman machines are built from.
- **Rootless podman with the systemd cgroup manager**, as on the machines.

Landlock would need no privilege and no kernel option, and is active on both machines' kernels,
but a Landlock rule's object is a file hierarchy named by an open descriptor
(https://man7.org/linux/man-pages/man7/landlock.7.html), so neither a `.git` file nor the
`config` of a new `.git` directory, before it exists, is an object it can refuse, at any depth.
It is not a backend for this policy.


## Acceptance

- Two sandboxes share the hook slots and differ in policy; a third container, the egress proxy
  and the machine's own processes are never judged.
- A `.git` or `.ko-agent-sandbox` by any folded spelling cannot appear by `creat`, `mknod`,
  `symlink`, `link`, `rename` or exchange, at any depth; one that `mkdir` makes never gains a
  `HEAD`, a `read-only` line still covers what lies below it, and nothing but directories enters
  a `.ko-agent-sandbox` at any position.
- A protected entry cannot be opened for writing, truncated, re-attributed by `chmod`, `chown`,
  times, an xattr, an ACL or a `chattr` flag, changed by a filesystem ioctl, unlinked, removed
  unless it is an empty directory, renamed, exchanged, hard-linked out, or replaced, through any
  name, descriptor or mapping, beyond what a decision taken in "Decisions still open" accepts.
- Under `NESTING=none` with the launcher's profile, the session creates no user namespace and no
  mount syscall succeeds, and a mount under the bind source refuses the launch.
- By default no socket inode comes to be in the workspace or beneath the persistent volume, by
  creation, rename or link, so the session opens no channel to another container. Under
  `unix-socket`, a descriptor one sandbox passes another is judged by the receiver's policy, a
  descriptor from another container is refused on arrival unless it is a non-directory of the share
  beneath a recorded root that the receiver could open so by path, of its own volume, or of a type
  that reaches no share, every directory among the refused and passing within one container
  unchanged, so a sandbox of another workspace and a
  `--workspace=read-only` session get nothing on the share, and no socket inode enters a gitdir
  directly. A launch whose backend or option differs from that of a live session sharing its volume
  or a raw mount, a linked worktree's main gitdir included, beside a live container of an earlier
  launcher without the labels, or beside one whose recorded root path no longer names its recorded
  identity, is refused, whichever launched first and when both launch at once.
- Git's everyday commands work; the commands the filter blocks stay blocked and listed.
- The file rules hold at any depth, with the resolved `read-only-path` lines.
- No container process runs before the policy, proven by the read-back of every attachment,
  program tag and map record and by the fixture suite in the attach cgroup, which a controller
  that attached nothing, a subset, another build or wrong records cannot pass; the policy
  outlives the controller; the attach cgroup cannot be removed while the container's scope or any
  task is in it.
- A later version ("Later versions") holds the `.git` and protected-entry rows through an alias
  the session binds, an overlay mount it makes and a nested mount the host made, for the sessions
  it admits, and on native Linux the two refusals of "Native Linux".


## Sources

- Linux 7.2.5: `include/linux/{bpf-cgroup-defs,lsm_hook_defs,seqlock,filter,bpf,fs}.h`,
  `include/linux/{kdev_t,nsproxy}.h`,
  `kernel/bpf/{cgroup,bpf_lsm,trampoline,btf,verifier,helpers,core,syscall}.c`,
  `kernel/trace/bpf_trace.c`, `security/{security,commoncap}.c`, `net/unix/af_unix.c`,
  `fs/{namei,attr,open,xattr,posix_acl,file_attr,ioctl,read_write,splice,remap_range}.c`,
  `fs/{fhandle,bpf_fs_kfuncs,dcache,file,fs_context,stat,namespace}.c`, `fs/mount.h`,
  `fs/fuse/{inode,acl,file,dir,ioctl,virtio_fs}.c`, `arch/{arm64,x86}/net/bpf_jit_comp.c`,
  `fs/overlayfs/{overlayfs.h,super.c,util.c}`, `fs/{ext4,btrfs}/acl.c`, `fs/xfs/xfs_acl.c`,
  `fs/ext4/ioctl.c`, `fs/crypto/policy.c`, `fs/verity/enable.c`, `fs/9p/vfs_inode.c`,
  `mm/mmap.c`, and `tools/testing/selftests/bpf/{progs,prog_tests}/lsm_cgroup.c` for a working
  attach.
- Microsoft's 6.18.54.1 (https://github.com/microsoft/WSL2-Linux-Kernel): `kernel/bpf/verifier.c`
  for the sleepable check.
- LLVM's BPF backend at `main` on 2026-10-20 (https://github.com/llvm/llvm-project),
  `llvm/lib/Target/BPF/BPFISelLowering.cpp`, for `LowerATOMIC_FENCE`.
- Loaders: libbpf 1.6.3, the machine's (https://github.com/libbpf/libbpf), or Aya 0.14.0, whose
  `LsmCgroup` is https://github.com/aya-rs/aya/pull/1135. Aya's resolution of a typeless ksym
  through `/proc/kallsyms` (https://github.com/aya-rs/aya/pull/1372) is in no release as of
  2026-10-19; the policy program reads no kernel symbol since the per-dentry `d_seq` replaced
  `rename_lock` ("What is gained and what is lost"), which the Phase 1 and 2 probes resolved as
  a typeless `__ksym` extern through `/proc/kallsyms`, as libbpf does at load. By the user's
  decision of 2026-10-26 the controller stays C over libbpf until the classifier is ported to
  Rust ("Later versions"), a scheduling choice: a Rust controller needs no CO-RE from `rustc`,
  which only the program needs. Aya is the port's candidate, under the relocation suite that
  section names.
- Prior art for container-scoped BPF policy, none of which carries this policy: KubeArmor
  (https://github.com/kubearmor/KubeArmor), BPFContain
  (https://github.com/willfindlay/bpfcontain-rs), Aegis-BPF (https://github.com/ErenAri/Aegis-BPF).
- Git at `master` on 2026-10-20 (https://github.com/git/git), `compat/fsmonitor/fsm-ipc-unix.c`,
  for where `fsmonitor--daemon` binds its socket.
- OCI runtime lifecycle and hook ordering:
  https://github.com/opencontainers/runtime-spec/blob/main/runtime.md,
  https://github.com/opencontainers/runtime-spec/blob/main/config.md.
