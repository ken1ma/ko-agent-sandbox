# Plan: a BPF cgroup-LSM backend for `--workspace=live`

The workspace filter costs 6–18× on metadata operations over an unfiltered bind mount on macOS and
5–30× on Windows (`../fuse/ko-agent-fs/doc/verification-log.md`, "The cost of a path walk"), and
sessions through it have frozen the podman machine. This plan replaces the filter on every platform
with a direct bind of the workspace and a policy the kernel running the containers enforces: BPF
programs of type `BPF_LSM_CGROUP`, attached to the sandbox's own cgroup, so the host and every
other container keep unfiltered access to the same files.

On macOS and Windows that kernel is the podman machine's; on native Linux it is the host's, within
the supported set "Native Linux" states.

Status: the environment prerequisites and the cgroup placement are measured on both machines
("Environment evidence"), and Phase 0 is done ("Inventory"); no BPF program has been loaded,
attached or shown to deny anything. The filter stays the default until "Acceptance" passes, and
no launch ever binds the workspace writable without the policy attached and verified.

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
  `readonly-path` lines for relocated hooks and symlink aliases (`file-rules.md`).
- The policy is effective for the sandbox's cgroup before any program of the image runs in the
  container: entrypoint, `podman exec` processes and OCI hooks that run in the container's
  namespaces. The container runtime's own processes are trusted, as the filter daemon is.
- The threat is a process inside the sandbox. A VM administrator, a compromised podman or runtime,
  and whoever runs the controller are trusted; pinned links do not resist them.
- On Windows the policy is what the WSL kernel enforces on container processes. It changes nothing
  about WSL as a boundary toward the Windows host
  (https://wsl.dev/technical-documentation/security/).

What else the backend changes, each way, is "What is gained and what is lost".


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
- A BPF policy program is less auditable than Rust. The classifier is a `no_std` Rust port of
  `policy.rs` compiled twice, into the program and into a host test binary, so its unit tests
  run on the host; the inode table, resolver and FUSE layer do not exist.
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

Read in Linux v7.1 (https://github.com/torvalds/linux/tree/v7.1). The podman machine on macOS
runs Fedora's `7.1.8-200.fc44.aarch64`; the WSL kernel is Microsoft's `6.18.54.1`, where each
fact below is to be re-read before Phase 2 relies on it.

- `include/linux/bpf-cgroup-defs.h`: `CGROUP_LSM_NUM` is 10. `kernel/bpf/cgroup.c`,
  `bpf_cgroup_atype_find`, gives one slot per distinct hook, refcounted across every cgroup that
  attaches it, and `-E2BIG` for an eleventh hook. Ten hooks serve any number of sandboxes. The
  pool is shared by everything in the VM, so the controller reads it before attaching rather
  than assuming it free.
- `cgroup.c`, `bpf_prog_run_array_cg`: a program's nonzero return grants, zero becomes `-EPERM`.
  A program on a void hook must return 1 (`kernel/bpf/verifier.c`, `return_retval_range`). The
  `lsm/` convention of returning a negative errno does not apply.
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
- Sleepable programs: `verifier.c`, `bpf_check_attach_target`, admits a sleepable LSM program by
  its hook alone; no check against `BPF_LSM_CGROUP` was found, and `trampoline.c` enters such a
  program under `rcu_read_lock`. The design needs no sleepable program: `fs/bpf_fs_kfuncs.c`
  tags `bpf_path_d_path` without `KF_SLEEPABLE`, and the policy below does not call it.
- The hooks below are outside every `#ifdef` of `include/linux/lsm_hook_defs.h`, so they need no
  `CONFIG_SECURITY_PATH`; both kernels' BTF lists them ("Inventory").

### The hooks

Eight hooks take eight of the ten slots `CGROUP_LSM_NUM` gives, and hold the writes and the names of
everything but directories at the VFS, whatever the backing. The name hooks are the `inode_*` hooks,
not the `path_*` hooks the syscalls call first, because overlayfs, which a session can mount where
"Mounts" allows it, changes its upper layer through the `inode_*` hooks alone ("Inventory", row 20);
each hook judges row 20's changes of its kind as well. Slots 9 and 10 stay free for what "Decisions
still open" may give them.

| slot | hook            | decides                                                   | rows      |
| ---- | --------------- | --------------------------------------------------------- | --------- |
| 1    | `inode_create`  | a new file's name and parent: `creat`, `O_CREAT`, `mknod` | 1         |
| 2    | `inode_mknod`   | a new FIFO's, socket's or device's name and parent        | 2         |
| 3    | `inode_symlink` | a new symlink's name, parent and target syntax            | 4         |
| 4    | `inode_link`    | the source object and the new name                        | 5         |
| 5    | `inode_rename`  | both names and parents, each way for `RENAME_EXCHANGE`    | 6, 7      |
| 6    | `inode_unlink`  | removal of a protected entry                              | 8         |
| 7    | `file_open`     | an open for writing of a protected object                 | 10–13, 19 |
| 8    | `inode_setattr` | `chmod`, `chown`, times, `truncate`, `O_TRUNC`            | 11, 14    |

`inode_create` judges a `mknod` of a regular file; the other types reach `inode_mknod`
(`fs/namei.c`, `filename_mknodat`).

### Directories

The plan judges neither `mkdir` nor `rmdir` (rows 3 and 9): a session creates and removes
directories at any name, `.git` and `.ko-agent-sandbox` included. Every non-directory put into a
new directory is still judged at the position it lands at, by `inode_create`, `inode_mknod`,
`inode_symlink`, `inode_link` or `inode_rename`. A directory filled elsewhere cannot take a guarded
name, since `inode_rename` refuses a rename onto one (`authorize_create`).

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
- **A `readonly` line keeps applying below a `.git` entry.** `policy.rs` lets no line apply in git
  state (`file-rules.md`), so without the rule a `.git` made under `readonly locked` would make
  `locked/.git/objects/payload` writable. Cost: a host repository below a `readonly` line is
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
    (`classify_within_gitdir`); or a `readonly` directory whose non-directories later `writable`
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
- Filesystem ioctls, row 18: `file_ioctl` and `file_ioctl_compat`. The commands read in v7.1 take
  a read-only descriptor and set a file's generation, set an empty directory's encryption policy,
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
    32-bit forms included.
- Under `NESTING=same-uid`, whether a nested podman's storage needs the xattr syscalls,
  `file_setattr` or the refused ioctl commands is a Phase 2 measurement. The rule cannot refuse a
  family the nested podman needs; the two free slots can hold two of its hooks, and which routes
  stay open on such sessions is a user decision in "Decisions still open", with each route's
  consequence stated there. Phase 2's gate stays unmet for that mode until it is taken.

What the seccomp rule reaches and what it misses:

- Every xattr, ACL and flag change a process requests enters through those syscalls;
  `io_uring_setup` already answers `ENOSYS` in a session ("Inventory", row 22).
- Row 18 is a list of commands, not a syscall family: the rule refuses the commands the row lists.
  xfs's and btrfs's are listed before Phase 2's gate, and a kernel change reopens the row
  ("Environment evidence").
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
  `--preserve-fds`.

### Mounts

Under `NESTING=none`, the launcher's seccomp profile refuses creating a user namespace and every
mount syscall (`TODO.md`, "Refuse user namespaces and mounts under `NESTING=none`"). That item
ships before this backend, and the backend does not ship without it.

- It removes row 20's overlay mount, whose `user.overlay.*` writes no taken slot holds, and row
  21's bind of the workspace at a second path: without a user namespace the session holds no
  capability to mount with.
- The profile has neither rule under `NESTING=same-uid`, where a nested podman creates user
  namespaces and mounts, nor on a `NESTING=none` session launched with the profile's loosening
  option. On both, the hooks judge rows 20 and 21 ("The policy"), and overlayfs's
  `user.overlay.*` names are the decision "Decisions still open" holds for them.


## The policy

The program classifies by object and position, never by a path string:

- The sandbox's policy names its workspace root as `(superblock, inode)`, recorded by the
  controller from the VM's own `stat` of the bind source. The program walks `d_parent` from the
  target dentry, bounded, folding each name as `policy.rs` folds (`git-metadata.md`, "The name
  rule"), until it meets the root or the filesystem root. Outside the root, everything is allowed.
- A string from `bpf_path_d_path` is not an identity: where "Mounts" allows them, unprivileged user
  namespaces work inside a session, so a task can bind the workspace at a second path
  in a mount namespace of its own.
- Inside the root, the walk's names give the position the filter's classifier uses: a `.git`
  component, the entries under it, `modules/<name>` and `worktrees/<name>`, `.ko-agent-sandbox`,
  and a file-rule line. The sandbox's policy also names the proof fixture's root as a second
  root ("Lifecycle"), judged by the same rules.
  - The line set is the launcher's resolved rules, the same text the filter receives, which the
    unprivileged guard (`ko-agent-fs --resolve`) folds and compiles into fixed-size map records
    before attach. The controller loads those records and parses no text from the workspace.
- The gitdir allowlist (`git-metadata.md`, "The classifier") is the policy here too. The filter
  finds a nested gitdir's root by the `HEAD` it holds, a lookup a program cannot make, so the
  controller records the roots under `modules/` at launch; a namespace without a recorded root
  stays wholly protected, the filter's own strict default, and the sandbox cannot add a root
  since the `.git` pointer its worktree needs is refused.
- "Directories" adds three rules to the classifier: no new `HEAD` in a `.git`, a `readonly` line
  applying below a `.git`, and a `.ko-agent-sandbox` protected in git state too.
- A second name of a guarded entry, a hard link to a `.git` pointer file or an NTFS short name,
  is the same object, which the filter recognizes by comparing every ordinary entry with its
  guarded siblings on each lookup (`fs.rs`, `policy_name`), a lookup a program cannot make.
  Here two rules replace it:
  - the controller records the identity of the workspace root's `.git` and `.ko-agent-sandbox`
    and of every gitdir the guard resolves, so any name of those objects is judged as the
    object;
  - on Windows, a mutation whose ancestry holds a component of NTFS's generated short-name form,
    uppercase, a tilde and a digit within the 8.3 lengths, is denied whatever the component is,
    which covers a `.git` the host creates mid-session. Cost: no session write through a name of
    that form on Windows, a form no project is known to use. The exact form is a Phase 3 row.
  - What neither covers: a hard link the host makes to a guarded file below the root, or after
    launch, is ordinary data to the walk, and a rewrite of a nested `.git` pointer file through
    it is within the property. The session cannot make such a link, since `inode_link` refuses a
    guarded source. Covering the launch-time half needs a scan of the whole tree at launch; the
    mid-session half has no cover a program can give. It is a pending user decision ("Decisions
    still open"), and Phase 3's row for it cannot pass without that decision.
- A mount inside the workspace, a filesystem the host mounted at `<workspace>/vendor`, has dentries
  whose `d_parent` chain ends at that filesystem's root, never at the workspace root, so a walk
  by dentry alone would allow everything in it. The filter crosses such mounts and classifies
  their contents (`fs.rs`, `open_ino`, no `RESOLVE_NO_XDEV`). Here:
  - the bind is recursive, so the sandbox sees them: `--mount type=bind` binds recursively by
    default, while `--volume` does not and needs `rbind`
    (https://docs.podman.io/en/latest/markdown/podman-run.1.html);
  - the controller lists the mounts under the bind source at launch and records, per nested
    superblock, the classification context of its mountpoint; every hook identifies a nested
    subtree by the superblock of the object it judges and resumes the walk from that context.
    No hook follows a mount: a superblock and its dentries are the same objects through every
    mount of them, so a bind the session makes in a mount namespace of its own, of the
    workspace or of a nested filesystem, at any other path, gets the same answer, and a mount
    the host adds mid-session does not propagate into the container under podman's default
    `rprivate`;
  - a nested superblock also mounted elsewhere in the container at launch refuses the launch,
    since its dentries would have two positions;
  - whether the macOS and Windows shares present a host-side mount as one tree or as a nested
    superblock is a Phase 2 row.
- Per-sandbox state is a map keyed by the cgroup id of the attach target, which the program reads
  with `bpf_get_current_ancestor_cgroup_id` at the slice's fixed depth, or cgroup-local storage;
  `kernel/bpf/helpers.c` defines both, and whether an `lsm_cgroup` program may call them is a
  Phase 1 check. The programs are loaded once and the links are per sandbox.
- An error in the walk, a name too long for the bound, or a missing map entry denies.


## Lifecycle

The programs enforce; the controller only loads them. It is an ordinary process making the
`bpf` syscalls that need `CAP_BPF` with `CAP_PERFMON`, or `CAP_SYS_ADMIN`, beside the kernel
that enforces: in a podman machine the launcher runs it for the launch through
`podman machine ssh` under the machine's `sudo`, and it exits once the links are pinned; on
native Linux it is the root-installed unit "Native Linux" describes. The session never has
those privileges, and the controller never reads the workspace: its input is the launcher's
fixed-size records, made by the unprivileged guard ("The policy"), and its output is links and
maps.

`--build` installs the BPF object and the controller into the machine, as it installs the
filter. The controller then runs at every launch, restart and recreate, since each attaches to a
new cgroup and only a privileged caller can: one `sudo -n` per launch in the machine, the unit's
work on native Linux. The programs themselves load once per machine boot: pinned programs
outlive the controller and later launches reuse them, and a pin in `bpffs` does not survive a
machine restart.
For each session:

1. Create the attach cgroup before any container process exists, and keep it alive. Two shapes,
   one to be proven in Phase 1:
   - a transient systemd slice held by a VM-side unit, under which `podman create
     --cgroup-parent=<slice>` places the container. systemd removes a transient slice once
     nothing is in it, at a moment Phase 1 measures, and a link whose cgroup is removed is
     detached without an error (`cgroup.c`, `bpf_cgroup_link_release`, "auto-detached by dying
     cgroup"), so the hold unit is not optional;
   - the container's own scope: `podman create`, attach to the scope, then `podman start`. Simpler
     if, between create and start, the scope exists and runs no image code. Unverified.
2. Load the programs if not loaded, fill the sandbox's map entries, attach every program by link,
   pin the links where the session cannot reach, and read them back.
3. Prove the enforcement without trusting step 2's report, in two parts, both before any
   container exists.
   - A read-back by a separate program, with the controller's privileges and none of its code:
     for each hook of the session's set, the eight of "The hooks" and those a decision in
     "Decisions still open" adds, `BPF_PROG_QUERY` on the attach cgroup with `BPF_LSM_CGROUP`
     lists the attached programs by id, as the kernel's own test does
     (`prog_tests/lsm_cgroup.c`, `query_prog_cnt`).
     - For each program, `BPF_OBJ_GET_INFO_BY_FD` gives its tag and its `map_ids`
       (`kernel/bpf/syscall.c`, `bpf_prog_get_info_by_fd`): the tag must equal the installed
       object's, the map ids must be exactly the ids of the sandbox's pinned maps, and those
       maps' contents, read by id, must equal the records the guard produced.
     - The tag alone proves nothing about the maps: the kernel zeroes map references before
       computing it (`kernel/bpf/core.c`, `bpf_prog_calc_tag`).
   - A fixture the kernel judges, under the launcher's state directory in the VM, so a missing
     hook costs nothing in the workspace.
     - The guard writes a tree laid out as a workspace, with a `.git` holding `config` and a
       hook, a `.ko-agent-sandbox`, and one entry per resolved rule line, and the sandbox's
       policy records that tree's root as a second root.
     - The launcher places a process of its own in the attach cgroup and runs one refused
       operation per hook of that set against the fixture: `creat`, `mkfifo`, `symlink`, `link`
       and `rename` to a guarded name, an `unlink` of a guarded entry, an open for writing and a
       `chmod` of a guarded file, and one operation per hook a decision adds; then one write per
       rule-line entry and one write to an ordinary entry.
     - Each write's expected answer is derived from the whole ordered rule set, as the filter
       decides it (`file-rules.md`, "The rule file"): refused under a `readonly` line, allowed
       under a `writable` line such as the defaults' `writable node_modules`, and the later
       line's answer where lines overlap; the fixture holds an overlapping pair on purpose.
       Every answer must be the expected one.
   A difference in either part ends the launch. Together they catch a controller that attached
   nothing, attached a subset, attached another build, loaded the wrong records, or whose
   program uses another map; what they do not catch is a defect the program shares with the
   fixture's expectations, which Phase 3's corpus is for.
4. Create and start the container. With the slice shape the container's scope lands below the
   proven cgroup; with the scope shape, steps 2 and 3 run between `podman create` and
   `podman start`.
5. A restart or recreate repeats 1–4; a stop of the container does not detach. `podman exec`
   joins the container's cgroup and needs nothing.
6. On teardown, end every task under the cgroup, then detach and remove the cgroup.

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

macOS, the default podman machine:

| item          | observed                                                                       |
| ------------- | ------------------------------------------------------------------------------ |
| machine       | Fedora CoreOS 44.20260817.3.1, aarch64, kernel 7.1.8-200.fc44                  |
| LSMs          | `lockdown,capability,yama,selinux,bpf,landlock,ipe,ima,evm`                    |
| BPF           | BTF readable; bpffs at `/sys/fs/bpf`, mode 700; `libbpf` 1.6.3; no compiler   |
| podman        | rootless, `cgroupManager=systemd`, cgroup v2, crun 1.29.1; `sudo -n` works     |

Windows, an EC2 Server instance, build 10.0.26100.32522:

| item          | observed                                                                       |
| ------------- | ------------------------------------------------------------------------------ |
| WSL           | 3.0.3.0 pre-release (`wsl --update --pre-release`), kernel 6.18.54.1           |
| LSMs          | `capability,landlock,yama,safesetid,selinux,bpf,ima`, `securityfs` mounted first |
| BPF           | BTF readable; `sudo -n` works; loading and pinning untested                    |
| podman        | 6.1.0, rootless, systemd, cgroup v2, provider `wsl`                            |

WSL 3.0.1.0 ran kernel 6.18.40.1, whose published `CONFIG_LSM` lacks `bpf`; the pre-release was
installed for its kernel.

The placement, the same on both machines: after `systemd-run --user --unit=ko-agent-probe-hold
--slice=ko-agent-probe.slice /usr/bin/sleep 180`, the cgroup of a container run with
`--cgroup-parent=ko-agent-probe.slice` was, with uid 501 on macOS and 1000 on Windows,

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

Build the BPF objects and the controller in a builder container with clang and libbpf, outside
the machine; the machine keeps its images and installs no toolchain.


## Inventory

The policy transcribes `fuse/ko-agent-fs` at commit `0fe166a159c1f3cc75dd966a8b0e2d4faae5aa31`,
the last to change `src/{policy,fs,guard,rulefile}.rs`. A later change to those files reopens the
rows it touches. Phase 2 fills the macOS and WSL columns with the answer under the attached
programs.

| #  | syscalls                  | filter            | hooks v7.1 calls             | macOS | WSL |
| -- | ------------------------- | ----------------- | ---------------------------- | ----- | --- |
| 1  | open* O_CREAT, creat      | name              | path_mknod, inode_create     |       |     |
| 2  | mknod*, Unix socket bind  | name              | path_mknod, inode_mknod      |       |     |
| 3  | mkdir*                    | name              | path_mkdir, inode_mkdir      |       |     |
| 4  | symlink*                  | name, syntax      | path_symlink, inode_symlink  |       |     |
| 5  | link*                     | entry, name, move | path_link, inode_link        |       |     |
| 6  | rename*, RENAME_WHITEOUT  | entry, name, move | path_rename, inode_rename    |       |     |
| 7  | renameat2 RENAME_EXCHANGE | row 6 both ways   | path_rename, inode_rename ×2 |       |     |
| 8  | unlink*                   | entry             | path_unlink, inode_unlink    |       |     |
| 9  | rmdir, AT_REMOVEDIR       | entry             | path_rmdir, inode_rmdir      |       |     |
| 10 | open* O_WRONLY, O_RDWR    | entry             | file_open                    |       |     |
| 11 | open* O_TRUNC, any mode   | entry             | file_open, inode_setattr     |       |     |
| 12 | write*, splice, mmap, …   | row 10's open     | row 10's open                |       |     |
| 13 | fallocate, FICLONE*       | none              | row 10's open                |       |     |
| 14 | chmod*, chown*, truncate  | entry             | inode_setattr                |       |     |
| 15 | setxattr*, removexattr*   | none              | inode_setxattr, …removexattr |       |     |
| 16 | row 15 on ACL names       | none              | inode_set_acl, …remove_acl   |       |     |
| 17 | file_setattr, 2 ioctls    | none              | inode_file_setattr           |       |     |
| 18 | other ioctl commands      | none              | file_ioctl, …_compat         |       |     |
| 19 | open* O_TMPFILE           | none              | file_open                    |       |     |
| 20 | overlayfs upper layer     | not measured      | inode_*, file_open           |       |     |
| 21 | a second path             | as by the first   | as by the first              |       |     |
| 22 | io_uring_*                | not reached       | not reached                  |       |     |

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
  "Attributes, flags and ioctls" names refuses those listed here. The ones read in v7.1 take a
  read-only descriptor:
  - ext4's `EXT4_IOC_SETVERSION` and `EXT4_IOC_SETVERSION_OLD`, refused under `metadata_csum`,
    set the generation and ctime directly; `ext4_compat_ioctl` maps `EXT4_IOC32_SETVERSION` and
    `EXT4_IOC32_SETVERSION_OLD` to them. They, `EXT4_IOC_MIGRATE` and `EXT4_IOC_ALLOC_DA_BLKS`
    check the owner (`fs/ext4/ioctl.c`).
  - `FS_IOC_SET_ENCRYPTION_POLICY` sets a policy on an empty directory the caller owns
    (`fscrypt_ioctl_set_policy`).
  - `FS_IOC_ENABLE_VERITY` makes a file permanently read-only, checking write permission through
    `inode_permission` (`fsverity_ioctl_enable`).
  - xfs's and btrfs's commands are not read. FUSE answers a server's `ENOSYS` with `ENOTTY`
    (`fs/fuse/ioctl.c`).
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
    with `d_type`, `RENAME_WHITEOUT` and xattrs (`fs/overlayfs/super.c`). By that reading the
    filter, which implements no xattrs, cannot be one; whether each share can, Phase 2 measures.
- Row 21: a bind mount in a mount namespace of the session's own, which "Mounts" refuses where it
  refuses row 20's, or `open_by_handle_at`. The hooks judge dentries ("The policy"). Without
  `CAP_DAC_READ_SEARCH` in the initial user namespace, `open_by_handle_at` decodes directories only
  (`fs/fhandle.c`, `may_decode_fh`).
- Row 22: `io_uring_setup` answers `ENOSYS` in a session.

The source read is Linux v7.1. Upstream v6.18 makes the same calls for rows 1, 11 and 17, has
row 20's check of an upper layer, and its `bpf_lsm_disabled_hooks` lacks only
`file_alloc_security`; Microsoft's `6.18.54.1` is not read.

Both kernels' BTF lists every hook named in the table. The macOS kernel's is read from a session
on 2026-10-15 with `grep -aoE 'bpf_lsm_[a-z0-9_]+' /sys/kernel/btf/vmlinux`; the WSL kernel's
through `podman machine ssh` on 2026-10-16, with a `grep -aoE` for the table's 24 names.


## Phases

Each phase ends at its gate; a failed gate leaves the launcher as it is.

0. **Inventory.** Pin the repository commit the policy transcribes. Produce one table: operation,
   its syscalls, the filter's behavior, the hook above, the measured result on each kernel. Read
   both kernels' BTF. Confirm the rmdir reading against `policy.rs`. Done in "Inventory",
   whose measured results Phase 2 fills.
1. **One hook, one denial.** A `lsm_cgroup/file_open` program denying the open for writing of
   one marker name, the controller attaching it to a disposable cgroup of each shape in
   "Lifecycle", then a disposable container under it: the marker is refused, other files are
   not, a sibling container outside the cgroup opens the marker, a second attached cgroup shares
   the slot, and a deliberately failed attach starts no container. On macOS first, then WSL.
   Gate: inheritance, denial, isolation and fail-closed start, both kernels.
2. **Every hook.** The candidate programs on a disposable tree of the real share, exercising
   each syscall of the inventory, `openat2`, descriptor-relative calls, `RENAME_EXCHANGE`,
   `setfacl`, `setxattr`, `chattr` and row 18's commands, an overlay mount whose upper layer is
   in the tree, a host-side mount inside the tree, and ordinary git. Record the verifier's
   answer per hook per kernel, which attribute routes and ioctl commands each share accepts, and
   the cost of the bounded ancestry walk at the real tree's depths on both kernels, so the
   policy's price is known before the classifier and the lifecycle are built.
   Also read xfs's and btrfs's ioctl commands into row 18; measure whether a nested podman under
   `NESTING=same-uid` needs the xattr syscalls, `file_setattr` or the refused ioctl commands
   while it pulls and extracts an image, creates, runs and execs into a container, and removes
   both, and whether each share stores a `security.capability` set and removed from a user
   namespace the session creates, before the decisions on open routes are put.
   Gate: the inventory's macOS and WSL columns are complete; every route, row 20's `user.overlay.*`
   names included, is held by its slot or by the seccomp rules "Attributes, flags and ioctls" and
   "Mounts" name, or covered by a decision taken for it, such as "Directories"; and the walk's cost
   is recorded beside the unfiltered bind's.
3. **The policy.** The classifier in the programs, the map compiler in the guard, and the
   filter's test corpus run against the bind: the name-rule corpus, the pointer rewrite, the
   second-name cases, hooks, config, alternates, operational writability, the blocked git
   commands, symlink escape and the rename races (`git-metadata.md`, "Test list"); a host hard
   link to the root's `.git` pointer file and to `.ko-agent-sandbox`
   (`tests/mounted_mutate.rs`, `a_second_name_of_a_guarded_entry_is_guarded_like_it`); the NTFS
   short-name form on a real NTFS volume; a nested mount holding a `.git`; a linked git worktree,
   whose main gitdir the launcher binds read-only (`TODO.md`, "Deferred — writable git from a
   linked worktree").
   Also: under `NESTING=same-uid` and on a `NESTING=none` session with the profile loosened, the
   session binds the workspace and a nested filesystem at other paths in a mount namespace of its
   own and mutates through the aliases, and through an overlay mount; under `NESTING=none`
   otherwise, `unshare -Ur` and each mount syscall are refused; a host hard link to a nested `.git`
   pointer file, made before and after launch; a `HEAD` by each creating syscall in a `.git` the
   session makes in `sub/` and in `.git/objects/x/`, and by a rename or `RENAME_EXCHANGE` over a
   directory placeholder; an exchange of a filled directory with a session-made `.git`; host `git`
   in `sub/` under a global relative `core.hooksPath`; writes below a `.git` made under a `readonly`
   line; a file in `.git/objects/x/.ko-agent-sandbox`. Gate: each row ENFORCED, or an existing
   filter residual, or covered by a decision the user has taken, "Directories" or one in "Decisions
   still open". A listed loss passes nothing.
4. **Lifecycle.** The ordering of "Lifecycle" on rootless podman: first-process denial, restart,
   recreate, `podman exec`, stop and kill, controller exit, machine restart, link loss; and the
   proof's catches, a controller that attaches a subset of the hooks, one that attaches another
   build's program, one that loads wrong records, and one whose program uses a map other than
   the pinned one, each of which must end the launch.
   Gate: no container process runs before the policy, on either machine, and each of the four
   defective controllers is caught.
5. **Measurement.** `probe/perf-probe.py` and the real-tree rows of `verification-log.md` on the
   bind with the policy, beside the filter and the unfiltered bind; the machine's CPU and memory
   during the stat storm under each.
   Gate: the numbers are recorded; the default changes only by a release decision.
6. **Integration.** A backend selector with a capability probe, `--workspace=read-only` and the
   printed host requirements where the probe fails, the launch line naming the backend and the
   accepted differences, the removal of the filter, and the documentation changes "The recorded
   decisions this answers" names. It needs the profile "Mounts" relies on to have shipped.


## What is gained and what is lost

The git property, the file rules and the blocked git commands are in neither list: the hooks
hold them as the filter does. The name rule is held too, except for directories, which "Lost"
lists. The lists are what else changes.

Gained:

- **The filter's whole cost.** The ceiling is measured
  (`../fuse/ko-agent-fs/doc/verification-log.md`, "The cost of a path walk"):

  | workload                              | through the filter | unfiltered bind |
  | ------------------------------------- | ------------------ | --------------- |
  | `ls -lR`, per entry                   | 12.7 ms            | 0.7 ms          |
  | `git status`, 4,200 files at depth 7  | 72 s               | not measured    |
  | `sbt` build of this repository        | 604 s              | 43 s            |

  The policy's own cost over the unfiltered bind is Phase 5's number. It runs on mutations and
  opens, never on `lookup` or `getattr`, the operations that dominate those columns.
- **The daemon's share of the machine's hangs.** `git status` in a worktree of hundreds of
  files has frozen the podman machine for over an hour, with memory not short and
  `podman machine ssh` failing throughout. The daemon and its requests go with the filter.
  - What the bind keeps is the share server's one worker thread per share, which one blocked
    request stalls for every later one (`upstream-issues.md`, "Setting a FIFO's times blocks
    the macOS virtio-fs server").
  - The refusal of `mknod` of a FIFO that `TODO.md` ("A FIFO in the workspace hangs the podman
    machine") considers for the filter is an `inode_mknod` rule here.
- **No window between resolving and acting.** The decision is taken inside the syscall, on the
  dentry the kernel acts on, which the filter's resolver and its `ESTALE` rules exist to
  approximate. A held directory handle follows a directory the host moved and is judged by its
  current position. The walk reads `d_parent` without the rename lock, so a concurrent rename
  can be seen mid-move; Phase 3's rename races measure what that passes.
- **Data coherency is the share's own.** The filter's two residual cache cases
  (`../fuse/ko-agent-fs/doc/architecture.md`, "Coherency") have no layer to occur in.
- **No daemon.** No `ENOTCONN` failure domain shared by a workspace's sessions, no serialized
  round trips, no inode table.

Lost, stated as what becomes possible that the filter does not allow:

- **A privileged controller in the path.** The enforcement is the verified program in the
  kernel; the controller that installs it runs with the `bpf` syscall's privileges, as root in
  the machine for the launch, or as the host's root unit ("Native Linux"), where the filter
  daemon runs as an ordinary user throughout.
  - It parses no text from the workspace: the unprivileged guard folds and compiles the rules into
    fixed-size records ("The policy"), and the controller installs them and attaches links.
  - What becomes possible is a defect in that installing, reached only through the launcher,
    since the sandbox has no path to the controller and the host unit's socket is not bound
    into the container.
- **A mistake in the kernel-facing glue, which no host test reaches.** The classifier itself is
  unit-tested on the host, a `no_std` crate compiled into the program and into a test binary,
  as `policy.rs` is tested, and the folding, parsing and map compilation stay in the guard's
  Rust and reuse `policy.rs`.
  - What the host cannot run is the glue around it, the `d_parent` walk, its CO-RE reads and
    its bounds: an LSM program has no `BPF_PROG_TEST_RUN` (`kernel/bpf/bpf_lsm.c`,
    `lsm_prog_ops` is empty).
  - A wrong bound or read there passes a write to a protected entry until Phase 3's corpus, run
    through real syscalls against the attached program, catches it.
- **No writable session on a kernel without the LSM.** The probe fails, the launch binds nothing
  writable and says what the host lacks. A lost session, never a weaker one.
- **No session write through an NTFS short name on Windows.** Refused by form ("The policy"), a
  form no project is known to use. No protection is weakened.
- **A directory at any name, `.git` and `.ko-agent-sandbox` included.** The session can create
  and remove empty directories at a guarded name or position, which the filter refuses.
  "Directories" has the rules that keep this from weakening any protection.
- **Under `NESTING=none`, nothing in the container sets xattrs (`setfattr`), ACLs (`setfacl`) or
  `chattr` flags, or runs row 18's ioctl commands.** The seccomp rule ("Attributes, flags and
  ioctls") refuses them under `~` too, where the filter refuses them in the workspace alone, and
  `cp -a` drops xattrs and ACLs there. No protection is weakened.

Decisions still open, each the user's, taken after Phase 2's table:

- **Cgroup shape.** Slice with a hold unit, or the container's scope between create and start;
  Phase 1 measures both.
- **Native Linux, SELinux enforcing: relabel or `label=disable`.** "Native Linux" states both;
  the relabel is the plan's default, and `label=disable` a per-host choice.
- **The routes under `NESTING=same-uid` whose syscalls a nested podman needs.** The seccomp
  rule cannot refuse those syscalls, and the two free slots ("The hooks") can hold two of their
  hooks. Which two, and so which routes stay open on such sessions, is this decision.
  - A `NESTING=none` session attaches eight hooks and such a session ten, so both fit the
    machine's ten slots at once, unless something else in the VM holds one ("The mechanism").
  Each route's consequence, read in v7.1:
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
  ("Mounts").** No taken slot holds `inode_setxattr`, and the seccomp rule does not see
  overlayfs's own writes ("Attributes, flags and ioctls"). Pending, between:
  - accepting them: a `user.` xattr on a protected directory, which no host program here reads;
  - `inode_setxattr` in a free slot on such sessions, which holds row 15 there too and leaves one
    free slot to the decision above.
- **A hard link the host makes to a nested `.git` pointer file or `.ko-agent-sandbox` entry,
  below the root or after launch.** The filter catches it by comparing siblings on every lookup;
  the program catches only objects recorded at launch ("The policy"). Pending, between:
  - extending the residual `git-metadata.md` records for host-made hard links to protected
    inodes to these entries;
  - a scan of the whole tree at launch, which covers the launch-time half at the cost of a walk
    of the tree per launch, accepting the mid-session half.
- **Denylist inside a gitdir.** Only if Phase 3 finds the allowlist too large for the program:
  a denylist of the executable state (`config*`, `hooks`, `commondir`, `gitdir`,
  `objects/info`, the rebase, sequencer, bisect and `rr-cache` state) is smaller and fails open
  on a future git file that executes. Not recommended before that finding.


## Native Linux

A native Linux host runs the backend on its own kernel, without a podman machine, within a
supported set the launcher states rather than discovers. A host outside it gets
`--workspace=read-only` and a message naming the missing requirement; a podman machine is never
created for it. The requirements, each checked at launch:

- **`bpf` in the active LSM list**, read from `/sys/kernel/security/lsm`. Fedora CoreOS's
  kernel activates it (the machine's list above). Where a kernel does not, the message names the
  boot parameter, `lsm=` with `bpf` appended, and the reboot; which distributions ship it
  inactive is not something this plan records, since the probe answers per host.
- **The root-installed controller**, a systemd system unit running the controller as root and
  reached over a socket the launcher's user may write.
  - The host is never prompted for sudo (`../SECURITY.md`, "Silent changes to what you own"), so
    the launcher prints the unit and its install command, as `--build` prints the `fuse.conf`
    change for a machine.
  - Loading an LSM program needs `CAP_BPF` with `CAP_PERFMON`, or `CAP_SYS_ADMIN`
    (`kernel/bpf/syscall.c`, `is_perfmon_prog_type`). A BPF token on a delegated `bpffs`
    satisfies those two checks for an unprivileged process (`bpf_prog_load`,
    `bpf_token_capable`); whether the attach also works unprivileged is unverified, so the unit is
    what the plan builds and the token a later reduction.
- **Under SELinux enforcing, a label the container may use.** The launcher's default is a
  persistent file-context rule and a relabel of the workspace to a shared container type
  at level `s0`.
  - The commands are `semanage fcontext`, then `restorecon`, both printed for the user; the first
    is what keeps a later `restorecon` from undoing the second.
  - Confined host services then lose access to that tree, and `../SECURITY.md`'s "labels never
    changed" gains this consented exception.
  - The alternative, `label=disable` for the sandbox container, runs it outside SELinux
    confinement, which the launcher already does for nested containers (`../SECURITY.md`, "No
    containers inside the sandbox by default"); it costs no relabel and removes a layer around
    the container.
- **Rootless podman with the systemd cgroup manager**, as on the machines.

Hosts without SELinux need the first two and the last.

Landlock would need no privilege and no kernel option, and is active on both machines' kernels,
but a Landlock rule's object is a file hierarchy named by an open descriptor
(https://man7.org/linux/man-pages/man7/landlock.7.html), so neither a `.git` file nor the
`config` of a new `.git` directory, before it exists, is an object it can refuse, at any depth.
It is not a backend for this policy.


## Acceptance

- Two sandboxes share the hook slots and differ in policy; a third container, the egress proxy
  and the machine's own processes are never judged.
- A `.git` or `.ko-agent-sandbox` by any folded spelling cannot appear by `creat`, `mknod`,
  `symlink`, `link`, `rename` or exchange, at any depth, directly or through an overlay mount the
  session makes; one that `mkdir` makes never gains a `HEAD`, a `readonly` line still covers what
  lies below it, and nothing but directories enters a `.ko-agent-sandbox` at any position.
- A protected entry cannot be opened for writing, truncated, re-attributed by `chmod`, `chown`,
  times, an xattr, an ACL or a `chattr` flag, changed by a filesystem ioctl, unlinked, removed
  unless it is an empty directory, renamed, exchanged, hard-linked out, or replaced, through any
  name, descriptor, mapping, nested mount or overlay mount, beyond what a decision taken in
  "Decisions still open" accepts.
- Under `NESTING=none`, unless the session loosens the profile, it creates no user namespace and
  no mount syscall succeeds.
- Git's everyday commands work; the commands the filter blocks stay blocked and listed.
- The file rules hold at any depth, with the resolved `readonly-path` lines.
- No container process runs before the policy, proven by the read-back of every attachment,
  program tag, program map id and map record and by the fixture suite in the attach cgroup,
  which a controller that attached nothing, a subset, another build, wrong records or another
  map cannot pass; the policy outlives the controller; the attach cgroup cannot be removed
  while the container's scope or any task is in it.


## Sources

- Linux v7.1: `include/linux/bpf-cgroup-defs.h`, `include/linux/lsm_hook_defs.h`,
  `kernel/bpf/{cgroup,bpf_lsm,trampoline,btf,verifier,helpers,core,syscall}.c`,
  `security/{security,commoncap}.c`,
  `fs/{namei,attr,open,xattr,posix_acl,file_attr,ioctl,read_write,splice,remap_range}.c`,
  `fs/{fhandle,bpf_fs_kfuncs}.c`, `fs/fuse/{inode,acl,file,dir,ioctl}.c`,
  `fs/overlayfs/{overlayfs.h,super.c,util.c}`, `fs/{ext4,btrfs}/acl.c`, `fs/xfs/xfs_acl.c`,
  `fs/ext4/ioctl.c`, `fs/crypto/policy.c`, `fs/verity/enable.c`, `mm/mmap.c`, and
  `tools/testing/selftests/bpf/{progs,prog_tests}/lsm_cgroup.c` for a working attach.
- Loaders: libbpf (https://github.com/libbpf/libbpf) or Aya's `lsm_cgroup` support
  (https://github.com/aya-rs/aya/pull/1135). Decide after Phase 1.
- Prior art for container-scoped BPF policy, none of which carries this policy: KubeArmor
  (https://github.com/kubearmor/KubeArmor), BPFContain
  (https://github.com/willfindlay/bpfcontain-rs), Aegis-BPF (https://github.com/ErenAri/Aegis-BPF).
- OCI runtime lifecycle and hook ordering:
  https://github.com/opencontainers/runtime-spec/blob/main/runtime.md,
  https://github.com/opencontainers/runtime-spec/blob/main/config.md.
