# The BPF backend's architecture

How the BPF cgroup-LSM backend holds what `../../../doc/bpf-lsm-cgroup.md` promises: the kernel
mechanism it rests on, the policy the program applies, the lifecycle that installs and proves it at
every launch, and the launcher code that drives it. What the suites measured of it is
`evidence.md`. The three documents use distinct section names, so a quoted section name without a
document names the one of them that holds it.

The code is `../../../src/main/scala/KoAgentBpf.scala`, the launcher's side ("The launcher's
side"), and this directory: the policy program `../policy.bpf.c`, the controller, the read-back
and the proof fixture, with the classifier's host build under `../test/host/`. The guard compiles
the policy's records (`../../../fuse/ko-agent-fs/src/bpf_records.rs`).


## The mechanism

Read in Linux 7.2.5 (`linux-7.2.tar.xz` with `patch-7.2.5.xz` from
https://cdn.kernel.org/pub/linux/kernel/v7.x/), which the podman machine on macOS runs as
Fedora's `7.2.5-200.fc44.aarch64`. The WSL kernel is Microsoft's `6.18.54.1`, whose source is read
for the sleepable bullet alone, the one difference found; the suites measure the rest on it.

- `include/linux/bpf-cgroup-defs.h`: `CGROUP_LSM_NUM` is 10. `kernel/bpf/cgroup.c`,
  `bpf_cgroup_atype_find`, gives one slot per distinct hook, refcounted across every cgroup that
  attaches it, and `-E2BIG` for an eleventh hook, which `__cgroup_bpf_attach` folds into the
  `EINVAL` the attach answers (measured, "One hook on macOS"). Ten hooks serve any number of
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

Eight hooks take eight of the ten slots `CGROUP_LSM_NUM` gives, a ninth under `unix-socket`, a value
of `--workspace` ("The launcher's side"; `file_receive` below), and hold the writes and the names of
everything but directories at the VFS, whatever the backing. The name hooks are the `inode_*` hooks,
not the `path_*` hooks the syscalls call first, because overlayfs, which a session can mount where
"Mounts" allows it, changes its upper layer through the `inode_*` hooks alone ("Inventory", row 20);
each hook judges row 20's changes of its kind as well. Slots 9 and 10 stay free for the routes
`../../../doc/TODO.md` plans as values of `--workspace` ("Attribute routes as `--workspace` values,
spending the free hook slots").

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

### Attributes, flags and ioctls

No taken slot holds rows 15–18. The filter refuses each under the whole workspace, since it does
not implement the operation ("Inventory", filter column `none`; for xattrs,
`../../../fuse/ko-agent-fs/doc/verification-log.md`, "Extended attributes"). The routes:

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
  - `file_setattr`.
  - Not `ioctl` by its command argument, in the first version. libseccomp refuses some commands of
    a syscall and allows the rest only with the allowed commands spelled out: an unconditional rule
    for a syscall clears the argument rules before it (`src/db.c`, `_db_rule_add`, v2.6.0: "the new
    filter has no chains so we need to clear the existing chains"), and the podman default's `ioctl`
    allow is such a rule; a rule holds one comparison per argument (`db_col_rule_add`, `-EINVAL` for
    a second), so the allowed commands are the binary prefixes of the low 32 bits holding no refused
    command, one `SCMP_CMP_MASKED_EQ` rule each, 255 for the 19 commands of rows 17 and 18 beside 19
    refusals, in a filter the kernel bounds at 4,096 instructions (`BPF_MAXINSNS`). The user's
    decision of 2026-10-26: not in the first version (`../../../doc/TODO.md`, "Attribute routes as
    `--workspace` values, spending the free hook slots", has what reopens it). On the machines rows
    17 and 18 are closed by the shares: virtiofs and 9p answer `FS_IOC_SETFLAGS`,
    `FS_IOC_FSSETXATTR` and the row 18 commands `ENOTTY` before any hook ("Every hook on macOS",
    "Every hook on WSL", `share`), with the 64-bit register's high bits ignored as the kernel reads
    `cmd` as `unsigned int`. Native Linux ("Native Linux"), whose filesystems implement them, needs
    `file_ioctl` and `file_ioctl_compat` as hooks, or the `--workspace` value `../../../doc/TODO.md`
    plans for them.
- Under `NESTING=same-uid`, a later version, the rule cannot refuse a family the nested podman
  needs ("Every hook on macOS", nested podman), and the free slots can hold two of its hooks: which
  routes stay open on such sessions is a user decision, with each route's consequence, in
  `../../../doc/TODO.md`, "The BPF backend's later versions".

What the seccomp rule reaches and what it misses:

- Every xattr, ACL and flag change a process requests enters through those syscalls;
  `io_uring_setup` already answers `ENOSYS` in a session ("Inventory", row 22).
- Row 18 is a list of commands, not a syscall family, and the rule refuses none of them (above):
  the shares' answers close the row on the machines, and a kernel or share change reopens it
  ("Environment evidence").
- The rule refuses those calls everywhere in the container, under `~` as well. It answers
  `ENOTSUP` to the xattr syscalls, so that `cp -a` drops attributes silently as through the
  filter, and `ENOTTY` to the ioctl commands, as FUSE answers for the filter (`fs/fuse/ioctl.c`).
- overlayfs's own writes to its upper layer reach `inode_setxattr` without those syscalls
  (row 20). Where "Mounts" refuses the overlay mount, none is made; elsewhere neither a slot nor the
  rule holds them, a decision pending for the later version that admits the mount
  (`../../../doc/TODO.md`, "The BPF backend's later versions").
  - overlayfs sets its `user.overlay.*` names on existing directories of the upper layer,
    protected ones included: `uuid` on the upper root at its first mount and `impure` on a
    parent (`fs/overlayfs/util.c`, `ovl_init_uuid_xattr`, `ovl_set_impure`).
  - A `trusted.overlay.*` name needs `CAP_SYS_ADMIN` in the initial user namespace
    (`fs/xattr.c`, `xattr_permission`).

Hooks the policy does not need, and the fact that excuses each:

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
  fixed-file install also call. The hook's isolation rests on io_uring staying refused: a transfer
  into another ring's fixed-file table by `IORING_OP_MSG_RING` was reported to skip the hook (a
  report to the io_uring list of 2026-05-21, not verified here on either kernel), and
  `io_uring_setup` answers `ENOSYS` under the launcher's profile ("Inventory", row 22), which the
  launcher suite measures under the profile the launcher installs; a configuration that admits
  io_uring reopens this hook. `pidfd_getfd` needs a pid visible in the session's pid namespace,
  which holds the container's processes alone. A descriptor is judged where it is used: an `openat`
  through a received directory descriptor runs the receiver's hooks, and the sender's see nothing,
  since an `O_PATH` open returns before `security_file_open` (`fs/open.c`, `do_dentry_open`) and no
  hook is on the send; a descriptor already open for writing takes the receiver's `write` with
  `file_permission` alone, which is not attached. So the receiver's policy over the share is what
  counts, and the sandboxes that can exchange descriptors are those reaching one socket's inode:
  each launch has its own podman network and pid namespace, and a pathname socket is found by its
  inode (`net/unix/af_unix.c`, `unix_find_bsd`, `unix_find_socket_byinode`) through any mount of its
  superblock, a read-only mount included, since the permission check there (`include/linux/fs.h`,
  `path_permission`; `fs/namei.c`, `sb_permission`) refuses a regular file, a directory or a symlink
  on a read-only superblock and reads no mount flag. A socket bound in the workspace is thus reached
  through a direct bind of the tree and not through a FUSE mount of it; the launcher binds no socket
  into the container (`AgentSandboxLauncher`, the `podman create` arguments); and the clipboard and
  run-on-host relays speak through FIFOs that `podman exec` processes, which are in the cgroup,
  create. What two containers have in common is a volume, the raw tree where a
  `--workspace=read-only` session binds it (`AgentSandboxLauncher`, `workspaceBind`), and a linked
  worktree's main gitdir, bound read-only into its container.
  - By default the session opens no channel to another container: the policy refuses a socket
    inode on a superblock of the root's type, beneath a recorded root and beneath the
    persistent volume's root, by `inode_mknod`, `inode_rename` and `inode_link` ("The policy").
    The hook is then not attached. What else could carry a descriptor does not reach another
    container: an abstract socket stays in the launch's own network namespace, a socket pair in
    the processes holding it, and no socket is bound before the policy, which precedes the
    container's first process. A socket the host binds under the workspace is a listener in the
    host's kernel, which the VM's lookup does not find; on a native Linux host it would be, a
    question for that version ("Native Linux"). Sockets under `/tmp` and the rest of `~`,
    each container's own, stay allowed. What binds where is measured in "Environment
    evidence": the one program with a socket on shared storage is Codex's app-server daemon,
    under `~/.codex`, and `codex exec` works without it ("Launcher on macOS", "Launcher on WSL").
  - `unix-socket` lifts the refusal and attaches
    `file_receive` as a ninth hook, run on the receiver's cgroup since the hook's argument is a file
    (`kernel/bpf/bpf_lsm.c`, `bpf_lsm_find_cgroup_shim`). Of a file whose mount belongs to another
    mount namespace (`fs/mount.h`, `real_mount`, `mnt_ns`; the task's in `nsproxy`), or to none,
    because the sender's container ended before the receiver read the message and its namespace was
    torn down with it (`fs/namespace.c`, `umount_tree` clears `mnt_ns`), it refuses a directory,
    whatever it names; it passes a non-directory on a superblock of the root's type only beneath a
    recorded root and, when it has `FMODE_WRITE`, only where the receiver's `file_open` would admit
    opening it for writing, which the sender's may have, since two sessions of one workspace run
    under the rule files of their own launches ("The policy", the maps); one on a superblock of the
    volume's type only beneath the recorded volume root, so another workspace's volume file does not
    arrive; and one of any other type, which reaches no share and starts no lookup. Under
    `NESTING=none` another mount namespace is another container: the profile refuses a user
    namespace, `CLONE_NEWNS` needs `CAP_SYS_ADMIN`, which `CapEff` zero lacks ("Environment
    evidence"), and `podman exec` joins the container's namespaces; the mounts inside the container,
    `/tmp`, the volumes and the bind, are its namespace's own, and a pipe, a socket or an anonymous
    inode sits on a kernel-internal mount of no namespace (`fs/namespace.c`, `kern_mount`,
    `MNT_NS_INTERNAL`) and passes, reaching no filesystem, as does a file of the runtime's own
    namespaces: one whose root is the receiver's own root directory, which is the host's root for
    the runtime's processes, the container's init before it pivots into the container's root among
    them, and a container's root for every session process, whose own namespace alone has it
    (`fs/namespace.c`, `pivot_root`); the one the controller runs in, by the inode number of its own
    `/proc/self/ns/mnt`; and an anonymous one, told by its flag on 7.2 and by the one inode number,
    0xEFFFFFF7, that every anonymous namespace carries on 6.18 (measured: `crun` 1.28 passes the
    volume as such a clone whose root is the volume directory, "Policy on WSL"), which `open_tree`
    with `OPEN_TREE_CLONE` makes (`fs/namespace.c`, `is_anon_ns`): the session has neither under the
    profile, and the runtime passes the container's mount sources into it as it starts (measured: a
    directory descriptor of the volume's mountpoint, refused as a directory, ended `crun`'s start,
    "Policy on macOS"; on WSL the same descriptor came from a namespace that was neither the
    controller's nor pid 1's, which are one there, so the runtime's namespaces are not knowable by
    number, "Policy on WSL"). What keeps that exception the runtime's: a descriptor of those
    namespaces can be sent only by a process holding one, the runtime's own processes, which pass
    them to the container's init before it execs the first process and leave none open across that
    exec (the policy suite's row on the first process's descriptors), and to which the session has
    no socket, since the sockets a session can reach are its own and, under the option, those of
    other sessions in the volume; so what processes of one container pass each other passes as
    today. A directory descriptor from another namespace is refused whatever it names: a lookup
    through it starts at its own path and mount (`fs/namei.c`, `path_init`), descends the mounts
    beneath, found by parent mount and dentry whatever the caller's namespace (`fs/namespace.c`,
    `__lookup_mnt`), and ascends by `..` past the receiver's root and the sender's bind
    (`follow_dotdot`, `choose_mountpoint`), so a descriptor of the sender's container root reaches
    its writable workspace bind, and one of `/repo/sub` passed to a sandbox of `/repo/sub` by a
    sandbox of `/repo` reaches `/repo`, where `mkdirat` and `unlinkat` with `AT_REMOVEDIR` are
    judged by no hook ("Directories") and, under a profile without the seccomp rules, a read-only
    open takes `fsetxattr` and `ioctl` ("Attributes, flags and ioctls"). A non-directory descriptor
    starts no lookup (`path_init` answers `ENOTDIR` to a name through one), and a reopen of it by an
    empty name is a `file_open`. `scm_detach_fds` (`net/core/scm.c`) installs a message's
    descriptors in order and stops at the refusal: the earlier ones arrive, the later ones are
    dropped, and the message carries `MSG_CTRUNC` with no error from `recvmsg`.
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
      this workspace gives it nothing. The policy suite measures both ("Suites", policy).
  - A `--workspace=read-only` session shares the raw tree and the volume with a live one, and
    its `ro` mount judges only what it opens by path: an `openat` through a received directory
    descriptor resolves on the sender's writable mount, so without a policy of its own the
    session could open the live session's `.git/config` for writing, judged by nothing. So it
    runs under a policy recording no root ("The policy"), and that is why its launch runs the
    controller as a live launch does. The filter admits what a passed descriptor widens, since
    the live session's mount judged the open; here nothing arrives by default, and under the
    option `file_receive` refuses the writable file. Where the probe fails, no session of the
    host has a policy, and the mode keeps the raw `ro` bind alone ("Native Linux"). The policy
    suite measures it.
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
    mount on the renamed directory (the one-hook suite's identity test) while a new launch spells
    the new name. The launcher lists every sandbox container by the name pattern each of its
    versions has used (`sandboxRunContainer`; `podman ps --all --filter name=`,
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
mount syscall (`../../../SECURITY.md`, "No containers inside the sandbox by default";
`SeccompProfile.scala`).

- It removes row 20's overlay mount, whose `user.overlay.*` writes no taken slot holds, and row
  21's bind of the workspace at a second path: without a user namespace the session holds no
  capability to mount with.
- Neither `NESTING=same-uid`, where a nested podman creates user namespaces and mounts, nor
  `NESTING=user-namespace` runs under the profile: both keep podman's default. On both, sessions of
  a later version (`../../../doc/TODO.md`, "The BPF backend's later versions"), the hooks judge rows
  20 and 21 ("The policy"), and overlayfs's `user.overlay.*` names are a decision that item holds.


## The policy

The program classifies by object and position, never by a path string:

- The sandbox's policy names its workspace root as `(superblock, inode)`, recorded by the
  controller from the VM's own `statx` of the bind source, with the root's filesystem type name; a
  `--workspace=read-only` session's policy records the type and no root. The program walks
  `d_parent` from the target dentry, bounded, folding each name as `policy.rs` folds
  (`../../../fuse/ko-agent-fs/doc/git-metadata.md`, "The name rule"), until it meets a recorded
  workspace or volume root or the filesystem root. A recorded gitdir root or guarded object met on
  the way is marked and the walk goes on, so that the file rules and a symlink target's depth keep
  the workspace's ancestry above it; it is the walk's root only when the walk reached the filesystem
  root with no workspace root above it, while a walk that reaches the bound denies whatever it
  marked. An object on a superblock of another type, `~`, the volumes and the container's own
  filesystems, is outside before any walk and allowed. On a superblock of the root's type, a
  mutation is allowed only beneath a recorded root: a walk that meets none, or reaches the bound,
  which stays above the deepest path the every-hook suite measures, denies. Every workspace a
  machine serves is on its one share type, which the one-hook suite's `findmnt` row records (on
  Windows the launcher takes `/mnt/<drive>` paths alone, `SandboxWorkspace`), so another workspace's
  object is of the root's type.
  - Nothing the session may write lies there: the container's one other host bind, a linked
    worktree's main gitdir (`SandboxWorkspace.linkedGitdirBind`), is read-only, and the rest is
    volumes and its own filesystems. What the rule denies is another workspace's directory
    reached through a descriptor a sandbox passed ("The hooks", `file_receive`), the whole
    share for a read-only session, and the same type's unrecorded superblocks: a submount the
    guest mounts mid-session ("Mounts" below) is one and in no table, while a FUSE mount the
    session makes is of type `fuse`, not `virtiofs`.
  - The identity's encoding, one on both sides: the program reads the inode's `i_ino` and its
    superblock's `s_dev`, a `dev_t` the kernel lays out as `MKDEV` does (`include/linux/kdev_t.h`,
    `MINORBITS` 20); the controller records `statx`'s `stx_ino` and `MKDEV` of its `stx_dev_major`
    and `stx_dev_minor`, which `fs/stat.c` (`cp_statx`, `generic_fillattr`) fills from the same two
    fields, while a plain `stat`'s `st_dev` is `new_encode_dev`'s other layout. FUSE fills the
    inode's number and the attribute from the server's one number (`fs/fuse/inode.c`,
    `fuse_squash_ino`, the identity on a 64-bit kernel; `fs/fuse/dir.c`, `fuse_fillattr`). The
    one-hook suite found the two readings of one object equal on both kernels ("One hook
  on macOS", "One hook on WSL", identity).
- No socket inode comes to be on a superblock of the root's type, beneath a recorded root, or
  beneath the persistent volume's root, recorded as `(superblock, inode)` like a workspace root
  since the volume shares its superblock with `~` ("Environment evidence"): `inode_mknod` refuses
  the creation, and `inode_rename`, each way for an exchange, and `inode_link` refuse a source whose
  inode is a socket. The walk from the new name's parent that meets the volume's root, or the bound,
  denies. The three hooks see the moved inode alone, so a directory holding a bound socket, moved
  whole, would carry it; what stops that is the mount layout, which the lifecycle suite tests: a
  socket is bound under `~`, the volume and the share are other mounts, and `rename` across mounts
  answers `EXDEV` before any hook (`fs/namei.c`, `do_renameat2`), while beneath the volume no socket
  comes to be in the first place. A version that binds another mount into the container reopens
  this. `unix-socket` lifts the rule and keeps a socket out of a gitdir by the same three hooks
  ("The hooks", `file_receive`, has the channel each closes).
- No FIFO comes to be on a superblock of the root's type beneath a recorded root, none there is
  opened, and none has its times changed: `inode_mknod` refuses the creation by type, `file_open`
  any open of one by the inode's type, for reading as for writing, before the hook's early exit for
  reads, and `inode_setattr` a time change on one, by type and `ATTR_ATIME` or `ATTR_MTIME` in the
  attribute's `ia_valid` (`include/linux/fs.h`), so that `chmod` and `chown` of one stay as they
  are, as in the filter; on every platform. The user's decision of 2026-10-25, taken against
  documenting the hazard and waiting for libkrun: on the macOS machine a FIFO's times reaching
  libkrun's passthrough `setattr` block the share's one worker thread, and with it every session on
  the machine (`../../../doc/upstream-issues.md`, "Setting a FIFO's times blocks the macOS virtio-fs
  server"; `../../../doc/TODO.md`, "A FIFO in the workspace hangs the podman machine"). Why three
  hooks: a write through a FIFO makes the guest kernel flush its times to the share itself
  (`fs/pipe.c`, `pipe_write`, `file_update_time`; `fs/fuse/file.c`, `fuse_write_inode`,
  `fuse_flush_times`), past `security_inode_setattr`, which `fs/attr.c` calls from `notify_change`
  alone, so the time rule holds `touch` and not use; the open rule holds use, of a FIFO the host
  made included, since every open but `O_PATH` passes `security_file_open` before the file's own
  open (`fs/open.c`, `do_dentry_open`) and an `O_PATH` open opens no pipe. Under `unix-socket`,
  `file_receive` refuses a FIFO of the share's type by inode type too, whatever its mode: a
  container on the machine outside any policy can open one and pass the descriptor, and a write
  through it would flush the times as the session's own open would. A `--workspace=read-only`
  session needs none of these: its bind is read-only, which still lets a FIFO be opened for writing,
  since `do_dentry_open` takes the mount's write access for no special file (`fs/open.c`), but a
  write or a read through it changes no time on the share, since `file_update_time` and
  `touch_atime` take that write access first and skip the update where the mount refuses it
  (`fs/inode.c`, `mnt_get_write_access_file`), and FUSE flushes `mtime` and `ctime` alone
  (`fs/fuse/dir.c`, `fuse_flush_times`). What stays is the host's own use of a FIFO it made, and a
  container outside any policy using one, neither of which a session's hook sees. The filter, whose
  daemon receives the flush as a `SETATTR` request, refuses it instead (`fs.rs`, `setattr`), since
  the kernel opens a FIFO on a FUSE mount without asking the daemon. The program holds the four
  rules (`policy.bpf.c`, `R_FIFO`), each a corpus case of `exercise.c`'s `fifo` group over a FIFO
  the host made, skipped where the share refuses to make one, as both machines' shares do; the
  measured sections of the policy to benchmark suites measure the program holding them.
    Each share is one superblock (`fs/fuse/virtio_fs.c`, `virtio_fs_test_super`), so a second
    share bound into a disposable container is the policy suite's stand-in for a submount made after
    attach.
- A string from `bpf_path_d_path` is not an identity: where "Mounts" allows them, unprivileged user
  namespaces work inside a session, so a task can bind the workspace at a second path
  in a mount namespace of its own.
- Inside the root, the walk's names give the position the filter's classifier uses: a `.git`
  component, the entries under it, `modules/<name>` and `worktrees/<name>`, `.ko-agent-sandbox`,
  and a file-rule line. The sandbox's policy also names the proof fixture's root as a second
  root ("Lifecycle"), judged by the same rules.
  - The line set is the launcher's resolved rules, the same text the filter receives, which the
    unprivileged guard (`ko-agent-fs --resolve --bpf-records`, `bpf_records.rs`) folds and compiles
    into fixed-size map records before attach, in the layout of the C header it generates
    (`../../../fuse/ko-agent-fs/include/records.h`). The controller loads those records and parses
    no text from the workspace. The records are bounded, and the guard refuses a launch whose rules
    exceed a bound: 128 lines of at most 7 components of 63 bytes, 16 alias contexts (the context of
    a symlink whose end an anchored `pinned-path` line names, which every entry below the end also
    stands as, `RuleContext::also`), and at most 2 alias contexts live at one position, a third
    denying the mutation. The program keeps the alias contexts as the filter does: activated at the
    line's end, advanced with each name below it, dropped once they can decide nothing.
- The gitdir allowlist (`../../../fuse/ko-agent-fs/doc/git-metadata.md`, "The classifier") is the
  policy here too. The filter finds a nested gitdir's root by the `HEAD` it holds, a lookup a
  program cannot make, so the controller records the roots under `modules/` at launch; a namespace
  without a recorded root stays wholly protected, the filter's own strict default, and the sandbox
  cannot add a root since the `.git` pointer its worktree needs is refused. A denylist of the
  executable state (`config*`, `hooks`, `commondir`, `gitdir`, `objects/info`, the rebase, sequencer
  and `rr-cache` state) would be smaller and fail open on a future git file that executes; the
  allowlist loads within the verifier's budget on both kernels ("Suites", policy).
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
    that form on Windows, a form no project is known to use. On a real NTFS volume a write
    through `VSCODE~1` is refused ("Policy on WSL", short name).
  - What neither covers, a residual recorded here beside
    `../../../fuse/ko-agent-fs/doc/git-metadata.md`'s for host-made hard links to protected inodes:
    a hard link the host makes to the `.git` pointer file of a nested repository that is not a
    submodule, or to any guarded file after launch, is ordinary data to the walk, and a rewrite of
    the pointer through it is within the property. The session cannot make such a link, since
    `inode_link` refuses a guarded source; the filter catches only a link beside its target, by
    comparing siblings; a scan of the whole tree at launch would cover the launch-time half at the
    cost of a walk of the tree per launch, the cost the backend removes, and nothing a program can
    do covers the mid-session half. The residual narrows the property, and the host's trust does not
    restore it: a host program that hard-links such a file for its own reasons, a backup or
    `cp -al`, gives the session a write path to the pointer that the host did not intend, so the
    statement of the property excludes a host-made second name the policy cannot recognize. The
    user, 2026-10-22, on recording the submodule pointer files and accepting the rest: "Add the
    third option as recommended one, as you recommend." Refusing every write through a file with
    `i_nlink > 1` was not among the options: pnpm installs by hard-linking from a store on the
    installation's filesystem, which in a session is the workspace's (https://pnpm.io/faq, "Does
    pnpm work across multiple drives or filesystems?"), so hard-linked files in a workspace are
    ordinary.
- A mount inside the workspace, a filesystem the host mounted at `<workspace>/vendor`, has dentries
  whose `d_parent` chain ends at that filesystem's root, never at the workspace root, so a walk
  by dentry alone would allow everything in it; a bind mount of a directory of the workspace's
  own filesystem has dentries whose chain passes the bind's source, not its mountpoint. The
  filter crosses such mounts and classifies their contents (`fs.rs`, `open_ino`, no
  `RESOLVE_NO_XDEV`). Here:
  - the first version refuses the launch when the VM shows a mount under the bind source, and
    names it. The session makes none ("Mounts"), the launcher binds nothing under the workspace
    (`SandboxWorkspace.linkedGitdirBind` refuses a target inside the workspace mount or holding it),
    and a mount the host adds mid-session does not propagate into the container under podman's
    default `rprivate`; what remains is the share. Whether the macOS and Windows virtiofs servers
    present a host-side mount as one tree or as a nested superblock, one present at launch and one
    the host makes after attach, is measured in the every-hook suite: the macOS server presents an
    attached disk image as a superblock of its own and the WSL share a second mount point as a
    symlink, and a write beneath either is denied ("Every hook on macOS", "Every hook on WSL",
    host-side mount). The launch is refused for a mount the VM shows and the mutations beneath a
    nested superblock are denied: only virtiofs auto-mounts a directory its server flags with
    `FUSE_ATTR_SUBMOUNT` (`fs/fuse/virtio_fs.c`, `auto_submounts`), as a new superblock of the
    parent's type at the guest's next lookup (`fs/fuse/dir.c`, `fuse_dentry_automount`,
    `fs_context_for_submount`), and a 9p share never does. Apple does not document whether its
    server flags one; neither rule depends on the answer;
  - native Linux's version ("Native Linux"), where the host's own `git` reads a tree with the
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
  running program. The controller freezes the four record maps once filled (`BPF_MAP_FREEZE`),
  after which the kernel refuses every write to them from user space for their lifetime
  (`kernel/bpf/syscall.c`, `map_get_sys_perms`); this stops a stray write by a tool of the
  machine's root, not root, who can detach the programs. The slots are per hook, not per program
  (`bpf_cgroup_atype_find` keys them by `attach_btf_id`), so this takes no slot; its cost is the
  verifier's time per program set, paid ahead of the launch ("Lifecycle", the preloaded set).
- The walk's state across its loops is per CPU and per slot: the kernel runs a cgroup's programs
  under `rcu_read_lock` and `migrate_disable` with no recursion count (`kernel/bpf/cgroup.c`,
  `bpf_prog_run_array_cg`), so under full preemption a second task on the CPU enters the program
  over the first's state. Each call on an object of the share's type takes the lowest free of four
  slots by an atomic or on a per-CPU word and releases it at its decision; a fifth such task at once
  is denied and counted (`reentry`), while a call on another type, the runtime's and the container's
  own files, takes no slot and passes. Task-local storage would allocate the 28 KB of state inside
  the hook. The macOS kernel runs `full (lazy)` preemption, a mode a boot parameter can change since
  the kernel is `PREEMPT_DYNAMIC` (`dynamic_preempt_schedule` in its kallsyms), and the WSL kernel
  `none` ("Policy on macOS", "Policy on WSL", preemption).
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

`--build` installs the BPF object and the controller into the machine, as it installs the filter.
The controller then runs at every launch, restart and recreate, since each attaches to a new cgroup
and only a privileged caller can: one `sudo -n` per launch, in the machine or on the host. The
verifier checks a sandbox's nine programs within 0.6 s on the macOS machine and 2.0 s on the WSL one
("Lifecycle on macOS", "Lifecycle on WSL"), time a launch waits for only when no preloaded set is
ready at its attach: the controller keeps one preloaded set per machine, loaded and pinned with
empty maps and attached to nothing, which a launch takes by renaming its pin directory to the
session's name, fills and attaches (step 2), and the controller prepares the next preloaded set
afterwards, in the background. A boot leaves no preloaded set; the reconcile at the launcher's start
prepares one in the background (step 7), seconds before the launch's attach, and the launcher
suite's launches that found none took the set their own reconcile prepared, on both machines. No
boot-time unit prepares one: by the user's decision of 2026-10-28, a wait of at most one load per
boot costs less than a system unit in the machine's configuration, installed only with the user's
consent. A restart or recreate attaches the programs the launch pinned (step 5). A preloaded set is
used once, dies with the boot as every pin does, and fails the read-back's tag check when `--build`
installed another object since, as a stale pin does; the launcher suite measured the fill through
the pinned programs' map ids. The preloaded set is the user's decision of 2026-10-25 over one
program set per machine, verified once per boot, whose hooks would find the session's records in
inner maps of a map-of-maps keyed by the attach cgroup, found through the task's cgroup ancestry:
that would cost the per-sandbox programs "The policy" relies on, the invariant that no record
changes under a running program, and the read-back's showing that a cgroup's programs read that
cgroup's records, where the preloaded set costs one idle program set per machine, 1.5 MiB of kernel
memory ("Launcher on macOS", "Launcher on WSL", the kernel's memory), and a background preparation.
The pins outlive the controller, and a pin in `bpffs` does not survive a machine restart. For each
session:

1. Create the attach cgroup before any container process exists, and keep it alive: under the
   systemd manager, a transient slice held by a VM-side unit, under which `podman create
   --cgroup-parent=<slice>` places the container; under the cgroupfs manager, the WSL machine's
   ("Environment evidence"), a directory the launcher makes under the user's delegated subtree,
   which podman takes as an absolute `--cgroup-parent` and which stays until removed ("One hook
   on WSL").
   - A link whose cgroup is removed is detached without an error (`cgroup.c`,
     `bpf_cgroup_link_release`, "auto-detached by dying cgroup"), so what removes the slice decides
     whether the hold unit is needed: systemd left the empty slice and the link in place for the 60
     s the one-hook suite watched after the hold unit and a container below had stopped, and a stop
     of the slice unit removed it within 1 ms and detached the link ("One hook on macOS"). Whether
     systemd ever removes the empty slice by itself is unmeasured beyond those 60 s, so the hold
     unit stays until a longer watch says otherwise, and teardown stops the slice unit.
   - Rejected: the container's own cgroup, a scope under systemd and a directory under cgroupfs,
     attached between `podman init`, which performs every step short of starting the container
     (https://docs.podman.io/en/latest/markdown/podman-init.1.html), and `podman start`. It
     works: on both machines the cgroup exists after `podman init`, holds the runtime's process
     alone, and a policy attached there refuses the started command ("One hook on macOS",
     "One hook on WSL"). It fails "What the backend must hold": the `createContainer` hooks run
     in the container's namespaces during create, before any attach there is possible (OCI
     runtime spec, `config.md`, "CreateContainer Hooks").
   - In which cgroup a `createContainer` hook runs is what the spec leaves open: a hook may
     expect the mounts and nothing about cgroups (the same section, and
     https://github.com/opencontainers/runtime-spec/issues/1039). crun, 1.30 on macOS and 1.28
     on WSL, runs it inside the container's own cgroup below the attach cgroup, where the policy
     refused its write ("One hook on macOS", "One hook on WSL"); a crun that ran a hook outside
     would reopen this step.
2. Take the preloaded set, or load the sandbox's programs and maps where none is ready; fill the
   records and freeze their maps ("The policy"), attach every program by link, pin the links and the
   programs where the session cannot reach, and read them back. A pinned link holds its program and
   the program its maps (`kernel/bpf/syscall.c`, `bpf_link_free`), so the maps need no pin; the
   programs are pinned for step 5 and for the preloaded set, so that a restart, a recreate or a
   launch attaches them without the verifier's time again.
   The controller attaches only below the invoking user's slice, in the machine as on native
   Linux ("Native Linux"); any other cgroup is refused before the attach.
3. Prove the enforcement without trusting step 2's report, in two parts, both before any
   container process runs.
   - A read-back by a separate program, with the controller's privileges and none of its code:
     for each hook of the session's set, the eight of "The hooks", the ninth under
     `unix-socket` and those a later `--workspace` value adds, `BPF_PROG_QUERY` on
     the attach cgroup with `BPF_LSM_CGROUP`
     lists the attached programs by id, as the kernel's own test does
     (`prog_tests/lsm_cgroup.c`, `query_prog_cnt`), with the attach-flags buffer the query of
     this type requires beside the id buffer (`__cgroup_bpf_query`, `EINVAL` without it).
     - One query lists the programs of every hook together (`kernel/bpf/cgroup.c`,
       `__cgroup_bpf_query`, `CGROUP_LSM_START` to `CGROUP_LSM_END`). For each program,
       `BPF_OBJ_GET_INFO_BY_FD` gives its `attach_btf_id`, tag and `map_ids`
       (`kernel/bpf/syscall.c`, `bpf_prog_get_info_by_fd`): the ids must name each hook of the set
       once and nothing else, the tag must equal the installed object's, and every map, opened by id
       (`BPF_MAP_GET_FD_BY_ID`, which needs `CAP_SYS_ADMIN`), must have the record format's type,
       key and value sizes and entry count, and the records the guard produced as its contents, the
       four record maps frozen, which the descriptor's fdinfo shows (`frozen:`,
       `bpf_map_show_fdinfo`) and `bpf_map_info` does not; the string literals' read-only map must
       hold the installed object's bytes, since the tag covers instructions alone and a build
       differing in data alone keeps every tag.
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
       decides it (`../../../doc/file-rules.md`, "The rule file"): refused under a `read-only` line,
       allowed under a `writable` line such as the defaults' `writable node_modules`, and the later
       line's answer where lines overlap; the fixture holds an overlapping pair on purpose. Every
       answer must be the expected one.
   A difference in either part ends the launch. Together they catch a controller that attached
   nothing, attached a subset, attached another build, loaded the wrong records, or whose
   program uses another map; what they do not catch is a defect the program shares with the
   fixture's expectations, which the policy suite's corpus is for. The proof runs at every
   launch, the user's decision of 2026-10-26, and the controller keeps the two parts separable for
   the skip rule `../../../doc/TODO.md` plans ("The proof fixture skipped on an unchanged
   launch"), since the proof's 306 to 386 ms on WSL ("Lifecycle on WSL") is a cost every launch
   pays.
4. Create and start the container; its scope, or its directory under cgroupfs, lands below the
   proven cgroup. `podman init` makes the container first, and the start waits for the machine to
   confirm the placement: a watcher the script of steps 1 to 3 leaves behind reads the cgroup of
   the process `State.Pid` names and reports it on the share (`KoAgentBpf.PlacementWatcher`), and
   the launch ends unstarted unless that cgroup lies below the attach cgroup, or when it cannot be
   read (`KoAgentBpf.placementVerdict`).
   - Why: the proof runs the launcher's own fixture in the attach cgroup, not the container, so the
     placement would rest on the runtime honouring `--cgroup-parent` as "Environment evidence"
     measured; a runtime that placed the container elsewhere would leave it without a policy,
     unreported.
   - Not from `podman inspect`: `State.CgroupPath` is empty until the container runs (podman
     6.1.4, `libpod/container.go`, `cGroupPath`), and `HostConfig.CgroupParent` is the request,
     not the placement. Podman itself reads `/proc/<State.Pid>/cgroup`, and sets `State.Pid` at
     create (`libpod/oci_conmon_common.go`, `createOCIContainer`), as the OCI runtime spec requires
     a pid in the `created` state (`runtime.md`, "State").
   - Measured on 2026-10-27: after `init` the status reads `initialized` and `State.Pid` names
     `crun`, whose `/proc/<pid>/cgroup` names `<parent>/libpod-<id>.scope/container` on macOS and
     `<parent>/libpod-<id>` on WSL. Read over `podman machine ssh` it took 0.25 s and 1.0 s, and a
     launch makes no other machine round trip between create and start; through the watcher, with
     `init` run right after the create, the start waited 57 ms on macOS and 55 ms on WSL.
   - A pid reused after the container's process ended reads another process's cgroup, below the
     attach cgroup only if that process were there, where nothing but the container runs: reuse can
     only refuse the launch, so the pid needs no start-time check.
   - The start runs only after the launcher's own `init` succeeded (`KoAgentBpf.confirmPlacement`).
     The check covers the instance that `init` made: `podman start` makes another when that one
     ended before it (podman 6.1.4, `prepareToStart`, `init` from `Exited`, `reinit` from
     `Stopped`), which only an act in the machine in that window causes, no session process
     existing yet; that the same runtime then places it as it placed the first is the measured
     behaviour, not a guarantee, and the window is left open, since a check before `start` would
     leave one of its own.
   - The check does not cover the `createContainer` hooks, which run during `init`, before it;
     their placement stays with the hook rows of "One hook on macOS" and "One hook on WSL" and the
     rerun rule of "Environment evidence".
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
   containers. The preloaded set's pin directory is kept while its tags are the installed object's
   and unpinned otherwise; a directory named for a session the lock holder is not launching and no
   container names is a launch that died after taking the preloaded set, and goes as an orphan. A
   pin and its cgroup are removed only when no container, a stopped or initialized one included,
   names the cgroup, no launch or restart holds the lock, and the cgroup's
   `cgroup.events` reads `populated 0`, which counts the descendants' tasks as `cgroup.procs`
   does not
   (`Documentation/admin-guide/cgroup-v2.rst`, "Core Interface Files"); under systemd the hold
   unit is stopped first, once the cgroup has no container, so that it does not count. A stopped
   container keeps its pins (step 5), so an empty cgroup alone is no orphan. A record whose
   session has no container, no attach cgroup and no pins, as a machine restart leaves a live
   session, is dropped by the launcher's reconcile script before the controller, which could not
   open its cgroup (`KoAgentBpf.reconcileScript`). A listing or a
   label that cannot be read leaves every pin in place and is reported, each named. The reconcile
   removes only cgroups below the user's slice and pins below the controller's own directory,
   each by the identity the launcher recorded, and refuses a symlink, another filesystem or a
   path outside those roots, as a cleanup guard elsewhere has admitted `.` and volume roots as
   safe to remove (https://github.com/kubearmor/KubeArmor/issues/2822).

What a failure before step 4 leaves, and why the policy cannot lapse during a session:
`../../../doc/bpf-lsm-cgroup.md`, "Launches".


## The launcher's side

At every launch under `bpf`, a capability probe (`KoAgentBpf.checksScript`) checks:

- `bpf` in the active LSM list;
- cgroup v2 with the user's delegated subtree under the manager podman reports;
- `bpffs` and `securityfs` mounted, which the launcher mounts where the machine does not
  ("Environment evidence", Windows);
- the share's type among the measured ones;
- a container placed below the attach cgroup, with the WSL setting named where that fails.

What a failed probe leaves: `../../../doc/bpf-lsm-cgroup.md`, "Launches".

How the steps of "Lifecycle" map onto the code:

- `--build` builds the backend's sources in the machine against its kernel where the probe's
  kernel checks and the kernel's BTF pass, and otherwise names what is missing and builds the rest
  (`KoAgentBpf.buildFailures`). The backend's build and install run after the rest, and failing on
  a kernel those checks cannot tell apart, warn and leave the rest built. It installs the binaries
  beside the filter under `~/.local/share/ko-agent-sandbox/bpf/`, records the tags and prepares
  the preloaded set.
- A launch runs the probe and the reconcile under the launch lock (`reconcileScript`, the
  controller's `reconcile`; "Lifecycle", 7).
- `startSandbox` holds the launch lock from the backend's steps 1 to 3 through the listing of the
  live sessions, the comparison (`refusalBeside`) and `podman create`. Steps 1 to 3 are
  `launchScript`: the guard's records, the fixture, the attach cgroup, the controller's `attach`,
  which takes the preloaded set that `readback check-preloaded` passed (`--preloaded`) or loads a
  set, then `readback verify` and the proof. The create's `--cgroup-parent`, `--restart=no` and
  labels (`labelArguments`) come from those steps.
- A read-only launch runs the same steps with `--no-root` and no records.
- The session's teardown (`teardownScript`) takes the filter reap's place in the reaper.

## Inventory

The policy transcribes `fuse/ko-agent-fs` at commit `0fe166a159c1f3cc75dd966a8b0e2d4faae5aa31`, the
last to change `src/{policy,fs,guard,rulefile}.rs`. A later change to those files reopens the rows
it touches. The macOS and WSL columns hold the answer under the attached programs: `yes`, the hooks
listed are called and a program there refuses the operation; `none`, the share answers before any
hook; `note`, the row of "Every hook on macOS" or "Every hook on WSL" named by the row's number.

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
  lands in the upper layer. "Mounts" refuses the mount under `NESTING=none`;
  `NESTING=user-namespace` keeps podman's default profile.
  - overlayfs changes the upper layer through `vfs_create`, `vfs_mkdir`, `vfs_rename` and
    their siblings, `notify_change` and `vfs_setxattr` (`fs/overlayfs/overlayfs.h`), which call
    the `inode_*` hooks only; `fs/namei.c` calls the `path_*` hooks from the syscalls' paths.
  - It opens an upper file through `backing_file_open`, which reaches `file_open`.
  - It accepts an upper layer whose dentries revalidate, FUSE's and virtiofs's among them, only
    with `d_type`, `RENAME_WHITEOUT` and xattrs, and one whose dentries do not with a warning for
    each it lacks (`fs/overlayfs/super.c`, `ovl_make_workdir`). By that reading the filter, which
    implements no xattrs, cannot be one. Measured in the every-hook suite: on virtiofs the mount is
    read-only, since the work directory cannot be created there; on drvfs, whose `cache=0x5` selects
    9p's dentry operations without `d_revalidate` (`fs/9p/vfs_super.c`), it is writable with the
    warning for `RENAME_WHITEOUT` ("Every hook on macOS", "Every hook on WSL").
- Row 21: a bind mount in a mount namespace of the session's own, which "Mounts" refuses where it
  refuses row 20's, or `open_by_handle_at`. The hooks judge dentries ("The policy"). Without
  `CAP_DAC_READ_SEARCH` in the initial user namespace, `open_by_handle_at` decodes directories only
  (`fs/fhandle.c`, `may_decode_fh`); 9p answers `name_to_handle_at` with `EOPNOTSUPP`.
- Row 22: `io_uring_setup` answers `ENOSYS` in a session, from the seccomp profile, and `EACCES`
  from SELinux to a plain container on the macOS machine ("Every hook on macOS"); on the WSL machine
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
`out/mill-daemon/socketPort`, and Gradle's daemon and workers on TCP ports (`../../../SECURITY.md`).
`~` and the persistent volume are two mounts of one xfs superblock, `/dev/vda4`.


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
  `rename_lock` ("What is gained and what is lost"), which the one-hook and every-hook suites
  resolved as a typeless `__ksym` extern through `/proc/kallsyms`, as libbpf does at load. By the
  user's decision of 2026-10-26 the controller stays C over libbpf until the classifier is ported to
  Rust (`../../../doc/TODO.md`, "The BPF backend's later versions"), a scheduling choice: a Rust
  controller needs no CO-RE from `rustc`, which only the program needs. Aya is the port's candidate,
  under the relocation suite that item names.
- Prior art for container-scoped BPF policy, none of which carries this policy: KubeArmor
  (https://github.com/kubearmor/KubeArmor), BPFContain
  (https://github.com/willfindlay/bpfcontain-rs), Aegis-BPF (https://github.com/ErenAri/Aegis-BPF).
- Git at `master` on 2026-10-20 (https://github.com/git/git), `compat/fsmonitor/fsm-ipc-unix.c`,
  for where `fsmonitor--daemon` binds its socket.
- OCI runtime lifecycle and hook ordering:
  https://github.com/opencontainers/runtime-spec/blob/main/runtime.md,
  https://github.com/opencontainers/runtime-spec/blob/main/config.md.
