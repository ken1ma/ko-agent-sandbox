# Plan: a BPF cgroup-LSM backend for `--write=live`

The workspace filter costs 6–18× on metadata operations over an unfiltered bind mount on macOS and
5–30× on Windows (`../fuse/ko-agent-fs/doc/verification-log.md`, "The cost of a path walk"), and
sessions through it have frozen the podman machine. This plan replaces the filter on every platform
with a direct bind of the project and a policy the kernel running the containers enforces: BPF
programs of type `BPF_LSM_CGROUP`, attached to the sandbox's own cgroup, so the host and every
other container keep unfiltered access to the same files.

On macOS and Windows that kernel is the podman machine's; on native Linux it is the host's, within
the supported set "Native Linux" states.

Status: the environment prerequisites and the cgroup placement are measured on both machines
("Environment evidence"), and Phase 0 is done ("Inventory"); no BPF program has been loaded,
attached or shown to deny anything. The filter stays the default until "Acceptance" passes, and
no launch ever binds the project writable without the policy attached and verified.

The reader acting on this plan starts at "Phases" and "What is gained and what is lost". The
sections before them are what the phases rest on.


## What the backend must hold

- The property `../fuse/ko-agent-fs/doc/git-metadata.md` states: no sandbox write makes a later
  host `git` run a program the sandbox chose or open an object directory it chose. The immutable
  set, the name rule and the double-sided rename and link rules are that document's.
- `.ko-agent-sandbox` is neither created at any depth nor written (`../SECURITY.md`, "A project
  loosening its own confinement").
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
  `.git` needs a mount target created in the project. The hooks here judge the name and the
  object at every mutation, at any depth, and create nothing in the project; the proof's
  fixture lives under the launcher's state directory ("Lifecycle").

`design.md`'s principle "Do not trade security for performance" stands: the backend is built to
hold the same property and the same file rules, and Phase 2's gate is where every route of the
inventory is shown covered within the ten slots. What else it changes is "What is gained and
what is lost", and no protection is dropped for speed: a route the slots cannot hold is a
pending decision in "Decisions still open", never a recorded loss that a gate passes. The two
documents above are updated in the change that adds the backend.


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
  `struct path` argument is usable as such, and `dentry->d_parent` walks are CO-RE reads.
- Sleepable programs: `verifier.c`, `bpf_check_attach_target`, admits a sleepable LSM program by
  its hook alone; no check against `BPF_LSM_CGROUP` was found, and `trampoline.c` enters such a
  program under `rcu_read_lock`. The design needs no sleepable program: `fs/bpf_fs_kfuncs.c`
  tags `bpf_path_d_path` without `KF_SLEEPABLE`, and the policy below does not call it.
- Hooks under `CONFIG_SECURITY_PATH` (`include/linux/lsm_hook_defs.h`) are compiled into both
  kernels: the BTF at `/sys/kernel/btf/vmlinux` of each lists the `bpf_lsm_path_*` hooks of
  "Inventory"'s table.

### The hooks

Eight hooks hold the names and the writes at the VFS, whatever the backing. The two remaining
slots must hold the xattr and ACL routes and `path_rmdir`; how is Phase 2's question.

| hook            | decides                                                   | call site      |
| --------------- | --------------------------------------------------------- | -------------- |
| `path_mkdir`    | a new directory's name and parent                         | `fs/namei.c`   |
| `path_mknod`    | a new file's name and parent: `creat`, `O_CREAT`, `mknod` | `may_o_create` |
| `path_symlink`  | a new symlink's name, parent and target syntax            | `fs/namei.c`   |
| `path_link`     | the source object and the new name                        | `fs/namei.c`   |
| `path_rename`   | both names, both parents, `RENAME_EXCHANGE` by `flags`    | `fs/namei.c`   |
| `path_unlink`   | removal of a protected entry                              | `fs/namei.c`   |
| `file_open`     | an open for writing of a protected object                 | `fs/open.c`    |
| `inode_setattr` | `chmod`, `chown`, times, `truncate`, `ftruncate`          | `fs/attr.c`    |

The routes the two slots must hold, each refused under the whole workspace as the filter refuses
every xattr and ACL operation by not implementing `setxattr` and `removexattr`
(`../fuse/ko-agent-fs/doc/verification-log.md`, "Extended attributes"):

- xattrs: `inode_setxattr` and `inode_removexattr`. The macOS share forwards xattrs: through an
  unfiltered bind `setxattr` succeeds.
- POSIX ACLs: `inode_set_acl` and `inode_remove_acl`.
  - `fs/xattr.c`, `do_setxattr` and `removexattr`, route the `system.posix_acl_*` names to
    `do_set_acl` and `vfs_remove_acl` before `vfs_setxattr`'s `security_inode_setxattr`, so the
    xattr hooks never see an ACL.
  - `fs/posix_acl.c`, `vfs_set_acl`, calls `security_inode_set_acl`, and
    `posix_acl_update_mode` rewrites `i_mode`, a `chmod` that `inode_setattr` never sees.
  - A FUSE superblock, virtiofs included, carries `SB_POSIXACL` (`fs/fuse/inode.c`,
    `fuse_fill_super`), and `fuse_set_acl` forwards the ACL to the server as an xattr, so whether
    the macOS share stores one is the server's to answer; ext4, xfs and btrfs store both routes
    (`fs/{ext4,btrfs}/acl.c`, `fs/xfs/xfs_acl.c`).
- `path_rmdir`. Without it a session can remove, leaves first, a protected directory whose tree
  holds no protected non-directory; one holding such an entry stays, since unlinking it is
  refused (`policy.rs` at the commit "Inventory" pins).
  - Such a directory is `.git/hooks` holding no hook, empty directories at most; a gitdir whose
    protected entries are such directories, which the session empties first, since in the git
    rules a gitdir's root is the one protected directory whose entries can be operational
    (`classify_within_gitdir`); or a `readonly` directory whose non-directories later `writable`
    lines all lift (`child_rule_context`).
  - The removed name cannot be refilled: `mkdir`, creation and a rename onto it stay refused
    (`authorize_create`, `authorize_rule_create`).
  - `objects` and `objects/info` are pinned, not protected: the filter removes them too, since
    only `mkdir` can create them again, which starts them empty (`is_pinned_within_gitdir`).

Five hooks for two slots. No other hook stands in for them: `inode_permission` sees neither an
ACL change, whose `may_write_xattr` checks only the immutable and append flags and the id
mapping (`fs/xattr.c`), nor a `security.` or `system.` xattr, for which `xattr_permission`
returns before any permission check. What holds them:

- Under `NESTING=none`, a seccomp rule in the launcher's profile refusing the `setxattr` and
  `removexattr` syscall families, `setxattrat` and `removexattrat` included. It takes no slot,
  so `path_rmdir` keeps its slot and every route is covered.
  - Every xattr and ACL change enters through those syscalls; `io_uring_setup` already answers
    `ENOSYS` in a session (`TODO.md`, "Deferred — refuse user namespaces").
  - The rule refuses them everywhere in the container, under `~` as well, answering `ENOTSUP`
    so that `cp -a` drops attributes silently, as it does through the filter.
- Under `NESTING=same-uid`, whether a nested podman's storage needs those syscalls is a Phase 2
  measurement. If it does, the rule cannot apply, two slots hold two of the five, and which
  three routes stay open on such sessions is a user decision in "Decisions still open", with
  each route's consequence stated there. Phase 2's gate stays unmet for that mode until it is
  taken.

Both kernels' BTF lists every hook this section takes ("Inventory").

Hooks the plan does not take, and the fact that excuses each:

- `inode_create`: `may_o_create` calls `security_path_mknod` before `security_inode_create`, so
  `path_mknod` already judges every `O_CREAT`.
- `path_truncate`, `file_truncate`, `path_chmod`, `path_chown`: `fs/open.c` routes `do_truncate`,
  `chmod_common` and `chown_common` through `notify_change`, whose one security call is
  `security_inode_setattr`.
- `mmap_file`, `file_mprotect`: a shared writable mapping needs a descriptor opened for writing
  (`mm/mmap.c`, `FMODE_WRITE`), which `file_open` refused.
- `file_permission`: judges descriptors that predate the policy or were passed in. The policy is
  attached before the container's first process ("What the backend must hold"), so none
  predates it, and the launcher passes no host descriptor into the container: it never uses
  `--preserve-fds`.


## The policy

The program classifies by object and position, never by a path string:

- The sandbox's policy names its workspace root as `(superblock, inode)`, recorded by the
  controller from the VM's own `stat` of the bind source. The program walks `d_parent` from the
  target dentry, bounded, folding each name as `policy.rs` folds (`git-metadata.md`, "The name
  rule"), until it meets the root or the filesystem root. Outside the root, everything is allowed.
- A string from `bpf_path_d_path` is not an identity: unprivileged user namespaces work inside a
  session (`unshare -Ur` succeeds), so a task can bind the workspace at a second path in a mount
  namespace of its own.
- Inside the root, the walk's names give the position the filter's classifier uses: a `.git`
  component, the entries under it, `modules/<name>` and `worktrees/<name>`, `.ko-agent-sandbox`,
  and a file-rule line. The sandbox's policy also names the proof fixture's root as a second
  root ("Lifecycle"), judged by the same rules.
  - The line set is the launcher's resolved rules, the same text the filter receives, which the
    unprivileged guard (`ko-agent-fs --resolve`) folds and compiles into fixed-size map records
    before attach. The controller loads those records and parses no project text.
- The gitdir allowlist (`git-metadata.md`, "The classifier") is the policy here too. The filter
  finds a nested gitdir's root by the `HEAD` it holds, a lookup a program cannot make, so the
  controller records the roots under `modules/` at launch; a namespace without a recorded root
  stays wholly protected, the filter's own strict default, and the sandbox cannot add a root
  since the `.git` pointer its worktree needs is refused.
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
    it is within the property. The session cannot make such a link, since `path_link` refuses a
    guarded source. Covering the launch-time half needs a scan of the whole tree at launch; the
    mid-session half has no cover a program can give. It is a pending user decision ("Decisions
    still open"), and Phase 3's row for it cannot pass without that decision.
- A mount inside the workspace, a filesystem the host mounted at `project/vendor`, has dentries
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
those privileges, and the controller never reads the project: its input is the launcher's
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
     for each of the ten hooks, `BPF_PROG_QUERY` on the attach cgroup with `BPF_LSM_CGROUP`
     lists the attached programs by id, as the kernel's own test does
     (`prog_tests/lsm_cgroup.c`, `query_prog_cnt`).
     - For each program, `BPF_OBJ_GET_INFO_BY_FD` gives its tag and its `map_ids`
       (`kernel/bpf/syscall.c`, `bpf_prog_get_info_by_fd`): the tag must equal the installed
       object's, the map ids must be exactly the ids of the sandbox's pinned maps, and those
       maps' contents, read by id, must equal the records the guard produced.
     - The tag alone proves nothing about the maps: the kernel zeroes map references before
       computing it (`kernel/bpf/core.c`, `bpf_prog_calc_tag`).
   - A fixture the kernel judges, under the launcher's state directory in the VM, so a missing
     hook costs nothing in the project.
     - The guard writes a tree laid out as a workspace, with a `.git` holding `config` and a
       hook, a `.ko-agent-sandbox`, and one entry per resolved rule line, and the sandbox's
       policy records that tree's root as a second root.
     - The launcher places a process of its own in the attach cgroup and runs one refused
       operation per hook against the fixture: `mkdir`, `creat`, `symlink`, `link` and `rename`
       to a guarded name, an open for writing, `chmod`, `unlink` and `rmdir` of guarded entries,
       `setxattr` and `setfacl` where those hooks apply; then one write per rule-line entry and
       one write to an ordinary entry.
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
the project writable. During a session the policy cannot lapse without a trusted hand: a link
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
- Row 9: "The hooks" has what removing a protected directory allows; read in `policy.rs`.
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
- Row 17: a route "The hooks" does not list.
  - `FS_IOC_SETFLAGS` and `FS_IOC_FSSETXATTR` take a read-only descriptor
    (`fs/file_attr.c`, `ioctl_fssetxattr`), and `vfs_fileattr_set` admits the owner.
  - Only the append-only and immutable flags need `CAP_LINUX_IMMUTABLE` in the initial user
    namespace, and a project id is refused outside it.
  - Seccomp can refuse `file_setattr` and the two ioctl commands by the command argument.
- Row 18: commands a filesystem implements itself, outside `vfs_fileattr_set`; "The hooks" does
  not list them either. The ones read in v7.1 take a read-only descriptor:
  - ext4's `EXT4_IOC_SETVERSION`, refused under `metadata_csum`, sets the generation and ctime
    directly; it, `EXT4_IOC_MIGRATE` and `EXT4_IOC_ALLOC_DA_BLKS` check the owner
    (`fs/ext4/ioctl.c`).
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
  lands in the upper layer.
  - overlayfs changes the upper layer through `vfs_create`, `vfs_mkdir`, `vfs_rename` and
    their siblings, `notify_change` and `vfs_setxattr` (`fs/overlayfs/overlayfs.h`), which call
    the `inode_*` hooks only; `fs/namei.c` calls the `path_*` hooks from the syscalls' paths.
  - It opens an upper file through `backing_file_open`, which reaches `file_open`.
  - It accepts an upper layer whose dentries revalidate, FUSE's and virtiofs's among them, only
    with `d_type`, `RENAME_WHITEOUT` and xattrs (`fs/overlayfs/super.c`). By that reading the
    filter, which implements no xattrs, cannot be one; whether each share can, Phase 2 measures.
- Row 21: a bind mount in a mount namespace of the session's own, or `open_by_handle_at`. The
  hooks judge dentries ("The policy"). Without `CAP_DAC_READ_SEARCH` in the initial user
  namespace, `open_by_handle_at` decodes directories only (`fs/fhandle.c`, `may_decode_fh`).
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
   both kernels' BTF. Confirm the `path_rmdir` reading against `policy.rs`. Done in "Inventory",
   whose measured results Phase 2 fills.
1. **One hook, one denial.** A `lsm_cgroup/file_open` program denying the open for writing of
   one marker name, the controller attaching it to a disposable cgroup of each shape in
   "Lifecycle",
   then a disposable container under it: the marker is refused, other files are not, a sibling
   container outside the cgroup opens the marker, a second attached cgroup shares the slot, and
   a deliberately failed attach starts no container. On macOS first, then WSL.
   Gate: inheritance, denial, isolation and fail-closed start, both kernels.
2. **Every hook.** The candidate programs on a disposable tree of the real share, exercising
   each syscall of the inventory, `openat2`, descriptor-relative calls, `RENAME_EXCHANGE`,
   `setfacl` and `setxattr`, a host-side mount inside the tree, and ordinary git. Record the
   verifier's answer per hook per kernel, which attribute routes each share accepts, and the
   cost of the bounded ancestry walk at the real tree's depths on both kernels, so the policy's
   price is known before the classifier and the lifecycle are built.
   Also measure whether a nested podman under `NESTING=same-uid` needs the xattr syscalls, and
   whether each share stores a `security.capability` set and removed from a user namespace the
   session creates, before the decision on open routes is put.
   Gate: the inventory's macOS and WSL columns are complete, every route covered within the slots or
   by the seccomp rule "The hooks" names, or a decision taken for each route that is not, and
   the walk's cost recorded beside the unfiltered bind's.
3. **The policy.** The classifier in the programs, the map compiler in the guard, and the
   filter's test corpus run against the bind: the name-rule corpus, the pointer rewrite, the
   second-name cases, hooks, config, alternates, operational writability, the blocked git
   commands, symlink escape and the rename races (`git-metadata.md`, "Test list"); a host hard
   link to the root's `.git` pointer file and to `.ko-agent-sandbox`
   (`tests/mounted_mutate.rs`, `a_second_name_of_a_guarded_entry_is_guarded_like_it`); the NTFS
   short-name form on a real NTFS volume; a nested mount holding a `.git`; a linked git worktree,
   whose main gitdir the launcher binds read-only (`TODO.md`, "Deferred — writable git from a
   linked worktree").
   Also: the session binds the workspace and a nested filesystem at other paths in a mount
   namespace of its own and mutates through the aliases; a host hard link to a nested `.git`
   pointer file, made before and after launch.
   Gate: each row ENFORCED, or an existing filter residual, or covered by a decision the user
   has taken in "Decisions still open". A listed loss passes nothing.
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
6. **Integration.** A backend selector with a capability probe, `--write=reject` and the printed
   host requirements where the probe fails, the launch line naming the backend and the accepted
   differences, the removal of the filter, and the documentation changes "The recorded decisions
   this answers" names.


## What is gained and what is lost

The git property, the name rule, the file rules and the blocked git commands are in neither
list: the hooks hold them as the filter does. The lists are what else changes.

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
  - The refusal of `mknod` of a FIFO that `TODO.md` ("A FIFO in the project hangs the podman
    machine") considers for the filter is a `path_mknod` rule here.
- **No window between resolving and acting.** The decision is taken inside the syscall, on the
  dentry the kernel acts on, which the filter's resolver and its `ESTALE` rules exist to
  approximate. A held directory handle follows a directory the host moved and is judged by its
  current position. The walk reads `d_parent` without the rename lock, so a concurrent rename
  can be seen mid-move; Phase 3's rename races measure what that passes.
- **Data coherency is the share's own.** The filter's two residual cache cases
  (`../fuse/ko-agent-fs/doc/architecture.md`, "Coherency") have no layer to occur in.
- **No daemon.** No `ENOTCONN` failure domain shared by a project's sessions, no serialized
  round trips, no inode table.

Lost, stated as what becomes possible that the filter does not allow:

- **A privileged controller in the path.** The enforcement is the verified program in the
  kernel; the controller that installs it runs with the `bpf` syscall's privileges, as root in
  the machine for the launch, or as the host's root unit ("Native Linux"), where the filter
  daemon runs as an ordinary user throughout.
  - It parses no project text: the unprivileged guard folds and compiles the rules into
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
  form no project is known to use. A usability loss, not a guarantee.

Decisions still open, each the user's, taken after Phase 2's table:

- **Cgroup shape.** Slice with a hold unit, or the container's scope between create and start;
  Phase 1 measures both.
- **Native Linux, SELinux enforcing: relabel or `label=disable`.** "Native Linux" states both;
  the relabel is the plan's default, and `label=disable` a per-host choice.
- **The attribute routes under `NESTING=same-uid`, if a nested podman needs the xattr
  syscalls.** Two slots then hold two of the five hooks ("The hooks"), and which three routes
  stay open on such sessions is this decision. Each route's consequence, read in v7.1:
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
  - `path_rmdir` open: a protected directory the session can empty can be removed and not
    refilled.
  Pending; nothing is pre-accepted.
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
supported set the launcher states rather than discovers. A host outside it gets `--write=reject`
and a message naming the missing requirement; a podman machine is never created for it. The
requirements, each checked at launch:

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
    `bpf_token_capable`);
    whether the attach also works unprivileged is unverified, so the unit is what the plan builds
    and the token a later reduction.
- **Under SELinux enforcing, a label the container may use.** The launcher's default is a
  persistent file-context rule and a relabel of the project directory to a shared container type
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
(https://man7.org/linux/man-pages/man7/landlock.7.html), so a `.git` that does not exist yet
is not an object it can refuse, and a new one at any depth would stay creatable. It is not a
backend for this policy.


## Acceptance

- Two sandboxes share the hook slots and differ in policy; a third container, the egress proxy
  and the machine's own processes are never judged.
- A `.git` or `.ko-agent-sandbox` by any folded spelling cannot appear by `mkdir`, `creat`,
  `mknod`, `symlink`, `link`, `rename` or exchange, at any depth.
- A protected entry cannot be opened for writing, truncated, re-attributed by `chmod`, `chown`,
  times, an xattr or an ACL, unlinked, renamed, exchanged, hard-linked out, or replaced, through
  any name, descriptor, mapping or nested mount.
- Git's everyday commands work; the commands the filter blocks stay blocked and listed.
- The file rules hold at any depth, with the resolved `readonly-path` lines.
- No container process runs before the policy, proven by the read-back of every attachment,
  program tag, program map id and map record and by the fixture suite in the attach cgroup,
  which a controller that attached nothing, a subset, another build, wrong records or another
  map cannot pass; the policy outlives the controller; the attach cgroup cannot be removed
  while the container's scope or any task is in it.


## Sources

- Linux v7.1: `include/linux/bpf-cgroup-defs.h`, `include/linux/lsm_hook_defs.h`,
  `kernel/bpf/{cgroup,bpf_lsm,trampoline,btf,verifier,helpers}.c`,
  `fs/{namei,attr,open,xattr,posix_acl,bpf_fs_kfuncs}.c`, `fs/fuse/{inode,acl}.c`,
  `fs/{ext4,btrfs}/acl.c`, `fs/xfs/xfs_acl.c`, `security/commoncap.c`, `mm/mmap.c`, and
  `tools/testing/selftests/bpf/{progs,prog_tests}/lsm_cgroup.c` for a working attach.
- Loaders: libbpf (https://github.com/libbpf/libbpf) or Aya's `lsm_cgroup` support
  (https://github.com/aya-rs/aya/pull/1135). Decide after Phase 1.
- Prior art for container-scoped BPF policy, none of which carries this policy: KubeArmor
  (https://github.com/kubearmor/KubeArmor), BPFContain
  (https://github.com/willfindlay/bpfcontain-rs), Aegis-BPF (https://github.com/ErenAri/Aegis-BPF).
- OCI runtime lifecycle and hook ordering:
  https://github.com/opencontainers/runtime-spec/blob/main/runtime.md,
  https://github.com/opencontainers/runtime-spec/blob/main/config.md.
