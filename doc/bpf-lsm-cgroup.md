# The BPF cgroup-LSM backend

The workspace filter costs 6–18× on metadata operations over an unfiltered bind mount on macOS and
5–30× on Windows (`../fuse/ko-agent-fs/doc/verification-log.md`, "The cost of a path walk"), and
sessions through it have frozen the podman machine. The backend that `--workspace=<mode>,bpf`
selects binds the workspace directly and has the kernel running the containers enforce the policy:
BPF programs of type `BPF_LSM_CGROUP`, attached to the sandbox's own cgroup, so the host and every
other container keep unfiltered access to the same files.

This document states what the backend promises. How it holds each promise is
`../bpf/ko-agent-bpf/doc/architecture.md`, and what the suites measured of it on both machines is
`../bpf/ko-agent-bpf/doc/evidence.md`. The three documents use distinct section names, so a quoted
section name without a document names the one of them that holds it.

The first version serves `NESTING=none` sessions launched with the launcher's own seccomp profile
on the podman machines, where that kernel is the machine's, and gives a `--workspace=read-only`
session there a policy recording no root ("The hooks", `file_receive`, has why).
`NESTING=same-uid` and `NESTING=user-namespace` sessions (`../SECURITY.md`, "No containers inside
the sandbox by default") and native Linux hosts keep the filter (`TODO.md`, "The BPF backend's
later versions"). `fuse` stays the default of both modes until the release decision (`TODO.md`,
"The BPF backend as the default"), and no launch binds the workspace writable without the policy
attached and verified.


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


## What a session can and cannot do

Under `--workspace=live,bpf` on a podman machine:

- Two sandboxes share the hook slots and differ in policy; a third container, the egress proxy
  and the machine's own processes are never judged ("The mechanism").
- A `.git` or `.ko-agent-sandbox` by any folded spelling cannot appear by `creat`, `mknod`,
  `symlink`, `link`, `rename` or exchange, at any depth; one that `mkdir` makes never gains a
  `HEAD`, a `read-only` line still covers what lies below it, and nothing but directories enters
  a `.ko-agent-sandbox` at any position ("Directories").
- A protected entry cannot be opened for writing, truncated, re-attributed by `chmod`, `chown`,
  times, an xattr, an ACL or a `chattr` flag, changed by a filesystem ioctl, unlinked, removed
  unless it is an empty directory, renamed, exchanged, hard-linked out, or replaced, through any
  name, descriptor or mapping.
  - The filesystem ioctls are answered by the machines' shares before any hook; a share or kernel
    that implements them reopens that route ("Attributes, flags and ioctls").
  - A second name the host gives a guarded file after launch, or to a nested repository's `.git`
    pointer file that is no submodule's, is ordinary data to the policy ("The policy", the
    second-name rule).
- The file rules hold at any depth, with the resolved `read-only-path` lines; git's everyday
  commands work, and the commands the filter blocks stay blocked and listed.
- Under `NESTING=none` with the launcher's profile, the session creates no user namespace, no
  mount syscall succeeds, and no xattr or ACL is set and no `file_setattr` call succeeds anywhere in
  the container, `~` included; the ioctls that set file flags fail on the share alone, which
  answers them itself ("Attributes, flags and ioctls", "Mounts").
- No FIFO on the share is made, opened, retimed or, under `unix-socket`, received ("The policy").
- By default no socket inode comes to be in the workspace or beneath the persistent volume, by
  creation, rename or link, so the session opens no channel to another container.
- Under `unix-socket`, a descriptor one sandbox passes another is judged by the receiver's policy;
  a descriptor from another container is refused on arrival unless it is a non-directory of the
  share beneath a recorded root that the receiver could open so by path, of its own volume, or of
  a type that reaches no share, every directory among the refused, and what passes within one
  container passes unchanged. A sandbox of another workspace and a `--workspace=read-only`
  session get nothing on the share, and no socket inode enters a gitdir directly ("The hooks",
  `file_receive`).


## Directories

The policy judges neither `mkdir` nor `rmdir` (rows 3 and 9): a session creates and removes
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


## Launches

Beside the mode, `--workspace` takes comma-separated values for the backend and for sockets, the
user's decisions of 2026-10-26:

- The backend is `bpf` or `fuse`, the filter; `fuse` is the default of both modes until the
  release decision.
- `unix-socket` allows Unix sockets in the workspace and beneath the persistent volume at the cost
  of the ninth hook ("The hooks", `file_receive`), and is a fatal error with `fuse`, since the
  filter cannot honor it.
- The values are accepted in any order, and the container label holds one canonical spelling, so
  that the refusal beside a live session compares settings, not spellings.

What a launch under `bpf` does and refuses:

- A capability probe runs at every launch ("The launcher's side"). Where it fails, a live launch is
  refused and a read-only launch keeps the raw `ro` bind alone; both print what the machine lacks,
  each with the remedy per provider. The launch line names the backend, and the steps' times go to
  the run's `ko-agent-bpf.log`.
- An installation from another launcher build, or one whose tags were recorded under another
  kernel than the machine runs, as after `podman machine os upgrade` or `wsl --update`, is refused,
  and the refusal names `--build`.
- No container process runs before the policy, proven by the read-back of every attachment,
  program tag and map record and by the fixture suite in the attach cgroup, which a controller that
  attached nothing, a subset, another build or wrong records cannot pass ("Lifecycle", 3). A
  failure at any step before the container starts ends the launch; the launcher prints which step
  and never binds the workspace writable.
- During a session the policy cannot lapse without a trusted hand: a link is detached only when its
  cgroup is removed, and a cgroup with the container's scope or tasks in it cannot be removed, so
  only root detaching the link ends the enforcement, and root is trusted ("What the backend must
  hold"). The policy outlives the controller. The lifecycle suite measures both ("Lifecycle on
  macOS", the policy cannot lapse).
- A launch whose backend or `unix-socket` setting differs from that of a live session sharing its
  volume or a raw mount, a linked worktree's main gitdir included, beside a live container of an
  earlier launcher without the labels, or beside one whose recorded root path no longer names its
  recorded identity, is refused, whichever launched first and when both launch at once ("The
  hooks", `file_receive`).
- The sessions the first version does not serve keep the filter.


## What is gained and what is lost

The git property, the file rules and the blocked git commands are in neither list: the hooks
hold them as the filter does. The name rule is held too, except for directories, which "Lost"
lists. The lists are what else changes.

Gained:

- **The filter's whole cost.** The ceiling is measured
  (`../fuse/ko-agent-fs/doc/verification-log.md`, "The cost of a path walk"):

  | workload                             | through the filter | unfiltered bind | under the policy |
  | ------------------------------------ | ------------------ | --------------- | ---------------- |
  | `ls -lR`, per entry                  | 12.7 ms            | 0.69 ms         | 0.69 ms          |
  | `git status`, 4,475 files at depth 7 | 72 s               | 3.8 s           | 3.8 s            |
  | `sbt` build of this repository       | 604 s              | 87 s            | 84 s             |

  The `sbt` row's bind and policy figures keep the output in the workspace as the filter's does; the
  43 s of "an sbt build, by where its output goes" had it outside. The policy's own cost over the
  unfiltered bind is measured in "Benchmark on macOS" and "Benchmark on WSL": `entry-cost.py`'s
  rounds overlap the bind's in every row on both machines; the single runs of the walk and the
  build lie within 6 % of the bind's on the per-file rows, `find`, `git status` and the build,
  and scatter up to 1.2 times either way on the depth rows, 200 `lstat` of 0.1 to 1 ms each; the
  program itself takes 13 to 16 µs a judged call on either kernel, 40 to 65 µs at the build's
  depth of 20. It runs on mutations and opens, never on
  `lookup` or `getattr`, the operations that dominate those columns.
- **The daemon's share of the machine's hangs.** `git status` in a worktree of hundreds of
  files has frozen the podman machine for over an hour, with memory not short and
  `podman machine ssh` failing throughout. The daemon and its requests go with the filter.
  - What the bind keeps is the share server's one worker thread per share, which one blocked
    request stalls for every later one (`upstream-issues.md`, "Setting a FIFO's times blocks
    the macOS virtio-fs server").
  - A FIFO on the share is refused by type, its creation in `inode_mknod`, its open in
    `file_open`, its time change in `inode_setattr` and, under `unix-socket`, its descriptor
    in `file_receive` ("The policy"), the decision of 2026-10-25; the program holds the rules,
    which the measured sections of the policy to benchmark suites measure.
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
    the move leaves no region (`authorize_region_move`). The policy suite runs it as a race;
  - the program reads each dentry's own sequence count, `d_seq`, before and after reading its
    parent, name and inode (`fs/dcache.c`, `__d_move` and `d_exchange` hold it odd across the parent
    and name change), and reads every level's count again after the last level, as the RCU path walk
    revalidates the dentry it came from after reading the next (`fs/namei.c`, `lookup_fast`),
    through the address each level was read at, a scalar the probe helper returned, under the
    caller's RCU read lock, which keeps a dentry's memory a dentry (`fs/dcache.c`, `__d_free`): the
    chain counts only when each first value is even and every later read equals it, so it is the
    object's position over one interval of the walk and not a composition of two moments, and a
    barrier separates each count read from the field reads, as `read_seqbegin` and `read_seqretry`
    have (`include/linux/seqlock.h`, `smp_rmb`) and two plain reads do not; otherwise the walk is
    discarded and made again, and denied after a bound. The one-hook and every-hook suites read the
    global `rename_lock` sequence around the whole walk instead, as `d_path` does, which discards a
    walk at any rename in the VM: sixteen renaming processes made 35 of 11,891 walks give up after
    four retries and denied permitted operations ("Policy on macOS"), where `d_path` takes the write
    lock on its second try and a program cannot. Clang emits no barrier instruction for BPF: a fence
    outside the single-thread scope is a fatal error in LLVM's BPF backend (`BPFISelLowering.cpp`,
    `LowerATOMIC_FENCE`). The barrier is an atomic fetch-add on a map word between the reads: the
    arm64 JIT emits `ldaddal`, or `ldxr`/`stlxr` with `dmb ish` without LSE
    (`arch/arm64/net/bpf_jit_comp.c`, `emit_lse_atomic`, `emit_ll_sc_atomic`), and the x86 JIT a
    `lock`-prefixed `xadd` (`arch/x86/net/bpf_jit_comp.c`, `emit_atomic_rmw`); both verifiers accept
    it and the jited dumps show those instructions ("One hook on macOS", "One hook on WSL");
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
  - A wrong bound or read there passes a write to a protected entry until the policy suite's corpus,
    run through real syscalls against the attached program, catches it.
- **No writable session on a kernel without the LSM.** The probe fails, the launch binds nothing
  writable and says what the host lacks. A lost session, never a weaker one.
- **No session write through an NTFS short name on Windows.** Refused by form ("The policy"), a
  form no project is known to use. No protection is weakened.
- **No Unix socket in the workspace or beneath the persistent volume, by default.** Of the
  installed software, Codex's app-server daemon alone binds one there ("Environment evidence");
  `unix-socket` allows them at the cost of a ninth hook ("The hooks", `file_receive`).
  - On the Windows machine the option reaches the volume alone: the 9p share answers a socket
    bind `ENOTSUP` after the hook admits it ("Every hook on WSL", share), measured again on
    2026-10-27 in a `live,bpf,unix-socket` session, where a bind beneath the volume, the
    refusals under `.git` and `.ko-agent-sandbox`, and a share descriptor passed inside the
    session behaved as on macOS.
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
- **Under `NESTING=none`, nothing in the container sets xattrs (`setfattr`) or ACLs (`setfacl`),
  or calls `file_setattr`.** The seccomp rule ("Attributes, flags and ioctls") refuses them under
  `~` too, where the filter refuses them in the workspace alone, and `cp -a` drops xattrs and ACLs
  there; `chattr` and row 18's ioctl commands are answered by the share on the machines. No
  protection is weakened.


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
- A BPF policy program is less auditable than Rust. The classifier is the C program the suites
  measured, compiled a second time into a host test binary against headers standing in for the
  kernel's types and the helpers (`../bpf/ko-agent-bpf/test/host/`), with `policy.rs`'s corpus run
  through both (`../fuse/ko-agent-fs/tests/bpf_equivalence.rs`: every path of the conformance
  table and of the git corpus, written, unlinked, created and moved, under the rules as the
  guard's compiler writes them), so the two classifiers are shown to agree, the three rules
  "Directories" adds apart, and the C one is unit-tested on the host; the inode table, resolver
  and FUSE layer do not exist. The user, 2026-10-22: "Let's proceed with C, but I will
  definitely want to migrate to Rust when CO-RE becomes stable in Rust." The migration is a
  later version (`TODO.md`, "The BPF backend's later versions").
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
    1727). The loader's correctness and the classifier's are validated apart, the one by the
    relocation suite the Rust port's item in `TODO.md` names, the other by the corpus.
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
the same property and the same file rules, and every route of "Inventory" is held by the hooks, the
launcher's seccomp rules ("Attributes, flags and ioctls", "Mounts") or "Directories", as the
every-hook suite's gate required. What else it changes is "What is gained and what is lost", and no
protection is dropped for speed: a route neither a hook nor the rules hold is the user's decision,
taken in "Directories" or pending in `TODO.md` for the version that opens the route, never a
recorded loss.


## Native Linux

A later version (`TODO.md`, "The BPF backend's later versions") runs the backend on a native
Linux host's own kernel, without
a podman machine, within a supported set the launcher states rather than discovers. A host
outside it gets `--workspace=read-only` and a message naming the missing requirement; a podman
machine is never created for it. The set is chosen so that the host's launch is the machine's
launch, one `sudo -n` of the controller under the same cgroup manager, with no mechanism of its
own. The requirements, each checked at launch:

- **`bpf` in the active LSM list**, read from `/sys/kernel/security/lsm`. Every default list in
  `security/Kconfig` ends in `bpf`, and the machine's Fedora kernel lists it ("Environment
  evidence"); which distributions drop it is not something this document records, since the probe
  answers per host. Where a kernel lacks it, the message names the boot parameter, `lsm=` with
  `bpf` appended, and the reboot.
- **A sudoers drop-in for the controller**, granting the launcher's user `sudo -n` of the
  root-owned controller binary and nothing else.
  - The host is never prompted for sudo (`../SECURITY.md`, "Silent changes to what you own"), so
    `--build` prints the drop-in and its install command, as it prints the `fuse.conf` change
    for a machine, and the user runs them once.
  - What any sudo-granted binary needs, both checked by the lifecycle suite: the controller loads
    the object installed beside it and takes no object path, and it attaches only under the invoking
    user's slice, `/user.slice/user-<uid>.slice/`, with the uid from `SUDO_UID`; either refusal
    fails the launch.
  - Loading an LSM program needs `CAP_BPF` with `CAP_PERFMON`, or `CAP_SYS_ADMIN`
    (`kernel/bpf/syscall.c`, `is_perfmon_prog_type`). A BPF token on a delegated `bpffs`
    satisfies those two checks for an unprivileged process (`bpf_prog_load`,
    `bpf_token_capable`); whether the attach also works unprivileged is unverified, so the
    drop-in is what the version builds and the token a later reduction.
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


## Out of scope

A kernel or distribution that drops the BPF LSM or BTF, restricts what the program needs, or
changes a hook it attaches to. The capability probe or the program's load then fails and the launch
is refused ("Launches"), so such a kernel costs the session, never its protection; the user updates
the machine's kernel and runs `--build` again.
