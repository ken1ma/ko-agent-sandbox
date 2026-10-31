# The BPF backend's evidence

What the suites measured of the backend `../../../doc/bpf-lsm-cgroup.md` promises, on the podman
machines of macOS and Windows, and how they measure it again.

A change to the code of a source that a suite's `sources.txt` lists, under `../test/podman/`, reruns
that suite on both machines, and its sections below are rewritten from the reruns, naming the new
sources digest. A comment edit needs no rerun: the digest covers the sources' code, comments aside
(`../../../src/main/scala/SourceDigest.scala`). Run the check from the repository root:

```sh
bpf/ko-agent-bpf/test/SourceDigestCheck.scala
```

It fails while a section names a digest its suite's sources no longer have, so a section stands
for the code in the tree alone. No marker lets a section stand for superseded code, the user's
decision of 2026-10-26: every later change of the program, the Rust port among them, would reuse
it. On Windows, where no shebang runs, the check is
`scala shebang bpf\ko-agent-bpf\test\SourceDigestCheck.scala`.

This document, `../../../doc/bpf-lsm-cgroup.md` and `architecture.md` use distinct section names,
so a quoted section name without a document names the one of them that holds it.


## Suites

What each suite measures, and its gate, which a rerun passes as the first run did. The one-hook
and every-hook suites are not rerun: their drivers are in the tree of commit 654586d
(`bpf/probe/phase1/`, `bpf/probe/phase2/`). The one-hook suite asked whether a cgroup-attached LSM
program loads and denies on each machine's kernel, which the launcher's capability probe asks at
every launch (`KoAgentBpf.checksScript`) and the policy suite shows; the every-hook suite
inventoried what each hook sees and what each share answers, which the policy suite's corpus
exercises and the every-hook sections record. Its measured columns fill the design document's
"Inventory".

- **One hook**, retired: one denial. A `lsm_cgroup/file_open` program denying the open for writing
  of one marker name, the controller attaching it to a disposable cgroup of the shape in "Lifecycle"
  and of the rejected one, then a disposable container under it: the marker is refused, other files
  are not, a sibling container outside the cgroup opens the marker, a second attached cgroup shares
  the slot, and a deliberately failed attach starts no container. Also, on each share, the identity
  test: a directory's and a file's `(superblock, i_ino)` in the guest stay the same after a host
  rename of it and of an ancestor, after the guest drops its caches, and for the two names of a
  host-made hard link, and differ from a host-made replacement at the same name, and the identity
  the controller's `statx` records equals the one an attached program reads from the object's inode
  ("The policy"), on both kernels; `findmnt` records the share's backend and options first, since 9p
  without metadata caching makes a new inode per lookup and keeps `i_ino` from the QID alone
  (`fs/9p/vfs_inode.c`, `v9fs_get_new_inode_from_fid`). And the verifier's time to load the eight
  programs, nine with `unix-socket`, with the `rename_lock` read and its fetch-add barrier ("What is
  gained and what is lost") in the walk, and `bpftool prog dump jited` showing the barrier
  instruction on each architecture. And, under the attach cgroup, a `createContainer` hook
  (`podman --hooks-dir`) that records its `/proc/self/cgroup` and opens the marker for writing: the
  open must fail with `EPERM` and the recorded cgroup must lie below the attach cgroup, with the
  installed crun ("Lifecycle", 1); the attach cgroup's `cgroup.events` reading `populated 1` with a
  container below it and no task of its own, and `populated 0` after the container's stop
  ("Lifecycle", 7); and whether the manager removes the empty slice within 60 s. On macOS first,
  then WSL. The driver was `bpf/probe/phase1/phase1.sh`, `phase1.ps1` on Windows, run on the host;
  its transcript is this suite's record, and its programs are C with libbpf, not the classifier's
  Rust, since the suite measures the kernel and not the port. Gate: inheritance, denial, isolation,
  fail-closed start, stable identities and the hook's refused open below the attach cgroup, both
  kernels.
- **Every hook**, retired. The candidate programs on a disposable tree of the real share, exercising
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
  with bounded loops before the policy suite ports the rest.
  The driver was `bpf/probe/phase2/phase2.sh`, `phase2.ps1` on Windows, run on the host, and its
  transcript is this suite's record: `inventory.bpf.c` records which of 33 hooks each operation
  of the exerciser (`mutate.c`) reaches and refuses the operation on a deny name, attached in
  batches of eight that keep a hook whose refusal a row claims apart from the hooks the same
  operation reaches first; `classify.bpf.c` is the representative program, its loops the kernel's
  numeric-iterator loops (`bpf_iter_num_*`, Linux 6.4), which the verifier checks by the
  convergence of the loop's state rather than by simulating each iteration
  (`kernel/bpf/verifier.c`, `process_iter_next_call`), deciding a corpus of 51 cases on a
  fixture laid out as a workspace, under the defaults' rules and filler lines filling the
  128-line rule map, and ordinary git in a clone of this repository; the exerciser's open loops
  give the walk's cost at the clone's deepest file, at depth 32 and at depth 63, under the
  policy and on the bare bind. What the program leaves to the policy suite is listed at its end.
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
- **Policy** (`../test/podman/policy/`). The classifier in the programs, with what the every-hook
  suite left to it ("The policy"): the guarded objects' identities, the alias contexts, the
  short-name form, the symlink target rules, `file_receive` and the walk's state against reentry;
  its host build and the corpus run through both classifiers ("What is gained and what is lost");
  the map compiler in the guard (`../../../fuse/ko-agent-fs/src/bpf_records.rs`), producing the
  records "The policy" describes in one layout, from which it generates the C header
  `../../../fuse/ko-agent-fs/include/records.h` that a test compares with the committed file; and
  the filter's test corpus transcribed into the suite's corpus, each case naming the test it
  transcribes (`../../../fuse/ko-agent-fs/doc/git-metadata.md`, "Test list"; `tests/mounted_*.rs`),
  since those tests mount a FUSE filter over a backing tree they write directly, which under the
  policy is a process outside the cgroup, and read `mkdir` as judged, which "Directories" does not.
  The walk's per-CPU slots ("The policy") replace the every-hook suite's per-CPU state; each
  kernel's preemption mode is read from `/sys/kernel/debug/sched/preempt`. The rows, each run with
  the policy attached, on both machines:
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
    counted as the one-hook suite's stats row counts them, no write succeeds, and both renamers
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
  - the seccomp profile "Mounts" relies on, derived from the machine's default
    (`SeccompProfile.scala`): `unshare` and each mount syscall answer `EPERM` and a child process
    still starts.
  The driver is `../test/podman/policy/Policy.scala`, one driver for both hosts, run on the host,
  and its transcript is this suite's record: `policy.bpf.c` is the every-hook suite's program with
  the additions above, the walk, each level of it and of its snapshot, the rule match, the alias
  activation and the symlink judgment each a global function verified once per program, since the
  verifier checks a loop's inlined body at every iteration until its states converge and 6.18
  converges slowly ("Policy on WSL"); `exercise.c` lays out the fixtures, decides the corpus of 252
  cases in seventeen groups, runs the race and the storm, and binds, serves and receives sockets and
  descriptors; `controller.c` is the every-hook suite's with the records, computing an alias context
  in user space as the guard does. The runs settled the record layout, which the guard's compiler
  writes. The host build (`../test/host/`) runs the filter's own corpus through the program before
  any host run, and a program it has not passed is not run on the machines.
  Gate: each row ENFORCED, or an existing filter residual, or covered by a decision the user has
  taken, such as "Directories"; and the policy program loads on both kernels, its verifier figures
  recorded as the every-hook suite's are, each program within 500,000 instructions, half the limit,
  on each kernel, since 6.18 processes many times 7.2's instructions for one loop ("Policy on WSL",
  28 times for the walk) and a program near the limit fails to load at the next change of the walk.
  A listed loss passes nothing.
- **Lifecycle** (`../test/podman/lifecycle/`). The ordering of "Lifecycle" on rootless podman:
  first-process denial, restart, recreate, `podman exec`, stop and kill, controller exit, machine
  restart, link loss; and the proof's catches, a controller that attaches a subset of the hooks, one
  that attaches another build's program, one whose build differs in data alone, one that loads wrong
  records, and one that leaves the record maps unfrozen, each of which must end the launch; a write
  from user space to each record map of a live session, refused. The reconcile of "Lifecycle", 7: a
  launcher killed between the pins and `podman create`, and a `podman create` that fails after the
  pins, each leave a cgroup and pins the next start removes; a launcher killed between
  `podman create` and `podman start` leaves a container that names the cgroup, whose pins stay until
  the container is removed; a stopped session's and a live session's stay, and a listing that fails
  removes nothing. The restart invariant of "Lifecycle", 5: the created container's restart policy
  reads `no`, and after a machine restart with a stopped container present, nothing starts it. The
  socket rule's dependence on the mounts ("The policy"): a directory under `~` holding a bound
  socket, moved into the volume or the workspace, fails with `EXDEV`. The controller's two refusals:
  one given an object path, and one asked for a cgroup outside the invoking user's slice, in the
  machine; and its third, a mount under the bind source, which it lists in the VM before the attach
  ("The policy"). The launch cost of steps 2 and 3 on both machines, the verifier's 0.6 s and 1.7 s
  for the nine programs among it ("Policy on macOS", "Policy on WSL"), and a restart's with the
  pinned programs ("Lifecycle", 5). The proof at every launch and the preloaded set rest on those
  figures ("Lifecycle", 3 and the preloaded set). The rows the reuse of pins, the reconcile's
  identities and the cleanup add, on both machines:
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
  The lifecycle suite also binds the evidence to the code it measured: every driver records the
  digest of its suite's sources beside the object's hash, the measurement sections name it, and
  `../test/SourceDigestCheck.scala` fails when the sources' code differs from the digest its
  section names, so that a section cannot stand as evidence for code it did not measure.
  Gate: no container process runs before the policy, on either machine, each of the three
  defective controllers is caught, the stale pins and the contradicting identities are refused,
  the reconcile removes the two orphans and nothing else, and the evidence check passes.
- **Benchmark** (`../test/podman/benchmark/`). `../../../fuse/ko-agent-fs/bench/entry-cost.py` and
  the real-tree rows of `../../../fuse/ko-agent-fs/doc/verification-log.md` on the bind with the
  policy, beside the filter and the unfiltered bind; the machine's CPU and memory during the stat
  storm under each, the stat storm being `walk-cost.py`'s rows over the real tree, `lstat` of every
  tracked file by path and `git status`. The driver is `../test/podman/benchmark/Benchmark.scala`,
  one Scala CLI script for both hosts, run on the host, and its transcript and tables are this
  suite's record: it builds the lifecycle suite's controller, read-back and fixture over the policy
  suite's program, with `stats.c` reading the program's counters beside them, clones the real-tree
  rows' tree (sbt/sbt, shallow) into a scratch workspace on the share, launches the policy over it
  through steps 1 to 3 of "Lifecycle" under the launcher's default rules, and runs the two probes
  over that one tree in three containers: the sandbox image over a writable bind of the workspace
  (`../../../fuse/ko-agent-fs/bench/unfiltered.sh`'s command), the same command below the attach
  cgroup, and the launcher's session through the filter, and before the launch one `entry-cost.py`
  round on the bind with no program attached, the control for the shim the first attach installs for
  every task in the VM ("The mechanism"). `entry-cost.py` runs in interleaved rounds, three by
  default; the `sbt` build of "an sbt build, by where its output goes" runs once on the bind and
  once under the policy, on a clone of this repository made inside the tree with its output there,
  the filter's 604 s standing from that log; `walk-cost.py` runs once per stack. A sampler in the
  machine reads `/proc/stat`, `/proc/meminfo` and the pressure files each second during each run,
  and the program's counters are read after each run under the policy, so that each figure comes
  with the calls each hook judged. A hook file's creation in `.git/hooks`, refused under the policy
  and through the filter and made over the bare bind, shows each stack is what it claims before the
  figures are taken. Gate: the numbers are recorded; the default changes only by a release decision.
- **Launcher** (`../test/podman/launcher/`). The launcher's side ("The launcher's side"), measured
  through the launcher's jar. Its rows, which need the launcher, follow;
  `../test/podman/launcher/Launcher.scala` runs them by the user's decisions of 2026-10-29: from a
  host terminal with no other sandbox session on the machine, which it refuses otherwise (A); the
  earlier build the lifecycle suite's `other.bpf.o`, swapped in for the installed object and
  restored (B); the memory row's sets loaded by the installed controller, unattached (D);
  `codex exec`, which needs a signed-in Codex, by hand (E); the WSL proof's failure a unit test of
  the launch script (F); no row for a boot-time unit, which the backend does not install (C):
  - under the profile the launcher installs, `io_uring_setup` answers `ENOSYS` from the
    container's first process and from a `podman exec` process ("The hooks", `file_receive`);
  - a launch under the other backend or the other setting of `unix-socket` while a session
    sharing its volume or a raw mount is live, refused in either order: for a main checkout and
    a linked worktree sharing its volume, for two sessions of one workspace naming two volumes,
    for a workspace below another's root, for a linked worktree with its own volume beside its
    main checkout, after a host rename of the workspace between the two launches, which name
    two volumes, beside a live container of an earlier launcher without the labels too, and of
    two such launches racing, one refused;
  - a linked git worktree, whose main gitdir the launcher binds read-only
    (`../../../doc/TODO.md`, "Deferred — writable git from a linked worktree"), and a symlink
    under its main checkout's `.git/objects` to a socket outside, through which the worktree's
    container cannot connect;
  - `codex exec` run with the daemon directory unwritable ("The hooks", `file_receive`);
  - the preloaded set ("Lifecycle"): a launch taking it by rename and filling its maps through the
    pinned programs' ids, passing the read-back and the proof, its step 2 at a recreate's cost; two
    launches racing for one preloaded set never sharing one, their programs disjoint (both took a
    set in the runs, the second the one prepared behind the first); a preloaded set of a build
    `--build` replaced, unpinned by its tags; a launch that died after taking the preloaded set,
    removed by the reconcile, built as such a launch leaves it: the record, the attach cgroup and
    the taken set attached there; a launch finding no preloaded set, as the first after a boot,
    which took the one its own reconcile prepared; a live session's records, read back before and
    after another launch takes the preloaded set and the next one is prepared, unchanged, and the
    two sessions' program ids disjoint;
  - the sessions' cost in the kernel: the memory of one, four and eight program sets, and the same
    after their removal, so that the per-sandbox sets "The policy" relies on have a measured price;
    the sets are loaded unattached, so links are not counted. The kernel charges a map's and a
    program's memory to the memory cgroup of the process that made them, and the charge outlives
    the process (`kernel/bpf/syscall.c`, `bpf_map_save_memcg`, the map's `objcg`), so every load
    runs in a cgroup kept for the measurement and summed by it, whose `memory.current` is read
    after the loader exits: under systemd a hold unit's service in a slice, under cgroupfs a
    directory of the delegated subtree, which stays until removed. The machine's root offers no
    reading, `memory.current` being a file of non-root cgroups alone
    (`Documentation/admin-guide/cgroup-v2.rst`), and `bpftool`'s `memlock` is each map's own
    estimate (`kernel/bpf/syscall.c`, `bpf_map_memory_usage`), not the charge;
  - on WSL, the proof run by the launcher itself: its process enters the leaf below the attach
    cgroup through a transient scope of the user manager ("Lifecycle on WSL"), and a scope that
    cannot be created or a migration that fails ends the launch before any container;
  - the FIFO rules ("The policy"): `mknod` of a FIFO refused by type in `inode_mknod`, its
    open in `file_open`, a time change on one in `inode_setattr` and, under `unix-socket`, its
    descriptor in `file_receive`, each a corpus case over a FIFO the host made, opened with
    `O_NONBLOCK` so that the test itself never waits, and the proof's `mkfifo` at an ordinary name:
    the FIFO cases are in the policy suite's corpus and the `mkfifo` in the lifecycle suite's
    fixture;




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
setup note for Windows names it. Under it the session's limits apply, below the attach cgroup as
well: `memory.max` 7,105,761,280 and `pids.max` 2048 in a `live,fuse` and a `live,bpf` session on
2026-10-27, where podman issue 29966 reports no controller for rootless podman on WSL 3.0.3 by
default. References:
https://learn.microsoft.com/windows/wsl/wsl-config,
https://github.com/microsoft/WSL/issues/41492,
https://github.com/podman-container-tools/podman/issues/29749,
https://github.com/podman-container-tools/podman/issues/29966.

## The suites' measurements

### One hook on macOS

Measured on 2026-10-21 with `bpf/probe/phase1/phase1.sh` of commit 654586d on the machine above,
podman 6.1.2, clang 19.1.7, no other `lsm_cgroup` link in the VM. The suite's transcript holds the
raw lines.

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

### One hook on WSL

Measured on 2026-10-21 with `bpf/probe/phase1/phase1.ps1` of commit 654586d on the Windows machine
above, podman 6.1.4 under the cgroupfs manager, clang 19.1.7, no other `lsm_cgroup` link in the VM.
The rows below name what differs from macOS; every other row passed as there.

| row                      | measured                                                              |
| ------------------------ | --------------------------------------------------------------------- |
| mounts                   | no securityfs and no bpffs until the suite mounted them               |
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
version: the stack depth and instruction count the verifier admits ("Suites", every hook) are the
compiler's output, so a compiler change reopens that gate with the kernel unchanged.

### Every hook on macOS

Measured on 2026-10-21 with `bpf/probe/phase2/phase2.sh` of commit 654586d on the machine of "One
hook on macOS", podman 6.1.2, clang 19.1.7, `classify.bpf.o` of SHA-256
`3fd866407d2d007c5f6ab550d5e3af9eddc146356b8bd4a7147940ae99746e70`. The exerciser's containers run
without podman's seccomp profile, which answers `file_setattr` and `io_uring_setup` with `ENOSYS`
and refuses a mount in a user namespace before the kernel does; rows 20 and 21 run with
`label=disable` besides, as the sandbox's nesting mode does. The transcript holds the raw lines.

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

### Every hook on WSL

Measured on 2026-10-21 with `bpf/probe/phase2/phase2.ps1` of commit 654586d on the Windows machine
of "One hook on WSL", podman 6.1.4, clang 19.1.7, `classify.bpf.o` of SHA-256
`aba2e8b1be6ad42e3540474b221370238e281c7c363e6cc06c56478fd0d9c256`, built against that kernel's BTF.
The containers run as on macOS. The rows below name what differs from macOS; every other row passed
as there.

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


### Policy on macOS

Measured on 2026-10-27 with `../test/podman/policy/Policy.scala` on the machine of "One hook on
macOS", podman 6.1.2, crun 1.30, clang 19.1.7, `policy.bpf.o` of SHA-256
`81b80f90f32c1c751b4a8904c498e57c592a297317377b121367c8eac00b14f0`, built from sources of code
digest `8b80574529703dad22e01e237387c011dfc93db6f348604ec454545b7c31dfcd` (`sources.txt` lists them
in digest order; `../test/SourceDigestCheck.scala` recomputes it): the program with the FIFO
rules ("The policy"), from `../policy.bpf.c`. The containers run as in the every-hook suite. Every
one of the 48 rows passes; the rows give this run's figures and the transcript holds its raw lines.
Figures of the runs before, of 2026-10-22 under the program as first written and of 2026-10-24 under
the revision before the FIFO rules, are kept where they are the reason for a rule or the only
measurement of their kind, and named as such.

| row                      | measured                                                              |
| ------------------------ | --------------------------------------------------------------------- |
| preemption               | `full (lazy)`, 10 CPUs                                                |
| verifier, per program    | 45,398 to 47,873 insns (45,217 to 47,873 before the FIFO rules), at   |
|                          | most 25 states per insn, 67 to 85 ms each, 541 ms for all nine; the   |
|                          | run of 2026-10-24, whose log holds the per-function counts: the walk  |
|                          | and position 40,584 insns (39,476 before the scratch locks'           |
|                          | admission, 33,135 with the loop bodies inlined, 16,758 before the     |
|                          | review's three changes), each level of the walk 248 and of its        |
|                          | snapshot 39, the rule match 2,524, the alias activation 634 and the   |
|                          | symlink judgment 2,797, each a global function verified once, stack   |
|                          | 352 to 384 of 512 bytes                                               |
| barrier                  | the jited `file_open`, 32,336 bytes, holds three `ldaddal`, one per   |
|                          | fetch-add: before and after a level's reads, and before the snapshot  |
| records                  | 128 rule lines, eleven roots (three workspaces, a submodule's gitdir, |
|                          | four guarded `.git`, two guarded `.ko-agent-sandbox` and the volume), |
|                          | the alias context of `.claude` holding the five `.claude` lines as    |
|                          | partial matches, which the guard's compiler reproduces                |
|                          | (`bpf_records.rs`, its first test)                                    |
| corpus                   | 256 cases: 242 under the default flags, 6 under the short-name flag   |
|                          | and 8 under `unix-socket`, 0 mismatches each; of the 242, 5 answered  |
|                          | by the share before any hook, the `mkfifo` cases with `EACCES`,       |
|                          | counted apart, and 4 skipped, the `fifo` group's cases on the host    |
|                          | FIFO the share refused to make (`result=EACCES`)                      |
| git                      | status, add, commit, a branch, log and gc in the clone; `git config`  |
|                          | and `git init` refused; git outside the policy in `sub/`, whose       |
|                          | session-made `.git` has no `HEAD`, finds the workspace's gitdir       |
| race                     | 2,580 moves of the outer directory, 1,012 moves and 414 exchanges of  |
|                          | the inner, against 10,464 writes by path and through held             |
|                          | descriptors: 6,061 refused, 4,403 absent, 0 succeeded; 5 walks read a |
|                          | torn name and were made again (9, 15, 8, 6, 2, 11 and 12 in the runs  |
|                          | before), none gave up                                                 |
| race, global sequence    | the first run, validating the walk by `rename_lock`: 167 walks        |
|                          | overlapped a rename and 35 of 11,891 gave up after four retries       |
| storm                    | 16 processes, 24,850 decisions, 0 wrong, 0 denied for want of a slot, |
|                          | no nesting on any CPU; walk means 20 to 32 µs, 236 µs at most (the    |
|                          | runs before: 29,498, 25,312 and 30,394 decisions, means 19 to 35 µs,  |
|                          | 478 µs at most but for one `inode_unlink` walk of 1.22 ms)            |
| slots exhausted          | with four marked taken a write on the share is refused and counted    |
|                          | once as reentry; with three it runs in the fourth; freed, in the      |
|                          | first                                                                 |
| storm, global sequence   | the first run: 16 walks gave up and 17 permitted operations in four   |
|                          | processes were denied                                                 |
| sockets by default       | `bind` beneath the volume `EPERM` and under its superblock's `~`      |
|                          | stand-in allowed, from where `mv` and `ln` beneath the volume and     |
|                          | `mv` into the workspace are refused                                   |
| second share             | a directory under `/private/tmp`, virtiofs, bound into the container: |
|                          | a write inside gets `EPERM`, a directory is made ("Directories")      |
| walk cost, in program    | `file_open` over the 10,000 opens for writing of the pairs below, all |
|                          | walked to depth 11: 61.3 µs mean, 161 µs at most; the storm's walks   |
|                          | at depth 3 average 20 to 32 µs and the race's at depth 5, 33 µs       |
| walk cost, syscall       | five pairs of 2,000 opens at depth 11, a container under the policy   |
|                          | and one bare, the policy's first in the odd pairs, policy minus bare: |
|                          | the open for writing +38, +131, +73, +68 and +68 µs, median +68, the  |
|                          | program's own figure; the open for reading, which the hook leaves     |
|                          | before any walk, −34 to +18, median +6; `lstat`, which no hook sees,  |
|                          | −19 to +56, median +11; the bare write open at 775 to 809 µs. A run   |
|                          | of 2026-10-24 with the bare open at 949 to 1,791 µs spread the write  |
|                          | open's difference from −640 to +443 and `lstat`'s to +1,224, so the   |
|                          | syscall figure holds on a quiet share only, and the program's timer   |
|                          | is the one to read                                                    |
| container start          | with `file_receive` attached, the runtime passes 16 descriptors of    |
|                          | its own namespaces into the starting container, all passed, and the   |
|                          | first process holds no descriptor beyond the standard three; the      |
|                          | controller's namespace is pid 1's, 0xEFFFFFF8, the initial one        |
| container start, refused | the first run, with every other namespace's descriptor judged: a      |
|                          | directory descriptor of the volume's mountpoint, `_data`, refused,    |
|                          | and `crun` failed with `write to sync socket: Connection reset`       |
| slots                    | four sandboxes with nine hooks each hold nine of the ten              |
| descriptors              | every row of "Suites", 3 as listed but the host FIFO's, skipped as    |
|                          | the share made no FIFO; B's `file_receive` over the rows: 134 calls,  |
|                          | 128 of the runtime's namespaces, 4 allowed, 2 denied                  |
| seccomp                  | under the generated profile `unshare` with `CLONE_NEWUSER` and the    |
|                          | twelve mount syscalls answer `EPERM`, and a child process runs        |


### Policy on WSL

Measured on 2026-10-27 with `../test/podman/policy/Policy.scala` on the Windows machine of "One hook
on WSL", podman 6.1.4 under the cgroupfs manager, crun 1.28, clang 19.1.7, `policy.bpf.o` of SHA-256
`463cfe8660a9f165cdff072bcf99efd47edbb9d82596030ecd337841ee2bd0a5`, built against that kernel's BTF
from sources of code digest `8b80574529703dad22e01e237387c011dfc93db6f348604ec454545b7c31dfcd`,
those "Policy on macOS" measures: the program with the FIFO rules. Every one of the 49 rows passes.
The rows below name what differs from macOS and give this run's figures; every other row passed as
there. Figures of the runs of 2026-10-24, under the revision before the FIFO rules, are kept where
they are the reason for a rule or the only measurement of their kind, and named as such.

| row                      | measured                                                              |
| ------------------------ | --------------------------------------------------------------------- |
| preemption               | `none`, 4 CPUs                                                        |
| verifier, per program    | 113,296 to 118,558 insns of the 1,000,000 limit (113,101 to 118,558   |
|                          | before the FIFO rules), the walk and position 109,037 of them, 2.7    |
|                          | times the count on 7.2.5 (107,929 before the scratch locks'           |
|                          | admission; 919,220 with the loop bodies inlined, 24.7 s for all nine; |
|                          | 121,408 before the review's three changes); each level of the walk    |
|                          | 248 and of its snapshot 39, the rule match 1,955, the alias           |
|                          | activation 634 and the symlink judgment 4,665; stack 352 to 384       |
|                          | bytes; at most 46 states per insn; 207 to 491 ms each, 2.07 s for all |
|                          | nine (1.67 s and 1.73 s in the runs of 2026-10-24)                    |
| barrier                  | the jited `file_open`, 24,769 bytes, holds three `lock xadd`, the     |
|                          | scan matching the instruction under any `REX` prefix                  |
| corpus                   | 242 default cases, 0 mismatches: 236 run, the exchange among them     |
|                          | answered `EINVAL` by 9p before any hook; 6 skipped, the two names     |
|                          | NTFS cannot hold (a newline, non-UTF-8 bytes) and the `fifo` group's  |
|                          | four on the host FIFO 9p refused to make (`EOPNOTSUPP`). The five     |
|                          | `mkfifo` cases are refused `EPERM` by the policy, whose FIFO rule in  |
|                          | `inode_mknod` runs before 9p answers; the macOS share answers         |
|                          | `EACCES` before any hook. Of the socket group 4 of 8 run, the rest    |
|                          | needing a bound socket, which 9p refuses after the hook               |
| race                     | no descriptor held, since 9p refuses to move a directory with an open |
|                          | handle below it, and no exchange; 1,204 moves of the outer directory  |
|                          | and 119 of the inner against 3,728 writes: 290 refused, 3,438 absent, |
|                          | 0 succeeded; 1 walk read a torn name and was made again (2, 1, 4, 1,  |
|                          | 0, 2 and 4 in the runs of 2026-10-24, in one of which the outer       |
|                          | renamer's first failed move answered `EACCES`)                        |
| storm                    | 16 processes, 8,246 decisions in the 5 s a 9p operation's 10 ms       |
|                          | allows, 0 wrong, 0 reentry; walk means 34 to 55 µs, 2.7 ms at most    |
|                          | (6,678 decisions, 29 to 49 µs and 4.1 ms in the last run of           |
|                          | 2026-10-24)                                                           |
| short name, real volume  | NTFS serves `.vscode` as `VSCODE~1`; under the flag a write through   |
|                          | it is refused and the host sees no file in `.vscode`                  |
| walk cost, in program    | `file_open` over the pairs' 10,000 opens for writing at depth 11:     |
|                          | 40.5 µs mean, 2.10 ms at most (37.3 µs and 1.21 ms in the last run of |
|                          | 2026-10-24)                                                           |
| walk cost, syscall       | five pairs as on macOS, policy minus bare: the open for writing +139, |
|                          | −66, +6, −186 and −87 µs, median −66; the open for reading −284 to    |
|                          | +24, median −29; `lstat` −659 to +120, median −178; the bare write    |
|                          | open 10.64 to 10.97 ms (the runs of 2026-10-24: medians −202 and −564 |
|                          | µs for the write open), so 9p's jitter within a pair exceeds the      |
|                          | walk's cost in every run and the program's timer alone gives it       |
| container start          | with `file_receive` attached, the runtime passes 10 descriptors, all  |
|                          | passed, and the first process holds no descriptor beyond the standard |
|                          | three. In the runs of 2026-10-24 the volume mountpoint arrived as an  |
|                          | `open_tree` clone, an anonymous namespace whose root is the volume    |
|                          | directory and whose inode number is 0xEFFFFFF7, the receiver `crun`   |
|                          | still at the host's root                                              |
| container start, refused | the runs of 2026-10-24 before that number was known: the clone's      |
|                          | namespace was neither the controller's nor pid 1's, which are one on  |
|                          | this machine, and carried neither anonymity field the program looked  |
|                          | for                                                                   |
| second share             | no `D:` drive on the machine; not measured                            |
| descriptors              | every row as on macOS but the host FIFO's, skipped as 9p made no      |
|                          | FIFO; B's `file_receive` over the rows: 87 calls, 80 of the           |
|                          | runtime's, 4 allowed, 3 denied                                        |


### Lifecycle on macOS

Measured on 2026-10-29 with `../test/podman/lifecycle/Lifecycle.scala` on the machine of "One hook
on macOS", podman 6.1.2, crun 1.30, clang 19.1.7, `policy.bpf.o` of SHA-256
`81b80f90f32c1c751b4a8904c498e57c592a297317377b121367c8eac00b14f0`, the object "Policy on macOS"
measures, built again byte for byte, beside `other.bpf.o` of SHA-256
`40e11723b1709a982062f31d438ec09f28de09a041cb32e7a1a7490b66bfa62b`, the same source counting each
call twice in its statistics, which stands for another build, and `other-data.bpf.o` of SHA-256
`4901d9e57541470a03087e9fc039b55b89068896fdeac7805b4a135b86dac341`, the source with one string
literal of the same length changed, whose instructions and tags equal the installed object's; all
built from sources of code digest `4c2db67893e30bc12114655d2d96045b42453aeac71f3788aad248901c655b09`
(`sources.txt` lists them in digest order; `../test/SourceDigestCheck.scala` recomputes it): the
program with the FIFO rules and the launcher's controller, read-back and fixture, from `../`, the
controller freezing the record maps, and the suite's `rewrite.c`, which writes to them. Every one of
the 71 rows passes in one run, the four machine-restart rows among them. The containers run as in
the every-hook suite; fourteen launches ran through the launcher's steps 1 to 4, and the reconcile's
rows ran the controller's attach alone nine times. A fact of the runs of 2026-10-25, under the
program before the FIFO rules, is kept as a reason for them and named as such.

| row                      | measured                                                              |
| ------------------------ | --------------------------------------------------------------------- |
| install                  | the read-back loads the nine programs once and records their tags and |
|                          | the read-only data's 758 bytes: 553 ms                                |
| step 2 at launch         | over the twenty-two attaches that loaded, the controller's load took  |
|                          | 389 to 513 ms, filling and freezing the maps 0.1 ms, the eight or     |
|                          | nine attaches 0.4 to 0.7 ms, once 1.7 ms                              |
| step 2 at a recreate     | the pinned programs checked in 16 ms and attached to the new cgroup   |
|                          | in 0.3 ms, nothing loaded; the old links read cgroup_id 0 after their |
|                          | cgroup went, the programs stayed pinned                               |
| step 3                   | the read-back 14 to 18 ms: eight programs, nine maps (the eight of    |
|                          | the policy and the string literals' read-only map, its bytes the      |
|                          | installed object's), five roots, 56 rules, the four record maps       |
|                          | frozen; the proof's 68 operations (69 under `unix-socket`, 67 under   |
|                          | the launcher's defaults alone) 39 to 50 ms, 0 mismatches, in a scope  |
|                          | under the slice                                                       |
| the record maps          | root's write of each map's first entry back unchanged, through the    |
|                          | pinned program's map ids: `EPERM` from `roots`, `rules`, `aliases`    |
|                          | and `policy_config`, success on `stats`; the read-back passes after   |
|                          | it, and the recreate's check finds the four frozen                    |
| the session              | the first process is refused `.git/config` and writes an ordinary     |
|                          | file; `podman exec` is refused; after `podman restart` the first      |
|                          | process is refused again; after `podman kill` the container is exited |
|                          | and the eight programs stay attached, the link naming the cgroup; the |
|                          | restart policy reads `no`                                             |
| identity                 | each link's cgroup_id is the attach cgroup's inode number             |
| the controller           | exited before the container started; no process of it remains         |
| sockets and mounts       | a socket bound under the container's `/tmp`; `rename` of that         |
|                          | directory into the volume and into the workspace answers `EXDEV`      |
| the policy cannot lapse  | `rmdir` of the attach cgroup with the container in it: `EBUSY`;       |
|                          | root's unpin of the links: 0 programs attached and the protected      |
|                          | write succeeds                                                        |
| defective controllers    | seven hooks: `hook-set attached=7 expected=8`; the other build: `tag` |
|                          | on `file_open`; the build differing in data alone: `rodata`, its 758  |
|                          | bytes differing from the installed object's under equal tags; another |
|                          | rule file's records: `map-contents rules index=55`; one leaving the   |
|                          | record maps unfrozen: `map-frozen` on `roots`; no container exists    |
|                          | after any; the proof alone catches the records too, one mismatch      |
|                          | (`.vscode/settings.json`)                                             |
| `unix-socket`            | nine hooks attached and verified; the proof's `bind` in `.git`        |
|                          | refused, and a directory descriptor sent from a mount namespace of    |
|                          | the sender's own refused on arrival                                   |
| pins across a rule       | the check finds `map-contents rules index=55`, the pins go and fresh  |
| change                   | programs load with new ids                                            |
| pins across a new build  | with the other object installed and its tags recorded, the check      |
|                          | finds `tag`; fresh programs of the new build load and verify; the pin |
|                          | directory holds this launch's eight links and eight programs alone    |
| the controller's         | an object given as a path, a cgroup outside the user's slice, a tmpfs |
| refusals                 | mounted at `tree/vendor` under the bind source, a proof fixture on    |
|                          | tmpfs: each `refused reason=...`, status 3, nothing pinned            |
| the reconcile            | a listing that fails (`podman ps` made to fail) is reported and keeps |
|                          | all five sessions; the launcher killed before `podman create` and a   |
|                          | `podman create` that failed: pins and slices removed; a created, a    |
|                          | stopped and a live container keep theirs; the created one's go once   |
|                          | it is removed                                                         |
| contradicting identities | a container whose label names another cgroup: kept, unassociated; a   |
|                          | cgroup recreated at its path (inode 52865, then 53780): refused; a    |
|                          | pin directory renamed to another session's name: refused by its       |
|                          | links' cgroup id; nothing removed                                     |
| cleanup refusals         | a session name and a cgroup path with `..`; a symlink in place of the |
|                          | pin directory (`ELOOP`); a tmpfs mounted on it (`EXDEV`); a recorded  |
|                          | identity off by one; each refused, nothing removed. cgroup2 refuses a |
|                          | symlink in place of a cgroup directory with `EPERM`                   |
| a refusal removes        | one foreign link among a session's eight: refused, its 9 links and 8  |
| nothing                  | programs all surviving; a programs directory that is a symlink        |
|                          | (`ELOOP`): refused, all 8 links surviving                             |
| machine restart          | `podman machine stop` 62 s, `start` 12 s; the pin root is gone with   |
|                          | bpffs, the attach cgroups are gone, the two containers stay exited    |
|                          | and the reconcile keeps both, since their containers name them        |
| bpffs                    | holds symlinks and renames of pin directories                         |
| FIFO                     | the proof's `mkfifo` at an ordinary name answers `EPERM` under the    |
|                          | FIFO rules. On 2026-10-25, before them, the same `mkfifo` passed      |
|                          | `inode_mknod`, which judged a socket by type and any other node by    |
|                          | name, and the FIFO left on the share preceded a `podman machine stop` |
|                          | that did not return                                                   |


### Lifecycle on WSL

Measured on 2026-10-29 with `../test/podman/lifecycle/Lifecycle.scala` on the Windows machine of
"One hook on WSL", podman 6.1.4 under the cgroupfs manager, crun 1.28, clang 19.1.7, `policy.bpf.o`
of SHA-256 `463cfe8660a9f165cdff072bcf99efd47edbb9d82596030ecd337841ee2bd0a5`, the object "Policy on
WSL" measures, built again byte for byte, beside `other.bpf.o` of SHA-256
`43af7b4d6bb547246b8cc6728d956059c699111f9d2112aa0eaf214802ae7ab4` and `other-data.bpf.o` of SHA-256
`7099595b9d5d308eadb99538a915ecdd2fce7980e2a60ed140485fff4f7eb78f`; all built from sources of code
digest `4c2db67893e30bc12114655d2d96045b42453aeac71f3788aad248901c655b09`, those "Lifecycle on
macOS" measures. Every one of the 71 rows passes in one run, the four machine-restart rows among
them. The rows below name what differs from macOS; every other row passed as there, the reconcile
removing the cgroup directories itself under cgroupfs.

| row                      | measured                                                              |
| ------------------------ | --------------------------------------------------------------------- |
| install                  | the tags and the read-only data recorded in 2.03 s                    |
| step 2 at launch         | over the twenty-two attaches that loaded, the load 1.53 to 1.91 s,    |
|                          | filling and freezing 0.1 to 3.8 ms, the attaches 12.5 to 19.5 ms in   |
|                          | twelve and 0.2 to 0.6 ms in the other ten                             |
| step 2 at a recreate     | the pins checked in 43 ms and attached in 18 ms                       |
| step 3                   | the read-back 27 to 56 ms; the proof's 68 operations (69 under        |
|                          | `unix-socket`, 67 under the launcher's defaults alone) 339 to 372 ms  |
|                          | on 9p, 0 mismatches; its `mkfifo` and `bind` answer `EPERM`, the      |
|                          | policy's, since 9p answers both after the hooks                       |
| the proof's cgroup       | a process of the ssh session cannot join the leaf below the attach    |
|                          | cgroup: on 2026-10-25 writing its `cgroup.procs` answered `EACCES`,   |
|                          | since the move needs write access to the common ancestor's            |
|                          | `cgroup.procs` and the session's cgroup shares no ancestor the user   |
|                          | owns with the delegated subtree. From a transient scope of the user   |
|                          | manager, `app.slice/run-*.scope`, the join into                       |
|                          | `app.slice/<attach>/proof` works on every launch, the ten of this run |
|                          | among them. A launcher reaching the machine over ssh takes that step  |
| sockets and mounts       | `rename` of the socket's directory into the volume (ext4) and into    |
|                          | the workspace (9p) answers `EXDEV`                                    |
| machine restart          | `podman machine stop` 2 s, `start` 8 s; the rows as on macOS          |


### Benchmark on macOS

Measured on 2026-10-29 with `../test/podman/benchmark/Benchmark.scala` on the machine of "One hook
on macOS", podman 6.1.2, crun 1.30, clang 19.1.7, `policy.bpf.o` of SHA-256
`81b80f90f32c1c751b4a8904c498e57c592a297317377b121367c8eac00b14f0`, the object "Policy on macOS" and
"Lifecycle on macOS" measure, built again byte for byte, from sources of code digest
`eff6c014187840184e409bd26b5bda2ee124d0f62dfb9a7be809df804beca47c`. The tree is sbt/sbt at
`09a886e3`, 4,509 tracked files at mean depth 7.0 among 8,004 entries, the corpus `entry-cost.py`'s
2,101 entries, and the build a clone of this repository at the tree's root, under the launcher's
default rules, 55 lines. Every one of the 26 rows passes in one run. The three stacks run the
sandbox image with the session's user mapping, the policy's containers below the attach cgroup, the
filter's through the launcher under `--workspace=live,fuse`; `entry-cost.py` ran three rounds a
stack, interleaved, after one round on the bare bind before the launch; the figures are the mean,
with the range, over the rounds. A live session of the backend held its eight links throughout, so
the shim was installed in every round; the bare bind's control is the run of 2026-10-25, under the
program before the FIFO rules, named as such.

| row                      | measured                                                              |
| ------------------------ | --------------------------------------------------------------------- |
| the launch               | load 469 ms, attach 0.6 ms, read-back 14.1 ms, the proof's 67         |
|                          | operations 37.3 ms, 0 mismatches; a hook file in `.git/hooks` made on |
|                          | the bare bind, refused under the policy and through the filter        |
| the bare bind, µs an     | this run, with a live session's eight links attached and so the shim  |
| entry                    | installed: `find` 72, `find -printf` 156, `ls -lR` 694, `cp -r`       |
|                          | 1,204, `rm -rf` 326, each inside the range of the bind's rounds but   |
|                          | `rm -rf`, above the bind's 284 to 307 and inside the policy's 302 to  |
|                          | 326. On 2026-10-25, before the launcher could start a session of the  |
|                          | backend, with nothing under the suite's pin root (other attachments   |
|                          | not checked): 76, 167, 719, 1,258, 342, each inside the range of that |
|                          | run's bind rounds: the shim the first attach installs costs tasks     |
|                          | outside the cgroup nothing the rounds' spread shows                   |
| `entry-cost.py`, µs an   | `find`: bind 71 (68 to 75), policy 72 (67 to 75), filter 384;         |
| entry, bind / policy /   | `find -printf`: 153 (145 to 161), 151 (150 to 151), 1,247; `ls -lR`:  |
| filter                   | 685 (677 to 700), 685 (666 to 705), 12,119; `cp -r`: 1,182 (1,125 to  |
|                          | 1,214), 1,181 (1,171 to 1,188), 8,555; `rm -rf`: 298 (284 to 307),    |
|                          | 316 (302 to 326), 2,267. Policy over bind 0.99 to 1.06 times over     |
|                          | overlapping ranges in every row; filter over bind 5.4 to 17.7 times,  |
|                          | as "The cost of a path walk" measured in 2026-09                      |
| the program's share of a | 3,600 judged calls each of `file_open`, `inode_create` and            |
| `entry-cost.py` round    | `inode_unlink` (the corpus's 1,800 files made, copied and removed     |
|                          | twice over), 126, 32 and 36 more answered at the superblock check,    |
|                          | every walk 4 deep and none retried or without a slot; one create      |
|                          | refused a round, the suite's own hook file in `.git/hooks`; 15.0 to   |
|                          | 15.5 µs mean from entry to decision, 0.08 ms at most: the three       |
|                          | hooks' 10,800 judged calls take 164 to 165 ms of a round's 8 to 9 s   |
| the build                | `sbt 'testOnly *SandboxTextWidthTest'`, output in the workspace: bind |
|                          | 87 s wall, sbt's own 58 s; policy 84 s, 55 s; 10 of 10 tests under    |
|                          | both. The policy judged 1,717 opens, 1,379 creates, 210 renames (420  |
|                          | walks, source and destination), 106 unlinks and 508 attribute         |
|                          | changes, walks up to 20 deep, 40 to 46 µs mean a call and 91 for a    |
|                          | rename, 0.14 ms at most; it refused 4 symlinks at depth 7, the        |
|                          | absolute targets "The policy" refuses as the filter refuses sbt's     |
|                          | links into its cache, under which sbt writes copies ("sbt over        |
|                          | dangling cache links"); the machine 21 % busy mean, 46 % max, memory  |
|                          | used rising to 2.9 GB under both, from 1.0 and 1.2                    |
| `walk-cost.py`, bind /   | `lstat` by path: depth 1 0.09 / 0.09 / 0.59 ms, depth 7 0.33 / 0.37 / |
| policy / filter          | 5.29 ms, depth 15 0.68 / 0.67 / 16.1 ms; every tracked file by path   |
|                          | 0.34 / 0.36 / 5.44 ms a file, through a directory fd 0.09 / 0.09 /    |
|                          | 1.37 ms; `find . -type f` 1.9 / 1.9 / 13.8 s; `git status` 3.8 / 3.8  |
|                          | / 69.1 s, `--untracked-files=no` 0.9 / 0.9 / 38.8 s. The depth rows,  |
|                          | 200 `lstat` each of 0.1 to 1 ms, scatter 0.92 to 1.12 times policy    |
|                          | over bind, the per-file rows 1.06 and 1.00; the policy judged 4       |
|                          | opens, 4 creates and 4 unlinks in the whole run, git's lock at depth  |
|                          | 2, 16 to 20 µs each; the filter's figures lie near "a real tree" of   |
|                          | 2026-09-19 (5.97 ms a file, 71.5 s)                                   |
| the machine during the   | `/proc/stat` over the run, ten CPUs: bind 8 % busy mean, 20 % max     |
| stat storm               | over 31 s; policy 8 %, 21 % over 25 s; filter 6 %, 19 % over 484 s;   |
|                          | no iowait; memory used 1.0 to 1.5 GB of 11.9 GB under each, memory    |
|                          | pressure `some avg10` 0.00 throughout, io at most 0.18                |
| the machine during       | bare, bind and policy 5 to 7 % busy mean, 6 to 14 % max over 8 to 9 s |
| `entry-cost.py`          | a round; filter 7 % mean, 19 to 21 % max over 76 s a round            |
| the probe's own label    | `entry-cost.py` reports `unfiltered bind mount`, `BPF policy` and     |
|                          | `filtered`: it tells the policy from the bind by a hook file in       |
|                          | `.git/hooks`, which the policy refuses by name and allows the         |
|                          | directory ("Directories")                                             |
| the attach cgroup        | under the systemd manager the slice `ko-agent-bpf5-policy.slice` lies |
|                          | below `ko.slice/ko-agent.slice/ko-agent-bpf5.slice`, the hierarchy    |
|                          | systemd reads from a slice name's dashes                              |

### Benchmark on WSL

Measured on 2026-10-29 with `../test/podman/benchmark/Benchmark.scala` (`scala shebang`) on the
Windows machine of "One hook on WSL", podman 6.1.4 under the cgroupfs manager, crun 1.28, clang
19.1.7, `policy.bpf.o` of SHA-256
`463cfe8660a9f165cdff072bcf99efd47edbb9d82596030ecd337841ee2bd0a5`, the object "Policy on WSL" and
"Lifecycle on WSL" measure, built again byte for byte, from sources of code digest
`eff6c014187840184e409bd26b5bda2ee124d0f62dfb9a7be809df804beca47c`, those "Benchmark on macOS"
measures. The tree is sbt/sbt at `09a886e3`, 4,509 tracked files, the corpus and the build as on
macOS, the machine of four CPUs and 7.8 GB on the 9p share. Every one of the 26 rows passes in one
run, whose workloads took 2 h 19 min, the filter's `walk-cost.py` 77 min of it. No session of the
backend was live and nothing was pinned under the launcher's pin root, so the bare round is the
shim's control. The rows below name what differs from macOS; the stacks and the rounds are the same.

| row                      | measured                                                              |
| ------------------------ | --------------------------------------------------------------------- |
| the launch               | load 1,914 ms, attach 19.0 ms, read-back 39.7 ms, the proof's 67      |
|                          | operations 341 ms on 9p, 0 mismatches; the attach cgroup a directory  |
|                          | under `app.slice`, the proof joined from a transient scope            |
| the bare bind, µs an     | before the launch, no link of any session attached: `find` 609,       |
| entry                    | `find -printf` 1,530, `ls -lR` 3,149, `cp -r` 14,430, `rm -rf` 1,934; |
|                          | each inside the range of the bind's rounds but `cp -r`, 70 above it   |
|                          | in this first round after the clone (iowait 6 %, io pressure 74.7):   |
|                          | the shim the first attach installs costs tasks outside the cgroup     |
|                          | nothing the rounds' spread shows                                      |
| `entry-cost.py`, µs an   | `find`: bind 651 (597 to 699), policy 639 (599 to 671), filter 3,423; |
| entry, bind / policy /   | `find -printf`: 1,528 (1,462 to 1,635), 1,505 (1,365 to 1,579),       |
| filter                   | 12,076; `ls -lR`: 3,056 (2,940 to 3,234), 3,139 (3,013 to 3,212),     |
|                          | 96,491; `cp -r`: 13,472 (13,017 to 14,360), 13,929 (13,648 to         |
|                          | 14,182), 71,326; `rm -rf`: 1,825 (1,716 to 2,034), 1,831 (1,748 to    |
|                          | 1,985), 19,733. Policy over bind 0.98 to 1.03 times over overlapping  |
|                          | ranges in every row; filter over bind 5.3 to 31.6 times               |
| the program's share of a | the same 3,600 judged calls a hook, 6, 10 and 0 answered at the       |
| `entry-cost.py` round    | superblock check, every walk 4 deep, the suite's own hook file        |
|                          | refused once a round; 12.7 to 14.5 µs mean from entry to decision,    |
|                          | 0.73 ms at most once: 148 to 149 ms of a round's 74 to 78 s           |
| the build                | bind 318 s wall, sbt's own 250 s; policy 316 s, 244 s; 10 of 10 tests |
|                          | under both. The policy judged 1,745 opens, 1,775 creates, 210 renames |
|                          | (420 walks), 107 unlinks and 752 attribute changes, walks up to 20    |
|                          | deep, 42 to 65 µs mean a call and 89 for a rename, 3.8 ms at most; it |
|                          | refused 3 symlinks at depth 7, as on macOS; the machine 33 and 35 %   |
|                          | busy mean, 84 and 93 % max, memory used rising from 0.6 to 2.3 GB     |
|                          | under both                                                            |
| `walk-cost.py`, bind /   | `lstat` by path: depth 1 1.14 / 0.94 / 3.99 ms, depth 7 6.02 / 5.70 / |
| policy / filter          | 53.3 ms, depth 15 12.0 / 11.4 / 189.5 ms; every tracked file by path  |
|                          | 5.86 / 5.48 / 54.8 ms a file, through a directory fd 1.06 / 1.02 /    |
|                          | 15.7 ms; `find . -type f` 15.6 / 15.4 / 161.3 s; `git status` 22.1 /  |
|                          | 21.7 / 674.4 s, `--untracked-files=no` 10.9 / 11.0 / 388.9 s. Policy  |
|                          | over bind 0.82 to 1.06 times on the depth rows, 0.94 and 0.96 per     |
|                          | file, 0.98 to 1.01 on the commands; the policy judged 4 opens, 4      |
|                          | creates and 4 unlinks, 16 µs each; the bare 9p bind costs 6 to 18     |
|                          | times the macOS virtiofs bind, and the filter 3.5 to 36 times the     |
|                          | bind on top                                                           |
| the machine during the   | four CPUs: bind 14 % busy mean, 37 % max over 364 s; policy 17 %, 36  |
| stat storm               | % over 246 s; filter 14 %, 55 % over 4,649 s; iowait at most 5, 5 and |
|                          | 15 %; memory used 0.56 to 0.71 GB of 7.8 GB under each, memory        |
|                          | pressure `some avg10` at most 0.14, 0.00 and 3.19; io pressure at     |
|                          | most 1.8, 1.2 and 5.1                                                 |
| the machine during       | bind and policy 13 to 14 % busy mean, 16 to 18 % max over 71 to 79 s  |
| `entry-cost.py`          | a round, the bare round 172 s; filter 14 to 15 % mean, 55 to 62 % max |
|                          | over 604 to 641 s a round, with iowait peaks of 20 to 39 %; memory    |
|                          | pressure at most 0.37 under bare, bind and policy, 1.08 under the     |
|                          | filter                                                                |


### Launcher on macOS

Measured on 2026-10-30 with `../test/podman/launcher/Launcher.scala` on the machine of "One hook on
macOS", podman 6.1.2, crun 1.30, through the launcher's jar from `sbt dist` and its `--build`, the
installed backend that of "Lifecycle on macOS", from sources of code digest
`888a45d5aad487ed37a68962911173a9d0d8cae4014efc325ce3bfcb952f7d91` (`sources.txt`: the backend and
`KoAgentBpf.scala`, the launcher's side of it). Every one of the 61 rows passes in one run of 57
launches, each a `java -jar` of the launcher from a scratch git repository under `~`, with no other
session on the machine; the `codex exec` row, which needs a signed-in Codex, ran by hand.

| row                      | measured                                                              |
| ------------------------ | --------------------------------------------------------------------- |
| `io_uring_setup`         | answers `ENOSYS` to the session's first process and to a              |
|                          | `podman exec` process                                                 |
| the preloaded set        | every launch took one: attached in 0.0 to 0.1 ms, read back in 13.2   |
|                          | to 14.4 ms, tested in 28.2 to 49.4 ms; the read-back finds the taken  |
|                          | set's records the launch's and the four record maps frozen, and the   |
|                          | next set prepared, passing its check, unfrozen. A live session's      |
|                          | records read back the same before and after another launch took a     |
|                          | set, the two sessions' eight program ids disjoint; two launches       |
|                          | racing both took one, their programs disjoint                         |
| a launch finding none    | with the preloaded set removed, the launch took the one its own       |
|                          | reconcile prepared at the launcher's start                            |
| another build installed  | with the lifecycle suite's `other.bpf.o` in the installed object's
place and its  | |                          | tags recorded, a launch ran and its read-back passed
against the new  | |                          | tags, so the set of the earlier build was not
attached; it took a set | |                          | of the new build. The installed object
restored by SHA-256            | | a launch dead after the  | a session's record, its attach cgroup
and the taken set's programs    | | take                     | attached there with no container: the
next launch's reconcile removed | |                          | the pins, the record and the cgroup  
                                | | `unix-socket` session    | a `podman exec` process starts under
`file_receive` and is refused    | |                          | the write to `.git/config`; after
`podman restart` the container runs | |                          | again, its `podman exec` process
starts and is refused again          | | the linked worktree      | the main checkout's session
binds a socket in its tree, and a         | |                          | host-made `.git/objects/s`
links to it as `../../sock`: the main      | |                          | session connects through
the link; the linked worktree's session,     | |                          | beside it under the same
settings, answers `ENOENT`, the main tree    | |                          | not being mounted there 
                                             | | a FIFO the host made     | the session's `lstat` of
it answers `EACCES`: the share refuses it    | |                          | before any hook, the
policy having none on `lookup` or `getattr`      | | the refusals             | one workspace with
two volumes, a main checkout and its linked        | |                          | worktree sharing
its volume, a workspace below another's root, a      | |                          | linked worktree
with its own volume beside its main checkout, and a   | |                          | host rename of
the workspace between the launches: each refused       | |                          | beside a live
session of the other backend and of the other           | |                          | `unix-socket`
setting, in both orders, 20 refusals; beside an         | |                          | unlabelled
container named as the launcher's, a `bpf` launch refused  | |                          | and a
filter launch run; of two launches of one workspace under the   | |                          | two
backends racing, one ran and one was refused; a second session of | |                          | one
workspace under the same backend and setting ran                  | | in a session             |
measured on 2026-10-26 in a `live,bpf,unix-socket` session: a socket  | |                          |
bind on the share and beneath the volume, and a bind, rename and link | |                          |
into `.git` and a bind in `.ko-agent-sandbox` refused, a share        | |                          |
descriptor passed over a socketpair inside the session                | | `codex exec`             |
by hand on 2026-10-30 in a `live,bpf` session, Codex 0.165.0 signed   | |                          |
in: `codex exec` answered, the socket of its app-server daemon under  | |                          |
`~/.codex` removed first; no socket lay under `~/.codex` or the       | |                          |
persistent volume after it, and a socket bind beneath the volume in   | |                          |
the same session answered `EPERM`, the policy's refusal               | | the kernel's memory      |
program sets loaded with the installed controller's `preload` into    | |                          |
one cgroup kept for the measurement, unattached: 1,542 to 1,544 KiB a | |                          |
set, nine programs and their maps, at one, four and eight sets        | |                          |
(`memory.current` 208,896 bytes before, 12,840,960 at eight), and     | |                          |
225,280 after their removal                                           |


### Launcher on WSL

Measured on 2026-10-30 with `../test/podman/launcher/Launcher.scala` (`scala shebang`) on the
Windows machine of "One hook on WSL", podman 6.1.4 under the cgroupfs manager, crun 1.28, through
the launcher's jar and its `--build`, the installed backend that of "Lifecycle on WSL", from sources
of code digest `888a45d5aad487ed37a68962911173a9d0d8cae4014efc325ce3bfcb952f7d91`, those "Launcher
on macOS" measures. Every one of the 43 rows passes in one run of 30 launches. The rows below name
what differs from macOS; every other row passed as there.

| row                      | measured                                                              |
| ------------------------ | --------------------------------------------------------------------- |
| the preloaded set        | every launch took one: attached in 0.1 ms, read back in 23.1 to 28.8  |
|                          | ms, tested in 231 to 338 ms on 9p                                     |
| the proof's cgroup       | on every launch the launcher's own proof joined the leaf below the    |
|                          | attach cgroup from a transient scope of the user manager, as          |
|                          | "Lifecycle on WSL" measured of the suite's; a scope that cannot be    |
|                          | made or a join that fails ends the launch script with status 4 before |
|                          | its placement step, which `KoAgentBpfTest` runs with those failures   |
|                          | stubbed                                                               |
| `unix-socket` session    | after `podman restart` the container ran again under `file_receive`,  |
|                          | then the launcher's cleanup removed it, its `podman wait` having      |
|                          | returned at the restart's stop, and the session's pins went with it   |
| the linked worktree      | not measured: the share answers a socket bind `ENOTSUP`, so no socket |
|                          | lies in the main checkout's tree                                      |
| a FIFO the host made     | not measured: NTFS makes none                                         |
| the refusals             | the cases without a linked worktree or a host rename, 8 refusals, as  |
|                          | on macOS. A linked worktree's launch is refused by the guard for the  |
|                          | worktree's absolute pointer (`../../../doc/TODO.md`, "Deferred — a   |
|                          | linked worktree's absolute pointer on Windows"), and the host refuses |
|                          | to rename a directory a live session's share holds                    |
| in a session             | measured on 2026-10-27 in a `live,bpf,unix-socket` session, the rows  |
|                          | of macOS's; the share's `ENOTSUP` answers every bind on it, so the    |
|                          | share rows measure the share, not the policy. A launch took the       |
|                          | preloaded set, attached in 0.1 ms, read back in 20.3 ms, proved in    |
|                          | 269.2 ms                                                              |
| `codex exec`             | as on macOS, by hand on 2026-10-30, Codex 0.165.0                     |
| the kernel's memory      | 1,539 to 1,540 KiB a set (`memory.current` 0 bytes before, 12,611,584 |
|                          | at eight), and 4,096 after their removal                              |


