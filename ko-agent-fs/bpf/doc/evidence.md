# The BPF backend's evidence

This document records what the suites measured of the backend that
`../../../doc/bpf-lsm-cgroup.md` promises, on the podman machines of macOS and Windows, and how to
measure it again.

Each suite lists its sources in a `sources.txt` under `../test/podman/`. When the code of one of
those sources changes:

- rerun that suite on both machines;
- rewrite its sections below from the reruns, naming the new sources digest.

The change need not wait for the rerun, and several changes can wait for one rerun. Until the rerun,
the check below fails for that suite, and `../../../doc/TODO.md`, "BPF suite reruns", lists the
suite. Rerun the listed suites before a release.

A comment edit needs no rerun: the digest covers the sources' code, without their comments
(`../../../src/main/scala/SourceDigest.scala`). Run the check from the repository root:

```sh
ko-agent-fs/bpf/test/SourceDigestCheck.scala
```

On Windows, where no shebang runs, the check is
`scala shebang ko-agent-fs\bpf\test\SourceDigestCheck.scala`.

- The check fails while a section names a digest that its suite's sources no longer have. A
  section therefore stands only for the code in the tree.
- No marker lets a section stand for superseded code, by the user's decision of 2026-10-26: every
  later change of the program, the Rust port among them, would reuse such a marker.

This document, `../../../doc/bpf-lsm-cgroup.md` and `architecture.md` use distinct section names.
A quoted section name without a document therefore names the one of the three that holds it.


## Suites

Each suite below lists what it measures and its gate. A rerun must pass the gate as the first run
did.

The one-hook and every-hook suites are retired and not rerun. Their drivers are in the tree of
commit 654586d (`bpf/probe/phase1/`, `bpf/probe/phase2/`).

- The one-hook suite asked whether a cgroup-attached LSM program loads and denies on each
  machine's kernel. The launcher's capability probe asks this at every launch
  (`KoAgentBpf.checksScript`), and the policy suite shows it.
- The every-hook suite inventoried what each hook sees and what each share answers. The policy
  suite's corpus exercises this, and the every-hook sections record it. The every-hook suite's
  measured columns fill the design document's "Inventory".

- **One hook**, retired: one denial.
  - The program: a `lsm_cgroup/file_open` program denies the open for writing of one marker name.
    The controller attaches it to a disposable cgroup, once of the shape in "Lifecycle" and once of
    the rejected shape, and then starts a disposable container under it.
  - Denial and isolation: the marker is refused and other files are not; a sibling container
    outside the cgroup opens the marker; a second attached cgroup shares the slot; a deliberately
    failed attach starts no container.
  - Identity, on each share and on both kernels:
    - a directory's and a file's `(superblock, i_ino)` in the guest stay the same after a host
      rename of the object and of an ancestor, after the guest drops its caches, and for the two
      names of a host-made hard link;
    - they differ from a host-made replacement at the same name;
    - the identity that the controller's `statx` records equals the one an attached program reads
      from the object's inode ("The policy");
    - `findmnt` records the share's backend and options first, since 9p without metadata caching
      makes a new inode per lookup and takes `i_ino` from the QID alone (`fs/9p/vfs_inode.c`,
      `v9fs_get_new_inode_from_fid`).
  - The verifier's time to load the eight programs, nine with `unix-socket`, with the `rename_lock`
    read and its fetch-add barrier ("What is gained and what is lost") in the walk.
    `bpftool prog dump jited` shows the barrier instruction on each architecture.
  - Under the attach cgroup, with the installed crun ("Lifecycle", 1): a `createContainer` hook
    (`podman --hooks-dir`) records its `/proc/self/cgroup` and opens the marker for writing. The
    open must fail with `EPERM`, and the recorded cgroup must lie below the attach cgroup.
  - The attach cgroup's `cgroup.events` reads `populated 1` with a container below it and no task
    of its own, and `populated 0` after the container stops ("Lifecycle", 7).
  - Whether the manager removes the empty slice within 60 s.
  - The order: macOS first, then WSL.
  - The driver was `bpf/probe/phase1/phase1.sh`, `phase1.ps1` on Windows, run on the host. Its
    transcript is this suite's record. Its programs are C with libbpf, not the classifier's Rust,
    since the suite measures the kernel and not the port.
  - Gate: inheritance, denial, isolation, fail-closed start, stable identities, and the hook's
    refused open below the attach cgroup, on both kernels.
- **Every hook**, retired.
  - The candidate programs run on a disposable tree of the real share. The exerciser covers each
    syscall of the inventory, `openat2`, descriptor-relative calls, `RENAME_EXCHANGE`, `setfacl`,
    `setxattr`, `chattr` and row 18's commands; an overlay mount whose upper layer is in the tree;
    a host-side mount inside the tree; and ordinary git.
  - It records the verifier's answer per hook per kernel, which attribute routes and ioctl
    commands each share accepts, and the cost of the bounded ancestry walk at the real tree's
    depths on both kernels. The policy's price is then known before the classifier and the
    lifecycle are built.
  - A representative program, loaded on both kernels and run at the real tree's depth and at the
    walk's bound, holds together:
    - the bounded walk, twice, as `inode_rename` walks its source and its destination;
    - the folding;
    - the ordered rule match over a rule map filled to its `max_entries`;
    - the git-context transitions;
    - the `rename_lock` read.
  - Its record: the verifier's log, its instruction count and stack depth, clang's version and the
    object's hash.
  - Why it is loaded:
    - only loading, not reading, shows that a program meets the verifier's instruction budget and
      512-byte stack (`include/linux/bpf.h`, `BPF_COMPLEXITY_LIMIT_INSNS`;
      `include/linux/filter.h`, `MAX_BPF_STACK`);
    - `policy.rs`'s `fold` and `child_context` allocate, so the port is written allocation-free
      with bounded loops before the policy suite ports the rest.
  - The driver was `bpf/probe/phase2/phase2.sh`, `phase2.ps1` on Windows, run on the host. Its
    transcript is this suite's record:
    - `inventory.bpf.c` records which of 33 hooks each operation of the exerciser (`mutate.c`)
      reaches, and refuses the operation on a deny name. It attaches in batches of eight, which
      keep a hook whose refusal a row claims apart from the hooks the same operation reaches
      first.
    - `classify.bpf.c` is the representative program. Its loops are the kernel's numeric-iterator
      loops (`bpf_iter_num_*`, Linux 6.4). The verifier checks them by the convergence of the
      loop's state rather than by simulating each iteration (`kernel/bpf/verifier.c`,
      `process_iter_next_call`).
    - The program decides a corpus of 51 cases on a fixture laid out as a workspace, under the
      defaults' rules with filler lines filling the 128-line rule map, and ordinary git in a clone
      of this repository.
    - The exerciser's open loops give the walk's cost at the clone's deepest file, at depth 32 and
      at depth 63, under the policy and on the bare bind.
    - What the program leaves to the policy suite is listed at its end.
  - xfs's and btrfs's ioctl commands are read into row 18.
  - For the later version, measure the following before the user takes the decisions on open
    routes:
    - whether a nested podman under `NESTING=same-uid` needs the xattr syscalls, `file_setattr` or
      the refused ioctl commands while it pulls and extracts an image, creates, runs and execs
      into a container, and removes both;
    - whether each share stores a `security.capability` set and removed from a user namespace the
      session creates.
  - Gate:
    - the inventory's macOS and WSL columns are complete;
    - every route of the first version's sessions, row 20's `user.overlay.*` names included, is
      held by its slot, or by the seccomp rules that "Attributes, flags and ioctls" and "Mounts"
      name, or is covered by a decision taken for it, such as "Directories";
    - the walk's cost is recorded beside the plain bind's;
    - the representative program loads on both kernels.
- **Policy** (`../test/podman/policy/`). It measures:
  - the classifier in the programs, with what the every-hook suite left to it ("The policy"): the
    guarded objects' identities, the alias contexts, the short-name form, the symlink target
    rules, `file_receive` and the walk's state against reentry;
  - the classifier's host build, and the corpus run through both classifiers ("What is gained and
    what is lost");
  - the map compiler in the guard (`../../policy/src/bpf_records.rs`). It produces the records
    that "The policy" describes, in one layout, and generates from that layout the C header
    `../../policy/include/records.h`, which a test compares with the committed file;
  - the FUSE backend's test corpus, transcribed into the suite's corpus, each case naming the test
    it transcribes (`../../policy/doc/git-metadata.md`, "Test list";
    `../../fuse/tests/mounted_*.rs`). The cases are transcribed because those tests mount the FUSE
    backend over a backing tree they write directly, which under the policy is a process outside
    the cgroup, and because they read `mkdir` as judged, which "Directories" does not.
  - The walk's per-CPU slots ("The policy") replace the every-hook suite's per-CPU state. Each
    kernel's preemption mode is read from `/sys/kernel/debug/sched/preempt`.
  - Its rows, each run with the policy attached, on both machines:
    - the corpus, in groups:
      - the name rule, the launcher's directory, hooks in the gitdir, a submodule's and a
        worktree's, a `hooks` that is itself a symlink, config, the redirections, alternates and
        operational state, with the region rules of a gitdir;
      - the file rules: a freed file, a pinned component, the writable region, a relocated hook
        directory and the symlinked `.claude`;
      - the "Directories" rules:
        - a `HEAD` made by each creating syscall in a `.git` the session makes in `sub/` and in
          `.git/objects/x/`, and by an exchange over a directory placeholder (a rename over one
          answers `EISDIR` before any hook);
        - an exchange of a filled directory with a session-made `.git`;
        - writes below a `.git` made under a `read-only` line;
        - a file in `.git/objects/x/.ko-agent-sandbox`;
      - the symlink target rules, the walk's bound, in the workspace and below the recorded
        `.git`, and sockets;
      - second names, each judged by its name and by its second name: a workspace whose `.git` is
        a pointer file, with a host hard link to it and to `.ko-agent-sandbox`
        (`../../fuse/tests/mounted_mutate.rs`,
        `a_second_name_of_a_guarded_entry_is_guarded_like_it`); and a submodule worktree's pointer
        file, with a host hard link to it in another directory;
    - ordinary git in a clone; and host git in `sub/`, whose session-made `.git` has no `HEAD`,
      finding the workspace's gitdir;
    - the torn-name race of "What is gained and what is lost", at two levels:
      - one process renames `node_modAAAA`, which holds `.vscode/tasks.json`, to `BBBBBBBBules`
        and back in a loop, by `rename` and by `RENAME_EXCHANGE` with a directory of the other
        name;
      - another process moves their parent `outerAAAA` to `BBBBouter` and back, by `rename` over an
        empty placeholder and by `RENAME_EXCHANGE` with it;
      - a third writes that file and creates files beside it, by path under every combination of
        the names, and through directory descriptors of both `.vscode` directories held from the
        start;
      - the writes, refusals, walks and retries are counted as the one-hook suite's stats row
        counts them;
      - no write succeeds;
      - both renamers moved, and a path the writer wrote changed its answer between refused and
        absent, which only a move of its names causes; without this, the race did not run;
      - the walks that read a torn name and were made again are reported, 0 to 15 a run, since
        each dentry is validated over the read of its own name;
    - the storm:
      - sixteen processes create, write, rename, link and symlink at once, with permitted and
        refused names mixed. Every decision is counted and none is wrong. The reentry count and
        the deepest slot taken are recorded.
      - Then the slots are exhausted by hand through the per-CPU guard word: with four taken, a
        write is refused and counted; with three, it runs in the fourth; freed, it runs in the
        first. The word is set while a container that is already up sleeps, so that no call of
        the runtime's is in flight.
    - sockets by default: a `bind` beneath the persistent volume's root is refused, and one under
      a directory on the volume's superblock that stands for `~` is allowed. From there the socket
      can be neither renamed nor linked beneath the volume, nor moved into the workspace, which
      recreates it by `mknod`;
    - a second host share bound into a disposable container, on which a write is denied;
    - the walk's cost at the clone's deepest file:
      - `file_open`'s own timer;
      - five interleaved pairs of a container under the policy and one beside it, in alternating
        order: each pair's difference for the open for writing, beside two operations the policy
        does not walk, the open for reading, which the hook leaves first, and `lstat`, which no
        hook sees;
      - the jited barrier;
    - the NTFS short-name form under its flag: a mutation whose ancestry or own name has the form
      is denied, and a name with a `~` outside the form is allowed. The form on a real NTFS volume
      is the Windows driver's row;
    - under `unix-socket`, four sandboxes with their own policies: a live session, a second
      session of the workspace launched under a later rule file, a session of another workspace,
      and a `--workspace=read-only` session. They hold nine hooks of the ten slots and differ in
      policy. The rows:
      - a socket in the workspace is allowed. One under `.git/objects`, at the gitdir's root
        (`fsmonitor--daemon.ipc`) or under a `read-only` line is refused: by `bind`, by `rename`
        and `RENAME_EXCHANGE` of one bound elsewhere, and by `link`. A symlink there to a socket
        outside is allowed;
      - a container starts with `file_receive` attached: the runtime's descriptors pass, and its
        first process holds no descriptor beyond the standard three;
      - a pipe, a socket pair's end and a workspace file, passed between two processes of one
        container, arrive;
      - the later session is sent one message of three descriptors: a read-only one of an ordinary
        file, a writable one of a file that its rule file refuses and the sender's allows, and a
        read-only one again. It gets the first alone, and `MSG_CTRUNC`. It is also sent a writable
        descriptor of a file both allow, which it writes, beside a read-only one of the refused
        file, which it cannot reopen for writing;
      - no receiver gets a directory descriptor of the sender's container root, of its `/tmp` or
        of the receiver's own root. A pipe sent after a refused directory is dropped with it; one
        sent before it arrives;
      - a sender whose container ends and is removed before the receiver reads (the receiver waits
        for the driver's marker of that): its writable file and directory do not arrive, and the
        hook's record shows the file's mount in no namespace; its read-only share file does
        arrive;
      - a file descriptor sent into the other workspace's session and into the read-only session:
        they get nothing. The read-only session itself writes nothing on the share, writes `/tmp`
        and reads the workspace;
    - the seccomp profile that "Mounts" relies on, derived from the machine's default
      (`SeccompProfile.scala`): `unshare` of a user namespace and each mount syscall answer
      `EPERM`, and a child process still starts. Both runs hold `CAP_SYS_ADMIN` as root in the
      container, so a missing capability cannot answer in the profile's place: without the
      profile, none of those answers `EPERM`.
  - The driver is `../test/podman/policy/Policy.scala`, one driver for both hosts, run on the host.
    Its transcript is this suite's record:
    - `policy.bpf.c` is the every-hook suite's program with the additions above. The walk, each
      level of it and of its snapshot, the rule match, the alias activation and the symlink
      judgment are each a global function, verified once per program. The reason: the verifier
      checks a loop's inlined body at every iteration until its states converge, and 6.18
      converges slowly ("Policy on WSL").
    - `exercise.c` lays out the fixtures, runs the corpus of 259 cases in eighteen groups and
      compares each answer with the expected one, runs the race and the storm, and binds, serves
      and receives sockets and descriptors. `--self-test` runs the same corpus under the installed
      backend, from the rule file and roots that `../../../src/main/scala/BpfCorpus.scala` gives
      both runners.
    - The shipped controller attaches each session's policy, from records the shipped fixture
      writes in place of the guard, and the shipped read-back verifies it. So the corpus runs
      against maps filled as a launch fills them.
    - After each corpus run, the program's denials, read from its counters, must number at least
      the refusals the cases saw, so a case's `EPERM` cannot come from anywhere but the program.
    - `inspect.c` reads what a launch does not: the verifier's figures, and the program's own
      counters, slot guard, last decision and jited bytes.
    - The runs settled the record layout, which the guard's compiler writes.
    - The host build (`../test/host/`) runs the FUSE backend's own corpus through the program
      before any host run. A program that has not passed it is not run on the machines.
  - Gate:
    - each row is ENFORCED, or an existing FUSE backend residual, or covered by a decision the
      user has taken, such as "Directories";
    - the policy program loads on both kernels, with its verifier figures recorded as the
      every-hook suite's are;
    - each program stays within 500,000 instructions, half the limit, on each kernel. The reason:
      6.18 processes many times 7.2's instructions for one loop ("Policy on WSL", 28 times for the
      walk), and a program near the limit fails to load at the next change of the walk;
    - a listed loss passes nothing.
- **Lifecycle** (`../test/podman/lifecycle/`). It measures, on rootless podman:
  - the ordering of "Lifecycle": first-process denial, restart, recreate, `podman exec`, stop and
    kill, controller exit, machine restart, link loss;
  - the proof's catches. Each of these controllers must end the launch:
    - one that attaches a subset of the hooks;
    - one that attaches another build's program;
    - one whose build differs in data alone;
    - one that loads wrong records;
    - one that leaves the record maps unfrozen;
  - a write from user space to each record map of a live session, which is refused;
  - the reconcile of "Lifecycle", 7:
    - a launcher killed between the pins and `podman create`, and a `podman create` that fails
      after the pins, each leave a cgroup and pins, which the next start removes;
    - a launcher killed between `podman create` and `podman start` leaves a container that names
      the cgroup. Its pins stay until the container is removed;
    - a stopped session's and a live session's pins stay;
    - a listing that fails removes nothing;
  - the restart invariant of "Lifecycle", 5: the created container's restart policy reads `no`,
    and after a machine restart with a stopped container present, nothing starts it;
  - the socket rule's dependence on the mounts ("The policy"): a directory under `~` that holds a
    bound socket fails with `EXDEV` when it is moved into the volume or the workspace;
  - the controller's refusals: two in the machine, one given an object path and one asked for a
    cgroup outside the invoking user's slice; and a third, a mount under the bind source, which it
    lists in the VM before the attach ("The policy");
  - the launch cost of steps 2 and 3 on both machines, the verifier's 0.5 s and 0.9 s for the nine
    programs among it ("Policy on macOS", "Policy on WSL"), and a restart's cost with the pinned
    programs ("Lifecycle", 5). The proof at every launch and the preloaded set rest on those
    figures ("Lifecycle", 3 and the preloaded set).
  - The rows that the reuse of pins, the reconcile's identities and the cleanup add, on both
    machines:
    - a restart after `--build` installed another object, and one after a rule change: each loads
      and verifies fresh programs and attaches none of the old pins, which are unpinned. The
      launch's own pins are attached only when the read-back finds the installed tag and this
      launch's records ("Lifecycle", 5);
    - the reconcile under identities that contradict: a container whose labels name another
      session's cgroup, a cgroup directory whose recorded identity no longer matches its path, and
      a pin under another session's name. The reconcile associates no pin or cgroup with a session
      it cannot establish, removes nothing for them, and reports each;
    - the cleanup's refusals, one each: a pin path with a relative component; a symlink in place
      of a pin directory or of a cgroup directory; a mount on the pin directory; and a cgroup
      directory whose identity changed since the launcher recorded it. Each is refused, and
      nothing is removed;
    - refusals found late: one foreign link among a session's pins, and a programs directory that
      cannot be opened once the links were checked. Each leaves every pin in place, since the
      reconcile checks all of a session's pins before it removes any;
    - a reconcile killed between a cgroup's removal and its pins', with every pin in place and
      with one link pin fewer: the removal detached the links, and the next reconcile removes
      both sessions with their pins.
  - The lifecycle suite also binds the evidence to the code it measured:
    - every driver records the digest of its suite's sources beside the object's hash;
    - the measurement sections name that digest;
    - `../test/SourceDigestCheck.scala` fails when the sources' code differs from the digest its
      section names, so that a section cannot stand as evidence for code it did not measure.
  - The transcript names the cgroup-LSM links of other runs attached before the first launch, a
    launcher session's or another suite's. Beside one, the first attach finds the kernel's shim
    installed ("The hooks"), and no attach of the run measures its cost.
  - Gate:
    - no container process runs before the policy, on either machine;
    - each of the five defective controllers is caught;
    - the stale pins and the contradicting identities are refused;
    - the reconcile removes the two orphans and nothing else;
    - the evidence check passes.
- **Benchmark** (`../test/podman/benchmark/`). It measures:
  - `../../bench/entry-cost.py` and the real-tree rows of `../../fuse/doc/verification-log.md` on
    the bind with the policy, beside the plain bind, and beside the FUSE backend when `--stacks`
    names it;
  - the machine's CPU and memory during the stat storm under each. The stat storm is
    `walk-cost.py`'s rows over the real tree, `lstat` of every tracked file by path, and
    `git status`.
  - The driver is `../test/podman/benchmark/Benchmark.scala`, one Scala CLI script for both hosts,
    run on the host. Its transcript and tables are this suite's record. It:
    - builds the lifecycle suite's controller, read-back and fixture over the policy suite's
      program, with `stats.c` beside them, which reads the program's counters;
    - clones the real-tree rows' tree (sbt/sbt, shallow) into a scratch workspace on the share;
    - launches the policy over it through steps 1 to 3 of "Lifecycle", under the launcher's
      default rules;
    - runs the two probes over that one tree in two containers: the sandbox image over a
      writable bind of the workspace (`../../bench/plain-bind.sh`'s command) and the same command
      below the attach cgroup;
    - runs them in a third, the launcher's session through the FUSE backend, only when `--stacks`
      names `fuse`, by the user's decision of 2026-11-09. That stack repeats "The cost of a path
      walk" (`../../fuse/doc/verification-log.md`), which no change of the BPF sources moves, and
      took 108 of the 138 minutes of the WSL run of 2026-11-01;
    - before the launch, runs one `entry-cost.py` round on the bind with no program attached. This
      is the control for the shim that the first attach installs for every task in the VM ("The
      mechanism").
  - `entry-cost.py` runs in interleaved rounds, three by default. The `sbt` build of "an sbt
    build, by where its output goes" runs once on the bind and once under the policy, on a clone
    of this repository made inside the tree, with its output there; the FUSE backend's 604 s
    stands from that log. `walk-cost.py` runs once per stack.
  - A sampler in the machine reads `/proc/stat`, `/proc/meminfo` and the pressure files each
    second during each run. The program's counters are read after each run under the policy, so
    that each figure comes with the calls each hook judged.
  - Before the figures are taken, the creation of a hook file in `.git/hooks` shows that each
    stack is what it claims: it is refused under the policy and through the FUSE backend, and made
    over the bind.
  - Gate: the numbers are recorded.
- **Launcher** (`../test/podman/launcher/`). It measures the launcher's side ("The launcher's
  side") through the launcher's jar. Its rows need the launcher.
  `../test/podman/launcher/Launcher.scala` runs them by the user's decisions of 2026-10-29:
  - A: from a host terminal with no other sandbox session on the machine; it refuses otherwise;
  - B: the earlier build is the lifecycle suite's `other.bpf.o`, swapped in for the installed
    object and restored;
  - C: no row for a boot-time unit, which the backend does not install;
  - D: the memory row's sets are loaded by the installed controller, unattached;
  - E: the WSL proof's failure is a unit test of the launch script.

  The rows:
  - under the profile the launcher installs, `io_uring_setup` answers `ENOSYS` from the
    container's first process and from a `podman exec` process ("The hooks", `file_receive`);
  - a launch under the other backend, or under the other setting of `unix-socket`, while a session
    that shares its volume or a raw mount is live: it is refused, in either order. The cases:
    - a main checkout and a linked worktree sharing its volume;
    - two sessions of one workspace naming two volumes;
    - a workspace below another's root;
    - a linked worktree with its own volume beside its main checkout;
    - a host rename of the workspace between the two launches, which then name two volumes;
    - beside a live container of an earlier launcher without the labels;
    - two such launches racing, one of them refused;
  - a linked git worktree, whose main gitdir the launcher binds read-only
    (`../../../doc/TODO.md`, "Deferred — writable git from a linked worktree"), and a symlink
    under its main checkout's `.git/objects` to a socket outside. The worktree's container cannot
    connect through the symlink;
  - the preloaded set ("Lifecycle"):
    - a launch takes it by rename and fills its maps through the pinned programs' ids. It passes
      the read-back and the proof, and its step 2 costs what a recreate's does;
    - two launches racing for one preloaded set never share one, and their programs are disjoint.
      In the runs both took a set, the second taking the one prepared behind the first;
    - a preloaded set of a build that `--build` replaced is unpinned by its tags;
    - a launch that died after taking the preloaded set is removed by the reconcile. The suite
      builds it as such a launch leaves it: the record, the attach cgroup, and the taken set
      attached there;
    - a launch that finds no preloaded set, as the first after a boot does, takes the one its own
      reconcile prepared;
    - a live session's records, read back before and after another launch takes the preloaded set
      and the next one is prepared, are unchanged, and the two sessions' program ids are disjoint;
  - the sessions' cost in the kernel, so that the per-sandbox sets "The policy" relies on have a
    measured price:
    - the memory of one, four and eight program sets, and the same after their removal;
    - the sets are loaded unattached, so links are not counted;
    - the kernel charges a map's and a program's memory to the memory cgroup of the process that
      made them, and the charge outlives the process (`kernel/bpf/syscall.c`,
      `bpf_map_save_memcg`, the map's `objcg`);
    - so every load runs in a cgroup kept for the measurement, which sums the loads, and its
      `memory.current` is read after the loader exits. Under systemd that cgroup is a hold unit's
      service in a slice; under cgroupfs it is a directory of the delegated subtree, which stays
      until removed;
    - the machine's root offers no reading, since `memory.current` is a file of non-root cgroups
      alone (`Documentation/admin-guide/cgroup-v2.rst`);
    - `bpftool`'s `memlock` is each map's own estimate (`kernel/bpf/syscall.c`,
      `bpf_map_memory_usage`), not the charge;
  - on WSL, the proof run by the launcher itself: its process enters the leaf below the attach
    cgroup through a transient scope of the user manager ("Lifecycle on WSL"). A scope that cannot
    be created, or a migration that fails, ends the launch before any container;
  - the FIFO rules ("The policy"):
    - refused by type: `mknod` of a FIFO in `inode_mknod`, its open in `file_open`, a time change
      on one in `inode_setattr` and, under `unix-socket`, its descriptor in `file_receive`;
    - each is a corpus case over a FIFO the host made, opened with `O_NONBLOCK` so that the test
      itself never waits;
    - the proof's `mkfifo` at an ordinary name;
    - the FIFO cases are in the policy suite's corpus, and the `mkfifo` in the lifecycle suite's
      fixture.


## Environment evidence

Both machines were measured on 2026-10-10 and 2026-10-11 with a plain container and no BPF
program: the placement below is settled, and the enforcement is not. Repeat a row only after a
change in the component it names. A kernel, WSL, podman, crun or cgroup-manager change reopens the
placement and hook rows of that platform; nothing else does.

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

WSL 3.0.1.0 ran kernel 6.18.40.1, whose published `CONFIG_LSM` lacks `bpf`. 3.0.3 was installed
for its kernel; it has been a release since 2026-10-09, and 3.0.4 of 2026-10-20 is the
pre-release (https://github.com/microsoft/WSL/releases).

The launcher's `--build` notes a WSL kernel older than the WSL row's, which
`KoAgentBpf.MeasuredWslKernel` copies. Change both together: `KoAgentBpfTest` fails until they
agree.

The placement under the systemd manager was measured on both machines on 2026-10-10 and
2026-10-11, macOS on its earlier kernel 7.1.8. After
`systemd-run --user --unit=ko-agent-probe-hold --slice=ko-agent-probe.slice /usr/bin/sleep 180`,
the cgroup of a container run with `--cgroup-parent=ko-agent-probe.slice` was the following, with
uid 501 on macOS and 1000 on Windows:

```text
/user.slice/user-<uid>.slice/user@<uid>.service/ko.slice/ko-agent.slice/
    ko-agent-probe.slice/libpod-<id>.scope/container       (one path, wrapped here)
```

The Windows placement needs `%UserProfile%\.wslconfig` holding `[wsl2]` and
`isolateDistroCgroup=false`, after `wsl --shutdown`.

- With the default, `podman run` fails with `crun: controller pids is not available`.
  `--cgroups=disabled` makes it run, but places the container in no cgroup of its own, which this
  backend cannot use.
- The setting applies to every WSL2 distribution of that Windows user. The launcher neither writes
  nor removes it; the setup note for Windows names it.
- Under the setting, the session's limits apply, below the attach cgroup as well: `memory.max`
  7,105,761,280 and `pids.max` 2048 in a `live,bpf` and a `live,fuse` session on 2026-10-27.
  Podman issue 29966 reports no controller for rootless podman on WSL 3.0.3 by default.

References:
https://learn.microsoft.com/windows/wsl/wsl-config,
https://github.com/microsoft/WSL/issues/41492,
https://github.com/podman-container-tools/podman/issues/29749,
https://github.com/podman-container-tools/podman/issues/29966.

Sockets, measured in a sandbox session on 2026-10-21 with Codex 0.163.0, from `/proc/net/unix` and
a `find -type s` over the container:

- the one pathname socket bound was Claude Code's, under `/tmp`;
- the one socket file on shared storage was Codex's app-server daemon's,
  `~/.codex/app-server-daemon/daemon-updater.sock` on the persistent volume, its daemon not
  running;
- none was in the workspace;
- sbt 2's server socket is under `~/.config/sbt/2/server` (`project/target/active.json`); Mill's
  daemon listens on the TCP port it writes to `out/mill-daemon/socketPort`, and Gradle's daemon and
  workers on TCP ports (`../../../SECURITY.md`);
- `~` and the persistent volume are two mounts of one xfs superblock, `/dev/vda4`.

`codex exec` answers while the policy refuses the socket of Codex's app-server daemon beneath the
persistent volume ("The hooks", `file_receive`). The run is by hand, in a `live,bpf` session with
Codex signed in, outside the suites by the user's decision of 2026-11-09: a Codex release and the
policy's socket rule decide its answer, not the Launcher suite's sources. Repeat it after a Codex
release that changes where the daemon binds, or after a change of the socket rule. In the session:

```sh
codex exec 'print hello'                     # answers
find ~/.codex ~/persistent-volume -type s    # prints nothing
python3 -c "import socket; socket.socket(socket.AF_UNIX).bind('$HOME/persistent-volume/t.sock')"
                                             # fails with PermissionError, errno 1 (EPERM)
```

- macOS, 2026-11-09, Codex 0.166.0: `codex exec` answered; afterwards no socket lay under
  `~/.codex` or the persistent volume, and a socket bind beneath the volume answered `EPERM`, the
  policy's refusal.
- Windows, 2026-11-09, Codex 0.167.0: the same answers.

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
`3fd866407d2d007c5f6ab550d5e3af9eddc146356b8bd4a7147940ae99746e70`. The transcript holds the raw
lines.

- The exerciser's containers run without podman's seccomp profile. That profile answers
  `file_setattr` and `io_uring_setup` with `ENOSYS`, and refuses a mount in a user namespace before
  the kernel does.
- Rows 20 and 21 also run with `label=disable`, as the sandbox's nesting mode does.

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

Measured on 2026-11-09 with `../test/podman/policy/Policy.scala` on the default podman machine,
kernel 7.2.7-200.fc44, podman 6.1.4, crun 1.30, clang 19.1.7.

- The object: `policy.bpf.o` of SHA-256
  `e20c98e3b65a822cac01a5f4ae9e66c3e15b322fc039d1d66d22c5cdd3ff031f`, built from sources of code
  digest `5096f1ee9fece15f1f9633cfee032ba7a463982091c356cbe237f3879297a46d` (`sources.txt` lists
  them in digest order; `../test/SourceDigestCheck.scala` recomputes it). It is the program with
  the FIFO rules ("The policy"), from `../policy.bpf.c`.
- The containers run as in the every-hook suite.
- Every one of the 53 rows passes. The rows give this run's figures, and the transcript holds its
  raw lines.
- Figures of earlier runs are kept where they are the reason for a rule or the only measurement of
  their kind, and are named as such: the run of 2026-10-22, under the program as first written;
  the run of 2026-10-24, under the revision before the FIFO rules; and the run of 2026-11-01,
  under the suite's own controller.

| row                      | measured                                                              |
| ------------------------ | --------------------------------------------------------------------- |
| preemption               | `full (lazy)`, 10 CPUs                                                |
| verifier, per program    | 43,363 to 46,114 insns, at most 25 states per insn, 67 to 81 ms each, |
|                          | 496 ms for all nine; the walk and position 38,615 insns, each level   |
|                          | of the walk 248 and of its snapshot 39, the rule match 2,524, the     |
|                          | alias activation 689 and the symlink judgment 2,778, each a global    |
|                          | function verified once; stack 352 to 384 of 512 bytes. The run of     |
|                          | 2026-10-24 counted the walk and position at 40,584 insns: 39,476      |
|                          | before the scratch locks' admission, 33,135 with the loop bodies      |
|                          | inlined, 16,758 before the review's three changes                     |
| barrier                  | the jited `file_open`, 31,432 bytes, holds three `ldaddal`, one per   |
|                          | fetch-add: before and after a level's reads, and before the snapshot  |
| records                  | 128 rule lines, eleven roots (three workspaces, a submodule's gitdir, |
|                          | four guarded `.git`, two guarded `.ko-agent-sandbox` and the volume), |
|                          | the alias context of `.claude` holding the five `.claude` lines as    |
|                          | partial matches, which the guard's compiler reproduces                |
|                          | (`bpf_records.rs`, its first test). The shipped fixture writes them   |
|                          | in layout `863db990`; the shipped controller attaches the run's six   |
|                          | policies, and the shipped read-back verifies each, with its record    |
|                          | maps frozen                                                           |
| corpus                   | 259 cases: 245 under the default flags, 6 under the short-name flag   |
|                          | and 8 under `unix-socket`, 0 mismatches each; of the 245, 5 answered  |
|                          | by the share before any hook, the `mkfifo` cases with `EACCES`,       |
|                          | counted apart, and 4 skipped, the `fifo` group's cases on the host    |
|                          | FIFO the share refused to make (`result=EACCES`)                      |
| denials                  | in each corpus run the program denied as many calls as the cases saw  |
|                          | refusals: 152 under the default flags, 4 under the short-name flag    |
|                          | and 5 under `unix-socket`                                             |
| git                      | status, add, commit, a branch, log and gc in the clone; `git config`  |
|                          | and `git init` refused; git outside the policy in `sub/`, whose       |
|                          | session-made `.git` has no `HEAD`, finds the workspace's gitdir       |
| race                     | 538 moves and 2,166 exchanges of the outer directory, 970 moves and   |
|                          | 336 exchanges of the inner, against 10,476 writes by path and through |
|                          | held descriptors: 6,366 refused, 4,110 absent, 0 succeeded; a path's  |
|                          | answer changed between refused and absent 1,510 times; 1 walk read a  |
|                          | torn name and was made again (6 on 2026-11-01, and 5, 9, 15, 8, 6, 2, |
|                          | 11 and 12 in the runs before it), none gave up                        |
| race, global sequence    | the first run, validating the walk by `rename_lock`: 167 walks        |
|                          | overlapped a rename and 35 of 11,891 gave up after four retries       |
| storm                    | 16 processes, 35,428 decisions, 0 wrong, 0 denied for want of a slot, |
|                          | no nesting on any CPU; walk means 16 to 26 µs, 125 µs at most         |
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
|                          | walked to depth 10: 51.7 µs mean, 136 µs at most; the storm's walks   |
|                          | at depth 3 average 16 to 26 µs and the race's at depth 5, 29 µs       |
| walk cost, syscall       | five pairs of 2,000 opens at depth 10, a container under the policy   |
|                          | and one bare, the policy's first in the odd pairs, policy minus bare: |
|                          | the open for writing +83, +41, +68, +96 and +99 µs, median +83,       |
|                          | against the program's own 52 µs; the open for reading, which the hook |
|                          | leaves before any walk, +6 to +32, median +12; `lstat`, which no hook |
|                          | sees, −45 to +36, median +12; the bare write open at 680 to 736 µs. A |
|                          | run of 2026-10-24 with the bare open at 949 to 1,791 µs spread the    |
|                          | write open's difference from −640 to +443 and `lstat`'s to +1,224, so |
|                          | the syscall figure holds on a quiet share only, and the program's     |
|                          | timer is the one to read                                              |
| container start          | with `file_receive` attached, the runtime passes 16 descriptors of    |
|                          | its own namespaces into the starting container, all passed, and the   |
|                          | first process holds no descriptor beyond the standard three; the      |
|                          | controller's namespace is 0xEFFFFFF8, the initial one                 |
| container start, refused | the first run, with every other namespace's descriptor judged: a      |
|                          | directory descriptor of the volume's mountpoint, `_data`, refused,    |
|                          | and `crun` failed with `write to sync socket: Connection reset`       |
| slots                    | four sandboxes with nine hooks each hold nine of the ten              |
| descriptors              | every row that "Suites" lists passes but the host FIFO's, skipped as  |
|                          | the share made no FIFO; B's `file_receive` over the rows: 134 calls,  |
|                          | 128 of the runtime's namespaces, 4 allowed, 2 denied                  |
| seccomp                  | as root with `CAP_SYS_ADMIN`, under the generated profile `unshare`   |
|                          | with `CLONE_NEWUSER` and the nine mount syscalls the exerciser calls  |
|                          | answer `EPERM`, and a child process runs; `unshare` with              |
|                          | `CLONE_NEWNS`, which the profile admits, succeeds                     |
| seccomp, unconfined      | the same calls without the profile: none answers `EPERM`; `unshare`   |
|                          | with `CLONE_NEWUSER`, `mount`, `fsopen`, `open_tree`, `fspick` and    |
|                          | `umount2` succeed, `move_mount` answers `ELOOP`, `fsmount` `EBADF`,   |
|                          | and `mount_setattr` and `pivot_root` `EINVAL`                         |


### Policy on WSL

Measured on 2026-11-09 with `../test/podman/policy/Policy.scala` on the Windows machine of "One hook
on WSL", kernel 6.18.54.1, podman 6.1.4 under the cgroupfs manager, crun 1.28, clang 19.1.7.

- The object: `policy.bpf.o` of SHA-256
  `f8cd2eae6c890ad1e29ee0af77cb55cacbd07f98e2b4a964d4bfa55001f021b7`, built against that kernel's
  BTF from sources of code digest
  `5096f1ee9fece15f1f9633cfee032ba7a463982091c356cbe237f3879297a46d`, the sources "Policy on
  macOS" measures: the program with the FIFO rules.
- Every one of the 54 rows passes. The rows below name what differs from macOS and give this run's
  figures; every other row passed as there.
- Figures of earlier runs are kept where they are the reason for a rule or the only measurement of
  their kind, and are named as such: the runs of 2026-10-24, under the revision before the FIFO
  rules; the run of 2026-10-27; and the run of 2026-11-01, under the suite's own controller.

| row                      | measured                                                              |
| ------------------------ | --------------------------------------------------------------------- |
| preemption               | `none`, 4 CPUs                                                        |
| verifier, per program    | 59,324 to 64,391 insns of the 1,000,000 limit, the walk and position  |
|                          | 55,145 of them, 1.4 times the count on 7.2.7; each level of the walk  |
|                          | 248 and of its snapshot 39, the rule match 1,955, the alias           |
|                          | activation 689 and the symlink judgment 4,450; stack 352 to 384       |
|                          | bytes; at most 29 states per insn; 106 to 166 ms each, 866 ms for all |
|                          | nine. The runs of 2026-10-24 counted the walk and position at 109,037 |
|                          | insns, 2.7 times 7.2.7's: 107,929 before the scratch locks'           |
|                          | admission, 919,220 with the loop bodies inlined (24.7 s for all       |
|                          | nine), 121,408 before the review's three changes                      |
| barrier                  | the jited `file_open`, 24,528 bytes, holds three `lock xadd`, the     |
|                          | scan matching the instruction under any `REX` prefix                  |
| corpus                   | 245 default cases, 0 mismatches: 239 run, the exchange among them     |
|                          | answered `EINVAL` by 9p after the hook; 6 skipped, the two names NTFS |
|                          | cannot hold (a newline, non-UTF-8 bytes) and the `fifo` group's four  |
|                          | on the host FIFO 9p refused to make (`EOPNOTSUPP`). The five `mkfifo` |
|                          | cases are refused `EPERM` by the policy, whose FIFO rule in           |
|                          | `inode_mknod` runs before 9p answers; the macOS share answers         |
|                          | `EACCES` before any hook. Of the socket group 4 of 8 run, the rest    |
|                          | needing a bound socket, which 9p refuses after the hook               |
| denials                  | the program denied 158 calls against the 157 refusals the cases saw   |
|                          | under the default flags, 4 against 4 under the short-name flag and 3  |
|                          | against 3 under `unix-socket`                                         |
| second names             | the host could not make the hard links `GIT~1` and `KO-AGE~1` in the  |
|                          | workspace whose `.git` is a pointer file: NTFS serves those names as  |
|                          | the short names of `.git` and `.ko-agent-sandbox`. The served names   |
|                          | stand in, and `GIT~1` names the pointer file's inode in the machine   |
| race                     | no descriptor held, since 9p refuses to move a directory with an open |
|                          | handle below it, and no exchange; 844 moves of the outer directory    |
|                          | and 229 of the inner against 3,072 writes: 375 refused, 2,697 absent, |
|                          | 0 succeeded; a path's answer changed between refused and absent 377   |
|                          | times; 1 walk read a torn name and was made again (2 on 2026-11-01, 1 |
|                          | on 2026-10-27; 2, 1, 4, 1, 0, 2 and 4 in the runs of 2026-10-24, in   |
|                          | one of which the outer renamer's first failed move answered `EACCES`) |
| storm                    | 16 processes, 9,996 decisions in the 5 s a 9p operation's 10 ms       |
|                          | allows, 0 wrong, 0 reentry; walk means 27 to 45 µs, 2.0 ms at most    |
| short name, real volume  | NTFS serves `.vscode` as `VSCODE~1`; under the flag a write through   |
|                          | it is refused and the host sees no file in `.vscode`                  |
| walk cost, in program    | `file_open` over the pairs' 10,000 opens for writing at depth 10:     |
|                          | 35.4 µs mean, 2.28 ms at most                                         |
| walk cost, syscall       | five pairs as on macOS, policy minus bare: the open for writing −107, |
|                          | +250, −32, +141 and −321 µs, median −32; the open for reading −301 to |
|                          | +417, median −120; `lstat` −288 to +302, median +153; the bare write  |
|                          | open 9.92 to 10.56 ms (the runs of 2026-10-24: medians −202 and −564  |
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

Measured on 2026-11-09 with `../test/podman/lifecycle/Lifecycle.scala` on the machine of "Policy on
macOS", kernel 7.2.7-200.fc44, podman 6.1.4, crun 1.30, clang 19.1.7.

- The objects:
  - `policy.bpf.o` of SHA-256 `e20c98e3b65a822cac01a5f4ae9e66c3e15b322fc039d1d66d22c5cdd3ff031f`,
    the object "Policy on macOS" measures, built again byte for byte;
  - `other.bpf.o` of SHA-256 `1be0447b686d3a8dcf3ce37c1a4ed84f794828cacf04c0d3c8103ba380909b0f`,
    the same source counting each call twice in its statistics, which stands for another build;
  - `other-data.bpf.o` of SHA-256
    `e8d23513779cc0ceab86cc08d758925ed703fa08c990ca9c546d9ded6ec55fef`, the source with one string
    literal of the same length changed, whose instructions and tags equal the installed object's.
- All were built from sources of code digest
  `f5c0bffc3ac03342b8a8f9f41ae2bd31b7131f3eb4fe9aeaa88c90445c21509a` (`sources.txt` lists them in
  digest order; `../test/SourceDigestCheck.scala` recomputes it). The sources are the program with
  the FIFO rules and the launcher's controller, read-back and fixture, from `../`, the controller
  freezing the record maps; and the suite's `rewrite.c`, which writes to those maps.
- Every one of the 76 rows passes in one run, the four machine-restart rows among them.
- The containers run as in the every-hook suite. Fourteen launches ran through the launcher's steps
  1 to 4, and the reconcile's rows ran the controller's attach alone eleven times.
- Two facts of earlier runs are kept and named with their dates:
  - one of the runs of 2026-10-25, under the program before the FIFO rules, as a reason for those
    rules;
  - the attach cost of the run of 2026-11-01 before any of its sessions stayed attached, which this
    run, beside two other cgroups' links, did not measure.

| row                      | measured                                                              |
| ------------------------ | --------------------------------------------------------------------- |
| install                  | the read-back loads the nine programs once and records their tags and |
|                          | the read-only data's 758 bytes: 492 ms                                |
| step 2 at launch         | over the twenty-four attaches that loaded, the controller's load took |
|                          | 359 to 481 ms, filling and freezing the maps 0.1 to 0.2 ms, the       |
|                          | attaches 0.3 to 0.5 ms for seven or eight hooks, 1.5 ms for nine. The |
|                          | first launch's link listing holds sixteen links of two other cgroups, |
|                          | made before the launch's eight. On 2026-11-01 the first twelve        |
|                          | attaches, through the reconcile's first session, took 7.5 to 9.4 ms;  |
|                          | the ten after, each made while the reconcile's earlier sessions       |
|                          | stayed attached, took 0.3 to 0.5 ms                                   |
| step 2 at a recreate     | the pinned programs checked in 14 ms and attached to the new cgroup   |
|                          | in 0.3 ms, nothing loaded; the old links read cgroup_id 0 after their |
|                          | cgroup went, the programs stayed pinned                               |
| step 3                   | the read-back 13 to 16 ms: eight programs, nine maps (the eight of    |
|                          | the policy and the string literals' read-only map, its bytes the      |
|                          | installed object's), five roots, 56 rules, the four record maps       |
|                          | frozen; the proof's 68 operations (69 under `unix-socket`, 67 under   |
|                          | the launcher's defaults alone) 35 to 46 ms, 0 mismatches, in a scope  |
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
|                          | the sender's own refused on arrival; after `podman restart` the first |
|                          | process is refused again, and a `podman exec` process starts under    |
|                          | `file_receive` and is refused                                         |
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
|                          | cgroup recreated at its path (inode 2653618, then 2654533): refused;  |
|                          | a pin directory renamed to another session's name: refused by its     |
|                          | links' cgroup id; nothing removed                                     |
| cleanup refusals         | a session name and a cgroup path with `..`; a symlink in place of the |
|                          | pin directory (`ELOOP`); a tmpfs mounted on it (`EXDEV`); a recorded  |
|                          | identity off by one; each refused, nothing removed. cgroup2 refuses a |
|                          | symlink in place of a cgroup directory with `EPERM`                   |
| a refusal removes        | one foreign link among a session's eight: refused, its 9 links and 8  |
| nothing                  | programs all surviving; a programs directory that is a symlink        |
|                          | (`ELOOP`): refused, all 8 links surviving                             |
| a reconcile killed       | two sessions whose cgroups were removed, one keeping every pin and    |
| before the pins' removal | one a link pin fewer: their links read cgroup_id 0, and the next      |
|                          | reconcile removes both with their pins, `links=8 progs=8` and         |
|                          | `links=7 progs=8`, each `cgroup=gone`                                 |
| machine restart          | `podman machine stop` 2 s, `start` 12 s; the pin root is gone with    |
|                          | bpffs, the attach cgroups are gone, the two containers stay exited    |
|                          | and the reconcile keeps both, since their containers name them        |
| bpffs                    | holds symlinks and renames of pin directories                         |
| FIFO                     | the proof's `mkfifo` at an ordinary name answers `EPERM` under the    |
|                          | FIFO rules. On 2026-10-25, before them, the same `mkfifo` passed      |
|                          | `inode_mknod`, which judged a socket by type and any other node by    |
|                          | name, and the FIFO left on the share preceded a `podman machine stop` |
|                          | that did not return                                                   |


### Lifecycle on WSL

Measured on 2026-11-09 with `../test/podman/lifecycle/Lifecycle.scala` on the Windows machine of
"One hook on WSL", kernel 6.18.54.1, podman 6.1.4 under the cgroupfs manager, crun 1.28, clang
19.1.7.

- The objects: `policy.bpf.o` of SHA-256
  `f8cd2eae6c890ad1e29ee0af77cb55cacbd07f98e2b4a964d4bfa55001f021b7`, the object "Policy on WSL"
  measures, built again byte for byte; beside it `other.bpf.o` of SHA-256
  `811c5ab5401e891b93fcc2909ace6a39f2374489342f7ff11b74af3740bb63d1` and `other-data.bpf.o` of
  SHA-256 `abc0cb3cd9633f64abc10f90daf2f93169cd6ef3b7512ac8dd5a8b06706789dc`.
- All were built from sources of code digest
  `f5c0bffc3ac03342b8a8f9f41ae2bd31b7131f3eb4fe9aeaa88c90445c21509a`, the sources "Lifecycle on
  macOS" measures.
- Every one of the 76 rows passes in one run, the four machine-restart rows among them.
- The rows below name what differs from macOS; every other row passed as there. Under cgroupfs the
  reconcile removes the cgroup directories itself.

| row                      | measured                                                              |
| ------------------------ | --------------------------------------------------------------------- |
| install                  | the tags and the read-only data recorded in 919 ms                    |
| step 2 at launch         | over the twenty-four attaches that loaded, the load 0.69 to 1.30 s,   |
|                          | filling and freezing 0.1 to 1.2 ms, the attaches 12.7 to 19.0 ms in   |
|                          | the first twelve and 0.2 to 1.1 ms in the other twelve; the first     |
|                          | launch's query lists its own eight links alone                        |
| step 2 at a recreate     | the pins checked in 43 ms and attached in 16 ms                       |
| step 3                   | the read-back 25 to 48 ms; the proof's 68 operations (69 under        |
|                          | `unix-socket`, 67 under the launcher's defaults alone) 354 to 388 ms  |
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
| machine restart          | `podman machine stop` 2 s, `start` 10 s; the rows as on macOS         |


### Benchmark on macOS

Measured on 2026-11-09 with `../test/podman/benchmark/Benchmark.scala` on the machine of "Policy on
macOS", kernel 7.2.7-200.fc44, podman 6.1.4, crun 1.30, clang 19.1.7.

- The object: `policy.bpf.o` of SHA-256
  `e20c98e3b65a822cac01a5f4ae9e66c3e15b322fc039d1d66d22c5cdd3ff031f`, the object "Policy on macOS"
  and "Lifecycle on macOS" measure, built again byte for byte, from sources of code digest
  `ed7d58fa8a1d656031f2ecb60261c3e64ebe3c9c265754843a6335efe254e6d9`.
- The tree: sbt/sbt at `0fc33066`, 4,537 tracked files at mean depth 7.0 among 8,065 entries. The
  corpus is `entry-cost.py`'s 2,101 entries, and the build is a clone of this repository at the
  tree's root. The launcher's default rules apply, 55 lines.
- Every one of the 26 rows passes in one run.
- The three stacks run the sandbox image with the session's user mapping: the policy's containers
  below the attach cgroup, and the fuse stack's through the launcher under `--workspace=live,fuse`.
- `entry-cost.py` ran three rounds a stack, interleaved, after one round on the bare bind before
  the launch. The figures are the mean, with the range, over the rounds.
- Before the launch, bpffs held no pin of a session. It held the launcher's preloaded set, nine
  programs and no link, systemd's `userns-restrict` programs and maps, and this suite's empty pin
  root.

| row                      | measured                                                              |
| ------------------------ | --------------------------------------------------------------------- |
| the launch               | load 419 ms, fill 0.1 ms, attach 0.4 ms, read-back 13.4 ms, the       |
|                          | proof's 67 operations 33.7 ms, 0 mismatches; a hook file in           |
|                          | `.git/hooks` made on the bind, refused under the policy and through   |
|                          | the FUSE backend                                                      |
| the bare bind, µs an     | before the launch, with no session's pin in bpffs (other attachments  |
| entry                    | not checked): `find` 65, `find -printf` 151, `ls -lR` 895, `cp -r`    |
|                          | 1,482, `rm -rf` 298. `find` and `rm -rf` lie inside the range of the  |
|                          | bind's rounds; the other three lie 4, 26 and 30 % above its top, in   |
|                          | this first round after the clone, with the machine 14 % busy mean     |
|                          | against 5 to 6 % in later rounds. So the shim the first attach        |
|                          | installs costs tasks outside the cgroup nothing the rounds' spread    |
|                          | shows                                                                 |
| `entry-cost.py`, µs an   | `find`: bind 65 (62 to 68), policy 65 (64 to 66), fuse 371;           |
| entry, bind / policy /   | `find -printf`: 143 (141 to 145), 144 (137 to 153), 1,199; `ls -lR`:  |
| fuse                     | 665 (614 to 711), 652 (625 to 671), 11,493; `cp -r`: 1,103 (1,050 to  |
|                          | 1,136), 1,203 (1,085 to 1,267), 7,606; `rm -rf`: 302 (297 to 310),    |
|                          | 325 (314 to 341), 2,070. Policy over bind 0.98 to 1.01 times over     |
|                          | overlapping ranges in three rows; `cp -r` 1.09 times, the policy      |
|                          | above the bind in each round by 131, 133 and 35 µs; `rm -rf` 1.07     |
|                          | times over disjoint ranges, the policy above the bind by 31, 17 and   |
|                          | 20 µs; fuse over bind 5.7 to 17.3 times, as "The cost of a path walk" |
|                          | measured in 2026-09                                                   |
| the program's share of   | 3,600 allowed calls each of `file_open`, `inode_create` and           |
| an `entry-cost.py` round | `inode_unlink` (the corpus's 1,800 files made, copied and removed     |
|                          | twice over), 134, 32 and 36 more answered at the superblock check,    |
|                          | every walk 4 deep and none retried or without a slot; one create      |
|                          | refused a round, the hook file by which `entry-cost.py` labels the    |
|                          | stack; 12.2 to 12.9 µs mean from entry to decision, 0.17 ms at most:  |
|                          | the three hooks' 10,801 judged calls take 133 to 138 ms of a round's  |
|                          | 8 s. In each round `cp -r`'s excess over the bind, 275, 279 and 74 ms |
|                          | over 2,101 entries, exceeds the 44 to 46 ms that the program's timer  |
|                          | gives all of the round's `inode_create` calls; in the first two       |
|                          | rounds it exceeds the 137 and 138 ms of all three hooks. `rm -rf`'s   |
|                          | excess, 65, 36 and 42 ms, exceeds the 46 ms of the round's            |
|                          | `inode_unlink` calls in the first round alone                         |
| the build                | `sbt 'testOnly *SandboxTextWidthTest'`, output in the workspace: bind |
|                          | 85 s wall, sbt's own 55 s; policy 81 s, 52 s; 10 of 10 tests under    |
|                          | both. The policy judged 1,865 opens, 1,481 creates, 214 renames (428  |
|                          | walks, source and destination), 110 unlinks and 669 attribute         |
|                          | changes, walks up to 20 deep, 33 to 39 µs mean a call and 77 for a    |
|                          | rename, 0.12 ms at most; it refused 5 symlinks at most 7 deep, 25 µs  |
|                          | mean each, the absolute targets "The policy" refuses as the FUSE      |
|                          | backend refuses sbt's links into its cache, under which sbt writes    |
|                          | copies ("sbt over dangling cache links"); the machine 20 and 21 %     |
|                          | busy mean, 47 and 50 % max, memory used rising to 3.1 GB under both,  |
|                          | from 1.0 and 1.1                                                      |
| `walk-cost.py`, bind /   | `lstat` by path: depth 1 0.08 / 0.09 / 0.56 ms, depth 7 0.31 / 0.33 / |
| policy / fuse            | 4.98 ms, depth 15 0.62 / 0.65 / 19.0 ms; every tracked file by path   |
|                          | 0.32 / 0.33 / 4.97 ms a file, through a directory fd 0.09 / 0.09 /    |
|                          | 1.28 ms; `find . -type f` 1.9 / 1.8 / 13.0 s; `git status` 3.6 / 3.5  |
|                          | / 63.1 s, `--untracked-files=no` 0.7 / 0.8 / 35.9 s. The depth rows,  |
|                          | 200 `lstat` each of 0.08 to 0.65 ms, put the policy 1.00 to 1.13      |
|                          | times the bind, 0 to 0.06 ms above it, the per-file rows 1.03 and     |
|                          | 1.00; the policy judged 4 opens, 4 creates and 4 unlinks in the whole |
|                          | run, git's lock at depth 2, 15 to 19 µs each; the fuse stack's        |
|                          | figures lie 17 and 12 % below "a real tree" of 2026-09-19 (5.97 ms a  |
|                          | file, 71.5 s)                                                         |
| the machine during the   | `/proc/stat` over the run, ten CPUs: bind 8 % busy mean, 15 % max     |
| stat storm               | over 29 s; policy 7 %, 17 % over 23 s; fuse 6 %, 29 % over 451 s;     |
|                          | iowait under 0.5 %; memory used 1.0 to 1.2 GB of 11.9 GB under bind   |
|                          | and policy, 1.0 to 1.8 GB under fuse; memory pressure `some avg10`    |
|                          | 0.00 throughout, io at most 0.18                                      |
| the machine during       | the bare round 14 % busy mean, 29 % max over 9 s; bind and policy 5   |
| `entry-cost.py`          | to 6 % mean, 6 to 9 % max over 7 to 8 s a round; fuse 6 to 7 % mean,  |
|                          | 23 % max over 67 to 73 s a round                                      |
| the probe's own label    | `entry-cost.py` reports `plain bind mount`, `BPF backend` and         |
|                          | `FUSE backend`: it tells the policy from the bind by a hook file in   |
|                          | `.git/hooks`, which the policy refuses by name and allows the         |
|                          | directory ("Directories")                                             |
| the attach cgroup        | under the systemd manager the slice                                   |
|                          | `ko-agent-bpftest-benchmark-policy.slice` lies below                  |
|                          | `ko.slice/ko-agent.slice/ko-agent-bpftest.slice/`                     |
|                          | `ko-agent-bpftest-benchmark.slice`, the hierarchy systemd reads from  |
|                          | a slice name's dashes                                                 |


### Benchmark on WSL

Measured on 2026-11-09 with `../test/podman/benchmark/Benchmark.scala` (`scala shebang`) on the
Windows machine of "Policy on WSL", kernel 6.18.54.1, podman 6.1.4 under the cgroupfs manager, crun
1.28, clang 19.1.7.

- The object: `policy.bpf.o` of SHA-256
  `f8cd2eae6c890ad1e29ee0af77cb55cacbd07f98e2b4a964d4bfa55001f021b7`, the object "Policy on WSL"
  and "Lifecycle on WSL" measure, built again byte for byte, from sources of code digest
  `ed7d58fa8a1d656031f2ecb60261c3e64ebe3c9c265754843a6335efe254e6d9`, the sources "Benchmark on
  macOS" measures.
- The tree is sbt/sbt at `0fc33066`, 4,537 tracked files; the corpus and the build are as on
  macOS. The machine has four CPUs and 7.8 GB, and the tree is on the 9p share.
- Every one of the 26 rows passes in one run. Its workloads took 2 h 25 min, the fuse stack's
  `walk-cost.py` 81 min of it.
- Before the launch, bpffs held only this suite's pin root, so the bare round is the shim's control.
- The rows below name what differs from macOS; the stacks and the rounds are the same.

| row                      | measured                                                              |
| ------------------------ | --------------------------------------------------------------------- |
| the launch               | load 916 ms, fill 0.2 ms, attach 17.0 ms, read-back 68.5 ms, the      |
|                          | proof's 67 operations 328 ms on 9p, 0 mismatches; the attach cgroup a |
|                          | directory under `app.slice`                                           |
| the bare bind, µs an     | before the launch, no link of any session attached: `find` 712,       |
| entry                    | `find -printf` 1,625, `ls -lR` 3,199, `cp -r` 14,760, `rm -rf` 1,817; |
|                          | inside the range of the bind's rounds for `ls -lR`, below it for      |
|                          | `rm -rf`, and 1 to 13 % above its top for the others, in this first   |
|                          | round after the clone: the shim the first attach installs costs tasks |
|                          | outside the cgroup nothing the rounds' spread shows                   |
| `entry-cost.py`, µs an   | `find`: bind 620 (609 to 630), policy 672 (656 to 686), fuse 3,832;   |
| entry, bind / policy /   | `find -printf`: 1,493 (1,462 to 1,531), 1,603 (1,521 to 1,662),       |
| fuse                     | 12,350; `ls -lR`: 3,099 (2,895 to 3,306), 3,356 (3,339 to 3,387),     |
|                          | 102,167; `cp -r`: 14,230 (13,820 to 14,659), 14,738 (14,528 to        |
|                          | 15,033), 78,313; `rm -rf`: 2,010 (1,939 to 2,072), 2,015 (1,957 to    |
|                          | 2,106), 20,475. Policy over bind 1.00 to 1.07 times over overlapping  |
|                          | ranges in three rows; `find` 1.08 times over disjoint ranges, the     |
|                          | policy above the bind in each round by 65, 66 and 26 µs, and `ls -lR` |
|                          | 1.08 times, by 444, 290 and 37 µs. The program judges neither         |
|                          | command: it leaves an open for reading before any walk, and no hook   |
|                          | sees `lookup` or `getattr`. Fuse over bind 5.5 to 33.0 times          |
| the program's share of a | the same 3,600 judged calls a hook, 7, 10 and 0 answered at the       |
| `entry-cost.py` round    | superblock check, every walk 4 deep, the suite's own hook file        |
|                          | refused once a round; 10.5 to 13.4 µs mean from entry to decision,    |
|                          | 1.02 ms at most once: 132 to 135 ms of a round's 79 to 82 s. The      |
|                          | excess of `cp -r` over the bind, 1.5 and 1.7 s in two rounds over     |
|                          | 2,101 entries, exceeds the 47 to 48 ms that the program's timer gives |
|                          | all of the round's `inode_create` calls; in the third the policy ran  |
|                          | 6 µs an entry below the bind                                          |
| the build                | bind 352 s wall, sbt's own 285 s; policy 303 s, 237 s; 10 of 10 tests |
|                          | under both. The policy judged 1,929 opens, 1,976 creates, 218 renames |
|                          | (436 walks), 113 unlinks and 953 attribute changes, walks up to 20    |
|                          | deep, 35 to 83 µs mean a call and 78 for a rename, 2.3 ms at most; it |
|                          | refused 4 symlinks at most 7 deep; the machine 37 and 39 % busy mean, |
|                          | 94 and 92 % max, memory used rising from 0.6 to 2.6 GB under both     |
| `walk-cost.py`, bind /   | `lstat` by path: depth 1 1.05 / 1.17 / 4.59 ms, depth 7 5.31 / 6.03 / |
| policy / fuse            | 52.8 ms, depth 15 11.7 / 12.1 / 199.2 ms; every tracked file by path  |
|                          | 5.46 / 6.14 / 54.8 ms a file, through a directory fd 1.03 / 1.12 /    |
|                          | 16.5 ms; `find . -type f` 15.1 / 17.3 / 172.5 s; `git status` 22.0 /  |
|                          | 22.8 / 711 s, `--untracked-files=no` 10.7 / 10.6 / 409 s. Policy over |
|                          | bind 1.03 to 1.15 times on the depth rows, 1.12 and 1.09 per file,    |
|                          | 0.99 to 1.15 on the commands, in one run each; the policy judged 4    |
|                          | opens, 4 creates and 4 unlinks, 15 to 16 µs each; the bare 9p bind    |
|                          | costs 6 to 19 times the macOS virtiofs bind, and the FUSE backend 4.4 |
|                          | to 38 times the bind on top                                           |
| the machine during the   | four CPUs: bind 14 % busy mean, 35 % max over 356 s; policy 16 %, 35  |
| stat storm               | % over 267 s; fuse 14 %, 58 % over 4,795 s; iowait at most 5, 4 and   |
|                          | 49 %; memory used 0.54 to 0.74 GB of 7.8 GB under each, memory        |
|                          | pressure `some avg10` 0.00 throughout; io pressure at most 1.9, 1.1   |
|                          | and 13.1                                                              |
| the machine during       | bind and policy 13 to 14 % busy mean, 15 to 17 % max over 74 to 83 s  |
| `entry-cost.py`          | a round, the bare round 80 s; fuse 14 % mean, 55 to 60 % max over 610 |
|                          | to 667 s a round, with iowait peaks of 19 to 53 %; memory pressure    |
|                          | 0.00 throughout                                                       |


### Launcher on macOS

Measured on 2026-11-09 with `../test/podman/launcher/Launcher.scala` on the machine of "Policy on
macOS", kernel 7.2.7-200.fc44, podman 6.1.4, crun 1.30, through the launcher's jar from `sbt dist`
and its `--build`.

- The installed `policy.bpf.o` has SHA-256
  `e20c98e3b65a822cac01a5f4ae9e66c3e15b322fc039d1d66d22c5cdd3ff031f`, from sources of code digest
  `c2dfa0f6ee5ea9caf6d717a0a8e26561262a1a6f74e45985d51c37546fbc9940` (`sources.txt`: the backend
  and `KoAgentBpf.scala`, the launcher's side of it).
  - "Policy on macOS" and "Lifecycle on macOS" built the same object, byte for byte.
- Every one of the 59 rows passes in one run of 57 launches. Each launch is a `java -jar` of the
  launcher from a scratch git repository under `~`, with no other session on the machine.

| row                      | measured                                                              |
| ------------------------ | --------------------------------------------------------------------- |
| `io_uring_setup`         | answers `ENOSYS` to the session's first process and to a              |
|                          | `podman exec` process                                                 |
| the preloaded set        | the six launches whose steps the suite read each took one; the four   |
|                          | whose steps it prints attached in 0.0 to 0.2 ms, read back in 13.1 to |
|                          | 13.4 ms and tested in 32.7 to 37.5 ms. The read-back finds the taken  |
|                          | set's records the launch's, 4 roots and 55 rules, and the four record |
|                          | maps frozen, and the next set prepared, passing its check, unfrozen.  |
|                          | A live session's records read back the same before and after another  |
|                          | launch took a set, the two sessions' eight program ids disjoint; two  |
|                          | launches racing both took one, their programs disjoint                |
| a launch finding none    | with the preloaded set removed, the launch took the one its own       |
|                          | reconcile prepared at the launcher's start                            |
| another build installed  | with the lifecycle suite's `other.bpf.o` in the installed object's    |
|                          | place and its tags recorded, a launch ran and its read-back passed    |
|                          | against the new tags, so the set of the earlier build was not         |
|                          | attached; it took a set of the new build. The original object was put |
|                          | back afterwards, and its SHA-256 matched the installed one's          |
| a launch dead after the  | a session's record, its attach cgroup and the taken set's programs    |
| take                     | attached there with no container: the next launch's reconcile removed |
|                          | the pins, the record and the cgroup                                   |
| `unix-socket` session    | a `podman exec` process starts under `file_receive`, and its write to |
|                          | `.git/config` is refused; at `podman restart` the launcher's cleanup  |
|                          | removes the container and then the pins, within 30 s. The lifecycle   |
|                          | suite measures a restarted session's first process and `podman exec`  |
| the linked worktree      | the main checkout's session binds a socket in its tree, and a         |
|                          | host-made `.git/objects/s` links to it as `../../sock`: the main      |
|                          | session connects through the link; the linked worktree's session,     |
|                          | beside it under the same settings, answers `ENOENT`, the main tree    |
|                          | not being mounted there                                               |
| a FIFO the host made     | the session's `lstat` of it answers `EACCES`: the share refuses it    |
|                          | before any hook, the policy having none on `lookup` or `getattr`      |
| the refusals             | one workspace with two volumes, a main checkout and its linked        |
|                          | worktree sharing its volume, a workspace below another's root, a      |
|                          | linked worktree with its own volume beside its main checkout, and a   |
|                          | host rename of the workspace between the launches: each refused       |
|                          | beside a live session of the other backend and of the other           |
|                          | `unix-socket` setting, in both orders, 20 refusals; beside an         |
|                          | unlabelled container named as the launcher's, a `bpf` launch refused  |
|                          | and a `fuse` launch run; of two launches of one workspace under the   |
|                          | two backends racing, one ran and one was refused; a second session of |
|                          | one workspace under the same backend and setting ran. Each refusal    |
|                          | beside a labelled session names that session's settings, as in        |
|                          | `runs under --workspace=live,fuse`, and says to end it first or to    |
|                          | launch with the same backend and socket setting                       |
| in a session             | measured on 2026-10-26 in a `live,bpf,unix-socket` session: a socket  |
|                          | bind on the share and beneath the volume, and a bind, rename and link |
|                          | into `.git` and a bind in `.ko-agent-sandbox` refused, a share        |
|                          | descriptor passed over a socketpair inside the session                |
| the kernel's memory      | program sets loaded with the installed controller's `preload` into    |
|                          | one cgroup kept for the measurement, unattached: 1,518 to 1,520 KiB a |
|                          | set, nine programs and their maps, at one, four and eight sets        |
|                          | (`memory.current` 212,992 bytes before, 12,648,448 at eight), and     |
|                          | 225,280 after their removal                                           |


### Launcher on WSL

Measured on 2026-11-09 with `../test/podman/launcher/Launcher.scala` (`scala shebang`) on the
Windows machine of "One hook on WSL", kernel 6.18.54.1, podman 6.1.4 under the cgroupfs manager,
crun 1.28, through the launcher's jar and its `--build`.

- The installed `policy.bpf.o` has SHA-256
  `f8cd2eae6c890ad1e29ee0af77cb55cacbd07f98e2b4a964d4bfa55001f021b7`, from sources of code digest
  `c2dfa0f6ee5ea9caf6d717a0a8e26561262a1a6f74e45985d51c37546fbc9940`, the sources "Launcher on
  macOS" measures.
  - "Policy on WSL" and "Lifecycle on WSL" built the same object, byte for byte.
- Every one of the 42 rows passes in one run of 30 launches.
- The rows below name what differs from macOS; every other row passed as there.

| row                      | measured                                                              |
| ------------------------ | --------------------------------------------------------------------- |
| the preloaded set        | the six launches whose steps the suite read each took one; the four   |
|                          | whose steps it prints attached in 0.1 to 0.2 ms, read back in 26.0 to |
|                          | 31.9 ms and tested in 238 to 367 ms on 9p                             |
| the proof's cgroup       | on every launch the launcher's own proof joined the leaf below the    |
|                          | attach cgroup from a transient scope of the user manager, as          |
|                          | "Lifecycle on WSL" measured of the suite's; a scope that cannot be    |
|                          | made or a join that fails ends the launch script with status 4 before |
|                          | its placement step, which `KoAgentBpfTest` runs with those failures   |
|                          | stubbed                                                               |
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
| the kernel's memory      | 1,515 to 1,516 KiB a set (`memory.current` 0 bytes before, 12,414,976 |
|                          | at eight), and 4,096 after their removal                              |


