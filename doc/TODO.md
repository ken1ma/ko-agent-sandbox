# TODO

This file lists remaining work that adds real security or maintainability for the actual threat
model. This file also lists ideas whose benefit is uncertain, each with the condition that decides
whether to build it. design.md records each idea examined and found without benefit, with its
reason, so that nobody proposes it again.

## Credential brokering — `--egress-cred`, then the provider plan

- [ ] Run `sbt "testWithPodman *ProxyContainerTest"` on Linux. The proxy's attached `podman start`
  is measured, and passes, on macOS (podman 6.1.2, 2026-10-04) and on Windows (f3d413d).
- [ ] Check `--egress-cred` under `--run-on-host` against real hosts. `egress-proxy.md`, "Brokered
  credentials", has the GitHub session's measurement. The checks:
  - With `--run-on-host=sbt` and `maven.pkg.github.com` allowed in
    `.ko-agent-sandbox/run-on-host/sbt/egress/rule`:
    - `--egress-cred=GH_TOKEN@maven.pkg.github.com` resolves a private GitHub Packages artifact;
    - `env` in the command shows the placeholder;
    - `--egress-log` shows the sbt proxy's `inject=GH_TOKEN` line.
  - With a binding, `src/probe/ProcArgs.java` finds the value in no environment or argument of
    `podman`, the runner or a supervisor.
- [ ] Test that a host command's request reaches a local origin with the value. The test needs an
  origin that the host proxy trusts, and that proxy checks origins against the JDK's own trust
  store.
- [ ] Give a value without a recognized prefix a placeholder that its program accepts. A program
  that checks the value's syntax before sending the value refuses the placeholder of 22 letters
  and digits (`egress-proxy.md`, "Where the value goes").
- [ ] Run real sessions on `--egress-cred` before taking up `plan-provider-credential-proxy.md`.
  - Take that plan's steps one at a time, each on a use case those sessions produced, never as
    `--egress-cred`'s automatic second half.
  - What that plan adds, storage, generations, refresh and removal, is where the field failures
    are (docker/sbx-releases #492: a removed credential was still injected after a restart).
  - A per-run static value needs none of these.
- AWS is in neither: `design.md`, "Credential brokering at the egress proxy", explains why, and
  what a session forwards instead.
- [ ] Refuse a credential that is not the session's at a model host (SECURITY.md, "Exfiltration
  through allowed network traffic", has the attack).
  - This item is an exception to the order above: its use case came from a review of the
    documents, not from a session on `--egress-cred`.
  - A target of a service definition gains a property, `require-placeholder`. On a brokered target
    that carries the property, the proxy forwards a request only if one authentication form the
    target declares holds this run's placeholder and no other declared form is present.
  - The proxy refuses any other request with a fixed reason and a `deny` audit line, at every path.
  - The target declares every form the provider accepts, not only the one the client sends: a
    request without the client's header is not thereby unauthenticated.
    - Anthropic accepts an API key as `Authorization: Bearer` and as `x-api-key`
      (https://platform.claude.com/docs/en/manage-claude/authentication), so checking one header
      does not exclude a foreign key in the other.
    - The tests send a foreign key in each declared form, alone and beside the placeholder.
    - A form the provider adds later reopens the attack until the catalog declares it.
  - The property needs a selected service instance, so it needs the provider plan's delivery steps
    1, 2 and 5: the catalog, storage with per-run generations for a static key, the brokered
    overlay and one API-key client.
    - The property needs neither executable sources and refresh (step 4) nor OAuth (step 6).
    - An `--egress-cred=NAME@HOST` binding does not carry the property. That plan keeps the binding
      separate from a selected service. A binding also forwards a token that is not a placeholder
      and names one header, so a binding cannot refuse the placeholder beside a foreign key in
      another declared form.
  - The property protects an API-key session only. A subscription login stays a tunnel until
    step 6.
  - A workspace that tests against the provider with its own key selects no credential for that
    host, or accepts the refusal. Every other host keeps the rule that the proxy forwards a token
    that is not a placeholder (`egress-proxy.md`, "Where the value goes").
  - Measure first, with the model host inspected at the root:
    - the hosts and paths the installed `claude` calls, login and refresh included;
    - that a long server-sent-event stream survives the one-request-per-connection relay;
    - that `claude` trusts `NODE_EXTRA_CA_CERTS` on every connection to the provider.
  - Rejected: exact-path grants on the model host without brokering (`/v1/messages` alone).
    - The path list is the per-release contract with the CLI that brokering declines.
    - A retrievable-storage behavior added at an allowed endpoint reopens the attack.
    - The cost of the rejection: a subscription session gets no path-based protection before
      step 6, since exact-path grants refuse the storage endpoints whatever credential is sent.
  - Codex: taking the property to the OpenAI hosts needs these steps, each read from
    `--egress-log` (`design.md`, "Credential brokering at the egress proxy", has what is
    measured):
    - one `codex` turn that succeeds with those hosts inspected;
    - a second turn in the same session, to learn whether the refused upgrades recur per turn;
    - if the upgrades recur, a measurement of whether a custom `[model_providers.NAME]` with
      `supports_websockets = false` accepts the ChatGPT login. The built-in provider cannot be
      overridden (`design.md`, "No WebSocket on an inspected connection").

## Host process observations without helper processes

- [ ] Start no `ps`, `pgrep` or `lsof` under `--run-on-host`, where `RunOnHostSession.HostProcesses`
  starts them by absolute path. Make the kernel calls behind those programs through the JDK's
  foreign-function API instead, as `src/probe/ProcArgs.java` calls `sysctl`.
  - A helper inherits the environment of the runner or supervisor that starts it, and a call does
    not.
  - `ps` and `pgrep` read `sysctl` `kern.proc` and `kern.procargs2`; `lsof` reads libproc's
    `proc_pidinfo` and `proc_pidfdinfo`.
  - The registration script's `ps` runs inside the leader's perl and needs another form.

## What a host command reads of other processes

`run-on-host.md`, "The Seatbelt profile", has `SeatbeltProfile.ProcessReadRule` and its
measurement.

- [ ] Measure the older `kern.procargs` call under the rule; the probe reads `kern.procargs2`
  alone.
- [ ] Start what the launcher starts, the runner, each supervisor and `podman`, with a controlled
  environment: a fixed set of names and the `--env` forwards, and nothing else from the launching
  shell. The profile's rule is the boundary, and the controlled environment bounds what a miss in
  the rule exposes.
  - `podman`'s set starts from the variables its manual documents (podman(1), "Environment
    Variables"): `CONTAINERS_CONF`, `CONTAINER_CONNECTION`, `CONTAINER_HOST`,
    `CONTAINER_SSHKEY`, `PODMAN_CONNECTIONS_CONF`, `TMPDIR` and the `XDG_*` directories among
    them. `podman`'s client also reads `CONTAINER_PROXY` (`pkg/bindings/connection.go`), which
    that page does not list, so the page is not the whole set.
- [ ] Decide the operations, other than `process-info-pidinfo`, that `(deny default)` leaves
  allowed.
  - `(deny default)` leaves `process-info*`, `nvram*`, `iokit-get-properties` and
    `file-map-executable` allowed (Firefox's `SandboxPolicyContent.h`: "These are not included in
    (deny default)"; Chromium's `renderer.sb` denies the first three as "allowed by default").
  - The command profile names only `process-info-pidinfo`, which `ProcessReadRule` denies outside
    the command's sandbox.
  - The probe's `ops` mode measures a family by leaving the family's allow out under
    `(deny default)`. `(deny default)` denies none of these operations, so the mode cannot show
    that the JDK does without `file-map-executable` (`run-on-host.md`, "The Seatbelt profile") or
    `process-info*`.
- [ ] Measure under the rendered profile the other routes to another process's arguments,
  environment or memory. The profile grants none of these routes by name:
  - a task port (`task_for_pid` and its read, inspect and name flavors);
  - the process service `com.apple.sysmond` behind `pgrep`. The profile's one Mach service is the
    resolver's (`SeatbeltProfile.MachServices`), and `pgrep` fails under the profile with
    "sysmond service not found".

## The profile probe's confined sbt on this checkout

- [ ] `run-on-host-profile-iterate.sh`'s `run_command` fails under the rendered profile after
  `emit`, which runs an unconfined sbt in the same checkout. The cause is not found.
  - `sbt about` stops at `Compile / previousCompile` with `Operation not permitted` on
    `target/out/jvm/scala-3.8.4/ko-agent-sandbox-build/zinc/inc_compile_3.zip`, then prints
    "failed to connect to server" (2026-10-03).
  - `narrow` runs the same function in this checkout; `mach` runs it in its fixture.

## IDE integration through VS Code's Agent Host

- [ ] Carry out `plan-ide-integration.md` from its phase 1, in this order:
  - the measurements that step 2's "Not measured" paragraph says the relay's design needs first,
    then that design;
  - one harness (step 3);
  - `--protocol=ahp` (step 4), whose acceptance stages the same paragraph names.
  - ACP is deferred; the plan keeps ACP's reviewed design and the conditions that reopen it.

## The host microphone for voice dictation

`microphone.md` has the design and what is measured.

- [ ] On the latest stable Debian, Fedora and Ubuntu desktops, check:
  - the recorder programs their default installs carry;
  - whether ALSA's `default` PCM reaches the microphone;
  - the package to name;
  - the environment the reaper's job needs to find the audio server's socket (`XDG_RUNTIME_DIR`,
    `PULSE_SERVER`).

## Codex's `/voice`: WebRTC media through the egress proxy

- [ ] Serve Codex's `/voice` (`microphone.md`, "Codex"). Find what its WebRTC media connection
  needs, either UDP to the host and port the call's setup names, or TCP or TURN on 443. Then give
  the proxy a way to carry that connection.
  - The proxy can read the setup only by inspecting `chatgpt.com`, which its defaults tunnel.
  - A grant by address and port would be a new kind of egress rule, for the ruleset and
    SECURITY.md.
  - Then measure Codex's helper on the daemon:
    - whether the helper opens ALSA's `default` through the PulseAudio plugin with no card to
      list, and takes the null sink as its speaker;
    - whether capture and playback run together for minutes (openai/codex#47370's code 37). Try
      `pipewire-alsa` if alsa-plugins' pulse PCM fails (`microphone.md`, "Decisions");
    - whether the reply appears as transcript;
    - whether the helper's feature gate opens for the sign-in.

## A FIFO in the workspace hangs the podman machine

Decided 2026-10-25: on every platform, the creation of a FIFO in the workspace and a time change on
a FIFO there are refused, until libkrun opens the FIFO without blocking (`upstream-issues.md`,
containers/libkrun).

- [ ] File the libkrun report (`upstream-issues.md`, "Setting a FIFO's times blocks the macOS
  virtio-fs server"), with the kernel's flush path as the reason mere use of a FIFO triggers it.

Where the refusals are:

- The filter refuses both (`../ko-agent-fs/fuse/src/fs.rs`, `mknod` and `setattr`;
  `tests/mounted_mutate.rs`, `a_fifo_is_neither_made_nor_retimed_through_the_mount`).
- The BPF backend's hooks refuse both, and any open of a FIFO. Under the `unix-socket` value of
  `--workspace`, the hooks also refuse a FIFO's descriptor
  (`../ko-agent-fs/bpf/doc/architecture.md`, "The policy").

Why the refusals cover more than the creation:

- A session's write through a FIFO makes the guest kernel flush the FIFO's changed times to the
  share itself, with no `utimensat` from any process. Refusing creation alone would leave a FIFO
  the host made as a hang that a session can trigger by writing to it.
- The filter's daemon receives that flush as a `SETATTR` request and refuses it. The BPF hooks
  never see the flush, so the backend refuses the open instead.

## One list of launch refusals

- [ ] List every condition that stops a launch, in the launcher (`AgentSandboxLauncher.scala`,
  `SandboxWorkspace.scala`, `RunOnHostPrereqs.scala`, …) and in the filter's mount-time guard
  (`../ko-agent-fs/policy/src/guard.rs`). No document lists them all:
  - `SECURITY.md` has the guard's refusals;
  - `../ko-agent-fs/fuse/doc/troubleshooting.md` has some filter messages;
  - `run-on-host.md` has its prerequisites.
- [ ] Write one list from it in `doc/launch-refusals.md`, linked from `README.md` and
  `SECURITY.md`. Each entry gives the refusal's message, what the user does, and the document that
  records the refusal's reason. The reason stays where it was decided.

## A stale podman machine OS

A podman machine keeps the OS image `podman machine init` gave it until the user runs
`podman machine os upgrade --restart`, which the launcher prints and never runs (`SECURITY.md`,
"Silent changes to what you own"). Measured 2026-10-19: the machine of the BPF backend's evidence
(`../ko-agent-fs/bpf/doc/evidence.md`) ran an August image with kernel 7.1.8, while September's
image carried 7.2.5.

- [ ] At `--build`, print a notice when the machine's OS has an update. The dry run
  `podman machine os upgrade -n -f json` prints a boolean for that
  (https://docs.podman.io/en/latest/markdown/podman-machine-os-upgrade.1.html).
  - The dry run queries the registry, so it runs at `--build`, not at every launch.
  - The WSL provider does not support the command; `wsl --update` brings that provider's kernel
    (`README.md`). On WSL, the notice prints the WSL kernel version beside the one that evidence
    names.
- [ ] Print the machine's kernel version in the launch line, so that a report says which kernel a
  session ran on. `podman info` has the version as `host.kernel`.

## The run-on-host acceptance test's host prerequisites

The test names one fixture's missing host run at a time, after `emit` fails on that fixture. A
launch on this repository offers the runs of the nested mill and Gradle fixtures alone. Maven runs
from the workspace root's `mvnw` (`run-on-host.md`, "Maven"), and the mvn fixture and the Mill
1.1.10 copy are workspaces that only the test uses.

- [ ] Check every selected fixture before the first `emit`, print every missing host run at once,
  and exit. The check uses the launch's own findings (`RunOnHostProvisioning.finding`) through the
  test classpath, so that its wording is the refusals' wording.
- [ ] If that check is not built, list each fixture's host run in the script's header:
  `./mvnw --version` in `mvn-fixture`, `./gradlew --version` in `gradle-fixture`, and
  `MILL_VERSION=1.1.10-jvm ./mill --no-daemon version` in `mill-fixture`. The header holds the mill
  line.

## `src/probe/`: the rerun acceptance test apart from the one-off probes

`src/probe/` holds two kinds of file under one name. sbt runs some on every test run:
`run-on-host-acceptance-setup.sh` and `run-on-host-acceptance-test.sh` with the `*-fixture`
directories (`RunOnHostAcceptanceSetupTest`, `EmitRunOnHostProfile`). The rest measured something
once, such as `ProcArgs.java`, `ahp-hostile-host.py` and `seatbelt-semantics.sh`, and the code
cites them for what they measured.

- [ ] Move the acceptance test and its fixtures to a test location named for them, and keep
  `src/probe/` for the one-off probes. Update `run-on-host.md` and the code comments that cite
  the moved paths. The BPF backend's suites made the same split
  (`../ko-agent-fs/bpf/test/podman/`).

## Measure the agents under the `--nesting=none` seccomp profile

The profile (`SECURITY.md`, "No containers inside the sandbox by default") is measured with its
rules installed by hand on one shell (2026-10-17). `unshare -Ur` and `bwrap --unshare-user` are
refused. A thread and a child process in Python 3.14, Node 24 and Java 25, `git status`, `rg` and
`uv run` work. `claude`, `codex`, `kiro-cli`, `copilot`, `opencode` and `agy` start (`--version`).

- [x] In a session launched with the profile, run `sbt testFull` on the podman machine on Windows
  (x86_64). `SessionBoundaryTest` checks each refused syscall and that processes start.
  - `SessionBoundaryTest` passes on macOS (aarch64, podman 6.1.2) and on Windows (2026-10-26).
  - The Windows run's two failures are in other suites: `ClaudeManagedHelpersTest` (its own
    section below) and `KoReviewTest`.
  - `KoReviewTest`'s review cycle against the fake codex and claude exceeded its 300 s timeout on
    the `/mnt/c` workspace. Whether the profile or the share's speed caused the timeout is
    unmeasured.
- [x] Measure each installed agent, as the image configures it, running a command in such a
  session, and report one that fails to the user.
  - Each of the six runs a shell command without a prompt, in the session's own user, pid, mount,
    net and cgroup namespaces: the command's `/proc/self/ns/*` inodes equal the session shell's.
  - The agents measured: `claude -p` 2.1.310, `codex exec` 0.164.0, `agy -p` 1.4.7,
    `opencode run` 1.19.4, `kiro-cli chat --no-interactive` 2.34.0 and `copilot -p` 1.0.103.
  - The measurements ran on 2026-10-26 and 2026-10-27 in `--workspace=live,bpf,unix-socket`
    sessions on macOS. Each agent was signed in interactively first, and the launch's
    `--model-provider` named the agent's provider (`google`, `openai`, `aws`, `github`). Without
    that option, the agent's first request is refused.
  - Kiro rejected the seeded agent file, which lacked `name`. The Containerfile seed has the field.
    A volume seeded earlier needs the field edited into `~/.kiro/agents/ko-agent-sandbox.json`, or
    `--reset`.
  - [x] Playwright 1.64.1's Chromium 156 starts and renders a page under Playwright's default
    launch, which passes `--no-sandbox` (measured 2026-10-26, `chromium.launch()` with the
    headless shell and with the full browser).
    - With `chromiumSandbox: true`, Chromium dies with `No usable sandbox!`, since it needs the
      user namespace that the profile refuses.
    - Chromium has two needs beyond the image:
      - the download, `npx playwright install chromium`, reads `cdn.playwright.dev`, which
        redirects to `storage.googleapis.com`; both hosts need `read` rule lines;
      - ten shared libraries that the image lacks (`libnspr4`, `libnss3`, `libatk1.0-0`,
        `libatk-bridge2.0-0`, `libxcomposite1`, `libxdamage1`, `libxrandr2`, `libgbm1`,
        `libxkbcommon0`, `libatspi2.0-0`), which `ko-sandbox-apt-get` unpacked and
        `LD_LIBRARY_PATH` reached. Decide whether the image ships them.
  - `agy`'s Auto mode: `limitations.md` measures it under podman's default profile only.

## The `ko-agent-fs/` tree measured on both machines

The policy, the FUSE filter and the BPF backend share one tree (`../ko-agent-fs/Cargo.toml`). The
filter's binary is split into `ko-agent-fs`, the policy's `--resolve`, and `ko-agent-fs-fuse`, the
mount. These checks need the two machines:

- [ ] Rerun the launcher suite on both machines, and record "Launcher on macOS" and "Launcher on
  WSL" with the suite's new digest. The suite digests `KoAgentBpf.scala` and the BPF backend's
  Containerfile, whose code names the `ko-agent-fs/` paths. `SourceDigestCheck.scala` fails both
  sections until the reruns are recorded.
- [ ] Run `sbt testWithPodman` on both machines.

## The BPF backend's later versions

The first version of the BPF backend (`bpf-lsm-cgroup.md`) leaves these items to the versions after
it. Each item waits behind gates the suites name for it (`../ko-agent-fs/bpf/doc/evidence.md`,
"Suites"). Until then, the backend selector launches those sessions with the filter. On the podman
machines, the selector launches their `--workspace=read-only` sessions under the no-root policy,
which denies the whole share and needs none of the routes the first item names.

A quoted section name below without a document refers to one of the BPF backend's three documents,
whose section names are distinct.

- [ ] `NESTING=same-uid` and `NESTING=user-namespace` sessions, where the session mounts and creates
  user namespaces. The version needs:
  - the routes a nested podman needs, and the free slots;
  - overlayfs's `user.overlay.*` names;
  - the every-hook suite's nested-podman measurement;
  - the policy suite's alias and overlay rows. Among them is a copy-up that moves a protected object
    to a new inode in the overlay's upper layer, written during the copy and right after it. That
    object must stay protected by its position alone, and by nothing that waits on a notification
    from user space;
  - a key for `file_receive` other than the mount namespace, since a nested container of such a
    session would fail a mount-namespace key (`../ko-agent-fs/bpf/doc/architecture.md`, "The
    hooks").

  The version's policy suite rows:
  - the session binds the workspace and a nested filesystem at other paths in a mount namespace of
    its own, and mutates through the aliases and through an overlay mount;
  - a host hard link to a nested `.git` pointer file, made before and after launch. This is the
    residual that `../ko-agent-fs/bpf/doc/architecture.md` records under the second-name rule.

  The version's gate stays unmet until the user takes the two decisions below; nothing is
  pre-accepted.
  - Which routes stay open under `NESTING=same-uid`:
    - The seccomp rule cannot refuse the syscalls a nested podman needs ("Every hook on macOS",
      nested podman, in `../ko-agent-fs/bpf/doc/evidence.md`).
    - The two free slots (`../ko-agent-fs/bpf/doc/architecture.md`, "The hooks") can hold two of
      the routes' hooks.
    - A `NESTING=none` session attaches eight hooks and such a session ten, so both fit the
      machine's ten slots at once. One route's hook has no slot when something else in the VM
      holds a slot, or when a `unix-socket` session holds the ninth.
    - Each route's consequence when left open:
      - `inode_set_acl` open: an ACL set on a protected file rewrites its mode bits
        (`posix_acl_update_mode`), a `chmod` the hooks never see;
      - `inode_remove_acl` open: an ACL the host set on a protected file can be removed. The mode
        bits stay, since `fuse_set_acl`, `ext4_set_acl`, `xfs_set_acl` and `btrfs_set_acl` update
        the mode only for a non-null ACL;
      - `inode_setxattr` open: a `user.` xattr can be set on a protected file, which no host
        program here reads (`xattr_permission`; `cap_inode_setxattr` needs `CAP_SYS_ADMIN` for the
        other `security.` names);
      - `inode_setxattr` open, from a user namespace the session creates ("The policy"):
        `security.capability` can be set on a protected file.
        - `cap_inode_setxattr` exempts that name, and `cap_convert_nscap` admits it with
          `CAP_SETFCAP` in the caller's namespace for a file whose owner is mapped there
          (`security/commoncap.c`), as the session's own files are.
        - The capability written is namespaced to that user namespace, and no host process is in
          it;
      - `inode_removexattr` open: a `user.` xattr the host set can be removed. So can a
        `security.capability` the host set, from a user namespace the session creates
        (`cap_inode_removexattr`, `capable_wrt_inode_uidgid(..., CAP_SETFCAP)`);
      - `inode_file_setattr` open: a flag other than the append-only and immutable ones, or an
        `fsxattr` field other than the project id, can be set on a protected file the session
        owns ("Inventory", the row "file_setattr, 2 ioctls");
      - `file_ioctl` and `file_ioctl_compat` open: the commands of the "Inventory" row "other ioctl
        commands" reach a protected entry. Such an entry can have its ext4 generation and ctime
        set, get an encryption policy if it is an empty directory, or be made permanently
        read-only.
  - overlayfs's `user.overlay.*` names on protected directories, where the session can mount. No
    taken slot holds `inode_setxattr`, and the seccomp rule does not see overlayfs's own writes
    (`../ko-agent-fs/bpf/doc/architecture.md`, "Attributes, flags and ioctls"). Choose between:
    - accepting the names: a `user.` xattr on a protected directory, which no host program here
      reads;
    - `inode_setxattr` in a free slot on such sessions. That hook also holds the "Inventory" row
      "setxattr*, removexattr*" there, and leaves one free slot to the decision above.
- [ ] Native Linux hosts, as `bpf-lsm-cgroup.md`, "Native Linux", designs them. The version needs:
  - the controller's two refusals, and the mount under the bind source there with a nested mount
    holding a `.git`. The lifecycle suite measures these in the machines;
  - the host's own mount topology under the workspace (`../ko-agent-fs/bpf/doc/architecture.md`,
    "Mounts").
- [ ] The classifier in Rust, once `rustc` emits the CO-RE field relocations that the walk's reads
  need (https://github.com/aya-rs/aya/issues/349).
  - The user: "Rust should give us fewer vulnerabilities and fewer things to harden with great
    efforts." `bpf-lsm-cgroup.md`, "The recorded decisions this answers", has what the language can
    and cannot cost in the program.
  - The port keeps the shape the verifier accepted in C: the numeric-iterator loops with their
    state in map memory, the masks `barrier_var` keeps, and the global functions verified once per
    program. Each must be found under Rust's BPF target and measured on both kernels, as the
    every-hook and policy suites measured the C program.
  - A loader other than libbpf, for the controller or the port, must first be shown to resolve the
    object's CO-RE relocations as libbpf does on both kernels. The demonstration uses a fixture
    whose BTF holds two types of one name, since a loader that picks the wrong type reads the wrong
    field without an error (reported against Aya as its issue 1727, not verified here).

## The BPF backend as the default

`fuse` stays the default of both `--workspace` modes until a release decision.

- [ ] Make `bpf` the default once all of these hold:
  - the backend holds every promise of `bpf-lsm-cgroup.md` ("What a session can and cannot do",
    "Launches"), shown on both podman machines (`../ko-agent-fs/bpf/doc/evidence.md`);
  - a later version ("The BPF backend's later versions") holds the `.git` and protected-entry rows,
    for the sessions it admits, through an alias the session binds, an overlay mount the session
    makes and a nested mount the host made;
  - on native Linux, a later version holds the two refusals of `bpf-lsm-cgroup.md`, "Native Linux".

## A self-test of the BPF backend on the user's kernel

- [ ] Run the policy suite's corpus against the installed policy on the user's machine, as
  `--self-test` runs the filter's corpus.
  - The evidence covers two kernels, 7.2.5 and 6.18.54.1 (`../ko-agent-fs/bpf/doc/evidence.md`),
    and a user's machine runs the kernel its OS or WSL brings.
  - A launch's proof covers one refused operation per hook and one write per rule line, not the
    corpus's 252 cases.
  - One corpus, two runners: `exercise.c` moves into the bundled `ko-agent-fs/bpf/`, beside
    `fixture.c`, since `--build` builds only what the jar bundles and `test/` is excluded. The
    policy suite builds `exercise.c` from there and keeps its other rows: the race, the storm, the
    descriptors across sandboxes and the verifier figures.
  - Measure the self-test on both machines before it ships.

## Attribute routes as `--workspace` values, spending the free hook slots

Under `--nesting=none`, the seccomp profile refuses extended attributes, ACLs and `file_setattr`
everywhere in the session, `/home` and `/tmp` included, since a seccomp filter sees no path and no
descriptor's file (`SECURITY.md`, "The default's seccomp profile";
`../ko-agent-fs/bpf/doc/architecture.md`, "Attributes, flags and ioctls").

- The profile could refuse the ioctl commands that set a file's flags only by spelling every
  allowed command as a masked prefix, some 255 rules. The user's decision of 2026-10-26 left those
  rules unbuilt; the last item has what reopens them. On the machines, the shares answer those
  ioctls with `ENOTTY`.
- The BPF hooks could judge these operations by position instead, as the hooks judge the rest of
  the policy. But the seven hooks needed (`inode_{set,remove}xattr`, `inode_{set,remove}_acl`,
  `inode_file_setattr`, `file_ioctl{,_compat}`) exceed the free slots. The policy leaves two of the
  kernel's ten slots free, and one under `unix-socket`.

Decided 2026-10-26: the rule stays for every session, and the routes become values of
`--workspace` that a user selects, like `unix-socket`, each costing its slots.

- [ ] Add the values `xattr` (two hooks) and `acl` (two hooks), each allowed with `bpf` alone.
  - Under such a value, the session's hooks judge that family by position, and the launch's
    seccomp profile omits the family's rule.
  - A launch whose selected values need more slots than the machine has free is refused, and the
    refusal names the count. So the user cannot have every value at once.
  - File flags and the ioctls (three hooks) stay with the shares' own answers until a value for
    them fits. Native Linux ("The BPF backend's later versions") needs that value or the hooks,
    since its filesystems implement those operations.
  - The per-launch profile: one derived file per combination of values under the state root,
    beside `nesting-none.json`, named to `podman create` by path.
  - The read-back and the proof take the added hooks as they take `file_receive`: one refused
    operation per hook of the set (`../ko-agent-fs/bpf/doc/architecture.md`, "Lifecycle", 3).
  - Every sandbox on the machine shares the slots, and the `same-uid` version's nested podman needs
    some of these routes. Record in "The BPF backend's later versions" which values that version
    admits.
- [ ] Refuse in the seccomp profile, by masked prefixes, about 255 rules, the ioctl commands of
  two "Inventory" rows (`../ko-agent-fs/bpf/doc/architecture.md`): the two ioctls of the row
  "file_setattr, 2 ioctls", and the commands of the row "other ioctl commands". Do so once any of
  these holds:
  - a share, a kernel or a virtiofs server starts implementing `FS_IOC_SETFLAGS` or one of the
    other ioctl commands, which reopens that row (`../ko-agent-fs/bpf/doc/evidence.md`,
    "Environment evidence");
  - native Linux is admitted, whose filesystems implement these commands;
  - the compiled prefix filter is measured on both machines and found small enough beside podman's
    profile.

  The user's decision of 2026-10-26 left the refusal out of the first version: the shares'
  `ENOTTY` on both machines closes the two rows. The alternative is the value for file flags and
  the ioctls above.

## The proof fixture skipped on an unchanged launch

The BPF backend proves its attachment at every launch, restart and recreate, in two parts
(`../ko-agent-fs/bpf/doc/architecture.md`, "Lifecycle", 3):

- the read-back, 40 to 47 ms on WSL;
- the fixture's proof, 68 operations the kernel judges: 306 to 386 ms on WSL and 38 to 47 ms on
  macOS ("Lifecycle on WSL", "Lifecycle on macOS", in `../ko-agent-fs/bpf/doc/evidence.md`).

The user, 2026-10-26: 0.4 s on Windows matters. Every launch pays the proof until this item is
built.

- [ ] Run the proof on the first launch after a boot, after `--build`, after a rule change and
  after a failed proof; run the read-back on every launch.
  - The launcher keeps a marker beside the fixture tree. The marker holds the installed object's
    tag, the resolved rule set's hash and the boot id.
  - The launcher skips the proof while all three match the marker's, and the marker names a passed
    proof.
  - What a skipped proof does not catch: a defect that none of the three signals, such as a
    controller bug that depends on the session's own records. The read-back still proves the
    attached set, the tags and the records. Record that residual beside the rule when the rule
    ships.
  - The controller keeps the two parts of step 3 separable for this
    (`../ko-agent-fs/bpf/doc/architecture.md`, "Lifecycle", 3).

## The retired boot unit's removal

- [ ] Before the first release, delete what removes the boot unit that a839d14 and ee8793c
  installed with consent: `KoAgentBpf`'s "The boot unit of the builds a839d14 and ee8793c" section
  and its call in `installKoAgentBpf`, and its test in `KoAgentBpfTest`. No release ever installed
  the unit.

## The ordinary suites on a Windows host

`sbt testWithPodman` typed in PowerShell runs `testFull` in the Windows JVM, and the ordinary
suites assume a Unix JVM. Until those suites are fixed, `development.md` ("On Windows x64") runs
only the container-launching suites on Windows. That document's command returns to
`sbt testWithPodman` once the suites are fixed. The failures below are from Codex's run of
2026-10-27 on the EC2 machine, and a run of 2026-10-28 fails the same suites.

- [ ] Skip, with a clue, the tests that need a Unix host:
  - those running `sh`, `/bin/bash` or `/usr/bin/perl` (`RunOnHostAcceptanceSetupTest`,
    `RunOnHostSandboxTest`, `RunOnHostSessionTest`);
  - those setting POSIX permissions or reading the `unix` attribute view
    (`RunOnHostProvisioningTest`, `MicrophoneRelayTest`, `RunOnHostSessionTest`, and
    `SandboxStatsTest` and `RunOnHostSandboxTest` through `RunOnHostSession.publish`);
  - those calling `com.sun.security.auth.module.UnixSystem`, whose `UnsatisfiedLinkError` munit
    treats as fatal, aborting the rest of `RunOnHostSandboxTest`;
  - the Mill file and lock cases of `RunOnHostSandboxTest`, whose code answers `None` without a
    `SecureDirectoryStream`, which Windows lacks.
- [ ] Make the fixtures that spell Unix paths independent of the JVM's filesystem. An `Os.Mac` or
  `Os.Linux` argument does not change how `Path` parses a string. The fixtures are in
  `SeatbeltProfileTest`, `SeccompProfileTest`, `RunOnHostPrereqsTest` and `RunOnHostSandboxTest`,
  and in path cases of `OptionsFileTest`, `AwsCredentialTest`, `AgentSandboxLauncherTest`,
  `EgressRulesTest`, `SandboxStatsTest`, `SandboxWorkspaceTest`, `ClaudePluginsTest` and
  `SandboxLifecycleTest`.
- [ ] `ClaudePluginsTest`'s directory-symlink fixture loses `elsewhere/sbt-global` on Windows. The
  fixture makes the link before the link's target, and which link type Windows then makes is
  unchecked.

## Capabilities a `NESTING=none` session could keep

- [ ] Decide whether `NESTING=none` keeps `CAP_SYS_CHROOT`, which the session's `--cap-drop=ALL`
  removes (`AgentSandboxLauncher.scala`). Without the capability, containers-common's seccomp
  profile answers `chroot` with `EPERM`, in a user namespace the session creates too (measured
  2026-10-17: `unshare -Ur chroot / true` fails with `Operation not permitted`).
  - Grant it only for a tool the sessions run that needs it. Chromium's namespace sandbox is not
    one: it also needs a user namespace, which the `--nesting=none` seccomp profile refuses
    (`SECURITY.md`, "No containers inside the sandbox by default").
  - Record each risk of `chroot` with what removes the risk. Start from `SECURITY.md` ("No
    containers inside the sandbox by default"), which judges `chroot` for `same-uid`: nothing in
    the sandbox is chroot-confined, and `no-new-privileges` leaves no setuid program for a crafted
    root to confuse. podman grants the capability to every process in the session.
- [ ] Look for other capabilities a session could hold without weakening a boundary, and grant
  only those a tool the sessions run needs. For each capability, find:
  - the kernel checks that test it, and in which user namespace. podman grants the capability in
    the rootless container's user namespace, so a check against the initial namespace still fails,
    as for `CAP_LINUX_IMMUTABLE` and `CAP_DAC_READ_SEARCH` in
    `../ko-agent-fs/bpf/doc/architecture.md` ("Inventory", the rows "file_setattr, 2 ioctls" and
    "a second path");
  - the syscalls the seccomp profile allows only with it, such as `chroot` for `CAP_SYS_CHROOT`
    and `open_by_handle_at` for `CAP_DAC_READ_SEARCH` (`includes.caps` in
    https://github.com/containers/container-libs/blob/main/common/pkg/seccomp/seccomp.json; read
    the copy the podman machine's containers-common package installs);
  - which boundary in `SECURITY.md` or `bpf-lsm-cgroup.md` relies on its absence.
- [ ] A change that grants a capability also updates, in the same change:
  - the set that the entrypoint's check (`ko-sandbox-entrypoint`) and `SessionBoundaryTest.scala`
    expect;
  - the statement of that set in the first section of
    `../container/ko-agent-sandbox/AGENTS-SANDBOX.md`;
  - for `CAP_SYS_CHROOT`, the `same-uid` launch line (`LaunchMessages.scala`, `nestingLine`) and
    `README.md`'s `--nesting` entry, which name the capability as what `same-uid` adds.

## Japanese names in file rules

- [ ] Let `read-only` and `writable` lines name Japanese directories and files; `file-rules.md`
  limits names to `a`–`z`, `0`–`9`, `.`, `_`, `-` and `*`.
  - The filter's name matching rests on names being ASCII
    (`../ko-agent-fs/policy/doc/security-research.md`, "Real-filesystem case-folding: APFS and
    NTFS").
  - The run-on-host profile spells each name as a regex (`SeatbeltProfile.fileRuleFilters`).

## Deferred — executable agent configuration in the persistent volume

- [ ] Carry out `plan-executable-agent-configuration.md` in its two phases:
  1. reconcile the keys that name a program a later session starts without a tool call;
  1. make the code directories unwritable. Phase 2 waits for each agent's measurement on a refused
     write, which the plan names.

## Deferred — package-manager settings against malicious packages

SECURITY.md, "The supply chain", has npm's seven-day window and why uv gets none.

- [ ] Set Cargo's window, `registry.global-min-publish-age`, in `/.cargo/config.toml` once
  `--build` installs Rust 1.100 (2026-11-12), which stabilizes the setting. Rust 1.98.1 ignores
  the setting with a warning.
  - That file lets a `.cargo/config.toml` in the workspace shorten the window, as `.npmrc` does
    for npm's window. `CARGO_REGISTRY_GLOBAL_MIN_PUBLISH_AGE` would override the workspace's file.
  - A version already in `Cargo.lock` installs even when younger than the window. Measure first
    that `Cargo.lock` does not record the window, for uv's reason.
- [ ] Add a window for `cs`, Maven and Gradle, only once one of them offers a resolution-time
  setting that its lockfile does not record. A search on 2026-09-30 found none.
- [ ] Set npm's `ignore-scripts` only after measuring that the image's agents and the common `npx`
  targets still work when installed with lifecycle scripts skipped. An installation can succeed
  and leave a package unusable because the installation skipped a required script
  (https://docs.npmjs.com/cli/v11/using-npm/config/#ignore-scripts). An explicit `npm run` still
  runs its script.

## Deferred — GREASE ECH on inspected hosts

- [ ] Allow an ECH extension on an inspected host, only if a client that sends GREASE ECH —
  a browser, a BoringSSL-based program — enters the image.
  - The proxy is the TLS server there, so ignoring an extension it cannot decrypt is what every
    non-ECH server does. A GREASE client continues, a real-ECH client aborts on its own when the
    rejection is not confirmed, and the origin never sees the client's hello.
  - On a `tunnel` host the refusal stays: GREASE and real ECH are indistinguishable by design
    (RFC 9849, 6.2), and real ECH under a passing outer SNI is domain fronting through the allowed
    host (`TLSHelper`, the extension constant).
  - The change adds a second ECH step to SECURITY.md's handshake list and its tests.

## Deferred — inspected-connection keep-alive

- [ ] Client-side keep-alive on inspected connections, only if the per-request TLS handshake ever
  measurably hurts (104 handshakes added seconds to the recorded 104-archive install).
  - Both legs' framing is parsed and enforced, so the design is a request loop per client
    connection with a fresh origin connection per request.
  - The change needs a larger state machine at the enforcement point, and the one-request rule's
    smuggling argument re-argued in SECURITY.md.

## Deferred — Git LFS batch downloads

If `git lfs pull` becomes important:

- inspect the LFS batch request body;
- allow only `operation=download`;
- continue refusing upload;
- add end-to-end tests before enabling it.

Do not blindly allow the batch `POST` endpoint merely because downloads use it.

## Deferred — writable git from a linked worktree

A launch from a linked worktree binds the main worktree's Git directory read-only (`SECURITY.md`,
"The host's git executing what the sandbox wrote"). The writable form binds the `.git` of the main
worktree's filter mount at the same target, so the filter's policy governs that `.git`.
`worktrees/<name>` is a nested gitdir there. That gitdir's `config`, `hooks/`, `commondir` and
`gitdir` stay frozen while the session writes its index and refs
(`../ko-agent-fs/policy/doc/git-metadata.md`, "The immutable set"). Only `.git` crosses; the main
worktree's working files stay out of the session.

- The linked session joins the daemon of the main worktree's mount as one of that daemon's
  sessions. The session's marker goes under that mount's directory, so that the reap counts the
  session, and the mount-time guard runs on the main root (`KoAgentFs`).
- `--reset` in the main worktree unmounts that filter, and every linked session's git then fails
  with `ENOTCONN`. Either record that failure beside the volume's behavior (`SECURITY.md`, "What
  the persistent volume holds"), or refuse the reset while a linked session mounts the filter, as
  podman refuses the volume.
- Unverified: a bind of a subpath of the FUSE mount keeps the filter's positional classification.
  Lookups name the parent inode, so the bind should keep it. The mounted suite proves the
  classification before the bind is offered.
- The mount-path probe already asks about the target. The SELinux label question does not arise:
  the filter's mountpoint needs no relabel.

## Deferred — a linked worktree's absolute pointer on Windows

`git worktree add` writes the pointer as `C:/Users/<me>/repo/.git/worktrees/<name>`, which the
container's git cannot follow at `/mnt/c/...`, so the read-only bind is skipped there
(`SandboxWorkspace.linkedGitdirBind`). Two routes:

- A relative pointer resolves under `/mnt/c` as it does under `C:`, and the bind serves one.
  - But `git worktree add --relative-paths`, or `git worktree repair --relative-paths` for an
    existing worktree (git 2.48 or later), also sets `extensions.relativeWorktrees`. The image's
    git, Debian trixie's 2.47.3, refuses a repository with an extension it does not know, in the
    main worktree as in the linked one.
  - The launch reads the extension from the common config, and keeps the no-git warning with a
    note rather than promise git (`SandboxWorkspace.setsRelativeWorktrees`).
  - The route opens when the image's git is 2.48 or later, and that check goes with the upgrade.
    Until then only a hand-written relative pointer works, and `git worktree repair` rewrites such
    a pointer absolute.
  - "The workspace root mounted at its own path" has the row that measures the hand-written
    pointer.
- For an absolute pointer, bind a launcher-written pointer file naming the `/mnt/<drive>` spelling
  over `<mountPath>/.git`. The bind hides the filter's protected pointer from the container alone.
  - Setting `GIT_DIR` and `GIT_WORK_TREE` instead would redirect git in every other repository the
    agent uses, such as clones under `~`.
  - `<main>/.git/worktrees/<name>/gitdir` keeps the `C:/` spelling either way. `git worktree list`
    reads that file, and nothing the read-only bind serves needs it.

## Deferred — LAN destinations, as a session option

The proxy refuses every private, loopback, link-local and CGNAT address after resolution, and the
rule grammar refuses an IP literal. So a corporate site on the LAN without a public name is
unreachable from a session. If such a site is ever needed, this design keeps the security model:

- [ ] A launch option naming exact addresses: never a range, and never a line in
  `.ko-agent-sandbox/egress/`. The user selects the option at launch, and the banner tints it
  orange, as the banner tints `--run-on-host`.
  - An address is local to whoever runs the sandbox. A committed line would name a different
    machine on every clone, and a reviewer could not say what the line reaches.
- [ ] The vetting allows those addresses and nothing else of the private space, and only when
  the CONNECT names the address itself. A public name resolving to a private address stays
  refused. Otherwise a name whose answer changes, or a name with one public and one private
  record, would reach the LAN through the name.
- [ ] An exception to the lifecycle's step 10 for the listed addresses, and only those. A
  ClientHello with no SNI is the form a client sends to an address, and the proxy allows that form
  there. A ClientHello naming any host stays refused.
  - The connection is opaque, as the simplest form. An inspected address is possible, since the
    leaf can include an `iPAddress` name, and is its own further decision.
  - The opaque form's consequence is stated with the option:
    - nothing binds the tunnel to a name, so the origin's identity rests on the client's own
      certificate check, which the client may skip;
    - the grant reaches every application endpoint selectable at the address, by `Host`, by
      HTTP/2's `:authority` or by whatever protocol the client speaks after the handshake, since
      the proxy sees none of it.
- [ ] Stated cost, in SECURITY.md when it is implemented:
  - the traffic is a tunnel by construction: the hello allowed at step 10 leads to opaque
    application traffic at step 11, so request methods, targets and bodies are neither inspected
    nor logged;
  - the sandbox then reaches, from the host's own address, services that authenticate by
    location: router and NAS pages, dev servers, dashboards, registries and CI runners, with the
    cloud metadata endpoint in the same class;
  - port 443 and the one-client network bound the attack surface, not the trust.

## Deferred — the upstream proxy's interception CA, explicit resolvers, the container matrix

- [ ] Trust an upstream proxy's interception CA, so that a TLS-terminating upstream proxy stops
  failing closed with certificate errors (`egress-proxy.md`, "Through an upstream proxy").
  - Including the CA is authority: the CA lets that proxy read and change opaque model traffic. So
    the trust needs a launch-time selection and a banner line of its own.
  - Four stores are extended: the proxy's origin trust, the sandbox PEM bundle, the image JDK's
    `cacerts`, and `ko-sandbox-jdk-use-proxy`'s certificate.
  - An endpoint CA, for an `https` endpoint under a private CA, is carried the same way but extends
    one store only: the trust the proxy verifies the endpoint against. In any of the four stores,
    an endpoint CA would be interception authority.
- [ ] Explicit resolvers for the proxy container, only when podman's resolver stops answering for
  someone. podman's resolver follows the host's on Linux, and the host's through the machine
  elsewhere.
  - Any resolver keeps the all-answers-public check for origins: an internal mirror for a public
    name is a refusal naming the non-public answer, never a private address allowed.
- [ ] Run `ProxyContainerTest`'s upstream case on native Linux and in the macOS and Windows
  podman machines, and record whether each can route to a private endpoint.
  - A platform that cannot must fail the launch, never bypass the upstream proxy.
  - The same run checks whether an address the host has on its network reaches a loopback helper
    such as cntlm under rootless podman.

## Deferred — `--explain-request`, the ordered rules traced for one request

The rule file's order is its meaning (`egress-proxy.md`, "The rule file"). `--egress-check` answers
"is this host allowed", and the question left to an operator is "which line decided this request".
doas answers that question with `doas -C`, which evaluates a hypothetical command against the file
through the same code that would run it. The equivalent here is a trace:

- [ ] `--explain-request METHOD URL`, printing:
  - the request's classification;
  - each applicable line with the grant state it leaves;
  - the boundary the longest match selects;
  - the decision.
- [ ] The proxy's own resolver and authorizer emit the trace as they decide, run through the
  launcher's dry run. Production never gets a second evaluator:
  - the tests' plain ordered evaluator stays the oracle that the fold is checked against;
  - a trace that could disagree with enforcement would be worse than none.

## Deferred — staged-workspace extensions and hardening

These items are separate increments after the staged workspace in `plan-staged.md`, not reasons to
put all of its lifecycle into one change. `../ko-agent-fs/fuse/doc/architecture.md` ("Who may reach
the mount") defines the initial one-stage-per-workspace sharing unit and what happens when it
fails.

- [ ] Detect workspace-root replacement before attaching a persistent stage.
  - Record a host-only root identity, an optional resolved-gitdir identity and a small secondary
    fingerprint; ordinary branch switches and host edits must remain live.
  - An uncertain or different origin preserves the stage and requires explicit reattachment.
  - Reattachment must not rewrite the per-path baselines that detect apply conflicts.
- [ ] Create a host-only rollback bundle before applying a sealed generation.
  - The bundle records the original contents and metadata, the absence of new paths, and the
    sealed-plan identity, which makes a partial multi-file apply recoverable.
  - Preflight the bundle's storage cost, and require an explicit override when a bundle cannot be
    made.
- [ ] Treat stage and apply disk exhaustion as a boundary condition.
  - Preflight upper-layer, temporary-replacement, rollback and staged-control-journal space.
  - Fail writes or apply closed; retain a precise partial result.
  - Never spill into the host workspace, discard pending state, or fall back to live
    write.
  - The initial increment defines the live mutation journal's bounded, fail-closed storage
    behavior, and this item does not defer it.
- [ ] Add a tested host-side migration when a persistent stage representation first changes.
  - The staged-workspace increment versions upper layers and whiteouts, lower baselines, sealed
    generations and apply plans, and refuses an unknown version. Extend the manifest to rollback
    bundles when those are implemented.
  - A migration never silently reinterprets or deletes an older stage.
- [ ] Attribute mutations in shared live and staged workspaces to attached sessions where the
  request supplies reliable identity.
  - Keep this diagnostic and best-effort: journal entries may report an unknown session, and
    status may report multiple or unknown sessions. The workspace-wide journal or trusted
    upper-layer delta remains authoritative.
- [ ] Add non-interactive plan/apply only with a concrete automation use case.
  - `--stage plan` seals the current generation and returns a digest;
    `--stage apply --plan=<digest> --yes` applies the whole conflict-free plan.
  - The digest binds the workspace identity, representation version, generation, complete
    operation groups, content and metadata hashes, lower baselines, and rename and hard link
    relationships.
  - A mismatch changes nothing; path selection remains interactive and rewrites the remaining
    plan under a new digest.
- [ ] Add `--stage-name=<name>` only when one workspace needs concurrent independent staged change
  sets.
  - Each name selects a separate upper layer, merged mount, cache and failure domain over the
    same workspace; sessions sharing a name still share those resources.
  - Define safe name encoding, resource limits, management-command selection, workspace-wide apply
    serialization and migration from the sole unnamed stage before exposing it.

## Deferred — `--self-test`'s remaining share rows

`--self-test` runs share rows after the ko-agent-fs workspace's suites (`SelfTestShare.scala`,
`../ko-agent-fs/doc/testing.md`):

- the share is what the container suites cannot reach;
- the coherency rows cross the share launcher-driven and machine-recorded;
- the scratch is gone on success and kept on failure. The scratch's files tell a row that measured a
  refusal apart from a row where the probe broke;
- a killed run leaves nothing outside the mounts/ sweep, `--reset-all`'s container sweep and the
  named scratch.

Still to fold, to that same standard:

- [ ] The `probe/lower-probe.py` rows (hard-link identity, rename flags, symlink creation, case
  folding, open-file holds), with the launcher in place of `lower-probe-host.py`. Delete both probe
  halves when their rows are added. The rows' machine record adds the upper volume's filesystem,
  which the staged design needs the answers for (`plan-staged.md`).
- [ ] The row that needs `--run-on-host`: a command through the channel, then `target/` read back
  from the container. A host-native build turns host writes from an occasional human edit into
  every build.

## Deferred — keep the host awake during long sandbox work (caffeinate)

The design is recorded here so that it can be adopted or rejected deliberately rather than
redesigned from scratch.

**Problem.** A host that idle-sleeps mid-build suspends the podman machine: builds stall, and API
connections break. Claude Code solves the problem on macOS by wrapping long commands in
`caffeinate`. The agent here runs inside a Linux container, which cannot reach the host's power
manager. The launcher execs away on POSIX, so neither side has an obvious place to run
`caffeinate`.

**The lease design:**

- A `caffeinate` shim in the sandbox image, under the macOS name so that agents' trained habit
  transfers. The shim accepts the familiar flags (`-t`, `-w`), execs the wrapped command with its
  exit status passed through, and refreshes a lease file under a dedicated mount every 15 s while
  the command runs.
- The launcher mounts a launcher-owned lease directory there and starts a host-side watcher.
  - The watcher reads lease **freshness, never content**, so there is nothing to inject into.
  - The channel is one bit whose worst misuse drains a battery. The channel belongs in
    SECURITY.md's low-bandwidth list once the feature is built.
- The watcher per host:
  - macOS: a detached sh loop (reaper pattern) runs `/usr/bin/caffeinate -i -t 20` while the lease
    is fresh. The assertion doubles as the poll interval, so there is no child pid to manage;
  - Linux: the same loop runs `/usr/bin/systemd-inhibit --what=idle:sleep`, where that absolute
    path exists;
  - Windows: a daemon thread in the resident launcher calls kernel32
    `SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)` through FFM. The state is per
    thread and clears when the thread dies, so there is no teardown path;
  - WSL is a documented gap: the Linux mechanism cannot reach the Windows power manager.
- Simpler work that comes with it:
  - on macOS, `--build` and `--update` run under `caffeinate -i` unconditionally: the work is
    finite, so there is no reason to ask;
  - *not* a session-wide environment-variable wrap. The launcher's only scope is the whole session,
    where an idle open agent would keep the laptop awake; scoping the lease to a command avoids
    that.

**Open questions:** whether the feature is worth building at all, and whether a container→host
channel, however narrow, should exist for a convenience. One constraint on any implementation:
command builders must take the podman path as a parameter, never read the global. Reading the
global fails fast on podman-less machines and kills the test JVM.

## Deferred — read grants a user adds to a host command's profile

The `curl` that macOS ships does not run under a command's profile: LibreSSL stops at
`fopen('/private/etc/ssl/openssl.cnf')`, `Operation not permitted` (`run-on-host.md`, "The
command's lifetime and environment"). The launcher grants a system path only where a build
measurably needs it (`SeatbeltProfile.SystemPaths.txt`), and no build here runs `curl`.

- [ ] A way for a user to add a read grant, only once a build of theirs needs such a program:
  `/private/etc/ssl/openssl.cnf` is the first case.
  - Where the grant is stated decides who can widen a profile:
    - a file under `.ko-agent-sandbox/run-on-host/` arrives with the repository, as the program's
      rule file does, so the launch prints the file as it prints that rule file's hosts;
    - a launch option is the user's alone.
  - The grant covers reads of single files, never a write, an exec or a directory. A grant for a
    path under the user's home is refused: what a host command cannot read there is its
    confinement.
  - Before choosing the form, measure that `curl` fetches from an allowed host with that one file
    granted. The acceptance test's "CA bundle variables" rows print what `curl` does, and whether
    `curl` then reads `CURL_CA_BUNDLE` or `SSL_CERT_FILE`.

## Deferred — Node for ScalablyTyped and scalajs-bundler under `--run-on-host`

Both plugins run `npm install` from the sbt JVM, which a host command cannot do (read from the
code, not measured):

- The command's `PATH` is the JDK's `bin` and the system directories, and the profile executes
  nothing else, so no Homebrew, nvm or asdf `node` or `npm` is found or run
  (`RunOnHostSandbox.scala`, the command's environment; `SeatbeltProfile.SystemPaths.txt`).
- `HOME` passes through, so npm's cache is `~/.npm`, which the profile does not grant.
- The plugins, read at scalajs-bundler `2d9cbce` and ScalablyTyped Converter `c2c414f`:
  - scalajs-bundler runs `npm install` (or `yarn`) by name in its install directory under the target
    (`ExternalCommand.scala`). scalajs-bundler runs `node` for bundling (`JSBundler.scala`) and for
    tests under jsdom (`JSDOMNodeJSEnv.scala`), so it needs Node at every build, not only at
    install.
  - ScalablyTyped runs `npm install` (or `yarn`) by name in `<crossTarget>/scalablytyped-npm`
    (`NpmInstall.scala`). Under its external-npm plugin, it calls the project's own `externalNpm`
    task instead, which returns a directory holding `package.json` and `node_modules`
    (`docs/plugin-no-bundler.md`). ScalablyTyped publishes what it converts to the Ivy home's
    `local` (`Utils.IvyLocal`), which the run-on-host cache holds.

- [ ] Measure the workaround that needs no change here: ScalablyTyped's external-npm plugin with
  `externalNpm` returning a directory the session ran `npm install` in, in the container. Record
  whether the conversion then runs on the host without Node.
- [ ] A Node a host command may run, only once a build needs it on the host, in the shape of the
  mill launcher's grant:
  - a Node distribution the user provisions, read-only and executable, on the command's `PATH`,
    never the host's `PATH`;
  - npm's cache in the workspace's run-on-host cache (`npm_config_cache`), not `~/.npm`;
  - the registry allowed in the sbt program's egress rule. `HTTPS_PROXY` and `NODE_EXTRA_CA_CERTS`
    already reach Node (`run-on-host.md`, the CA variables' table). npm's use of the proxy and of
    HTTP/1.1 through the inspecting proxy is still to be measured;
  - what `npm install` then runs on the host: the lifecycle scripts of every package, under the
    command's profile. SECURITY.md's "Run on host" should state that beside the limit that
    `node_modules` already has there.

## Deferred — a bound on a silent host command

The runner's progress bound limits the start of an sbt server and of a mill daemon
(`run-on-host.md`, "The channel and the command", "`mill`"). A command that stalls after its
server or daemon is up, or a Maven command at any point, stays silent until the agent gives up.
Nothing bounds such a command: not the supervisor, not the runner, whose writers die only with
their requester, and not the shim, which reads output to EOF. One form would bound it, and that
form waits on a measurement:

- [ ] A generic bound in the runner: no output for N seconds ends the command through the same
  SIGTERM, so the command's logs are kept. A stderr line names the bound and the run's
  `run-on-host.log`.
  - Silence is measured where the command's bytes are read, and time the pump spends blocked on a
    slow requester does not count.
  - N must exceed a healthy silence: a module compiling, a large download (which the proxy logs
    once, at its start) or a slow test. A value below a healthy silence is not a one-off failure.
    The rerun hits the same silence, and the workspace cannot build on the host until the constant
    changes.
  - Five minutes is the smallest value defensible without measurement.

A time-to-first-output limit would miss stalls after the JVM prints its `_JAVA_OPTIONS` banner.

## Deferred — a container mill or gradle beside the host's daemon

Under `--run-on-host`, the host's mill daemon keeps its lock and `socketPort` in the workspace's
`out/mill-daemon`. A `./mill` run in the container without `MILL_OUTPUT_DIR` uses the same `out/`.
The rules allow the bootstrap's downloads by default, so an agent can run it.

- [ ] Measure, on a small mill build with a host daemon up, what the container's `./mill` does
  with the host's lock and port, and what the host's next command does with what the container
  left.
  - The same run measures a cold compile with and without `MILL_OUTPUT_DIR` under `~/.cache`.
    `../ko-agent-fs/fuse/doc/troubleshooting.md` ("Everything works but slowly") says that this is
    not measured.
  - If the two conflict, the run-on-host text that the launcher appends is the place to tell an
    agent to set the variable.
- [ ] Measure the same conflict for gradle. The two sides' daemon registries are separate: the
  host's registry is under the runner's temporary directory (`RunOnHostSandbox.gradleCommand`),
  and the container's registry is in its gradle user home. But both builds use the workspace's
  `build/` and the locks under its `.gradle/`, and the rules allow `./gradlew`'s download by
  default.

## Deferred — an idle bound for the sbt server

The runner sets no idle bound on its sbt server. The server lives until the launch ends, until
`ko-sandbox-run-on-host sbt shutdown`, or until sbt's own `serverIdleTimeout` of seven days
(`run-on-host.md`, the startup-cost paragraph). A terminal user keeps a warm server on purpose, so
the server's heap is the price chosen. Mill's daemon exits after Mill's own thirty minutes.

The form, if a launch ever wants one:

- The runner keeps the bound, and a launch option selects it. An environment variable cannot
  select it, since the command's environment is closed by design.
- Thirty minutes, Mill's default, is the value to start from.
- Idle time counts from the end of the last sbt command, never from the server's start.
- The runner's serve loop blocks in the handshake reader between requests, so the bound needs a
  timer thread. That thread is the one thread that retires runtimes outside the serial dispatch,
  and it is fenced as follows:
  - one lock covers the runner's runtime state;
  - a request takes the lock, marks the runtime busy and cancels its pending expiry before the
    command receives the runtime, and re-arms the expiry when the command ends;
  - each re-arming increments an idle generation kept with the runtime;
  - an expiry carries the generation it was armed with. Under the lock, the expiry retires the
    runtime only if that instance is idle and its generation is still the expiry's own. So a
    cancelled callback that had left its sleep before a request re-armed the timer does nothing,
    and a timer that outlives a retired runtime does nothing to the replacement.

The bound's tests: a request arriving as the timer fires, that late callback, and a stale timer
after replacement, each leaving one consistent runtime.

## The workspace root mounted at its own path

- [ ] Run `sbt "testWithPodman *MountPathTest"` on Linux; all Linux cases must pass.
- [ ] On Windows, run the launcher inside a WSL distribution — as a Linux program, with Java and
  rootless podman installed there — from `/mnt/c/Users/<me>/src/app`: `bash -c pwd` must print
  that path, the one a PowerShell launch of the same directory prints.
- [ ] On Windows, from a linked worktree whose `.git` holds a relative pointer (hand-written until
  the image's git reads `extensions.relativeWorktrees`): the launch must print `git is read-only
  in this session`, `git status` must work in the session, and `git add` must fail.

Recorded macOS results (2026-09-18):

- `MountPathTest`, `MountLifecycleTest` and the run-on-host acceptance test pass.
- `sbt testFull` inside a session passes in every suite except `ClipboardRelayTest` and
  `SandboxLifecycleTest`; those two pass when run alone on Linux.
- The four agents start without a trust prompt on fresh and used volumes.
- A host build's error reports a path accessible inside the session.

Recorded Windows results (Windows Server 2025, 10.0.26100.32522, podman 6.1.0; 2026-09-19):

- A launch from PowerShell in `C:\Users\<me>\src\app` mounts the filter at
  `/mnt/c/Users/<me>/src/app`, and `bash -c pwd` prints that path.
- A launch from PowerShell in `\\wsl.localhost\podman-machine-default\home\user\<dir>` is
  refused with `error: cannot map ... into the podman machine`, before any `workspace:` line.
- A first launch of a new workspace prepares the image's JDK (`JdkTrust.prepareScript` through
  `HostCommands.quoteFreeSh`) and reaches a shell.
- Under `KO_AGENT_SANDBOX_CLIPBOARD=paste`, `xclip -selection clipboard -t image/png -o` in the
  session reads a copied image, 15498 bytes, through both wrapped clipboard execs.

## Claude Code plugins (`--claude-plugin-dir`)

- [ ] On Windows, a plugin holding a file with a second name (`mklink /H`) must be refused with
  "has a second name", and a plugin without one must be accepted. `FFMHelper.kernel32.numberOfLinks`
  has never run; its struct offset and flags come from the Windows API reference.
- [ ] On Windows, a plugin holding a directory junction (`mklink /J`) must be refused as "a
  junction, device or pipe". The walk's `isOther` check is measured on POSIX with a pipe alone.
- [ ] Inside a session launched with the probe (`src/test/claude-plugins/managed-probe/README.md`),
  run `sbt testFull`. `SessionBoundaryTest`'s plugin-mount test runs only there, and has not run
  yet.
- [ ] Run `claude plugin test src/test/claude-plugins/managed-probe` on the host. The command has
  not run, since the sandbox turns the test kit off under `allowManagedHooksOnly`.

## Deferred — readable session directory names under `--run-on-host`

- [ ] Name the sessions `runner-<random>` and `command-<random>` instead of `r<random>` and
  `s<random>` (`RunOnHostSession.Kind`), once the path length allows it.
  - The session's `tmp/` hosts sbt's boot socket. `RunOnHostPrereqs.SessionTmpMaxLength` leaves
    that path 53 characters, of which the root and Java's 20-digit temp-directory name take 51.
  - The longer names need one of two changes:
    - sbt's boot socket comes to need fewer than its 50 characters past the directory. The fix
      that the thin-client entry requests only turns the crash into a message, and lifts no length
      (`upstream-issues.md`, "The JVM thin client crashes instead of reporting a long boot-socket
      path").
    - The session names get a shorter random part of their own, with the collision retry that
      `Files.createTempDirectory` does.
- [ ] Name the root after the launcher and the feature,
  `/private/tmp/ko-agent-sandbox-run-on-host-<uid>` in place of `/private/tmp/ko-agent-<uid>`
  (`RunOnHostSession.root`), under the same budget. Otherwise a second host feature that keeps
  state under `/private/tmp` would land in a root that names neither feature.

## Deferred — the per-command supervisor process under `--run-on-host`

- [ ] Re-evaluate the supervisor, the `--run-command-on-host` process the runner starts for each
  request (`RunOnHostSandbox.runCommandMain`; `run-on-host.md`, "The channel and the command").
  - What it buys:
    - the runner's cancel is a SIGTERM to one process, answered by that process's shutdown hook,
      which ends exactly the command's groups and directory;
    - a command's death, however it dies, is confined to its own process and never takes the
      runner and its warm servers with it;
    - the acceptance test drives one command's whole lifecycle as `RunOnHost` with no runner, which
      is how the supervisor rows measure the profile.
  - What it costs:
    - one more JVM start per command, about a third of a second in the jar form and tens of
      milliseconds as the native image;
    - a second code path for the command's runtime, the supervisor's own under Maven.
  - The alternative is the same work in a runner thread, with cancellation done by hand. Decide
    with the measured cost per command, and with what the acceptance test would drive instead.

## Deferred — the native-image launcher

A GraalVM (JDK 25) native image, built with `native-image` and a C toolchain, starts in tens of
milliseconds where `java -jar` takes ~350 ms.

- The launcher branches on running as an image (`RunOnHostSandbox.isNativeImage`: the supervisor's
  self-invocation, its launch file, the Seatbelt proxy inputs). The launcher stays resident when
  GraalVM refuses the FFM execvp (`SandboxLifecycle.handOver`).
- No build or test exercises any of this code.
- The proxy as an image does not start under its profile, and fails with
  `Fatal error: CSunMiscSignal.open() failed` (macOS 26.4.1, GraalVM CE 25.0.2,
  `run-on-host-profile-iterate.sh mach-proxy <binary>`).
- What the profile lacks for the proxy image is unmeasured. So are the image's Mach services, which
  the same mode measures once the image starts.

The build:

    sbt dist
    cd target/dist
    eval $(cs java --jvm graalvm-community:25 --env)
    export PATH="$JAVA_HOME/bin:$PATH"
    native-image --enable-native-access=ALL-UNNAMED \
      --add-exports=java.base/sun.security.x509=ALL-UNNAMED \
      --add-exports=java.base/sun.security.util=ALL-UNNAMED \
      -H:IncludeResources='sandbox-build/.*|defaults/.*|agentsandbox/.*' \
      -o ko-agent-sandbox -jar ko-agent-sandbox.jar

- [ ] Build the binary in CI, and run the launcher suite as the binary on both shipping
  architectures. Only then does the README offer the binary. build.sbt's comments explain the two
  exports and the resource includes that the command carries.
- [ ] Compute the bundle digests (`LauncherImages.bundledSourceId`) while `native-image` builds the
  binary, with build-time initialization. The binary then hashes nothing at launch, and
  `bundleSourceId` stays the one implementation. Check first that the bundled resources are
  readable at that point.
- Java Sound is not available in an image (oracle/graal,
  `substratevm/.../hosted/jdk/JNIRegistration*.java`, read at `master` on 2026-10-09).
  - native-image copies a JDK library that its code loads by literal name next to the binary. But
    native-image ships the JNI metadata and `libjava` shim exports that such a library needs for
    AWT only, not for `libjsound`.
  - No issue in oracle/graal reports Java Sound in an image.
  - Nothing in the launcher uses Java Sound; the microphone relay's Windows relay records through
    `sox_ng` (`microphone.md`, "Decisions").
  - The jar hashes its three bundles in about 30 ms (a fresh JVM in a Linux container,
    2026-09-28), too little to justify an sbt step that precomputes them with the launcher's own
    classes.
- [ ] Decide the native image together with the published identity: whether the binary is a
  release artifact at all, or `java -jar` and a Coursier command are the two forms.

## Review plugin (`ko-review.md`)

- [ ] Have a Codex author ask the skill's three questions, reviewer, model and effort, as
  selectable menus, as a Claude author does with AskUserQuestion. A Codex author asks them instead
  in its reply, with numbered options that the user types back (`ko-review.md`). Codex's
  `request_user_input` can be that menu once both of these hold:
  - Codex's default mode offers the tool as a stable feature;
  - the tool allows more than three options per question.

  Until both hold, the skill keeps the prose question.
  - `default_mode_request_user_input` is under development (`ko-review.md` has the measurement).
    Once the feature is stable but still off, the image's Codex defaults enable it.
  - The tool's schema asks for "2-3 mutually exclusive choices" (openai/codex `main`, 2026-10-18).
    That limit leaves out choices such as `high` after the default, `low` and `medium`, and
    free-form entry does not replace a selectable option. The option limit of
    `request_user_input_async` is unverified.
  - Codex's default-mode prompt reserves the tool for optional questions and has required ones
    asked in plain text. So the menu words each question as optional, with the recommended choice
    first.
- [ ] Check a linked worktree whose main Git directory is mounted read-only. The test suite covers
  the helper's path (`ko-review.md`, "Tests"), and `SECURITY.md` covers the session's git reads.
  One session launched from such a worktree and driven to approval closes this item.

## Deferred — `--add-dir`, a further host directory in the workspace

- [ ] `--add-dir=<path>` exposes another host directory to the sandbox beside the workspace root,
  as the `--add-dir` of Claude Code, Codex, Antigravity and Copilot widens their own file access.
  `design.md`, "Terminology", keeps `--workspace` for the mode and names the single directory the
  workspace root, so added directories need no rename. To settle before building:
  - whether an added directory follows the workspace mode or carries its own;
  - where its file rules and egress rules come from, since `.ko-agent-sandbox` is read at the
    workspace root;
  - whether it may be a repository of its own, and which Git entries the filter then protects;
  - whether the launcher refuses the home directory and its credential directories there as it
    does for the workspace root;
  - whether exposing a directory also records it as trusted for each agent and loads its
    instructions and skills, as Copilot's `--add-dir` loads the directory's `.github/skills`.
    `ko-sandbox-entrypoint` records trust for the workspace root only.

## Before the first release — the former records directory

- [ ] Delete `LauncherState.formerWorkspacesStateRoot`, its `--reset-all` step and its
  `ResetRecordTest` case once the machines that launched before the workspace rename have run
  `--reset-all` or removed `<state root>/projects/` by hand. Nothing writes or reads that
  directory; a machine that never removes it keeps a few path strings, no resource.

## Before the first release — continuous integration

There is no CI. [development.md](development.md#tests) gives the launcher, proxy and filter
test commands. `--self-test` runs the filter suites on demand. A user's `--build` instead performs
the checks whose results depend on that artifact and machine: `cargo deny check licenses bans
sources`, compilation, binary identity, and the installed filter's mount self-test.

- [ ] Add CI for the launcher's and proxy's `sbt testFull`, and the filter's pure and binary suites
  on both shipping architectures. Add `cargo deny check advisories` there: `deny.toml` records why
  its moving external database must not block installation.
- [ ] Keep the checks above in `--build`, and keep the mounted filter suites in
  `--self-test`; CI does not prove the filter on a user's own machine.

## Before the first release — the published identity

- [ ] One decision that must settle several names together:
  - the jar's artifact name and publication coordinates;
  - the Scala package names (`agentsandbox.*`, containing neither the `ko-` prefix nor an
    organization);
  - the image label key (`ko-agent-sandbox.bundle` — OCI convention wants a reverse-DNS key, and
    the right prefix is this same identity, so deciding the key alone would decide the identity by
    accident).

  Until then a changed key ends in the "rebuild with --build" refusal, so the exposure is bounded.
