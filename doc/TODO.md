# TODO

This file lists remaining work that adds real security or maintainability for the actual threat
model. This file also lists ideas whose benefit is uncertain, each with the condition that decides
whether to build it. design.md records each idea examined and found without benefit, with its
reason, so that nobody proposes it again. `TODO-run-on-host.md` lists the work on `--run-on-host`,
and `TODO-win.md` the work that only a Windows host has.

## Credential brokering — `--egress-cred`, then the preset plan

- [ ] Run `sbt "testWithPodman *ProxyContainerTest"` on Linux. The proxy's attached `podman start`
  is measured, and passes, on macOS (podman 6.1.4, fdf1d04, 2026-11-02) and on Windows (f3d413d).
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
- [ ] Implement `plan-preset-credential-proxy.md` in its delivery order. At a selected credential's
  refusing hosts, the refusal stops uploads under a foreign key in a form that the catalog
  declares (SECURITY.md, "Exfiltration through allowed network traffic").
- [ ] Decide `plan-login-brokering.md`, which brokers the agents' own logins so that the refusal
  covers a signed-in session.
- [ ] Measure `CODEX_ACCESS_TOKEN@openai`, which the preset plan delivers from Codex's source, with
  a token from a ChatGPT Business or Enterprise workspace, once the plan's step 2 has landed:
  - launch with `--egress-preset=openai --egress-preset-cred=CODEX_ACCESS_TOKEN@openai bash` and
    run `codex exec --skip-git-repo-check "say ok"`;
  - expect `inject=CODEX_ACCESS_TOKEN` on `auth.openai.com`'s
    `/api/accounts/v1/user-auth-credential/whoami` and on the `chatgpt.com` requests, and record
    every host whose lines carry `cred=`. A line with `cred=` and no `inject=` sent the placeholder
    where the entry does not substitute;
  - record the result in `ko-agent-egress-proxy/doc/preset/openai-evidence.md`.
- AWS is in neither: `design.md`, "Credential brokering at the egress proxy", explains why, and
  what a session forwards instead.

## The brokered login store off disk

`plan-login-brokering.md` keeps an agent login's real tokens in the persistent volume's `store`
subdirectory, a plaintext file at rest. Keeping them off disk takes a secret that no file holds:

- [ ] The host's keychain holds a key, the launcher pipes it to the proxy at launch as it pipes a
  brokered value, and the store holds the tokens encrypted under it. No refresh crosses to the
  host, unlike tokens kept in the keychain themselves.
  - Open: the hosts without a keychain, such as a Linux host without a Secret Service.
  - A key in a file encrypts nothing: whoever reads the store reads the key.

## The layout container

`plan-preset-credential-proxy.md` ("The volume's store") runs a short-lived container on every
launch to settle the persistent volume's layout, so that the serving proxy mounts only `store`.

- [ ] Skip that container on a settled volume. A new volume and a `0.0` volume need it; the launch
  must still refuse a layout version that it does not know, which today only that container reads.

## Server tools that connect where a request says

A model request can make the provider connect to a server the request names, outside the ruleset
(SECURITY.md, "The web reached through the model provider"). Anthropic's Cowork proxy "blocks
headers that would enable server-side fetch", without naming them
(https://www.anthropic.com/research/how-we-contain-claude). Each control below waits for a
measurement showing whether Claude Code or Codex sends what it refuses:

- [ ] Refuse `anthropic-beta: mcp-client-*` at `api.anthropic.com`, which turns on the MCP
  connector (https://platform.claude.com/docs/en/agents-and-tools/mcp-connector). Claude Code's
  evidence lists `/v1/mcp_servers`, so the measurement comes first.
- [ ] Refuse a request whose body declares `web_fetch` or `mcp_toolset` in its `tools` at
  `api.anthropic.com`, or `mcp` at `api.openai.com`
  (https://developers.openai.com/api/docs/guides/tools-connectors-mcp.md).
  - The proxy parses no body today. design.md rules out a body field only as a log field ("Model
    hosts inspected by default"), so a refusal by body needs a decision of its own.
  - The tool types carry version dates, so the check follows each release's names.
  - Claude Code's WebSearch runs on the provider's servers, so the check leaves the search tool
    alone.

## Comparable sandboxes, read for ideas to take

Each pass reads a project's current release for what this launcher lacks or does worse. The pass
records each idea where its decision lives: an adopted idea in a plan or this file, a declined one
in design.md with its reason. The pass then updates the project's line here with the version
read and the ideas still undecided.

- nono (https://github.com/nolabs-ai/nono): a sandbox with a credential proxy, a sandbox per tool,
  Sigstore attestation of skills and instruction files, a tamper-evident audit log and file
  rollback. Read 2026-11-21: nono-proxy 0.82.0, and the documentation at e75c83b. Undecided:
  - Sandboxed OAuth logins (`docs/cli/features/sandboxed-oauth-logins.mdx`) are taken up in
    `plan-login-brokering.md`.
  - [ ] A placeholder in a declared shape, such as `sk-ant-oat01-{}` or `ghp_{}`, for a client that
    checks a token's prefix. The item on values without a recognized prefix, under "Credential
    brokering", needs this.
  - [ ] AWS SigV4 re-signing at TLS-intercepted hosts, which answers 403 to a key ID that the
    profile does not name (`docs/cli/features/credential-injection.mdx`). design.md leaves
    re-signing out.
- Docker Sandboxes (https://github.com/docker/sbx-releases): the releases and issues, the source of
  many failure reports that design.md cites. Not yet read as a pass. Its agent logins, brokered by
  answering the token endpoint (https://github.com/docker/sandbox-kit-spec, `credential@1.md`,
  `oauth`), are weighed in `plan-login-brokering.md`.
- sandbox-runtime (https://github.com/anthropics/sandbox-runtime), Claude Code's sandbox:
  credential masking, SigV4 re-signing and violation reports. Not yet read as a pass.
- Codex's `codex-rs/network-proxy` (https://github.com/openai/codex): the credential broker and
  the policy decisions handed to the agent. Not yet read as a pass.
- greywall (https://github.com/GreyhavenHQ/greywall), a sandbox without containers, and clampdown
  (https://github.com/89luca89/clampdown), a container sandbox; both broker credentials. Not yet
  read as a pass.
- OpenShell (https://github.com/ai-openshell/openshell), an agent runtime whose proxy
  TLS-terminates and swaps placeholders, with Copilot CLI as a provider. Its gateway alone refreshes
  OAuth tokens and writes each new access token to the provider record
  (https://docs.nvidia.com/openshell/latest/how-it-works/providers/overview.md, "Credential
  Refresh"). Not yet read as a pass.
- Lens sandbox-core (https://github.com/lensapp/lens-sandbox-core), the policy, proxy and
  credential library of Lens's sandbox. Its proxy answers OAuth token and refresh requests with
  placeholders (`oauthTokenAnswer`, `oauthRefreshAnswer`, PR #63). Not yet read as a pass.
- iron-proxy (https://github.com/paradigmxyz/iron-proxy), an egress firewall that swaps secrets,
  and GitHub's agentic-workflow firewall (https://github.com/github/gh-aw-firewall), which sets
  each Copilot host's `Authorization` scheme (`containers/api-proxy/providers/copilot-auth.js`).
  Not yet read as a pass.

## IDE integration through VS Code's Agent Host

- [ ] Carry out `plan-ide-integration.md` from its phase 1, in this order:
  - the measurements that step 2's "Not measured" paragraph says the relay's design needs first,
    then that design;
  - one harness (step 3);
  - `--protocol=ahp` (step 4), whose acceptance stages the same paragraph names.
  - ACP is deferred; the plan keeps ACP's reviewed design and the conditions that reopen it.

## The host microphone for voice dictation

`mic.md` has the design and what is measured.

- [ ] On the latest stable Debian, Fedora and Ubuntu desktops, check:
  - the recorder programs their default installs carry;
  - whether ALSA's `default` PCM reaches the microphone;
  - the package to name;
  - the environment the reaper's job needs to find the audio server's socket (`XDG_RUNTIME_DIR`,
    `PULSE_SERVER`).

## Codex's `/voice`: WebRTC media through the egress proxy

- [ ] Serve Codex's `/voice` (`mic.md`, "Codex"). Find what its WebRTC media connection
  needs, either UDP to the host and port the call's setup names, or TCP or TURN on 443. Then give
  the proxy a way to carry that connection.
  - The defaults inspect `chatgpt.com`, so the log shows the setup's paths.
  - A grant by address and port would be a new kind of egress rule, for the ruleset and
    SECURITY.md.
  - Then measure Codex's helper on the daemon:
    - whether the helper opens ALSA's `default` through the PulseAudio plugin with no card to
      list, and takes the null sink as its speaker;
    - whether capture and playback run together for minutes (openai/codex#47370's code 37). Try
      `pipewire-alsa` if alsa-plugins' pulse PCM fails (`mic.md`, "Decisions");
    - whether the reply appears as transcript;
    - whether the helper's feature gate opens for the sign-in.

## A FIFO in the workspace hangs the podman machine

Decided 2026-10-25: on every platform, the creation of a FIFO in the workspace and a time change on
a FIFO there are refused, until libkrun opens the FIFO without blocking (`upstream-issues.md`,
containers/libkrun).

- [ ] File the libkrun report (`upstream-issues.md`, "Setting a FIFO's times blocks the macOS
  virtio-fs server"), with the kernel's flush path as the reason mere use of a FIFO triggers it.

Where the refusals are:

- The FUSE backend refuses both (`../ko-agent-fs/fuse/src/fs.rs`, `mknod` and `setattr`;
  `tests/mounted_mutate.rs`, `a_fifo_is_neither_made_nor_retimed_through_the_mount`).
- The BPF backend's hooks refuse both, and any open of a FIFO. Under the `unix-socket` value of
  `--workspace`, the hooks also refuse a FIFO's descriptor
  (`../ko-agent-fs/bpf/doc/architecture.md`, "The policy").

Why the refusals cover more than the creation:

- A session's write through a FIFO makes the guest kernel flush the FIFO's changed times to the
  share itself, with no `utimensat` from any process. Refusing creation alone would leave a FIFO
  the host made as a hang that a session can trigger by writing to it.
- The BPF hooks never see that flush, so the BPF backend refuses the open instead. The FUSE
  backend's daemon receives the flush as a `SETATTR` request and refuses it.

## One list of launch refusals

- [ ] List every condition that stops a launch, in the launcher (`AgentSandboxLauncher.scala`,
  `SandboxWorkspace.scala`, `RunOnHostPrereqs.scala`, …) and in the workspace policy's guard
  (`../ko-agent-fs/policy/src/guard.rs`). No document lists them all:
  - `SECURITY.md` has the guard's refusals;
  - `../ko-agent-fs/fuse/doc/troubleshooting.md` has some of the FUSE backend's messages;
  - `run-on-host.md` has its prerequisites.
- [ ] Write one list from it in `doc/launch-refusals.md`, linked from `README.md` and
  `SECURITY.md`. Each entry gives the refusal's message, what the user does, and the document that
  records the refusal's reason. The reason stays where it was decided.

## The `ssh` that `podman machine ssh` runs on macOS

- [ ] Check whether a workspace can supply the `ssh` that `podman machine ssh` runs on macOS.
  - The launcher runs it on macOS (`KoAgentFs.scala`, `SandboxStats.scala`), and podman inherits
    the launcher's `PATH`.
  - Under `npm run`, that `PATH` starts with `node_modules/.bin`, which `findOnPath` refuses for the
    launcher's own programs (design.md, "No repository-controlled host executable resolution").
  - Check with a `node_modules/.bin/ssh` in a workspace and a launch from an `npm run` script.
  - If podman runs it, put the system `ssh`'s directory first on macOS, as `hostProcess` does
    with Windows OpenSSH (design-win.md, "Every process the launcher starts finds Windows OpenSSH
    first").

## `src/probe/`: the shell probes as Scala CLI scripts

`development.md`, "Probes", says to write a host-side probe as a standalone Scala CLI script.
Five probes in `src/probe/` are shell scripts. Four run on the macOS host, and
`podman-attach-stdin.sh` runs on any host with podman.

- [ ] Rewrite each shell probe as a Scala CLI script, and update the documents and code comments
  that cite its path: `jvm-proxy-rule.sh`, `loopback-rule.sh`, `podman-attach-stdin.sh`,
  `seatbelt-semantics.sh` and `session-recovery.sh`.

## BPF suite reruns

The suites whose sources changed since their evidence was measured. One rerun of a suite clears
its item (`../ko-agent-fs/bpf/doc/evidence.md` has the procedure).

- [ ] Rerun the Launcher suite on macOS, and rewrite "Launcher on macOS" from the rerun. The code of
  `KoAgentBpf.scala` differs from the sources of that section's evidence of 2026-11-09.

## The BPF backend's later versions

The first version of the BPF backend (`bpf-lsm-cgroup.md`) leaves these items to the versions after
it. Each item waits behind gates the suites name for it (`../ko-agent-fs/bpf/doc/evidence.md`,
"Suites"). Until then, a `bpf` launch of those sessions is refused, read-only ones included, and
the refusal names `fuse`.

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
    "Mounts");
  - `--self-test`'s BPF corpus rows there, which run on the podman machines alone
    (`../src/main/scala/BpfSelfTest.scala`).
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

- the read-back, 25 to 48ms on WSL;
- the fixture's proof, 68 operations the kernel judges: 354 to 388ms on WSL and 35 to 46ms on
  macOS ("Lifecycle on WSL", "Lifecycle on macOS", in `../ko-agent-fs/bpf/doc/evidence.md`).

The user, 2026-10-26: 0.4s on Windows matters. Every launch pays the proof until this item is
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

## The uid/gid mapping warm-up's retirement

- [ ] Remove `ImageBuilds.warmUpUidGidMappingCopies` and its calls once rootless podman stops
  copying an image for a new uid/gid mapping. On Windows, where the copy took about 100s,
  `--update` then prints `warmed … in` under a second.
  - `--update` rebuilds the sandbox image without cache. A `--build` that reuses the cached image
    reuses its copy too, so its short duration shows nothing.
  - Podman's maintainers call the copy expected: the kernel allows ID-mapped mounts to root alone,
    and they know of no plan to change that.
    https://github.com/podman-container-tools/podman/issues/26479

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

## The guard's read-only paths in the sbt build volumes

- [ ] Under the BPF backend, skip an sbt build whose `project` or `project/target` lies under a path
  the workspace policy's guard makes read-only, before creating either directory.
  `SbtBuildVolumes.plan` consults only the rule lines, so a build inside a hook directory the
  repository keeps, or inside a listed symlink's target, gets an empty `project/target` created on
  the host and hidden in the session.
  - `KoAgentBpf.Launched.resolved` holds the guard's `read-only-path` and `read-only-under` entries
    in `createUnderLaunchLock`, before `podman create`, so `SbtBuildVolumes.prepare` can move there
    and consult them.
  - The FUSE backend resolves those entries at its mount, after the create, and keeps the gap.

## One term for the file rules' pinned names, in documents, comments and identifiers

The workspace policy calls a name pinned when a listed name passes through it, as `.claude` for
`.claude/settings.json` does, when the guard traversed it, or when it is a gitdir's `objects` or
`objects/info`. The policy refuses to rename or unlink a pinned name, and refuses to create anything
at it except an empty directory by `mkdir`. It allows `rmdir` of that directory, and each entry
inside follows its own rules (`RuleContext::pinned` and `authorize_rule_create` in
`../ko-agent-fs/policy/src/policy.rs`). "Pin" is this project's own word for this, and readers meet
it undefined:

- `file-rules.md`, "The rule file", says "`*` pins every entry it matches". The same document's
  opening list describes the behavior without the word.
- `../ko-agent-fs/fuse/doc/troubleshooting.md` sends a reader of `pinned-file-rule-component` to
  `file-rules.md`, which never defines it.
- The BPF backend also uses "pin" in the kernel's sense, a file in the BPF filesystem
  (`../ko-agent-fs/bpf/doc/architecture.md`, "Lifecycle"), and `policy.bpf.c` uses both senses.

- [ ] Choose the term with the user. Facts the choice must fit:
  - The name may hold a symlink as well as a directory: the guard traverses symlinks, and
    `.claude -> shared/claude` makes the symlink a component of a listed name.
  - "Protected" already has another meaning: `Protected` in
    `../ko-agent-fs/policy/doc/git-metadata.md` and the `protected-*` refusal reasons mean that
    the session cannot modify the entry at all. A pinned directory stays writable inside.
  - Candidates so far: "fixed name", "held name", or plain wording such as "a name that a listed
    name passes through".
- [ ] Rename the term in documents, comments and identifiers in one change. The identifiers include:
  - the resolved rules' `pinned-path` word;
  - `RuleWord::Pinned`, `RuleContext::pinned` and `is_pinned_within_gitdir`;
  - the refusal reasons `pinned-file-rule-component` and `pinned-git-component`;
  - the BPF program's `R_RULE_PINNED`, `R_GIT_PINNED` and record fields;
  - `FileRules`, `SeatbeltProfile` and `BpfCorpus` on the Scala side.

  `rg -i 'pinned[-_ ]?(path|file-rule|git|component)|is_pinned|R_\w*PINNED|\.pinned\(\)'`
  lists the code. The change alters every BPF suite's sources, so each suite joins "BPF suite
  reruns".
- [ ] Replace each loose use of "pin" with the verb it stands for:
  - `bpf-lsm-cgroup.md`, `the commit "Inventory" pins`: names;
  - `../ko-agent-fs/fuse/doc/TODO.md`, "the open descriptor pins": keeps alive;
  - `plan-executable-agent-configuration.md`, "pinned (`allowManagedHooksOnly`)" and "No
    requirement pins `notify`": fixes through a managed setting.

  Version pins stay, by the decision recorded in commit 1c1639b.
- [ ] Consider an AGENTS.md rule that an identifier and the documents and comments that name it
  always change together, so that an agent renames both without asking. Record the rule's reason in
  `../agents-prompt-rationale.md`.

## Japanese names in file rules

- [ ] Let `read-only` and `writable` lines name Japanese directories and files; `file-rules.md`
  limits names to `a`–`z`, `0`–`9`, `.`, `_`, `-` and `*`.
  - The workspace policy's name matching rests on names being ASCII
    (`../ko-agent-fs/policy/doc/security-research.md`, "Real-filesystem case-folding: APFS and
    NTFS").
  - The run-on-host profile spells each name as a regex (`SeatbeltProfile.fileRuleFilters`).

## A sandbox removed with a plain `podman rm -f` leaves its home volume

The sandbox's home is an anonymous volume (`--mount type=volume,dst=/home/nonroot`). Every launcher
removal passes `--volumes` (`SandboxLifecycle.scala`, `LauncherState.scala`), and a normal exit
removes the volume through `--rm`. A user's `podman rm -f` without `--volumes` keeps it (measured
on Windows, podman 6.2.0).

- [ ] Let `--reset` find such a volume. An anonymous volume carries no link to its workspace, so
  the sweep cannot attribute it. One candidate: create the home as a volume named and labeled per
  run, which the sweep removes like the run's networks, and check that podman still copies the
  image's home into it.

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

## Deferred — Claude Code's hint headers on the audit line

- [ ] Print Claude Code's hint headers as fields of the inspected `allow` line, only if a reader of
  the log needs to attribute a model request to a prompt or a subagent, and a measurement shows
  that the headers arrive through the proxy.
  - The headers are `x-claude-code-` followed by `session-id`, `prompt-id`, `request-class`,
    `agent-type`, `agent-id`, `parent-agent-id`, `compaction` and `context-compacted`
    (https://code.claude.com/docs/en/llm-gateway-protocol, "Gateway hint headers").
  - That page says Claude Code sends them by default on a direct connection, and not by default
    under a custom base URL. A launch sets `HTTPS_PROXY`, not `ANTHROPIC_BASE_URL`, and which of
    the two cases that is has not been measured.
  - The values are the client's free text. So each field needs the rule that `client=` has: the
    line prints a value's start, as far as its characters are in a fixed set
    (SECURITY.md, "The audit line grammar").
  - `x-claude-code-prev-tool-durations` stays out: it is up to 4 KB of timing data.
  - The proxy would hold a list of a client's header names, which each release can change.

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

## Deferred — an HTTP/2 relay for gRPC hosts

- [ ] Inspect HTTP/2 on a host, only if an agent's model traffic needs HTTP/2, or
  `aicode.googleapis.com` serves more than agy's `/voice` and its `fetchConfig`.
  - agy's `/voice` streams over gRPC, which needs HTTP/2, so a workspace that dictates in agy adds
    `aicode.googleapis.com` as a tunnel. The proxy offers only `http/1.1` to the client
    (`TLSHelper`).
  - The relay would read each stream's headers, check its method and path against the rules,
    print a line per stream, and relay the data and trailers to an HTTP/2 origin connection.
  - The proxy has no HTTP/2 code: the framing, HPACK, flow control and stream resets are new code
    or a new dependency.
  - SECURITY.md's one-request argument is re-argued for the streams of one connection, as
    keep-alive needs.
  - The relay is the only way to inspect such a host. Tunnelling only the connections whose
    ClientHello offers `h2` alone would give any process a tunnel by offering it.

## Deferred — Git LFS batch downloads

If `git lfs pull` becomes important:

- inspect the LFS batch request body;
- allow only `operation=download`;
- continue refusing upload;
- add end-to-end tests before enabling it.

Do not blindly allow the batch `POST` endpoint merely because downloads use it.

## Deferred — writable git from a linked worktree

A launch from a linked worktree binds the main worktree's gitdir read-only (`SECURITY.md`,
"The host's git executing what the sandbox wrote"). The writable form binds the `.git` of the main
worktree's FUSE mount at the same target, so the FUSE backend governs that `.git`.
`worktrees/<name>` is a nested gitdir there. That gitdir's `config`, `hooks/`, `commondir` and
`gitdir` stay frozen while the session writes its index and refs
(`../ko-agent-fs/policy/doc/git-metadata.md`, "The immutable set"). Only `.git` crosses; the main
worktree's working files stay out of the session.

- The linked session joins the daemon of the main worktree's mount as one of that daemon's
  sessions. The session's marker goes under that mount's directory, so that the reap counts the
  session, and the mount-time guard runs on the main root (`KoAgentFs`).
- `--reset` in the main worktree unmounts that FUSE mount, and every linked session's git then fails
  with `ENOTCONN`. Either record that failure beside the volume's behavior (`SECURITY.md`, "What
  the persistent volume holds"), or refuse the reset while a linked session uses that mount, as
  podman refuses the volume.
- Unverified: a bind of a subpath of the FUSE mount keeps the FUSE backend's positional
  classification. Lookups name the parent inode, so the bind should keep it. The mounted suite
  proves the classification before the bind is offered.
- The mount-path probe already asks about the target. The SELinux label question does not arise:
  the FUSE backend's mountpoint needs no relabel.

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
  - Including the CA is authority: the CA lets that proxy read and change every host's traffic,
    the model hosts' included. So the trust needs a launch-time selection and a banner line of its
    own.
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
- [ ] Run `ProxyContainerTest`'s upstream case on native Linux and in the macOS podman machine,
  and record whether each can route to a private endpoint.
  - The Windows podman machine can (WSL2 6.18.58.1, podman 6.2.0; 2026-11-24). A container
    resolves `host.containers.internal` to 172.20.96.1, and the upstream case passes through it,
    with the firewall rule of `egress-proxy.md`, "Through an upstream proxy".
  - A platform that cannot must fail the launch, never bypass the upstream proxy.
- [ ] On native Linux and in the macOS and Windows podman machines, check whether an address the
  host has on its network reaches a loopback helper such as cntlm under rootless podman.
  - `ProxyContainerTest`'s upstream proxy binds on every interface, so its pass leaves this open.

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
  exit status passed through, and refreshes a lease file under a dedicated mount every 15s while
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

## The workspace root mounted at its own path

- [ ] Run `sbt "testWithPodman *MountPathTest"` on Linux; all Linux cases must pass.
- [ ] On Windows, run the launcher inside a WSL distribution — as a Linux program, with Java and
  rootless podman installed there — from `/mnt/c/Users/<me>/src/app`: `bash -c pwd` must print
  that path, the one a PowerShell launch of the same directory prints.

Recorded macOS results (2026-09-18):

- `MountPathTest`, `MountLifecycleTest` and the run-on-host acceptance test pass.
- `sbt testFull` inside a session passes in every suite except `ClipboardRelayTest` and
  `SandboxLifecycleTest`; those two pass when run alone.
- The four agents start without a trust prompt on fresh and used volumes.
- A host build's error reports a path accessible inside the session.

Recorded Windows results (Windows Server 2025, 10.0.26100.32522, podman 6.1.0; 2026-09-19):

- A launch from PowerShell in `C:\Users\<me>\src\app` mounts the FUSE backend at
  `/mnt/c/Users/<me>/src/app`, and `bash -c pwd` prints that path.
- A launch from PowerShell in `\\wsl.localhost\podman-machine-default\home\user\<dir>` is
  refused with `error: cannot map ... into the podman machine`, before any `workspace:` line.
- A first launch of a new workspace prepares the image's JDK (`JdkTrust.prepareScript` through
  `Podman.quoteFreeSh`) and reaches a shell.
- Under `KO_AGENT_SANDBOX_CLIPBOARD=paste`, `xclip -selection clipboard -t image/png -o` in the
  session reads a copied image, 15498 bytes, through both wrapped clipboard execs.

Recorded Windows results (WSL2 6.18.58.1, podman 6.2.0, BPF backend; 2026-11-23), from a linked
worktree whose `.git` holds the hand-written pointer `gitdir: ../<main>/.git/worktrees/<name>`:

- The launch prints `git is read-only in this session`.
- `git status` in the session works, and `git add` fails: git cannot create `index.lock` in the
  main worktree's gitdir, a read-only file system there.

## Claude Code plugins (`--claude-plugin-dir`)

- [ ] Inside a session launched with the probe (`src/test/claude-plugins/managed-probe/README.md`),
  run `sbt testFull`. `SessionBoundaryTest`'s plugin-mount test runs only there, and has not run
  yet.

Recorded Windows results (WSL2 6.18.58.1, podman 6.2.0; 2026-11-23), from launches with
`--claude-plugin-dir` on plugins under `%TEMP%`:

- A plugin holding a file with a second name (`New-Item -ItemType HardLink`) is refused with "has
  a second name (a hard link)", so `FFMHelper.kernel32.numberOfLinks` counts links.
- A plugin holding a directory junction (`New-Item -ItemType Junction`) is refused as "a junction,
  device or pipe".
- A plugin with neither is accepted, and the banner lists it as `ok@host`.

## Deferred — the native-image launcher

A GraalVM (JDK 25) native image, built with `native-image` and a C toolchain, starts in tens of
milliseconds where `java -jar` takes ~350ms.

- The launcher branches on running as an image (`RunOnHostSandbox.isNativeImage`: the supervisor's
  self-invocation, its launch file, the Seatbelt proxy inputs). The launcher stays resident when
  GraalVM refuses the FFM execvp (`SandboxLifecycle.handOver`).
- No build or test exercises any of this code.
- The proxy as an image does not start under its profile, and fails with
  `Fatal error: CSunMiscSignal.open() failed` (macOS 26.4.1, GraalVM CE 25.0.2,
  `RunOnHostProfileIterate.scala mach-proxy <binary>`).
- What the profile lacks for the proxy image is unmeasured. So are the image's Mach services, which
  the same mode measures once the image starts.

The build:

    sbt dist
    cd dist
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
- [ ] Build the binary with the GraalVM release that `container/debian-graalvm/Containerfile`
  pins: in that image on Linux, and from the release its `ARG` lines name on macOS and Windows.
  - The command above installs GraalVM with `cs java`, but Coursier's JVM index stops at GraalVM
    Community 25.0.2.
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
    `sox_ng` (`mic.md`, "Decisions").
  - The jar hashes its three bundles in about 30ms (a fresh JVM in a Linux container,
    2026-09-28), too little to justify an sbt step that precomputes them with the launcher's own
    classes.
- [ ] Decide the native image together with the published identity: whether the binary is a
  release artifact at all, or `java -jar` and a Coursier command are the two forms.

## Deferred — `--add-dir`, a further host directory in the workspace

- [ ] `--add-dir=<path>` exposes another host directory to the sandbox beside the workspace root,
  as the `--add-dir` of Claude Code, Codex, Antigravity and Copilot widens their own file access.
  `design.md`, "Terminology", keeps `--workspace` for the mode and names the single directory the
  workspace root, so added directories need no rename. To settle before building:
  - whether an added directory follows the workspace mode or carries its own;
  - where its file rules and egress rules come from, since `.ko-agent-sandbox` is read at the
    workspace root;
  - whether it may be a repository of its own, and which Git entries the workspace policy then
    protects;
  - whether the launcher refuses the home directory and its credential directories there as it
    does for the workspace root;
  - whether exposing a directory also records it as trusted for each agent and loads its
    instructions and skills, as Copilot's `--add-dir` loads the directory's `.github/skills`.
    `ko-sandbox-entrypoint` records trust for the workspace root only.

## Deferred — a WSL distribution's Coursier cache as the overlay

- [ ] Evaluate letting `--cache-overlay=coursier` on Windows use the Coursier cache inside a WSL
  distribution, which the option refuses (`design.md`, "A cold Coursier cache, and the host's as an
  opt-in overlay"). podman runs in its own distribution, `podman-machine-default`, which sees
  Windows drives at `/mnt/<drive>` but not another distribution's files. The candidates:
  - run the launcher inside that distribution as a Linux program with its own podman, so that the
    Linux discovery finds `~/.cache/coursier/v1`. "The workspace root mounted at its own path"
    lists that setup as untested;
  - point the distribution's Coursier at the Windows cache with `COURSIER_CACHE=/mnt/<drive>/...`,
    which needs no launcher change; builds in WSL then read their cache from the Windows drive, at
    an unmeasured speed;
  - accept a directory inside the podman machine, under the contract for a server's directory that
    "Deferred — remote podman connections" would state.

## Deferred — `--cache-overlay` on macOS

`design.md`, "A cold Coursier cache, and the host's as an opt-in overlay", has the decision, and
`upstream-issues.md`, containers/podman, the evidence.

- [ ] File the podman report (`upstream-issues.md`, "A macOS machine cannot select its virtio-fs
  permission semantics").
- [ ] Once a podman release shares host folders with one owner whoever asks, allow the option on
  macOS:
  - remove `CacheOverlay.MacRefusal`;
  - give the cache the data volume's single spelling, as `SandboxWorkspace.canonicalWorkspaceRoot`
    gives the workspace root, since the machine does not share `/System/Volumes/Data`;
  - run `CacheOverlayLifecycleTest` on macOS.

## `--cache-overlay` on native Linux

The option is enabled on native Linux, and no run there has verified it yet.

- [ ] Run `sbt "testWithPodman *CacheOverlayLifecycleTest"` on native Linux, and on an
  SELinux-enforcing host, whose snapshot then covers the labels. Refuse the option on a host where
  podman changes the cache's metadata or needs container labels disabled.

## Deferred — remote podman connections

- [ ] Refuse a launch whose podman connection is neither native podman on this host nor the local
  machine's, or state a contract for a remote server. Every `--volume` source is a client path: the
  workspace and gitdir binds, the launcher's file binds and the `--cache-overlay` directory. Over a
  remote connection, podman mounts the server's directories at those paths.

## Before the first release — the former records directory

- [ ] Delete `LauncherState.formerWorkspacesStateRoot`, its `--reset-all` step and its
  `ResetRecordTest` case once the machines that launched before the workspace rename have run
  `--reset-all` or removed `<state root>/projects/` by hand. Nothing writes or reads that
  directory; a machine that never removes it keeps a few path strings, no resource.

## Persisted state not yet surveyed

AGENTS.md prefers the least persisted state that meets the requirements. Of the launcher's state,
these were examined and stay, each for the reason given: the audit logs, which outlive runs by
design; the `ruleset/<id>` caches, derived and keyed by stamps; the BPF reconcile notes, which carry
an asynchronous result to the next prompt; the workspace record, which maps a hashed workspace id
back to its path; the run-on-host caches.

- [ ] Examine the rest for state to drop, derive or move into its owner's lifetime: the FUSE
  backend's state, the BPF proof fixture, the install directory in the podman machine, the seccomp
  profile file (`SeccompProfile.profileFile`) and ko-review's state.

## The flat log files' cleanup

- [ ] After 2026-12-17, two months after launchers began writing run directories, delete
  `EgressRules.runLogDirsToPrune`'s branch for the flat log files (`proxy-*.log`,
  `run-on-host-*.log`, `microphone-*.log`) and its case in `EgressRulesTest`.

## Before the first release — continuous integration

There is no CI. [development.md](development.md#tests) gives the launcher, proxy and FUSE backend
test commands. `--self-test` runs the FUSE backend's suites on demand. A user's `--build` instead
performs the checks whose results depend on that artifact and machine: `cargo deny check licenses
bans sources`, compilation, binary identity, and the installed FUSE backend's mount self-test.

- [ ] Add CI for the launcher's and proxy's `sbt testFull`, and `ko-agent-fs`'s pure and binary
  suites on both shipping architectures. Add `cargo deny check advisories` there: `deny.toml`
  records why its moving external database must not block installation.
- [ ] Keep the checks above in `--build`, and keep the FUSE backend's mounted suites in
  `--self-test`; CI does not prove the FUSE backend on a user's own machine.
- [ ] Repeat, on the image CI builds, the measurement of each agent whose model hosts the defaults
  inspect (`agent-measurement.md`, "Measurement"), signed in to that agent with a test
  account. The measurement suite runs it ("The measurement suite").
  - A run that passes at another client version is the evidence for recording that version in
    `ko-agent-egress-proxy/doc/preset/<name>-evidence.md`.
  - CI runs no `/voice`, which needs a microphone. `/voice` is measured by hand.

## Before the first release — the published identity

- [ ] One decision that must settle several names together:
  - the jar's artifact name and publication coordinates;
  - the Scala package names (`agentsandbox.*`, containing neither the `ko-` prefix nor an
    organization);
  - the image label key (`ko-agent-sandbox.bundle` — OCI convention wants a reverse-DNS key, and
    the right prefix is this same identity, so deciding the key alone would decide the identity by
    accident).

  Until then a changed key ends in the "rebuild with --build" refusal, so the exposure is bounded.

## Deferred — the egress proxy as a published image and a standalone gateway

The goal is a proxy that runs on a gateway between the internet and the agents' subnet, deployed
apart from the launcher. A registry image fits that deployment better than a binary in the
launcher jar. `--build` builds every image locally from the jar's bundle.

- [ ] Decide how a gateway holds its CA key. design.md ("No profile that allows hosts no rule
  names") keeps the key out of the proxy, the process facing the internet.
  - One shape keeps the serving process keyless: a startup step issues the leaf and drops the
    key, as `RunOnHostInspection.create` does.
- [ ] Publish the proxy image from CI, built on each shipping architecture ("Before the first
  release — continuous integration").
  - The image's registry name belongs to the published identity's decision (above).
  - Check which CPU features native-image's default `-march` requires: a published binary runs on
    CPUs other than the build machine's.
- [ ] Decide whether `--build` pulls the published image or keeps building the proxy locally.
  - Pulling replaces the check that locks the default-named image to the jar that bundled its
    sources (`LauncherImages.bundleMismatch`).
  - ko-agent-fs faces the same choice: `--build` compiles it from source and checks the result on
    the user's machine.
- [ ] Check whether `--proxy-image` already runs a pulled image. Launches pass `--pull=never`, so
  the user pulls the image first.

## Deferred — the egress proxy's jar from the launcher's build

The proxy's image build runs `sbt dist` and then `native-image`
(`ko-agent-egress-proxy/Containerfile`). The launcher's own `sbt dist` could build the proxy's jar
instead, as it builds ko-review's (`ko-review/doc/design.md`, "Where the parts are"):

- The launcher jar carries the proxy's jar and a list of its dependencies' resolved versions. The
  build stage fetches those with `cs fetch` and runs `native-image` on them. No image build runs sbt
  or resolves dependencies.
- The launcher jar grows by the proxy's jar alone.
- `ko-agent-egress-proxy-build:cache` stays: the build stage still runs `native-image`, which the
  distroless final stage cannot, and the cache tag keeps that stage's layers
  (`ImageBuilds.buildCommands`).
- Once CI builds the proxy's native binary per architecture and publishes it, the image build
  fetches the binary instead, and the build stage goes.

## Deferred — the sbt build volumes' host creation, pinned to the checked directories

- [ ] Create each sbt build's missing `project` and `project/target` relative to directory handles
  that `SbtBuildVolumes.prepare` checked, so that a parent changed after the check cannot redirect
  the creation. Low priority: the window is milliseconds after the start prompt, and the result is
  an empty directory.
  - On Linux and macOS, through FFM (`FFMHelper`): `openat` each component with `O_DIRECTORY |
    O_NOFOLLOW` from the workspace root, then `mkdirat` under the open parent.
  - On Windows, through `ntdll`'s `NtCreateFile` with the parent's handle as `RootDirectory` and
    `FILE_OPEN_REPARSE_POINT`.
  - podman resolves the mount's destination by path afterwards, so the mount stays redirectable,
    inside the container only.
