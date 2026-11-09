# Running the `ko-agent-fs` tests

- Run the Cargo and rig commands from `ko-agent-fs`, the Cargo workspace.
- Run the launcher commands from the repository root.
- Use the Linux musl target to test the binaries as they ship. A glibc build misses the
  static-link constraint documented at `fuse/src/fs.rs`'s `rename` implementation.

`--build` compiles the image and checks dependencies with `cargo deny`. It does not run these
suites. The [Containerfile](../Containerfile) explains why the image build compiles only the release
profile.


## Unprivileged — no mount needed

    cargo test --locked --target "$(uname -m)-unknown-linux-musl"

This runs:

- the unit tests beside the sources;
- the static Git-corpus and file-rule conformance suites;
- the same corpus through the BPF backend's classifier built for the host
  (`policy/tests/bpf_equivalence.rs`, which compiles `bpf/policy.bpf.c` with `$CC` or `cc`);
- both binaries' tests for argument handling and startup refusal.

It needs no mount privileges. It runs in CI or inside a `ko-agent-sandbox` session, where the musl
target is preinstalled. A session cannot add a target to the image's toolchain
(`container/ko-agent-sandbox/Containerfile`, "rustup's home").


## Both suites, anywhere podman runs — `--self-test`

Run `--build` first. It provides the sandbox image and pulls the Rust image. Then:

    java -jar target/dist/ko-agent-sandbox.jar --self-test

What the launcher does:

- It builds `ko-agent-self-test` on top of the sandbox image, from the bundled source and the
  pinned toolchain.
- It runs both suites, ignored tests included, in a container with `/dev/fuse` and
  `CAP_SYS_ADMIN` and no host bind mounts. The container is removed on exit.
- It ends the suites' output with a summary: the total counts, then one row per test binary.
- It keeps the current self-test and compile-cache images, and removes the ones they replace.
- The image carries the BPF classifier's host build. Its builder stage compiles it, and
  `KO_AGENT_FS_POLICY_HOST` names it to `policy/tests/bpf_equivalence.rs`. The suite therefore
  needs neither a C compiler nor the sources in the container.

On macOS and Windows, whatever the suites' result, it makes the policy suite's corpus of
operations under the BPF backend that `--build` installed, on the machine's own kernel, and compares
each answer with the expected one (`../../src/main/scala/BpfSelfTest.scala`):

- It loads the policies that launches load: `short-names` on Windows alone, then `unix-socket` off
  and on. Under each policy it runs the groups whose answers the policy suite measured under that
  policy (`../bpf/doc/evidence.md`, "Suites").
- The corpus runs in containers of the self-test image, under the attach cgroup, on a scratch
  directory under the launcher's state root. A failed run keeps the directory until the next run.
- Without an installed backend from this launcher's build, the self-test fails before it builds
  its image. On a machine whose kernel lacks what the backend needs, `--self-test --no-bpf` skips
  the corpus and shows the skipped row.
- The whole `--self-test` took, on 2026-11-09 with its images already built, the corpus rows
  included:
  - 16 s on macOS (kernel 7.2.7-200.fc44, virtiofs);
  - 53 s on Windows (WSL2 kernel 6.18.54.1, 9p), in a run whose failed suite left out the share
    rows.
- The corpus rows passed on both machines on 2026-11-09, 0 mismatches. The skipped cases are the
  policy suite's on each share: the `fifo` group's where the share refuses the host FIFO, and on
  9p the two names NTFS cannot hold and the `unix` cases that need a bound socket.

Once the suites pass, it also checks whether host writes reach the session through the real share:

- The check creates a scratch directory in the workspace (`SelfTestShare.scala`).
- It removes the directory on success, and reports the kept path on failure.
- The container-only suites cannot test that direction.


## Mounted — the privileged dev rig

The rig tests edits without rebuilding the jar. Run it in a POSIX shell on a host with podman. It
runs `fuse/tests/mounted_*.rs` and the ignored mount cases in `fuse/tests/binary.rs` in a container
with `/dev/fuse` and `CAP_SYS_ADMIN`. An ordinary sandbox session lacks those mount privileges.

    fuse/probe/rig.sh                        # the whole ignored suite, mount probe first
    fuse/probe/rig.sh a_handle_held          # one filter, for a single test or a family
    GLIBC=1 fuse/probe/rig.sh                # against glibc instead of the shipping musl triple

- If the first mount probe reports `PROBE FAIL`, check `/dev/fuse`, the mount privileges and
  fuser's mount setup before you look into the suite's assertions.
- Use `GLIBC=1` to check whether a failure depends on the libc. Compile times differ by only a
  few percent, so switching libc does not save build time.
- Build output stays in the `ko-agent-fs-rig-target` volume, apart from the source tree's
  `target/`. Each container downloads the musl `rust-std` target again.

  - For frequent runs, build a rig image with the apt packages and the musl target installed, so
    nothing is downloaded each time.

- The rig exits with Cargo's exit status, so a deliberately failing control must fail the command.

`fuse/probe/rig.sh` documents the rig's flags and toolchain choice beside their implementation.
Each package's `tests/binary.rs` documents how it finds the compiled binary.


## What the mounted suites cover

`fuse/tests/common/mod.rs` is their harness:

- It mounts the FUSE backend over a temporary backing tree with `fs::mount_config`: the product's
  options, not a convenient subset.
- It asserts every refusal as `EPERM` specifically, not merely as an error.

The suites that run over it:

- the read path;
- the adversarial set:
  - `RENAME_EXCHANGE` on protected operands, `O_TRUNC` on a hook, `mknod` in `hooks/`;
  - hard link aliasing in both directions;
  - the full name-rule corpus;
  - an existing `.git` pointer file, a symlinked `hooks/`, nested `modules/` and `worktrees/`
    protected entries;
  - a second name of a guarded entry;
  - a directory handle held across the rename that vacates its name, to a symlink or to a second
    name;
  - a file descriptor whose name becomes a second name;
- real git:
  - the everyday commands must pass;
  - `rebase`, `config --local` and `init` must **fail**, so a later widening of the allowlist
    cannot quietly reopen them;
  - the host's own hook must still run;
- the concurrency tests:
  - the rename pair, the only tests that reach `openat2`'s `EAGAIN` path;
  - the create pair, where the host makes an entry between the kernel's lookup and the backing
    open.

The suites run as a single uid. So they cannot tell `allow_other` + `default_permissions`
(`fuse/doc/architecture.md`, "Who may reach the mount") from the alternative. Only the launcher,
mounting for a real container, can.
