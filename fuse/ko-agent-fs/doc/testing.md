# Running the `ko-agent-fs` tests

Two suites, split by whether a test has to mount, and three places to run them in. Everything
builds for the musl triple — one triple everywhere, because that is the one that ships and the
difference is not cosmetic: the static-musl link constraint `fs.rs` records at its `rename` is
invisible to a glibc build, and only the shipping triple makes `tests/binary.rs` spawn the
artifact as it ships rather than a differently-linked build of it.

The image build runs neither suite: it gates on `cargo deny` and builds, so a user's `--build`
compiles the dependency tree once, in the release profile (`Containerfile` has why).


## Unprivileged — no mount needed

    cargo test --locked --target "$(uname -m)-unknown-linux-musl"

The policy core, the inode table, the startup guard, the static git corpus, and the parts of
`tests/binary.rs` that drive the real binary without mounting — argument handling and the startup
refusal, which the in-process suites bypass. None of it mounts, so it runs in CI and inside a
`ko-agent-sandbox` session, whose image ships the musl target for exactly this — it has to,
since its rustup home is read-only and a session cannot add a target to it.


## Both suites, anywhere podman runs — `--self-test`

    java -jar ko-agent-sandbox.jar --self-test
    java -jar ko-agent-sandbox.jar --self-test a_handle_held

The launcher builds `ko-agent-self-test` — the crate's suites compiled against the pinned
toolchain, on top of the sandbox image — and runs them in a container with `/dev/fuse` and
`CAP_SYS_ADMIN`.
The container binds and writes nothing, and `--rm` removes it. The launcher retains the current
self-test output and compile-cache tags and removes images they replace. `--include-ignored`, so
this container is where *both* halves run, on macOS and Windows as readily as on Linux. It needs
`--build` to have happened; it does not run one.

Without a case filter, the launcher then runs its share rows (`SelfTestShare.scala`): a scratch
lower inside the current directory, mounted through the installed filter, with a container reading
the launcher's host writes back through the real share — the host-writer/session-reader
direction the container suites cannot reach, because their backing tree is the container's own
storage (`doc/TODO.md`, "End-to-end coherency through the real host share"). The scratch is
removed on success and kept on failure.

This is how the filter is proved on a machine. The rig below is the loop for changing it.


## Mounted — the privileged dev rig

Everything in `tests/mounted_*.rs`, and the ignored mount cases in `tests/binary.rs`, mounts a
real filter over a throwaway backing tree. That needs `/dev/fuse` and `CAP_SYS_ADMIN` — which
the sandbox deliberately does not have (`SECURITY.md`, "No containers inside the sandbox by
default") — so they are `#[ignore]`d by default. `--self-test` above runs them on an arbitrary
machine; this rig runs them against source you are still editing, with no jar rebuild in between:

    probe/rig.sh                        # the whole ignored suite, mount probe first
    probe/rig.sh a_handle_held          # one filter, for a single test or a family
    GLIBC=1 probe/rig.sh                # against glibc instead of the shipping musl triple

Each flag the rig needs is justified beside itself in that script rather than here, because that is
where a reader changing one is standing. What is worth knowing before reading it:

- **The mount probe runs first.** `mount_probe` mounts a trivial read-only filesystem and reads one
  file back, so a `PROBE FAIL` says the container is wrong — `/dev/fuse`, the mount privilege, or
  fuser's libfuse-free path — rather than leaving you to read that off thirty test failures.
- **The toolchain is read from `Containerfile`, never repeated.** The rig has to compile with the
  compiler that ships, and a second copy of the version is a rig that quietly stops doing so; a
  test holds the script to deriving it (`KoAgentFsTest`).
- **`GLIBC=1` answers one question** — whether a failure is libc-specific — and is not a faster
  alternative: the two compile within a few percent of each other, and all that musl adds is one
  `rust-std` download per container.
- **The target directory is a named volume, outside the source mount.** `tests/binary.rs` resolves
  the binary relative to the running test executable rather than through `CARGO_BIN_EXE_`, precisely
  so the crate can be compiled at one path and tested at another; keeping `CARGO_TARGET_DIR` off the
  host share also keeps the rig's build out of the one a sandbox session makes in `target/`. The
  volume does not cover the `rust-std` download, which lands in the image's rustup home — if the rig
  ever becomes routine, bake the apt packages and the target into a small image instead.
- **The exit status is cargo's**, so a control run — patch the source, expect a failure, restore —
  reads the way it should from a shell.


## What the mounted suites cover

`tests/common/mod.rs` is their harness: a filter over a temporary backing tree, mounted with
`fs::mount_config` — the product's options, not a convenient subset — and every refusal asserted as
`EPERM` specifically rather than merely as an error. Over it run the read path; the adversarial set
(`RENAME_EXCHANGE` on protected operands, `O_TRUNC` on a hook, `mknod` in `hooks/`, hardlink
aliasing in both directions, the full name-rule corpus, an existing `.git` pointer file, a symlinked
`hooks/`, nested `modules/` and `worktrees/` control state, a directory handle held across the
rename that vacates its name); real git, where the everyday commands
must pass, `rebase`/`config --local`/`init` must **fail** so a later widening of the allowlist
cannot quietly reopen them, and the host's own hook must still run; and the concurrency/TOCTOU pair,
which is also the only thing that reaches `openat2`'s `EAGAIN` path.

The suites run as a single uid, so they cannot tell `allow_other` + `default_permissions`
(`architecture.md`, "Who may reach the mount") from the alternative; only the launcher mounting for
a real container can.
