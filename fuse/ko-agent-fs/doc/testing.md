# Running the `ko-agent-fs` tests

Run the Cargo and rig commands from `fuse/ko-agent-fs`, and the launcher commands from the
repository root. Use the Linux musl target to test the binary as shipped; a glibc build misses
the static-link constraint documented at `fs.rs`'s `rename` implementation.

`--build` compiles the image and checks dependencies with `cargo deny`; it does not run these
suites. The [Containerfile](../Containerfile) explains why the image build compiles only the release
profile.


## Unprivileged — no mount needed

    cargo test --locked --target "$(uname -m)-unknown-linux-musl"

This runs the policy, inode-table, startup-guard and static Git-corpus suites, plus binary tests
for argument handling and startup refusal. It needs no mount privileges and runs in CI or inside a
`ko-agent-sandbox` session, where the musl target is preinstalled; the read-only rustup home
prevents adding targets during a session.


## Both suites, anywhere podman runs — `--self-test`

Run `--build` first to provide the sandbox image, then:

    java -jar target/dist/ko-agent-sandbox.jar --self-test
    java -jar target/dist/ko-agent-sandbox.jar --self-test a_handle_held

The launcher builds `ko-agent-self-test` from the bundled source and pinned toolchain on top of the
sandbox image. It runs both suites, including ignored tests, with `/dev/fuse` and `CAP_SYS_ADMIN`
in a container with no host bind mounts, removed on exit. It retains the current self-test and
compile-cache images and removes those they replace.

Without a case filter, it also checks whether host writes reach the session through the real
share. This check creates a scratch directory in the project, removes it on success, and reports
its retained path on failure (`SelfTestShare.scala`). The container-only suites cannot test that
direction.


## Mounted — the privileged dev rig

Run the rig in a POSIX shell on a host with podman to test edits without rebuilding the jar. It runs
`tests/mounted_*.rs` and the ignored mount cases in `tests/binary.rs` in a container with
`/dev/fuse` and `CAP_SYS_ADMIN`; an ordinary sandbox session lacks those mount privileges:

    probe/rig.sh                        # the whole ignored suite, mount probe first
    probe/rig.sh a_handle_held          # one filter, for a single test or a family
    GLIBC=1 probe/rig.sh                # against glibc instead of the shipping musl triple

- If the initial mount probe reports `PROBE FAIL`, check `/dev/fuse`, mount privileges and
  fuser's mount setup before investigating the suite's assertions.
- Use `GLIBC=1` to check whether a failure is libc-specific. Compilation times differ by only a
  few percent; switching libc does not avoid the build cost.
- Build output persists in the `ko-agent-fs-rig-target` volume, separate from the source tree's
  `target/`. The musl `rust-std` target is downloaded again for each container.

  - For frequent runs, bake the apt packages and musl target into a rig image to avoid repeated
    downloads.

- The rig returns Cargo's exit status, so a deliberately failing control must fail the command.

The rig's flags and toolchain selection are documented beside their implementation in
`probe/rig.sh`; `tests/binary.rs` documents how it locates the compiled binary.


## What the mounted suites cover

`tests/common/mod.rs` is their harness: a filter over a temporary backing tree, mounted with
`fs::mount_config` — the product's options, not a convenient subset — and every refusal asserted as
`EPERM` specifically rather than merely as an error. Over it run the read path; the adversarial set
(`RENAME_EXCHANGE` on protected operands, `O_TRUNC` on a hook, `mknod` in `hooks/`, hardlink
aliasing in both directions, the full name-rule corpus, an existing `.git` pointer file, a symlinked
`hooks/`, nested `modules/` and `worktrees/` protected entries, a directory handle held across the
rename that vacates its name); real git, where the everyday commands
must pass, `rebase`/`config --local`/`init` must **fail** so a later widening of the allowlist
cannot quietly reopen them, and the host's own hook must still run; and the concurrency/TOCTOU pair,
the only tests that reach `openat2`'s `EAGAIN` path.

The suites run as a single uid, so they cannot tell `allow_other` + `default_permissions`
(`architecture.md`, "Who may reach the mount") from the alternative; only the launcher mounting for
a real container can.
