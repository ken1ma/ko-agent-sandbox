# Running the `ko-agent-fs` tests

Two tiers, split by whether a test has to mount. Both build for the musl triple, and so does the
image build's own gate (`Containerfile`) — one triple everywhere, because that is the one that ships
and the difference is not cosmetic: the static-musl link constraint `fs.rs` records at its `rename`
is invisible to a glibc build, and only the shipping triple makes `tests/binary.rs` spawn the
artifact's real shape rather than a differently-linked build of it.


## Unprivileged — no mount needed

    cargo test --locked --target "$(uname -m)-unknown-linux-musl"

The policy core, the inode table, the startup guard, the static git corpus, and the parts of
`tests/binary.rs` that drive the real binary without mounting — argument handling and the startup
refusal, which the in-process suites bypass. None of it mounts, so it runs in CI and inside a
`ko-agent-sandbox` session, whose image carries the musl target for exactly this — it has to, since
its rustup home is read-only and a session cannot add a target to it.


## Mounted — the privileged dev rig

Everything in `tests/mounted_*.rs`, and the two `#[ignore]`d cases in `tests/binary.rs`, mounts a
real filter over a throwaway backing tree. That needs `/dev/fuse` and `CAP_SYS_ADMIN` — which the
sandbox deliberately does not have (`SECURITY.md`, "No containers inside the sandbox") — so they are
`#[ignore]`d by default and run in a privileged container instead. From the repository root:

    podman run --rm -it \
      --device /dev/fuse \
      --cap-add SYS_ADMIN \
      --security-opt label=disable \
      -v "$PWD/fuse/ko-agent-fs:/work" \
      -w /work \
      -e CARGO_TARGET_DIR=/tmp/target \
      -e DEBIAN_FRONTEND=noninteractive \
      docker.io/library/rust:1.97.1-slim-trixie \
      bash -lc '
        apt-get update -qq &&
        apt-get install -y --no-install-recommends fuse3 git musl-tools >/dev/null &&
        echo user_allow_other >> /etc/fuse.conf &&
        triple="$(uname -m)-unknown-linux-musl" &&
        rustup target add "$triple" &&
        cargo run --locked --target "$triple" --example mount_probe &&
        cargo test --locked --target "$triple" -- --ignored
      '

Dropping `musl-tools`, the `rustup target add` and both `--target` arguments builds against glibc
instead. That is worth doing to answer one question — whether a failure is libc-specific — and not
as a faster alternative: the two compile within a few percent of each other, and all musl costs on
top is one `rust-std` download per container.

What the unobvious parts are for:

- **`mount_probe` before the suite.** It mounts a trivial read-only filesystem and reads one file
  back, so a `PROBE FAIL` says the venue is wrong — `/dev/fuse`, the mount privilege, or fuser's
  libfuse-free path — rather than leaving you to read that off thirty test failures.
- **`fuse3`** supplies `fusermount3`, which fuser falls back to when `mount(2)` is refused, and
  which the harness teardown and the binary-level mount smoke call directly. **`git`** is
  `mounted_git.rs`'s. `DEBIAN_FRONTEND` only silences apt's four lines of debconf frontend
  complaints, which read like failures and are not — the same reason `debian-temurin` sets it.
- **`user_allow_other`** because the suites mount with the product's own options
  (`fs::mount_config`), `allow_other` among them; on the `fusermount3` path that line is the
  difference between mounting and `EPERM`. It is unnecessary when `mount(2)` succeeds directly, and
  harmless then.
- **`label=disable`, and no `:Z`.** On a podman machine the source arrives over virtiofs as `nfs_t`;
  relabelling a machine-shared source is what the launcher itself never does (`security-research.md`
  records why), so turn labelling off rather than relabel.
- **`/work`, and a target directory outside the mount.** `tests/binary.rs` resolves the binary
  relative to the running test executable rather than through `CARGO_BIN_EXE_`, precisely so the
  crate can be compiled at one path and tested at another; redirecting `CARGO_TARGET_DIR` keeps the
  build off the host share and out of your own `target/`. Swap it for a named volume
  (`-v ko-agent-fs-rig-target:/tmp/target`) if you run the rig repeatedly and would rather not pay
  a cold build each time — though that will not cover the `rust-std` download, which lands in the
  image's rustup home. If the rig ever becomes routine, bake the apt packages and the target into a
  small image instead of paying for both on every run.

The rust tag matches the one `Containerfile` pins, so the rig compiles with the toolchain that
ships.


## What the mounted suites cover

`tests/common/mod.rs` is their harness: a filter over a temporary backing tree, mounted with
`fs::mount_config` — the product's options, not a convenient subset — and every refusal asserted as
`EPERM` specifically rather than merely as an error. Over it run the read path; the adversarial set
(`RENAME_EXCHANGE` on protected operands, `O_TRUNC` on a hook, `mknod` in `hooks/`, hardlink
aliasing in both directions, the full name-rule corpus, an existing `.git` pointer file, a symlinked
`hooks/`, nested `modules/` and `worktrees/` control state); real git, where the everyday commands
must pass, `rebase`/`config --local`/`init` must **fail** so a later widening of the allowlist
cannot quietly reopen them, and the host's own hook must still run; and the concurrency/TOCTOU pair,
which is also the only thing that reaches `openat2`'s `EAGAIN` path.
