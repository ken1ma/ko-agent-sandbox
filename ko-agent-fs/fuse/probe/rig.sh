#!/bin/sh
# Run the mounted tests against source edits in a privileged container. ko-agent-fs/doc/testing.md
# has the usage, the prerequisites and the unprivileged alternative. The comments on the flags below
# explain the privileges they need.
set -eu

workspace=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

# Read the toolchain version from the image build instead of repeating it here. With a second copy
# of the version, the rig could quietly stop testing the compiler that ships, and nothing else would
# notice.
rust=$(sed -n 's/^ARG RUST_VERSION=\(.*\)$/\1/p' "$workspace/Containerfile")
[ -n "$rust" ] || { echo "rig: no ARG RUST_VERSION in $workspace/Containerfile" >&2; exit 1; }

# Cargo's target directory is a named volume. Without it, every run builds the whole dependency
# tree from scratch. It is deliberately not the workspace's own `target/`: that would put build
# output on the host share, where it would collide with what a sandbox session compiles there.
volume=ko-agent-fs-rig-target
podman volume exists "$volume" 2>/dev/null || podman volume create "$volume" >/dev/null

# Fixed text. The two values that vary are passed as environment variables, not spliced into the
# text. It is a quoted heredoc, not a quoted string, because it holds comments as well as commands:
# one apostrophe in a comment would end a quoted string, and the outer shell would then run the rest
# of it outside the container.
inner=$(cat <<'INNER'
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

# fuse3 supplies fusermount3. fuser falls back to it when mount(2) is refused, and the harness
# teardown and the binary-level mount test call it directly. mounted_git.rs needs git.
packages="fuse3 git"
[ "$RIG_GLIBC" = 1 ] || packages="$packages musl-tools"
apt-get install -y --no-install-recommends $packages >/dev/null

# The suites mount with the product's options, allow_other among them. On the fusermount3 path,
# this one line decides between mounting and EPERM. It is unnecessary, and harmless, when mount(2)
# succeeds directly.
echo user_allow_other >> /etc/fuse.conf

# Use the shipping triple, because the difference matters: a glibc build cannot show the static-musl
# link constraint that src/fs.rs records at its rename, and only this triple makes tests/binary.rs
# run the binary as it ships. GLIBC=1 answers one question: whether a failure is libc-specific
# (ko-agent-fs/doc/testing.md).
if [ "$RIG_GLIBC" = 1 ]; then
    target=""
else
    triple="$(uname -m)-unknown-linux-musl"
    rustup target add "$triple"
    target="--target $triple"
fi

# Run the mount probe first. A PROBE FAIL says that /dev/fuse, the mount privilege or fuser's
# libfuse-free path is wrong, instead of leaving that to be guessed from thirty test failures.
cargo run --locked $target -p ko-agent-fs-fuse --example mount_probe
cargo test --locked $target -p ko-agent-fs-fuse -- --ignored $RIG_FILTER
INNER
)

# `bash -c`, never `bash -lc`: a login shell sources /etc/profile, which on Debian *sets* PATH
# instead of extending it. That discards the image's ENV PATH, which holds rustup and cargo. The
# symptom is `rustup: command not found` in an image that clearly has rustup.
#
# `label=disable`, and no `:Z`: on a podman machine the source arrives over virtiofs as `nfs_t`.
# The launcher itself never relabels a source the machine shares (`doc/verification-log.md`
# records why), so turn labeling off instead of relabeling.
#
# `SYS_ADMIN` is needed even with the setuid fusermount3. One would expect it to be redundant, but
# measurement shows otherwise: without it, the probe fails with `fusermount3: mount failed:
# Operation not permitted` (`doc/verification-log.md`). A setuid binary cannot exceed the
# container's capability bounding set. A podman machine grants what a container does not, which
# is why the daemon mounts there unprivileged.
exec podman run --rm -it \
    --device /dev/fuse \
    --cap-add SYS_ADMIN \
    --security-opt label=disable \
    -v "$workspace:/work" \
    -v "$volume:/tmp/target" \
    -w /work \
    -e CARGO_TARGET_DIR=/tmp/target \
    -e "RIG_FILTER=${1:-}" \
    -e "RIG_GLIBC=${GLIBC:-0}" \
    "docker.io/library/rust:$rust-slim-trixie" \
    bash -c "$inner"
