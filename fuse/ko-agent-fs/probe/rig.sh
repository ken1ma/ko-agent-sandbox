#!/bin/sh
# The privileged dev rig. Everything in `tests/mounted_*.rs`, and the two `#[ignore]`d cases in
# `tests/binary.rs`, mounts a real filter over a throwaway backing tree — which needs `/dev/fuse`
# and `CAP_SYS_ADMIN`, deliberately absent from a `ko-agent-sandbox` session (`SECURITY.md`, "No
# containers inside the sandbox by default"). So they run here instead: on the host, in a
# privileged container, against the toolchain that ships.
#
#     probe/rig.sh                        # the whole ignored suite, mount probe first
#     probe/rig.sh a_handle_held          # one filter, for a single test or a family
#     GLIBC=1 probe/rig.sh                # against glibc instead of the shipping musl triple
#
# The unprivileged half needs none of this and runs anywhere, this sandbox included:
# `cargo test --locked --target "$(uname -m)-unknown-linux-musl"`. `doc/testing.md` has the split
# and what each suite covers.
#
# Exit status is cargo's, so a control run — patch the source, expect a failure, restore — reads
# the way it should from a shell.
set -eu

crate=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

# The toolchain read from the image build rather than repeated here. A second copy of the version
# is a rig that quietly stops exercising the compiler that ships, and nothing else would notice.
rust=$(sed -n 's/^ARG RUST_VERSION=\(.*\)$/\1/p' "$crate/Containerfile")
[ -n "$rust" ] || { echo "rig: no ARG RUST_VERSION in $crate/Containerfile" >&2; exit 1; }

# Cargo's target directory as a named volume: without it every run pays a cold build of the whole
# dependency tree. Deliberately not the crate's own `target/`, which would put build output on the
# host share and collide with what a sandbox session compiles there.
volume=ko-agent-fs-rig-target
podman volume exists "$volume" 2>/dev/null || podman volume create "$volume" >/dev/null

# Fixed text; the two values that vary travel as environment rather than being spliced in. A
# quoted heredoc, not a quoted string: the text is prose as much as shell, and one apostrophe in
# the prose would end a string — the outer shell then runs the rest of it, unmounted.
inner=$(cat <<'INNER'
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

# fuse3 supplies fusermount3, which fuser falls back to when mount(2) is refused and which the
# harness teardown and the binary-level mount smoke call directly. git is mounted_git.rs.
packages="fuse3 git"
[ "$RIG_GLIBC" = 1 ] || packages="$packages musl-tools"
apt-get install -y --no-install-recommends $packages >/dev/null

# The suites mount with the product options, allow_other among them; on the fusermount3 path this
# one line is the difference between mounting and EPERM. Unnecessary when mount(2) succeeds
# directly, and harmless then.
echo user_allow_other >> /etc/fuse.conf

# The shipping triple, because the difference is not cosmetic: the static-musl link constraint
# src/fs.rs records at its rename is invisible to a glibc build, and only this triple makes
# tests/binary.rs spawn the artifact as it ships. GLIBC=1 answers one question — whether a
# failure is libc-specific — and is not a faster alternative.
if [ "$RIG_GLIBC" = 1 ]; then
    target=""
else
    triple="$(uname -m)-unknown-linux-musl"
    rustup target add "$triple"
    target="--target $triple"
fi

# The mount probe first. A PROBE FAIL says /dev/fuse, the mount privilege, or fuser's libfuse-free
# path is wrong, rather than leaving that to be read off thirty test failures.
cargo run --locked $target --example mount_probe
cargo test --locked $target -- --ignored $RIG_FILTER
INNER
)

# `bash -c`, never `bash -lc`: a login shell sources /etc/profile, which on Debian *assigns* PATH
# rather than extending it, discarding the image ENV PATH where rustup and cargo live. The symptom
# is `rustup: command not found` in an image that plainly has one.
#
# `label=disable`, and no `:Z`: on a podman machine the source arrives over virtiofs as `nfs_t`,
# and relabelling a machine-shared source is what the launcher itself never does
# (`doc/verification-log.md` records why) — so turn labelling off rather than relabel.
#
# `SYS_ADMIN` is not redundant with the setuid fusermount3, which is the reasonable expectation and
# is measured wrong: dropped, the probe fails with `fusermount3: mount failed: Operation not
# permitted` (`doc/verification-log.md`). A setuid binary does not escape the container's
# capability bounding set. A Podman machine grants what a container does not, which is why the
# daemon mounts there unprivileged.
exec podman run --rm -it \
    --device /dev/fuse \
    --cap-add SYS_ADMIN \
    --security-opt label=disable \
    -v "$crate:/work" \
    -v "$volume:/tmp/target" \
    -w /work \
    -e CARGO_TARGET_DIR=/tmp/target \
    -e "RIG_FILTER=${1:-}" \
    -e "RIG_GLIBC=${GLIBC:-0}" \
    "docker.io/library/rust:$rust-slim-trixie" \
    bash -c "$inner"
