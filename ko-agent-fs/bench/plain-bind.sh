#!/bin/sh
# The control run for the benchmarks and probes that compare a FUSE backend session with the share
# beneath the FUSE mount (entry-cost.py, xattr-probe.py, lower-probe.py). It runs a command in the
# sandbox image over a plain, writable bind mount of the current directory at its own path: what a
# session has, without either backend. The launcher has no such mode, so this is a script. Run it on
# the HOST, in the scratch workspace the benchmark or probe was copied to:
#
#     .../bench/plain-bind.sh python3 entry-cost.py
#
# The user mapping is the one a session uses (AgentSandboxLauncher, ContainerUid), so file ownership
# through the share looks as it does in a session.
#
# On an SELinux-enforcing host the container can read the bind mount only with `:Z`, which relabels
# the directory recursively. RELABEL=1 adds it; use it only for a scratch workspace you will delete.
#
# On Windows, use plain-bind.ps1.
set -eu

[ $# -gt 0 ] || { echo "usage: $0 <command> [args...]" >&2; exit 2; }

workspace=$(pwd -P)
exec podman run --rm -i --network=none --entrypoint= \
    --userns=keep-id:uid=65532,gid=65532 --user=65532:65532 \
    --volume="$workspace:$workspace:rw${RELABEL:+,Z}" --workdir="$workspace" \
    ko-agent-sandbox:latest "$@"
