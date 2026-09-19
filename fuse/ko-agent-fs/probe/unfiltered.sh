#!/bin/sh
# The control of the probes that compare a filtered session with the share under the filter
# (perf-probe.py, xattr-probe.py, lower-probe.py): a command in the sandbox image over a writable
# bind mount of the current directory at its own path — what a session has, without the filter.
# The launcher has no such mode, which is why this is a script. Run it on the HOST, in the scratch
# project the probe was copied to:
#
#     .../probe/unfiltered.sh python3 perf-probe.py
#
# The user mapping is a session's (AgentSandboxLauncher, ContainerUid), so ownership through the
# share is what a session sees.
#
# On an SELinux-enforcing host the container reads the bind mount only under `:Z`, which relabels
# the directory recursively: RELABEL=1 adds it, for a scratch project you will delete.
#
# On Windows, unfiltered.ps1.
set -eu

[ $# -gt 0 ] || { echo "usage: $0 <command> [args...]" >&2; exit 2; }

project=$(pwd -P)
exec podman run --rm -i --network=none --entrypoint= \
    --userns=keep-id:uid=65532,gid=65532 --user=65532:65532 \
    --volume="$project:$project:rw${RELABEL:+,Z}" --workdir="$project" \
    ko-agent-sandbox:latest "$@"
