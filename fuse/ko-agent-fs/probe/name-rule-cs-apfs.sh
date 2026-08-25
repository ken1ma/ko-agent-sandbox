#!/bin/sh
# The name-rule row for case-sensitive APFS (doc/TODO.md, "P1 — Platform verification"), driven
# end to end: the backing is a sparse image mounted case-sensitive under $HOME — no
# repartitioning, and the podman machine's /Users share reaches it — a filtered session runs
# apfs-name-rule-probe.py against it, and the host-side checks (the property itself) run here
# afterwards.
#
# Run ON THE macOS HOST, from the repository root, with the jar assembled and images built:
#
#     fuse/ko-agent-fs/probe/name-rule-cs-apfs.sh [path/to/ko-agent-sandbox.jar]
#
# On a pass, record the printed versions in doc/verification-log.md and tick the TODO row: fold
# tables are OS-version-specific, so the versions are part of the result.
set -eu

jar=${1:-target/dist/ko-agent-sandbox.jar}
[ -f "$jar" ] || { echo "no launcher jar at $jar; run: sbt --server dist" >&2; exit 1; }
jar=$(cd "$(dirname "$jar")" && pwd)/$(basename "$jar")

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
image="$HOME/ko-agent-fs-cs-probe.sparseimage"
mountpoint="$HOME/ko-agent-fs-cs-probe"

cleanup() {
    cd "$HOME"
    # The session's own state first, while the project still exists; then the volume.
    { [ -d "$mountpoint/scratch" ] &&
        (cd "$mountpoint/scratch" && java -jar "$jar" --reset >/dev/null 2>&1); } || true
    hdiutil detach "$mountpoint" -quiet 2>/dev/null || true
    rm -f "$image"
    rmdir "$mountpoint" 2>/dev/null || true
}
trap cleanup EXIT

rm -f "$image"
hdiutil create -quiet -size 256m -fs "Case-sensitive APFS" -volname ko-agent-fs-cs \
    -type SPARSE "$image"
mkdir -p "$mountpoint"
hdiutil attach -quiet -nobrowse -mountpoint "$mountpoint" "$image"

personality=$(diskutil info "$mountpoint" | sed -n 's/.*File System Personality: *//p')
case "$personality" in
    *ase-sensitive*) ;;
    *) echo "the volume mounted as '$personality', not case-sensitive; aborting" >&2; exit 1 ;;
esac

project="$mountpoint/scratch"
mkdir "$project"
cp "$here/apfs-name-rule-probe.py" "$project/"

# The probe runs inside the filtered session; its own canary aborts if the filter is off. A
# launch that cannot serve the scratch tree usually means the machine's share did not cross into
# the mounted volume — `podman machine ssh ls "$project"` shows what the VM sees.
(
    cd "$project"
    env -u KO_AGENT_SANDBOX_WORKSPACE_GUARD KO_AGENT_SANDBOX_SESSION_START=immediate \
        java -jar "$jar" python3 apfs-name-rule-probe.py
)

# The property itself, on the host against the real fold table.
cd "$project"
if ls .git >/dev/null 2>&1; then
    echo "FAIL: host-side ls resolves a .git in $project" >&2
    exit 1
fi
if git rev-parse --git-dir >/dev/null 2>&1; then
    echo "FAIL: host-side git discovered a repository at $project" >&2
    exit 1
fi

echo
echo "PASS. Record in doc/verification-log.md (\"The .git name rule on real filesystems\"):"
sw_vers
echo "File System Personality: $personality"
