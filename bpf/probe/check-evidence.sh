#!/bin/sh
# The evidence check of doc/plan-bpf-lsm-cgroup.md ("Phases", 4): each measurement section of the
# plan names the SHA-256 of the sources its probe was built from, and this script recomputes it, so
# that a section cannot stand as evidence for a program it did not measure. Run it from anywhere:
#
#     bpf/probe/check-evidence.sh
#
# For every `### Phase N on PLATFORM` section holding `sources of SHA-256 \`HASH\``, the hash is
# recomputed over the files bpf/probe/phaseN/sources.txt lists, in that order, concatenated; the
# drivers record the same hash in their build output. A section without the phrase is reported and
# passes: the phases before the check existed name their object's hash alone. Exit status 1 when any
# named hash differs.
set -u

# shellcheck disable=SC1007
PROBE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PLAN=$PROBE_DIR/../../doc/plan-bpf-lsm-cgroup.md
status=0

sha256_stdin() {
    if command -v sha256sum > /dev/null 2>&1; then sha256sum | cut -d' ' -f1; else shasum -a 256 | cut -d' ' -f1; fi
}

# The sections, each as one line: `N|PLATFORM|HASH-or-empty`. The hash follows the phrase
# "sources of SHA-256", on the same line or the next, as a backticked 64-digit hex number.
sections=$(awk -v phrase="sources of SHA-256" '
    /^### Phase [0-9]+ on / { if (phase != "") print phase "|" platform "|" hash
        phase = $3; platform = $5; hash = ""; want = 0; next }
    /^## / { if (phase != "") print phase "|" platform "|" hash; phase = "" }
    phase != "" {
        text = $0
        if (index(text, phrase)) { want = 1; text = substr(text, index(text, phrase) + length(phrase)) }
        if (want && match(text, /`[0-9a-f]+`/) && RLENGTH == 66) { hash = substr(text, RSTART + 1, 64); want = 0 }
    }
    END { if (phase != "") print phase "|" platform "|" hash }
' "$PLAN")

printf '%s\n' "$sections" | while IFS='|' read -r phase platform hash; do
    [ -n "$phase" ] || continue
    dir=$PROBE_DIR/phase$phase
    if [ -z "$hash" ]; then
        printf 'INFO Phase %s on %s names no sources hash\n' "$phase" "$platform"
        continue
    fi
    if [ ! -f "$dir/sources.txt" ]; then
        printf 'FAIL Phase %s on %s: %s/sources.txt is missing\n' "$phase" "$platform" "$dir"
        exit 1
    fi
    # shellcheck disable=SC2046
    actual=$(cd "$dir" && cat $(cat sources.txt) | sha256_stdin)
    if [ "$actual" = "$hash" ]; then
        printf 'PASS Phase %s on %s: sources %s\n' "$phase" "$platform" "$hash"
    else
        printf 'FAIL Phase %s on %s: the section names %s, the sources hash to %s\n' "$phase" "$platform" "$hash" \
            "$actual"
        exit 1
    fi
done || status=1
exit $status
