#!/bin/sh
# What is installed on this host and where — the layout RunOnHostPolicy encodes.
#
# Run it on a new machine, and after upgrading Coursier or the JDK. Every "MISSING" line is a
# case the prerequisite classifier has to name, not a gap to fill in silently; a line that
# disagrees with RunOnHostPolicyTest's fixtures is a finding, not a test to relax.
#
# Run from the project directory. Read-only but for one temporary directory it removes.

set -u

# Run this on the Mac, in a host terminal. Inside a sandbox session every answer below would
# describe the container instead, and would read as a host missing its whole toolchain.
if [ "$(uname -s)" != "Darwin" ]; then
    echo "This probe reports a macOS host's layout; this is $(uname -s). Run it on the Mac." >&2
    exit 2
fi
if [ -n "${KO_AGENT_SANDBOX_EGRESS_POLICY:-}" ] || [ -d /etc/ko-agent-sandbox ]; then
    echo "This looks like a sandbox session. Run the probe in a host terminal instead." >&2
    exit 2
fi

say() { printf '%-34s %s\n' "$1" "$2"; }
absent() { printf '%-34s MISSING (%s)\n' "$1" "$2"; }

echo "=== host ==="
say "macOS"            "$(sw_vers -productVersion 2>/dev/null || echo unknown)"
say "arch"             "$(uname -m)"
say "sandbox-exec"     "$([ -x /usr/bin/sandbox-exec ] && echo /usr/bin/sandbox-exec || echo MISSING)"

echo
echo "=== environment overrides ==="
for v in XDG_CACHE_HOME XDG_STATE_HOME COURSIER_CACHE COURSIER_JVM_CACHE COURSIER_BIN_DIR \
         MILL_FINAL_DOWNLOAD_FOLDER MILL_USER_CACHE_DIR JAVA_HOME SBT_OPTS JAVA_TOOL_OPTIONS; do
    eval "value=\${$v:-}"
    if [ -n "$value" ]; then say "$v" "$value"; else say "$v" "(unset)"; fi
done

echo
echo "=== project ==="
project=$(pwd -P)
say "canonical project root" "$project"
probe_dir=$(mktemp -d "$project/.venue-probe.XXXXXX") || exit 1
: > "$probe_dir/casetest"
if [ -e "$probe_dir/CASETEST" ]; then say "filesystem case" "INSENSITIVE (the fold rule binds)"
else say "filesystem case" "sensitive"; fi
rm -rf "$probe_dir"
say "project/build.properties" "$([ -f project/build.properties ] && cat project/build.properties || echo MISSING)"
say "mill bootstrap" "$([ -f ./mill ] && echo ./mill || echo MISSING)"

echo
echo "=== coursier ==="
cs_path=$(command -v cs 2>/dev/null || true)
if [ -n "$cs_path" ]; then
    say "cs on PATH" "$cs_path"
    say "cs real path" "$(python3 -c 'import os,sys;print(os.path.realpath(sys.argv[1]))' "$cs_path")"
    say "cs version" "$(cs version 2>/dev/null || echo unknown)"
    say "cs install dir" "$(dirname "$(python3 -c 'import os,sys;print(os.path.realpath(sys.argv[1]))' "$cs_path")")"
else
    absent "cs on PATH" "cs install sbt is a prerequisite"
fi

cache_root="$HOME/Library/Caches/Coursier"
echo "(measuring cache sizes; a large v1 has millions of inodes and this can take a minute)"
say "cache root" "$([ -d "$cache_root" ] && echo "$cache_root" || echo "MISSING $cache_root")"
for sub in v1 jvm arc; do
    d="$cache_root/$sub"
    if [ -d "$d" ]; then
        entries=$(ls -1 "$d" 2>/dev/null | wc -l | tr -d ' ')
        say "  $sub" "present, $(du -sh "$d" 2>/dev/null | cut -f1) $entries entries"
    else say "  $sub" "MISSING"; fi
done
if [ -d "$cache_root/jvm" ]; then
    echo "  managed JVMs:"
    ls -1 "$cache_root/jvm" 2>/dev/null | sed 's/^/    /'
fi

echo
echo "=== sbt ==="
sbt_path=$(command -v sbt 2>/dev/null || true)
if [ -n "$sbt_path" ]; then
    real=$(python3 -c 'import os,sys;print(os.path.realpath(sys.argv[1]))' "$sbt_path")
    say "sbt on PATH" "$sbt_path"
    say "sbt real path" "$real"
    say "first line" "$(head -1 "$real" 2>/dev/null | cut -c1-70)"
else
    absent "sbt on PATH" "cs install sbt"
fi

echo
echo "=== mill ==="
mill_cache="${XDG_CACHE_HOME:-$HOME/.cache}/mill"
say "user cache dir" "$([ -d "$mill_cache" ] && echo "$mill_cache" || echo "MISSING $mill_cache")"
say "download folder" "$([ -d "$mill_cache/download" ] && ls -1 "$mill_cache/download" | tr '\n' ' ' || echo MISSING)"

echo
echo "=== what a Seatbelt profile would name ==="
say "PROJECT" "$project"
say "COURSIER_JDK_HOME" "${JAVA_HOME:-UNSET — a prerequisite failure}"
say "MILL_DOWNLOAD" "${XDG_CACHE_HOME:-$HOME/.cache}/mill/download"
say "AGENT_CACHE_V1" "${XDG_CACHE_HOME:-$HOME/.cache}/ko-agent-sandbox/cache/<projectId>/coursier/v1"
printf '\nThe sbt distribution is the other half of TOOL; src/probe/sbt-exec-chain.sh finds it.\n'
