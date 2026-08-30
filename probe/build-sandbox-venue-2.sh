#!/bin/sh
# Follow-up to build-sandbox-venue.sh: the three facts §2.1 and §3 need and the first probe
# either missed or contradicted — where cs installs, what the sbt launcher actually executes,
# and how Coursier names a managed JDK on a host whose Coursier cache has no jvm/ directory.
set -u
if [ "$(uname -s)" != "Darwin" ]; then echo "Run this on the Mac." >&2; exit 2; fi
if [ -n "${KO_AGENT_SANDBOX_EGRESS_POLICY:-}" ] || [ -d /etc/ko-agent-sandbox ]; then
    echo "This looks like a sandbox session. Run it in a host terminal." >&2; exit 2
fi

echo "=== cs install directory ==="
cs install --help 2>&1 | grep -i -B1 -A2 'dir' | head -20
echo "-- launchers actually present --"
ls -l "$HOME/Library/Application Support/Coursier/bin" 2>/dev/null

echo
echo "=== what the sbt launcher runs ==="
sbt_real=$(python3 -c 'import os,shutil;print(os.path.realpath(shutil.which("sbt")))')
echo "-- $sbt_real --"
cat "$sbt_real"

echo
echo "=== how Coursier names a JDK ==="
echo "-- cs java-home (no download; may fail, that is an answer) --"
cs java-home 2>&1 | head -5
echo "-- cs java --available (first 10) --"
cs java --available 2>&1 | head -10
echo "-- anything called jvm under the cache root --"
find "$HOME/Library/Caches/Coursier" -maxdepth 1 -print 2>/dev/null
echo "-- JAVA_HOME really exists? --"
ls -d "$JAVA_HOME" 2>/dev/null && echo "yes" || echo "no"
echo "-- is JAVA_HOME under the cache root? --"
case "$JAVA_HOME" in "$HOME/Library/Caches/Coursier"/*) echo "yes, under arc/" ;; *) echo "NO" ;; esac
