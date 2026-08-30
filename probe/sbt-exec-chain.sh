#!/bin/sh
# What the cs-installed sbt actually runs: the wrapper's exec target, the distribution beside it,
# and the interpreters the chain needs. SeatbeltProfile grants the distribution *home*, so this is
# how that path is confirmed.
#
# Run it after upgrading sbt or reinstalling it with cs: the distribution path encodes the sbt
# version Coursier fetched, so it moves.
#
# Writes to a file rather than the terminal: Coursier's installed launchers carry an appended jar,
# so `cat` on one dumps binary and eats the scrollback.
set -u
if [ "$(uname -s)" != "Darwin" ]; then echo "Run this on the Mac." >&2; exit 2; fi

out=${1:-/tmp/sbt-exec-chain.txt}
: > "$out"
note() { printf '\n=== %s ===\n' "$1" >> "$out"; }

wrapper=$(python3 -c 'import os,shutil;print(os.path.realpath(shutil.which("sbt")))')

note "wrapper: $wrapper"
# Text lines only, so an appended jar cannot reach the file as raw bytes.
LC_ALL=C sed -n '1,80p' "$wrapper" | LC_ALL=C tr -d '\000' | LC_ALL=C grep -a . >> "$out"

note "absolute paths the wrapper names"
LC_ALL=C grep -ao '/[A-Za-z0-9_./ +%-]\{8,\}' "$wrapper" | sort -u >> "$out"

inner=$(LC_ALL=C grep -ao "$HOME/Library/Caches/Coursier/arc/[^\"']*" "$wrapper" | head -1)
note "inner launcher: ${inner:-NOT FOUND}"
if [ -n "$inner" ] && [ -f "$inner" ]; then
    ls -l "$inner" >> "$out"
    note "inner launcher, text"
    LC_ALL=C sed -n '1,120p' "$inner" | LC_ALL=C grep -a . >> "$out"
    note "what the distribution ships"
    ls -1 "$(dirname "$inner")" >> "$out"
    ls -1 "$(dirname "$(dirname "$inner")")" >> "$out"
fi

note "interpreters the chain needs"
for candidate in /usr/bin/env /bin/sh /bin/bash /usr/bin/dirname /usr/bin/uname /usr/bin/sed; do
    [ -x "$candidate" ] && echo "$candidate present" >> "$out"
done

echo "written to $out"
echo "review it with:  less $out"
