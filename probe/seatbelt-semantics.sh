#!/bin/sh
# Whether SBPL still behaves the way the guard depends on. The answers are recorded in
# RUN-ON-HOST.md "The Seatbelt profile" and encoded in SeatbeltProfile.scala;
# this is what measured them, and what re-measures them.
#
# Run it on each new macOS release. If E3, E4 or E5 stops answering DENIED, the guard has
# silently weakened and the profile no longer enforces what SECURITY.md claims — a release blocker,
# not a test to update.
#
# Each experiment isolates one variable: the profile is `(allow default)` plus the single deny
# under test, so the shell always runs and only that rule decides the outcome. The real profile is
# deny-by-default; matching semantics do not depend on the default.
#
# The scratch project is named with a space and a '+' on purpose — the two characters a real host
# puts in these paths (cs's install directory, the Coursier JDK home).
set -u
if [ "$(uname -s)" != "Darwin" ]; then echo "Run this on the Mac." >&2; exit 2; fi
[ -x /usr/bin/sandbox-exec ] || { echo "no /usr/bin/sandbox-exec" >&2; exit 2; }

# Canonical, because a rule naming a non-canonical path matches nothing and so fails *open*:
# /tmp is a symlink to /private/tmp, and SBPL canonicalizes the access but not the rule. E8 keeps
# that finding demonstrated rather than merely avoided.
raw=$(mktemp -d /tmp/seatbelt-probe.XXXXXX) || exit 1
root=$(cd "$raw" && pwd -P)
proj="$root/pro ject+1"
trap 'rm -rf "$root"' EXIT INT TERM
noncanonical="$raw/pro ject+1"

mkdir -p "$proj/.git" "$proj/.ko-agent-sandbox" "$proj/sub/nested/.git" "$proj/plain"
echo original > "$proj/.git/config"
echo original > "$proj/sub/nested/.git/config"
ln -s .git "$proj/link"

profile() { sed "s|@PROJ@|$proj|g" > "$root/p.sb"; }

# Prints DENIED, ALLOWED, or ERROR. A write is allowed only if it both succeeded and landed.
attempt() {
    marker=$1; shift
    if /usr/bin/sandbox-exec -f "$root/p.sb" /bin/sh -c "$*" >/dev/null 2>"$root/err"; then
        if [ -n "$marker" ] && ! grep -q probe "$marker" 2>/dev/null; then echo "ALLOWED-NO-EFFECT"
        else echo "ALLOWED"; fi
    else
        echo "DENIED"
    fi
}

report() { printf '\n%s\n  question: %s\n  result:   %s\n  means:    %s\n' "$1" "$2" "$3" "$4"; }

echo "scratch project: $proj"

# ---------------------------------------------------------------------------
profile <<'SB'
(version 1)
(allow default)
(deny file-write* (subpath "@PROJ@/.git"))
SB
r=$(attempt "$proj/.git/config" "echo probe > '$proj/.git/config'")
report "E1 subpath deny, path with a space and a '+'" \
    "does (subpath) deny a write to the named directory?" "$r" \
    "DENIED: literal paths work, spaces and '+' included. ALLOWED: the profile needs another form."

# ---------------------------------------------------------------------------
profile <<'SB'
(version 1)
(allow default)
(deny file-write* (regex #"/\.git(/|$)"))
SB
r=$(attempt "$proj/sub/nested/.git/config" "echo probe > '$proj/sub/nested/.git/config'")
report "E2 regex deny at any depth" \
    "does one regex cover a .git nested several levels down?" "$r" \
    "DENIED: the at-any-depth rule is one rule. ALLOWED: it must be an enumeration."

# ---------------------------------------------------------------------------
r=$(attempt "$proj/late/.git/config" \
    "mkdir -p '$proj/late/.git' && echo probe > '$proj/late/.git/config'")
report "E3 access-time evaluation" \
    "is a .git created *during* the run covered by the same rule?" "$r" \
    "DENIED: the guard is an invariant, and the Windows exclusion stands. ALLOWED: it is a scan."

# ---------------------------------------------------------------------------
r=$(attempt "$proj/.git/config" "echo probe > '$proj/link/config'")
report "E4 symlink canonicalization" \
    "does the rule see through 'link -> .git'?" "$r" \
    "DENIED: SBPL canonicalizes the accessed path. ALLOWED: the guard is bypassable."

# ---------------------------------------------------------------------------
r=$(attempt "$proj/.git/config" "echo probe > '$proj/.GIT/config'")
report "E5 case folding" \
    "does a lowercase rule catch an uppercase spelling on this insensitive volume?" "$r" \
    "DENIED: folding is free. ALLOWED: the fold rule needs an explicit case-insensitive pattern."

# ---------------------------------------------------------------------------
profile <<'SB'
(version 1)
(allow default)
(deny file-write* (subpath "@PROJ@/.git"))
SB
rm -f "$proj/plain/hard"
r=$(attempt "" "ln '$proj/.git/config' '$proj/plain/hard'")
report "E6 hardlink under a write deny" \
    "can a hardlink to a denied file be created when only writes are denied?" "$r" \
    "ALLOWED: a write deny alone is not enough; E7 is the fix. DENIED: it already covers linking."

# ---------------------------------------------------------------------------
profile <<'SB'
(version 1)
(allow default)
(deny file-write* (subpath "@PROJ@/.git"))
(deny file-link (subpath "@PROJ@/.git"))
SB
rm -f "$proj/plain/hard2"
r=$(attempt "" "ln '$proj/.git/config' '$proj/plain/hard2'")
report "E7 explicit file-link deny" \
    "does (deny file-link) refuse a hardlink whose *target* is denied?" "$r" \
    "DENIED: the link clause is enforceable as written. ALLOWED: it needs a different mechanism."

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
{
    echo '(version 1)'
    echo '(allow default)'
    printf '(deny file-write* (subpath "%s/.git"))\n' "$noncanonical"
} > "$root/p.sb"
echo original > "$proj/.git/config"
r=$(attempt "$proj/.git/config" "echo probe > '$proj/.git/config'")
report "E8 a rule naming a non-canonical path" \
    "does a rule spelled /tmp/... cover an access that resolves to /private/tmp/...?" "$r" \
    "ALLOWED: rules are matched as written, so a non-canonical rule fails OPEN. DENIED: rules canonicalize too."

printf '\n=== venue ===\n'
printf '%-20s %s\n' "macOS" "$(sw_vers -productVersion)"
printf '%-20s %s\n' "arch" "$(uname -m)"
printf '%-20s %s\n' "scratch volume" "$(df -h /tmp | tail -1 | awk '{print $1}')"
: > "$root/casetest"; [ -e "$root/CASETEST" ] && c=INSENSITIVE || c=sensitive
printf '%-20s %s\n' "scratch case" "$c"
printf '\nNote: /tmp and the project volume may differ in case sensitivity; E5 is only\n'
printf 'conclusive when the scratch volume above is INSENSITIVE, as the project volume is.\n'
