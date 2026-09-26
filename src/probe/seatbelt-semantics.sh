#!/bin/sh
# Whether SBPL still behaves the way the guard depends on. The answers are recorded in
# run-on-host.md "The Seatbelt profile" and encoded in SeatbeltProfile.scala;
# this is what measured them, and what re-measures them.
#
# Run it on each new macOS release. If E3, E4, E5, E9 or E12 stops answering DENIED, the guard has
# silently weakened and the profile no longer enforces what SECURITY.md claims — a release blocker,
# not a test to update. The same holds for the first answer of E13 and of E14, on which the file
# rules' pinned directories rest. A row of E13-E16 reading DENIED / ALLOWED / ALLOWED / ALLOWED /
# ALLOWED is a rule that would let a --run-on-host session keep node_modules writable. E17's
# narrowed rule reading DENIED / DENIED lets the profile's deny on a directory a line passes
# through narrow to the operations E13 and E14 measure (run-on-host.md, "The host command's
# filesystem rules").
#
# Each experiment isolates one variable: the profile is `(allow default)` plus the single deny
# under test, so the shell always runs and only that rule decides the outcome. The real profile is
# deny-by-default; matching semantics do not depend on the default.
#
# The scratch project is named with a space and a '+' on purpose — the two characters a real host
# puts in these paths (cs's install directory, the Coursier JDK home).
set -u
if [ "$(uname -s)" != "Darwin" ]; then echo "Run this on macOS." >&2; exit 2; fi
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

# Prints DENIED, ALLOWED, or ERROR. A write is allowed only if it both succeeded and is on disk.
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
    "DENIED: the deny held at access time, and the Windows exclusion holds. ALLOWED: it is a launch-time scan."

# ---------------------------------------------------------------------------
r=$(attempt "$proj/.git/config" "echo probe > '$proj/link/config'")
report "E4 symlink canonicalization" \
    "does the rule see through 'link -> .git'?" "$r" \
    "DENIED: SBPL canonicalizes the accessed path. ALLOWED: the guard is bypassable."

# ---------------------------------------------------------------------------
r=$(attempt "$proj/.git/config" "echo probe > '$proj/.GIT/config'")
report "E5 case alias of an existing entry" \
    "does .GIT resolve to the existing .git on this case-insensitive volume?" "$r" \
    "DENIED: the rule matches the resolved .git path. ALLOWED: this alias bypasses the rule."

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

# ---------------------------------------------------------------------------
# E9-E12: a guarded name the command creates under another spelling, where no entry of the
# guard's own spelling exists for the access to resolve to (E5's case). A DENIED here may be a
# pattern sandbox-exec did not compile, so these rows print its first stderr line.
mkdir -p "$proj/fresh9" "$proj/fresh10" "$proj/fresh12" "$proj/fold"
spelled() { printf '%s (%s)' "$1" "$(sed -n 1p "$root/err")"; }

profile <<'SB'
(version 1)
(allow default)
(deny file-write* (regex #"/\.git(/|$)"))
SB
r=$(attempt "" "mkdir '$proj/fresh9/.GIT'")
report "E9 a new .GIT under the lowercase pattern" \
    "is a .GIT created where no .git exists matched by /\\.git(/|\$)?" "$(spelled "$r")" \
    "DENIED: the lowercase pattern folds. ALLOWED: host git opens that .GIT as .git, and the guard needs E10."

profile <<'SB'
(version 1)
(allow default)
(deny file-write* (regex #"/\.[gG][iI][tT](/|$)"))
SB
r=$(attempt "" "mkdir '$proj/fresh10/.GIT'")
report "E10 a new .GIT under character classes" \
    "does /\\.[gG][iI][tT](/|\$) compile, and deny the new .GIT?" "$(spelled "$r")" \
    "DENIED with no compile error: classes are the spelling that folds. Otherwise it needs another."
r=$(attempt "" "mkdir '$proj/fresh10/.GITignore'")
report "E10b the anchor under character classes" \
    "does .GITignore stay outside the class pattern?" "$(spelled "$r")" \
    "ALLOWED: the (/|\$) anchor holds. DENIED: the pattern is wider than the name."

# U+212A KELVIN SIGN and U+017F LATIN SMALL LETTER LONG S case-fold to k and s; .git has no such
# letter. No profile: this is the volume's own answer.
mkdir "$proj/fold/.ko-agent-sandbox"
kelvin=$(printf '.\342\204\252o-agent-sandbox')
long_s=$(printf '.ko-agent-\305\277andbox')
for spelling in "$kelvin" "$long_s"; do
    if [ -e "$proj/fold/$spelling" ]; then r="ALIAS"; else r="DISTINCT"; fi
    report "E11 $spelling beside .ko-agent-sandbox" \
        "does this volume resolve the spelling to the existing .ko-agent-sandbox?" "$r" \
        "ALIAS: an entry so spelled is the guarded name to the launcher; see E12. DISTINCT: it is another name."
done

# The guard's own pattern for the name (SeatbeltProfile.anyDepth).
profile <<'SB'
(version 1)
(allow default)
(deny file-write* (regex #"/\.ko-agent-sandbox(/|$)"))
SB
for spelling in "$kelvin" "$long_s"; do
    r=$(attempt "" "mkdir '$proj/fresh12/$spelling'")
    rmdir "$proj/fresh12/$spelling" 2>/dev/null
    report "E12 a new $spelling under the lowercase pattern" \
        "does /\\.ko-agent-sandbox(/|\$) match the spelling?" "$(spelled "$r")" \
        "DENIED: the pattern covers it. ALLOWED where E11 says ALIAS: the guard misses a name the launcher reads."
done

# ---------------------------------------------------------------------------
# E13-E16: whether any rule can refuse moving a directory out of a writable region (node_modules)
# while leaving what npm does inside it — renames within it, rmdir, unlink — allowed. Without one,
# --run-on-host leaves the limit doc/file-rules.md, "Under --run-on-host", states.
# Each rule is judged on one path, so the only discriminators are the operation SBPL checks on
# each side of a rename and the vnode type.

region() { # a fresh node_modules with a package, an empty directory and a file, and a target
    rm -rf "$proj/nm" "$proj/out"
    mkdir -p "$proj/nm/x/.vscode" "$proj/nm/empty" "$proj/out"
    echo original > "$proj/nm/file"
}
compiles() { /usr/bin/sandbox-exec -f "$root/p.sb" /usr/bin/true 2>/dev/null; }
# The five operations, each against a fresh region: out of it, within it, rmdir and unlink in it,
# and mkdir outside it.
region_ops() { # label
    region; out=$(attempt "" "mv '$proj/nm/x' '$proj/out/x'")
    region; within=$(attempt "" "mv '$proj/nm/x' '$proj/nm/.x-retired'")
    region; rmd=$(attempt "" "rmdir '$proj/nm/empty'")
    region; unl=$(attempt "" "rm '$proj/nm/file'")
    region; mk=$(attempt "" "mkdir '$proj/out/y'")
    report "$1" "out of nm / within nm / rmdir in nm / unlink in nm / mkdir outside" \
        "$out / $within / $rmd / $unl / $mk" \
        "a rule refusing a move out is usable only as DENIED / ALLOWED / ALLOWED / ALLOWED / ALLOWED."
}

profile <<'SB'
(version 1)
(allow default)
(deny file-write-unlink (subpath "@PROJ@/nm"))
SB
region_ops "E13 file-write-unlink denied in the region: the operation a rename's source is checked as"

profile <<'SB'
(version 1)
(allow default)
(deny file-write-create (subpath "@PROJ@/out"))
SB
region_ops "E14 file-write-create denied outside: the operation a rename's destination is checked as"

profile <<'SB'
(version 1)
(allow default)
(deny file-write-unlink (require-all (subpath "@PROJ@/nm") (vnode-type DIRECTORY)))
SB
if compiles; then region_ops "E15 file-write-unlink denied on directories alone in the region"
else report "E15 vnode-type on file-write-unlink" "does the profile compile?" "REJECTED" \
    "vnode-type cannot narrow the unlink deny to directories."; fi

# An operation of a rename's own, if SBPL has one: a name it does not know refuses the profile.
for operation in file-write-rename file-rename; do
    printf '(version 1)\n(allow default)\n(deny %s (subpath "%s/nm"))\n' "$operation" "$proj" > "$root/p.sb"
    if compiles; then region_ops "E16 $operation denied in the region"
    else report "E16 $operation" "does SBPL know the operation?" "REJECTED" \
        "no rename-specific operation of that name."; fi
done
rm -rf "$proj/nm" "$proj/out"

# ---------------------------------------------------------------------------
# E17: which operations a renamex_np(RENAME_SWAP) exchange is checked as. The profile's deny on a
# directory a line passes through, `pin`, covers every write to the entry; narrowed to
# file-write-unlink and file-write-create, it would still refuse renaming it either way (E13, E14),
# and the question is whether it refuses exchanging it. No shell command exchanges, so python3's
# ctypes calls libSystem's renamex_np, as fuse/ko-agent-fs/probe/lower-probe-host.py does.
cat > "$root/swap.py" <<'PY'
import ctypes, sys
RENAME_SWAP = 0x2
renamex_np = ctypes.CDLL(None).renamex_np
sys.exit(renamex_np(sys.argv[1].encode(), sys.argv[2].encode(), ctypes.c_uint(RENAME_SWAP)) != 0)
PY
swap() { printf "python3 '%s' '%s' '%s'" "$root/swap.py" "$1" "$2"; } # the exchange, as a command
pinned() { # a fresh pinned directory and another one to exchange it with
    rm -rf "$proj/pin" "$proj/other"
    mkdir -p "$proj/pin" "$proj/other"
    echo pin > "$proj/pin/mark"
    echo other > "$proj/other/mark"
}
swap_ops() { # label
    pinned; forward=$(attempt "" "$(swap "$proj/pin" "$proj/other")")
    pinned; backward=$(attempt "" "$(swap "$proj/other" "$proj/pin")")
    report "$1" "exchange pin with other / exchange other with pin" "$forward / $backward" \
        "$2"
}
if ! python3 -c 'import ctypes; ctypes.CDLL(None).renamex_np' 2>/dev/null; then
    report "E17 RENAME_SWAP" "can python3 call renamex_np?" "SKIPPED" \
        "no python3 with ctypes and libSystem's renamex_np on this host."
else
    printf '(version 1)\n(allow default)\n' > "$root/p.sb"
    swap_ops "E17 control, no deny" "ALLOWED / ALLOWED: the exchange works here, so the rows below measure the rules."
    for operation in file-write-unlink file-write-create; do
        printf '(version 1)\n(allow default)\n(deny %s (literal "%s/pin"))\n' "$operation" "$proj" \
            > "$root/p.sb"
        swap_ops "E17 $operation denied on pin" "DENIED on a side: the exchange is checked as this operation there."
    done
    printf '(version 1)\n(allow default)\n(deny file-write-unlink file-write-create (literal "%s/pin"))\n' \
        "$proj" > "$root/p.sb"
    swap_ops "E17 the narrowed rule: file-write-unlink and file-write-create denied on pin" \
        "DENIED / DENIED: the pinned deny can narrow to these two. An ALLOWED: it cannot."
    rm -rf "$proj/pin" "$proj/other"
fi

printf '\n=== machine ===\n'
printf '%-20s %s\n' "macOS" "$(sw_vers -productVersion)"
printf '%-20s %s\n' "arch" "$(uname -m)"
printf '%-20s %s\n' "scratch volume" "$(df -h /tmp | tail -1 | awk '{print $1}')"
: > "$root/casetest"; [ -e "$root/CASETEST" ] && c=INSENSITIVE || c=sensitive
printf '%-20s %s\n' "scratch case" "$c"
printf '\nNote: /tmp and the project volume may differ in case sensitivity; E5 and E9-E12 are only\n'
printf 'conclusive when the scratch volume above is INSENSITIVE, as the project volume is.\n'
