#!/bin/sh
# Measures whether SBPL still behaves the way the guard depends on. run-on-host.md, "The Seatbelt profile", records
# the answers, and SeatbeltProfile.scala encodes them. This script measured the answers and re-measures them.
#
# Run the script on each new macOS release, and read the rows this way:
# - If E3, E4, E5, E9 or E12 stops answering DENIED, the guard has silently weakened, and the profile stops
#   enforcing what SECURITY.md claims. Such a change is a release blocker, not a test to update.
# - The same holds for the first answer of E13 and of E14, on which the file rules' pinned directories rest.
# - A row of E13-E16 that reads DENIED / ALLOWED / ALLOWED / ALLOWED / ALLOWED is a rule that would let a
#   --run-on-host session keep node_modules writable.
# - If E17's narrowed rule reads DENIED / DENIED, the profile's deny on a directory that a line passes through can
#   narrow to the operations that E13 and E14 measure (run-on-host.md, "The host command's filesystem rules").
#
# Each experiment isolates one variable: the profile is `(allow default)` plus the single deny under test, so the
# shell always runs and only that rule decides the outcome. The real profile denies by default, and matching
# semantics do not depend on the default.
#
# The scratch workspace's name holds a space and a '+' on purpose: a real host puts those two characters in these
# paths (cs's install directory, the Coursier JDK home).
set -u
if [ "$(uname -s)" != "Darwin" ]; then echo "Run this on macOS." >&2; exit 2; fi
[ -x /usr/bin/sandbox-exec ] || { echo "no /usr/bin/sandbox-exec" >&2; exit 2; }

# Use the canonical path, because a rule that names a non-canonical path matches nothing and so fails *open*. /tmp
# is a symlink to /private/tmp, and SBPL canonicalizes the access but not the rule. E8 keeps demonstrating that
# finding rather than merely avoiding it.
raw=$(mktemp -d /tmp/seatbelt-probe.XXXXXX) || exit 1
root=$(cd "$raw" && pwd -P)
workspace="$root/work space+1"
trap 'rm -rf "$root"' EXIT INT TERM
noncanonical="$raw/work space+1"

mkdir -p "$workspace/.git" "$workspace/.ko-agent-sandbox" "$workspace/sub/nested/.git" "$workspace/plain"
echo original > "$workspace/.git/config"
echo original > "$workspace/sub/nested/.git/config"
ln -s .git "$workspace/link"

profile() { sed "s|@WORKSPACE@|$workspace|g" > "$root/p.sb"; }

# Prints DENIED, ALLOWED or ALLOWED-NO-EFFECT. A write counts as ALLOWED only if it succeeded and its marker is on
# disk.
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

echo "scratch workspace: $workspace"

# ---------------------------------------------------------------------------
profile <<'SB'
(version 1)
(allow default)
(deny file-write* (subpath "@WORKSPACE@/.git"))
SB
r=$(attempt "$workspace/.git/config" "echo probe > '$workspace/.git/config'")
report "E1 subpath deny, path with a space and a '+'" \
    "does (subpath) deny a write to the named directory?" "$r" \
    "DENIED: literal paths work, spaces and '+' included. ALLOWED: the profile needs another form."

# ---------------------------------------------------------------------------
profile <<'SB'
(version 1)
(allow default)
(deny file-write* (regex #"/\.git(/|$)"))
SB
r=$(attempt "$workspace/sub/nested/.git/config" "echo probe > '$workspace/sub/nested/.git/config'")
report "E2 regex deny at any depth" \
    "does one regex cover a .git nested several levels down?" "$r" \
    "DENIED: the at-any-depth rule is one rule. ALLOWED: it must be an enumeration."

# ---------------------------------------------------------------------------
r=$(attempt "$workspace/late/.git/config" \
    "mkdir -p '$workspace/late/.git' && echo probe > '$workspace/late/.git/config'")
report "E3 access-time evaluation" \
    "is a .git created *during* the run covered by the same rule?" "$r" \
    "DENIED: the deny held at access time, and the Windows exclusion holds. ALLOWED: it is a launch-time scan."

# ---------------------------------------------------------------------------
r=$(attempt "$workspace/.git/config" "echo probe > '$workspace/link/config'")
report "E4 symlink canonicalization" \
    "does the rule see through 'link -> .git'?" "$r" \
    "DENIED: SBPL canonicalizes the accessed path. ALLOWED: the guard is bypassable."

# ---------------------------------------------------------------------------
r=$(attempt "$workspace/.git/config" "echo probe > '$workspace/.GIT/config'")
report "E5 case alias of an existing entry" \
    "does .GIT resolve to the existing .git on this case-insensitive volume?" "$r" \
    "DENIED: the rule matches the resolved .git path. ALLOWED: this alias bypasses the rule."

# ---------------------------------------------------------------------------
profile <<'SB'
(version 1)
(allow default)
(deny file-write* (subpath "@WORKSPACE@/.git"))
SB
rm -f "$workspace/plain/hard"
r=$(attempt "" "ln '$workspace/.git/config' '$workspace/plain/hard'")
report "E6 hard link under a write deny" \
    "can a hard link to a denied file be created when only writes are denied?" "$r" \
    "ALLOWED: a write deny alone is not enough; E7 is the fix. DENIED: it already covers linking."

# ---------------------------------------------------------------------------
profile <<'SB'
(version 1)
(allow default)
(deny file-write* (subpath "@WORKSPACE@/.git"))
(deny file-link (subpath "@WORKSPACE@/.git"))
SB
rm -f "$workspace/plain/hard2"
r=$(attempt "" "ln '$workspace/.git/config' '$workspace/plain/hard2'")
report "E7 explicit file-link deny" \
    "does (deny file-link) refuse a hard link whose *target* is denied?" "$r" \
    "DENIED: the link clause is enforceable as written. ALLOWED: it needs a different mechanism."

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
{
    echo '(version 1)'
    echo '(allow default)'
    printf '(deny file-write* (subpath "%s/.git"))\n' "$noncanonical"
} > "$root/p.sb"
echo original > "$workspace/.git/config"
r=$(attempt "$workspace/.git/config" "echo probe > '$workspace/.git/config'")
report "E8 a rule naming a non-canonical path" \
    "does a rule spelled /tmp/... cover an access that resolves to /private/tmp/...?" "$r" \
    "ALLOWED: rules are matched as written, so a non-canonical rule fails OPEN. DENIED: rules canonicalize too."

# ---------------------------------------------------------------------------
# In E9-E12, the command creates a guarded name under another spelling. Unlike in E5, no entry of the guard's own
# spelling exists for the access to resolve to. A DENIED here can come from a pattern that sandbox-exec did not
# compile, so these rows print the first line of sandbox-exec's stderr.
mkdir -p "$workspace/fresh9" "$workspace/fresh10" "$workspace/fresh12" "$workspace/fold"
spelled() { printf '%s (%s)' "$1" "$(sed -n 1p "$root/err")"; }

profile <<'SB'
(version 1)
(allow default)
(deny file-write* (regex #"/\.git(/|$)"))
SB
r=$(attempt "" "mkdir '$workspace/fresh9/.GIT'")
report "E9 a new .GIT under the lowercase pattern" \
    "is a .GIT created where no .git exists matched by /\\.git(/|\$)?" "$(spelled "$r")" \
    "DENIED: the lowercase pattern folds. ALLOWED: host git opens that .GIT as .git, and the guard needs E10."

profile <<'SB'
(version 1)
(allow default)
(deny file-write* (regex #"/\.[gG][iI][tT](/|$)"))
SB
r=$(attempt "" "mkdir '$workspace/fresh10/.GIT'")
report "E10 a new .GIT under character classes" \
    "does /\\.[gG][iI][tT](/|\$) compile, and deny the new .GIT?" "$(spelled "$r")" \
    "DENIED with no compile error: classes are the spelling that folds. Otherwise it needs another."
r=$(attempt "" "mkdir '$workspace/fresh10/.GITignore'")
report "E10b the anchor under character classes" \
    "does .GITignore stay outside the class pattern?" "$(spelled "$r")" \
    "ALLOWED: the (/|\$) anchor holds. DENIED: the pattern is wider than the name."

# U+212A KELVIN SIGN and U+017F LATIN SMALL LETTER LONG S case-fold to k and s, and .git has no such letter. E11
# uses no profile, so its answer is the volume's own.
mkdir "$workspace/fold/.ko-agent-sandbox"
kelvin=$(printf '.\342\204\252o-agent-sandbox')
long_s=$(printf '.ko-agent-\305\277andbox')
for spelling in "$kelvin" "$long_s"; do
    if [ -e "$workspace/fold/$spelling" ]; then r="ALIAS"; else r="DISTINCT"; fi
    report "E11 $spelling beside .ko-agent-sandbox" \
        "does this volume resolve the spelling to the existing .ko-agent-sandbox?" "$r" \
        "ALIAS: an entry so spelled is the guarded name to the launcher; see E12. DISTINCT: it is another name."
done

# E12 uses the guard's own pattern for the name (SeatbeltProfile.anyDepth).
profile <<'SB'
(version 1)
(allow default)
(deny file-write* (regex #"/\.ko-agent-sandbox(/|$)"))
SB
for spelling in "$kelvin" "$long_s"; do
    r=$(attempt "" "mkdir '$workspace/fresh12/$spelling'")
    rmdir "$workspace/fresh12/$spelling" 2>/dev/null
    report "E12 a new $spelling under the lowercase pattern" \
        "does /\\.ko-agent-sandbox(/|\$) match the spelling?" "$(spelled "$r")" \
        "DENIED: the pattern covers it. ALLOWED where E11 says ALIAS: the guard misses a name the launcher reads."
done

# ---------------------------------------------------------------------------
# E13-E16 ask whether any rule can refuse moving a directory out of a writable region (node_modules) while the rule
# allows what npm does inside the region: renames within it, rmdir and unlink. Without such a rule, --run-on-host
# keeps the limit that doc/file-rules.md, "Under --run-on-host", states.
# SBPL judges each rule on one path, so the only discriminators are the operation that SBPL checks on each side of a
# rename and the vnode type.

region() { # a fresh node_modules with a package, an empty directory and a file, and a target
    rm -rf "$workspace/nm" "$workspace/out"
    mkdir -p "$workspace/nm/x/.vscode" "$workspace/nm/empty" "$workspace/out"
    echo original > "$workspace/nm/file"
}
compiles() { /usr/bin/sandbox-exec -f "$root/p.sb" /usr/bin/true 2>/dev/null; }
# Runs the five operations, each against a fresh region: a move out of the region, a move within it, rmdir and
# unlink in it, and mkdir outside it.
region_ops() { # label
    region; out=$(attempt "" "mv '$workspace/nm/x' '$workspace/out/x'")
    region; within=$(attempt "" "mv '$workspace/nm/x' '$workspace/nm/.x-retired'")
    region; rmd=$(attempt "" "rmdir '$workspace/nm/empty'")
    region; unl=$(attempt "" "rm '$workspace/nm/file'")
    region; mk=$(attempt "" "mkdir '$workspace/out/y'")
    report "$1" "out of nm / within nm / rmdir in nm / unlink in nm / mkdir outside" \
        "$out / $within / $rmd / $unl / $mk" \
        "a rule refusing a move out is usable only as DENIED / ALLOWED / ALLOWED / ALLOWED / ALLOWED."
}

profile <<'SB'
(version 1)
(allow default)
(deny file-write-unlink (subpath "@WORKSPACE@/nm"))
SB
region_ops "E13 file-write-unlink denied in the region: the operation a rename's source is checked as"

profile <<'SB'
(version 1)
(allow default)
(deny file-write-create (subpath "@WORKSPACE@/out"))
SB
region_ops "E14 file-write-create denied outside: the operation a rename's destination is checked as"

profile <<'SB'
(version 1)
(allow default)
(deny file-write-unlink (require-all (subpath "@WORKSPACE@/nm") (vnode-type DIRECTORY)))
SB
if compiles; then region_ops "E15 file-write-unlink denied on directories alone in the region"
else report "E15 vnode-type on file-write-unlink" "does the profile compile?" "REJECTED" \
    "vnode-type cannot narrow the unlink deny to directories."; fi

# E16 looks for an operation of a rename's own, if SBPL has one. sandbox-exec refuses a profile that names an
# operation SBPL does not know.
for operation in file-write-rename file-rename; do
    printf '(version 1)\n(allow default)\n(deny %s (subpath "%s/nm"))\n' "$operation" "$workspace" > "$root/p.sb"
    if compiles; then region_ops "E16 $operation denied in the region"
    else report "E16 $operation" "does SBPL know the operation?" "REJECTED" \
        "no rename-specific operation of that name."; fi
done
rm -rf "$workspace/nm" "$workspace/out"

# ---------------------------------------------------------------------------
# E17 asks which operations SBPL checks a renamex_np(RENAME_SWAP) exchange as. The profile's deny on a directory
# that a line passes through, `pin`, covers every write to the entry. Narrowed to file-write-unlink and
# file-write-create, the deny would still refuse renaming the entry either way (E13, E14). The question is whether
# the narrowed deny refuses exchanging the entry. No shell command exchanges, so python3's ctypes calls libSystem's
# renamex_np, as ko-agent-fs/fuse/probe/lower-probe-host.py does.
cat > "$root/swap.py" <<'PY'
import ctypes, sys
RENAME_SWAP = 0x2
renamex_np = ctypes.CDLL(None).renamex_np
sys.exit(renamex_np(sys.argv[1].encode(), sys.argv[2].encode(), ctypes.c_uint(RENAME_SWAP)) != 0)
PY
swap() { printf "python3 '%s' '%s' '%s'" "$root/swap.py" "$1" "$2"; } # prints the exchange as a command
pinned() { # a fresh pinned directory and another one to exchange it with
    rm -rf "$workspace/pin" "$workspace/other"
    mkdir -p "$workspace/pin" "$workspace/other"
    echo pin > "$workspace/pin/mark"
    echo other > "$workspace/other/mark"
}
swap_ops() { # label
    pinned; forward=$(attempt "" "$(swap "$workspace/pin" "$workspace/other")")
    pinned; backward=$(attempt "" "$(swap "$workspace/other" "$workspace/pin")")
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
        printf '(version 1)\n(allow default)\n(deny %s (literal "%s/pin"))\n' "$operation" "$workspace" \
            > "$root/p.sb"
        swap_ops "E17 $operation denied on pin" "DENIED on a side: the exchange is checked as this operation there."
    done
    printf '(version 1)\n(allow default)\n(deny file-write-unlink file-write-create (literal "%s/pin"))\n' \
        "$workspace" > "$root/p.sb"
    swap_ops "E17 the narrowed rule: file-write-unlink and file-write-create denied on pin" \
        "DENIED / DENIED: the pinned deny can narrow to these two. An ALLOWED: it cannot."
    rm -rf "$workspace/pin" "$workspace/other"
fi

printf '\n=== machine ===\n'
printf '%-20s %s\n' "macOS" "$(sw_vers -productVersion)"
printf '%-20s %s\n' "arch" "$(uname -m)"
printf '%-20s %s\n' "scratch volume" "$(df -h /tmp | tail -1 | awk '{print $1}')"
: > "$root/casetest"; [ -e "$root/CASETEST" ] && c=INSENSITIVE || c=sensitive
printf '%-20s %s\n' "scratch case" "$c"
printf '\nNote: /tmp and the workspace volume may differ in case sensitivity; E5 and E9-E12 are only\n'
printf 'conclusive when the scratch volume above is INSENSITIVE, as the workspace volume is.\n'
