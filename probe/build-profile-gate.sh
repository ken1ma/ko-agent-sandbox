#!/bin/sh
# PLAN-SBT-ON-HOST.md §7.4, run by hand on macOS: Phase 2's exit criterion. One row per line of
# the plan's matrix, each run under the generated profile, each reporting PASS, FAIL or SKIP with
# what it observed. Everything else in probe/ finds out what a profile needs; this one finds out
# whether the profile that resulted enforces what §2.1 claims.
#
#   sh probe/build-profile-gate.sh              # the whole matrix, sbt test included
#   sh probe/build-profile-gate.sh quick        # the same, with `sbt test` left out
#
# What it does not cover, and why: the two proxy rows need the build's own proxy, which is Phase
# 3; the Mill rows run only when this project has a bootstrap, and this repository has none, so a
# second checkout that does is where they run. Both are reported as SKIP rather than omitted, so a
# clean run is one with no FAIL and every SKIP accounted for.
#
# The negative rows never write anything real: a "write" is `: >> file`, which opens for append
# and writes nothing, and every created marker lives in a scratch tree this script makes and
# removes. A denied row prints the denial on stderr; a wrongly permitted one leaves a marker the
# cleanup removes, and the row reports FAIL.
set -u
if [ "$(uname -s)" != "Darwin" ]; then echo "Run this on the Mac." >&2; exit 2; fi
case "${1:-full}" in full|quick) ;; *) echo "usage: $0 [full|quick]" >&2; exit 2 ;; esac
quick=$([ "${1:-full}" = quick ] && echo 1 || echo 0)

work=${TMPDIR:-/tmp}/ko-agent-build-profile
project=$(pwd -P)
scratch=$project/gate-scratch
mkdir -p "$work"
pass=0; fail=0; skip=0

report() { # status label detail
    # INFO is a measurement with no expected answer, so it counts toward nothing.
    case "$1" in PASS) pass=$((pass + 1)) ;; FAIL) fail=$((fail + 1)) ;; SKIP) skip=$((skip + 1)) ;; esac
    printf '  %-4s  %-46s %s\n' "$1" "$2" "${3:-}"
}

emit() { # tool
    rm -f "$work/gate-$1.env"
    sbt -batch "Test/runMain agentsandbox.launcher.EmitBuildProfile $work/gate-$1.sb probe/runtime-authority.txt $1" \
        >"$work/emit-$1.log" 2>&1 || { echo "emit failed for $1:"; tail -20 "$work/emit-$1.log"; return 1; }
    mv "$work/gate-$1.sb.env" "$work/gate-$1.env"
}

# The same invocation probe/build-profile-iterate.sh uses, so a result here and a result there
# describe the same build. $client selects sbt's thin client: sbtn (empty) or --jvm-client.
#
# The JVM settings travel in JAVA_TOOL_OPTIONS, which the server the client forks inherits; the
# same -D flags on the command line reach the client alone. XDG_RUNTIME_DIR and
# SBT_GLOBAL_SERVER_DIR keep sbt's sockets inside the session temp (BuildSandboxPolicy.
# SessionTmpMaxLength says why its length matters).
#
# PATH, because -java-home reaches the client alone: the client starts the server by re-running
# the sbt script, which takes `java` from PATH — /usr/bin/java, the stub §3.1 rejects and the
# profile denies. With it the fork dies silently and the client waits forever.
build_env() { # agent-v1 command...
    cache=$1; shift
    PATH="$JAVA_HOME/bin:$PATH" \
    COURSIER_CACHE=$cache XDG_RUNTIME_DIR=$SESSION_TMP SBT_GLOBAL_SERVER_DIR=$SESSION_TMP \
    JAVA_TOOL_OPTIONS="-Djava.io.tmpdir=$SESSION_TMP -Djava.util.prefs.userRoot=$SESSION_TMP -Dsbt.global.base=$SESSION_TMP/sbt-global" \
    "$@"
}
# A hang is a FAIL, not a stalled run: a client whose server never came up waits forever.
with_timeout() { # seconds command...
    limit=$1; shift
    "$@" & child=$!
    ( sleep "$limit"; kill "$child" 2>/dev/null ) & watchdog=$!
    wait "$child"; status=$?
    kill "$watchdog" 2>/dev/null; wait "$watchdog" 2>/dev/null
    return $status
}
run_sbt() { # client command...
    client=$1; shift
    with_timeout "${SBT_ROW_TIMEOUT:-600}" build_env "$agent_v1" /usr/bin/sandbox-exec -f "$work/gate-sbt.sb" \
        sbt $client -batch -java-home "$JAVA_HOME" "$@"
}

# A shell command under the sbt profile, so a row runs exactly what a build's script would.
sb() { /usr/bin/sandbox-exec -f "$work/gate-sbt.sb" /bin/sh -c "$1" >/dev/null 2>"$work/row.err"; }

# /bin/sh reports /private/var/select/sh on every run (runtime-authority.txt), so the first line
# of stderr is never the denial.
first_error() { grep -v 'var/select/sh' "$work/row.err" | head -1 | cut -c1-70; }
expect_denied() { # label command
    if sb "$2"; then report FAIL "$1" "allowed"
    else report PASS "$1" "denied: $(first_error)"; fi
}
expect_allowed() { # label command
    if sb "$2"; then report PASS "$1"
    else report FAIL "$1" "$(first_error)"; fi
}
# A path the negative rows name must exist on the host, or "denied" and "absent" read the same.
present_or_skip() { # label path
    [ -e "$2" ] && return 0
    report SKIP "$1" "$2 does not exist on this host"
    return 1
}

# --- setup -------------------------------------------------------------------------------------

# Every sbt server this run starts is ended at exit, whether or not `shutdown` could reach it: a
# server whose client hung is one `shutdown` cannot find, and each such run left one behind before
# this existed. The snapshot comes first because `emit` below is itself an sbt run with a server.
servers_before=$(pgrep -f -- '-Dsbt.script=' | sort)
end_new_servers() {
    for pid in $(pgrep -f -- '-Dsbt.script=' | sort); do
        case "
$servers_before
" in *"
$pid
"*) ;; *) kill "$pid" 2>/dev/null && echo "ended sbt server $pid" ;; esac
    done
}
trap end_new_servers EXIT

echo "emitting the sbt profile"
emit sbt || exit 1
# `emit` left a host server for this project, and a thin client attaches to whatever server the
# project's portfile names — every command then runs with *that* server's environment, and a
# client that cannot connect deletes the portfile and starts its own (§3.2). One server per
# project at a time, so the host one goes before any build_env client runs.
sbt --jvm-client -batch shutdown >/dev/null 2>&1
. "$work/gate-sbt.env"
grep -E '^(session temp|agent cache):' "$work/emit-sbt.log"
agent_v1=$(sed -n 's/^agent cache: //p' "$work/emit-sbt.log")
cache_root=${agent_v1%/cache/*}
state_root=${XDG_STATE_HOME:-$HOME/.local/state}/ko-agent-sandbox
user_v1=${COURSIER_CACHE:-$HOME/Library/Caches/Coursier}/v1
user_arc=${COURSIER_CACHE:-$HOME/Library/Caches/Coursier}/arc
sbt_launcher=${COURSIER_BIN_DIR:-$HOME/Library/Application Support/Coursier/bin}/sbt
mill_downloads=${MILL_FINAL_DOWNLOAD_FOLDER:-${MILL_USER_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/mill}/download}

# The scratch tree stands in for a project with nested repositories. Made on the host, outside
# the profile, so the rows test the guard and not the ability to build the fixture.
rm -rf "$scratch"
mkdir -p "$scratch/sub/nested/.git/hooks" "$scratch/.ko-agent-sandbox/egress"
printf 'fixture\n' > "$scratch/sub/nested/.git/config"
printf 'fixture\n' > "$scratch/.ko-agent-sandbox/egress/allowed"
ln -s sub/nested/.git "$scratch/link"
cleanup() {
    rm -rf "$scratch"
    rm -f "$agent_v1/gate-marker" "$project/.git/gate-marker" "$HOME/.sbt/boot/gate-marker" \
          "$user_v1/gate-marker" "$mill_downloads/gate-marker" 2>/dev/null
    end_new_servers
}
trap cleanup EXIT

# --- positive rows ------------------------------------------------------------------------------

# The profile's only egress is the build proxy, which is Phase 3. Until it exists the agent cache
# is warmed here, outside the profile, so the positive rows measure containment and not the
# absence of a network. Once Phase 3 lands this block goes and the proxy rows take its place.
# Unconditional: a partly warm cache is the common state, and a warm one costs one load.
echo
echo "warming the agent cache outside the profile (no build proxy until Phase 3)"
build_env "$agent_v1" sbt --jvm-client -batch -java-home "$JAVA_HOME" "Test/compile" >"$work/warm.log" 2>&1 \
    || { echo "warming failed:"; tail -20 "$work/warm.log"; exit 1; }
build_env "$agent_v1" sbt --jvm-client -batch shutdown >/dev/null 2>&1

echo
echo "positive rows"
if /usr/bin/sandbox-exec -f "$work/gate-sbt.sb" "$JAVA_HOME/bin/java" -version >"$work/java.log" 2>&1
then report PASS "java -version" "$(grep -m1 version "$work/java.log")"
else report FAIL "java -version" "$(tail -1 "$work/java.log")"; fi

# Both clients run so §3.2's pin stays measured. The server's java.home is checked against the
# JDK the profile granted: the server is forked by the client, so nothing about the client's own
# JVM proves which one the build runs in.
for client in "--jvm-client" ""; do
    label="sbt --version (${client:-sbtn})"
    if run_sbt "$client" --version >"$work/version.log" 2>&1
    then report PASS "$label" "$(grep -m1 'sbt' "$work/version.log" | cut -c1-40)"
    else report FAIL "$label" "$(tail -1 "$work/version.log" | cut -c1-70)"; fi
done
if run_sbt --jvm-client 'eval System.getProperty("java.home")' >"$work/jvm.log" 2>&1; then
    if grep -qF "$JAVA_HOME" "$work/jvm.log"
    then report PASS "server runs the granted JDK"
    else report FAIL "server runs the granted JDK" "$(grep -m1 'ans:' "$work/jvm.log" | cut -c1-70)"; fi
else report FAIL "server runs the granted JDK" "$(tail -1 "$work/jvm.log" | cut -c1-70)"; fi

for command in compile test; do
    [ "$command" = test ] && [ "$quick" = 1 ] && { report SKIP "sbt test" "quick mode"; continue; }
    if run_sbt --jvm-client "$command" >"$work/$command.log" 2>&1
    then report PASS "sbt $command" "$(grep -m1 '^\[success\]' "$work/$command.log")"
    else report FAIL "sbt $command" "$(grep -m1 '^\[error\]' "$work/$command.log" | cut -c1-70)"; fi
done
run_sbt --jvm-client shutdown >/dev/null 2>&1

# §3.2 pins --jvm-client because sbtn returns with nothing built; §17 keeps asking whether that
# changes. A build's success is the measure — sbtn's --version passes and proves nothing.
if run_sbt "" compile >"$work/sbtn.log" 2>&1 && grep -q '^\[success\]' "$work/sbtn.log"
then report INFO "sbtn compile" "passes: §3.2's pin is now a choice"
else report INFO "sbtn compile" "no build: $(tail -1 "$work/sbtn.log" | cut -c1-50)"; fi
run_sbt --jvm-client shutdown >/dev/null 2>&1

if [ -x "$project/mill" ]; then
    emit mill && {
        mill_sb=$work/gate-mill.sb
        for command in --version __.compile __.test; do
            [ "$command" = __.test ] && [ "$quick" = 1 ] && { report SKIP "./mill $command" "quick mode"; continue; }
            if /usr/bin/sandbox-exec -f "$mill_sb" ./mill "$command" >"$work/mill.log" 2>&1
            then report PASS "./mill $command"
            else report FAIL "./mill $command" "$(tail -1 "$work/mill.log" | cut -c1-70)"; fi
        done
    }
else
    report SKIP "./mill --version, __.compile, __.test" "no bootstrap in this project (§3.3)"
fi

# --- negative rows: reads --------------------------------------------------------------------------

echo
echo "reads"
present_or_skip "read ~/Documents" "$HOME/Documents" && expect_denied "read ~/Documents" "ls '$HOME/Documents'"
present_or_skip "read ~/.ssh" "$HOME/.ssh" && expect_denied "read ~/.ssh" "ls '$HOME/.ssh'"
present_or_skip "read the launcher state root" "$state_root" \
    && expect_denied "read the launcher state root" "ls '$state_root'"
expect_denied "read another project's agent cache" "ls '$cache_root/cache'"
expect_denied "read the user's other Coursier arc entries" "ls '$user_arc'"
# §7.2's ancestor literals carry file-read*, which on a directory is its listing. Whether that
# reveals sibling names is what this row measures; the profile's comment claims it does not.
expect_denied "list an ancestor of a granted path" "ls '$HOME/Library/Caches'"
expect_denied "read PROJECT/.git" "cat '$project/.git/HEAD'"
expect_denied "read a nested .git" "cat '$scratch/sub/nested/.git/config'"

# --- negative rows: writes -------------------------------------------------------------------------

echo
echo "writes"
jvm_dir=${COURSIER_CACHE:-$HOME/Library/Caches/Coursier}/jvm
if [ -e "$jvm_dir" ]; then expect_denied "write Coursier/jvm" ": > '$jvm_dir/gate-marker'"
else expect_denied "write the Coursier JDK home (no jvm/ exists, §3.1)" ": > '$JAVA_HOME/gate-marker'"; fi
expect_denied "write ~/.sbt/boot" ": > '$HOME/.sbt/boot/gate-marker'"
expect_denied "write the Coursier-installed sbt launcher" ": >> '$sbt_launcher'"
expect_denied "write PROJECT/.git/config" ": >> '$project/.git/config'"
expect_denied "create under PROJECT/.git" ": > '$project/.git/gate-marker'"
expect_denied "write PROJECT/sub/nested/.git/hooks/x" ": > '$scratch/sub/nested/.git/hooks/x'"
expect_denied "write PROJECT/.GIT/config (case fold)" ": >> '$scratch/sub/nested/.GIT/config'"
expect_denied "create PROJECT/.git during the build" "mkdir '$scratch/.git'"
expect_denied "link PROJECT/x -> PROJECT/.git/config" "ln '$scratch/sub/nested/.git/config' '$scratch/x'"
expect_denied "write via PROJECT/link -> PROJECT/.git" ": >> '$scratch/link/config'"
expect_denied "write PROJECT/.ko-agent-sandbox/..." ": >> '$scratch/.ko-agent-sandbox/egress/allowed'"
expect_denied "write the user's Coursier v1" ": > '$user_v1/gate-marker'"
present_or_skip "write the user's Mill download folder" "$mill_downloads" \
    && expect_denied "write the user's Mill download folder" ": > '$mill_downloads/gate-marker'"
present_or_skip "read and execute the Mill launcher" "$mill_downloads" && {
    launcher=$(ls -1d "$mill_downloads"/*-native-mac-* 2>/dev/null | head -1)
    if [ -n "$launcher" ] && [ -x "$project/mill" ] && [ -f "$work/gate-mill.sb" ]; then
        if /usr/bin/sandbox-exec -f "$work/gate-mill.sb" "$launcher" --version >/dev/null 2>"$work/row.err"
        then report PASS "read and execute the Mill launcher"
        else report FAIL "read and execute the Mill launcher" "$(head -1 "$work/row.err" | cut -c1-70)"; fi
    else report SKIP "read and execute the Mill launcher" "needs a Mill project and a provisioned launcher"; fi
}

echo
echo "allowed writes"
expect_allowed "write agent cache coursier/v1/..." ": > '$agent_v1/gate-marker'"
expect_allowed "write PROJECT/..." ": > '$scratch/ok'"
expect_allowed "write session temporary directory" ": > '$SESSION_TMP/gate-marker'"
# The guard is scoped to the project: a build's tests may make throwaway repositories in the
# session temp, and this project's own do.
expect_allowed "create .git in the session temporary directory" "mkdir -p '$SESSION_TMP/fixture/.git' && : > '$SESSION_TMP/fixture/.git/config'"

# --- network ------------------------------------------------------------------------------------

echo
echo "network"
# /bin/bash's /dev/tcp is a connect(2) with no tool to grant; an IP literal keeps DNS out of it.
if /usr/bin/sandbox-exec -f "$work/gate-sbt.sb" /bin/bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>"$work/row.err"
then report FAIL "connect directly to arbitrary Internet host" "connected"
else report PASS "connect directly to arbitrary Internet host" "denied: $(head -1 "$work/row.err" | cut -c1-50)"; fi
report SKIP "fetch allowed Maven artifact via proxy" "Phase 3: no build proxy yet"
report SKIP "fetch non-allowlisted host via proxy" "Phase 3: no build proxy yet"

echo
echo "PASS $pass  FAIL $fail  SKIP $skip"
echo "logs and profiles: $work"
[ "$fail" -eq 0 ]
