#!/bin/sh
# PLAN-SBT-ON-HOST.md §7.4, run by hand on macOS: Phase 2's exit criterion. One row per line of
# the plan's matrix, each run under the generated profile, each reporting PASS, FAIL or SKIP with
# what it observed. Everything else in probe/ finds out what a profile needs; this one finds out
# whether the profile that resulted enforces what §2.1 claims.
#
#   sh probe/build-profile-gate.sh [sbt|mill|all] [quick]
#
# The tool selects the positive rows; the negative matrix and the network rows run under every
# selected profile. `quick` leaves the test rows out. Emitting a profile goes through
# `sbt Test/runMain`, the launcher's own tooling until Phase 5's verb exists, whichever tool is
# selected; the sbt *build* rows run only for sbt.
#
# The sbt rows build this repository. The Mill rows build probe/mill-fixture, a one-module Mill
# project that exists for them: this repository is sbt-built, and a Mill build of it would be a
# second build definition rather than a measurement.
#
# What it does not cover, and why: the two proxy rows need the build's own proxy, which is Phase
# 3. They are reported as SKIP rather than omitted, so a clean run is one with no FAIL and every
# SKIP accounted for.
#
# The negative rows never write anything real: a "write" is `: >> file`, which opens for append
# and writes nothing, and every created marker lives in a scratch tree this script makes and
# removes. A denied row prints the denial on stderr; a wrongly permitted one leaves a marker the
# cleanup removes, and the row reports FAIL.
set -u
if [ "$(uname -s)" != "Darwin" ]; then echo "Run this on the Mac." >&2; exit 2; fi
tool=${1:-all}
case "$tool" in sbt|mill|all) ;; *) echo "usage: $0 [sbt|mill|all] [quick]" >&2; exit 2 ;; esac
case "${2:-full}" in
    full) quick=0 ;;
    quick) quick=1 ;;
    *) echo "usage: $0 [sbt|mill|all] [quick]" >&2; exit 2 ;;
esac
want() { [ "$tool" = all ] || [ "$tool" = "$1" ]; }

project=$(pwd -P)
# Paths are interpolated into sbt's command parser in `emit` and into single-quoted /bin/sh -c
# strings in the rows, where a quote character would end the quoting and inject. No path here
# earns escaping machinery: any interpolated path carrying a quote or backslash is refused.
safe_path() { # what value
    case "$2" in
        *[\'\"\\]*) echo "$1 contains a quote or backslash and cannot be interpolated safely: $2" >&2; exit 2 ;;
    esac
}
safe_path "the checkout path" "$project"
safe_path "HOME" "$HOME"
safe_path "JAVA_HOME" "${JAVA_HOME:-}"
safe_path "TMPDIR" "${TMPDIR:-}"
# Every path this run creates is unique to it — mktemp, not a pid, which is reused — so two gates
# do not share logs, and the cleanup removes only what this run made and never a project's file.
# The logs live under the project's target/gate/, git-ignored and, unlike $TMPDIR, shared with a
# sandbox session reading them. The project scratch tree is made after preflight, so an early
# exit leaves nothing there.
mkdir -p "$project/target/gate" && work=$(mktemp -d "$project/target/gate/run.XXXXXX") || exit 1
pass=0; fail=0; skip=0

report() { # status label detail
    # INFO is a measurement with no expected answer, so it counts toward nothing.
    case "$1" in PASS) pass=$((pass + 1)) ;; FAIL) fail=$((fail + 1)) ;; SKIP) skip=$((skip + 1)) ;; esac
    printf '  %-4s  %-46s %s\n' "$1" "$2" "${3:-}"
}

# The project each profile is for.
mill_project=$project/probe/mill-fixture
project_of() { if [ "$1" = mill ]; then printf '%s\n' "$mill_project"; else printf '%s\n' "$project"; fi; }

emit() { # tool
    rm -f "$work/gate-$1.env"
    # Each path quoted for sbt's own command parser: a checkout with a space in its path would
    # otherwise split into two arguments.
    args="\"$work/gate-$1.sb\" probe/runtime-authority.txt $1 \"$(project_of "$1")\""
    sbt -batch "Test/runMain agentsandbox.launcher.EmitBuildProfile $args" >"$work/emit-$1.log" 2>&1 \
        || { echo "emit failed for $1:"; tail -20 "$work/emit-$1.log"; return 1; }
    mv "$work/gate-$1.sb.env" "$work/gate-$1.env"
}

# --- the environment contract (§4) ----------------------------------------------------------------
#
# The JVM settings travel in JAVA_TOOL_OPTIONS, which the server sbt's client forks inherits; the
# same -D flags on the command line reach the client alone. XDG_RUNTIME_DIR and
# SBT_GLOBAL_SERVER_DIR keep sbt's sockets inside the session temp (BuildSandboxPolicy.
# SessionTmpMaxLength says why its length matters).
#
# PATH, because -java-home reaches sbt's client alone: the client starts the server by re-running
# the sbt script, which takes `java` from PATH — /usr/bin/java, the stub §3.1 rejects and the
# profile denies. Mill's `mill-jvm-version: system` takes `java` from PATH the same way.
build_env() { # agent-v1 command...
    cache=$1; shift
    PATH="$JAVA_HOME/bin:$PATH" \
    COURSIER_CACHE=$cache XDG_RUNTIME_DIR=$SESSION_TMP SBT_GLOBAL_SERVER_DIR=$SESSION_TMP \
    JAVA_TOOL_OPTIONS="-Djava.io.tmpdir=$SESSION_TMP -Djava.util.prefs.userRoot=$SESSION_TMP \
-Dsbt.global.base=$SESSION_TMP/sbt-global" \
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
# Under a profile, through the contract, with the timeout. $1 is the profile's tool.
sandboxed() { # tool command...
    profile=$work/gate-$1.sb; shift
    with_timeout "${GATE_ROW_TIMEOUT:-600}" build_env "$agent_v1" /usr/bin/sandbox-exec -f "$profile" "$@"
}
run_sbt() { # client command...
    client=$1; shift
    sandboxed sbt sbt $client -batch -java-home "$JAVA_HOME" "$@"
}

# A shell command under a profile, so a row runs exactly what a build's script would.
sb() { /usr/bin/sandbox-exec -f "$work/gate-$1.sb" /bin/sh -c "$2" >/dev/null 2>"$work/row.err"; }

# /bin/sh reports /private/var/select/sh on every run (runtime-authority.txt), so the first line
# of stderr is never the denial.
first_error() { grep -v 'var/select/sh' "$work/row.err" | head -1 | cut -c1-70; }
expect_denied() { # tool label command
    if sb "$1" "$3"; then report FAIL "$2" "allowed"
    else report PASS "$2" "denied: $(first_error)"; fi
}
expect_allowed() { # tool label command
    if sb "$1" "$3"; then report PASS "$2"
    else report FAIL "$2" "$(first_error)"; fi
}
# A path the negative rows name must exist on the host, or "denied" and "absent" read the same.
present_or_skip() { # label path
    [ -e "$2" ] && return 0
    report SKIP "$1" "$2 does not exist on this host"
    return 1
}

# --- servers and daemons ------------------------------------------------------------------------

# Processes whose working directory is this project: the gate never learns the pid of a server
# sbt's client forks or the daemon Mill's launcher starts, but each belongs to the project it
# runs in.
with_cwd() { # pattern dir exact|under
    for pid in $(pgrep -f -- "$1" 2>/dev/null); do
        cwd=$(lsof -a -p "$pid" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p')
        case "$3:$cwd" in exact:"$2"|under:"$2"/*) printf '%s\n' "$pid" ;; esac
    done
}
# An sbt server's cwd is its project, exactly: a nested project's server is another project's.
project_servers() { with_cwd '-Dsbt.script=' "$project" exact; }
# A Mill daemon's cwd is out/mill-daemon/<id>/sandbox (MillProcessLauncher.configureRunMillProcess).
mill_daemons() { with_cwd 'mill.daemon.MillDaemonMain' "$mill_project/out/mill-daemon" under; }
# §3.2: one sbt server per project at a time. A thin client attaches to whatever server the
# project's portfile names and runs with that server's environment, and one that cannot connect
# deletes the portfile and starts its own. A server already here is refused, as the wrapper will.
existing=$(project_servers | tr '\n' ' ')
if [ -n "$existing" ]; then
    echo "an sbt server is already running for $project (pid $existing): run 'sbt shutdown'," >&2
    echo "or kill it if its portfile is gone and shutdown cannot see it" >&2
    exit 1
fi
existing=$(mill_daemons | tr '\n' ' ')
if want mill && [ -n "$existing" ]; then
    echo "a Mill daemon is already running for $mill_project (pid $existing): run './mill shutdown' there," >&2
    echo "or kill it" >&2
    exit 1
fi
# Every server or daemon this run starts — `emit`'s included — is ended at exit, whether or not
# `shutdown` could reach it: a server whose client hung is one `shutdown` cannot find. Mill's
# daemon holds out/mill-daemon/daemonLock and a loopback port that a launcher under the profile
# finds and cannot connect to, so it is ended before the rows too.
end_project_servers() {
    for pid in $(project_servers); do kill "$pid" 2>/dev/null && echo "ended sbt server $pid"; done
    for pid in $(mill_daemons); do kill "$pid" 2>/dev/null && echo "ended Mill daemon $pid"; done
}
trap end_project_servers EXIT

# --- profiles -----------------------------------------------------------------------------------

profiles=""
if want sbt; then
    echo "emitting the sbt profile"
    emit sbt || exit 1
    profiles="sbt"
fi
if want mill; then
    echo "emitting the Mill profile, for $mill_project"
    emit mill || exit 1
    profiles="$profiles mill"
fi
# `emit`'s own sbt server goes before any build_env client runs, for §3.2's reason above.
sbt --jvm-client -batch shutdown >/dev/null 2>&1
profiles=${profiles# }
first=${profiles%% *}
# Each profile has its own session temp and agent cache — the fixture is another project, so
# another cache — and the contract's environment follows the profile in force.
use_profile() { # tool
    . "$work/gate-$1.env"
    agent_v1=$(sed -n 's/^agent cache: //p' "$work/emit-$1.log")
    cache_root=${agent_v1%/cache/*}
    safe_path "SESSION_TMP" "$SESSION_TMP"
    safe_path "the agent cache" "$agent_v1"
}
for p in $profiles; do
    echo "$p: $(grep -E '^(session temp|agent cache):' "$work/emit-$p.log" | tr '\n' ' ')"
done
use_profile "$first"
state_root=${XDG_STATE_HOME:-$HOME/.local/state}/ko-agent-sandbox
user_v1=${COURSIER_CACHE:-$HOME/Library/Caches/Coursier}/v1
user_arc=${COURSIER_CACHE:-$HOME/Library/Caches/Coursier}/arc
sbt_launcher=${COURSIER_BIN_DIR:-$HOME/Library/Application Support/Coursier/bin}/sbt
# As the bootstrap derives it (BuildSandboxPolicy.millDownloadDir): MILL_USER_CACHE_DIR is not an input.
mill_downloads=${MILL_FINAL_DOWNLOAD_FOLDER:-${XDG_CACHE_HOME:-$HOME/.cache}/mill/download}
# The concrete derived paths, after every environment override has had its say.
safe_path "the launcher state root" "$state_root"
safe_path "the user's Coursier cache" "${COURSIER_CACHE:-$HOME/Library/Caches/Coursier}"
safe_path "the sbt launcher path" "$sbt_launcher"
safe_path "the Mill download folder" "$mill_downloads"
mill_launcher=$(sed -n 's/^launcher: //p' "$work/emit-mill.log" 2>/dev/null)

# A scratch tree per profile, inside that profile's project, standing in for a project with
# nested repositories. Made on the host, outside the profile, so the rows test the guard and not
# the ability to build the fixture.
# One variable per profile — never a word-split list, which a space in the checkout path would
# split mid-path. Registered before the first tree exists, so a failed second mktemp leaves
# nothing.
scratch_sbt=""; scratch_mill=""
marker=gate-marker.${work##*.}
cleanup() {
    [ -n "$scratch_sbt" ] && rm -rf "$scratch_sbt"
    [ -n "$scratch_mill" ] && rm -rf "$scratch_mill"
    for p in $profiles; do use_profile "$p"; rm -f "$agent_v1/$marker" "$SESSION_TMP/$marker" 2>/dev/null; done
    rm -f "$project/.git/$marker" "$HOME/.sbt/boot/$marker" "$user_v1/$marker" "$mill_downloads/$marker" 2>/dev/null
    end_project_servers
}
trap cleanup EXIT
scratch_of() { if [ "$1" = mill ]; then printf '%s\n' "$scratch_mill"; else printf '%s\n' "$scratch_sbt"; fi; }
for p in $profiles; do
    scratch=$(mktemp -d "$(project_of "$p")/gate-scratch.XXXXXX") || exit 1
    if [ "$p" = mill ]; then scratch_mill=$scratch; else scratch_sbt=$scratch; fi
    mkdir -p "$scratch/sub/nested/.git/hooks" "$scratch/.ko-agent-sandbox/egress"
    printf 'fixture\n' > "$scratch/sub/nested/.git/config"
    printf 'fixture\n' > "$scratch/.ko-agent-sandbox/egress/allowed"
    ln -s sub/nested/.git "$scratch/link"
done

# --- warm-up ------------------------------------------------------------------------------------

# The profile's only egress is the build proxy, which is Phase 3. Until it exists the agent cache
# is warmed here, outside the profile, so the positive rows measure containment and not the
# absence of a network. Once Phase 3 lands this block goes and the proxy rows take its place.
# Unconditional: a partly warm cache is the common state, and a warm one costs one load.
echo
echo "warming the agent cache outside the profile (no build proxy until Phase 3)"
if want sbt; then
    use_profile sbt
    build_env "$agent_v1" sbt --jvm-client -batch -java-home "$JAVA_HOME" "Test/compile" >"$work/warm.log" 2>&1 \
        || { echo "sbt warm-up failed:"; tail -20 "$work/warm.log"; exit 1; }
    build_env "$agent_v1" sbt --jvm-client -batch shutdown >/dev/null 2>&1
fi
if want mill; then
    use_profile mill
    # Mill's launcher memoizes its resolved daemon classpath and JVM home in out/mill-daemon/cache
    # and reuses them while the files they name exist (CoursierClient.scala). Written by a run
    # against the user's cache, they name paths the profile denies; the memo goes, so the
    # redirected COURSIER_CACHE takes effect. out/mill-daemon's processId and socketPort are a
    # daemon's, alive or not, and a launcher believes them.
    end_project_servers
    rm -rf "$mill_project/out/mill-daemon"
    # __.test, not --version: the daemon classpath, the build's dependencies and the test
    # runner's are resolved separately, and the profile's rows need all three warm.
    ( cd "$mill_project" && build_env "$agent_v1" ./mill --no-daemon __.test ) >"$work/mill-warm.log" 2>&1 \
        || { echo "Mill warm-up failed:"; tail -20 "$work/mill-warm.log"; exit 1; }
fi

# --- positive rows ------------------------------------------------------------------------------

echo
echo "positive rows"
if /usr/bin/sandbox-exec -f "$work/gate-$first.sb" "$JAVA_HOME/bin/java" -version >"$work/java.log" 2>&1
then report PASS "java -version" "$(grep -m1 version "$work/java.log")"
else report FAIL "java -version" "$(tail -1 "$work/java.log")"; fi

if want sbt; then
    use_profile sbt
    # Both clients run so §3.2's pin stays measured. The server's java.home is checked against
    # the JDK the profile granted: the server is forked by the client, so nothing about the
    # client's own JVM proves which one the build runs in.
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

    # §3.2 pins --jvm-client because sbtn returns with nothing built; §17 keeps asking whether
    # that changes. A build's success is the measure — sbtn's --version passes and proves nothing.
    if run_sbt "" compile >"$work/sbtn.log" 2>&1 && grep -q '^\[success\]' "$work/sbtn.log"
    then report INFO "sbtn compile" "passes: §3.2's pin is now a choice"
    else report INFO "sbtn compile" "no build: $(tail -1 "$work/sbtn.log" | cut -c1-50)"; fi
    run_sbt --jvm-client shutdown >/dev/null 2>&1
fi

if want mill; then
    use_profile mill
    # --no-daemon: the launcher and the daemon talk over a loopback TCP socket
    # (out/mill-daemon/socketPort), which the profile grants to nothing, since loopback is every
    # local service. Without the daemon there is no socket — Mill's --jvm-client.
    for command in --version __.compile __.test; do
        [ "$command" = __.test ] && [ "$quick" = 1 ] && { report SKIP "./mill $command" "quick mode"; continue; }
        if ( cd "$mill_project" && sandboxed mill ./mill --no-daemon "$command" ) >"$work/mill.log" 2>&1
        then report PASS "./mill $command" "$(grep -m1 -i 'mill\|compiling\|passed' "$work/mill.log" | cut -c1-40)"
        else report FAIL "./mill $command" "$(grep -v 'Picked up' "$work/mill.log" | tail -1 | cut -c1-70)"; fi
    done
    # The daemon form stays measured, as sbtn does for sbt: if it starts passing, the flag
    # becomes a choice.
    if ( cd "$mill_project" && sandboxed mill ./mill --version ) >"$work/mill-daemon.log" 2>&1
    then report INFO "./mill --version (daemon)" "passes: the --no-daemon pin is now a choice"
    else
        why=$(grep -v 'Picked up' "$work/mill-daemon.log" | tail -1 | cut -c1-50)
        report INFO "./mill --version (daemon)" "no: $why"
    fi
    end_project_servers
fi

# --- negative rows, under every selected profile -----------------------------------------------

for p in $profiles; do
    use_profile "$p"
    scratch=$(scratch_of "$p")
    echo
    echo "reads, under the $p profile"
    present_or_skip "read ~/Documents" "$HOME/Documents" \
        && expect_denied "$p" "read ~/Documents" "ls '$HOME/Documents'"
    present_or_skip "read ~/.ssh" "$HOME/.ssh" && expect_denied "$p" "read ~/.ssh" "ls '$HOME/.ssh'"
    present_or_skip "read the launcher state root" "$state_root" \
        && expect_denied "$p" "read the launcher state root" "ls '$state_root'"
    expect_denied "$p" "read another project's agent cache" "ls '$cache_root/cache'"
    expect_denied "$p" "read the user's other Coursier arc entries" "ls '$user_arc'"
    # §7.2's ancestor chain is file-read-metadata: a listing would reveal sibling names.
    expect_denied "$p" "list an ancestor of a granted path" "ls '$HOME/Library/Caches'"
    expect_denied "$p" "read PROJECT/.git" "cat '$project/.git/HEAD'"   # the repository's, under both
    expect_denied "$p" "read a nested .git" "cat '$scratch/sub/nested/.git/config'"

    echo
    echo "writes, under the $p profile"
    jvm_dir=${COURSIER_CACHE:-$HOME/Library/Caches/Coursier}/jvm
    if [ -e "$jvm_dir" ]; then expect_denied "$p" "write Coursier/jvm" ": > '$jvm_dir/$marker'"
    else expect_denied "$p" "write the Coursier JDK home (no jvm/ exists, §3.1)" ": > '$JAVA_HOME/$marker'"; fi
    expect_denied "$p" "write ~/.sbt/boot" ": > '$HOME/.sbt/boot/$marker'"
    expect_denied "$p" "write the Coursier-installed sbt launcher" ": >> '$sbt_launcher'"
    expect_denied "$p" "write PROJECT/.git/config" ": >> '$project/.git/config'"
    expect_denied "$p" "create under PROJECT/.git" ": > '$project/.git/$marker'"
    expect_denied "$p" "write PROJECT/sub/nested/.git/hooks/x" ": > '$scratch/sub/nested/.git/hooks/x'"
    expect_denied "$p" "write PROJECT/.GIT/config (case fold)" ": >> '$scratch/sub/nested/.GIT/config'"
    expect_denied "$p" "create PROJECT/.git during the build" "mkdir '$scratch/.git'"
    expect_denied "$p" "link PROJECT/x -> PROJECT/.git/config" "ln '$scratch/sub/nested/.git/config' '$scratch/x'"
    expect_denied "$p" "write via PROJECT/link -> PROJECT/.git" ": >> '$scratch/link/config'"
    expect_denied "$p" "write PROJECT/.ko-agent-sandbox/..." ": >> '$scratch/.ko-agent-sandbox/egress/allowed'"
    expect_denied "$p" "write the user's Coursier v1" ": > '$user_v1/$marker'"
    present_or_skip "write the user's Mill download folder" "$mill_downloads" \
        && expect_denied "$p" "write the user's Mill download folder" ": > '$mill_downloads/$marker'"
    if [ "$p" = mill ]; then
        # The one provisioned file is executable; its neighbours in the download folder are not.
        if ( cd "$mill_project" && sandboxed mill "$mill_launcher" --no-daemon --version ) >/dev/null 2>"$work/row.err"
        then report PASS "read and execute the Mill launcher"
        else report FAIL "read and execute the Mill launcher" "$(first_error)"; fi
        expect_denied mill "list the Mill download folder" "ls '$mill_downloads'"
    fi

    echo
    echo "allowed writes, under the $p profile"
    expect_allowed "$p" "write agent cache coursier/v1/..." ": > '$agent_v1/$marker'"
    expect_allowed "$p" "write PROJECT/..." ": > '$scratch/ok'"
    expect_allowed "$p" "write session temporary directory" ": > '$SESSION_TMP/$marker'"
    # The guard is scoped to the project: a build's tests may make throwaway repositories in the
    # session temp, and this project's own do.
    expect_allowed "$p" "create .git in the session temporary directory" \
        "mkdir -p '$SESSION_TMP/fixture/.git' && : > '$SESSION_TMP/fixture/.git/config'"

    echo
    echo "network, under the $p profile"
    # /bin/bash's /dev/tcp is a connect(2) with no tool to grant; an IP literal keeps DNS out.
    if /usr/bin/sandbox-exec -f "$work/gate-$p.sb" /bin/bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>"$work/row.err"
    then report FAIL "connect directly to arbitrary Internet host" "connected"
    else report PASS "connect directly to arbitrary Internet host" "denied: $(head -1 "$work/row.err" | cut -c1-50)"; fi
done
report SKIP "fetch allowed Maven artifact via proxy" "Phase 3: no build proxy yet"
report SKIP "fetch non-allowlisted host via proxy" "Phase 3: no build proxy yet"

echo
echo "PASS $pass  FAIL $fail  SKIP $skip"
echo "logs and profiles: $work"
[ "$fail" -eq 0 ]
