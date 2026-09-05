#!/bin/sh
# The security gate, run by hand on macOS before each release, and when the profile generator,
# the wrapper or the channel changes. One row per contract claim, each run under the generated
# profile, each reporting PASS, FAIL or SKIP with what it observed. Everything else in src/probe/
# finds out what a profile needs; this one finds out whether the profile that resulted enforces
# what the contract claims — and, in the channel rows, whether the channel carries a build and
# tears down with its requester.
#
#   sh src/probe/build-profile-gate.sh [sbt|mill|all] [quick]
#
# The tool selects the positive rows; the negative matrix and the network rows run under every
# selected profile. `quick` leaves the test rows and the lifecycle rows out. Profiles for the
# negative matrix come from `sbt Test/runMain EmitBuildProfile`; the build rows run through
# RunOnHost — the RunOnHostSandbox wrapper — as plain java on the classpath emit printed, never
# through `sbt Test/runMain`, whose own server would hold this project's portfile against the
# wrapper (one server per project). Each wrapper row scavenges, publishes a session, starts the
# build's own proxy, builds under the profile and ends what it started, so the rows measure the
# lifecycle as well as the profile; there is no warm-up block, and a cold agent cache resolves
# through the proxy inside the profile, which is the measurement.
#
# The sbt rows build this repository. The mill rows build src/probe/mill-fixture, a one-module mill
# project that exists for them: this repository is sbt-built, and a mill build of it would be a
# second build definition rather than a measurement. src/probe/deny-fixture exists for the
# unlisted-host row: its resolution must reach a host the proxy refuses.
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
mill_project=$project/src/probe/mill-fixture
project_of() { if [ "$1" = mill ]; then printf '%s\n' "$mill_project"; else printf '%s\n' "$project"; fi; }

# The machine, before any row: a run with no machine recorded is not evidence for the next release.
echo "machine"
machine() { printf '  %s\n' "$1"; }
machine "macOS $(sw_vers -productVersion), $(uname -m)"
if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/java" ]
then machine "$("$JAVA_HOME/bin/java" -version 2>&1 | head -1) ($JAVA_HOME)"
else machine "JAVA_HOME does not name a JDK"; fi
machine "sbt $(sed -n 's/^sbt.version=//p' "$project/project/build.properties")"
machine "mill $(grep -m1 -o '"[0-9][^"]*"' "$mill_project/mill" | tr -d '"')"
if command -v podman >/dev/null 2>&1
then provider=$(podman machine info --format '{{.Host.VMType}}' 2>/dev/null || echo unknown)
    machine "$(podman --version), machine provider: $provider"
else machine "podman: absent"; fi
# The guard's fold rule depends on which answer the project's volume gives.
case_probe=$(mktemp -d "$project/target/gate/case.XXXXXX")
: > "$case_probe/a"
if [ -e "$case_probe/A" ]; then machine "project filesystem: case-folding"
else machine "project filesystem: case-sensitive"; fi
rm -rf "$case_probe"

emit() { # tool
    rm -f "$work/gate-$1.env"
    # Each path quoted for sbt's own command parser: a checkout with a space in its path would
    # otherwise split into two arguments.
    args="\"$work/gate-$1.sb\" src/main/resources/agentsandbox/runtime-authority.txt $1 \"$(project_of "$1")\""
    sbt -batch "Test/runMain agentsandbox.launcher.EmitBuildProfile $args" >"$work/emit-$1.log" 2>&1 \
        || { echo "emit failed for $1:"; tail -20 "$work/emit-$1.log"; return 1; }
    mv "$work/gate-$1.sb.env" "$work/gate-$1.env"
}

# --- the environment contract (RunOnHostSandbox) ------------------------------------------------
#
# The JVM settings travel in JAVA_TOOL_OPTIONS, which the server sbt's client forks inherits; the
# same -D flags on the command line reach the client alone. XDG_RUNTIME_DIR and
# SBT_GLOBAL_SERVER_DIR keep sbt's sockets inside the session temp (RunOnHostPolicy.
# SessionTmpMaxLength says why its length matters).
#
# PATH, because -java-home reaches sbt's client alone: the client starts the server by re-running
# the sbt script, which takes `java` from PATH — /usr/bin/java, the stub the JVM rule rejects and the
# profile denies. mill's `mill-jvm-version: system` takes `java` from PATH the same way.
# `env -i`, because the wrapper's environment is a closed set (RunOnHostSandbox.buildEnvironment;
# run-on-host.md, "The session", has the table) and a row passing on a variable or a PATH entry
# production withholds would measure nothing. The proxy settings are the one omission: these rows
# run without a proxy, the network rows measuring the denial itself. exec, because with_timeout
# backgrounds this function and kills $!: without it that pid is a subshell and the timeout kill
# would orphan the build instead of ending it.
build_env() { # agent-v1 command...
    cache=$1; shift
    account=$(id -un)
    exec env -i \
        PATH="$JAVA_HOME/bin:/usr/bin:/bin:/usr/sbin:/sbin" JAVA_HOME="$JAVA_HOME" \
        HOME="$HOME" ${LANG:+"LANG=$LANG"} ${LC_ALL:+"LC_ALL=$LC_ALL"} \
        TMPDIR="$SESSION_TMP" XDG_RUNTIME_DIR="$SESSION_TMP" SBT_GLOBAL_SERVER_DIR="$SESSION_TMP" \
        COURSIER_CACHE="$cache" USER="$account" LOGNAME="$account" \
        MILL_FINAL_DOWNLOAD_FOLDER="$mill_downloads" \
        JAVA_TOOL_OPTIONS="-Djava.io.tmpdir=$SESSION_TMP -Djava.util.prefs.userRoot=$SESSION_TMP \
-Dsbt.global.base=$sbt_global -Djava.net.preferIPv4Stack=true" \
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

# A build through the wrapper: RunOnHost scavenges, publishes a session, starts the build
# proxy, runs the tool under the generated profile, ends its server and proxy, and preserves the
# exit code. Its stderr carries the wrapper's own lines — `scavenged ...`, `refused: ...`,
# `Build requested network access ...` — which several rows read. $test_cp is captured from emit.
wrapper() { # tool project command...
    wrapper_tool=$1; wrapper_project=$2; shift 2
    with_timeout "${GATE_ROW_TIMEOUT:-900}" "$JAVA_HOME/bin/java" -cp "$test_cp" \
        agentsandbox.launcher.RunOnHost "$wrapper_tool" "$wrapper_project" \
        src/main/resources/agentsandbox/runtime-authority.txt -- "$@"
}
deny_project=$project/src/probe/deny-fixture
session_root=/private/tmp/ko-agent-$(id -u)

# A shell command under a profile, so a row runs exactly what a build's script would.
sb() { /usr/bin/sandbox-exec -f "$work/gate-$1.sb" /bin/sh -c "$2" >/dev/null 2>"$work/row.err"; }

first_error() { head -1 "$work/row.err" | cut -c1-70; }
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
# sbt's client forks or the daemon mill's launcher starts, but each belongs to the project it
# runs in.
with_cwd() { # pattern dir exact|under
    for pid in $(pgrep -f -- "$1" 2>/dev/null); do
        cwd=$(lsof -a -p "$pid" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p')
        case "$3:$cwd" in exact:"$2"|under:"$2"/*) printf '%s\n' "$pid" ;; esac
    done
}
# An sbt server's cwd is its project, exactly: a nested project's server is another project's.
project_servers() { with_cwd '-Dsbt.script=' "$project" exact; }
deny_servers() { with_cwd '-Dsbt.script=' "$deny_project" exact; }
# A mill daemon's cwd is out/mill-daemon/<id>/sandbox (MillProcessLauncher.configureRunMillProcess).
mill_daemons() { with_cwd 'mill.daemon.MillDaemonMain' "$mill_project/out/mill-daemon" under; }
# A build proxy a timed-out or killed wrapper left: the wrapper's own scavenger ends these at its
# next start, but the gate must not leave them when it exits before running one. Only this run's:
# its wrappers run on the run's scratch classpath, which the proxy re-invokes on its own command
# line — a concurrent gate's or a real build's proxy carries a different path and is not this
# gate's to end.
stray_proxies() {
    for pid in $(pgrep -f -- '--serve-proxy-on-host' 2>/dev/null); do
        ps -o command= -p "$pid" 2>/dev/null | grep -qF -- "$work" && printf '%s\n' "$pid"
    done
}
# One sbt server per project at a time (SECURITY.md "Run on host"). A thin client attaches to whatever server the
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
    echo "a mill daemon is already running for $mill_project (pid $existing): run './mill shutdown' there," >&2
    echo "or kill it" >&2
    exit 1
fi
# Every server or daemon this run starts — `emit`'s included — is ended at exit, whether or not
# `shutdown` could reach it: a server whose client hung is one `shutdown` cannot find. mill's
# daemon holds out/mill-daemon/daemonLock and a loopback port that a launcher under the profile
# finds and cannot connect to, so it is ended before the rows too.
end_project_servers() {
    for pid in $(project_servers); do kill "$pid" 2>/dev/null && echo "ended sbt server $pid"; done
    for pid in $(deny_servers); do kill "$pid" 2>/dev/null && echo "ended deny-fixture server $pid"; done
    for pid in $(mill_daemons); do kill "$pid" 2>/dev/null && echo "ended mill daemon $pid"; done
    for pid in $(stray_proxies); do kill "$pid" 2>/dev/null && echo "ended stray build proxy $pid"; done
}
trap end_project_servers EXIT
# Through `exit`, so Ctrl-C still runs the EXIT trap: an untrapped INT ends the shell without
# it, and a gate interrupted after `emit` would leave emit's server holding the portfile.
trap 'exit 130' INT
trap 'exit 143' TERM

# --- profiles -----------------------------------------------------------------------------------

profiles=""
if want sbt; then
    echo "emitting the sbt profile"
    emit sbt || exit 1
    profiles="sbt"
fi
if want mill; then
    echo "emitting the mill profile, for $mill_project"
    emit mill || exit 1
    profiles="$profiles mill"
fi
# `emit`'s own sbt server goes before any wrapper or build_env client runs, for the one-server reason
# above: the wrapper would find it holding this project's portfile and refuse.
sbt --jvm-client -batch shutdown >/dev/null 2>&1
profiles=${profiles# }
first=${profiles%% *}
test_cp=$(sed -n 's/^classpath: //p' "$work/emit-$first.log")
[ -n "$test_cp" ] || { echo "emit printed no classpath; the wrapper rows cannot run" >&2; exit 1; }
# Each profile has its own session temp and agent cache — the fixture is another project, so
# another cache — and the contract's environment follows the profile in force.
use_profile() { # tool
    . "$work/gate-$1.env"
    agent_v1=$(sed -n 's/^agent cache: //p' "$work/emit-$1.log")
    sbt_global=$(sed -n 's/^sbt global base: //p' "$work/emit-$1.log")
    cache_root=${agent_v1%/cache/*}
    safe_path "SESSION_TMP" "$SESSION_TMP"
    safe_path "the agent cache" "$agent_v1"
    safe_path "the sbt global base" "$sbt_global"
}
for p in $profiles; do
    echo "$p: $(grep -E '^(session temp|agent cache):' "$work/emit-$p.log" | tr '\n' ' ')"
done
use_profile "$first"
state_root=${XDG_STATE_HOME:-$HOME/.local/state}/ko-agent-sandbox
user_v1=${COURSIER_CACHE:-$HOME/Library/Caches/Coursier}/v1
user_arc=${COURSIER_CACHE:-$HOME/Library/Caches/Coursier}/arc
sbt_launcher=${COURSIER_BIN_DIR:-$HOME/Library/Application Support/Coursier/bin}/sbt
# As the bootstrap derives it (RunOnHostPolicy.millDownloadDir): MILL_USER_CACHE_DIR is not an input.
mill_downloads=${MILL_FINAL_DOWNLOAD_FOLDER:-${XDG_CACHE_HOME:-$HOME/.cache}/mill/download}
# The concrete derived paths, after every environment override has had its say.
safe_path "the launcher state root" "$state_root"
safe_path "the user's Coursier cache" "${COURSIER_CACHE:-$HOME/Library/Caches/Coursier}"
safe_path "the sbt launcher path" "$sbt_launcher"
safe_path "the mill download folder" "$mill_downloads"
mill_launcher=$(sed -n 's/^launcher: //p' "$work/emit-mill.log" 2>/dev/null)

# A scratch tree per profile, inside that profile's project, standing in for a project with
# nested repositories. Made on the host, outside the profile, so the rows test the guard and not
# the ability to build the fixture.
# One variable per profile — never a word-split list, which a space in the checkout path would
# split mid-path. Registered before the first tree exists, so a failed second mktemp leaves
# nothing.
scratch_sbt=""; scratch_mill=""; sibling_repo=""
marker=gate-marker.${work##*.}
cleanup() {
    [ -n "$scratch_sbt" ] && rm -rf "$scratch_sbt"
    [ -n "$scratch_mill" ] && rm -rf "$scratch_mill"
    [ -n "$sibling_repo" ] && rm -rf "$sibling_repo"
    for p in $profiles; do use_profile "$p"; rm -f "$agent_v1/$marker" "$SESSION_TMP/$marker" 2>/dev/null; done
    rm -f "$project/.git/$marker" "$HOME/.sbt/boot/$marker" "$user_v1/$marker" "$mill_downloads/$marker" 2>/dev/null
    # The channel rows' broker and stubbed execs; their FIFOs are this gate's alone — a real
    # session's live inside its container.
    if [ -n "${channel_broker:-}" ]; then
        kill "$channel_broker" 2>/dev/null
        kill_channel_execs
        rm -rf /tmp/ko-agent-sandbox/host-command
    fi
    end_project_servers
}
trap cleanup EXIT
scratch_of() { if [ "$1" = mill ]; then printf '%s\n' "$scratch_mill"; else printf '%s\n' "$scratch_sbt"; fi; }
# An unrelated repository outside the project, target of the symlink-escape rows.
sibling_repo=$(mktemp -d "${TMPDIR:-/tmp}/gate-sibling.XXXXXX") || exit 1
mkdir "$sibling_repo/.git"
printf 'fixture\n' > "$sibling_repo/.git/config"
for p in $profiles; do
    scratch=$(mktemp -d "$(project_of "$p")/gate-scratch.XXXXXX") || exit 1
    if [ "$p" = mill ]; then scratch_mill=$scratch; else scratch_sbt=$scratch; fi
    mkdir -p "$scratch/sub/nested/.git/hooks" "$scratch/.ko-agent-sandbox/egress"
    printf 'fixture\n' > "$scratch/sub/nested/.git/config"
    printf 'fixture\n' > "$scratch/.ko-agent-sandbox/egress/rule"
    ln -s sub/nested/.git "$scratch/link"
    # The escapes, made on the host: a symlink must add no authority over its target.
    ln -s "$HOME" "$scratch/esc-home"
    ln -s / "$scratch/esc-root"
    ln -s "$user_v1" "$scratch/esc-user-v1"
    ln -s "$sibling_repo" "$scratch/esc-repo"
done

# --- positive rows ------------------------------------------------------------------------------
#
# The wrapper rows come first: a cold agent cache resolves through the build proxy inside the
# profile, warming what the emit-profile rows after them read.

echo
echo "positive rows"
if /usr/bin/sandbox-exec -f "$work/gate-$first.sb" "$JAVA_HOME/bin/java" -version >"$work/java.log" 2>&1
then report PASS "java -version" "$(grep -m1 version "$work/java.log")"
else report FAIL "java -version" "$(tail -1 "$work/java.log")"; fi

if want sbt; then
    use_profile sbt
    for command in compile test; do
        [ "$command" = test ] && [ "$quick" = 1 ] && { report SKIP "sbt test" "quick mode"; continue; }
        if wrapper sbt "$project" "$command" >"$work/$command.log" 2>&1
        then report PASS "sbt $command (wrapper)" "$(grep -m1 '^\[success\]' "$work/$command.log")"
        else report FAIL "sbt $command (wrapper)" \
            "$(grep -m1 '^\[error\]\|^refused\|Exception' "$work/$command.log" | cut -c1-70)"; fi
    done

    # The emit-profile rows: same profile, no proxy behind them — the wrapper rows above warmed
    # the agent cache through it. Both clients run so the --jvm-client pin stays measured. The server's
    # java.home is checked against the JDK the profile granted: the server is forked by the
    # client, so nothing about the client's own JVM proves which one the build runs in.
    for client in "--jvm-client" ""; do
        label="sbt --version (${client:-sbtn})"
        if run_sbt "$client" --version >"$work/version.log" 2>&1
        then report PASS "$label" "$(grep -m1 'version:' "$work/version.log" | cut -c1-40)"
        else report FAIL "$label" "$(grep -v '^$' "$work/version.log" | tail -1 | cut -c1-70)"; fi
    done
    if run_sbt --jvm-client 'eval System.getProperty("java.home")' >"$work/jvm.log" 2>&1; then
        if grep -qF "$JAVA_HOME" "$work/jvm.log"
        then report PASS "server runs the granted JDK"
        else report FAIL "server runs the granted JDK" "$(grep -m1 'ans:' "$work/jvm.log" | cut -c1-70)"; fi
    else report FAIL "server runs the granted JDK" "$(tail -1 "$work/jvm.log" | cut -c1-70)"; fi
    # Processes the build itself starts must retain containment, guard rows included. The server
    # is already the client's forked JVM, so each eval measures a child of a child; run once,
    # under the sbt profile — inheritance across fork and exec is the kernel's behavior, not the
    # profile's, and the per-profile rows below cover both profiles' own grants.
    fork_row() { # label eval-expression
        if run_sbt --jvm-client "$2" >"$work/fork.log" 2>&1 && grep -q 'forked-exit=' "$work/fork.log"; then
            if grep -q 'forked-exit=0' "$work/fork.log"
            then report FAIL "$1" "the forked process succeeded"
            else report PASS "$1" "$(grep -m1 -o 'forked-exit=[0-9]*' "$work/fork.log")"; fi
        else report FAIL "$1" "$(tail -1 "$work/fork.log" | cut -c1-60)"; fi
    }
    fork_row "a process forked by the build cannot read ~" \
        'eval { val code = scala.sys.process.Process(Seq("/bin/ls", sys.env("HOME"))).!; "forked-exit=" + code }'
    fork_row "a process forked by the build cannot write PROJECT/.git" \
        'eval { val code = scala.sys.process.Process(
            Seq("/usr/bin/touch", "'"$project"'/.git/'"$marker"'")).!; "forked-exit=" + code }'
    run_sbt --jvm-client shutdown >/dev/null 2>&1

    # --jvm-client is pinned because sbtn returns with nothing built; this row keeps asking whether
    # that changes. A build's success is the measure — sbtn's --version passes and proves nothing.
    if run_sbt "" compile >"$work/sbtn.log" 2>&1 && grep -q '^\[success\]' "$work/sbtn.log"
    then report INFO "sbtn compile" "passes: the --jvm-client pin is now a choice"
    else report INFO "sbtn compile" "no build: $(grep -v '^$' "$work/sbtn.log" | tail -1 | cut -c1-50)"; fi
    run_sbt --jvm-client shutdown >/dev/null 2>&1
fi

if want mill; then
    use_profile mill
    # mill's launcher memoizes its resolved daemon classpath and JVM home in out/mill-daemon/cache
    # and reuses them while the files they name exist (CoursierClient.scala). Written by a run
    # against the user's cache, they name paths the profile denies; the memo goes, so the
    # wrapper's COURSIER_CACHE takes effect.
    rm -rf "$mill_project/out/mill-daemon"
    # --no-daemon: the launcher and the daemon talk over a loopback TCP socket
    # (out/mill-daemon/socketPort), which the profile grants to nothing, since loopback is every
    # local service. Without the daemon there is no socket — mill's --jvm-client.
    for command in --version __.compile __.test; do
        [ "$command" = __.test ] && [ "$quick" = 1 ] && { report SKIP "./mill $command" "quick mode"; continue; }
        if wrapper mill "$mill_project" "$command" >"$work/mill.log" 2>&1
        then report PASS "./mill $command (wrapper)" \
            "$(grep -m1 -i 'mill\|compiling\|passed' "$work/mill.log" | cut -c1-40)"
        else report FAIL "./mill $command (wrapper)" \
            "$(grep -v 'Picked up' "$work/mill.log" | tail -1 | cut -c1-70)"; fi
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
    expect_denied "$p" "read the user's Coursier v1" "ls '$user_v1/'"
    expect_denied "$p" "read the user's other Coursier arc entries" "ls '$user_arc'"
    # The profile's ancestor chain is file-read-metadata: a listing would reveal sibling names.
    expect_denied "$p" "list an ancestor of a granted path" "ls '$HOME/Library/Caches'"
    expect_denied "$p" "read PROJECT/.git" "cat '$project/.git/HEAD'"   # the repository's, under both
    expect_denied "$p" "read a nested .git" "cat '$scratch/sub/nested/.git/config'"
    expect_denied "$p" "read via PROJECT/link -> PROJECT/.git" "cat '$scratch/link/config'"
    # The trailing slash on each ls'd symlink forces resolution into the target: ls on a link
    # whose target cannot even be stat'ed prints the link's own name and succeeds, exactly like a
    # broken link, and a denial so complete it covers the stat would otherwise read as a grant.
    expect_denied "$p" "read ~ via a project symlink" "ls '$scratch/esc-home/'"
    expect_denied "$p" "read /Users via a project symlink to /" "ls '$scratch/esc-root/Users'"
    expect_denied "$p" "read the user's Coursier v1 via a project symlink" "ls '$scratch/esc-user-v1/'"
    expect_denied "$p" "read another repository via a project symlink" "cat '$scratch/esc-repo/.git/config'"
    expect_denied "$p" "write another repository via a project symlink" ": >> '$scratch/esc-repo/.git/config'"

    echo
    echo "writes, under the $p profile"
    jvm_dir=${COURSIER_CACHE:-$HOME/Library/Caches/Coursier}/jvm
    if [ -e "$jvm_dir" ]; then expect_denied "$p" "write Coursier/jvm" ": > '$jvm_dir/$marker'"
    else expect_denied "$p" "write the Coursier JDK home (no jvm/; the home is in arc/)" \
        ": > '$JAVA_HOME/$marker'"; fi
    expect_denied "$p" "write ~/.sbt/boot" ": > '$HOME/.sbt/boot/$marker'"
    expect_denied "$p" "write the Coursier-installed sbt launcher" ": >> '$sbt_launcher'"
    expect_denied "$p" "write PROJECT/.git/config" ": >> '$project/.git/config'"
    expect_denied "$p" "create under PROJECT/.git" ": > '$project/.git/$marker'"
    expect_denied "$p" "write PROJECT/sub/nested/.git/hooks/x" ": > '$scratch/sub/nested/.git/hooks/x'"
    expect_denied "$p" "write PROJECT/.GIT/config (case fold)" ": >> '$scratch/sub/nested/.GIT/config'"
    expect_denied "$p" "create PROJECT/.git during the build" "mkdir '$scratch/.git'"
    expect_denied "$p" "link PROJECT/x -> PROJECT/.git/config" "ln '$scratch/sub/nested/.git/config' '$scratch/x'"
    expect_denied "$p" "write via PROJECT/link -> PROJECT/.git" ": >> '$scratch/link/config'"
    expect_denied "$p" "write PROJECT/.ko-agent-sandbox/..." ": >> '$scratch/.ko-agent-sandbox/egress/rule'"
    expect_denied "$p" "write the user's Coursier v1" ": > '$user_v1/$marker'"
    present_or_skip "write the user's mill download folder" "$mill_downloads" \
        && expect_denied "$p" "write the user's mill download folder" ": > '$mill_downloads/$marker'"
    if [ "$p" = mill ]; then
        # The one provisioned file is executable; its neighbours in the download folder are not.
        if ( cd "$mill_project" && sandboxed mill "$mill_launcher" --no-daemon --version ) >/dev/null 2>"$work/row.err"
        then report PASS "read and execute the mill launcher"
        else report FAIL "read and execute the mill launcher" "$(first_error)"; fi
        expect_denied mill "list the mill download folder" "ls '$mill_downloads'"
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
    # `sb` exports no proxy variables, so curl here is the build that ignores them; either the
    # resolution or the connect must die on the profile, never on a slow timeout.
    expect_denied "$p" "HTTPS around the proxy (curl, direct)" \
        "/usr/bin/curl --max-time 5 -sS https://repo1.maven.org/maven2/"
    expect_denied "$p" "DNS resolution (direct socket)" "/usr/bin/nslookup -timeout=3 example.com"
done
# --- the build proxy ----------------------------------------------------------------------------

echo
echo "the build proxy"
if ! want sbt; then
    report SKIP "fetch allowed Maven artifact via proxy" "sbt rows not selected"
    report SKIP "fetch unlisted host via proxy" "sbt rows not selected"
else
    use_profile sbt
    # Made cold on purpose: with the artifact gone from the agent cache, a successful compile can
    # only have fetched it — and the direct-connect row already showed the profile's only route is
    # the proxy.
    rm -rf "$agent_v1/https/repo1.maven.org/maven2/org/scalameta"
    if wrapper sbt "$project" Test/compile >"$work/refetch.log" 2>&1
    then report PASS "fetch allowed Maven artifact via proxy" "munit re-fetched, Test/compile ok"
    else report FAIL "fetch allowed Maven artifact via proxy" \
        "$(grep -m1 '^\[error\]\|^refused\|Exception' "$work/refetch.log" | cut -c1-70)"; fi

    # deny-fixture's resolution reaches a refused host; the build must fail and the wrapper must
    # say which host — the wrapper's denied-host report.
    if wrapper sbt "$deny_project" update >"$work/deny.log" 2>&1
    then report FAIL "fetch unlisted host via proxy" "the build succeeded"
    elif grep -q 'Build requested network access' "$work/deny.log" \
        && grep -q 'denied.example.com' "$work/deny.log"
    then report PASS "fetch unlisted host via proxy" "refused; wrapper named denied.example.com"
    else report FAIL "fetch unlisted host via proxy" \
        "failed without the wrapper's diagnostic: $(tail -1 "$work/deny.log" | cut -c1-50)"; fi
fi

# --- the session lifecycle ----------------------------------------------------------------------

echo
echo "the session lifecycle"
sessions_now() { ls "$session_root" 2>/dev/null | grep -cv -e '^staging$' -e '^condemned$' -e '^root-lock$'; }
lifecycle_rows="two concurrent sessions
SIGTERM: the wrapper cleans up behind itself
SIGKILL mid-build: the running group is ended provably
SIGKILL: next start condemns and collects
orphan server ended by portfile attribution"
# A here-doc, not a pipe: report counts, and a pipeline would count in a subshell.
skip_lifecycle() {
    while IFS= read -r row; do report SKIP "$row" "$1"; done <<EOF
$lifecycle_rows
EOF
}
# The victim's own client record, bound to it directly: the recorded shim is spawned by the
# wrapper, so its parent pid is the victim's, and the recorded start time must match the live
# process — the same pid-plus-start proof the wrapper's own scavenger uses, so a stale record
# whose pid was reused by another child of the victim never passes. Empty when the wrapper ends
# first.
await_client_record() { # victim-pid
    tries=0
    while [ "$tries" -lt 600 ]; do
        for record in "$session_root"/*/records/client; do
            [ -f "$record" ] || continue
            read -r pgid start < "$record" || continue
            [ "$(ps -o ppid= -p "$pgid" 2>/dev/null | tr -d ' ')" = "$1" ] || continue
            [ "$(ps -o lstart= -p "$pgid" 2>/dev/null | sed 's/^ *//;s/ *$//')" = "$start" ] || continue
            printf '%s\n' "$record"; return 0
        done
        kill -0 "$1" 2>/dev/null || return 0
        tries=$((tries + 1)); sleep 0.5
    done
}
# Always launched with `&`, and exec so $! IS the wrapper JVM: without it the background pid is
# the subshell running this function, java is its child, and every staged kill — and the shim's
# parent-pid check above — would land on or look at the wrong process.
victim_wrapper() { # log-name
    exec "$JAVA_HOME/bin/java" -cp "$test_cp" agentsandbox.launcher.RunOnHost \
        sbt "$project" src/main/resources/agentsandbox/runtime-authority.txt -- compile >"$work/$1" 2>&1
}
if [ "$quick" = 1 ]; then
    skip_lifecycle "quick mode"
elif [ "$tool" != all ]; then
    skip_lifecycle "needs both tools"
else
    # Concurrency: one sbt and one mill session overlap, each with its own directory and proxy.
    wrapper sbt "$project" compile >"$work/conc-sbt.log" 2>&1 & conc_sbt=$!
    wrapper mill "$mill_project" __.compile >"$work/conc-mill.log" 2>&1 & conc_mill=$!
    peak=0; tries=0
    while [ "$tries" -lt 600 ]; do
        now=$(sessions_now); [ "$now" -gt "$peak" ] && peak=$now
        kill -0 "$conc_sbt" 2>/dev/null || kill -0 "$conc_mill" 2>/dev/null || break
        tries=$((tries + 1)); sleep 0.5
    done
    wait "$conc_sbt"; conc_a=$?
    wait "$conc_mill"; conc_b=$?
    if [ "$conc_a" -eq 0 ] && [ "$conc_b" -eq 0 ]
    then report PASS "two concurrent sessions" "both built; peak concurrent session dirs: $peak"
    else report FAIL "two concurrent sessions" "sbt exit $conc_a, mill exit $conc_b"; fi

    # SIGTERM mid-build: the wrapper's shutdown hook — a JVM's `finally` never runs on a signal —
    # ends the groups and removes the session before the JVM exits (RunOnHostSession).
    victim_wrapper sigterm.log & victim=$!
    client_record=$(await_client_record "$victim")
    if [ -z "$client_record" ]; then
        report FAIL "SIGTERM: the wrapper cleans up behind itself" \
            "no client record appeared: $(tail -1 "$work/sigterm.log" | cut -c1-50)"
    else
        kill -TERM "$victim" 2>/dev/null; wait "$victim" 2>/dev/null
        sleep 1
        # The victim's own session directory, not a root-wide count: a concurrent legitimate
        # session is not this row's to judge.
        victim_session=${client_record%/records/client}
        if [ ! -d "$victim_session" ] && [ ! -d "$session_root/condemned/${victim_session##*/}" ] \
            && [ -z "$(project_servers)" ] && [ -z "$(stray_proxies)" ]
        then report PASS "SIGTERM: the wrapper cleans up behind itself"
        else report FAIL "SIGTERM: the wrapper cleans up behind itself" \
            "left: $(ls -d "$victim_session" 2>/dev/null) \
$(project_servers | tr '\n' ' ')$(stray_proxies | tr '\n' ' ')"
        fi
    fi

    # SIGKILL mid-build: the shim leader survives the wrapper, so the next start ends the whole
    # running group provably instead of refusing a leaderless one.
    victim_wrapper killed-mid.log & victim=$!
    client_record=$(await_client_record "$victim")
    if [ -z "$client_record" ]; then
        report FAIL "SIGKILL mid-build: the running group is ended provably" \
            "no client record appeared: $(tail -1 "$work/killed-mid.log" | cut -c1-50)"
    else
        kill -9 "$victim" 2>/dev/null; wait "$victim" 2>/dev/null
        wrapper sbt "$project" --version >"$work/recover-mid.log" 2>&1
        if grep -q 'GroupEnded' "$work/recover-mid.log"
        then report PASS "SIGKILL mid-build: the running group is ended provably" \
            "$(grep -m1 'scavenged' "$work/recover-mid.log" | cut -c1-70)"
        else report FAIL "SIGKILL mid-build: the running group is ended provably" \
            "$(tail -1 "$work/recover-mid.log" | cut -c1-70)"; fi
    fi

    # The true orphan needs the shim gone too: SIGKILL the wrapper mid-build, let the client
    # finish its command cleanly — the shim publishes its exit beside the record, and a
    # cleanly-left server survives (session-recovery.sh M3) — then SIGKILL the shim alone.
    # Proxy recorded and ended, client group leaderless and refused, server alive behind the
    # portfile for attribution (RunOnHostSession). Killing any of the client's processes instead stages the
    # wrong state: a server whose client dies mid-exec dies with it — measured, as was the
    # completed deny-fixture variant whose server was gone before recovery.
    victim_wrapper killed.log & victim=$!
    client_record=$(await_client_record "$victim")
    if [ -z "$client_record" ]; then
        report FAIL "SIGKILL: next start condemns and collects" \
            "no client record appeared: $(tail -1 "$work/killed.log" | cut -c1-50)"
        report SKIP "orphan server ended by portfile attribution" "no orphan was staged"
    else
        client_pgid=$(awk '{print $1}' "$client_record")
        kill -9 "$victim" 2>/dev/null; wait "$victim" 2>/dev/null
        tries=0
        while [ ! -f "$client_record.exit" ] && [ "$tries" -lt 600 ]; do
            tries=$((tries + 1)); sleep 0.5
        done
        if [ ! -f "$client_record.exit" ]; then
            report FAIL "SIGKILL: next start condemns and collects" "the client never finished"
            report SKIP "orphan server ended by portfile attribution" "no orphan was staged"
            pkill -9 -g "$client_pgid" 2>/dev/null
        else
            kill -9 "$client_pgid" 2>/dev/null   # the shim alone: the build is done, the server stays
            sleep 1
            # The recovery run's own build is beside the point (and --version is the cheap one);
            # its stderr carries the scavenge of the victim's session.
            wrapper sbt "$project" --version >"$work/recover.log" 2>&1
            if grep -q 'scavenged' "$work/recover.log"
            then report PASS "SIGKILL: next start condemns and collects" \
                "$(grep -m1 'scavenged' "$work/recover.log" | cut -c1-70)"
            else report FAIL "SIGKILL: next start condemns and collects" \
                "$(tail -1 "$work/recover.log" | cut -c1-70)"; fi
            if grep -q 'ServerShutDown' "$work/recover.log"
            then report PASS "orphan server ended by portfile attribution" \
                "$(grep -m1 -o 'ServerShutDown([^)]*)' "$work/recover.log" | cut -c1-70)"
            else report FAIL "orphan server ended by portfile attribution" \
                "$(grep -m1 'scavenged' "$work/recover.log" | cut -c1-70)"; fi
        fi
    fi
fi

# --- the channel ---------------------------------------------------------------------------
#
# The real shim against the real broker, the `podman exec` transport a local script and the
# sandbox this host. The wrapper behind it is the same one the rows above measured; what these
# add is the channel — framing, streamed output and the build's own exit code, the
# working-directory boundary, and teardown by descriptor lifetime.

echo
echo "the channel"
channel_dir=/tmp/ko-agent-sandbox/host-command
channel_rows="channel: sbt test returns the build's own exit code
channel: a working directory outside the project is refused
channel: a dead shim ends the running build
channel: a dead sandbox ends the channel and its build"
skip_channel() {
    while IFS= read -r row; do report SKIP "$row" "$1"; done <<EOF
$channel_rows
EOF
}
# Only processes the stub podman recorded, proven by the same pid-plus-start identity the
# wrapper's scavenger uses — never a pattern kill, which would match a real session's own
# `podman exec` command lines, and never by pid alone, which a recycled pid defeats. Each owned
# tree goes descendants-first, while the parent still holds them: the shell behind an exec may
# have forked its command, and a surviving orphan keeps the FIFO and pipe open (the measured
# behavior RunOnHostChannel.end answers on the broker's side). Every signal is proved
# immediately before it fires — a descendant by its link to the live, owned parent, which is
# killed after its children and spawns nothing new, so a recycled pid cannot re-enter the tree;
# the recorded root by its start time once more.
parent_of() { ps -o ppid= -p "$1" 2>/dev/null | tr -d ' '; }
kill_owned_children() { # parent-pid
    for child in $(pgrep -P "$1" 2>/dev/null); do
        [ "$(parent_of "$child")" = "$1" ] || continue
        kill_owned_children "$child"
        [ "$(parent_of "$child")" = "$1" ] && kill -9 "$child" 2>/dev/null
    done
}
kill_channel_execs() {
    [ -f "$work/exec.pids" ] || return 0
    while IFS='|' read -r pid start; do
        [ "$(ps -o lstart= -p "$pid" 2>/dev/null)" = "$start" ] || continue
        ps -o command= -p "$pid" 2>/dev/null | grep -qF "$channel_dir" || continue
        kill_owned_children "$pid"
        [ "$(ps -o lstart= -p "$pid" 2>/dev/null)" = "$start" ] && kill -9 "$pid" 2>/dev/null
    done < "$work/exec.pids"
}
# `exec` for the same reason as victim_wrapper: the staged kills must land on the shim itself.
channel_shim() { # log cwd args...
    chan_log=$1; chan_cwd=$2; shift 2
    cd "$chan_cwd" || exit 1
    PATH="$work/bin:$PATH" exec "$project/container/ko-agent-sandbox/sandbox-run-on-host" "$@" \
        >"$work/$chan_log" 2>"$work/$chan_log.err"
}
channel_settled() { # await the broker between rows: no session, no server, no build proxy
    tries=0
    while { [ "$(sessions_now)" -gt 0 ] || [ -n "$(project_servers)" ] || [ -n "$(stray_proxies)" ]; } \
        && [ "$tries" -lt 240 ]; do tries=$((tries + 1)); sleep 0.5; done
}
if [ "$quick" = 1 ]; then
    skip_channel "quick mode"
elif ! want sbt; then
    skip_channel "needs sbt"
else
    # macOS has neither flock(1) nor timeout(1): the shim's serialization is stubbed out — the
    # rows are serial — and its exit-read bound runs unbounded, which only a broker dying
    # mid-build would notice.
    mkdir -p "$work/bin"
    printf '#!/bin/sh\nexit 0\n' > "$work/bin/flock"; chmod +x "$work/bin/flock"
    printf '#!/bin/sh\nshift\nexec "$@"\n' > "$work/bin/timeout"; chmod +x "$work/bin/timeout"
    # `podman exec -i C sh -c S` runs S here, and container liveness is a file this gate flips.
    # Each exec records its pid — which survives the exec — so "the container died, taking every
    # exec with it" can be staged, and cleaned up, against exactly this gate's processes: a
    # pattern kill would match every live session's own `podman exec` command lines too.
    cat > "$work/podman" <<EOF
#!/bin/sh
case "\$1 \$2" in
    "exec -i")
        echo "\$\$|\$(ps -o lstart= -p \$\$)" >> "$work/exec.pids"
        shift 3; exec "\$@" ;;
    "container inspect") cat "$work/running" ;;
esac
EOF
    chmod +x "$work/podman"
    echo true > "$work/running"
    rm -rf "$channel_dir"
    "$JAVA_HOME/bin/java" -cp "$test_cp" agentsandbox.launcher.AgentSandboxLauncher \
        --serve-run-on-host "$work/podman" C "$project" sbt "$work/channel.log" "$project" \
        >/dev/null 2>&1 & channel_broker=$!
    tries=0
    while [ ! -p "$channel_dir/req" ] && [ "$tries" -lt 100 ]; do tries=$((tries + 1)); sleep 0.2; done
    if [ ! -p "$channel_dir/req" ]; then
        skip_channel "the broker made no FIFOs: $(tail -1 "$work/channel.log" 2>/dev/null | cut -c1-50)"
    else
        # The exit criterion's row: an agent-invoked `sbt test`, its exit code the build's own.
        with_timeout 1800 channel_shim chan-test.log "$project" sbt test; status=$?
        if [ "$status" -eq 0 ] && grep -q '^\[success\]' "$work/chan-test.log"
        then report PASS "channel: sbt test returns the build's own exit code" \
            "$(grep -m1 '^\[success\]' "$work/chan-test.log")"
        else report FAIL "channel: sbt test returns the build's own exit code" \
            "exit $status: $(tail -1 "$work/chan-test.log.err" | cut -c1-60)"; fi
        channel_settled

        with_timeout 120 channel_shim chan-refused.log /private/tmp sbt --version; status=$?
        if [ "$status" -eq 2 ] && grep -q 'CHANNEL_UNAVAILABLE' "$work/chan-refused.log.err"
        then report PASS "channel: a working directory outside the project is refused"
        else report FAIL "channel: a working directory outside the project is refused" \
            "exit $status: $(tail -1 "$work/chan-refused.log.err" | cut -c1-60)"; fi

        # The shim dies; the broker sees the descriptor close and TERMs the wrapper, whose hook
        # is the SIGTERM row's measured teardown.
        channel_shim chan-kill.log "$project" sbt compile & shim=$!
        tries=0
        while [ "$(sessions_now)" -eq 0 ] && [ "$tries" -lt 600 ]; do tries=$((tries + 1)); sleep 0.5; done
        kill -9 "$shim" 2>/dev/null; wait "$shim" 2>/dev/null
        channel_settled
        broker_state=$(kill -0 "$channel_broker" 2>/dev/null && echo alive || echo gone)
        if [ "$(sessions_now)" -eq 0 ] && [ -z "$(project_servers)" ] && [ -z "$(stray_proxies)" ] \
            && [ "$broker_state" = alive ]
        then report PASS "channel: a dead shim ends the running build"
        else report FAIL "channel: a dead shim ends the running build" \
            "sessions: $(sessions_now), servers: $(project_servers | tr '\n' ' '), broker $broker_state"; fi

        # The sandbox dies: every exec dies with it, the shim included; the broker ends the build
        # and, with the container gone, itself.
        channel_shim chan-dead.log "$project" sbt compile & shim=$!
        tries=0
        while [ "$(sessions_now)" -eq 0 ] && [ "$tries" -lt 600 ]; do tries=$((tries + 1)); sleep 0.5; done
        echo false > "$work/running"
        kill -9 "$shim" 2>/dev/null; wait "$shim" 2>/dev/null
        kill_channel_execs
        channel_settled
        tries=0
        while kill -0 "$channel_broker" 2>/dev/null && [ "$tries" -lt 120 ]; do tries=$((tries + 1)); sleep 0.5; done
        broker_state=$(kill -0 "$channel_broker" 2>/dev/null && echo alive || echo gone)
        if [ "$(sessions_now)" -eq 0 ] && [ -z "$(project_servers)" ] && [ "$broker_state" = gone ]
        then report PASS "channel: a dead sandbox ends the channel and its build"
        else report FAIL "channel: a dead sandbox ends the channel and its build" \
            "sessions: $(sessions_now), broker $broker_state"; fi
        rm -rf "$channel_dir"
    fi
fi

# After every wrapper row: nothing of any session outlives it.
leftover=""
[ -n "$(project_servers)" ] && leftover="sbt server: $(project_servers | tr '\n' ' ')"
[ -n "$(deny_servers)" ] && leftover="$leftover deny-fixture server: $(deny_servers | tr '\n' ' ')"
[ -n "$(stray_proxies)" ] && leftover="$leftover proxy: $(stray_proxies | tr '\n' ' ')"
[ "$(sessions_now)" -gt 0 ] && leftover="$leftover session dirs: $(sessions_now)"
if [ -z "$leftover" ]
then report PASS "no proxy or sbt server survives its session"
else report FAIL "no proxy or sbt server survives its session" "$leftover"; fi

echo
echo "PASS $pass  FAIL $fail  SKIP $skip"
echo "logs and profiles: $work"
[ "$fail" -eq 0 ]
