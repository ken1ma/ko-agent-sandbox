#!/bin/sh
# The security gate, run by hand on macOS before each release, and when the profile generator,
# the wrapper or the channel changes. One row per contract claim, each run under the generated
# profile, each reporting PASS, FAIL or SKIP with what it observed. Everything else in src/probe/
# finds out what a profile needs; this one finds out whether the profile that resulted enforces
# what the contract claims — and, in the channel rows, whether the channel carries a command and
# tears down with its requester.
#
#   sh src/probe/run-on-host-profile-gate.sh [sbt|mill|gradle|mvn|all] [quick]
#
# The program selects the positive rows; the negative matrix and the network rows run under every
# selected profile. `quick` leaves the test rows and the lifecycle rows out. Profiles for the
# negative matrix come from `sbt Test/runMain EmitRunOnHostProfile`; the build rows run through
# RunOnHost — the RunOnHostSandbox wrapper — as plain java on the classpath emit printed, never
# through `sbt Test/runMain`, whose own server would hold this project's portfile and be ended by
# the wrapper (one server per build directory). Each wrapper row scavenges, publishes a command directory, starts the
# command's own proxy and sbt server or mill daemon in it — the broker's functions over the command's own session — runs
# the command under the profile and ends what it started, so the rows measure the lifecycle as well as the
# profile; there is no warm-up block, and a cold run-on-host cache resolves through the proxy inside the
# profile, which is the measurement.
#
# The sbt rows build this repository. The mill rows build src/probe/mill-fixture, the gradle rows
# src/probe/gradle-fixture and the mvn rows src/probe/mvn-fixture, one-module projects that exist
# for them: this repository is sbt-built, and a mill, Gradle or Maven build of it would be a second
# build definition rather than a measurement.
# src/probe/deny-fixture exists for the unlisted-host row: its resolution must reach a host the
# proxy refuses. src/probe/ivy-fixture exists for the inter-project row: resolving a dependsOn
# edge enters Ivy, whose lock file lives in the Ivy home, and this repository has no such edge.
#
# The negative rows never write anything real: a "write" is `: >> file`, which opens for append
# and writes nothing, and every created marker is in a scratch tree this script makes and
# removes. A denied row prints the denial on stderr; a wrongly permitted one leaves a marker the
# cleanup removes, and the row reports FAIL. The `open` row, wrongly permitted, starts Calculator,
# which the row ends unless it was running before.
set -u
. "$(dirname "$0")/run-on-host-gate-setup.sh"
if [ "$(uname -s)" != "Darwin" ]; then echo "Run this on macOS." >&2; exit 2; fi
program=${1:-all}
case "$program" in sbt|mill|gradle|mvn|all) ;; *) echo "usage: $0 [sbt|mill|gradle|mvn|all] [quick]" >&2; exit 2 ;; esac
case "${2:-full}" in
    full) quick=0 ;;
    quick) quick=1 ;;
    *) echo "usage: $0 [sbt|mill|gradle|mvn|all] [quick]" >&2; exit 2 ;;
esac
want() { [ "$program" = all ] || [ "$program" = "$1" ]; }

project=$(pwd -P)
# Paths are interpolated into sbt's command parser in `emit` and into single-quoted /bin/sh -c
# strings in the rows, where a quote character would end the quoting and inject. No path here
# earns escaping: any interpolated path carrying a quote or backslash is refused.
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
# The logs are under the project's target/gate/, git-ignored and, unlike $TMPDIR, shared with a
# sandbox session reading them. The project scratch tree is made after preflight, so an early
# exit leaves nothing there.
mkdir -p "$project/target/gate" && work=$(mktemp -d "$project/target/gate/run.XXXXXX") || exit 1
pass=0; fail=0; skip=0
# Only this run's sleeping fixtures may be collected after a cancellation.
fixture_tag=$(printf 'gate-%s' "${work##*/}" | tr '.' '-')
fixture_sleep="fixture[.]Main sleep $fixture_tag([[:space:]]|$)"

report() { # status label detail
    # INFO is a measurement with no expected answer, so it counts toward nothing.
    case "$1" in PASS) pass=$((pass + 1)) ;; FAIL) fail=$((fail + 1)) ;; SKIP) skip=$((skip + 1)) ;; esac
    printf '  %-4s  %-46s %s\n' "$1" "$2" "${3:-}"
}

# The project each profile is for.
mill_project=$project/src/probe/mill-fixture
gradle_project=$project/src/probe/gradle-fixture
mvn_project=$project/src/probe/mvn-fixture
project_of() {
    case "$1" in
        mill) printf '%s\n' "$mill_project" ;;
        gradle) printf '%s\n' "$gradle_project" ;;
        mvn) printf '%s\n' "$mvn_project" ;;
        *) printf '%s\n' "$project" ;;
    esac
}

# The machine, before any row: a run with no machine recorded is not evidence for the next release.
echo "machine"
machine() { printf '  %s\n' "$1"; }
machine "macOS $(sw_vers -productVersion), $(uname -m)"
if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/java" ]
then machine "$("$JAVA_HOME/bin/java" -version 2>&1 | head -1) ($JAVA_HOME)"
else machine "JAVA_HOME does not name a JDK"; fi
machine "sbt $(sed -n 's/^sbt.version=//p' "$project/project/build.properties")"
machine "mill $(grep -m1 -o '"[0-9][^"]*"' "$mill_project/mill" | tr -d '"')"
machine "gradle $(sed -n 's|^distributionUrl=.*/gradle-\(.*\)-bin.zip$|\1|p' \
    "$gradle_project/gradle/wrapper/gradle-wrapper.properties")"
mvn_version=$(sed -n 's|^distributionUrl=.*/apache-maven-\(.*\)-bin.zip$|\1|p' \
    "$mvn_project/.mvn/wrapper/maven-wrapper.properties")
machine "maven $mvn_version"
if command -v podman >/dev/null 2>&1
then provider=$(podman machine info --format '{{.Host.VMType}}' 2>/dev/null || echo unknown)
    machine "$(podman --version), machine provider: $provider"
else machine "podman: absent"; fi
# The .GIT probe reaches the existing .git only on a case-insensitive volume.
case_probe=$(mktemp -d "$project/target/gate/case.XXXXXX")
: > "$case_probe/a"
if [ -e "$case_probe/A" ]; then machine "project filesystem: case-insensitive"; folding=1
else machine "project filesystem: case-sensitive"; folding=0; fi
rm -rf "$case_probe"

emit() { # program
    rm -f "$work/gate-$1.env"
    # Each path quoted for sbt's own command parser: a checkout with a space in its path would
    # otherwise split into two arguments.
    args="\"$work/gate-$1.sb\" src/main/resources/agentsandbox/runtime-authority.txt $1 \"$(project_of "$1")\""
    sbt -batch "Test/runMain agentsandbox.launcher.EmitRunOnHostProfile $args" >"$work/emit-$1.log" 2>&1 \
        || { echo "emit failed for $1:"; tail -20 "$work/emit-$1.log"; return 1; }
    mv "$work/gate-$1.sb.env" "$work/gate-$1.env"
}

# --- the environment contract (RunOnHostSandbox) ------------------------------------------------
#
# The JVM settings travel in _JAVA_OPTIONS, which the server sbt's client forks inherits; the
# same -D flags on the command line reach the client alone. XDG_RUNTIME_DIR and
# SBT_GLOBAL_SERVER_DIR keep sbt's sockets inside the command's temporary directory (RunOnHostPrereqs.
# SessionTmpMaxLength says why its length matters).
#
# PATH, because -java-home reaches sbt's client alone: the client starts the server by re-running
# the sbt script, which takes `java` from PATH — /usr/bin/java, the stub the JVM rule rejects and the
# profile denies. mill's `mill-jvm-version: system` takes `java` from PATH the same way.
# `env -i`, because the wrapper's environment is a closed set (RunOnHostSandbox.commandEnvironment;
# run-on-host.md, "The command's lifetime and environment", has the table). A row passing on a variable
# or a PATH entry production withholds would invalidate the measurement. These rows run without a
# proxy, with one temporary directory for clients and servers; network rows measure denial itself.
# exec, because with_timeout backgrounds this function and kills $!: without it that pid is a
# subshell and the timeout kill would orphan the command instead of ending it.
command_env() { # agent-v1 command...
    cache=$1; shift
    account=$(id -un)
    exec env -i \
        PATH="$JAVA_HOME/bin:/usr/bin:/bin:/usr/sbin:/sbin" JAVA_HOME="$JAVA_HOME" \
        HOME="$HOME" ${LANG:+"LANG=$LANG"} ${LC_ALL:+"LC_ALL=$LC_ALL"} \
        TMPDIR="$SESSION_TMP" XDG_RUNTIME_DIR="$SESSION_TMP" SBT_GLOBAL_SERVER_DIR="$SESSION_TMP" \
        COURSIER_CACHE="$cache" USER="$account" LOGNAME="$account" \
        MILL_FINAL_DOWNLOAD_FOLDER="$mill_downloads" GRADLE_USER_HOME="$gradle_user_home" \
        _JAVA_OPTIONS="-Djava.io.tmpdir=\"$SESSION_TMP\" -Djava.util.prefs.userRoot=\"$SESSION_TMP\" \
-Dsbt.global.base=\"$sbt_global\" -Dsbt.ivy.home=\"$ivy_home\" -Dmaven.repo.local=\"$m2_repository\" \
-Daether.connector.http.useSystemProperties=true -Djava.net.preferIPv4Stack=true" \
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
# Under a profile, through the contract, with the timeout. $1 is the profile's program.
sandboxed() { # program command...
    profile=$work/gate-$1.sb; shift
    with_timeout "${GATE_ROW_TIMEOUT:-600}" command_env "$cache_v1" /usr/bin/sandbox-exec -f "$profile" "$@"
}
run_sbt() { # client command...: the executable the wrapper runs; the profile PATH holds no sbt
    client=$1; shift
    sandboxed sbt "$sbt_executable" "-Dsbt.global.base=$sbt_global" \
        $client -batch -java-home "$JAVA_HOME" "$@"
}

# A command through the wrapper: RunOnHost scavenges, publishes a command directory, starts the command's
# proxy and, for sbt, its server, runs the program under the generated profile, ends them, and preserves the
# exit code. Its stderr carries the wrapper's own lines — `scavenged ...`, `refused: ...`,
# `Command requested network access ...` — which several rows read. $test_cp and $lock_script
# are captured from emit and RunOnHost; the command runs under the build lock the broker's spawn
# takes (locked_wrapper).
build_lock() { "$JAVA_HOME/bin/java" -cp "$test_cp" agentsandbox.launcher.RunOnHost --build-lock "$1" "$2"; }
# The hash that names a build directory's lock and the broker's records for it (RunOnHostSession.buildHash).
build_hash() { lock=$(build_lock sbt "$1") && printf '%s\n' "${lock##*-}"; }
locked_wrapper() { # program project command...
    lw_program=$1; lw_project=$2; shift 2
    lock=$(build_lock "$lw_program" "$lw_project") || return 2
    # exec, so the with_timeout background pid is this perl and then the wrapper JVM, not a
    # subshell whose kill would miss them (victim_wrapper's own reason).
    exec /usr/bin/perl -e "$lock_script" "$lock" 0 "$JAVA_HOME/bin/java" -cp "$test_cp" \
        agentsandbox.launcher.RunOnHost "$lw_program" "$lw_project" \
        src/main/resources/agentsandbox/runtime-authority.txt -- "$@"
}
wrapper() { # program project command...
    wrapper_program=$1; wrapper_project=$2; shift 2
    with_timeout "${GATE_ROW_TIMEOUT:-900}" locked_wrapper "$wrapper_program" "$wrapper_project" "$@"
}
deny_project=$project/src/probe/deny-fixture
ivy_project=$project/src/probe/ivy-fixture
command_root=/private/tmp/ko-agent-$(id -u)

# A shell command under a profile, so a row runs exactly what a build's script would.
sb() { /usr/bin/sandbox-exec -f "$work/gate-$1.sb" /bin/sh -c "$2" >/dev/null 2>"$work/row.err"; }

first_error() { head -1 "$work/row.err" | cut -c1-70; }
expect_denied() { # program label command
    if sb "$1" "$3"; then report FAIL "$2" "allowed"
    else report PASS "$2" "denied: $(first_error)"; fi
}
expect_allowed() { # program label command
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
# sbt's client forks or the daemon mill executable starts, but each belongs to the project it
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
ivy_servers() { with_cwd '-Dsbt.script=' "$ivy_project" exact; }
# A mill daemon's cwd is out/mill-daemon/<id>/sandbox (MillProcessLauncher.configureRunMillProcess).
mill_daemons() { with_cwd 'mill.daemon.MillDaemonMain' "$mill_project/out/mill-daemon" under; }
# A launch's gradle daemons carry the launch's tmp/ as java.io.tmpdir in their initial
# environment, the client's own (RunOnHostGradleDaemons): those of every session under the root here,
# this gate's own included. The "yours" row's daemon, unconfined in a registry under $work, is
# found by its log open there (DaemonMain).
gradle_daemons() {
    for pid in $(pgrep -f -- 'org.gradle.launcher.daemon.bootstrap.GradleDaemon' 2>/dev/null); do
        ps -wwE -o command= -p "$pid" 2>/dev/null | tr ' ' '\n' \
            | grep -qF -- "=-Djava.io.tmpdir=\"$command_root/" && printf '%s\n' "$pid"
    done
}
gate_gradle_daemons() {
    for pid in $(pgrep -f -- 'org.gradle.launcher.daemon.bootstrap.GradleDaemon' 2>/dev/null); do
        lsof -a -p "$pid" -Fn 2>/dev/null | sed -n 's/^n//p' \
            | awk -v d="$work/your-registry/" 'index($0, d) == 1 { found = 1 } END { exit !found }' \
            && printf '%s\n' "$pid"
    done
}
# This run's proxies: a command's, and under the channel rows the broker's. A timed-out or killed
# wrapper's, and a killed broker's, is ended by the next start's scavenge, but the gate must not
# leave one when it exits before running a start. Only this run's: its wrappers run on the run's
# scratch classpath, which the proxy re-invokes on its own command line — a concurrent gate's or
# a real command's proxy carries a different path and is not this gate's to end.
stray_proxies() {
    for pid in $(pgrep -f -- '--serve-proxy-on-host' 2>/dev/null); do
        ps -o command= -p "$pid" 2>/dev/null | grep -qF -- "$work" && printf '%s\n' "$pid"
    done
}
# The proxies no broker's session records: a command's own. A broker's proxy is meant to outlive
# each command, so the rows between commands settle on these.
command_proxies() {
    recorded=$(cat "$command_root"/b*/records/proxy-* 2>/dev/null | awk '{print $1}')
    for pid in $(stray_proxies); do
        pgid=$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ')
        printf '%s\n' "$recorded" | grep -qx "$pgid" || printf '%s\n' "$pid"
    done
}
# The broker's sbt runtime records for a build directory, `<pgid> <start>` each — the proxy's and the
# server's — and whether a record's group leader lives.
broker_proxy_record() { # build-directory
    cat "$command_root"/b*/records/proxy-sbt-"$(build_hash "$1")" 2>/dev/null
}
broker_server_record() { # build-directory
    cat "$command_root"/b*/records/server-sbt-"$(build_hash "$1")" 2>/dev/null
}
broker_daemon_record() { # build-directory
    cat "$command_root"/b*/records/daemon-mill-"$(build_hash "$1")" 2>/dev/null
}
# The broker's gradle daemon records, `<pid> <start>` each, one per daemon of the launch's registry.
broker_gradle_records() {
    cat "$command_root"/b*/records/daemon-gradle-* 2>/dev/null
}
# The mill daemon behind a broker record: the MillDaemonMain in the record's group, the starter's.
daemon_in_group() { # record-line
    [ -n "$1" ] || return 0
    for pid in $(mill_daemons); do
        [ "$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ')" = "${1%% *}" ] && printf '%s\n' "$pid"
    done
}
# The broker session holding the sbt runtime of a build directory.
broker_session_of() { # build-directory
    ls -d "$command_root"/b*/records/proxy-sbt-"$(build_hash "$1")" 2>/dev/null | head -1 | sed 's|/records/.*||'
}
# The sbt servers no broker's session records: a command's own — the gate's entry starts one in the
# command's session — where the broker's server outlives each command.
command_servers() {
    recorded=$(cat "$command_root"/b*/records/server-sbt-* 2>/dev/null | awk '{print $1}')
    for pid in $(project_servers) $(deny_servers) $(ivy_servers); do
        pgid=$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ')
        printf '%s\n' "$recorded" | grep -qx "$pgid" || printf '%s\n' "$pid"
    done
}
record_alive() { # record-line
    [ -n "$1" ] || return 1
    ra_pgid=${1%% *}; ra_start=$(printf '%s' "${1#* }" | sed 's/^ *//;s/ *$//')
    [ "$(ps -o lstart= -p "$ra_pgid" 2>/dev/null | sed 's/^ *//;s/ *$//')" = "$ra_start" ]
}
# The emitter always uses this checkout, even when only another program's rows are selected.
gate_require_idle "$command_root" "$project" "$mill_project" "$gradle_project" "$mvn_project" || exit 1

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
existing=$(gradle_daemons | tr '\n' ' ')
if want gradle && [ -n "$existing" ]; then
    echo "a gradle daemon of a launch is running under $command_root (pid $existing): end that launch," >&2
    echo "or kill it" >&2
    exit 1
fi
# Every server or daemon this run starts — `emit`'s included — is ended at exit, whether or not
# `shutdown` could reach it: a server whose client hung is one `shutdown` cannot find. mill's
# daemon holds out/mill-daemon/daemonLock and a port that a mill executable under the profile
# finds and cannot connect to, so it is ended before the rows too.
end_project_servers() {
    for pid in $(project_servers) $(deny_servers) $(ivy_servers) $(mill_daemons) \
        $(gradle_daemons) $(gate_gradle_daemons) $(stray_proxies); do
        gate_end_unclaimed_process "$command_root" "$pid" && echo "ended gate process $pid"
    done
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
if want gradle; then
    echo "emitting the gradle profile, for $gradle_project"
    emit gradle || exit 1
    profiles="$profiles gradle"
fi
if want mvn; then
    echo "emitting the mvn profile, for $mvn_project"
    emit mvn || exit 1
    profiles="$profiles mvn"
fi
profiles=${profiles# }
first=${profiles%% *}
test_cp=$(sed -n 's/^classpath: //p' "$work/emit-$first.log")
[ -n "$test_cp" ] || { echo "emit printed no classpath; the wrapper rows cannot run" >&2; exit 1; }
# The proxy's own profile, for the java and classpath the wrapper rows run their proxies with.
echo "emitting the proxy profile"
sbt -batch "Test/runMain agentsandbox.launcher.EmitRunOnHostProfile \"$work/gate-proxy.sb\" \
        src/main/resources/agentsandbox/runtime-authority.txt proxy \"$JAVA_HOME\" \"$test_cp\"" \
        >"$work/emit-proxy.log" 2>&1 || { echo "emit failed for the proxy:"; tail -20 "$work/emit-proxy.log"; exit 1; }
# `emit`'s own sbt server goes before any wrapper or command_env client runs, for the one-server reason
# above: the wrapper would find it holding this project's portfile and refuse.
sbt --jvm-client -batch shutdown >/dev/null 2>&1
gate_require_idle "$command_root" "$project" "$mill_project" "$gradle_project" "$mvn_project" || exit 1
lock_script=$("$JAVA_HOME/bin/java" -cp "$test_cp" agentsandbox.launcher.RunOnHost --lock-script)
# Each profile has its own command's temporary directory and run-on-host cache — the fixture is another project, so
# another cache — and the contract's environment follows the profile in force.
use_profile() { # program
    . "$work/gate-$1.env"
    cache_v1=$(sed -n 's/^run-on-host cache: //p' "$work/emit-$1.log")
    sbt_global=$(sed -n 's/^sbt global base: //p' "$work/emit-$1.log")
    ivy_home=$(sed -n 's/^ivy home: //p' "$work/emit-$1.log")
    gradle_user_home=$(sed -n 's/^gradle user home: //p' "$work/emit-$1.log")
    m2_repository=$(sed -n 's/^m2 repository: //p' "$work/emit-$1.log")
    cache_root=${cache_v1%/cache/*}
    safe_path "SESSION_TMP" "$SESSION_TMP"
    safe_path "the run-on-host cache" "$cache_v1"
    safe_path "the sbt global base" "$sbt_global"
    safe_path "the Ivy home" "$ivy_home"
    safe_path "the Gradle user home" "$gradle_user_home"
    safe_path "the Maven local repository" "$m2_repository"
}
for p in $profiles; do
    echo "$p: $(grep -E '^(command temporary directory|run-on-host cache):' "$work/emit-$p.log" | tr '\n' ' ')"
done
use_profile "$first"
state_root=${XDG_STATE_HOME:-$HOME/.local/state}/ko-agent-sandbox
user_v1=${COURSIER_CACHE:-$HOME/Library/Caches/Coursier}/v1
user_arc=${COURSIER_CACHE:-$HOME/Library/Caches/Coursier}/arc
sbt_executable=${COURSIER_BIN_DIR:-$HOME/Library/Application Support/Coursier/bin}/sbt
# As the bootstrap derives it (RunOnHostPrereqs.millDownloadDir): MILL_USER_CACHE_DIR is not an input.
mill_downloads=${MILL_FINAL_DOWNLOAD_FOLDER:-${XDG_CACHE_HOME:-$HOME/.cache}/mill/download}
# The concrete derived paths, after every environment override has had its say.
safe_path "the launcher state root" "$state_root"
safe_path "the user's Coursier cache" "${COURSIER_CACHE:-$HOME/Library/Caches/Coursier}"
safe_path "the sbt executable path" "$sbt_executable"
safe_path "the mill download folder" "$mill_downloads"
mill_executable=$(sed -n 's/^executable: //p' "$work/emit-mill.log" 2>/dev/null)
# The distribution ./gradlew unpacked on this host, as the wrapper derived it (RunOnHostPrereqs.gradleDistributionDir).
gradle_home=$(sed -n 's|^executable: \(.*\)/bin/gradle$|\1|p' "$work/emit-gradle.log" 2>/dev/null)
# The distribution ./mvnw unpacked on this host, as the wrapper derived it (RunOnHostPrereqs.mvnDistributionDir).
mvn_home=$(sed -n 's|^executable: \(.*\)/bin/mvn$|\1|p' "$work/emit-mvn.log" 2>/dev/null)

# A scratch tree per profile, inside that profile's project, standing in for a project with
# nested repositories. Made on the host, outside the profile, so the rows test the guard and not
# the ability to build the fixture.
# One variable per profile — never a word-split list, which a space in the checkout path would
# split mid-path. Registered before the first tree exists, so a failed second mktemp leaves
# nothing.
scratch_sbt=""; scratch_mill=""; scratch_gradle=""; scratch_mvn=""; sibling_repo=""; pin_saved=""
gate_opts_file=""; port_saved=""; redirect_saved=""; unrelated_listener=""
marker=gate-marker.${work##*.}
cleanup() {
    # The ivy fixture's pin, edited under the sbt.version row: restored on any exit.
    [ -n "$pin_saved" ] && printf '%s\n' "$pin_saved" > "$ivy_project/project/build.properties"
    # The fixture's option file the mill rows add, and its socketPort the planted row overwrites.
    [ -n "$gate_opts_file" ] && rm -f "$gate_opts_file"
    [ -n "$port_saved" ] && printf '%s' "$port_saved" > "$mill_project/out/mill-daemon/socketPort"
    if [ -n "$redirect_saved" ] && [ -d "$redirect_saved" ]; then
        rm -f "$mill_project/out/mill-daemon"; mv "$redirect_saved" "$mill_project/out/mill-daemon"
    fi
    [ -n "$scratch_sbt" ] && rm -rf "$scratch_sbt"
    [ -n "$scratch_mill" ] && rm -rf "$scratch_mill"
    [ -n "$scratch_gradle" ] && rm -rf "$scratch_gradle"
    [ -n "$scratch_mvn" ] && rm -rf "$scratch_mvn"
    [ -n "$sibling_repo" ] && rm -rf "$sibling_repo"
    for p in $profiles; do
        use_profile "$p"
        rm -f "$cache_v1/$marker" "$SESSION_TMP/$marker" "$gradle_user_home/$marker" 2>/dev/null
    done
    rm -f "$project/.git/$marker" "$HOME/.sbt/boot/$marker" "$user_v1/$marker" "$mill_downloads/$marker" \
        "$HOME/.gradle/$marker" "$HOME/.m2/repository/$marker" 2>/dev/null
    # The unrelated-service row's listener is this gate's.
    [ -n "$unrelated_listener" ] && kill "$unrelated_listener" 2>/dev/null
    # The channel rows' broker and stubbed execs; their FIFOs are this gate's alone — a real
    # session's live inside its container.
    if [ -n "${channel_broker:-}" ]; then
        kill "$channel_broker" 2>/dev/null
        [ -n "${second_broker:-}" ] && kill "$second_broker" 2>/dev/null
        kill_channel_execs
        rm -rf /tmp/ko-agent-sandbox/run-on-host
        [ -n "${channel_dir2:-}" ] && rm -rf "$channel_dir2"
    fi
    end_project_servers
}
trap cleanup EXIT
scratch_of() {
    case "$1" in
        mill) printf '%s\n' "$scratch_mill" ;;
        gradle) printf '%s\n' "$scratch_gradle" ;;
        mvn) printf '%s\n' "$scratch_mvn" ;;
        *) printf '%s\n' "$scratch_sbt" ;;
    esac
}
# An unrelated repository outside the project, target of the symlink-escape rows.
sibling_repo=$(mktemp -d "${TMPDIR:-/tmp}/gate-sibling.XXXXXX") || exit 1
mkdir "$sibling_repo/.git"
printf 'fixture\n' > "$sibling_repo/.git/config"
for p in $profiles; do
    scratch=$(mktemp -d "$(project_of "$p")/gate-scratch.XXXXXX") || exit 1
    case "$p" in
        mill) scratch_mill=$scratch ;; gradle) scratch_gradle=$scratch ;; mvn) scratch_mvn=$scratch ;;
        *) scratch_sbt=$scratch ;;
    esac
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
# The wrapper rows come first: a cold run-on-host cache resolves through the command's proxy inside the
# profile, warming what the emit-profile rows after them read.

echo
echo "positive rows"
# From the profile's own project: the JVM reads its working directory at start, and the first
# profile grants its program's project, the fixture's under mill, gradle or mvn.
if ( cd "$(project_of "$first")" && /usr/bin/sandbox-exec -f "$work/gate-$first.sb" "$JAVA_HOME/bin/java" -version ) \
    >"$work/java.log" 2>&1
then report PASS "java -version" "$(grep -m1 version "$work/java.log")"
else report FAIL "java -version" "$(tail -1 "$work/java.log")"; fi

if want sbt; then
    use_profile sbt
    sbt_ready=1
    for command in compile test; do
        [ "$command" = test ] && [ "$quick" = 1 ] && { report SKIP "sbt test" "quick mode"; continue; }
        if wrapper sbt "$project" "$command" >"$work/$command.log" 2>&1
        then report PASS "sbt $command (wrapper)" "$(grep -m1 '^\[success\]' "$work/$command.log")"
        else
            sbt_ready=0
            report FAIL "sbt $command (wrapper)" \
                "$(grep -m1 '^\[error\]\|^refused\|Exception' "$work/$command.log" | cut -c1-70); $work/$command.log"
        fi
    done
    # A build with an inter-project edge: Ivy must take its lock file in the redirected home, or
    # the build dies canonicalizing ~/.ivy2 (RunOnHostPrereqs.ivyHomeOf).
    version=$(sed -n 's/^sbt.version=//p' "$ivy_project/project/build.properties")
    if wrapper sbt "$ivy_project" app/packageBin >"$work/ivy.log" 2>&1
    then report PASS "sbt $version packageBin across dependsOn" "$(grep -m1 '^\[success\]' "$work/ivy.log")"
    else report FAIL "sbt $version packageBin across dependsOn" \
        "$(grep -m1 '^\[error\]\|^refused\|Exception' "$work/ivy.log" | cut -c1-70)"; fi

    # The emit-profile rows: same profile, no proxy behind them — the wrapper rows above warmed
    # the run-on-host cache through it. Both clients run so the need for --jvm-client stays measured. The server's
    # java.home is checked against the JDK the profile granted: the server is forked by the
    # client, so nothing about the client's own JVM proves which one the command runs in.
    for client in "--jvm-client" ""; do
        label="sbt --version (${client:-sbtn})"
        if run_sbt "$client" --version >"$work/version.log" 2>&1
        then report PASS "$label" "$(grep -m1 'version:' "$work/version.log" | cut -c1-40)"
        else report FAIL "$label" "$(grep -v '^$' "$work/version.log" | tail -1 | cut -c1-70)"; fi
    done
    # The wrapper sweeps host-cache links before warming the granted cache. If it failed, these
    # direct clients cannot establish that prerequisite themselves; the wrapper row holds the failure.
    if [ "$sbt_ready" -eq 1 ]; then
        if run_sbt --jvm-client 'eval System.getProperty("java.home")' >"$work/jvm.log" 2>&1; then
            if grep -qF "$JAVA_HOME" "$work/jvm.log"
            then report PASS "server runs the granted JDK"
            else report FAIL "server runs the granted JDK" "$(grep -m1 'ans:' "$work/jvm.log" | cut -c1-70)"; fi
        else report FAIL "server runs the granted JDK" "$(tail -1 "$work/jvm.log" | cut -c1-70)"; fi
        # Processes the command itself starts must retain containment, access restrictions included. The server
        # is already the client's forked JVM, so each eval measures a child of a child; run once,
        # under the sbt profile — inheritance across fork and exec is the kernel's behavior, not the
        # profile's, and the per-profile rows below cover each selected profile's grants.
        fork_row() { # label eval-expression
            if run_sbt --jvm-client "$2" >"$work/fork.log" 2>&1 && grep -q 'forked-exit=' "$work/fork.log"; then
                if grep -q 'forked-exit=0' "$work/fork.log"
                then report FAIL "$1" "the forked process succeeded"
                else report PASS "$1" "$(grep -m1 -o 'forked-exit=[0-9]*' "$work/fork.log")"; fi
            else report FAIL "$1" "$(tail -1 "$work/fork.log" | cut -c1-60)"; fi
        }
        fork_row "a process forked by the command cannot read ~" \
            'eval { val code = scala.sys.process.Process(Seq("/bin/ls", sys.env("HOME"))).!; "forked-exit=" + code }'
        fork_row "a process forked by the command cannot write PROJECT/.git" \
            'eval { val code = scala.sys.process.Process(
                Seq("/usr/bin/touch", "'"$project"'/.git/'"$marker"'")).!; "forked-exit=" + code }'
        run_sbt --jvm-client shutdown >/dev/null 2>&1
        # --jvm-client is required because sbtn returns with nothing built; this row keeps asking whether
        # that changes. A build's success is the measure — sbtn's --version passes and proves nothing.
        if run_sbt "" compile >"$work/sbtn.log" 2>&1 && grep -q '^\[success\]' "$work/sbtn.log"
        then report INFO "sbtn compile" "passes: the --jvm-client requirement can be reconsidered"
        else report INFO "sbtn compile" "no build: $(grep -v '^$' "$work/sbtn.log" | tail -1 | cut -c1-50)"; fi
        run_sbt --jvm-client shutdown >/dev/null 2>&1
    else
        for row in "server runs the granted JDK" \
            "a process forked by the command cannot read ~" \
            "a process forked by the command cannot write PROJECT/.git" "sbtn compile"; do
            report SKIP "$row" "sbt wrapper setup failed; see $work/compile.log and $work/test.log"
        done
    fi
fi

if want mill; then
    use_profile mill
    # Each wrapper row starts a daemon in the command's session — the stock bootstrap under the
    # daemon profile, ten seconds of denied connect retry — runs the client against its port, and
    # ends it with the session; out/mill-daemon is Mill's, neither cleared nor read for authority
    # (RunOnHostSandbox.BrokerRuntimes, RunOnHostMillDaemons), beyond the classpath memo a start deletes
    # when it names paths the profile denies (RunOnHostMillDaemons.discardForeignMemo).
    for command in __.compile __.test; do
        [ "$command" = __.test ] && [ "$quick" = 1 ] && { report SKIP "./mill $command" "quick mode"; continue; }
        if wrapper mill "$mill_project" "$command" >"$work/mill.log" 2>&1
        then report PASS "./mill $command (wrapper)" \
            "$(grep -m1 -i 'mill\|compiling\|passed' "$work/mill.log" | cut -c1-40)"
        else report FAIL "./mill $command (wrapper)" \
            "$(grep -v 'Picked up' "$work/mill.log" | tail -1 | cut -c1-70)"; fi
    done
    if [ -z "$(mill_daemons)" ]
    then report PASS "no mill daemon survives its command"
    else report FAIL "no mill daemon survives its command" "$(mill_daemons | tr '\n' ' ')"; fi
fi

if want gradle; then
    use_profile gradle
    # Each wrapper row's client starts a daemon in the registry under the command's session,
    # resolving through the proxy into the run-on-host cache's Gradle user home; the wrapper
    # records the daemon after the command and ends it with the session (RunOnHostGradleDaemons).
    for task in help build; do
        [ "$task" = build ] && [ "$quick" = 1 ] && { report SKIP "gradle build (wrapper)" "quick mode"; continue; }
        if wrapper gradle "$gradle_project" "$task" >"$work/gradle.log" 2>&1
        then report PASS "gradle $task (wrapper)" "$(grep -m1 'BUILD SUCCESSFUL' "$work/gradle.log" | cut -c1-40)"
        else report FAIL "gradle $task (wrapper)" \
            "$(grep -m1 'FAILURE\|^refused\|Exception' "$work/gradle.log" | cut -c1-70)"; fi
    done
    if [ -z "$(gradle_daemons)" ]
    then report PASS "no gradle daemon survives its command"
    else report FAIL "no gradle daemon survives its command" "$(gradle_daemons | tr '\n' ' ')"; fi
fi

if want mvn; then
    use_profile mvn
    # One-shot, no daemon: each row is one Maven JVM under the profile, resolving plugins and the
    # test dependency from Central through the proxy into the run-on-host cache's local repository.
    for goal in --version test; do
        [ "$goal" = test ] && [ "$quick" = 1 ] && { report SKIP "mvn test (wrapper)" "quick mode"; continue; }
        if wrapper mvn "$mvn_project" "$goal" >"$work/mvn.log" 2>&1
        then report PASS "mvn $goal (wrapper)" "$(grep -m1 'BUILD SUCCESS\|^Apache Maven' "$work/mvn.log" | cut -c1-40)"
        else report FAIL "mvn $goal (wrapper)" \
            "$(grep -m1 '^\[ERROR\]\|^refused\|Exception' "$work/mvn.log" | cut -c1-70)"; fi
    done
fi

# --- negative rows, under every selected profile -----------------------------------------------

# The unrelated service the network rows connect to, bound before the rows to a port of the
# kernel's choosing on the loopback address.
cat > "$work/unrelated.py" <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0)); s.listen(5)
print("port %d" % s.getsockname()[1], flush=True)
while True:
    c, _ = s.accept()
    c.close()
PY
python3 "$work/unrelated.py" >"$work/unrelated.log" 2>&1 & unrelated_listener=$!
tries=0
while ! grep -q port "$work/unrelated.log" && [ "$tries" -lt 50 ]; do tries=$((tries + 1)); sleep 0.1; done
unrelated_port=$(sed -n 's/^port //p' "$work/unrelated.log")

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
    expect_denied "$p" "read another project's run-on-host cache" "ls '$cache_root/cache'"
    expect_denied "$p" "read the user's Coursier v1" "ls '$user_v1/'"
    expect_denied "$p" "read the user's other Coursier arc entries" "ls '$user_arc'"
    # The profile's ancestor chain is file-read-metadata: a listing would reveal sibling names.
    expect_denied "$p" "list an ancestor of a granted path" "ls '$HOME/Library/Caches'"
    expect_denied "$p" "read PROJECT/.git" "cat '$project/.git/HEAD'"   # the launcher repository's
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
    present_or_skip "write ~/.ivy2" "$HOME/.ivy2" \
        && expect_denied "$p" "write ~/.ivy2" ": > '$HOME/.ivy2/$marker'"
    present_or_skip "write ~/.gradle" "$HOME/.gradle" \
        && expect_denied "$p" "write ~/.gradle" ": > '$HOME/.gradle/$marker'"
    present_or_skip "write ~/.m2/repository" "$HOME/.m2/repository" \
        && expect_denied "$p" "write ~/.m2/repository" ": > '$HOME/.m2/repository/$marker'"
    expect_denied "$p" "write the Coursier-installed sbt script" ": >> '$sbt_executable'"
    expect_denied "$p" "write PROJECT/.git/config" ": >> '$project/.git/config'"
    expect_denied "$p" "create under PROJECT/.git" ": > '$project/.git/$marker'"
    expect_denied "$p" "write PROJECT/sub/nested/.git/hooks/x" ": > '$scratch/sub/nested/.git/hooks/x'"
    expect_denied "$p" "write existing .git/config through .GIT" ": >> '$scratch/sub/nested/.GIT/config'"
    expect_denied "$p" "create PROJECT/.git during the command" "mkdir '$scratch/.git'"
    # A spelling the volume folds to a guarded name, created where no entry exists for the access
    # to resolve to: host git and the launcher would open it as the name (seatbelt-semantics.sh
    # E9-E12). U+212A KELVIN SIGN and U+017F LONG S fold to k and s; .git has no such letter.
    mkdir "$scratch/fresh"
    for spelling in .GIT .KO-AGENT-SANDBOX "$(printf '.\342\204\252o-agent-sandbox')" \
        "$(printf '.ko-agent-\305\277andbox')"; do
        if [ "$folding" = 1 ]
        then expect_denied "$p" "create PROJECT/$spelling where no such entry exists" "mkdir '$scratch/fresh/$spelling'"
        else report SKIP "create PROJECT/$spelling where no such entry exists" "the project volume folds no case"; fi
    done
    expect_denied "$p" "link PROJECT/x -> PROJECT/.git/config" "ln '$scratch/sub/nested/.git/config' '$scratch/x'"
    expect_denied "$p" "write via PROJECT/link -> PROJECT/.git" ": >> '$scratch/link/config'"
    expect_denied "$p" "write PROJECT/.ko-agent-sandbox/..." ": >> '$scratch/.ko-agent-sandbox/egress/rule'"
    expect_denied "$p" "write the user's Coursier v1" ": > '$user_v1/$marker'"
    present_or_skip "write the user's mill download folder" "$mill_downloads" \
        && expect_denied "$p" "write the user's mill download folder" ": > '$mill_downloads/$marker'"
    if [ "$p" = mvn ]; then
        # The one provisioned distribution runs; its neighbours under wrapper/dists are unreadable.
        if ( cd "$mvn_project" && sandboxed mvn "$mvn_home/bin/mvn" --batch-mode --version ) \
            >/dev/null 2>"$work/row.err"
        then report PASS "read and execute the Maven distribution"
        else report FAIL "read and execute the Maven distribution" "$(first_error)"; fi
        expect_denied mvn "list the wrapper's dists folder" "ls '${mvn_home%/*/*}'"
        expect_denied mvn "write the Maven distribution" ": >> '$mvn_home/bin/mvn'"
    fi
    if [ "$p" = gradle ]; then
        # The one provisioned distribution runs; its neighbours under wrapper/dists are unreadable.
        if ( cd "$gradle_project" && sandboxed gradle "$gradle_home/bin/gradle" --version ) \
            >/dev/null 2>"$work/row.err"
        then report PASS "read and execute the Gradle distribution"
        else report FAIL "read and execute the Gradle distribution" "$(first_error)"; fi
        expect_denied gradle "list the wrapper's dists folder" "ls '${gradle_home%/*/*}'"
        expect_denied gradle "write the Gradle distribution" ": >> '$gradle_home/bin/gradle'"
    fi
    if [ "$p" = mill ]; then
        # The one provisioned file, the JVM launcher, is executable; its neighbours in the download
        # folder are not. Run directly and without the daemon: this row is the grant, not the runtime.
        if ( cd "$mill_project" && sandboxed mill "$mill_executable" --no-daemon --version ) \
            >/dev/null 2>"$work/row.err"
        then report PASS "read and execute the mill launcher"
        else report FAIL "read and execute the mill launcher" "$(first_error)"; fi
        expect_denied mill "list the mill download folder" "ls '$mill_downloads'"
    fi

    echo
    echo "Mach services, under the $p profile"
    calculator_before=$(pgrep -x Calculator)
    expect_denied "$p" "start an application through open" "/usr/bin/open -g -a Calculator"
    [ -n "$calculator_before" ] || pkill -x Calculator
    # The proxy's JVM dies of a segmentation fault without the service SeatbeltProfile.MachServices
    # names; a command's JVM asking the system's resolver must not. Whether the name resolves is
    # not this row's question.
    cat > "$SESSION_TMP/Resolve.java" <<'EOF'
class Resolve {
    public static void main(String[] arguments) {
        try { System.out.println(java.net.InetAddress.getByName("localhost")); }
        catch (java.net.UnknownHostException ex) { System.out.println(ex); }
    }
}
EOF
    # From the profile's own project: a JVM asks for its working directory at start, and the
    # gate's is the sbt profile's project alone.
    expect_allowed "$p" "a JVM resolving a name survives it" \
        "cd '$(project_of "$p")' && '$JAVA_HOME/bin/java' '$SESSION_TMP/Resolve.java'"

    echo
    echo "allowed writes, under the $p profile"
    expect_allowed "$p" "write run-on-host cache coursier/v1/..." ": > '$cache_v1/$marker'"
    expect_allowed "$p" "write PROJECT/..." ": > '$scratch/ok'"
    expect_allowed "$p" "write command's temporary directory" ": > '$SESSION_TMP/$marker'"
    [ "$p" = gradle ] && expect_allowed gradle "write the Gradle user home" ": > '$gradle_user_home/$marker'"
    # The guard is scoped to the project: a build's tests may make throwaway repositories in the
    # command's temporary directory, and this project's own do.
    expect_allowed "$p" "create .git in the command's temporary directory" \
        "mkdir -p '$SESSION_TMP/fixture/.git' && : > '$SESSION_TMP/fixture/.git/config'"

    echo
    echo "network, under the $p profile"
    # /bin/bash's /dev/tcp is a connect(2) with no program to grant; an IP literal keeps DNS out.
    if /usr/bin/sandbox-exec -f "$work/gate-$p.sb" /bin/bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>"$work/row.err"
    then report FAIL "connect directly to arbitrary Internet host" "connected"
    else report PASS "connect directly to arbitrary Internet host" "denied: $(head -1 "$work/row.err" | cut -c1-50)"; fi
    # `sb` exports no proxy variables, so curl here is the command that ignores them; either the
    # resolution or the connect must die on the profile, never on a slow timeout.
    expect_denied "$p" "HTTPS around the proxy (curl, direct)" \
        "/usr/bin/curl --max-time 5 -sS https://repo1.maven.org/maven2/"
    expect_denied "$p" "DNS resolution (direct socket)" "/usr/bin/nslookup -timeout=3 example.com"
    # An unrelated service of this host: what a Gradle process may reach — its daemon, workers
    # and file-lock socket connect to each other's ports of the kernel's choosing — and no other
    # program's process may (SECURITY.md "Run on host", the table). The listener is the gate's.
    unrelated_row="connect to an unrelated service of this host"
    if [ -z "$unrelated_port" ]; then report SKIP "$unrelated_row" "the gate's listener did not bind"
    elif [ "$p" = gradle ]
    then expect_allowed "$p" "$unrelated_row" "/bin/bash -c 'exec 3<>/dev/tcp/127.0.0.1/$unrelated_port'"
    else expect_denied "$p" "$unrelated_row" "/bin/bash -c 'exec 3<>/dev/tcp/127.0.0.1/$unrelated_port'"; fi
done
# --- the command's proxy ----------------------------------------------------------------------------

echo
echo "the command's proxy"
if ! want sbt; then
    report SKIP "fetch allowed Maven artifact via proxy" "sbt rows not selected"
    report SKIP "fetch unlisted host via proxy" "sbt rows not selected"
else
    use_profile sbt
    # Made cold on purpose: with the artifact gone from the run-on-host cache, a successful compile can
    # only have fetched it — and the direct-connect row already showed the profile's only route is
    # the proxy.
    rm -rf "$cache_v1/https/repo1.maven.org/maven2/org/scalameta"
    if wrapper sbt "$project" Test/compile >"$work/refetch.log" 2>&1
    then report PASS "fetch allowed Maven artifact via proxy" "munit re-fetched, Test/compile ok"
    else report FAIL "fetch allowed Maven artifact via proxy" \
        "$(grep -m1 '^\[error\]\|^refused\|Exception' "$work/refetch.log" | cut -c1-70)"; fi

    # deny-fixture's resolution reaches a refused host; the command must fail and the wrapper must
    # say which host — the wrapper's denied-host report.
    if wrapper sbt "$deny_project" update >"$work/deny.log" 2>&1
    then report FAIL "fetch unlisted host via proxy" "the command succeeded"
    elif grep -q 'Command requested network access' "$work/deny.log" \
        && grep -q 'denied.example.com' "$work/deny.log"
    then report PASS "fetch unlisted host via proxy" "refused; wrapper named denied.example.com"
    else report FAIL "fetch unlisted host via proxy" \
        "failed without the wrapper's diagnostic: $(tail -1 "$work/deny.log" | cut -c1-50)"; fi
fi

# --- the proxy's own profile ----------------------------------------------------------------------
#
# The wrapper rows above ran every fetch through a proxy under this profile, so they prove the
# confined proxy works, the resolver rule included. These rows prove the profile denies, with the
# granted java as the probe, since the profile execs nothing else. A JVM reading `@dir` reports
# "Failed to read" on a directory it may open and "could not open" on one it may not, so the
# control's word separates the denial from the directory; `-Xlog` to a file is a write, whose
# control creates the file and whose denial the JVM reports as the open it could not make.
echo
echo "the proxy's own profile"
# From /, as the wrapper runs its proxy: the JVM asks for its working directory at start. Both
# streams, since the JVM reports a log file it cannot open on stdout.
proxy_java() {
    (cd / && /usr/bin/sandbox-exec -f "$work/gate-proxy.sb" "$JAVA_HOME/bin/java" "$@") >"$work/row.err" 2>&1
}
if proxy_java -version
then report PASS "the proxy's java starts under its profile"
else report FAIL "the proxy's java starts under its profile" "$(first_error)"; fi
if "$JAVA_HOME/bin/java" @"$HOME" -version >/dev/null 2>"$work/row.err" \
    || ! grep -q 'Failed to read' "$work/row.err"
then report FAIL "the proxy cannot read ~" "control: $(first_error)"
elif proxy_java @"$HOME" -version
then report FAIL "the proxy cannot read ~" "allowed"
elif grep -q 'could not open' "$work/row.err"
then report PASS "the proxy cannot read ~" "denied: $(first_error)"
else report FAIL "the proxy cannot read ~" "$(first_error)"; fi
write_probe=$work/gate-proxy-write.log
if ! "$JAVA_HOME/bin/java" -Xlog:gc:file="$write_probe" -version >/dev/null 2>"$work/row.err" \
    || [ ! -e "$write_probe" ]
then report FAIL "the proxy cannot write a file" "control: $(first_error)"
elif rm -f "$write_probe" && proxy_java -Xlog:gc:file="$write_probe" -version || [ -e "$write_probe" ]
then report FAIL "the proxy cannot write a file" "allowed"
elif grep -q 'Error opening log file' "$work/row.err"
then report PASS "the proxy cannot write a file" "denied: $(first_error)"
else report FAIL "the proxy cannot write a file" "$(first_error)"; fi

# --- the command lifecycle ----------------------------------------------------------------------

echo
echo "the command lifecycle"
# Command sessions alone: the broker's own session (b<random>), the build locks and the retirement
# locks are not commands.
commands_now() {
    ls "$command_root" 2>/dev/null \
        | grep -cv -e '^staging$' -e '^condemned$' -e '^root-lock$' -e '^build-lock$' -e '^retire-lock$' \
            -e '^b[0-9]'
}
lifecycle_rows="two concurrent commands
SIGTERM: the wrapper cleans up behind itself
SIGKILL mid-command: the running group is ended provably
SIGKILL: next start condemns and collects
leaderless server ended by portfile attribution"
# A here-doc, not a pipe: report counts, and a pipeline would count in a subshell.
skip_lifecycle() {
    while IFS= read -r row; do report SKIP "$row" "$1"; done <<EOF
$lifecycle_rows
EOF
}
# The victim's own client record, bound to it directly: the recorded spawn is started by the
# wrapper, so its parent pid is the victim's, and the recorded start time must match the live
# process — the same pid-plus-start proof the wrapper's own scavenger uses, so a stale record
# whose pid was reused by another child of the victim never passes. Empty when the wrapper ends
# first.
await_client_record() { # victim-pid
    tries=0
    while [ "$tries" -lt 600 ]; do
        for record in "$command_root"/*/records/client; do
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
# the subshell running this function, java is its child, and every staged kill — and the spawn's
# parent-pid check above — would signal or look at the wrong process.
victim_wrapper() { # log-name
    lock=$(build_lock sbt "$project") || exit 2
    exec /usr/bin/perl -e "$lock_script" "$lock" 0 "$JAVA_HOME/bin/java" -cp "$test_cp" \
        agentsandbox.launcher.RunOnHost \
        sbt "$project" src/main/resources/agentsandbox/runtime-authority.txt -- compile >"$work/$1" 2>&1
}
if [ "$quick" = 1 ]; then
    skip_lifecycle "quick mode"
elif [ "$program" != all ]; then
    skip_lifecycle "needs both programs"
else
    # Concurrency: one sbt and one mill command overlap, each with its own directory and proxy.
    wrapper sbt "$project" compile >"$work/conc-sbt.log" 2>&1 & conc_sbt=$!
    wrapper mill "$mill_project" __.compile >"$work/conc-mill.log" 2>&1 & conc_mill=$!
    peak=0; tries=0
    while [ "$tries" -lt 600 ]; do
        now=$(commands_now); [ "$now" -gt "$peak" ] && peak=$now
        kill -0 "$conc_sbt" 2>/dev/null || kill -0 "$conc_mill" 2>/dev/null || break
        tries=$((tries + 1)); sleep 0.5
    done
    wait "$conc_sbt"; conc_a=$?
    wait "$conc_mill"; conc_b=$?
    if [ "$conc_a" -eq 0 ] && [ "$conc_b" -eq 0 ]
    then report PASS "two concurrent commands" "both built; peak concurrent command directories: $peak"
    else report FAIL "two concurrent commands" "sbt exit $conc_a, mill exit $conc_b"; fi

    # SIGTERM mid-command: the wrapper's shutdown hook — a JVM's `finally` never runs on a signal —
    # ends the groups and removes the command's directory before the JVM exits (RunOnHostSession).
    victim_wrapper sigterm.log & victim=$!
    client_record=$(await_client_record "$victim")
    if [ -z "$client_record" ]; then
        report FAIL "SIGTERM: the wrapper cleans up behind itself" \
            "no client record appeared: $(tail -1 "$work/sigterm.log" | cut -c1-50)"
    else
        kill -TERM "$victim" 2>/dev/null; wait "$victim" 2>/dev/null
        sleep 1
        # The victim's own directory, not a root-wide count: a concurrent legitimate command
        # is not this row's to judge.
        victim_session=${client_record%/records/client}
        if [ ! -d "$victim_session" ] && [ ! -d "$command_root/condemned/${victim_session##*/}" ] \
            && [ -z "$(project_servers)" ] && [ -z "$(stray_proxies)" ]
        then report PASS "SIGTERM: the wrapper cleans up behind itself"
        else report FAIL "SIGTERM: the wrapper cleans up behind itself" \
            "left: $(ls -d "$victim_session" 2>/dev/null) \
$(project_servers | tr '\n' ' ')$(stray_proxies | tr '\n' ' ')"
        fi
    fi

    # SIGKILL mid-command: the spawn, the leader, survives the wrapper, so the next start ends the whole
    # running group provably instead of refusing a leaderless one.
    victim_wrapper killed-mid.log & victim=$!
    client_record=$(await_client_record "$victim")
    if [ -z "$client_record" ]; then
        report FAIL "SIGKILL mid-command: the running group is ended provably" \
            "no client record appeared: $(tail -1 "$work/killed-mid.log" | cut -c1-50)"
    else
        kill -9 "$victim" 2>/dev/null; wait "$victim" 2>/dev/null
        wrapper sbt "$project" --version >"$work/recover-mid.log" 2>&1
        if grep -q 'GroupEnded' "$work/recover-mid.log"
        then report PASS "SIGKILL mid-command: the running group is ended provably" \
            "$(grep -m1 'scavenged' "$work/recover-mid.log" | cut -c1-70)"
        else report FAIL "SIGKILL mid-command: the running group is ended provably" \
            "$(tail -1 "$work/recover-mid.log" | cut -c1-70)"; fi
    fi

    # The leaderless server needs the spawns gone too: SIGKILL the wrapper mid-command, let the
    # client finish its command cleanly — the spawn publishes its exit beside the record — then
    # SIGKILL the client's spawn and the server's spawn alone: the server, its group's leader
    # gone, survives with the portfile. Proxy recorded and ended, client and server groups
    # leaderless and skipped, server ended by attribution (RunOnHostSession.collectServers).
    # Killing any of the client's processes instead stages the wrong state: a server whose
    # client dies mid-exec cancels the exec, and the wrapper's teardown would end the server's
    # group behind its live leader.
    victim_wrapper killed.log & victim=$!
    client_record=$(await_client_record "$victim")
    if [ -z "$client_record" ]; then
        report FAIL "SIGKILL: next start condemns and collects" \
            "no client record appeared: $(tail -1 "$work/killed.log" | cut -c1-50)"
        report SKIP "leaderless server ended by portfile attribution" "no orphan was staged"
    else
        client_pgid=$(awk '{print $1}' "$client_record")
        server_record=$(ls "${client_record%/records/client}"/records/server-sbt-* 2>/dev/null | head -1)
        kill -9 "$victim" 2>/dev/null; wait "$victim" 2>/dev/null
        tries=0
        while [ ! -f "$client_record.exit" ] && [ "$tries" -lt 600 ]; do
            tries=$((tries + 1)); sleep 0.5
        done
        if [ ! -f "$client_record.exit" ]; then
            report FAIL "SIGKILL: next start condemns and collects" "the client never finished"
            report SKIP "leaderless server ended by portfile attribution" "no orphan was staged"
            pkill -9 -g "$client_pgid" 2>/dev/null
        else
            # The spawns alone: the command is done, the server stays.
            kill -9 "$client_pgid" 2>/dev/null
            [ -n "$server_record" ] && kill -9 "$(awk '{print $1}' "$server_record")" 2>/dev/null
            sleep 1
            staged=$(project_servers | tr '\n' ' ')
            # The recovery run's own command is beside the point (and --version is the cheap one);
            # its stderr reports cleanup of the victim's command directory.
            wrapper sbt "$project" --version >"$work/recover.log" 2>&1
            if grep -q 'scavenged' "$work/recover.log"
            then report PASS "SIGKILL: next start condemns and collects" \
                "$(grep -m1 'scavenged' "$work/recover.log" | cut -c1-70)"
            else report FAIL "SIGKILL: next start condemns and collects" \
                "$(tail -1 "$work/recover.log" | cut -c1-70)"; fi
            if [ -n "$staged" ] && grep -q 'ServerShutDown' "$work/recover.log" && [ -z "$(project_servers)" ]
            then report PASS "leaderless server ended by portfile attribution" \
                "$(grep -m1 -o 'ServerShutDown([^)]*)' "$work/recover.log" | cut -c1-70)"
            else report FAIL "leaderless server ended by portfile attribution" \
                "staged: ${staged:-none}; $(grep -m1 'scavenged' "$work/recover.log" | cut -c1-70)"; fi
        fi
    fi
fi

# --- the channel ---------------------------------------------------------------------------
#
# The real shim against the real broker, the `podman exec` transport a local script and the
# sandbox this host. The wrapper behind it is the same one the rows above measured; what these
# add is the channel — framing, streamed output and the command's own exit code, the
# working-directory boundary, and teardown by descriptor lifetime — and the broker's runtime: the
# proxy and the sbt server or mill daemon the commands of one build directory share, and what
# retires them (doc/run-on-host.md, "sbt" and "mill").

echo
echo "the channel"
channel_dir=/tmp/ko-agent-sandbox/run-on-host
channel_rows="channel: sbt test returns the command's own exit code
channel: the broker's sbt server serves the commands of one build directory
channel: the broker's proxy serves the commands of one build directory
channel: the starting request's -D reaches the build
channel: a cancelled command's warm server survives, and the next command reuses it
channel: the denied-host report is per command
channel: a second build directory stays warm beside the first, each reused
channel: an edited sbt.version takes effect after shutdown
channel: a second launch attaches to the first's sbt server, recording nothing
channel: a second launch forwarding a variable the first did not is refused, the server kept
channel: a working directory outside the project is refused
channel: a dead shim ends the running command
channel: a dead sandbox ends the channel, its command and the broker's runtimes
channel: TERM to the broker ends its command before the broker exits
channel: a killed broker's command ends with it, and its server with the next start
channel: a planted portfile nominates nothing: refused, no shutdown spoken
channel: the broker's end takes the gradle daemon, and the JVM its build forked"
mill_channel_rows="channel: a second launch attaches to the first's mill daemon
channel: mill compile starts the broker's daemon, and the next command reuses it
channel: a mill build's forked JVM writes temporary files where the daemon's profile allows
channel: a redirected out/mill-daemon is refused before Mill's launcher acts on it
channel: a planted socketPort reaches no daemon: the client is denied, the daemon untouched
channel: after a cancelled mill command, the next command runs
channel: a mill option-file edit replaces the daemon, and the next command runs under it
channel: a mill daemon of yours, mismatched, is ended by proof before the broker's starts
channel: a mill daemon of yours, matching, is ended by proof before the broker's starts
channel: a mill daemon of yours mid-command is left until its client disconnects
channel: a mill daemon of yours busy past the bound is refused, and left alive
channel: a new launch adopts nothing planted in out/mill-daemon"
gradle_channel_rows="channel: gradle build starts a daemon in the launch's registry, and the next command reuses it
channel: the daemon maps Gradle's native libraries from the user home's read-write grant
channel: a toolchain the project asks for, not the launch's JDK, fails by name
channel: a gradle daemon of yours, in a registry of your own, is neither attached to nor ended
channel: after a cancelled gradle command, the next command runs, the records following the daemons"
skip_channel() {
    while IFS= read -r row; do report SKIP "$row" "$1"; done <<EOF
$channel_rows
$mill_channel_rows
$gradle_channel_rows
EOF
}
skip_mill_channel() {
    while IFS= read -r row; do report SKIP "$row" "$1"; done <<EOF
$mill_channel_rows
EOF
}
skip_gradle_channel() {
    while IFS= read -r row; do report SKIP "$row" "$1"; done <<EOF
$gradle_channel_rows
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
        ps -o command= -p "$pid" 2>/dev/null | grep -qF -e "$channel_dir" -e "${channel_dir2:-$channel_dir}" \
            || continue
        kill_owned_children "$pid"
        [ "$(ps -o lstart= -p "$pid" 2>/dev/null)" = "$start" ] && kill -9 "$pid" 2>/dev/null
    done < "$work/exec.pids"
}
# `exec` for the same reason as victim_wrapper: the staged kills must be delivered to the shim itself.
channel_shim() { # log cwd args...
    chan_log=$1; chan_cwd=$2; shift 2
    cd "$chan_cwd" || exit 1
    PATH="$work/bin:$PATH" exec "$project/container/ko-agent-sandbox/sandbox-run-on-host" "$@" \
        >"$work/$chan_log" 2>"$work/$chan_log.err"
}
channel_settled() { # await the broker between rows: no command directory, command server or command proxy
    tries=0
    while { [ "$(commands_now)" -gt 0 ] || [ -n "$(command_servers)" ] || [ -n "$(command_proxies)" ]; } \
        && [ "$tries" -lt 240 ]; do tries=$((tries + 1)); sleep 0.5; done
}
# The server processes behind a broker record, as project_servers finds them: the members of the
# record's group — a supervisor and the JVM it starts, so more than one line is normal.
server_in_group() { # record-line
    [ -n "$1" ] || return 0
    for pid in $(project_servers) $(deny_servers) $(ivy_servers); do
        [ "$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ')" = "${1%% *}" ] && printf '%s\n' "$pid"
    done
}
if [ "$quick" = 1 ]; then
    skip_channel "quick mode"
elif [ "$program" = mvn ]; then
    skip_channel "needs sbt, mill or gradle"
else
    # macOS has neither flock(1) nor timeout(1): the shim's serialization is stubbed out — the
    # rows are serial — and its exit-read bound runs unbounded, which only a broker dying
    # mid-command would notice.
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
    start_channel_broker() { # false when it made no FIFO
        echo true > "$work/running"
        rm -rf "$channel_dir"
        "$JAVA_HOME/bin/java" -cp "$test_cp" agentsandbox.launcher.AgentSandboxLauncher \
            --serve-run-on-host "$work/podman" C "$project" sbt,mill,gradle "$work/channel.log" "$project" \
            >/dev/null 2>&1 & channel_broker=$!
        tries=0
        while [ ! -p "$channel_dir/req" ] && [ "$tries" -lt 100 ]; do tries=$((tries + 1)); sleep 0.2; done
        [ -p "$channel_dir/req" ]
    }
    if ! start_channel_broker; then
        skip_channel "the broker made no FIFOs: $(tail -1 "$work/channel.log" 2>/dev/null | cut -c1-50)"
    else
        # The exit criterion's row: an agent-invoked `sbt test`, its exit code the command's own.
        with_timeout 1800 channel_shim chan-test.log "$project" sbt test; status=$?
        if [ "$status" -eq 0 ] && grep -q '^\[success\]' "$work/chan-test.log"
        then report PASS "channel: sbt test returns the command's own exit code" \
            "$(grep -m1 '^\[success\]' "$work/chan-test.log")"
        else report FAIL "channel: sbt test returns the command's own exit code" \
            "exit $status: $(tail -1 "$work/chan-test.log.err" | cut -c1-60)"; fi
        channel_settled

        # The broker holds one server and one proxy record for the build directory, each unchanged
        # after the next command of the same directory, and no runtime of either kind in a
        # command's own session.
        root_server=$(broker_server_record "$project")
        root_record=$(broker_proxy_record "$project")
        with_timeout 300 channel_shim chan-reuse.log "$project" sbt about
        channel_settled
        # The server record's group is still alive (server_in_group) and no sbt server runs outside
        # a broker's recorded group — a second server would be a group of its own, which
        # command_servers would name.
        if [ -n "$root_server" ] && record_alive "$root_server" \
            && [ "$(broker_server_record "$project")" = "$root_server" ] \
            && [ -n "$(server_in_group "$root_server")" ] && [ -z "$(command_servers)" ] \
            && grep -q 'This is sbt' "$work/chan-reuse.log"
        then report PASS "channel: the broker's sbt server serves the commands of one build directory" \
            "record $root_server, group $(server_in_group "$root_server" | tr '\n' ' ')"
        else report FAIL "channel: the broker's sbt server serves the commands of one build directory" \
            "record before: ${root_server:-none}, after: $(broker_server_record "$project"), \
group: $(server_in_group "$root_server" | tr '\n' ' '), command servers: $(command_servers | tr '\n' ' ')"; fi
        if [ -n "$root_record" ] && record_alive "$root_record" \
            && [ "$(broker_proxy_record "$project")" = "$root_record" ] && [ -z "$(command_proxies)" ]
        then report PASS "channel: the broker's proxy serves the commands of one build directory" \
            "record $root_record"
        else report FAIL "channel: the broker's proxy serves the commands of one build directory" \
            "record before: $root_record, after: $(broker_proxy_record "$project"), \
command proxies: $(command_proxies | tr '\n' ' ')"; fi

        # The request that starts a server gives it its -D (RunOnHostSandbox.serverCommand).
        # `shutdown` ends the server the test row started, and the next request starts one.
        probe='eval sys.props.getOrElse("gate.probe", "unset")'
        with_timeout 300 channel_shim chan-shutdown.log "$project" sbt shutdown
        channel_settled
        with_timeout 600 channel_shim chan-probe.log "$project" sbt -Dgate.probe=probe-set "$probe"
        channel_settled
        if grep -q 'probe-set' "$work/chan-probe.log"
        then report PASS "channel: the starting request's -D reaches the build"
        else report FAIL "channel: the starting request's -D reaches the build" \
            "$(grep -m1 'probe-\|unset' "$work/chan-probe.log" | cut -c1-40)"; fi

        # A client disconnect mid-task follows stock sbt: it detaches the channel (removeChannel,
        # force = false) without stopping the running task, which runs to completion on the warm
        # server — as in a terminal. The broker does not retire the server, so the same server,
        # its record unchanged, serves the next command once the task finishes. The task runs on
        # the task engine — not `eval`, which runs on the command thread — and writes a marker so
        # the disconnect lands while it is still running. The sleep is short, so the next command
        # waits it out rather than the gate.
        #
        # The wrapper hands sbt all of its arguments as one command, so the `set` and the task
        # invocation ride one string joined by `;`; the task body is a single expression — the
        # marker written inside the sleep's argument — so no inner `;` or newline meets sbt's
        # command splitter. Def.uncached makes the marker and sleep run on every invocation:
        # sbt 2 otherwise reuses the Unit result without running either side effect.
        cancel_marker=$project/target/gate-cancel-started
        rm -f "$cancel_marker"
        gate_task='set TaskKey[Unit]("koGateSleep") := Def.uncached(java.lang.Thread.sleep('
        gate_task="${gate_task}if (java.nio.file.Files.writeString("
        gate_task="${gate_task}java.nio.file.Paths.get(\"$cancel_marker\"), \"started\")"
        gate_task="${gate_task}.toString.nonEmpty) 20000L else 20000L))"
        channel_shim chan-cancel.log "$project" sbt "$gate_task; koGateSleep" & shim=$!
        if ! gate_wait_started "$shim" 1200 test -f "$cancel_marker"; then
            report FAIL "channel: a cancelled command's warm server survives, and the next command reuses it" \
                "no running task to cancel; see $work/chan-cancel.log{,.err}"
            kill -9 "$shim" 2>/dev/null; wait "$shim" 2>/dev/null
        else
        # The marker proves the task runs on a server: record it now, whether the task reused a
        # warm one or started its own, and compare the same group after the cancel.
        old_record=$(broker_server_record "$project")
        old_server=$(server_in_group "$old_record")
        kill -9 "$shim" 2>/dev/null; wait "$shim" 2>/dev/null
        channel_settled
        with_timeout 600 channel_shim chan-after-cancel.log "$project" sbt about
        channel_settled
        new_server=$(server_in_group "$(broker_server_record "$project")")
        if [ -n "$old_server" ] && [ "$new_server" = "$old_server" ] \
            && [ "$(broker_server_record "$project")" = "$old_record" ] \
            && grep -q 'This is sbt' "$work/chan-after-cancel.log"
        then report PASS "channel: a cancelled command's warm server survives, and the next command reuses it" \
            "server $old_server kept across the cancel"
        else report FAIL "channel: a cancelled command's warm server survives, and the next command reuses it" \
            "old server ${old_server:-none}, after cancel: ${new_server:-none} \
(record before $old_record, after $(broker_server_record "$project"))"; fi
        fi
        rm -f "$cancel_marker"

        # The report reads only what the command added to the shared proxy log (the reportFrom
        # offset), never the whole log. This fixture's build cannot load without its refused
        # resolver, so every command — update and about alike — re-requests it and reports its
        # own denial: the second command's report holds only its own request, not the first's
        # carried over, so its count never exceeds the first's. Its own variable: with_timeout's
        # `status` is overwritten by the second command's.
        with_timeout 600 channel_shim chan-deny1.log "$deny_project" sbt update; deny_status=$?
        channel_settled
        with_timeout 300 channel_shim chan-deny2.log "$deny_project" sbt about
        channel_settled
        deny1_count=$(grep -c 'Command requested network access' "$work/chan-deny1.log.err")
        deny2_count=$(grep -c 'Command requested network access' "$work/chan-deny2.log.err")
        if [ "$deny_status" -ne 0 ] && grep -q 'denied.example.com' "$work/chan-deny1.log.err" \
            && grep -q 'denied.example.com' "$work/chan-deny2.log.err" \
            && [ "$deny2_count" -ge 1 ] && [ "$deny2_count" -le "$deny1_count" ]
        then report PASS "channel: the denied-host report is per command" \
            "each command reports its own denial ($deny1_count, then $deny2_count)"
        else report FAIL "channel: the denied-host report is per command" \
            "update exit $deny_status; reports: deny1=$deny1_count deny2=$deny2_count"; fi

        # Both directories warm: the root has a runtime (root_record, from chan-reuse above), the
        # deny fixture one (deny_record). Visiting each again reuses its own; neither retires the
        # other.
        deny_record=$(broker_proxy_record "$deny_project")
        root_record=$(broker_proxy_record "$project")
        with_timeout 600 channel_shim chan-root.log "$project" sbt about
        channel_settled
        root_same=$([ "$(broker_proxy_record "$project")" = "$root_record" ] && echo yes || echo no)
        deny_after_root=$([ "$(broker_proxy_record "$deny_project")" = "$deny_record" ] \
            && record_alive "$deny_record" && echo yes || echo no)
        with_timeout 600 channel_shim chan-deny3.log "$deny_project" sbt update
        channel_settled
        deny_reused=$([ "$(broker_proxy_record "$deny_project")" = "$deny_record" ] && echo yes || echo no)
        if [ -n "$root_record" ] && [ "$root_same" = yes ] && [ "$deny_after_root" = yes ] \
            && [ "$deny_reused" = yes ] && record_alive "$root_record"
        then report PASS "channel: a second build directory stays warm beside the first, each reused"
        else report FAIL "channel: a second build directory stays warm beside the first, each reused" \
            "root reused: $root_same (alive $(record_alive "$root_record" && echo yes || echo no)), \
deny alive after root: $deny_after_root, deny reused: $deny_reused"; fi

        # After `shutdown` the next command's server is assembled from the build directory afresh:
        # the fixture's pin is edited under a live server, and restored by the cleanup.
        pin_file=$ivy_project/project/build.properties
        pin_saved=$(cat "$pin_file")
        with_timeout 900 channel_shim chan-pin1.log "$ivy_project" sbt about
        channel_settled
        printf 'sbt.version=1.12.13\n' > "$pin_file"
        with_timeout 300 channel_shim chan-pin3.log "$ivy_project" sbt shutdown
        channel_settled
        with_timeout 900 channel_shim chan-pin4.log "$ivy_project" sbt about
        channel_settled
        printf '%s\n' "$pin_saved" > "$pin_file"; pin_saved=""
        before_edit=$(grep -m1 -o 'This is sbt [0-9.]*' "$work/chan-pin1.log")
        after_shutdown=$(grep -m1 -o 'This is sbt [0-9.]*' "$work/chan-pin4.log")
        if [ -n "$before_edit" ] && [ "$before_edit" != "This is sbt 1.12.13" ] \
            && [ "$after_shutdown" = "This is sbt 1.12.13" ]
        then report PASS "channel: an edited sbt.version takes effect after shutdown" \
            "$before_edit, then $after_shutdown"
        else report FAIL "channel: an edited sbt.version takes effect after shutdown" \
            "before: ${before_edit:-none}, after shutdown: ${after_shutdown:-none}"; fi

        # --- two launches on one project (doc/run-on-host.md, "The channel and the command") ------
        #
        # A second broker on the same project: its commands attach to the first broker's server
        # and daemon when they would start one under the same confinement and environment, and
        # otherwise end them by the first's records and start their own
        # (RunOnHostSandbox.BrokerRuntimes.attached, takeOver). The shim and the
        # broker both spell the channel directory as one constant, and the stub podman runs every
        # exec on this host, so a second broker would share the first's FIFOs: its own stub
        # rewrites the constant in each script it execs, and its shim is a copy with the constant
        # rewritten. Its execs go into the same pid file, which the cleanup reads for both
        # directories. The directory is this run's own under /tmp, its name safe for the
        # rewrites and the shim's unquoted uses, where the checkout's path may carry a space or a
        # sed delimiter; the cleanup removes it.
        channel_dir2=$(mktemp -d /tmp/ko-agent-gate-channel.XXXXXX) || exit 1
        sed "s|^dir=/tmp/ko-agent-sandbox/run-on-host\$|dir=$channel_dir2|" \
            "$project/container/ko-agent-sandbox/sandbox-run-on-host" > "$work/shim2"
        chmod +x "$work/shim2"
        cat > "$work/podman2" <<EOF
#!/bin/sh
case "\$1 \$2" in
    "exec -i")
        echo "\$\$|\$(ps -o lstart= -p \$\$)" >> "$work/exec.pids"
        script=\$(printf '%s' "\$6" | sed 's|/tmp/ko-agent-sandbox/run-on-host|$channel_dir2|g')
        exec sh -c "\$script" ;;
    "container inspect") cat "$work/running2" ;;
esac
EOF
        chmod +x "$work/podman2"
        # A name-only forward's value travels under its carrier name in the broker's own
        # environment (RunOnHostChannel.spawnBroker), which the launcher sets: this gate sets it.
        # The broker sessions under the root — `b` and digits, as commands_now tells them from
        # `build-lock/` — are not the gate's alone: a launch on this project from another
        # terminal, an agent session's included, keeps its own broker session there. So the
        # second broker's session is the one that appears when it starts, and the first's the
        # one whose server record for the project is alive.
        broker_sessions() { ls "$command_root" 2>/dev/null | grep '^b[0-9]' | sed "s|^|$command_root/|"; }
        session_record() { # session record-name
            cat "$1/records/$2" 2>/dev/null
        }
        sbt_record=server-sbt-$(build_hash "$project")
        mill_record=daemon-mill-$(build_hash "$mill_project")
        start_second_broker() { # [--env=NAME]: false when it made no FIFO and published no session
            echo true > "$work/running2"
            rm -rf "$channel_dir2"
            broker_sessions > "$work/sessions-before"
            KO_AGENT_RUN_ON_HOST_ENV_GATE_SHARE=1 "$JAVA_HOME/bin/java" -cp "$test_cp" \
                agentsandbox.launcher.AgentSandboxLauncher --serve-run-on-host "$work/podman2" C2 "$project" \
                sbt,mill,gradle "$work/channel2.log" "$@" "$project" >/dev/null 2>&1 & second_broker=$!
            tries=0
            second_session_dir=""
            while { [ ! -p "$channel_dir2/req" ] || [ -z "$second_session_dir" ]; } && [ "$tries" -lt 100 ]; do
                tries=$((tries + 1)); sleep 0.2
                second_session_dir=$(broker_sessions | grep -vxFf "$work/sessions-before" | head -1)
            done
            [ -p "$channel_dir2/req" ] && [ -n "$second_session_dir" ]
        }
        stop_second_broker() {
            [ -n "${second_broker:-}" ] || return 0
            kill -TERM "$second_broker" 2>/dev/null
            tries=0
            while kill -0 "$second_broker" 2>/dev/null && [ "$tries" -lt 120 ]; do tries=$((tries + 1)); sleep 0.5; done
            kill -9 "$second_broker" 2>/dev/null
            second_broker=""
            rm -rf "$channel_dir2"
        }
        second_shim() { # log cwd args...
            chan_log=$1; chan_cwd=$2; shift 2
            cd "$chan_cwd" || exit 1
            PATH="$work/bin:$PATH" exec "$work/shim2" "$@" >"$work/$chan_log" 2>"$work/$chan_log.err"
        }
        first_session=""
        for candidate in $(broker_sessions); do
            record_alive "$(session_record "$candidate" "$sbt_record")" && first_session=$candidate
        done
        second_session() { printf '%s\n' "$second_session_dir"; }
        root_now() { ls "$command_root" 2>/dev/null | tr '\n' ' '; }
        share_row="channel: a second launch attaches to the first's sbt server, recording nothing"
        takeover_row="channel: a second launch forwarding a variable the first did not takes the sbt server over"
        takeback_row="channel: the first launch's next command takes the sbt server back"
        teardown_row="channel: the first launch's command during the second's teardown starts its own server"
        mill_share_row="channel: a second launch attaches to the first's mill daemon"
        mill_takeover_row="channel: a second launch forwarding a variable the first did not takes the mill daemon over"
        # The mill rows are reported once: here, or with the mill rows' own skip.
        if ! start_second_broker; then
            report FAIL "$share_row" "the second broker made no FIFOs: $(tail -1 "$work/channel2.log" | cut -c1-50)"
            report SKIP "$takeover_row" "no second broker"
            report SKIP "$takeback_row" "no second broker"
            report SKIP "$teardown_row" "no second broker"
            want mill && report SKIP "$mill_share_row" "no second broker"
            want mill && report SKIP "$mill_takeover_row" "no second broker"
        else
            # The first broker's server for the project is warm from the rows above. The second
            # launch's `about` runs in it: the record and its group unchanged, no second server,
            # and nothing recorded in the second broker's session.
            share_before=$(broker_server_record "$project")
            with_timeout 600 second_shim chan-share-sbt.log "$project" sbt about; share_status=$?
            channel_settled
            share_session=$(second_session)
            share_records=$(ls "$share_session/records" 2>/dev/null | tr '\n' ' ')
            if [ "$share_status" -eq 0 ] && grep -q 'This is sbt' "$work/chan-share-sbt.log" \
                && [ -n "$share_before" ] && record_alive "$share_before" \
                && [ "$(broker_server_record "$project")" = "$share_before" ] \
                && [ -n "$(server_in_group "$share_before")" ] && [ -z "$(command_servers)" ] \
                && [ -n "$share_session" ] && [ -z "$share_records" ] \
                && grep -q 'attached to' "$work/channel2.log"
            then report PASS "$share_row" "$(grep -m1 -o 'attached to [^ ]*' "$work/channel2.log")"
            else report FAIL "$share_row" "exit $share_status, record before ${share_before:-none}, after \
$(broker_server_record "$project"), command servers: $(command_servers | tr '\n' ' '), second session \
${share_session:-none} records: ${share_records:-none}; $(tail -1 "$work/chan-share-sbt.log.err" | cut -c1-50)"; fi

            # The daemon the second launch attaches to is the first broker's, started here by its
            # own `version` — the start meets the wrapper rows' memo before the mill rows below
            # do — and shut down after, so the mill rows still measure a start of their own.
            if want mill; then
                with_timeout 900 channel_shim chan-share-mill1.log "$mill_project" mill version
                channel_settled
                mill_share_record=$(broker_daemon_record "$mill_project")
                mill_share_daemon=$(daemon_in_group "$mill_share_record")
                with_timeout 600 second_shim chan-share-mill.log "$mill_project" mill version; mill_share_status=$?
                channel_settled
                if [ "$mill_share_status" -eq 0 ] && grep -q '1\.1\.9' "$work/chan-share-mill.log" \
                    && [ -n "$mill_share_daemon" ] && record_alive "$mill_share_record" \
                    && [ "$(broker_daemon_record "$mill_project")" = "$mill_share_record" ] \
                    && [ "$(daemon_in_group "$mill_share_record")" = "$mill_share_daemon" ] \
                    && [ "$(mill_daemons | wc -l | tr -d ' ')" -eq 1 ] \
                    && [ -z "$(ls "$(second_session)/records" 2>/dev/null)" ] \
                    && grep -q 'attached to .* mill runtime' "$work/channel2.log"
                then report PASS "$mill_share_row" "daemon $mill_share_daemon in group ${mill_share_record%% *}"
                else report FAIL "$mill_share_row" "exit $mill_share_status, daemon before ${mill_share_daemon:-none}, \
after $(daemon_in_group "$(broker_daemon_record "$mill_project")" | tr '\n' ' '), all: $(mill_daemons | tr '\n' ' '); \
$(tail -1 "$work/chan-share-mill.log.err" | cut -c1-50)"; fi
                with_timeout 300 channel_shim chan-share-mill2.log "$mill_project" mill shutdown
                channel_settled
            fi
            stop_second_broker

            # The second launch forwards a variable the first did not: the server it would start
            # has another environment, so it ends the first broker's server by its record, under
            # the retirement lock, and starts its own; the first's record stays, its group gone.
            # The first launch's next command finds its group dead and takes the server back
            # the same way: two launches whose runtimes differ alternate restarts.
            if ! start_second_broker --env=GATE_SHARE; then
                report FAIL "$takeover_row" \
                    "the second broker made no FIFOs: $(tail -1 "$work/channel2.log" | cut -c1-50)"
                report SKIP "$takeback_row" "no second broker"
                report SKIP "$teardown_row" "no second broker"
                want mill && report SKIP "$mill_takeover_row" "no second broker"
            else
                taken_before=$(session_record "$first_session" "$sbt_record")
                with_timeout 600 second_shim chan-share-takeover.log "$project" sbt about; takeover_status=$?
                channel_settled
                second=$(second_session)
                taken_after=$(session_record "$second" "$sbt_record")
                if [ "$takeover_status" -eq 0 ] && grep -q 'This is sbt' "$work/chan-share-takeover.log" \
                    && [ -n "$taken_before" ] && ! record_alive "$taken_before" \
                    && [ -z "$(server_in_group "$taken_before")" ] \
                    && [ -n "$taken_after" ] && record_alive "$taken_after" \
                    && [ -n "$(server_in_group "$taken_after")" ] && [ -z "$(command_servers)" ] \
                    && grep -q 'took over' "$work/channel2.log"
                then report PASS "$takeover_row" "$(grep -m1 -o 'took over [^ ]*' "$work/channel2.log")"
                else report FAIL "$takeover_row" "exit $takeover_status, first's record ${taken_before:-none} \
$(record_alive "$taken_before" && echo alive || echo gone), second's ${taken_after:-none} \
$(record_alive "$taken_after" && echo alive || echo gone) in ${second:-no session}, command servers: \
$(command_servers | tr '\n' ' '), root: $(root_now); $(tail -1 "$work/chan-share-takeover.log.err" | cut -c1-60)"; fi

                with_timeout 600 channel_shim chan-share-takeback.log "$project" sbt about; takeback_status=$?
                channel_settled
                taken_back=$(session_record "$first_session" "$sbt_record")
                if [ "$takeback_status" -eq 0 ] && grep -q 'This is sbt' "$work/chan-share-takeback.log" \
                    && [ -n "$taken_back" ] && [ "$taken_back" != "$taken_before" ] && record_alive "$taken_back" \
                    && [ -n "$(server_in_group "$taken_back")" ] \
                    && [ -n "$taken_after" ] && ! record_alive "$taken_after" \
                    && [ -z "$(server_in_group "$taken_after")" ] && [ -z "$(command_servers)" ] \
                    && grep -q 'took over' "$work/channel.log"
                then report PASS "$takeback_row" "$(grep -m1 -o 'took over [^ ]*' "$work/channel.log")"
                else report FAIL "$takeback_row" "exit $takeback_status, first's record ${taken_back:-none} \
$(record_alive "$taken_back" && echo alive || echo gone), second's ${taken_after:-none} \
$(record_alive "$taken_after" && echo alive || echo gone) in ${second:-no session}, command servers: \
$(command_servers | tr '\n' ' '), root: $(root_now); $(tail -1 "$work/chan-share-takeback.log.err" | cut -c1-60)"; fi

                # The daemon likewise: the first broker's, started by its own `version`, is ended
                # by the second's and replaced; the first's `shutdown` then ends the second's the
                # same way and stops its own, so the mill rows still measure a start of their own.
                if want mill; then
                    with_timeout 900 channel_shim chan-share-mill-takeover0.log "$mill_project" mill version
                    channel_settled
                    mill_before=$(session_record "$first_session" "$mill_record")
                    mill_daemon_before=$(daemon_in_group "$mill_before")
                    with_timeout 600 second_shim chan-share-mill-takeover.log "$mill_project" mill version
                    mill_takeover_status=$?
                    channel_settled
                    mill_after=$(session_record "$second" "$mill_record")
                    if [ "$mill_takeover_status" -eq 0 ] && grep -q '1\.1\.9' "$work/chan-share-mill-takeover.log" \
                        && [ -n "$mill_daemon_before" ] && ! record_alive "$mill_before" \
                        && ! kill -0 "$mill_daemon_before" 2>/dev/null \
                        && [ -n "$mill_after" ] && record_alive "$mill_after" \
                        && [ -n "$(daemon_in_group "$mill_after")" ] \
                        && [ "$(mill_daemons | wc -l | tr -d ' ')" -eq 1 ] \
                        && grep -q 'took over .* mill daemon' "$work/channel2.log"
                    then report PASS "$mill_takeover_row" "daemon $mill_daemon_before ended, \
$(daemon_in_group "$mill_after") in group ${mill_after%% *}"
                    else report FAIL "$mill_takeover_row" "exit $mill_takeover_status, daemon before \
${mill_daemon_before:-none} $(kill -0 "$mill_daemon_before" 2>/dev/null && echo alive || echo gone), second's \
record ${mill_after:-none}, all: $(mill_daemons | tr '\n' ' '); \
$(tail -1 "$work/chan-share-mill-takeover.log.err" | cut -c1-50)"; fi
                    with_timeout 600 channel_shim chan-share-mill-takeover1.log "$mill_project" mill shutdown
                    channel_settled
                fi

                # The second launch owning the server again, its broker is ended while the
                # first's command runs: the taker waits on the retirement lock the teardown
                # holds, finds the group ended or ends it, and starts its own — one server, its
                # record the first's, no signal twice, the second's session collected.
                with_timeout 600 second_shim chan-share-retake.log "$project" sbt about; retake_status=$?
                channel_settled
                retaken=$(session_record "$second" "$sbt_record")
                takeovers_before=$(grep -c "took over $(basename "$second")" "$work/channel.log")
                kill -TERM "$second_broker" 2>/dev/null
                with_timeout 600 channel_shim chan-share-teardown.log "$project" sbt about; teardown_status=$?
                stop_second_broker
                channel_settled
                torn_down=$(session_record "$first_session" "$sbt_record")
                if [ "$retake_status" -eq 0 ] && [ "$teardown_status" -eq 0 ] \
                    && grep -q 'This is sbt' "$work/chan-share-teardown.log" \
                    && [ -n "$retaken" ] && ! record_alive "$retaken" && [ -z "$(server_in_group "$retaken")" ] \
                    && [ -n "$torn_down" ] && record_alive "$torn_down" \
                    && [ -n "$(server_in_group "$torn_down")" ] && [ -z "$(command_servers)" ] \
                    && [ ! -d "$second" ] && [ ! -d "$command_root/condemned/$(basename "$second")" ]
                then report PASS "$teardown_row" "$(if [ "$(grep -c "took over $(basename "$second")" \
                    "$work/channel.log")" -gt "$takeovers_before" ]; then echo "took the group over"; \
                    else echo "found the group ended by the teardown"; fi)"
                else report FAIL "$teardown_row" "exits $retake_status/$teardown_status, second's record \
${retaken:-none} $(record_alive "$retaken" && echo alive || echo gone), first's ${torn_down:-none} \
$(record_alive "$torn_down" && echo alive || echo gone), second's session \
$([ -d "$second" ] && echo kept || echo gone), condemned \
$([ -d "$command_root/condemned/$(basename "$second")" ] && echo kept || echo gone), root: $(root_now); \
$(tail -1 "$work/chan-share-teardown.log.err" | cut -c1-60)"; fi
            fi
        fi

        # --- mill: the broker's daemon (doc/run-on-host.md, "mill") ------------------------------
        #
        # The daemon the broker starts in its session serves every mill command of the build
        # directory; each client runs under a profile naming that daemon's port and no other. The
        # first row also meets the memo the wrapper rows left, naming the fixture project's cache,
        # which this broker's profile — the fixture as this repository's build directory — denies:
        # the start deletes it (RunOnHostMillDaemons.discardForeignMemo), or the daemon dies unable to
        # open its jars. The
        # fixture's `run` prints the TMPDIR the build sees and, with `sleep`, stays up for the
        # cancel and busy-daemon rows.
        if ! want mill; then skip_mill_channel "needs mill"; else
        mill_row="channel: mill compile starts the broker's daemon, and the next command reuses it"
        # The start TERMs its starter once the daemon listens (RunOnHostMillDaemons.endStarter): the channel
        # log says the TERM was sent — counted before and after, since the log accumulates — and
        # the starter's exit record, beside the daemon record, says it ended on it, 143.
        starters_termed_before=$(grep -c 'TERM to the mill starter' "$work/channel.log")
        with_timeout 900 channel_shim chan-mill1.log "$mill_project" mill __.compile; mill_status=$?
        channel_settled
        mill_record=$(broker_daemon_record "$mill_project")
        mill_daemon=$(daemon_in_group "$mill_record")
        starters_termed=$(grep -c 'TERM to the mill starter' "$work/channel.log")
        starter_exit=$(cat "$command_root"/b*/records/daemon-mill-"$(build_hash "$mill_project")".exit 2>/dev/null)
        with_timeout 300 channel_shim chan-mill2.log "$mill_project" mill version
        channel_settled
        if [ "$mill_status" -eq 0 ] && [ -n "$mill_daemon" ] && record_alive "$mill_record" \
            && [ "$(broker_daemon_record "$mill_project")" = "$mill_record" ] \
            && [ "$(daemon_in_group "$mill_record")" = "$mill_daemon" ] \
            && [ "$(mill_daemons | wc -l | tr -d ' ')" -eq 1 ] && grep -q '1\.1\.9' "$work/chan-mill2.log" \
            && [ "$starters_termed" -gt "$starters_termed_before" ] && [ "${starter_exit:-none}" = 143 ]
        then report PASS "$mill_row" "daemon $mill_daemon in group ${mill_record%% *}; starter exit 143 on the TERM"
        else report FAIL "$mill_row" "compile exit $mill_status, daemon before ${mill_daemon:-none}, after \
$(daemon_in_group "$(broker_daemon_record "$mill_project")" | tr '\n' ' '), all: $(mill_daemons | tr '\n' ' '), \
TERMs: $starters_termed (before $starters_termed_before), starter exit ${starter_exit:-none}"; fi

        # A forked JVM — a `run`, a test — inherits the daemon's profile but gets the command's
        # environment (RunModule.scala, ctx.env): the fixture's main creates a temporary file where
        # that environment says, and prints where.
        tmp_row="channel: a mill build's forked JVM writes temporary files where the daemon's profile allows"
        with_timeout 600 channel_shim chan-mill-tmp.log "$mill_project" mill run; tmp_status=$?
        channel_settled
        tmpfile=$(grep -m1 -o 'tmpfile=[^ ]*' "$work/chan-mill-tmp.log")
        if [ "$tmp_status" -eq 0 ] && [ -n "$tmpfile" ]
        then report PASS "$tmp_row" "$tmpfile"
        else report FAIL "$tmp_row" "exit $tmp_status: ${tmpfile:-no file}; \
$(grep -v 'Picked up' "$work/chan-mill-tmp.log.err" | tail -1 | cut -c1-50)"; fi

        # socketPort is the build's to write and authorizes nothing: a planted port is one the
        # client's profile does not admit, so its connect is denied and the daemon stays.
        port_row="channel: a planted socketPort reaches no daemon: the client is denied, the daemon untouched"
        port_file=$mill_project/out/mill-daemon/socketPort
        port_saved=$(cat "$port_file" 2>/dev/null)
        printf '%s' "$((port_saved + 1))" > "$port_file"
        with_timeout 300 channel_shim chan-mill-planted-port.log "$mill_project" mill version; planted_status=$?
        channel_settled
        printf '%s' "$port_saved" > "$port_file"; port_saved=""
        if [ "$planted_status" -ne 0 ] \
            && grep -q 'Operation not permitted' "$work/chan-mill-planted-port.log" "$work/chan-mill-planted-port.log.err" \
            && [ "$(daemon_in_group "$mill_record")" = "$mill_daemon" ]
        then report PASS "$port_row" "exit $planted_status; daemon $mill_daemon kept"
        else report FAIL "$port_row" "exit $planted_status; daemon now \
$(daemon_in_group "$(broker_daemon_record "$mill_project")" | tr '\n' ' '); \
$(grep -m1 -h 'Exception\|refused' "$work/chan-mill-planted-port.log.err" | cut -c1-50)"; fi

        # A client disconnect mid-command: the next command runs, whatever the daemon did on the
        # disconnect — stock Mill shuts it down (Server.scala; measured,
        # src/probe/run-on-host-broker-session.sh M5), which the wait below lets finish.
        cancel_row="channel: after a cancelled mill command, the next command runs"
        channel_shim chan-mill-cancel.log "$mill_project" mill run sleep "$fixture_tag" & shim=$!
        cancel_ready=no
        gate_wait_started "$shim" 600 grep -q 'fixture-main' "$work/chan-mill-cancel.log" 2>/dev/null \
            && cancel_ready=yes
        cancel_record=$(broker_daemon_record "$mill_project")
        cancel_daemon=$(daemon_in_group "$cancel_record")
        kill -9 "$shim" 2>/dev/null; wait "$shim" 2>/dev/null
        channel_settled
        tries=0
        while [ -n "$cancel_daemon" ] && kill -0 "$cancel_daemon" 2>/dev/null && [ "$tries" -lt 120 ]; do
            tries=$((tries + 1)); sleep 0.5
        done
        forked=$(pgrep -f "$fixture_sleep" 2>/dev/null | head -1)
        if [ -n "$forked" ]
        then report INFO "forked run JVM after the cancel" "alive ($forked); killed"; kill "$forked" 2>/dev/null
        else report INFO "forked run JVM after the cancel" "gone"; fi
        with_timeout 300 channel_shim chan-mill-after-cancel.log "$mill_project" mill version
        channel_settled
        new_daemon=$(daemon_in_group "$(broker_daemon_record "$mill_project")")
        if [ "$cancel_ready" = yes ] && [ -n "$cancel_daemon" ] && [ -n "$new_daemon" ] \
            && grep -q '1\.1\.9' "$work/chan-mill-after-cancel.log"
        then report PASS "$cancel_row" "daemon before $cancel_daemon, after $new_daemon"
        else report FAIL "$cancel_row" "ready to cancel: $cancel_ready; see $work/chan-mill-cancel.log{,.err}; \
daemon before ${cancel_daemon:-none} \
$(kill -0 "$cancel_daemon" 2>/dev/null && echo alive || echo gone), after ${new_daemon:-none}"; fi

        # What Mill's launcher restarts the daemon on (RunOnHostPrereqs.millDaemonConfig) replaces
        # the daemon before the command, and removing the file replaces it again. The file is
        # this gate's, removed by the cleanup too.
        opts_row="channel: a mill option-file edit replaces the daemon, and the next command runs under it"
        opts_record=$(broker_daemon_record "$mill_project")
        gate_opts_file=$mill_project/.mill-jvm-opts
        printf -- '-Dko.gate.opts=1\n' > "$gate_opts_file"
        with_timeout 600 channel_shim chan-mill-opts1.log "$mill_project" mill version; opts1_status=$?
        channel_settled
        edited_record=$(broker_daemon_record "$mill_project")
        rm -f "$gate_opts_file"; gate_opts_file=""
        with_timeout 600 channel_shim chan-mill-opts2.log "$mill_project" mill version; opts2_status=$?
        channel_settled
        if [ "$opts1_status" -eq 0 ] && [ "$opts2_status" -eq 0 ] && [ -n "$edited_record" ] \
            && [ "$edited_record" != "$opts_record" ] \
            && [ "$(broker_daemon_record "$mill_project")" != "$edited_record" ] \
            && record_alive "$(broker_daemon_record "$mill_project")" \
            && grep -q 'its configuration changed' "$work/channel.log"
        then report PASS "$opts_row"
        else report FAIL "$opts_row" "exits $opts1_status/$opts2_status; records: $opts_record -> \
${edited_record:-none} -> $(broker_daemon_record "$mill_project")"; fi

        # A link at out/mill-daemon would point Mill's launcher at another build directory's
        # daemon, past the ownership and idleness checks (RunOnHostMillDaemons.rendezvousIsOwn): refused
        # before any of it runs. With the broker's daemon shut down first, since the daemon reads
        # its processId by path and would exit while the directory is aside.
        redirect_row="channel: a redirected out/mill-daemon is refused before Mill's launcher acts on it"
        with_timeout 300 channel_shim chan-mill-shutdown0.log "$mill_project" mill shutdown
        channel_settled
        redirect_saved=$mill_project/out/mill-daemon.gate
        mv "$mill_project/out/mill-daemon" "$redirect_saved"
        ln -s "$scratch_mill" "$mill_project/out/mill-daemon"
        with_timeout 300 channel_shim chan-mill-redirect.log "$mill_project" mill version; redirect_status=$?
        channel_settled
        rm -f "$mill_project/out/mill-daemon"
        mv "$redirect_saved" "$mill_project/out/mill-daemon"; redirect_saved=""
        if [ "$redirect_status" -eq 2 ] \
            && grep -q 'redirected mill daemon directory is refused' "$work/chan-mill-redirect.log.err" \
            && [ -z "$(mill_daemons)" ]
        then report PASS "$redirect_row"
        else report FAIL "$redirect_row" "exit $redirect_status, daemons: $(mill_daemons | tr '\n' ' '); \
$(tail -1 "$work/chan-mill-redirect.log.err" | cut -c1-60)"; fi

        # A daemon of yours — from a terminal, outside any launch — is ended by proof, once idle,
        # before the broker's starts, and the channel log says so. The broker's own is shut down
        # first, through Mill's own command, since only a start meets a foreign daemon; then an
        # unconfined ./mill leaves one — once with a JAVA_OPTS the closed environment lacks, so
        # its fingerprint differs from the broker's, and once with none, matching — and the next
        # channel command ends it and starts the broker's. The unconfined ./mill runs the native
        # launcher, with the JDK the profile grants first on its PATH.
        foreign_mill() { # in the fixture, unconfined: command...
            ( cd "$mill_project" && env -u JAVA_OPTS -u JDK_JAVA_OPTIONS PATH="$JAVA_HOME/bin:$PATH" "$@" )
        }
        foreign_row() { # label env-args...
            foreign_label=$1; shift
            with_timeout 300 channel_shim chan-mill-shutdown.log "$mill_project" mill shutdown
            channel_settled
            foreign_mill env "$@" ./mill version >"$work/foreign.log" 2>&1
            foreign=$(mill_daemons | head -1)
            ended_before=$(grep -c 'ended the mill daemon' "$work/channel.log")
            with_timeout 600 channel_shim chan-mill-foreign.log "$mill_project" mill version; foreign_status=$?
            channel_settled
            ours=$(daemon_in_group "$(broker_daemon_record "$mill_project")")
            if [ -n "$foreign" ] && ! kill -0 "$foreign" 2>/dev/null && [ "$foreign_status" -eq 0 ] \
                && [ "$(grep -c 'ended the mill daemon' "$work/channel.log")" -gt "$ended_before" ] \
                && [ -n "$ours" ] && [ "$ours" != "$foreign" ]
            then report PASS "$foreign_label" "foreign $foreign ended, the broker's $ours started"
            else report FAIL "$foreign_label" "foreign ${foreign:-none} \
$(kill -0 "${foreign:-0}" 2>/dev/null && echo alive || echo gone), exit $foreign_status, ours ${ours:-none}, \
log lines: $(grep -c 'ended the mill daemon' "$work/channel.log") (before $ended_before)"; fi
        }
        foreign_row "channel: a mill daemon of yours, mismatched, is ended by proof before the broker's starts" \
            JAVA_OPTS=-Dko.gate.foreign=1
        foreign_row "channel: a mill daemon of yours, matching, is ended by proof before the broker's starts"

        # A daemon of yours running a command — an established connection on its port — is left
        # until its client disconnects: the channel command waits, and completes once the daemon
        # is idle or gone (a client's disconnect mid-command ends the daemon, as above).
        busy_row="channel: a mill daemon of yours mid-command is left until its client disconnects"
        with_timeout 300 channel_shim chan-mill-shutdown2.log "$mill_project" mill shutdown
        channel_settled
        foreign_mill ./mill run sleep "$fixture_tag" >"$work/foreign-run.log" 2>&1 & foreign_client=$!
        tries=0
        while ! grep -q 'fixture-main' "$work/foreign-run.log" 2>/dev/null && [ "$tries" -lt 600 ]; do
            tries=$((tries + 1)); sleep 0.5
        done
        foreign=$(mill_daemons | head -1)
        channel_shim chan-mill-busy.log "$mill_project" mill version & shim=$!
        sleep 20
        waiting=$(kill -0 "$shim" 2>/dev/null && echo yes || echo no)
        foreign_alive=$(kill -0 "${foreign:-0}" 2>/dev/null && echo yes || echo no)
        kill "$foreign_client" 2>/dev/null; wait "$foreign_client" 2>/dev/null
        pkill -f "$fixture_sleep" 2>/dev/null
        wait "$shim"; busy_status=$?
        channel_settled
        ours=$(daemon_in_group "$(broker_daemon_record "$mill_project")")
        if [ -n "$foreign" ] && [ "$waiting" = yes ] && [ "$foreign_alive" = yes ] && [ "$busy_status" -eq 0 ] \
            && ! kill -0 "$foreign" 2>/dev/null && [ -n "$ours" ] && [ "$ours" != "$foreign" ]
        then report PASS "$busy_row" "waited 20s on foreign $foreign; then the broker's $ours"
        else report FAIL "$busy_row" "foreign ${foreign:-none} alive while busy: $foreign_alive, command \
waiting: $waiting, exit $busy_status, ours ${ours:-none}"; fi

        # One busy past the bound (RunOnHostMillDaemons.ForeignIdleDeadlineMillis): the command is refused
        # naming it, and the daemon and its build are left alone. The broker's daemon is shut down
        # first: a ./mill of yours with matching settings attaches to a live daemon of the launch's,
        # and the row needs a daemon of its own to be busy.
        bound_row="channel: a mill daemon of yours busy past the bound is refused, and left alive"
        with_timeout 300 channel_shim chan-mill-shutdown3.log "$mill_project" mill shutdown
        channel_settled
        foreign_mill ./mill run sleep "$fixture_tag" >"$work/foreign-run2.log" 2>&1 & foreign_client=$!
        tries=0
        while ! grep -q 'fixture-main' "$work/foreign-run2.log" 2>/dev/null && [ "$tries" -lt 600 ]; do
            tries=$((tries + 1)); sleep 0.5
        done
        foreign=$(mill_daemons | head -1)
        with_timeout 300 channel_shim chan-mill-bound.log "$mill_project" mill version; bound_status=$?
        channel_settled
        foreign_alive=$(kill -0 "${foreign:-0}" 2>/dev/null && echo yes || echo no)
        kill "$foreign_client" 2>/dev/null; wait "$foreign_client" 2>/dev/null
        pkill -f "$fixture_sleep" 2>/dev/null
        tries=0
        while [ -n "$foreign" ] && kill -0 "$foreign" 2>/dev/null && [ "$tries" -lt 120 ]; do
            tries=$((tries + 1)); sleep 0.5
        done
        [ -n "$foreign" ] && kill "$foreign" 2>/dev/null
        if [ -n "$foreign" ] && [ "$bound_status" -eq 2 ] && [ "$foreign_alive" = yes ] \
            && grep -q 'has been running a command' "$work/chan-mill-bound.log.err"
        then report PASS "$bound_row" "refused after the bound; foreign $foreign alive"
        else report FAIL "$bound_row" "foreign ${foreign:-none} alive after: $foreign_alive, exit $bound_status: \
$(tail -1 "$work/chan-mill-bound.log.err" | cut -c1-60)"; fi
        channel_settled
        fi

        # --- gradle: the launch's daemons (doc/run-on-host.md, "Gradle") -------------------------
        #
        # Gradle's own client starts the daemon in the launch's registry under the broker's tmp/,
        # and later clients match it there; the broker records each daemon after every command
        # and ends the records' groups with its session (RunOnHostGradleDaemons). The fixture's `run`
        # prints the TMPDIR the forked JVM sees and, with `sleep`, stays up for the cancel and
        # teardown rows.
        if ! want gradle; then skip_gradle_channel "needs gradle"; else
        gradle_row="channel: gradle build starts a daemon in the launch's registry, and the next command reuses it"
        with_timeout 900 channel_shim chan-gradle1.log "$gradle_project" gradle build; gradle_status=$?
        channel_settled
        gradle_record=$(broker_gradle_records)
        gradle_daemon=$(gradle_daemons | head -1)
        with_timeout 300 channel_shim chan-gradle2.log "$gradle_project" gradle help; gradle2_status=$?
        channel_settled
        if [ "$gradle_status" -eq 0 ] && [ "$gradle2_status" -eq 0 ] && [ -n "$gradle_daemon" ] \
            && [ "${gradle_record%% *}" = "$gradle_daemon" ] && record_alive "$gradle_record" \
            && [ "$(broker_gradle_records)" = "$gradle_record" ] \
            && [ "$(gradle_daemons | wc -l | tr -d ' ')" -eq 1 ] && grep -q 'BUILD SUCCESSFUL' "$work/chan-gradle1.log"
        then report PASS "$gradle_row" "daemon $gradle_daemon"
        else report FAIL "$gradle_row" "exits $gradle_status/$gradle2_status, daemon ${gradle_daemon:-none}, records: \
$(broker_gradle_records | tr '\n' ' '), all: $(gradle_daemons | tr '\n' ' ')"; fi

        # Gradle unpacks its native libraries under the user home and loads them from there: the
        # daemon has one mapped, from the directory the profile grants read-write.
        native_row="channel: the daemon maps Gradle's native libraries from the user home's read-write grant"
        # The launch's user home is the broker's project's, under its run-on-host cache
        # (RunOnHostPrereqs.gradleUserHomeOf); its name is the launcher's own.
        native=$(lsof -p "${gradle_daemon:-0}" 2>/dev/null | grep -F "/gradle-user-home/native/" | head -1 \
            | awk '{print $NF}')
        if [ -n "$native" ]
        then report PASS "$native_row" "${native##*/}"
        else report FAIL "$native_row" \
            "nothing under a gradle-user-home/native/ mapped in daemon ${gradle_daemon:-none}"; fi

        # The toolchain inventory is the launch's JDK alone, auto-detection and auto-download off
        # (RunOnHostSandbox.gradleCommand): a project asking for another feature version fails
        # naming it, before any denial could.
        toolchain_row="channel: a toolchain the project asks for, not the launch's JDK, fails by name"
        granted=$("$JAVA_HOME/bin/java" -XshowSettings:properties -version 2>&1 \
            | sed -n 's/^ *java.specification.version = //p')
        other=$([ "$granted" = 21 ] && echo 17 || echo 21)
        with_timeout 600 channel_shim chan-gradle-toolchain.log "$gradle_project" gradle compileJava \
            "-PgateToolchain=$other"; toolchain_status=$?
        channel_settled
        toolchain_logs="$work/chan-gradle-toolchain.log $work/chan-gradle-toolchain.log.err"
        toolchain_said=$(grep -m1 -hi 'toolchain' $toolchain_logs)
        if [ "$toolchain_status" -ne 0 ] && [ -n "$toolchain_said" ] \
            && ! grep -q 'Operation not permitted' $toolchain_logs
        then report PASS "$toolchain_row" "$(printf '%s' "$toolchain_said" | cut -c1-60)"
        else report FAIL "$toolchain_row" \
            "exit $toolchain_status: $(tail -1 "$work/chan-gradle-toolchain.log.err" | cut -c1-60)"; fi

        # A daemon of yours: one in a registry the launch does not name, so the launch's
        # commands neither attach to it nor end it. Started and stopped unconfined by the
        # fixture's own gradlew, with the JDK the profile grants first on its PATH, in a registry
        # of this gate's under $work — not your home's, where `--stop` would stop every daemon of
        # yours of that version (DaemonStopClient), unrelated builds' included.
        foreign_gradle() { # in the fixture, unconfined: command...
            ( cd "$gradle_project" \
                && env -u JAVA_OPTS -u JDK_JAVA_OPTIONS -u GRADLE_OPTS PATH="$JAVA_HOME/bin:$PATH" \
                    "$@" "-Dorg.gradle.daemon.registry.base=$work/your-registry" )
        }
        own_row="channel: a gradle daemon of yours, in a registry of your own, is neither attached to nor ended"
        foreign_gradle ./gradlew help >"$work/foreign-gradle.log" 2>&1
        foreign=$(gate_gradle_daemons | head -1)
        with_timeout 300 channel_shim chan-gradle-own.log "$gradle_project" gradle help; own_status=$?
        channel_settled
        foreign_alive=$(kill -0 "${foreign:-0}" 2>/dev/null && echo yes || echo no)
        ours=$(gradle_daemons | tr '\n' ' ')
        foreign_gradle ./gradlew --stop >/dev/null 2>&1
        if [ -n "$foreign" ] && [ "$foreign_alive" = yes ] && [ "$own_status" -eq 0 ] \
            && [ -n "$ours" ] && ! broker_gradle_records | grep -q "^$foreign "
        then report PASS "$own_row" "yours $foreign untouched; the launch's $ours"
        else report FAIL "$own_row" "yours ${foreign:-none} alive after: $foreign_alive, exit $own_status, \
the launch's: ${ours:-none}; $(tail -1 "$work/foreign-gradle.log" | cut -c1-50)"; fi

        # A client disconnect mid-build: Gradle cancels the build and, still busy after its
        # ten-second grace, stops the daemon (DaemonStateCoordinator, WatchForDisconnection); the
        # next command attaches or starts one, and the records follow — a stopped daemon's
        # forgotten, a fresh one's written.
        cancel_row="channel: after a cancelled gradle command, the next command runs, the records following the daemons"
        channel_shim chan-gradle-cancel.log "$gradle_project" gradle run --args="sleep $fixture_tag" & shim=$!
        cancel_ready=no
        gate_wait_started "$shim" 600 grep -q 'fixture-main' "$work/chan-gradle-cancel.log" 2>/dev/null \
            && cancel_ready=yes
        cancel_daemon=$(gradle_daemons | head -1)
        kill -9 "$shim" 2>/dev/null; wait "$shim" 2>/dev/null
        channel_settled
        tries=0
        while pgrep -f "$fixture_sleep" >/dev/null 2>&1 && [ "$tries" -lt 120 ]; do
            tries=$((tries + 1)); sleep 0.5
        done
        forked=$(pgrep -f "$fixture_sleep" 2>/dev/null | head -1)
        if [ -n "$forked" ]
        then report INFO "forked run JVM after the cancel" "alive ($forked); killed"; kill "$forked" 2>/dev/null
        else report INFO "forked run JVM after the cancel" "gone"; fi
        with_timeout 300 channel_shim chan-gradle-after-cancel.log "$gradle_project" gradle help; after_status=$?
        channel_settled
        if [ "$cancel_ready" = yes ] && [ -n "$cancel_daemon" ] && [ "$after_status" -eq 0 ] \
            && [ "$(gradle_daemons | wc -l | tr -d ' ')" -eq 1 ] \
            && [ "$(broker_gradle_records | wc -l | tr -d ' ')" -eq 1 ] && record_alive "$(broker_gradle_records)"
        then report PASS "$cancel_row" "daemon before $cancel_daemon, after $(gradle_daemons)"
        else report FAIL "$cancel_row" "ready to cancel: $cancel_ready; see $work/chan-gradle-cancel.log{,.err}; \
daemon before ${cancel_daemon:-none}, exit $after_status, daemons after: \
$(gradle_daemons | tr '\n' ' '), records: $(broker_gradle_records | tr '\n' ' ')"; fi
        fi

        with_timeout 120 channel_shim chan-refused.log /private/tmp sbt about; status=$?
        if [ "$status" -eq 2 ] && grep -q 'CHANNEL_UNAVAILABLE' "$work/chan-refused.log.err"
        then report PASS "channel: a working directory outside the project is refused"
        else report FAIL "channel: a working directory outside the project is refused" \
            "exit $status: $(tail -1 "$work/chan-refused.log.err" | cut -c1-60)"; fi

        # The shim dies; the broker sees the descriptor close and ends the command's client group,
        # leaving the warm server as stock sbt does on a disconnect (doc/run-on-host.md). So the
        # command's own group and directory go, while the broker, its proxy and its warm server
        # stay: the next command reuses that server.
        channel_shim chan-kill.log "$project" sbt compile & shim=$!
        tries=0
        while [ "$(commands_now)" -eq 0 ] && [ "$tries" -lt 600 ]; do tries=$((tries + 1)); sleep 0.5; done
        server_before=$(broker_server_record "$project")
        kill -9 "$shim" 2>/dev/null; wait "$shim" 2>/dev/null
        channel_settled
        broker_state=$(kill -0 "$channel_broker" 2>/dev/null && echo alive || echo gone)
        # Teardown appended the command's logs to the channel log before removing its directory
        # (appendSessionLogs); the broker's proxy and warm server are untouched by the command's end.
        if [ "$(commands_now)" -eq 0 ] && [ -z "$(command_servers)" ] && [ -z "$(command_proxies)" ] \
            && [ "$broker_state" = alive ] && grep -q "ended by signal" "$work/channel.log" \
            && record_alive "$(broker_proxy_record "$project")" \
            && [ -n "$server_before" ] && record_alive "$server_before"
        then report PASS "channel: a dead shim ends the running command"
        else report FAIL "channel: a dead shim ends the running command" \
            "commands: $(commands_now), command servers: $(command_servers | tr '\n' ' '), broker $broker_state," \
            "logs kept: $(grep -c 'ended by signal' "$work/channel.log")," \
            "warm server: ${server_before:-none} $(record_alive "$server_before" && echo alive || echo gone)"; fi

        # The sandbox dies: every exec dies with it, the shim included; the broker ends the command
        # and, with the container gone, itself: its session, server and proxy with it. With gradle
        # the command is a `run` whose forked JVM sleeps in the daemon's group, the group the
        # broker's end signals behind the daemon's record.
        gradle_end_row="channel: the broker's end takes the gradle daemon, and the JVM its build forked"
        gradle_run_daemon=""
        if want gradle; then
            channel_shim chan-dead.log "$gradle_project" gradle run --args="sleep $fixture_tag" & shim=$!
            tries=0
            while ! grep -q 'fixture-main' "$work/chan-dead.log" 2>/dev/null && [ "$tries" -lt 600 ]; do
                tries=$((tries + 1)); sleep 0.5
            done
            gradle_run_daemon=$(gradle_daemons | head -1)
        else
            channel_shim chan-dead.log "$project" sbt compile & shim=$!
            tries=0
            while [ "$(commands_now)" -eq 0 ] && [ "$tries" -lt 600 ]; do tries=$((tries + 1)); sleep 0.5; done
        fi
        broker_session=$(broker_session_of "$project")
        echo false > "$work/running"
        kill -9 "$shim" 2>/dev/null; wait "$shim" 2>/dev/null
        kill_channel_execs
        channel_settled
        tries=0
        while kill -0 "$channel_broker" 2>/dev/null && [ "$tries" -lt 120 ]; do tries=$((tries + 1)); sleep 0.5; done
        broker_state=$(kill -0 "$channel_broker" 2>/dev/null && echo alive || echo gone)
        # The broker's own teardown ended its server and proxy with its session.
        if [ "$(commands_now)" -eq 0 ] && [ -z "$(project_servers)" ] && [ -z "$(mill_daemons)" ] \
            && [ "$broker_state" = gone ] \
            && [ -z "$(stray_proxies)" ] && [ -n "$broker_session" ] && [ ! -d "$broker_session" ]
        then report PASS "channel: a dead sandbox ends the channel, its command and the broker's runtimes"
        else report FAIL "channel: a dead sandbox ends the channel, its command and the broker's runtimes" \
            "commands: $(commands_now), servers: $(project_servers | tr '\n' ' '), \
daemons: $(mill_daemons | tr '\n' ' '), broker $broker_state, \
proxies: $(stray_proxies | tr '\n' ' '), session ${broker_session:-unknown}: \
$([ -d "$broker_session" ] && echo kept || echo gone)"; fi
        if ! want gradle; then report SKIP "$gradle_end_row" "needs gradle"
        else
            forked=$(pgrep -f "$fixture_sleep" 2>/dev/null | tr '\n' ' ')
            if [ -n "$gradle_run_daemon" ] && [ -z "$(gradle_daemons)" ] && [ -z "$forked" ]
            then report PASS "$gradle_end_row" "daemon $gradle_run_daemon and its fork gone"
            else report FAIL "$gradle_end_row" "daemon ${gradle_run_daemon:-none} \
$(kill -0 "${gradle_run_daemon:-0}" 2>/dev/null && echo alive || echo gone), daemons: $(gradle_daemons | tr '\n' ' '), \
forked: ${forked:-none}"; pkill -f "$fixture_sleep" 2>/dev/null; fi
        fi
        rm -rf "$channel_dir"

        # The broker's own end mid-command. TERM: its hook ends the wrapper and waits for the
        # wrapper's teardown, then ends the broker's session, its server and its proxy, so the
        # moment the broker is gone the command's directory, the server and every proxy are gone
        # too. KILL: nothing waits, but the wrapper's stdin is the broker's pipe, and its EOF ends
        # the command by the same teardown; the broker's server and proxy stay, recorded in its
        # session, until the next start scavenges them by proof — the wrapper's recovery run
        # here. The shim is left blocked on its exit read (no timeout(1) here) and killed after.
        broker_end_row() { # row signal
            before=$(grep -c 'ended by signal' "$work/channel.log")
            if ! start_channel_broker; then report FAIL "$1" "the broker made no FIFOs"; return; fi
            # With gradle, TERM arrives during the launch's first gradle build, its daemon
            # unobserved and still cancelling when the teardown looks, so the teardown must find
            # it then. On KILL nothing observes, so the daemon is one a completed command
            # recorded, for the next start's scavenge to end by that record.
            if want gradle && [ "$2" = TERM ]; then
                channel_shim "chan-broker-$2.log" "$gradle_project" gradle run --args="sleep $fixture_tag" & shim=$!
                tries=0
                while ! grep -q 'fixture-main' "$work/chan-broker-$2.log" 2>/dev/null && [ "$tries" -lt 600 ]; do
                    tries=$((tries + 1)); sleep 0.5
                done
            else
                if want gradle; then
                    with_timeout 600 channel_shim "chan-broker-$2-gradle.log" "$gradle_project" gradle help
                    channel_settled
                fi
                channel_shim "chan-broker-$2.log" "$project" sbt compile & shim=$!
                tries=0
                while [ "$(commands_now)" -eq 0 ] && [ "$tries" -lt 600 ]; do tries=$((tries + 1)); sleep 0.5; done
            fi
            kill "-$2" "$channel_broker" 2>/dev/null
            tries=0
            while kill -0 "$channel_broker" 2>/dev/null && [ "$tries" -lt 240 ]; do
                tries=$((tries + 1)); sleep 0.5
            done
            if [ "$2" = KILL ]; then
                channel_settled
                orphan=$(stray_proxies | tr '\n' ' ')
                orphan_server=$(project_servers | tr '\n' ' ')
                wrapper sbt "$project" --version >"$work/recover-broker.log" 2>&1
                proxies_ended=$([ -n "$orphan" ] && [ -n "$orphan_server" ] \
                    && grep -q 'scavenged b.*GroupEnded.*GroupEnded' "$work/recover-broker.log" \
                    && [ -z "$(stray_proxies)" ] && echo yes || echo no)
            else
                proxies_ended=$([ -z "$(stray_proxies)" ] && echo yes || echo no)
            fi
            if [ "$(commands_now)" -eq 0 ] && [ -z "$(project_servers)" ] && [ -z "$(mill_daemons)" ] \
                && [ -z "$(gradle_daemons)" ] && ! pgrep -f "$fixture_sleep" >/dev/null 2>&1 \
                && [ "$proxies_ended" = yes ] && ! kill -0 "$channel_broker" 2>/dev/null \
                && [ "$(grep -c 'ended by signal' "$work/channel.log")" -gt "$before" ]
            then report PASS "$1"
            else report FAIL "$1" "commands: $(commands_now), servers: $(project_servers | tr '\n' ' '), \
daemons: $(mill_daemons | tr '\n' ' ') $(gradle_daemons | tr '\n' ' '), \
broker $(kill -0 "$channel_broker" 2>/dev/null && echo alive || echo gone), proxies ended: $proxies_ended, \
logs kept: $(grep -c 'ended by signal' "$work/channel.log") (before: $before)"; fi
            kill -9 "$shim" 2>/dev/null; wait "$shim" 2>/dev/null
            kill_channel_execs
            rm -rf "$channel_dir"
        }
        broker_end_row "channel: TERM to the broker ends its command before the broker exits" TERM
        broker_end_row "channel: a killed broker's command ends with it, and its server with the next start" KILL

        # A new launch adopts nothing a portfile nominates: the fixture's portfile names a live
        # socket that is not sbt's derivation for the directory, so the request is refused and
        # the listener hears the liveness probe's connect and no byte — the shutdown protocol is
        # never spoken to it. The listener is the gate's, recording what reaches it.
        planted_row="channel: a planted portfile nominates nothing: refused, no shutdown spoken"
        planted_mill_row="channel: a new launch adopts nothing planted in out/mill-daemon"
        cat > "$work/planted.py" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.bind(sys.argv[1]); s.listen(5)
print("bound", flush=True)
while True:
    c, _ = s.accept()
    c.settimeout(5)
    try:
        data = c.recv(4096)
    except OSError:
        data = b""
    print("bytes %d" % len(data), flush=True)
    c.close()
PY
        planted_sock=$work/planted.sock
        python3 "$work/planted.py" "$planted_sock" >"$work/planted.log" 2>&1 & planted_listener=$!
        tries=0
        while ! grep -q bound "$work/planted.log" && [ "$tries" -lt 50 ]; do tries=$((tries + 1)); sleep 0.1; done
        mkdir -p "$deny_project/project/target"
        printf '{"uri":"local://%s"}' "$planted_sock" > "$deny_project/project/target/active.json"
        # The mill rendezvous files name a gate listener's TCP port and a gate sleep's pid: the
        # new broker connects to nothing they name and signals nothing, and the client reaches
        # the broker's own daemon.
        cat > "$work/planted-tcp.py" <<'PY'
import socket, sys
s = socket.socket()
s.bind(("127.0.0.1", 0)); s.listen(5)
print("port %d" % s.getsockname()[1], flush=True)
while True:
    c, _ = s.accept()
    print("connect", flush=True)
    c.close()
PY
        python3 "$work/planted-tcp.py" >"$work/planted-tcp.log" 2>&1 & planted_tcp=$!
        sleep 3600 & planted_sleep=$!
        tries=0
        while ! grep -q port "$work/planted-tcp.log" && [ "$tries" -lt 50 ]; do tries=$((tries + 1)); sleep 0.1; done
        if want mill; then
            mkdir -p "$mill_project/out/mill-daemon"
            port_saved=$(cat "$mill_project/out/mill-daemon/socketPort" 2>/dev/null)
            sed -n 's/^port //p' "$work/planted-tcp.log" | tr -d '\n' > "$mill_project/out/mill-daemon/socketPort"
            printf '%s' "$planted_sleep" > "$mill_project/out/mill-daemon/processId"
        fi
        if ! start_channel_broker; then report FAIL "$planted_row" "the broker made no FIFOs"
        else
            with_timeout 300 channel_shim chan-planted.log "$deny_project" sbt about; status=$?
            channel_settled
            if [ "$status" -eq 2 ] && grep -q 'a live sbt server holds' "$work/chan-planted.log.err" \
                && grep -q 'bytes 0' "$work/planted.log" && ! grep -q 'bytes [1-9]' "$work/planted.log"
            then report PASS "$planted_row" "$(grep -c bytes "$work/planted.log") connects, no bytes"
            else report FAIL "$planted_row" "exit $status: $(tail -1 "$work/chan-planted.log.err" | cut -c1-60); \
listener: $(grep bytes "$work/planted.log" | tr '\n' ' ')"; fi
            if ! want mill; then report SKIP "$planted_mill_row" "needs mill"
            else
                with_timeout 600 channel_shim chan-planted-mill.log "$mill_project" mill version; status=$?
                channel_settled
                port_saved=""
                adopted=$(daemon_in_group "$(broker_daemon_record "$mill_project")")
                if [ "$status" -eq 0 ] && [ -n "$adopted" ] && ! grep -q connect "$work/planted-tcp.log" \
                    && kill -0 "$planted_sleep" 2>/dev/null
                then report PASS "$planted_mill_row" "daemon $adopted; the planted port heard nothing, the pid lives"
                else report FAIL "$planted_mill_row" "exit $status, daemon ${adopted:-none}, connects: \
$(grep -c connect "$work/planted-tcp.log"), planted pid $(kill -0 "$planted_sleep" 2>/dev/null && echo alive || echo gone)"; fi
            fi
            kill -TERM "$channel_broker" 2>/dev/null
            tries=0
            while kill -0 "$channel_broker" 2>/dev/null && [ "$tries" -lt 240 ]; do
                tries=$((tries + 1)); sleep 0.5
            done
            kill_channel_execs
            rm -rf "$channel_dir"
        fi
        rm -f "$deny_project/project/target/active.json"
        kill "$planted_listener" "$planted_tcp" "$planted_sleep" 2>/dev/null
        wait "$planted_listener" "$planted_tcp" "$planted_sleep" 2>/dev/null
    fi
fi

# After every wrapper row: no process or temporary directory outlives its command.
leftover=""
[ -n "$(project_servers)" ] && leftover="sbt server: $(project_servers | tr '\n' ' ')"
[ -n "$(deny_servers)" ] && leftover="$leftover deny-fixture server: $(deny_servers | tr '\n' ' ')"
[ -n "$(ivy_servers)" ] && leftover="$leftover ivy-fixture server: $(ivy_servers | tr '\n' ' ')"
[ -n "$(mill_daemons)" ] && leftover="$leftover mill daemon: $(mill_daemons | tr '\n' ' ')"
[ -n "$(gradle_daemons)" ] && leftover="$leftover gradle daemon: $(gradle_daemons | tr '\n' ' ')"
[ -n "$(stray_proxies)" ] && leftover="$leftover proxy: $(stray_proxies | tr '\n' ' ')"
[ "$(commands_now)" -gt 0 ] && leftover="$leftover command directories: $(commands_now)"
if [ -z "$leftover" ]
then report PASS "no proxy, sbt server, mill daemon or gradle daemon survives its command"
else report FAIL "no proxy, sbt server, mill daemon or gradle daemon survives its command" "$leftover"; fi

echo
echo "PASS $pass  FAIL $fail  SKIP $skip"
echo "logs and profiles: $work"
[ "$fail" -eq 0 ]
