#!/bin/sh
# What Mill does under the command profile when a build pins its JVM, `mill-jvm-version: temurin:21`:
# the measurements RunOnHostPrereqs.millPinnedJdk rests on (doc/run-on-host.md, "A pinned JVM").
# Run it on each new Mill release.
#
# Mill's launcher writes the JDK home it resolved for the pin to `out/mill-daemon/cache/java-home`,
# with a key naming the pin, and uses that home while the key matches and the directory exists
# (`CoursierClient.resolveJavaHome`, Mill 1.1.10). The supervisor grants the JDK that file names, a
# file a command can write, so the rows measure whether Mill then runs that JDK without fetching,
# and what it does when the file is absent, under another key, or names another JDK.
#
#   sh src/probe/mill-pinned-jvm.sh [pin]     # a Coursier JVM id; temurin:21 when omitted
#
# Run it on macOS from the repository root, with no sandbox session on this project. A pin that
# resolves to the JDK JAVA_HOME names measures no second grant, so pass one that differs.
#
# The provisioning run is yours: Mill's launcher, unconfined, in your environment. It downloads the
# pinned JDK into your Coursier cache, where it stays.
#
# Every row is `mill --no-daemon --version`, which prints the `java.home` of the JVM Mill started
# and evaluates no build. `--no-daemon` and a daemon start take the JVM from the same call
# (`MillProcessLauncher.javaExe`), so the rows need no broker. No proxy runs: a row that fetches
# fails at its first fetch, and its log names the host.
set -u
if [ "$(uname -s)" != "Darwin" ]; then echo "Run this on macOS." >&2; exit 2; fi
. "$(dirname "$0")/run-on-host-acceptance-setup.sh"

pin=${1:-temurin:21}
case "$pin" in
    ""|system|*[!A-Za-z0-9.:+_-]*)
        echo "usage: $0 [pin]   a Coursier JVM id other than system, such as temurin:21" >&2; exit 2 ;;
esac
project=$(pwd -P)
source_fixture=$project/src/probe/mill-fixture
[ -x "$source_fixture/mill" ] || { echo "Run this from the repository root." >&2; exit 2; }
jdk_home=$(cd "${JAVA_HOME:-/nonexistent}" 2>/dev/null && pwd -P) && [ -x "$jdk_home/bin/java" ] ||
    { echo "JAVA_HOME must name the granted JDK." >&2; exit 2; }
# As RunOnHostPrereqs.coursierCacheRoot reads it.
coursier_root=$(cd "${COURSIER_CACHE:-$HOME/Library/Caches/Coursier}" 2>/dev/null && pwd -P) ||
    { echo "no Coursier cache at ${COURSIER_CACHE:-$HOME/Library/Caches/Coursier}" >&2; exit 2; }
# Paths are interpolated into sbt's command parser in the emit and into the profile's string
# literals, where a quote or backslash would end the quoting.
safe_path() { # what value
    case "$2" in
        *[\'\"\\]*) echo "$1 contains a quote or backslash and cannot be interpolated safely: $2" >&2; exit 2 ;;
    esac
}
safe_path "the checkout path" "$project"
safe_path "JAVA_HOME" "$jdk_home"
acceptance_require_idle "/private/tmp/ko-agent-$(id -u)" "$project" || exit 1

# A fixed path: the run-on-host cache is per project path, so a path new to each run would leave
# a cache behind each time.
work=$project/target/mill-pinned-jvm
fixture=$work/pinned-jvm-fixture
java_home_file=$fixture/out/mill-daemon/cache/java-home
rm -rf "$work"; mkdir -p "$fixture" || exit 1
cp "$source_fixture/mill" "$source_fixture/build.mill.yaml" "$fixture/" || exit 1
grep -qxF 'mill-jvm-version: system' "$fixture/build.mill.yaml" ||
    { echo "$source_fixture/build.mill.yaml has no 'mill-jvm-version: system' line to replace" >&2; exit 1; }

echo "machine"
printf '  macOS %s, %s\n' "$(sw_vers -productVersion)" "$(uname -m)"
printf '  JAVA_HOME: %s (%s)\n' "$jdk_home" "$("$jdk_home/bin/java" -version 2>&1 | sed -n 1p)"
printf '  mill %s, pin %s\n' "$(grep -m1 -o '"[0-9][^"]*"' "$fixture/mill" | tr -d '"')" "$pin"

# The emit's temporary directory is this run's alone (EmitRunOnHostProfile.newSessionTmp).
SESSION_TMP=""
cleanup() {
    case "$SESSION_TMP" in /private/tmp/ko-agent-*-accept/*/tmp) rm -rf "${SESSION_TMP%/tmp}" ;; esac
    # A build directory left under the project would be met by the next launch's provisioning.
    rm -rf "$fixture"
}
trap cleanup EXIT

# Emitted before the pin replaces `system`, so the profile grants no pinned JDK: the rows add that
# grant themselves.
echo "emitting the mill profile, for $fixture"
sbt -batch "Test/runMain agentsandbox.launcher.EmitRunOnHostProfile \"$work/base.sb\" \
        src/main/resources/agentsandbox/SeatbeltProfile.SystemPaths.txt mill \"$fixture\"" \
    >"$work/emit.log" 2>&1 || { echo "emit failed:"; tail -20 "$work/emit.log"; exit 1; }
sbt --jvm-client -batch shutdown >/dev/null 2>&1
. "$work/base.sb.env"
cache_v1=$(sed -n 's/^run-on-host cache: //p' "$work/emit.log")
mill_executable=$(sed -n 's/^executable: //p' "$work/emit.log")
[ -n "$cache_v1" ] && [ -x "$mill_executable" ] ||
    { echo "emit named no run-on-host cache or no mill executable ($work/emit.log)" >&2; exit 1; }
safe_path "the command's temporary directory" "$SESSION_TMP"

# The supervisor's closed environment (RunOnHostSandbox.commandEnvironment) less its proxy settings.
# exec, because with_timeout kills the pid it backgrounds: without it that pid is a subshell and the
# kill would orphan the command.
closed_env() { # command...
    account=$(id -un)
    exec env -i \
        PATH="$jdk_home/bin:/usr/bin:/bin:/usr/sbin:/sbin" JAVA_HOME="$jdk_home" \
        HOME="$HOME" ${LANG:+"LANG=$LANG"} ${LC_ALL:+"LC_ALL=$LC_ALL"} \
        TMPDIR="$SESSION_TMP" COURSIER_CACHE="$cache_v1" USER="$account" LOGNAME="$account" \
        _JAVA_OPTIONS="-Djava.io.tmpdir=\"$SESSION_TMP\" -Djava.util.prefs.userRoot=\"$SESSION_TMP\" \
-Djava.net.preferIPv4Stack=true" \
        "$@"
}
# A hang ends the row, not the probe.
with_timeout() { # seconds command...
    limit=$1; shift
    "$@" & child=$!
    ( sleep "$limit"; kill "$child" 2>/dev/null ) & watchdog=$!
    wait "$child"; status=$?
    kill "$watchdog" 2>/dev/null; wait "$watchdog" 2>/dev/null
    return $status
}
# The launcher file itself, as the acceptance test's "read and execute the mill launcher" row runs it.
run_mill() { # profile log
    ( cd "$fixture" && with_timeout 300 closed_env \
        /usr/bin/sandbox-exec -f "$1" "$mill_executable" --no-daemon --version ) >"$2" 2>&1
}
said() { # log: what it says, less the JVM's own notices, stack frames and Coursier's progress
    grep -v -e '^Picked up ' -e '^WARNING: ' -e '^[[:space:]]*at ' -e '^Downloading ' -e '^  not found: ' "$1" |
        sed -n '1,4p' | cut -c1-150 | sed 's/^/      /'
}

# Unconfined, since no proxy runs here; a supervisor's first command fetches the same jars through
# its proxy.
echo "fetching Mill's own classpath into the run-on-host cache, unconfined ($cache_v1)"
( cd "$fixture" && closed_env "$mill_executable" --no-daemon --version ) >"$work/warm.log" 2>&1 ||
    { echo "the fixture does not run unconfined:"; said "$work/warm.log"; exit 1; }

echo "control: mill-jvm-version: system under the profile"
if run_mill "$work/base.sb" "$work/control.log" && grep -q '^java\.home: ' "$work/control.log"
then printf '  ran %s\n' "$(sed -n 's/^java\.home: //p' "$work/control.log")"
else
    echo "  it does not run, so the rows would measure nothing ($work/control.log):"
    said "$work/control.log"
    exit 1
fi

sed "s/^mill-jvm-version: system\$/mill-jvm-version: $pin/" "$source_fixture/build.mill.yaml" \
    > "$fixture/build.mill.yaml"
echo "provisioning $pin: the launcher, unconfined, in your environment ($work/provision.log)"
echo "  the first run for a pin downloads its JDK"
( cd "$fixture" && "$mill_executable" --no-daemon --version ) >"$work/provision.log" 2>&1 ||
    { echo "the provisioning run failed:"; said "$work/provision.log"; exit 1; }
[ -f "$java_home_file" ] || { echo "the provisioning run left no $java_home_file" >&2; exit 1; }

# The file is a JSON pair (`CoursierClient.cached`): the key, then the home.
recorded_field() { # index
    /usr/bin/perl -MJSON::PP -e 'local $/; print JSON::PP->new->decode(<STDIN>)->[$ARGV[0]]' "$1" < "$java_home_file"
}
record_home() { # key home
    /usr/bin/perl -MJSON::PP -e 'print JSON::PP->new->encode([@ARGV])' "$1" "$2" > "$java_home_file"
}
# The first check of RunOnHostPrereqs.resolveJdkHome a canonical home fails, or nothing.
jdk_home_refusal() { # canonical-home
    java=$(/usr/bin/perl -MCwd=realpath -e 'print realpath(shift) // ""' "$1/bin/java")
    case "$1/" in
        "$coursier_root"/*/*/) ;;
        *) echo "it is not two or more levels inside $coursier_root"; return ;;
    esac
    case "$java" in
        "$1"/*) [ -f "$java" ] && [ -x "$java" ] || echo "bin/java is not an executable file" ;;
        *) echo "bin/java resolves outside it, to ${java:-nothing}" ;;
    esac
}

pinned_key=$(recorded_field 0)
recorded_home=$(recorded_field 1)
pinned_home=$(cd "$recorded_home" 2>/dev/null && pwd -P) ||
    { echo "$java_home_file names no directory: $(cat "$java_home_file")" >&2; exit 1; }
safe_path "the pinned home" "$pinned_home"
echo
echo "the java-home file the provisioning run wrote"
printf '  key:  %s\n' "$pinned_key"
printf '  home: %s\n' "$recorded_home"
[ "$pinned_home" = "$recorded_home" ] || printf '  canonical: %s\n' "$pinned_home"
printf '  %s\n' "$("$pinned_home/bin/java" -version 2>&1 | sed -n 1p)"
refusal=$(jdk_home_refusal "$pinned_home")
if [ -z "$refusal" ]
then echo "  the home passes the checks JAVA_HOME passes (RunOnHostPrereqs.resolveJdkHome)"
else echo "  the home fails a check JAVA_HOME passes (RunOnHostPrereqs.resolveJdkHome): $refusal"; fi
case "$pinned_home" in
    "$coursier_root"/arc/*) echo "  it is inside your Coursier archive cache, $coursier_root/arc" ;;
    *) echo "  it is outside your Coursier archive cache, $coursier_root/arc" ;;
esac
distinct=1
if [ "$pinned_home" = "$jdk_home" ]; then
    distinct=0
    echo "  it is the JDK JAVA_HOME names: the rows that withhold or swap the grant are skipped"
fi

# base.sb with the pinned home granted as JAVA_HOME's is: read and execute on the home, metadata on
# each ancestor. In place after JAVA_HOME's grant, so the guard denies stay last.
{
    ancestor=${pinned_home%/*}
    while [ -n "$ancestor" ]; do
        printf '(allow file-read-metadata file-test-existence (literal "%s"))\n' "$ancestor"
        ancestor=${ancestor%/*}
    done
    printf '(allow process-exec* file-read* (subpath "%s"))\n' "$pinned_home"
} > "$work/grant.sb"
/usr/bin/awk -v grant="$work/grant.sb" \
    -v own="(allow process-exec* file-read* (subpath \"$jdk_home\"))" '
    { print }
    $0 == own { while ((getline rule < grant) > 0) print rule; close(grant); found = 1 }
    END { exit found ? 0 : 3 }' "$work/base.sb" > "$work/granted.sb" ||
    { echo "$work/base.sb has no grant of $jdk_home to place the pinned home's after" >&2; exit 1; }

rows=0
row() { # label profile key home: the java-home file the row starts with, none for an empty key
    rows=$((rows + 1)); log=$work/row-$rows.log
    rm -f "$java_home_file"
    [ -z "$3" ] || record_home "$3" "$4"
    before=$(cat "$java_home_file" 2>/dev/null)
    : > "$work/stamp"
    run_mill "$2" "$log"; exit_code=$?
    after=$(cat "$java_home_file" 2>/dev/null)
    ran=$(sed -n 's/^java\.home: //p' "$log" | sed -n 1p)
    case "$ran" in
        "") jvm="no JVM" ;;
        "$pinned_home"|"$recorded_home") jvm="the pinned JDK" ;;
        "$jdk_home") jvm="JAVA_HOME's JDK" ;;
        *) jvm="another JDK, $ran" ;;
    esac
    if [ -z "$before$after" ]; then file_after="not written"
    elif [ "$after" = "$before" ]; then file_after="unchanged"
    elif [ -z "$after" ]; then file_after="removed"
    else file_after="written, $after"; fi
    fetched=$(find "$cache_v1" -type f -newer "$work/stamp" | wc -l | tr -d ' ')
    printf '  %s\n' "$1"
    printf '      exit %s, ran %s; %s files written under the run-on-host cache; java-home file %s\n' \
        "$exit_code" "$jvm" "$fetched" "$file_after"
    [ "$exit_code" -eq 0 ] || said "$log"
}

echo
echo "rows: mill --no-daemon --version under the command profile, no proxy running"
row "java-home file present, its home granted" "$work/granted.sb" "$pinned_key" "$recorded_home"
[ "$distinct" = 0 ] ||
    row "java-home file present, its home not granted" "$work/base.sb" "$pinned_key" "$recorded_home"
row "java-home file absent, the pinned home granted" "$work/granted.sb" "" ""
row "java-home file under another key, the pinned home granted" "$work/granted.sb" \
    "stale $pinned_key" "$recorded_home"
[ "$distinct" = 0 ] ||
    row "java-home file names JAVA_HOME's JDK under the pin's key" "$work/base.sb" "$pinned_key" "$jdk_home"

echo
echo "logs: $work"
