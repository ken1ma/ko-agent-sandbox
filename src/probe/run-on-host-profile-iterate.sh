#!/bin/sh
# Discover the profile's runtime authority (run-on-host.md "The Seatbelt profile") the only way
# it allows — by running a real build and reading what it actually needs, never by listing what
# the host happens to have. Run it when a command stops under the profile and nothing names the
# missing grant.
#
# `(debug deny)` makes denials visible, which is what Bazel's darwin-sandbox puts at the top of
# every generated profile. `(trace)` — the other obvious instrument — is restricted on macOS 26 and
# writes nothing, and unified-log denials have their paths redacted unless private-data logging is
# enabled system-wide.
#
# The searches below do not rely on any of that: what is always reliable is whether the command
# works, so they start from a set that runs and remove cumulatively, keeping only grants whose
# absence breaks it.
#
#   sh src/probe/run-on-host-profile-iterate.sh checks         # which check fails? run this first
#   sh src/probe/run-on-host-profile-iterate.sh ops "<command>"    # which operations does it need?
#   sh src/probe/run-on-host-profile-iterate.sh paths          # what does /bin/sh need?
#   sh src/probe/run-on-host-profile-iterate.sh paths "$JAVA_HOME/bin/java -version"   # ... or the JDK
#   sh src/probe/run-on-host-profile-iterate.sh narrow         # drop every grant that is not needed
#   sh src/probe/run-on-host-profile-iterate.sh mach-route     # does `open` start a program outside the profile?
#   sh src/probe/run-on-host-profile-iterate.sh mach ["<sbt command>"]   # which Mach services does sbt fail without?
#   sh src/probe/run-on-host-profile-iterate.sh mach-proxy [native-image]   # ... and the host proxy, in either form?
#
# Whether the current grant set builds is src/probe/run-on-host-profile-gate.sh's question, not this one's.
#
# Runtime authority accumulates in src/main/resources/agentsandbox/SeatbeltProfile.RuntimeAuthority.txt,
# which you edit by hand: a line added because a command failed once is a grant that outlives every
# later command, so each belongs there only if it is a stable runtime read and not a path into user
# data.
set -u
if [ "$(uname -s)" != "Darwin" ]; then echo "Run this on macOS." >&2; exit 2; fi
. "$(dirname "$0")/run-on-host-gate-setup.sh"
gate_require_idle "/private/tmp/ko-agent-$(id -u)" "$(pwd -P)" || exit 1

mode=${1:-checks}
command=${2:-"about"}
work=${TMPDIR:-/tmp}/ko-agent-run-on-host-profile
authority=src/main/resources/agentsandbox/SeatbeltProfile.RuntimeAuthority.txt
mkdir -p "$work"
[ -f "$authority" ] ||
    printf '# One absolute path per line. Prefix with "x " if it must also be executable.\n' > "$authority"

emit() {
    rm -f "$work/command.env"
    sbt -batch "Test/runMain agentsandbox.launcher.EmitRunOnHostProfile $work/command.sb $1" \
        >"$work/emit.log" 2>&1 || { echo "emit failed:"; tail -20 "$work/emit.log"; return 1; }
    mv "$work/command.sb.env" "$work/command.env"
}

# -java-home because the sbt script declares `java_cmd=java` and would otherwise resolve
# /usr/bin/java from PATH, which the profile does not grant.
#
# No -Dsbt.server.autostart=false, which sbt 2 cannot honour: its own --no-server
# is "run sbtn, and fail if it cannot connect to a server", and sets that same flag. sbt 2 is
# client/server by construction, so the server starts inside the sandbox and its state goes to the
# command's temporary directory with everything else.
# The environment is the command's contract (RunOnHostSandbox): COURSIER_CACHE routes to the
# run-on-host cache, _JAVA_OPTIONS reaches the server the client forks where -D flags do not, and
# the two socket directories keep sbt inside the command's temporary directory.
# `run_bound` seconds, 0 for none: `mach` sets it, because an sbt client waits without end for a
# server that a denied lookup ended. The alarm is kept across each exec down to the client.
run_command() { # log [profile] [sbt-command]
    . "$work/command.env"
    tool_options="-Djava.io.tmpdir=$SESSION_TMP -Djava.util.prefs.userRoot=$SESSION_TMP"
    PATH="$JAVA_HOME/bin:$PATH" \
    COURSIER_CACHE=$(sed -n 's/^run-on-host cache: //p' "$work/emit.log") \
    XDG_RUNTIME_DIR=$SESSION_TMP SBT_GLOBAL_SERVER_DIR=$SESSION_TMP \
    _JAVA_OPTIONS="$tool_options -Dsbt.global.base=$SESSION_TMP/sbt-global -Dsbt.ivy.home=$SESSION_TMP/ivy-home" \
    /usr/bin/perl -e 'alarm shift; exec @ARGV or die "exec: $!\n"' "${run_bound:-0}" \
    /usr/bin/sandbox-exec -f "${2:-$work/command.sb}" \
        sbt "-Dsbt.global.base=$SESSION_TMP/sbt-global" \
        --jvm-client -batch -java-home "$JAVA_HOME" "${3:-$command}" >"$1" 2>&1
}

# A profile sandbox-exec cannot compile fails exactly as a missing grant does: the child dies
# either way. The difference is on sandbox-exec's own stderr, so it is captured rather than
# discarded, and a profile that will not compile is reported as that rather than as a denial.
dump_profile() {
    echo "--- profile ---"
    sed 's/^/   /' "$1"
    echo "---------------"
}

attempt_profile() {
    if /usr/bin/sandbox-exec -f "$1" /bin/sh -c "$2" >/dev/null 2>"$work/sbx.err"; then
        return 0
    fi
    if grep -qi 'sandbox-exec:.*\(compil\|syntax\|unable\|invalid\)' "$work/sbx.err" 2>/dev/null; then
        echo
        echo "!! the profile does not compile — this is not a missing grant:"
        sed 's/^/   /' "$work/sbx.err"
        dump_profile "$1"
        exit 1
    fi
    return 1
}

# Only these SBPL families take a path filter. Putting an unfiltered one — sysctl-read, say —
# inside an (allow ... (subpath ...)) makes the whole profile invalid.
path_family() {
    case "$1" in
        file-read*|file-write*|file-map-executable|process-exec*|file-ioctl) return 0 ;;
        *) return 1 ;;
    esac
}

# --- mach-lookup -----------------------------------------------------------------------------------
# A rendered profile with its mach-lookup rule (SeatbeltProfile.MachServices) replaced, in place so
# the guard denies stay last: by one global-name rule per line of a names file, or, with no names
# file, by the unfiltered grant — the baseline, since a JDK or a build may need a service the
# rendered rule does not name, and that is what the search is for.
mach_profile() { # rendered-profile names-file|"" out
    if [ -n "$2" ]
    then sed 's/.*/(allow mach-lookup (global-name "&"))/' "$2" > "$work/mach-rules.sb"
    else echo '(allow mach-lookup)' > "$work/mach-rules.sb"
    fi
    awk -v rules="$work/mach-rules.sb" '
        /^\(version 1\)$/ { print; print "(debug deny)"; next }
        /^\(allow mach-lookup \(global-name .*\)$/ {
            while ((getline rule < rules) > 0) print rule
            close(rules); found = 1; next
        }
        { print }
        END { exit found ? 0 : 3 }' "$1" > "$3" || {
        echo "$1 has no mach-lookup rule to replace; this mode measures nothing there." >&2
        exit 1
    }
}

# The names a launchd job definition registers: the MachServices keys of the launchd plists under
# /System/Library, /Library and ~/Library. A key of a nested dictionary (ResetAtClose,
# HideUntilCheckIn) comes along as a name no service has, which the search drops like any other.
# Names a process registers at run time are not here; `mach_search` says so when the full list
# does not run the command, and mach-extra.txt takes them.
mach_candidates() { # out
    for directory in /System/Library/LaunchDaemons /System/Library/LaunchAgents \
        /Library/LaunchDaemons /Library/LaunchAgents "$HOME/Library/LaunchAgents"; do
        for plist in "$directory"/*.plist; do
            [ -f "$plist" ] || continue
            /usr/bin/plutil -extract MachServices xml1 -o - "$plist" 2>/dev/null
        done
    done | sed -n 's|.*<key>\(.*\)</key>.*|\1|p' > "$work/mach-found.txt"
    [ -f "$work/mach-extra.txt" ] || : > "$work/mach-extra.txt"
    cat "$work/mach-found.txt" "$work/mach-extra.txt" | grep -v -e '["\\&]' -e '^$' | sort -u > "$1"
}

# Drop `chunk` from `keep` if `passes` still succeeds without it, else halve it, down to single
# names: cumulative removal as `paths` does it, by halves because the candidates are thousands
# and the needed names few. Greedy like `ops`: of two interchangeable names it keeps the one it
# tested last.
mach_reduce() { # passes keep chunk
    reduce_passes=$1; reduce_keep=$2
    cp "$3" "$work/mach-chunk-0"
    printf '%s\n' "$work/mach-chunk-0" > "$work/mach-queue"
    chunks=1
    while [ -s "$work/mach-queue" ]; do
        chunk=$(sed -n 1p "$work/mach-queue")
        sed 1d "$work/mach-queue" > "$work/mach-queue.rest"; mv "$work/mach-queue.rest" "$work/mach-queue"
        size=$(grep -c . "$chunk")
        [ "$size" != 0 ] || continue
        grep -vxFf "$chunk" "$reduce_keep" > "$work/mach-without.txt"
        if "$reduce_passes" "$work/mach-without.txt"; then
            printf '  drop    %s\n' "$([ "$size" = 1 ] && cat "$chunk" || echo "$size names")"
            cp "$work/mach-without.txt" "$reduce_keep"
        elif [ "$size" = 1 ]; then
            printf '  KEEP    %s\n' "$(cat "$chunk")"
        else
            half=$(( (size + 1) / 2 ))
            sed -n "1,${half}p" "$chunk" > "$work/mach-chunk-$chunks"
            sed "1,${half}d" "$chunk" > "$work/mach-chunk-$((chunks + 1))"
            { printf '%s\n' "$work/mach-chunk-$chunks" "$work/mach-chunk-$((chunks + 1))"
              cat "$work/mach-queue"; } > "$work/mach-queue.rest"
            mv "$work/mach-queue.rest" "$work/mach-queue"
            chunks=$((chunks + 2))
        fi
    done
}

# The names the quick command needs first — `java -version`, since a JVM start is seconds and
# `slow` is a build or a served fetch: the slow command is then tried with those names alone, and
# halves the rest only if that fails. `quick_label` names the quick command in the output.
mach_search() { # quick-passes slow-passes baseline-passes attempt-log
    all=$work/mach-all.txt; needed=$work/mach-needed.txt
    if ! "$3"; then
        echo "with mach-lookup unfiltered the profile still does not run the measured command, so no" \
            "lookup is the cause:" >&2
        tail -20 "$4" >&2
        exit 1
    fi
    echo "the rendered profile with mach-lookup unfiltered: PASS"
    echo "collecting candidate names from the launchd plists"
    mach_candidates "$all"
    echo "$(grep -c . "$all") candidates, $(grep -c . "$work/mach-extra.txt") of them from $work/mach-extra.txt"
    : > "$work/mach-none.txt"
    if ! "$2" "$all"; then
        cat >&2 <<EOF
every candidate granted and it still fails: a name it looks up is in no launchd plist.
Read the denied names while rerunning this mode, and add them to $work/mach-extra.txt, one per line:
  log stream --style compact --predicate 'sender == "Sandbox" AND eventMessage CONTAINS "mach-lookup"'
The attempt's own output:
EOF
        tail -20 "$4" >&2
        exit 1
    fi
    echo "all candidates: PASS"
    if "$2" "$work/mach-none.txt"; then
        echo "no name at all: PASS — the measured command fails on no denied lookup."
        : > "$needed"
    else
        echo "$quick_label, removing by halves:"
        cp "$all" "$needed"
        mach_reduce "$1" "$needed" "$all"
        if "$2" "$needed"; then
            echo "the measured command runs with those names alone."
        else
            echo "the measured command needs more than those names. Removing the rest by halves:"
            cp "$needed" "$work/mach-java.txt"
            grep -vxFf "$work/mach-java.txt" "$all" > "$work/mach-rest.txt"
            cp "$all" "$needed"
            mach_reduce "$2" "$needed" "$work/mach-rest.txt"
            echo "the first names again, with the rest settled:"
            mach_reduce "$2" "$needed" "$work/mach-java.txt"
        fi
    fi
    echo
    echo "the names it needs ($needed):"
    sed 's/^/  /' "$needed"
    echo
    echo "A name is listed because the measured command fails without it. A lookup whose denial the"
    echo "command survives is not listed, so the gate decides whether a build under these names behaves."
}

case "$mode" in
ops)
    # Which SBPL operation families a command needs, by the same cumulative removal `paths` uses —
    # paths held wide open at (subpath "/") so only the operation varies. Run this first when
    # `paths` reports that granting every root entry still fails: that is what "not only a path"
    # looks like, and holding operations fixed cannot see it.
    probe_command=${2:-"/bin/sh -c 'echo ok'"}
    families="file-read* file-write* file-map-executable process-exec* process-fork process-info*
              sysctl-read sysctl-write mach-lookup mach-register ipc-posix-shm ipc-posix-sem
              signal network* system-socket iokit-open pseudo-tty file-ioctl"
    keep=$(printf '%s' "$families" | tr -s ' \n' ' ')

    # A family under test must be genuinely absent when dropped: an unconditional
    # (allow file-read* file-map-executable process-exec* (subpath "/")) would re-grant three of
    # the families being measured and make their removal untestable.
    # Path-filtered families take (subpath "/"); the rest take no filter, which is a syntax error
    # for them.
    try_ops() {
        printf '(version 1)\n(debug deny)\n(deny default)\n' > "$work/ops.sb"
        for family in $1; do
            if path_family "$family"
            then printf '(allow %s (subpath "/"))\n' "$family" >> "$work/ops.sb"
            else printf '(allow %s)\n' "$family" >> "$work/ops.sb"
            fi
        done
        attempt_profile "$work/ops.sb" "$probe_command"
    }

    echo "measuring: $probe_command"
    if ! try_ops "$keep"; then
        echo "every family granted and it still fails — the command is broken, not the profile." >&2
        dump_profile "$work/ops.sb"
        exit 1
    fi
    echo "all families: PASS. Removing cumulatively:"
    for f in $keep; do
        candidate=$(printf '%s' "$keep" | tr ' ' '\n' | grep -vxF "$f" | tr '\n' ' ')
        if try_ops "$candidate"; then
            printf '  drop    %s\n' "$f"
            keep=$candidate
        else
            printf '  KEEP    %s\n' "$f"
        fi
    done
    # Greedy removal finds *a* minimal set, not *the* minimal one: where two families are
    # interchangeable it keeps whichever it happened to test last, which is how sysctl-write can
    # survive while sysctl-read drops. Try the weaker spelling of each before believing the result.
    echo
    echo "downgrades — is a weaker family enough?"
    for pair in "sysctl-write sysctl-read" "file-write* file-read*" "mach-register mach-lookup"; do
        strong=${pair% *}; weak=${pair#* }
        case " $keep " in *" $strong "*) ;; *) continue ;; esac
        candidate=$(printf '%s' "$keep" | tr ' ' '\n' | grep -vxF "$strong" | tr '\n' ' ')
        if try_ops "$candidate $weak"; then
            printf '  %s suffices in place of %s\n' "$weak" "$strong"
            keep="$candidate $weak"
        else
            printf '  %s is genuinely needed; %s is not enough\n' "$strong" "$weak"
        fi
    done

    echo
    dump_profile "$work/ops.sb"
    echo "the operations it needs: $keep"
    printf '%s\n' "$keep" > src/probe/seatbelt-runtime-operations.txt
    echo "written to src/probe/seatbelt-runtime-operations.txt, which 'paths' uses as its base"
    ;;
paths)
    # The minimal set of trees /bin/sh needs, by cumulative removal.
    #
    # Testing each denial independently cannot work here: what a loader needs is reachable by more
    # than one route, so every single removal is survivable and the "individually required" set
    # comes out empty while the union of it fails. Removing cumulatively — drop a tree only if the
    # set that remains still works — is the same algorithm `narrow` uses, and it converges.
    base='(deny default)'
    # The families `ops` measured, so a path search is not defeated by a missing operation. Without
    # this the JDK reports "not a path" when the truth is "not only a path".
    if [ -f src/probe/seatbelt-runtime-operations.txt ]; then
        ops=$(cat src/probe/seatbelt-runtime-operations.txt)
    else
        ops='file-read* process-exec*'
    fi
    # The JDK is measured, not assumed. Seeding the *bundle* rather than JAVA_HOME only widens the
    # starting point; the descent pass then reports whether Contents/Home would have sufficed, so
    # "a macOS JDK needs libjli.dylib from Contents/MacOS" is a result rather than a premise.
    jdk_seed=""
    if [ -n "${JAVA_HOME:-}" ]; then
        jdk_seed=$JAVA_HOME
        case "$JAVA_HOME" in */Contents/Home) jdk_seed=${JAVA_HOME%/Home} ;; esac
    fi
    keep="$work/keep.txt"
    { ls -1ad /.[!.]* /* /private/* 2>/dev/null; [ -n "$jdk_seed" ] && printf '%s\n' "$jdk_seed"; } \
        | while IFS= read -r t; do [ -e "$t" ] && printf '%s\n' "$t"; done > "$keep"

    profile_from() {
        printf '(version 1)\n(debug deny)\n%s\n' "$base" > "$work/paths.sb"
        filtered=""
        for family in $ops; do
            if path_family "$family"
            then filtered="$filtered $family"
            else printf '(allow %s)\n' "$family" >> "$work/paths.sb"
            fi
        done
        printf '(allow%s%s' "$filtered" "$granted" >> "$work/paths.sb"
        while IFS= read -r t; do
            case "$t" in
                "L "*) printf ' (literal "%s")' "${t#L }" >> "$work/paths.sb" ;;
                *)     printf ' (subpath "%s")' "$t" >> "$work/paths.sb" ;;
            esac
        done < "$1"
        printf ')\n' >> "$work/paths.sb"
    }
    passes() {
        profile_from "$1"
        attempt_profile "$work/paths.sb" "$probe_command"
    }

    # (subpath "/") passes while the union of every (subpath "/child") fails, so what is missing is
    # the root component itself: resolving /bin/sh authorizes "/" before "/bin". Which grant on "/"
    # suffices decides how much this costs — a literal names the directory entry alone and reveals
    # nothing about its contents.
    # What is already granted, so the measurement answers "what *else*" rather than rediscovering
    # the prerequisites' paths. The command under test defaults to a shell.
    probe_command=${2:-"/bin/sh -c 'echo ok'"}
    granted=""
    while IFS= read -r line; do
        case "$line" in ''|\#*) continue ;; esac
        path=${line#x }
        granted="$granted (subpath \"$path\")"
    done < "$authority"
    echo "measuring: $probe_command"

    root_grant=""
    for candidate in \
        '(allow file-read-metadata (literal "/"))' \
        '(allow file-read* (literal "/"))' \
        '(allow file-read* file-map-executable process-exec* (literal "/"))'
    do
        base="(deny default)$candidate"
        if passes "$keep"; then
            root_grant="$candidate"
            echo "root component: $candidate is enough"
            break
        fi
    done
    if [ -z "$root_grant" ]; then
        base='(deny default)'
        echo "no grant on \"/\" alone rescues the union — the gap is not a path." >&2
        dump_profile "$work/paths.sb"
        exit 1
    fi
    echo "all root entries: PASS. Removing cumulatively:"
    cp "$keep" "$work/snapshot.txt"
    while IFS= read -r tree; do
        grep -vxF "$tree" "$keep" > "$work/candidate.txt"
        if passes "$work/candidate.txt"; then
            printf '  drop    %s\n' "$tree"
            cp "$work/candidate.txt" "$keep"
        else
            printf '  KEEP    %s\n' "$tree"
        fi
    done < "$work/snapshot.txt"
    echo
    # A kept root entry is rarely the answer: /System is required, but a command has no business
    # reading all of it. Try replacing each with its children, keeping the descent only while the
    # command still works, so the result is as deep as the evidence allows.
    echo
    echo "descending into each kept tree:"
    changed=1
    while [ "$changed" = 1 ]; do
        changed=0
        while IFS= read -r tree; do
            children=$(ls -1d "$tree"/* 2>/dev/null) || continue
            [ -n "$children" ] || continue
            case "$tree" in "L "*) continue ;; esac
            grep -vxF "$tree" "$keep" > "$work/descend.txt"
            # The entry itself stays as a literal: resolving a child authorizes its parent as a
            # path component, and a grant on the children does not cover it. Without this a tree
            # can never be descended, and the result reads as "the whole tree is required".
            printf 'L %s\n' "$tree" >> "$work/descend.txt"
            printf '%s\n' "$children" >> "$work/descend.txt"
            if passes "$work/descend.txt"; then
                printf '  descend %s -> %s children\n' "$tree" "$(printf '%s' "$children" | grep -c .)"
                cp "$work/descend.txt" "$keep"
                changed=1
                break
            fi
        done < "$keep"
        [ "$changed" = 1 ] && {
            cp "$keep" "$work/snapshot.txt"
            while IFS= read -r tree; do
                grep -vxF "$tree" "$keep" > "$work/candidate.txt"
                if passes "$work/candidate.txt"; then cp "$work/candidate.txt" "$keep"; fi
            done < "$work/snapshot.txt"
        }
    done

    echo
    echo "the minimal set it needs:"
    sed 's/^/  /' "$keep"
    # Regenerate: the last profile written was a failed attempt, not the answer.
    profile_from "$keep"
    dump_profile "$work/paths.sb"
    echo
    ;;
checks)
    # A process that dies before writing anything says nothing about which grant is missing. This
    # runs checks in order, from the smallest possible program to a real build, and stops at the
    # first that fails, so the missing grant is one that check already needs. Output is not redirected:
    # the reason usually goes to the terminal, and redirecting is how it was lost.
    emit "$authority" || exit 1
    . "$work/command.env"
    check() {
        printf '\n--- %s\n' "$1"; shift
        if /usr/bin/sandbox-exec -f "$work/command.sb" "$@"; then
            echo "    ok"
        else
            echo "    FAILED (exit $?) — this check is the first to require the missing grant"
            exit 1
        fi
    }
    # Only binaries the profile grants: a check that fails because it reached for an ungranted
    # binary says nothing about the program it claims to test.
    check "the loader, through a granted shell"           /bin/sh -c 'echo hello'
    check "the sbt script's interpreter: /usr/bin/env sh"   /usr/bin/env sh -c 'echo hello'
    check "bash, which the inner sbt script needs"        /bin/bash -c 'echo hello'
    check "the coreutils that script calls"               /bin/bash -c 'uname -s; dirname /a/b; basename /a/b'
    check "the JDK"                                       "$JAVA_HOME/bin/java" -version
    check "the sbt script, no build"                     sbt -java-home "$JAVA_HOME" --script-version
    echo
    echo "every check passed; the gate is next: sh src/probe/run-on-host-profile-gate.sh quick"
    ;;
narrow)
    emit "$authority" || exit 1
    if ! run_command "$work/base.log"; then
        echo "the current grant set does not run the command; fix that with the gate before narrowing." >&2
        exit 1
    fi
    echo "the baseline runs the command. Removing one grant at a time."
    kept="$work/kept.txt"; : > "$kept"
    grep -vE '^\s*(#|$)' "$authority" | while IFS= read -r line; do
        grep -vE '^\s*(#|$)' "$authority" | grep -vxF "$line" > "$work/without.txt"
        if emit "$work/without.txt" && run_command "$work/try.log"; then
            printf '  drop    %s\n' "$line"
        else
            printf '  KEEP    %s\n' "$line"
            printf '%s\n' "$line" >> "$kept"
        fi
    done
    echo
    echo "the grants that earned their place: $kept"
    echo "review it, then replace the body of $authority with it."
    ;;
mach-route)
    # Whether a command, /usr/bin being executable, starts a program outside the profile through
    # LaunchServices. Each confined row has a control, the same `open` unconfined: a control that
    # starts nothing — an approval prompt, a changed default application — leaves its row undecided.
    emit "$authority" || exit 1
    . "$work/command.env"
    project=$(pwd -P)
    route=$project/target/mach-route
    rm -rf "$route"; mkdir -p "$route"
    confined() { /usr/bin/sandbox-exec -f "$work/command.sb" /bin/sh -c "$1" >"$work/route.out" 2>&1; }
    await() { # seconds condition...
        tries=$(( $1 * 2 )); shift
        while [ "$tries" -gt 0 ]; do
            "$@" && return 0
            tries=$((tries - 1)); sleep 0.5
        done
        return 1
    }
    row() { printf '%-64s %s\n' "$1" "$2"; }

    # R1: an application of the system's.
    calculator_runs() { pgrep -x Calculator >/dev/null; }
    if calculator_runs; then echo "Quit Calculator first: R1 tells a start by whether it runs." >&2; exit 2; fi
    echo "R1 open -a Calculator"
    /usr/bin/open -g -a Calculator
    if await 10 calculator_runs; then row "  control, unconfined" "STARTED"; r1_control=1
    else row "  control, unconfined" "not started: R1 decides nothing"; r1_control=0; fi
    pkill -x Calculator; await 10 sh -c '! pgrep -x Calculator >/dev/null'
    if [ "$r1_control" = 1 ]; then
        confined "/usr/bin/open -g -a Calculator"; status=$?
        if await 10 calculator_runs
        then row "  under the command profile" "STARTED: LaunchServices is reachable"
        else row "  under the command profile" "not started (open exited $status: $(sed -n 1p "$work/route.out"))"
        fi
        pkill -x Calculator
    fi

    # R2: a program the command wrote, run by Terminal, which no profile confines. The marker is
    # where the profile denies a write, so its existence is the program having run outside it.
    echo "R2 open PROJECT/target/mach-route/<script>.command (it opens Terminal windows; close them after)"
    script_text() { printf '#!/bin/sh\n: > "%s"\n' "$1"; }
    for kind in control confined; do
        marker=$work/mach-route-marker-$kind
        script=$route/$kind.command
        rm -f "$marker"
        if [ "$kind" = control ]; then
            script_text "$marker" > "$script"; chmod +x "$script"
            /usr/bin/open -g "$script"
            if await 20 test -e "$marker"; then row "  control, unconfined" "RAN"
            else row "  control, unconfined" "did not run: R2 decides nothing"; break; fi
        else
            if confined ": > '$marker'" || [ -e "$marker" ]; then
                row "  under the command profile" "the marker is writable under the profile: R2 decides nothing"
                break
            fi
            script_text "$marker" > "$route/text"
            confined "cp '$route/text' '$script' && chmod +x '$script' && /usr/bin/open -g '$script'"; status=$?
            if await 20 test -e "$marker"
            then row "  under the command profile" "RAN: a program the command wrote ran outside the profile"
            else row "  under the command profile" "did not run (open exited $status: $(sed -n 1p "$work/route.out"))"
            fi
            row "  extended attributes of the script the command wrote" \
                "$(xattr "$script" 2>/dev/null | paste -sd ' ' -)"
        fi
    done
    rm -rf "$route" "$work"/mach-route-marker-*
    ;;
mach)
    emit "$authority" || exit 1
    . "$work/command.env"
    # emit's own sbt server holds this project's portfile (the gate ends it for the same reason).
    sbt --jvm-client -batch shutdown >/dev/null 2>&1
    run_bound=${MACH_BOUND:-600}
    # A build of its own inside the project the profile grants: this checkout's target/ links into
    # the store of the unconfined sbt that emit ran, which the profile denies (run-on-host.md,
    # the sbt server's state), and the broker's sweep of those links is not this probe's to run.
    fixture=$(pwd -P)/target/mach-fixture
    rm -rf "$fixture"; mkdir -p "$fixture/project"
    cp project/build.properties "$fixture/project/"
    : > "$fixture/build.sbt"
    fixture_command() { (cd "$fixture" && run_command "$@"); }
    mach_profile "$work/command.sb" "" "$work/mach-open.sb"
    end_server() {
        [ ! -e "$fixture/project/target/active.json" ] ||
            fixture_command "$work/mach-shutdown.log" "$work/mach-open.sb" shutdown
    }
    quick_passes() {
        mach_profile "$work/command.sb" "$1" "$work/mach.sb"
        attempt_profile "$work/mach.sb" "'$JAVA_HOME/bin/java' -version"
    }
    # The server a passing attempt leaves would serve the next attempt's client from under the
    # earlier attempt's names, so it is ended under the unfiltered profile, which the baseline proved.
    build_passes() {
        mach_profile "$work/command.sb" "$1" "$work/mach.sb"
        fixture_command "$work/mach-try.log" "$work/mach.sb"; result=$?
        end_server
        if [ -e "$fixture/project/target/active.json" ]; then
            echo "an sbt server outlived its shutdown ($fixture/project/target/active.json," \
                "$work/mach-shutdown.log); end it, then rerun." >&2
            exit 1
        fi
        return "$result"
    }
    build_baseline() {
        fixture_command "$work/mach-try.log" "$work/mach-open.sb"; result=$?
        end_server
        return "$result"
    }
    quick_label="java -version"
    echo "measuring: sbt $command in $fixture, each attempt bounded at ${run_bound}s (MACH_BOUND)"
    mach_search quick_passes build_passes build_baseline "$work/mach-try.log"
    rm -rf "$fixture"
    ;;
mach-proxy)
    image=${2:-}
    if [ -n "$image" ]; then
        [ -f "$image" ] && [ -x "$image" ] || { echo "$image is not an executable file" >&2; exit 2; }
        # Absolute, since the proxy is started from /.
        image=$(cd "$(dirname "$image")" && pwd -P)/$(basename "$image")
        sbt -batch "Test/runMain agentsandbox.launcher.EmitRunOnHostProfile \"$work/proxy.sb\" \
                $authority proxy-image \"$image\"" >"$work/emit-proxy.log" 2>&1 ||
            { echo "emit failed for the proxy:"; tail -20 "$work/emit-proxy.log"; exit 1; }
    else
        emit "$authority" || exit 1
        proxy_cp=$(sed -n 's/^classpath: //p' "$work/emit.log")
        [ -n "$proxy_cp" ] || { echo "emit printed no classpath" >&2; exit 1; }
        sbt -batch "Test/runMain agentsandbox.launcher.EmitRunOnHostProfile \"$work/proxy.sb\" \
                $authority proxy \"$JAVA_HOME\" \"$proxy_cp\"" >"$work/emit-proxy.log" 2>&1 ||
            { echo "emit failed for the proxy:"; tail -20 "$work/emit-proxy.log"; exit 1; }
    fi
    sbt --jvm-client -batch shutdown >/dev/null 2>&1
    # java itself, from /: the proxy's profile grants no shell and no other working directory. A
    # native image has no quicker start than serving, so serving is its quick check too.
    quick_passes() {
        if [ -n "$image" ]; then serve_passes "$1"; return; fi
        mach_profile "$work/proxy.sb" "$1" "$work/mach.sb"
        (cd / && /usr/bin/sandbox-exec -f "$work/mach.sb" "$JAVA_HOME/bin/java" -version) >/dev/null 2>&1
    }
    # Started as RunOnHostSandbox.startProxy starts it, then one fetch through it, which makes it
    # resolve a name and connect.
    proxy_ready() { grep -q 'ko-agent-egress-proxy listening on :[0-9]' "$work/mach-proxy.log"; }
    # Not exec'd: the subshell then reports a JVM that a denied lookup ends with a segmentation
    # fault into the log, where this shell would report it on the terminal at every attempt.
    serve_under() { # profile
        served_profile=$1
        if [ -n "$image" ]
        then set -- "$image" -Djava.net.preferIPv4Stack=true --serve-proxy-on-host
        else set -- "$JAVA_HOME/bin/java" -Djava.net.preferIPv4Stack=true -cp "$proxy_cp" \
            agentsandbox.launcher.AgentSandboxLauncher --serve-proxy-on-host
        fi
        : > "$work/mach-proxy.log"
        (cd / && env -i ${HTTPS_PROXY:+"HTTPS_PROXY=$HTTPS_PROXY"} ${https_proxy:+"https_proxy=$https_proxy"} \
            EGRESS_PROFILE=deny-unless-allowed \
            EGRESS_RULE='deny defaults
allow https://repo1.maven.org/ read' EGRESS_BIND=127.0.0.1:0 \
            /usr/bin/sandbox-exec -f "$served_profile" "$@"; true) \
            >/dev/null 2>"$work/mach-proxy.log" &
        proxy_pid=$!
        result=1
        tries=60
        while [ "$tries" -gt 0 ] && kill -0 "$proxy_pid" 2>/dev/null && ! proxy_ready; do
            tries=$((tries - 1)); sleep 0.5
        done
        if proxy_ready; then
            port=$(sed -n 's/.*ko-agent-egress-proxy listening on :\([0-9]*\).*/\1/p' "$work/mach-proxy.log" |
                sed -n 1p)
            curl -fsS -o /dev/null --max-time 30 --proxy "http://127.0.0.1:$port" \
                https://repo1.maven.org/maven2/ 2>"$work/mach-curl.err" && result=0
        fi
        pkill -P "$proxy_pid" 2>/dev/null; wait "$proxy_pid" 2>/dev/null
        return "$result"
    }
    serve_passes() {
        mach_profile "$work/proxy.sb" "$1" "$work/mach.sb"
        serve_under "$work/mach.sb"
    }
    serve_baseline() {
        mach_profile "$work/proxy.sb" "" "$work/mach-open.sb"
        serve_under "$work/mach-open.sb"
    }
    if [ -n "$image" ]; then quick_label="the image serving"; else quick_label="java -version"; fi
    echo "measuring: the host proxy${image:+ ($image)} serving one fetch of https://repo1.maven.org/maven2/"
    mach_search quick_passes serve_passes serve_baseline "$work/mach-proxy.log"
    ;;
*)
    echo "usage: $0 [checks|ops|paths|narrow|mach-route|mach|mach-proxy] [command|native-image]" >&2; exit 2 ;;
esac
