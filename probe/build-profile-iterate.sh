#!/bin/sh
# Discover PLAN-SBT-ON-HOST.md §2.1's runtime authority the only way it admits — by running a real
# build and reading what it actually needs, never by listing what the host happens to have.
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
#   sh probe/build-profile-iterate.sh floor          # which layer fails? run this first
#   sh probe/build-profile-iterate.sh ops "<command>"    # which operations does it need?
#   sh probe/build-profile-iterate.sh paths          # what does /bin/sh need?
#   sh probe/build-profile-iterate.sh paths "$JAVA_HOME/bin/java -version"   # ... or the JDK
#   sh probe/build-profile-iterate.sh narrow         # drop every grant that is not needed
#
# Whether the current grant set builds is probe/build-profile-gate.sh's question, not this one's.
#
# Runtime authority accumulates in src/main/resources/agentsandbox/runtime-authority.txt, which you edit by hand: a line
# added because a build failed once is a grant that outlives every later build, so each belongs
# there only if it is a stable runtime read and not a path into user data.
set -u
if [ "$(uname -s)" != "Darwin" ]; then echo "Run this on the Mac." >&2; exit 2; fi

mode=${1:-floor}
command=${2:-"about"}
work=${TMPDIR:-/tmp}/ko-agent-build-profile
authority=src/main/resources/agentsandbox/runtime-authority.txt
mkdir -p "$work"
[ -f "$authority" ] || printf '# One absolute path per line. Prefix with "x " if it must also be executable.\n' > "$authority"

emit() {
    rm -f "$work/build.env"
    sbt -batch "Test/runMain agentsandbox.launcher.EmitBuildProfile $work/build.sb $1" \
        >"$work/emit.log" 2>&1 || { echo "emit failed:"; tail -20 "$work/emit.log"; return 1; }
    mv "$work/build.sb.env" "$work/build.env"
}

# -java-home because the sbt launcher declares `java_cmd=java` and would otherwise resolve
# /usr/bin/java from PATH, which the profile does not grant.
#
# No -Dsbt.server.autostart=false, which §3.2 asks for and sbt 2 cannot honour: its own --no-server
# is "run sbtn, and fail if it cannot connect to a server", and sets that same flag. sbt 2 is
# client/server by construction, so the server starts inside the sandbox and its state goes to the
# session temp with everything else.
# The environment is the build's contract (PLAN-SBT-ON-HOST.md §4): COURSIER_CACHE routes to the
# agent cache, JAVA_TOOL_OPTIONS reaches the server the client forks where -D flags do not, and
# the two socket directories keep sbt inside the session temp.
build() {
    . "$work/build.env"
    PATH="$JAVA_HOME/bin:$PATH" \
    COURSIER_CACHE=$(sed -n 's/^agent cache: //p' "$work/emit.log") \
    XDG_RUNTIME_DIR=$SESSION_TMP SBT_GLOBAL_SERVER_DIR=$SESSION_TMP \
    JAVA_TOOL_OPTIONS="-Djava.io.tmpdir=$SESSION_TMP -Djava.util.prefs.userRoot=$SESSION_TMP -Dsbt.global.base=$SESSION_TMP/sbt-global" \
    /usr/bin/sandbox-exec -f "$work/build.sb" \
        sbt --jvm-client -batch -java-home "$JAVA_HOME" "$command" >"$1" 2>&1
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

    # A family under test must be genuinely absent when dropped. An earlier version appended
    # (allow file-read* file-map-executable process-exec* (subpath "/")) unconditionally, which
    # re-granted three of the families being measured and made their removal untestable.
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
        echo "every family granted and it still fails — the command is broken, not the policy." >&2
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
    printf '%s\n' "$keep" > probe/runtime-operations.txt
    echo "written to probe/runtime-operations.txt, which 'paths' uses as its base"
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
    if [ -f probe/runtime-operations.txt ]; then
        ops=$(cat probe/runtime-operations.txt)
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
    # the policy's own paths. The command under test defaults to a shell.
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
    # A kept root entry is rarely the answer: /System is required, but a build has no business
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
floor)
    # A process that dies before writing anything says nothing about which grant is missing. This
    # climbs from the smallest possible program to a real build and stops at the first rung that
    # fails, so the missing grant belongs to that layer and not to sbt. Output is not redirected:
    # the reason usually goes to the terminal, and redirecting is how it was lost.
    emit "$authority" || exit 1
    . "$work/build.env"
    rung() {
        printf '\n--- %s\n' "$1"; shift
        if /usr/bin/sandbox-exec -f "$work/build.sb" "$@"; then
            echo "    ok"
        else
            echo "    FAILED (exit $?) — the missing grant belongs to this layer"
            exit 1
        fi
    }
    # Only binaries the profile grants: a rung that fails because the ladder reached for something
    # ungranted says nothing about the layer it claims to test.
    rung "the loader, through a granted shell"           /bin/sh -c 'echo hello'
    rung "the launcher's interpreter: /usr/bin/env sh"   /usr/bin/env sh -c 'echo hello'
    rung "bash, which the inner sbt script needs"        /bin/bash -c 'echo hello'
    rung "the coreutils that script calls"               /bin/bash -c 'uname -s; dirname /a/b; basename /a/b'
    rung "the JDK"                                       "$JAVA_HOME/bin/java" -version
    rung "the sbt wrapper, no build"                     sbt -java-home "$JAVA_HOME" --script-version
    echo
    echo "every rung passed; the gate is next: sh probe/build-profile-gate.sh quick"
    ;;
narrow)
    emit "$authority" || exit 1
    if ! build "$work/base.log"; then
        echo "the current grant set does not build; fix that with the gate before narrowing." >&2
        exit 1
    fi
    echo "baseline builds. Removing one grant at a time."
    kept="$work/kept.txt"; : > "$kept"
    grep -vE '^\s*(#|$)' "$authority" | while IFS= read -r line; do
        grep -vE '^\s*(#|$)' "$authority" | grep -vxF "$line" > "$work/without.txt"
        if emit "$work/without.txt" && build "$work/try.log"; then
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
*)
    echo "usage: $0 [floor|ops|paths|narrow] [command]" >&2; exit 2 ;;
esac
