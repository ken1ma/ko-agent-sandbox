#!/bin/sh

# A broker retains its build-directory claims after its sbt server ends. Check its open session
# lock before emit starts an unconfined sbt in the same checkout; killing only sbt does not free it.
gate_require_idle() (
    gate_root=$1; shift
    for gate_session in "$gate_root"/b* "$gate_root"/condemned/b*; do
        [ -f "$gate_session/lock" ] || continue
        gate_pids=$(lsof -t "$gate_session/lock" 2>/dev/null | paste -sd ' ' -)
        [ -n "$gate_pids" ] || continue
        for gate_claim in "$gate_session/project" "$gate_session"/records/build-*; do
            case "$gate_claim" in *.pending) continue ;; esac
            [ -f "$gate_claim" ] || continue
            gate_directory=$(cat "$gate_claim") || return 1
            [ -n "$gate_directory" ] || continue
            for gate_project do
                case "$gate_project/" in
                    "$gate_directory/"*)
                        echo "a sandbox session has a run-on-host broker (pid $gate_pids) for $gate_directory" >&2
                        gate_container=$(cat "$gate_session/run" 2>/dev/null) || gate_container=""
                        case "$gate_container" in
                            ""|*[!a-zA-Z0-9_.-]*|-*)
                                echo "end that sandbox session before running this probe ($gate_session)" >&2
                                ;;
                            *)
                                echo "End that session before retrying; this stops its agent and host builds:" >&2
                                printf '  podman stop %s\n' "$gate_container" >&2
                                ;;
                        esac
                        echo "While this probe runs, omit --run-on-host" \
                            "(including --run-on-host=sbt,mill) for this project." >&2
                        return 1
                        ;;
                esac
            done
        done
    done
)

# A session can start after preflight. Directory matches alone do not make its runtimes the gate's.
gate_end_unclaimed_process() (
    gate_root=$1; gate_pid=$2
    gate_start=$(ps -o lstart= -p "$gate_pid" 2>/dev/null)
    [ -n "$gate_start" ] || return 1
    gate_cwd=$(lsof -a -p "$gate_pid" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p')
    if [ -z "$gate_cwd" ] || ! gate_require_idle "$gate_root" "$gate_cwd" >/dev/null 2>&1; then
        echo "left process $gate_pid: its working directory is unknown or claimed by a live broker" >&2
        return 1
    fi
    [ "$(ps -o lstart= -p "$gate_pid" 2>/dev/null)" = "$gate_start" ] || return 1
    kill "$gate_pid"
)

# Seeing startup output alone is insufficient: the requester must still be alive when cancelled.
gate_wait_started() (
    gate_pid=$1; gate_limit=$2; shift 2
    gate_tries=0
    while kill -0 "$gate_pid" 2>/dev/null; do
        "$@" && return 0
        [ "$gate_tries" -lt "$gate_limit" ] || return 1
        gate_tries=$((gate_tries + 1))
        sleep 0.5
    done
    return 1
)
