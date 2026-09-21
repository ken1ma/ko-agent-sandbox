#!/bin/sh

# A broker retains its build-directory claims after its sbt server ends. Check its open session
# lock before emit starts an unconfined sbt in the same checkout; killing only sbt does not free it.
acceptance_require_idle() (
    acceptance_root=$1; shift
    for acceptance_session in "$acceptance_root"/b* "$acceptance_root"/condemned/b*; do
        [ -f "$acceptance_session/lock" ] || continue
        acceptance_pids=$(lsof -t "$acceptance_session/lock" 2>/dev/null | paste -sd ' ' -)
        [ -n "$acceptance_pids" ] || continue
        for acceptance_claim in "$acceptance_session/project" "$acceptance_session"/records/build-*; do
            case "$acceptance_claim" in *.pending) continue ;; esac
            [ -f "$acceptance_claim" ] || continue
            acceptance_directory=$(cat "$acceptance_claim") || return 1
            [ -n "$acceptance_directory" ] || continue
            for acceptance_project do
                case "$acceptance_project/" in
                    "$acceptance_directory/"*)
                        echo "a sandbox session has a run-on-host broker (pid $acceptance_pids)" \
                            "for $acceptance_directory" >&2
                        acceptance_container=$(cat "$acceptance_session/run" 2>/dev/null) || acceptance_container=""
                        case "$acceptance_container" in
                            ""|*[!a-zA-Z0-9_.-]*|-*)
                                echo "end that sandbox session before running this probe ($acceptance_session)" >&2
                                ;;
                            *)
                                echo "End that session before retrying; this stops its agent and host builds:" >&2
                                printf '  podman stop %s\n' "$acceptance_container" >&2
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

# A session can start after preflight. Directory matches alone do not make its runtimes the acceptance test's.
acceptance_end_unclaimed_process() (
    acceptance_root=$1; acceptance_pid=$2
    acceptance_start=$(ps -o lstart= -p "$acceptance_pid" 2>/dev/null)
    [ -n "$acceptance_start" ] || return 1
    acceptance_cwd=$(lsof -a -p "$acceptance_pid" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p')
    if [ -z "$acceptance_cwd" ] || ! acceptance_require_idle "$acceptance_root" "$acceptance_cwd" >/dev/null 2>&1; then
        echo "left process $acceptance_pid: its working directory is unknown or claimed by a live broker" >&2
        return 1
    fi
    [ "$(ps -o lstart= -p "$acceptance_pid" 2>/dev/null)" = "$acceptance_start" ] || return 1
    kill "$acceptance_pid"
)

# Seeing startup output alone is insufficient: the requester must still be alive when cancelled.
acceptance_wait_started() (
    acceptance_pid=$1; acceptance_limit=$2; shift 2
    acceptance_tries=0
    while kill -0 "$acceptance_pid" 2>/dev/null; do
        "$@" && return 0
        [ "$acceptance_tries" -lt "$acceptance_limit" ] || return 1
        acceptance_tries=$((acceptance_tries + 1))
        sleep 0.5
    done
    return 1
)
