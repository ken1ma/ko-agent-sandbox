#!/bin/sh
# Whether a container's standard input carries a secret to its process without the secret reaching
# `podman inspect` or `podman logs`, and whether the podman process that carried it can end while
# the container runs on (SECURITY.md, "Who holds a brokered value").
#
# The proxy image has no shell, so the measured container is an image that has one, created with
# the proxy container's options that bear on this: a read-only root with no tmpfs, `--init`, and
# `--interactive`. Its process reads a count line and that many lines, prints each line's checksum
# and never the line, prints `ready`, and sleeps.
#
#   sh src/probe/podman-attach-stdin.sh [image]     # default: ko-agent-sandbox:latest
#
# A row reads ERROR when an observation could not be made, which is no answer either way; the
# exit status is 0 only when no row reads FAIL or ERROR. Run it on each podman machine the
# launcher supports, and on each new podman release.
set -u
image=${1:-ko-agent-sandbox:latest}
podman=${PODMAN:-podman}
work=$(mktemp -d "${TMPDIR:-/tmp}/ko-agent-attach-stdin.XXXXXX") || exit 1
name=ko-agent-attach-probe-$$
trap 'exec 3>&- 2>/dev/null; "$podman" rm -f "$name" "$name-proxied" >/dev/null 2>&1; rm -rf "$work"' EXIT INT TERM

secret=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
expected=$(printf '%s\n' "$secret" | cksum)
script='read -r count; i=0
while [ "$i" -lt "$count" ]; do read -r line; printf "%s\n" "$line" | cksum; i=$((i + 1)); done
echo ready; exec sleep 300'

failed=0
row() { # label result
    printf '  %-88s %s\n' "$1" "$2"
    case "$2" in PASS|STOPPED|RUNNING) ;; *) failed=1 ;; esac
}

# podman-container-exists(1): 0 when the container exists, 1 when it does not, 125 on an error.
exists() { "$podman" container exists "$1" >/dev/null 2>&1; }

# running, stopped, gone or error. A container created with --rm is gone once it stops; only the
# status 1 says so, and any other failure is an observation that could not be made.
state() { # name
    exists "$1"
    case $? in
        0)  if state_running=$("$podman" inspect --format '{{.State.Running}}' "$1" 2>/dev/null); then
                case "$state_running" in true) echo running ;; false) echo stopped ;; *) echo error ;; esac
            else
                # Removed between the two calls, or an inspection that failed.
                exists "$1"
                case $? in 1) echo gone ;; *) echo error ;; esac
            fi ;;
        1)  echo gone ;;
        *)  echo error ;;
    esac
}

# PASS when the command ran and neither of its streams holds the secret.
lacks() { # label command...
    lacks_label=$1; shift
    if ! "$@" >"$work/observed" 2>"$work/observed.err"; then
        row "$lacks_label" "ERROR: $(sed -n 1p "$work/observed.err")"
    elif grep -qF "$secret" "$work/observed" "$work/observed.err"; then row "$lacks_label" FAIL
    else row "$lacks_label" PASS
    fi
}

# Creates the container, starts it attached with the given options, writes the two lines and keeps
# the writing end open: nothing measured here depends on an end of input. Sets `client` to the
# attached podman process. Fails unless the container reported ready and is running.
start_attached() { # name out start-option...
    attached_name=$1; attached_out=$2; shift 2
    "$podman" create --name "$attached_name" --rm --pull=never --init --interactive --read-only \
        --read-only-tmpfs=false --cap-drop=ALL --security-opt=no-new-privileges --network=none \
        --entrypoint sh "$image" -c "$script" >/dev/null || {
        echo "could not create a container from $image" >&2; return 1
    }
    rm -f "$work/in"; mkfifo "$work/in"
    "$podman" start --attach --interactive "$@" "$attached_name" <"$work/in" >"$attached_out" 2>&1 &
    client=$!
    exec 3>"$work/in"
    printf '1\n%s\n' "$secret" >&3
    tries=60
    while [ "$tries" -gt 0 ] && ! grep -q '^ready' "$attached_out" 2>/dev/null; do
        tries=$((tries - 1)); sleep 0.5
    done
    grep -q '^ready' "$attached_out" 2>/dev/null && [ "$(state "$attached_name")" = running ]
}

end_client() { kill "$client" 2>/dev/null; wait "$client" 2>/dev/null; exec 3>&-; sleep 3; }

versions=$("$podman" version --format '{{.Client.Version}} client, {{.Server.Version}} server' 2>/dev/null)
echo "podman $versions, image $image"

reached="the line written to the attached start reached the container's process"
if ! start_attached "$name" "$work/out" --sig-proxy=false; then
    row "$reached" "ERROR: the container did not report ready and running"
    sed 's/^/    /' "$work/out" 2>/dev/null
    exit 1
fi
if grep -qxF "$expected" "$work/out"; then row "$reached" PASS; else row "$reached" FAIL; fi
lacks "podman inspect does not hold the line" "$podman" inspect "$name"
lacks "podman logs does not hold the line" "$podman" logs "$name"
end_client
survives="with --sig-proxy=false, ending the attached podman process leaves the container running"
case "$(state "$name")" in
    running) row "$survives" PASS ;;
    error)   row "$survives" "ERROR: the container could not be inspected" ;;
    *)       row "$survives" FAIL ;;
esac
"$podman" rm -f "$name" >/dev/null 2>&1

# The contrast that says why the option is there: attached, podman forwards a signal by default.
contrast="without the option, ending the attached podman process leaves the container running"
if ! start_attached "$name-proxied" "$work/out-proxied"; then
    row "$contrast" "ERROR: the container did not report ready and running"
    exit 1
fi
end_client
case "$(state "$name-proxied")" in
    running)      row "$contrast" RUNNING ;;
    stopped|gone) row "$contrast" STOPPED ;;
    *)            row "$contrast" "ERROR: the container could not be inspected" ;;
esac
exit "$failed"
