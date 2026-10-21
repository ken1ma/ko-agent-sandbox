#!/bin/sh
# Phase 1 of doc/plan-bpf-lsm-cgroup.md ("Phases", 1) on the macOS podman machine, in one run.
# Run it on the HOST, from the repository root, with the default machine running:
#
#     bpf/probe/phase1/phase1.sh [OUTDIR]
#
# It builds the probe image (Containerfile), extracts /out into the machine under
# ~/.local/share/ko-agent-sandbox/bpf-probe, and runs the phase's rows through `podman machine
# ssh` and the machine's sudo, each printed as PASS, FAIL or INFO. The transcript and the files the
# rows produce land in OUTDIR (default: out/ beside this script, ignored by git). Send OUTDIR back;
# the transcript is what the plan's "Environment evidence" and Phase 1's gate are filled from.
# On Windows, phase1.ps1.
#
# The rows, in order: the environment; the verifier's time and stats per program; an attach
# cgroup, a slice held by a transient unit under the systemd manager or a cgroup directory under
# cgroupfs, with `file_open` attached, under which a container cannot open the marker for writing
# but reads it and writes its sibling, while a container outside it writes it; the identity of a
# file and a directory through the share across host renames, a cache drop, a hard link and a
# replacement, and the program's reading beside statx's; a second attach cgroup sharing the slot,
# then ten distinct hooks attached and an eleventh refused; `populated` of the attach cgroup with a
# container below it and after its stop, whether the manager removes the empty cgroup by itself
# within 60 s, and the link detached when it is removed; the container's own cgroup after
# `podman init`; an attach that fails and starts no container; a `createContainer` hook's cgroup
# and its write of the marker; the jited program's barrier instruction.
#
# It writes a fixture under $HOME/.cache (the share the machine mounts), two attach cgroups with
# their transient units, pins under /sys/fs/bpf/ko-agent-bpf-phase1 in the machine, and
# containers named ko-agent-bpf-*; all are removed on exit. The marker name is fixed in
# lsm_probe.bpf.c.
set -u

MARKER=ko-agent-bpf-marker
IMAGE=docker.io/library/alpine:3.22
PROBE_IMAGE=ko-agent-bpf-probe:phase1
MACHINE_DIR=.local/share/ko-agent-sandbox/bpf-probe
CTL=./$MACHINE_DIR/controller
PIN_ROOT=/sys/fs/bpf/ko-agent-bpf-phase1
FIX=$HOME/.cache/ko-agent-bpf-phase1.$$
# shellcheck disable=SC1007
PROBE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT=${1:-$PROBE_DIR/out}

mkdir -p "$OUT"
# shellcheck disable=SC1007
OUT=$(CDPATH= cd -- "$OUT" && pwd)
TRANSCRIPT=$OUT/transcript.log
: > "$TRANSCRIPT"

passed=0
failed=0

log() { printf '%s\n' "$*" | tee -a "$TRANSCRIPT"; }
info() { log "INFO $*"; }
pass() { passed=$((passed + 1)); log "PASS $*"; }
fail() { failed=$((failed + 1)); log "FAIL $*"; }
check() { # check DESCRIPTION COMMAND...: PASS when COMMAND succeeds
    desc=$1
    shift
    if "$@"; then pass "$desc"; else fail "$desc"; fi
}
has() { printf '%s\n' "$2" | grep -q -- "$1"; }
lacks() { ! has "$1" "$2"; }
eq2() { [ "$1" = "$2" ] && [ "$3" = "$4" ]; }
# A command in the machine, as the machine's user; its output is logged and returned.
vm() {
    out=$(podman machine ssh "$1" 2>&1)
    status=$?
    printf '%s\n' "$out" >> "$TRANSCRIPT"
    printf '%s\n' "$out"
    return $status
}
# The value of KEY in the first line of INPUT holding it, as the controller prints `key=value`.
field() { printf '%s\n' "$2" | sed -n "s/.* $1=\([^ ]*\).*/\1/p" | head -1; }
step() { log ""; log "== $*"; }

cleanup() {
    step "cleanup"
    vm "sudo -n $CTL unpin $PIN_ROOT/1; sudo -n $CTL unpin $PIN_ROOT/2; sudo -n $CTL unpin $PIN_ROOT/3
        sudo -n $CTL unpin $PIN_ROOT/4; sudo -n rmdir $PIN_ROOT 2>/dev/null; true" > /dev/null
    vm "systemctl --user stop ko-agent-bpf-hold1 ko-agent-bpf-hold2 ko-agent-bpf1.slice ko-agent-bpf2.slice \
        2>/dev/null; true" > /dev/null
    vm "rmdir /sys/fs/cgroup/user.slice/user-*.slice/user@*.service/app.slice/ko-agent-bpf? 2>/dev/null; true" \
        > /dev/null
    podman rm -f ko-agent-bpf-scope ko-agent-bpf-closed ko-agent-bpf-below > /dev/null 2>&1
    rm -rf "$FIX"
    log ""
    log "passed=$passed failed=$failed transcript=$TRANSCRIPT"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
step "environment"
# ---------------------------------------------------------------------------
podman machine inspect --format '{{.State}}' > /dev/null 2>&1 || { log "no default podman machine"; exit 2; }
vm "sudo -n true" > /dev/null || { log "sudo -n fails in the machine"; exit 2; }
UID_VM=$(vm "id -u")
KERNEL_VM=$(vm "uname -r")
HOME_VM=$(vm "echo \$HOME")
MANAGER=$(vm "podman info --format '{{.Host.CgroupManager}}'")
RUNTIME=$(vm "podman info --format '{{.Host.OCIRuntime.Name}} {{.Host.OCIRuntime.Version}}'" | head -1)
info "machine user uid=$UID_VM kernel=$KERNEL_VM podman=$(podman --version) cgroup manager=$MANAGER" \
    "runtime=$RUNTIME"
# The WSL machine mounts neither securityfs nor a bpffs (measured 2026-10-21); the probe mounts
# them, which the launcher's controller would have to do as well.
info "mounts: $(vm "findmnt -n -o FSTYPE /sys/kernel/security /sys/fs/bpf | tr '\n' ' '")"
vm "sudo -n sh -c 'findmnt -n /sys/kernel/security >/dev/null || mount -t securityfs securityfs /sys/kernel/security'
    sudo -n sh -c 'findmnt -n /sys/fs/bpf >/dev/null || mount -t bpf bpf /sys/fs/bpf'" > /dev/null
info "lsm=$(vm 'sudo -n cat /sys/kernel/security/lsm')"
info "kptr_restrict=$(vm 'cat /proc/sys/kernel/kptr_restrict')" \
    "bpffs=$(vm 'stat -f -c %T /sys/fs/bpf'):$(vm 'stat -c %a:%U /sys/fs/bpf')"
info "rename_lock=$(vm 'sudo -n grep -w rename_lock /proc/kallsyms | head -3 | tr "\n" " "')"
vm "findmnt -T $HOME -o TARGET,SOURCE,FSTYPE,OPTIONS" > "$OUT/findmnt.txt"
info "share: $(sed -n 2p "$OUT/findmnt.txt")"
vm "sudo -n mkdir -p $PIN_ROOT" > /dev/null

# ---------------------------------------------------------------------------
step "build and install the probe"
# ---------------------------------------------------------------------------
if ! podman build --build-arg "BUILD_KERNEL=$KERNEL_VM" -t "$PROBE_IMAGE" "$PROBE_DIR" >> "$TRANSCRIPT" 2>&1; then
    log "the probe image failed to build; the build log is in $TRANSCRIPT"
    exit 2
fi
vm "set -eu; mkdir -p $MACHINE_DIR
    podman create --replace --name ko-agent-bpf-extract $PROBE_IMAGE >/dev/null
    podman cp ko-agent-bpf-extract:/out/. $MACHINE_DIR/
    podman rm ko-agent-bpf-extract >/dev/null
    test -x $MACHINE_DIR/controller" > /dev/null
check "probe installed in the machine" [ $? -eq 0 ]
vm "cat $MACHINE_DIR/clang-version.txt $MACHINE_DIR/build-kernel.txt $MACHINE_DIR/lsm_probe.bpf.o.sha256" \
    > "$OUT/build.txt"
vm "cat $MACHINE_DIR/lsm_probe.bpf.asm" > "$OUT/lsm_probe.bpf.asm"
info "$(tr '\n' ' ' < "$OUT/build.txt")"
podman pull -q "$IMAGE" > /dev/null 2>&1 || { log "cannot pull $IMAGE"; exit 2; }

# ---------------------------------------------------------------------------
step "verifier: each program alone, then all eleven"
# ---------------------------------------------------------------------------
load=$(vm "sudo -n $CTL load")
load_status=$?
printf '%s\n' "$load" > "$OUT/verifier.txt"
printf '%s\n' "$load" | grep -E '^(load|verifier|prog) ' | sed 's/^/  /' | tee -a "$TRANSCRIPT"
check "every program loads, alone and together, and the controller exits 0" \
    eq2 "$(printf '%s\n' "$load" | grep -c ' ok=1')" 12 "$load_status" 0
info "slots before: $(field hooks_in_use "$(vm "sudo -n $CTL query /sys/fs/cgroup")") hooks in use"

# ---------------------------------------------------------------------------
step "fixture and the attach cgroup"
# ---------------------------------------------------------------------------
mkdir -p "$FIX/dir/sub" "$FIX/dir/$MARKER-dir"
echo marker > "$FIX/dir/sub/$MARKER"
echo other > "$FIX/dir/sub/other"
MARKER_PATH=$FIX/dir/sub/$MARKER
MARKER_DIR=$FIX/dir/$MARKER-dir
# The attach cgroup, by the machine's cgroup manager: under systemd a transient slice held by a
# unit, under cgroupfs (the WSL machine, measured 2026-10-21) a directory under the user's delegated
# subtree, which podman takes as an absolute --cgroup-parent and keeps until removed.
APP_SLICE=/user.slice/user-$UID_VM.slice/user@$UID_VM.service/app.slice
attach_cgroup() { # attach_cgroup N: sets CG, the cgroup's sysfs path, and PARENT, the --cgroup-parent value
    if [ "$MANAGER" = systemd ]; then
        vm "systemctl --user stop ko-agent-bpf-hold$1 2>/dev/null; systemctl --user reset-failed 2>/dev/null
            systemd-run --user --unit=ko-agent-bpf-hold$1 --slice=ko-agent-bpf$1.slice /usr/bin/sleep 1800" > /dev/null
        CG=$(vm "find /sys/fs/cgroup/user.slice -type d -name ko-agent-bpf$1.slice 2>/dev/null | head -1")
        PARENT=ko-agent-bpf$1.slice
    else
        PARENT=$APP_SLICE/ko-agent-bpf$1
        CG=/sys/fs/cgroup$PARENT
        vm "mkdir -p $CG" > /dev/null
    fi
}
release_hold() { # release_hold N: what kept the cgroup alive lets go; nothing under cgroupfs
    if [ "$MANAGER" = systemd ]; then vm "systemctl --user stop ko-agent-bpf-hold$1" > /dev/null; fi
}
remove_cgroup() { # remove_cgroup N
    if [ "$MANAGER" = systemd ]; then vm "systemctl --user stop ko-agent-bpf$1.slice" > /dev/null
    else
        vm "rmdir /sys/fs/cgroup$APP_SLICE/ko-agent-bpf$1" > /dev/null
    fi
}
attach_cgroup 1
CG1=$CG
PARENT1=$PARENT
check "attach cgroup 1 exists under the user's manager: $CG1" [ -n "$CG1" ]
attach=$(vm "sudo -n $CTL attach $CG1 $PIN_ROOT/1 file_open")
check "file_open attached and pinned: $(printf '%s\n' "$attach" | grep '^attach ')" [ "$(field ok "$attach")" = 1 ]
query=$(vm "sudo -n $CTL query $CG1")
check "query lists one program, on bpf_lsm_file_open" \
    eq2 "$(field prog_cnt "$query")" 1 "$(has 'hook=bpf_lsm_file_open' "$query"; echo $?)" 0

in_slice() { # in_slice SHELL-SCRIPT: run it in a container under attach cgroup 1
    podman run --rm --cgroup-parent="$PARENT1" --userns=keep-id --volume "$FIX:$FIX" "$IMAGE" \
        sh -c "$1" 2>&1 | tee -a "$TRANSCRIPT"
}
outside() {
    podman run --rm --userns=keep-id --volume "$FIX:$FIX" "$IMAGE" sh -c "$1" 2>&1 | tee -a "$TRANSCRIPT"
}
run1=$(in_slice "cat $MARKER_PATH > /dev/null && echo READ_OK
    (echo x >> $MARKER_PATH) 2>&1 && echo WRITE_OK || echo WRITE_FAIL
    (echo x >> $FIX/dir/sub/other) 2>&1 && echo OTHER_OK || echo OTHER_FAIL")
check "under cgroup 1, the marker opens for reading" has READ_OK "$run1"
check "under cgroup 1, the marker is refused for writing with EPERM" \
    eq2 "$(has WRITE_FAIL "$run1"; echo $?)" 0 "$(has 'not permitted' "$run1"; echo $?)" 0
check "under cgroup 1, the sibling file is written" has OTHER_OK "$run1"
run2=$(outside "(echo x >> $MARKER_PATH) 2>&1 && echo WRITE_OK || echo WRITE_FAIL")
check "outside cgroup 1, the marker is written" has WRITE_OK "$run2"

# ---------------------------------------------------------------------------
step "identity through the share"
# ---------------------------------------------------------------------------
sx() { vm "$CTL statx $1"; }
# Each comparison needs both identities present: a statx or a read-back that printed nothing fails.
same_pair() { [ -n "$3" ] && [ "$1" = "$2" ] && [ "$3" = "$4" ]; }   # same_pair DEV-A DEV-B INO-A INO-B
different_inos() { [ -n "$1" ] && [ -n "$2" ] && [ "$1" != "$2" ]; }
same_identity() { # same_identity DESCRIPTION STATX-LINE-A STATX-LINE-B
    check "$1: $(field mkdev "$2"):$(field ino "$2") vs $(field mkdev "$3"):$(field ino "$3")" \
        same_pair "$(field mkdev "$2")" "$(field mkdev "$3")" "$(field ino "$2")" "$(field ino "$3")"
}
different_identity() {
    check "$1: $(field mkdev "$2"):$(field ino "$2") vs $(field mkdev "$3"):$(field ino "$3")" \
        different_inos "$(field ino "$2")" "$(field ino "$3")"
}
program_matches() { # program_matches DESCRIPTION LAST-OPEN-LINE STATX-LINE
    check "$1: $(field s_dev "$2"):$(field i_ino "$2") fs_type=$(field fs_type "$2")" \
        same_pair "$(field s_dev "$2")" "$(field mkdev "$3")" "$(field i_ino "$2")" "$(field ino "$3")"
}
f0=$(sx "$MARKER_PATH")
d0=$(sx "$FIX/dir/sub")
info "$f0"
info "$d0"
# The program's reading of the same inode, from the open the container made above.
p0=$(vm "sudo -n $CTL last-open $PIN_ROOT/1/file_open")
info "$p0"
program_matches "the program's (s_dev, i_ino) equals statx's (mkdev, ino)" "$p0" "$f0"
in_slice "ls $MARKER_DIR > /dev/null" > /dev/null
program_matches "the program reads a directory's identity as statx does" \
    "$(vm "sudo -n $CTL last-open $PIN_ROOT/1/file_open")" "$(sx "$MARKER_DIR")"
mv "$FIX/dir/sub" "$FIX/dir/sub2"
same_identity "directory identity after a host rename of the directory" "$d0" "$(sx "$FIX/dir/sub2")"
mv "$FIX/dir/sub2" "$FIX/dir/sub"
mv "$MARKER_PATH" "$FIX/dir/sub/renamed"
same_identity "file identity after a host rename of the file" "$f0" "$(sx "$FIX/dir/sub/renamed")"
mv "$FIX/dir/sub/renamed" "$MARKER_PATH"
mv "$FIX/dir" "$FIX/dir2"
same_identity "file identity after a host rename of an ancestor" "$f0" "$(sx "$FIX/dir2/sub/$MARKER")"
same_identity "directory identity after a host rename of its parent" "$d0" "$(sx "$FIX/dir2/sub")"
mv "$FIX/dir2" "$FIX/dir"
vm "sync; sudo -n sh -c 'echo 2 > /proc/sys/vm/drop_caches'" > /dev/null
same_identity "file identity after the guest dropped its caches" "$f0" "$(sx "$MARKER_PATH")"
same_identity "directory identity after the guest dropped its caches" "$d0" "$(sx "$FIX/dir/sub")"
ln "$MARKER_PATH" "$FIX/dir/sub/link"
same_identity "the two names of a host-made hard link" "$(sx "$MARKER_PATH")" "$(sx "$FIX/dir/sub/link")"
rm "$FIX/dir/sub/link"
# On virtiofs the guest answers ENOENT for a replaced name for a few seconds (measured 2026-10-21).
wait_visible() { # wait_visible PATH: sets VISIBLE_LINE to PATH's statx line once it appears, within 30 s
    VISIBLE_AFTER_MS=0
    while :; do
        VISIBLE_LINE=$(sx "$1")
        has ' ino=' "$VISIBLE_LINE" && break
        [ "$VISIBLE_AFTER_MS" -lt 30000 ] || break
        sleep 0.5
        VISIBLE_AFTER_MS=$((VISIBLE_AFTER_MS + 500))
    done
    info "$1 became visible to the guest after about $VISIBLE_AFTER_MS ms"
}
rm "$MARKER_PATH"
echo replaced > "$MARKER_PATH"
wait_visible "$MARKER_PATH"
f5=$VISIBLE_LINE
different_identity "a host-made replacement at the same name differs" "$f0" "$f5"
in_slice "cat $MARKER_PATH > /dev/null" > /dev/null
p5=$(vm "sudo -n $CTL last-open $PIN_ROOT/1/file_open")
program_matches "the program reads the replacement's identity" "$p5" "$f5"
rm -r "$FIX/dir/sub"
mkdir "$FIX/dir/sub"
echo marker > "$MARKER_PATH"
wait_visible "$FIX/dir/sub"
different_identity "a host-made replacement of the directory differs" "$d0" "$VISIBLE_LINE"

# ---------------------------------------------------------------------------
step "a second cgroup shares the slot; ten hooks fit, an eleventh does not"
# ---------------------------------------------------------------------------
attach_cgroup 2
CG2=$CG
PARENT2=$PARENT
attach2=$(vm "sudo -n $CTL attach $CG2 $PIN_ROOT/2 file_open")
check "file_open attached to cgroup 2 as well" [ "$(field ok "$attach2")" = 1 ]
query2=$(vm "sudo -n $CTL query $CG2")
check "one hook in use for two cgroups: hooks_in_use=$(field hooks_in_use "$query2") links=$(field links "$query2")" \
    eq2 "$(field hooks_in_use "$query2")" 1 "$(field links "$query2")" 2
more=$(vm "sudo -n $CTL attach $CG2 $PIN_ROOT/2 --keep-going inode_create inode_mknod inode_symlink inode_link \
    inode_rename inode_unlink inode_setattr file_receive inode_mkdir inode_rmdir")
printf '%s\n' "$more" | grep '^attach ' | sed 's/^/  /' | tee -a "$TRANSCRIPT"
# The eleventh hook's attach answers EINVAL: __cgroup_bpf_attach folds bpf_cgroup_atype_find's
# -E2BIG into it (kernel/bpf/cgroup.c).
check "nine more hooks attach, the tenth distinct one fails with EINVAL: $(printf '%s\n' "$more" | grep '^attached ')" \
    eq2 "$(field count "$more")" 9 "$(has 'name=inode_rmdir ok=0 errno=22' "$more"; echo $?)" 0
info "$(printf '%s\n' "$(vm "sudo -n $CTL query $CG2")" | grep '^slots ')"
vm "sudo -n $CTL unpin $PIN_ROOT/2" > /dev/null
info "after unpinning cgroup 2: $(printf '%s\n' "$(vm "sudo -n $CTL query $CG1")" | grep '^slots ')"

# ---------------------------------------------------------------------------
step "the attach cgroup with a container below, then empty: populated, the manager, and the link"
# ---------------------------------------------------------------------------
attach2=$(vm "sudo -n $CTL attach $CG2 $PIN_ROOT/2 file_open")
before=$(vm "sudo -n $CTL link-info $PIN_ROOT/2/file_open")
info "$before"
# A container below the attach cgroup, which holds no task of its own: cgroup.events's populated
# counts the descendants' tasks (Documentation/admin-guide/cgroup-v2.rst) and cgroup.procs does
# not, which is what the reconcile of "Lifecycle", 7, rests on.
populated() { vm "sed -n 's/^populated //p' $1/cgroup.events"; }
podman run -d --rm --name ko-agent-bpf-below --cgroup-parent="$PARENT2" "$IMAGE" sleep 600 > /dev/null
procs2=$(vm "wc -l < $CG2/cgroup.procs")
populated2=$(populated "$CG2")
desc2="with a container below it, cgroup 2 holds no task of its own and reads populated 1:"
check "$desc2 procs=$procs2 populated=$populated2" eq2 "$procs2" 0 "$populated2" 1
release_hold 2
check "without its hold and with the container, cgroup 2 reads populated 1" [ "$(populated "$CG2")" = 1 ]
podman stop ko-agent-bpf-below > /dev/null
check "after the container's stop, cgroup 2 reads populated 0" [ "$(populated "$CG2")" = 0 ]
wait_removed() { # wait_removed CGROUP SECONDS: removed_after_ms=N, or still_present_after_ms=SECONDS*1000
    vm "t0=\$(date +%s%N)
        for i in \$(seq 1 $(($2 * 10))); do
            test -d $1 || { echo removed_after_ms=\$(( (\$(date +%s%N) - t0) / 1000000 )); exit 0; }
            sleep 0.1
        done; echo still_present_after_ms=$(($2 * 1000))"
}
info "cgroup 2 without its hold or a container: $(wait_removed "$CG2" 60)"
info "$(vm "sudo -n $CTL link-info $PIN_ROOT/2/file_open")"
remove_cgroup 2
info "cgroup 2 after its removal: $(wait_removed "$CG2" 10)"
after=$(vm "sudo -n $CTL link-info $PIN_ROOT/2/file_open")
info "$after"
detached() { [ "$1" != 0 ] && [ "$2" = 0 ]; }
check "the pinned link outlives the cgroup with cgroup_id 0, detached without an error" \
    detached "$(field cgroup_id "$before")" "$(field cgroup_id "$after")"
vm "sudo -n $CTL unpin $PIN_ROOT/2" > /dev/null

# ---------------------------------------------------------------------------
step "the container's own cgroup: podman create, podman init, attach, podman start"
# ---------------------------------------------------------------------------
# A guarded launch, the launcher's sequence: create, init, attach to the container's own cgroup,
# read from its init process (a `libpod-<id>.scope` under systemd, a `<id>` directory under
# cgroupfs), then start only when the controller succeeded; otherwise unpin and leave the container
# initialized. The same function runs with and without an injected controller failure.
# guarded_launch NAME PINDIR [CONTROLLER-OPTION]: sets LAUNCH_CG, LAUNCH_ATTACH, LAUNCH_OUTPUT and LAUNCH_STATUS.
guarded_launch() {
    podman rm -f "$1" > /dev/null 2>&1
    podman create --name "$1" --userns=keep-id --volume "$FIX:$FIX" "$IMAGE" \
        sh -c "echo STARTED; (echo x >> $MARKER_PATH) 2>&1 && echo WRITE_OK || echo WRITE_FAIL" > /dev/null
    podman init "$1" > /dev/null
    LAUNCH_PID=$(podman inspect --format '{{.State.Pid}}' "$1")
    LAUNCH_CG=$(vm "sed -n 's|^0::|/sys/fs/cgroup|p' /proc/$LAUNCH_PID/cgroup")
    info "after podman init: state=$(podman inspect --format '{{.State.Status}}' "$1") pid=$LAUNCH_PID" \
        "cgroup=$LAUNCH_CG"
    info "processes in it: $(vm "for p in \$(cat $LAUNCH_CG/cgroup.procs $LAUNCH_CG/*/cgroup.procs 2>/dev/null); do
        printf '%s(%s) ' \$p \$(cat /proc/\$p/comm); done")"
    if LAUNCH_ATTACH=$(vm "sudo -n $CTL attach $LAUNCH_CG $2 ${3:-} file_open"); then
        LAUNCH_OUTPUT=$(podman start --attach "$1" 2>&1 | tee -a "$TRANSCRIPT")
    else
        LAUNCH_OUTPUT=""
        vm "sudo -n $CTL unpin $2" > /dev/null
    fi
    LAUNCH_STATUS=$(podman inspect --format '{{.State.Status}}' "$1")
}
guarded_launch ko-agent-bpf-scope "$PIN_ROOT/3"
check "the container's cgroup exists after podman init" [ -n "$LAUNCH_CG" ]
check "file_open attached to the container's cgroup before start" [ "$(field ok "$LAUNCH_ATTACH")" = 1 ]
check "started under its cgroup's policy: the command ran and the marker is refused for writing" \
    eq2 "$(has STARTED "$LAUNCH_OUTPUT"; echo $?)" 0 "$(has WRITE_FAIL "$LAUNCH_OUTPUT"; echo $?)" 0
podman rm ko-agent-bpf-scope > /dev/null
info "$(vm "sudo -n $CTL link-info $PIN_ROOT/3/file_open")"
vm "sudo -n $CTL unpin $PIN_ROOT/3" > /dev/null

# ---------------------------------------------------------------------------
step "a failed attach starts no container"
# ---------------------------------------------------------------------------
# The same launch with the controller failing after its attach, as a read-back mismatch would.
guarded_launch ko-agent-bpf-closed "$PIN_ROOT/4" --fail-after-attach
check "the controller attached and then reported the injected failure" \
    eq2 "$(field ok "$LAUNCH_ATTACH")" 1 "$(has 'injected failure' "$LAUNCH_ATTACH"; echo $?)" 0
check "the container was never started: status=$LAUNCH_STATUS, nothing printed" \
    eq2 "$LAUNCH_STATUS" initialized "$(lacks STARTED "$LAUNCH_OUTPUT"; echo $?)" 0
podman rm -f ko-agent-bpf-closed > /dev/null

# ---------------------------------------------------------------------------
step "a createContainer hook under the attach cgroup: its cgroup, and its write of the marker"
# ---------------------------------------------------------------------------
# The OCI runtime spec leaves a createContainer hook's cgroup open ("Lifecycle", 1): the hook
# records its own and tries the marker. The machine's podman runs the container, since --hooks-dir
# is a global option of the podman that runs the runtime, not of the remote client; --cgroupns=host
# keeps /proc/self/cgroup a full path, which a private cgroup namespace would cut at the container's.
HOOKS=$HOME_VM/$MACHINE_DIR/hooks
hook_script="#!/bin/sh
# The Phase 1 probe's createContainer hook: it records where it runs and whether the marker opens.
{ echo cgroup=\$(sed -n 's/^0:://p' /proc/self/cgroup)
  if err=\$( (echo x >> $MARKER_PATH) 2>&1 ); then echo write=ok; else echo \"write=fail error=\$err\"; fi
} > $HOOKS/hook.out 2>&1"
hook_json="{\"version\": \"1.0.0\", \"hook\": {\"path\": \"$HOOKS/hook.sh\"}, \"when\": {\"always\": true},
    \"stages\": [\"createContainer\"]}"
vm "mkdir -p $HOOKS; rm -f $HOOKS/hook.out
    echo '$(printf '%s' "$hook_script" | base64 | tr -d '\n')' | base64 -d > $HOOKS/hook.sh
    chmod +x $HOOKS/hook.sh
    echo '$(printf '%s' "$hook_json" | base64 | tr -d '\n')' | base64 -d > $HOOKS/hook.json" > /dev/null
hook_run=$(vm "podman --hooks-dir $HOOKS run --rm --cgroupns=host --cgroup-parent=$PARENT1 --userns=keep-id \
    --volume $FIX:$FIX $IMAGE echo CONTAINER_RAN")
hook_out=$(vm "cat $HOOKS/hook.out 2>&1")
info "hook: $(printf '%s' "$hook_out" | tr '\n' ' ')"
check "the hook ran and the container started" \
    eq2 "$(has cgroup= "$hook_out"; echo $?)" 0 "$(has CONTAINER_RAN "$hook_run"; echo $?)" 0
hook_cg=$(printf '%s\n' "$hook_out" | sed -n 's/^cgroup=//p')
starts_with() { [ -n "$1" ] && case $2 in "$1"*) return 0 ;; esac; return 1; }
check "the hook ran below attach cgroup 1: $hook_cg" starts_with "${CG1#/sys/fs/cgroup}" "$hook_cg"
check "the hook's write of the marker is refused with EPERM" \
    eq2 "$(has write=fail "$hook_out"; echo $?)" 0 "$(has 'not permitted' "$hook_out"; echo $?)" 0

# ---------------------------------------------------------------------------
step "the barrier in the jited program, and the walk's counters"
# ---------------------------------------------------------------------------
jited=$(vm "sudo -n $CTL jited $PIN_ROOT/1/file_open /tmp/file_open.jited")
info "$jited"
vm "base64 /tmp/file_open.jited" | base64 --decode > "$OUT/file_open.jited" 2>/dev/null
barrier_seen() {
    [ -n "$(field fetch_add_insns "$1")" ] && [ "$(field fetch_add_insns "$1")" != 0 ] && {
        [ "$(field ldaddal "$1")" != 0 ] || [ "$(field dmb_ish "$1")" != 0 ] || [ "$(field lock_xadd "$1")" != 0 ]
    }
}
check "the xlated program holds the atomic fetch-add and the jited one a barrier instruction" barrier_seen "$jited"
vm "sudo -n $CTL stats $PIN_ROOT/1/file_open" | grep 'hook=file_open' | tee -a "$TRANSCRIPT"
vm "sudo -n $CTL stats $PIN_ROOT/1/file_open" > "$OUT/stats.txt"

[ "$failed" -eq 0 ] || exit 1
