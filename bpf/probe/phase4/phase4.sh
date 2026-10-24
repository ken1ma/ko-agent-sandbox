#!/bin/sh
# Phase 4 of doc/plan-bpf-lsm-cgroup.md ("Phases", 4) on the macOS podman machine, in one run.
# Run it on the HOST, from the repository root, with the default machine running:
#
#     bpf/probe/phase4/phase4.sh [OUTDIR]
#
# It builds the probe image (Containerfile) from a context assembled out of the files sources.txt
# lists, extracts /out into the machine under ~/.local/share/ko-agent-sandbox/bpf-probe4, and runs
# the phase's rows through `podman machine ssh` and the machine's sudo, each printed as PASS, FAIL or
# INFO. The transcript and the files the rows produce land in OUTDIR (default: out-macos/ beside this
# script, ignored by git; the Windows driver writes out-wsl/). Send OUTDIR back; the transcript is
# what "Phase 4 on macOS" and the phase's gate are filled from. On Windows, phase4.ps1.
#
# The rows, in order: the environment, the build with the hash of its sources, the installation
# with the installed object's tags; the launch of a session through the launcher's steps 1 to 4
# ("Lifecycle"): the attach cgroup, the controller's attach with pins, the read-back, the proof
# fixture run by a process of the launcher's own below the cgroup, then the container, whose first
# process is refused a protected write; `podman exec`, `podman restart`, `podman kill`, the
# controller gone, a recreate that attaches the pinned programs and loads nothing, the socket rule's
# dependence on the mounts, the cgroup that cannot be removed while the container is in it and the
# enforcement that ends only when root unpins; the three defective controllers, caught before any
# container exists; a launch under --unix-sockets with the ninth hook and its proof; the pins reused
# across a rule change and a new build; the controller's refusals; the reconcile over its orphans,
# its kept sessions, its contradictions and its cleanup refusals; the costs of the launch's steps;
# and last, the restart invariant across a machine restart, which stops the podman machine and with
# it every session running on it, so the driver asks first and skips the rows unless answered yes.
#
# It writes a workspace fixture and the proof fixture under $HOME/.cache (the share the machine
# mounts), attach cgroups ko-agent-bpf4-* with their transient units, a podman volume, pins under
# /sys/fs/bpf/ko-agent-bpf-phase4 in the machine, session records under the machine's probe
# directory, and containers labelled ko-agent-bpf4.session; all are removed on exit.
set -u

PROBE_IMAGE=ko-agent-bpf-probe:phase4
MACHINE_DIR=.local/share/ko-agent-sandbox/bpf-probe4
CTL=./$MACHINE_DIR/controller
RB=./$MACHINE_DIR/readback
FXT=./$MACHINE_DIR/fixture
FXT_C=/out/fixture
TAGS=./$MACHINE_DIR/tags.txt
PIN_ROOT=/sys/fs/bpf/ko-agent-bpf-phase4
FIX=$HOME/.cache/ko-agent-bpf-phase4.$$
VOL=ko-agent-bpf4-vol
LABEL=ko-agent-bpf4.session
LABEL_CG=ko-agent-bpf4.cgroup
HOOKS8="file_open inode_create inode_mknod inode_symlink inode_link inode_rename inode_unlink inode_setattr"
HOOKS9="$HOOKS8 file_receive"
HOOKS7="file_open inode_create inode_mknod inode_symlink inode_link inode_rename inode_unlink"
# shellcheck disable=SC1007
PROBE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(cd "$PROBE_DIR/../../.." && pwd)
OUT=${1:-$PROBE_DIR/out-macos}

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
gt() { [ "$1" -gt "$2" ] 2> /dev/null; }
ne() { [ "$1" != "$2" ]; }
# A command in the machine, as the machine's user; its output is logged and returned.
vm() {
    out=$(podman machine ssh "$1" 2>&1 < /dev/null)
    status=$?
    printf '%s\n' "$out" >> "$TRANSCRIPT"
    printf '%s\n' "$out"
    return $status
}
# The value of KEY in the first line of INPUT holding it, as the binaries print `key=value`.
field() { printf '%s\n' "$2" | sed -n "s/.* $1=\([^ ]*\).*/\1/p" | head -1; }
count_lines() { printf '%s\n' "$2" | grep -c -- "$1"; }
step() { log ""; log "== $*"; }
sha256_stdin() {
    if command -v sha256sum > /dev/null 2>&1; then sha256sum | cut -d' ' -f1; else shasum -a 256 | cut -d' ' -f1; fi
}

cleanup() {
    step "cleanup"
    # shellcheck disable=SC2046
    podman rm -f $(podman ps -aq --filter "label=$LABEL") > /dev/null 2>&1
    vm "sudo -n umount $PIN_ROOT/r4 2>/dev/null; sudo -n umount $FIX/tree/vendor 2>/dev/null
        [ -x $CTL ] && sudo -n sh -c 'for d in $PIN_ROOT/*; do [ -e \"\$d\" ] && $CTL unpin \"\$d\"; done'
        sudo -n rmdir $PIN_ROOT 2>/dev/null
        systemctl --user stop 'ko-agent-bpf4-*' 2>/dev/null; systemctl --user reset-failed 2>/dev/null
        rmdir /sys/fs/cgroup/user.slice/user-*.slice/user@*.service/app.slice/ko-agent-bpf4-*/proof 2>/dev/null
        rmdir /sys/fs/cgroup/user.slice/user-*.slice/user@*.service/app.slice/ko-agent-bpf4-* 2>/dev/null
        rm -rf $MACHINE_DIR/sessions; true" > /dev/null
    podman volume rm -f "$VOL" > /dev/null 2>&1
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
MANAGER=$(vm "podman info --format '{{.Host.CgroupManager}}'")
RUNTIME=$(vm "podman info --format '{{.Host.OCIRuntime.Name}} {{.Host.OCIRuntime.Version}}'" | head -1)
info "machine user uid=$UID_VM kernel=$KERNEL_VM podman=$(podman --version) cgroup manager=$MANAGER" \
    "runtime=$RUNTIME"
mount_fs() { # the pseudo filesystems the controller and the read-back need, mounted where the machine does not
    vm "sudo -n sh -c 'findmnt -n /sys/kernel/security >/dev/null || \
            mount -t securityfs securityfs /sys/kernel/security'
        sudo -n sh -c 'findmnt -n /sys/fs/bpf >/dev/null || mount -t bpf bpf /sys/fs/bpf'" > /dev/null
}
mount_fs
info "lsm=$(vm 'sudo -n cat /sys/kernel/security/lsm')"
vm "findmnt -T $HOME -o TARGET,SOURCE,FSTYPE,OPTIONS" > "$OUT/findmnt.txt"
FS_TYPE=$(vm "findmnt -T $HOME -n -o FSTYPE")
info "share: $(sed -n 2p "$OUT/findmnt.txt"), type $FS_TYPE"
vm "sudo -n mkdir -p $PIN_ROOT" > /dev/null
mkdir -p "$FIX"

SLICE_ROOT=/sys/fs/cgroup/user.slice/user-$UID_VM.slice
APP_SLICE=/user.slice/user-$UID_VM.slice/user@$UID_VM.service/app.slice

# ---------------------------------------------------------------------------
step "build, with the hash of its sources, and install"
# ---------------------------------------------------------------------------
# The context holds the files sources.txt lists, the policy program of Phase 3 and the guard's
# records header among them; their hash in that order is what the plan's section names and
# check-evidence.sh recomputes.
CTX=$FIX/build-context
mkdir -p "$CTX"
while read -r src; do cp "$PROBE_DIR/$src" "$CTX/"; done < "$PROBE_DIR/sources.txt"
# shellcheck disable=SC2046
SOURCES_SHA=$(cd "$PROBE_DIR" && cat $(cat sources.txt) | sha256_stdin)
info "sources sha256=$SOURCES_SHA over $(tr '\n' ' ' < "$PROBE_DIR/sources.txt")"
# The procedure's digest, the two drivers and the rule defaults, says which measurement ran; it binds
# nothing, since the plan's sections name the compiled sources' hash alone.
PROCEDURE_SHA=$(cat "$PROBE_DIR/phase4.sh" "$PROBE_DIR/phase4.ps1" \
    "$REPO_DIR/src/main/resources/agentsandbox/file-rule-defaults" | sha256_stdin)
info "procedure sha256=$PROCEDURE_SHA over phase4.sh phase4.ps1 file-rule-defaults"
if ! podman build --build-arg "BUILD_KERNEL=$KERNEL_VM" -t "$PROBE_IMAGE" -f "$CTX/Containerfile" "$CTX" \
    >> "$TRANSCRIPT" 2>&1; then
    log "the probe image failed to build; the build log is in $TRANSCRIPT"
    exit 2
fi
vm "set -eu; mkdir -p $MACHINE_DIR
    podman create --replace --name ko-agent-bpf4-extract $PROBE_IMAGE >/dev/null
    podman cp ko-agent-bpf4-extract:/out/. $MACHINE_DIR/
    podman rm ko-agent-bpf4-extract >/dev/null
    cp $MACHINE_DIR/policy.bpf.o $MACHINE_DIR/policy-installed.bpf.o
    test -x $MACHINE_DIR/controller && test -x $MACHINE_DIR/readback && test -x $MACHINE_DIR/fixture" > /dev/null
check "probe installed in the machine" [ $? -eq 0 ]
leftover=$(vm "sudo -n sh -c 'ls $PIN_ROOT; for d in $PIN_ROOT/*; do [ -e \"\$d\" ] && $CTL unpin \"\$d\"; done' | \
    grep -v ^unpinned")
[ -z "$leftover" ] || info "pins left by an earlier run, removed: $(printf '%s' "$leftover" | tr '\n' ' ')"
{ echo "sources sha256=$SOURCES_SHA"; echo "procedure sha256=$PROCEDURE_SHA"
  vm "cat $MACHINE_DIR/clang-version.txt $MACHINE_DIR/build-kernel.txt $MACHINE_DIR/objects.sha256"
} > "$OUT/build.txt"
info "$(tr '\n' ' ' < "$OUT/build.txt")"
# The installation records the object's tags once, under the running kernel: the verifier's pass
# the plan's --build takes ("Lifecycle", 3).
tags=$(vm "sudo -n $RB tags policy.bpf.o $TAGS")
info "$(printf '%s\n' "$tags" | grep '^tags ')"
check "the installed object's nine tags are recorded" [ "$(field programs "$tags")" = 9 ]

# ---------------------------------------------------------------------------
step "the workspace fixture, the proof fixture, the records and the volume"
# ---------------------------------------------------------------------------
TREE=$FIX/tree
PROOF=$FIX/state/proof
RULES_A=$FIX/rules-a.txt
RULES_B=$FIX/rules-b.txt
REC_A=$FIX/records-a.bin
REC_B=$FIX/records-b.bin
# The rules: the launcher's defaults and an overlapping pair on purpose, the defaults' `read-only
# .vscode` and a later `writable .vscode/settings.json`. B lacks the later line: another rule file,
# whose records differ from A's, and under which A's proof fixture fails one expectation.
sed 's/#.*//' "$REPO_DIR/src/main/resources/agentsandbox/file-rule-defaults" | awk 'NF == 2' > "$RULES_B"
cp "$RULES_B" "$RULES_A"
echo "writable .vscode/settings.json" >> "$RULES_A"
GUARDED="--guarded workspace= --guarded guarded-git=.git --guarded guarded-sandbox=.ko-agent-sandbox"
made=$(vm "$FXT make $TREE $RULES_A && mkdir -p $(dirname "$PROOF") && $FXT make $PROOF $RULES_A && \
    $FXT records $RULES_A $REC_A $GUARDED && $FXT records $RULES_B $REC_B $GUARDED")
printf '%s\n' "$made" | sed 's/^/  /' | tee -a "$TRANSCRIPT" > /dev/null
check "the workspace fixture, the proof fixture and two records files exist" \
    eq2 "$(count_lines '^make ' "$made")" 2 "$(count_lines '^records ' "$made")" 2
podman volume create "$VOL" > /dev/null 2>&1
VOLMP=$(vm "podman volume inspect --format '{{.Mountpoint}}' $VOL")
info "the volume's mountpoint in the machine: $VOLMP, on $(vm "findmnt -T $VOLMP -n -o FSTYPE")"
SESSION_OPTS="--userns=keep-id --security-opt seccomp=unconfined --volume $FIX:$FIX --volume $VOL:/vol"
# The session's first process: a protected write, refused, and an ordinary one, then it waits.
SESSION_CMD="echo STARTED; $FXT_C write $TREE/.git/config; $FXT_C write $TREE/ordinary; exec sleep infinity"
# The rule file and the records of the launch at hand: B's during the rule-change rows. The proof
# fixture is laid out for PROOF_LAID's rules, and PROOF_DIRTY says a proof failed on it.
RULES_CUR=$RULES_A
REC_CUR=$REC_A
PROOF_LAID=$RULES_A
PROOF_DIRTY=no
EXPECT_A="--tags $TAGS --records $REC_A --workspace $TREE --fixture $PROOF --volume $VOLMP"
EXPECT_B="--tags $TAGS --records $REC_B --workspace $TREE --fixture $PROOF --volume $VOLMP"

# ---------------------------------------------------------------------------
# The launcher's steps, as functions
# ---------------------------------------------------------------------------
# attach_cgroup NAME: step 1. Sets CG, the cgroup's sysfs path, and PARENT, the --cgroup-parent
# value: a transient slice held by a unit under systemd, a directory under the user's delegated
# subtree under cgroupfs ("Lifecycle", 1).
attach_cgroup() {
    if [ "$MANAGER" = systemd ]; then
        vm "systemctl --user stop ko-agent-bpf4-hold-$1 2>/dev/null; systemctl --user reset-failed 2>/dev/null
            systemd-run --user --unit=ko-agent-bpf4-hold-$1 --slice=ko-agent-bpf4-$1.slice /usr/bin/sleep 3600" \
            > /dev/null
        CG=$(vm "find /sys/fs/cgroup/user.slice -type d -name ko-agent-bpf4-$1.slice 2>/dev/null | head -1")
        PARENT=ko-agent-bpf4-$1.slice
    else
        PARENT=$APP_SLICE/ko-agent-bpf4-$1
        CG=/sys/fs/cgroup$PARENT
        vm "mkdir -p $CG" > /dev/null
    fi
    [ -n "$CG" ] || { fail "no attach cgroup for $1"; CG=/nonexistent; }
}
release_hold() { [ "$MANAGER" = systemd ] && vm "systemctl --user stop ko-agent-bpf4-hold-$1" > /dev/null; true; }
remove_cgroup() { # remove_cgroup NAME: what teardown does under each manager
    if [ "$MANAGER" = systemd ]; then
        vm "systemctl --user stop ko-agent-bpf4-hold-$1 ko-agent-bpf4-$1.slice 2>/dev/null; true" > /dev/null
    else
        vm "rmdir /sys/fs/cgroup$APP_SLICE/ko-agent-bpf4-$1/proof 2>/dev/null
            rmdir /sys/fs/cgroup$APP_SLICE/ko-agent-bpf4-$1" > /dev/null
    fi
}
cgroup_id() { vm "stat -c %i $1"; }
# record_session NAME CG: what the launcher records for the reconcile: the cgroup's path and identity.
record_session() {
    vm "mkdir -p $MACHINE_DIR/sessions && echo 'cgroup=$2 cgroup_id=$(cgroup_id "$2")' > $MACHINE_DIR/sessions/$1" \
        > /dev/null
}
forget_session() { vm "rm -f $MACHINE_DIR/sessions/$1" > /dev/null; }
# proof CG PARENT [--unix-sockets]: step 3's second part, the fixture run by a process of the
# launcher's own below the attach cgroup: a scope under the slice, or a leaf directory the process
# joins, since a cgroup with controllers enabled for its children takes no process of its own. The
# join needs write access to the common ancestor's cgroup.procs, and an ssh session's cgroup shares
# none the user owns with the delegated subtree, so a transient scope of the user manager comes
# first ("Phase 4 on WSL").
proof() {
    if [ "$MANAGER" = systemd ]; then
        vm "systemd-run --user --scope --slice=$2 -q $FXT run $PROOF $RULES_CUR ${3:-}"
    else
        vm "mkdir -p $1/proof && systemd-run --user --scope -q sh -c 'echo join from=\$(cat /proc/self/cgroup) \
            to=$1/proof; exec $FXT join $1/proof $FXT run $PROOF $RULES_CUR ${3:-}'; rmdir $1/proof"
    fi
}
# launch NAME fresh|restart CONTROLLER-OPTIONS CONTROLLER-HOOKS [EXPECT HOOKS]: steps 1 to 4 for a
# session. The read-back expects HOOKS8 under A's records unless EXPECT and HOOKS are given. Sets
# L_ATTACH, L_CHECK, L_VERIFY, L_PROOF, L_STEP (the step reached: attach, verify, proof, created,
# started) and L_CG.
launch() {
    name=$1
    mode=$2
    ctl_opts=$3
    ctl_hooks=$4
    expect=${5:-$EXPECT_A}
    hooks=${6:-$HOOKS8}
    L_ATTACH=
    L_CHECK=
    L_VERIFY=
    L_PROOF=
    L_STEP=attach
    attach_cgroup "$name"
    L_CG=$CG
    L_PARENT=$PARENT
    pins=$PIN_ROOT/$name
    reuse=no
    # The proof fixture is laid out once; its entries are laid out again, the root keeping its
    # identity, only after a failed proof or for other rules ("Lifecycle", 3).
    if [ "$PROOF_DIRTY" = yes ] || [ "$PROOF_LAID" != "$RULES_CUR" ]; then
        vm "find $PROOF -mindepth 1 -delete && $FXT make $PROOF $RULES_CUR" > /dev/null
        PROOF_LAID=$RULES_CUR
        PROOF_DIRTY=no
    fi
    if [ "$mode" = restart ]; then
        # shellcheck disable=SC2086
        L_CHECK=$(vm "sudo -n $RB check-pins $pins $expect $hooks")
        if has ' ok=1' "$L_CHECK"; then reuse=yes; else vm "sudo -n $CTL unpin $pins" > /dev/null; fi
    else
        vm "sudo -n $CTL unpin $pins" > /dev/null
    fi
    if [ "$reuse" = yes ]; then
        L_ATTACH=$(vm "sudo -n $CTL attach-pinned $CG $pins $ctl_hooks")
    else
        # shellcheck disable=SC2086
        L_ATTACH=$(vm "sudo -n $CTL attach $CG $pins --records $REC_CUR --workspace $TREE --fixture $PROOF \
            --volume $VOLMP $ctl_opts $ctl_hooks")
    fi
    printf '%s\n' "$L_ATTACH" | grep -E '^(attach|attach-pinned|refused) ' | sed 's/^/  /' | tee -a "$TRANSCRIPT"
    has '^attach' "$L_ATTACH" || return 1
    L_STEP=verify
    # shellcheck disable=SC2086
    L_VERIFY=$(vm "sudo -n $RB verify $CG $expect $hooks")
    printf '%s\n' "$L_VERIFY" | sed 's/^/  /' | tee -a "$TRANSCRIPT"
    has 'verify ok=1' "$L_VERIFY" || return 1
    L_STEP=proof
    case $ctl_opts in *unix-sockets*) proof_flag=--unix-sockets ;; *) proof_flag= ;; esac
    L_PROOF=$(proof "$CG" "$PARENT" "$proof_flag")
    printf '%s\n' "$L_PROOF" | grep -e mismatch -e '^fixture ops' | sed 's/^/  /' | tee -a "$TRANSCRIPT"
    [ "$(field mismatches "$L_PROOF")" = 0 ] || { PROOF_DIRTY=yes; return 1; }
    L_STEP=created
    # shellcheck disable=SC2086
    podman create --name "$name" --restart=no --cgroup-parent="$PARENT" --label "$LABEL=$name" --label "$LABEL_CG=$CG" \
        $SESSION_OPTS "$PROBE_IMAGE" sh -c "$SESSION_CMD" > /dev/null 2>&1 || return 1
    record_session "$name" "$CG"
    podman start "$name" > /dev/null 2>&1 || return 1
    L_STEP=started
}
exec_write() { podman exec "$1" $FXT_C write "$2" 2>&1 | tee -a "$TRANSCRIPT"; }
wait_logs() { # wait_logs NAME PATTERN COUNT: until the container's log holds COUNT lines of PATTERN, within 20 s
    i=0
    while [ $i -lt 40 ] && [ "$(podman logs "$1" 2>&1 | grep -c -- "$2")" -lt "$3" ]; do sleep 0.5; i=$((i + 1)); done
    podman logs "$1" 2>&1 | tee -a "$TRANSCRIPT"
}

# ---------------------------------------------------------------------------
step "the launch: steps 1 to 4, the first process refused, exec, restart, kill, the controller gone"
# ---------------------------------------------------------------------------
launch s1 fresh "" "$HOOKS8"
check "the launch ran every step: attach, read-back, proof, create, start (reached $L_STEP)" [ "$L_STEP" = started ]
check "the controller attached eight hooks with $(field rule_count "$L_ATTACH") rules and five roots, and pinned" \
    eq2 "$(field hooks "$L_ATTACH")" 8 "$(field roots "$L_ATTACH")" 5
check "the read-back finds eight programs of the installed tags over one map set holding the records" \
    eq2 "$(field programs "$L_VERIFY")" 8 "$(field maps "$L_VERIFY")" 9
check "the proof: $(printf '%s\n' "$L_PROOF" | grep '^fixture ops')" \
    eq2 "$(field mismatches "$L_PROOF")" 0 "$(gt "$(field ops "$L_PROOF")" 60; echo $?)" 0
logs=$(wait_logs s1 'result=' 2)
check "the first process is refused the protected write and makes the ordinary one" \
    eq2 "$(has '\.git/config result=EPERM' "$logs"; echo $?)" 0 "$(has 'tree/ordinary result=ok' "$logs"; echo $?)" 0
# The link's cgroup id is the attach cgroup's inode number: the identity the reconcile records.
CG_ID_S1=$(cgroup_id "$L_CG")
check "the links carry the attach cgroup's identity, its inode number $CG_ID_S1" \
    [ "$(field cgroup_id "$L_ATTACH")" = "$CG_ID_S1" ]
check "the controller has exited and no process of it remains while the policy holds" \
    has NONE "$(vm 'pgrep -x controller >/dev/null && echo RUNNING || echo NONE')"
check "podman exec joins the container's cgroup and is refused the protected write" \
    has 'result=EPERM' "$(exec_write s1 "$TREE/.git/config")"
# The socket rule's dependence on the mounts ("The policy"): a directory under the container's own
# filesystem holding a bound socket cannot be moved into the volume or the workspace.
sock=$(podman exec s1 sh -c "mkdir -p /tmp/d && $FXT_C bind /tmp/d/s; $FXT_C rename /tmp/d /vol/d; \
    $FXT_C rename /tmp/d $TREE/d" 2>&1 | tee -a "$TRANSCRIPT")
check "a directory holding a bound socket cannot be renamed into the volume or the workspace: EXDEV" \
    eq2 "$(count_lines 'result=EXDEV' "$sock")" 2 "$(has 'bind path=/tmp/d/s result=ok' "$sock"; echo $?)" 0
podman restart s1 > /dev/null 2>&1
logs=$(wait_logs s1 STARTED 2)
check "after podman restart the first process runs again under the policy and is refused again" \
    eq2 "$(count_lines STARTED "$logs")" 2 "$(count_lines '\.git/config result=EPERM' "$logs")" 2
podman kill s1 > /dev/null 2>&1
sleep 1
query=$(vm "sudo -n $CTL query $L_CG")
link=$(vm "sudo -n $CTL link-info $PIN_ROOT/s1/links/file_open")
check "after podman kill the container is exited and the programs stay attached: $(field prog_cnt "$query")" \
    eq2 "$(podman inspect --format '{{.State.Status}}' s1)" exited "$(field prog_cnt "$query")" 8
check "the pinned link still names the cgroup: $link" [ "$(field cgroup_id "$link")" = "$CG_ID_S1" ]
check "the created container's restart policy reads no" \
    [ "$(podman inspect --format '{{.HostConfig.RestartPolicy.Name}}' s1)" = no ]
# The policy cannot lapse without a trusted hand: the cgroup with the container's scope in it is
# not removable, and only root's unpin ends the enforcement.
podman start s1 > /dev/null 2>&1
rmdir_out=$(vm "sudo -n rmdir $L_CG 2>&1 || echo RMDIR_FAILED")
check "the attach cgroup cannot be removed while the container is in it: $(printf '%s' "$rmdir_out" | tr '\n' ' ')" \
    has RMDIR_FAILED "$rmdir_out"
vm "sudo -n $CTL unpin $PIN_ROOT/s1" > /dev/null
query=$(vm "sudo -n $CTL query $L_CG")
after_unpin=$(exec_write s1 "$TREE/.git/config")
check "root unpinning the links ends the enforcement: 0 programs attached, the protected write succeeds" \
    eq2 "$(field prog_cnt "$query")" 0 "$(has 'result=ok' "$after_unpin"; echo $?)" 0
podman rm -f s1 > /dev/null 2>&1
forget_session s1
remove_cgroup s1
COST_ATTACH="$(field load_ms "$L_ATTACH") $(field fill_ms "$L_ATTACH") $(field attach_ms "$L_ATTACH")"
COST_VERIFY=$(field ms "$L_VERIFY")
COST_PROOF=$(field ms "$L_PROOF")

# ---------------------------------------------------------------------------
step "a recreate attaches the pinned programs and loads nothing"
# ---------------------------------------------------------------------------
launch s2 fresh "" "$HOOKS8"
check "s2 launched fresh (reached $L_STEP)" [ "$L_STEP" = started ]
podman rm -f s2 > /dev/null 2>&1
remove_cgroup s2
link=$(vm "sudo -n $CTL link-info $PIN_ROOT/s2/links/file_open")
check "with its cgroup removed the pinned link is detached, cgroup_id 0, and the pinned programs stay" \
    eq2 "$(field cgroup_id "$link")" 0 "$(vm "sudo -n test -e $PIN_ROOT/s2/progs/file_open && echo PRESENT")" PRESENT
launch s2 restart "" "$HOOKS8"
pinned_start() { [ "$L_STEP" = started ] && has '^attach-pinned ' "$L_ATTACH"; }
check "the recreate checked the pins, attached them to the new cgroup and started (reached $L_STEP)" \
    eq2 "$(has 'check-pins ok=1' "$L_CHECK"; echo $?)" 0 "$(pinned_start; echo $?)" 0
logs=$(wait_logs s2 'result=' 2)
check "the recreated session's first process is refused the protected write" has '\.git/config result=EPERM' "$logs"
COST_PINNED=$(field ms "$L_ATTACH")
COST_CHECK=$(field ms "$L_CHECK")
podman rm -f s2 > /dev/null 2>&1
forget_session s2
remove_cgroup s2

# ---------------------------------------------------------------------------
step "the three defective controllers, each caught before any container exists"
# ---------------------------------------------------------------------------
# No container is created when a step before 4 fails; each launch ends at the read-back.
no_container() { ! podman container exists "$1" 2> /dev/null; }
launch d1 fresh "" "$HOOKS7"
verdict() { printf '%s\n' "$1" | grep 'ok=0' | cut -c1-70; }
check "a controller attaching seven of the eight hooks is caught by the read-back: $(verdict "$L_VERIFY")" \
    eq2 "$L_STEP" verify "$(field reason "$L_VERIFY")" hook-set
check "no container d1 exists" no_container d1
vm "sudo -n $CTL unpin $PIN_ROOT/d1" > /dev/null
remove_cgroup d1
launch d2 fresh "--object other.bpf.o" "$HOOKS8"
check "a controller attaching another build's programs is caught by their tags: $(verdict "$L_VERIFY")" \
    eq2 "$L_STEP" verify "$(field reason "$L_VERIFY")" tag
check "no container d2 exists" no_container d2
vm "sudo -n $CTL unpin $PIN_ROOT/d2" > /dev/null
remove_cgroup d2
launch d3 fresh "--records $REC_B" "$HOOKS8"
check "a controller loading another rule file's records is caught by the map contents: $(verdict "$L_VERIFY")" \
    eq2 "$L_STEP" verify "$(field reason "$L_VERIFY")" map-contents
check "no container d3 exists" no_container d3
# The proof alone would catch the records too: one expectation of A's fixture fails under B.
proof_b=$(proof "$L_CG" "$L_PARENT")
PROOF_DIRTY=yes
printf '%s\n' "$proof_b" | grep -e mismatch -e '^fixture ops' | sed 's/^/  /' | tee -a "$TRANSCRIPT"
check "the proof fixture catches the wrong records as well: $(printf '%s\n' "$proof_b" | grep '^fixture ops')" \
    [ "$(field mismatches "$proof_b")" = 1 ]
vm "sudo -n $CTL unpin $PIN_ROOT/d3" > /dev/null
remove_cgroup d3
launch d4 fresh "--object other-data.bpf.o" "$HOOKS8"
check "a controller attaching a build differing in data alone: $(verdict "$L_VERIFY")" \
    eq2 "$L_STEP" verify "$(field reason "$L_VERIFY")" rodata
check "no container d4 exists" no_container d4
vm "sudo -n $CTL unpin $PIN_ROOT/d4" > /dev/null
remove_cgroup d4

# ---------------------------------------------------------------------------
step "a launch under --unix-sockets: nine hooks, the proof's socket in .git and file_receive"
# ---------------------------------------------------------------------------
launch u1 fresh "--flags unix-sockets" "$HOOKS9" "$EXPECT_A --flags unix-sockets" "$HOOKS9"
check "the launch under unix-sockets ran every step with nine hooks (reached $L_STEP)" \
    eq2 "$L_STEP" started "$(field programs "$L_VERIFY")" 9
check "the proof refused a socket in .git and a directory descriptor from another mount namespace" \
    eq2 "$(has 'op=bind path=.git/ko-sock expect=EPERM got=EPERM' "$L_PROOF"; echo $?)" 0 \
        "$(has 'op=receive-dir path=. expect=refused got=refused' "$L_PROOF"; echo $?)" 0
podman rm -f u1 > /dev/null 2>&1
forget_session u1
vm "sudo -n $CTL unpin $PIN_ROOT/u1" > /dev/null
remove_cgroup u1

# ---------------------------------------------------------------------------
step "pins across a rule change and a new build"
# ---------------------------------------------------------------------------
launch s3 fresh "" "$HOOKS8"
check "s3 launched fresh (reached $L_STEP)" [ "$L_STEP" = started ]
PROG_ID_S3=$(field prog_id "$L_ATTACH")
podman rm -f s3 > /dev/null 2>&1
remove_cgroup s3
# A rule change: the pinned programs hold A's records, this launch wants B's, and its proof
# fixture and expectations follow B.
REC_CUR=$REC_B
RULES_CUR=$RULES_B
launch s3 restart "" "$HOOKS8" "$EXPECT_B"
fresh_start() { [ "$L_STEP" = started ] && has '^attach ' "$L_ATTACH"; }
check "after a rule change the pins fail the check and fresh programs are loaded: $(verdict "$L_CHECK")" \
    eq2 "$(field reason "$L_CHECK")" map-contents "$(fresh_start; echo $?)" 0
check "the fresh programs are new: prog_id $(field prog_id "$L_ATTACH") after $PROG_ID_S3" \
    [ "$(field prog_id "$L_ATTACH")" != "$PROG_ID_S3" ]
PROG_ID_S3=$(field prog_id "$L_ATTACH")
podman rm -f s3 > /dev/null 2>&1
remove_cgroup s3
# A new build installed: the other object takes the installed one's place and its tags are recorded.
vm "cp $MACHINE_DIR/other.bpf.o $MACHINE_DIR/policy.bpf.o && sudo -n $RB tags policy.bpf.o $TAGS" > /dev/null
launch s3 restart "" "$HOOKS8" "$EXPECT_B"
REC_CUR=$REC_A
RULES_CUR=$RULES_A
check "after a new build the pins fail the check on their tags and fresh programs are loaded: $(verdict "$L_CHECK")" \
    eq2 "$(field reason "$L_CHECK")" tag "$(fresh_start; echo $?)" 0
check "the fresh programs are the new build's, prog_id $(field prog_id "$L_ATTACH") after $PROG_ID_S3, verified" \
    eq2 "$(ne "$(field prog_id "$L_ATTACH")" "$PROG_ID_S3"; echo $?)" 0 "$(field programs "$L_VERIFY")" 8
old_pins=$(vm "sudo -n ls $PIN_ROOT/s3/links $PIN_ROOT/s3/progs | grep -c -v -e '^\$' -e ':\$'")
check "the old pins are gone: the pin directory holds the eight links and eight programs of this launch alone" \
    [ "$old_pins" = 16 ]
podman rm -f s3 > /dev/null 2>&1
forget_session s3
vm "sudo -n $CTL unpin $PIN_ROOT/s3" > /dev/null
remove_cgroup s3
vm "cp $MACHINE_DIR/policy-installed.bpf.o $MACHINE_DIR/policy.bpf.o && sudo -n $RB tags policy.bpf.o $TAGS" > /dev/null

# ---------------------------------------------------------------------------
step "the controller's refusals"
# ---------------------------------------------------------------------------
attach_cgroup x1
refusal() { # refusal CONTROLLER-ARGS...: the controller's refused line and status 3
    out=$(vm "sudo -n $CTL $*; echo STATUS=\$?")
    printf '%s\n' "$out" | grep -E '^(refused|STATUS)' | tr '\n' ' '
}
common="--records $REC_A --workspace $TREE --fixture $PROOF --volume $VOLMP"
r=$(refusal attach "$CG" "$PIN_ROOT/x1" "$common" --object /tmp/other.bpf.o "$HOOKS8")
check "an object given as a path is refused: $r" eq2 "$(field reason "$r")" object-path "$(field STATUS "$r")" 3
r=$(refusal attach /sys/fs/cgroup/system.slice "$PIN_ROOT/x1" "$common" "$HOOKS8")
check "a cgroup outside the invoking user's slice is refused: $r" \
    eq2 "$(field reason "$r")" cgroup-outside-slice "$(field STATUS "$r")" 3
mkdir -p "$TREE/vendor"
vm "sudo -n mount -t tmpfs tmpfs $TREE/vendor" > /dev/null
r=$(refusal attach "$CG" "$PIN_ROOT/x1" "$common" --bind-source "$TREE" "$HOOKS8")
check "a mount under the bind source refuses the launch and is named: $r" \
    eq2 "$(field reason "$r")" mount-under-bind-source "$(field STATUS "$r")" 3
vm "sudo -n umount $TREE/vendor" > /dev/null
r=$(refusal attach "$CG" "$PIN_ROOT/x1" --records "$REC_A" --workspace "$TREE" --fixture /tmp --volume "$VOLMP" \
    "$HOOKS8")
check "a proof fixture on another filesystem type is refused: $r" \
    eq2 "$(field reason "$r")" fixture-fs-type "$(field STATUS "$r")" 3
check "none of the refused attaches pinned anything" \
    [ "$(vm "sudo -n test -e $PIN_ROOT/x1 && echo PRESENT || echo ABSENT")" = ABSENT ]
remove_cgroup x1

# ---------------------------------------------------------------------------
step "the reconcile: orphans, kept sessions, contradictions, cleanup refusals"
# ---------------------------------------------------------------------------
# reconcile [fail]: the launcher's start. The recorded sessions, the containers by their labels,
# then the controller; a session some container names is kept, one whose container's label names
# another cgroup than the record is held; a session without a container has its hold unit stopped
# first, so that the hold does not count as populated ("Lifecycle", 7). A listing or a label read
# that fails tells the controller so, which then removes nothing; `fail` makes the listing fail.
# Sets R_OUT.
reconcile() {
    args="--manager $MANAGER"
    records=$(vm "cd $MACHINE_DIR/sessions 2>/dev/null && \
        for f in *; do [ -f \"\$f\" ] && echo \"\$f \$(cat \$f)\"; done")
    # `podman ps` renders .Labels as text, so the labels are read from each container's inspect.
    format="{{index .Config.Labels \"$LABEL\"}} {{index .Config.Labels \"$LABEL_CG\"}}"
    list_cmd="podman ps -aq --filter label=$LABEL"
    [ "${1:-}" = fail ] && list_cmd=false
    listing=$(vm "ids=\$($list_cmd) || exit 9
        for id in \$ids; do podman inspect --format '$format' \$id || exit 9; done; echo LISTING_OK")
    listing_failed=no
    if has LISTING_OK "$listing"; then labels=$(printf '%s\n' "$listing" | grep -v LISTING_OK)
    else listing_failed=yes; args="$args --listing-failed"; labels=; fi
    printf '%s\n' "$records" | while read -r name rest; do
        [ -n "$name" ] || continue
        cg=$(field cgroup "x $rest")
        id=$(field cgroup_id "x $rest")
        named=$(printf '%s\n' "$labels" | awk -v n="$name" '$1 == n { print $2 }')
        if [ -z "$named" ]; then
            [ "$listing_failed" = no ] && release_hold "$name"
        elif [ "$named" = "$cg" ]; then
            echo "--named $name"
        else
            echo "--hold $name"
        fi
        echo "--session $name $cg $id"
    done > "$FIX/reconcile-args"
    # A stopped hold unit leaves its slice; populated follows within the second.
    sleep 1
    # shellcheck disable=SC2046
    R_OUT=$(vm "sudo -n $CTL reconcile $PIN_ROOT $args $(tr '\n' ' ' < "$FIX/reconcile-args")")
    printf '%s\n' "$R_OUT" | sed 's/^/  /' | tee -a "$TRANSCRIPT"
    printf '%s\n' "$R_OUT" | sed -n 's/.*cgroup=stop-slice slice=\(.*\)/\1/p' | while read -r slice; do
        vm "systemctl --user stop $slice" > /dev/null
    done
    printf '%s\n' "$R_OUT" | sed -n 's/^reconcile session=\([^ ]*\) action=removed.*/\1/p' | while read -r name; do
        forget_session "$name"
    done
}
action_of() { printf '%s\n' "$R_OUT" | sed -n "s/^reconcile session=$1 action=\([^ ]*\).*/\1/p"; }
reason_of() { printf '%s\n' "$R_OUT" | sed -n "s/^reconcile session=$1 .*reason=\([^ ]*\).*/\1/p"; }
# o1: the launcher killed between the pins and podman create.
attach_cgroup o1
vm "sudo -n $CTL attach $CG $PIN_ROOT/o1 $common $HOOKS8" > /dev/null
record_session o1 "$CG"
# o2: podman create fails after the pins.
attach_cgroup o2
vm "sudo -n $CTL attach $CG $PIN_ROOT/o2 $common $HOOKS8" > /dev/null
record_session o2 "$CG"
podman create --name o2 --cgroup-parent="$PARENT" --label "$LABEL=o2" --label "$LABEL_CG=$CG" \
    localhost/ko-agent-bpf4-no-such-image:none true > /dev/null 2>&1 && fail "podman create of a missing image worked"
# o3: the launcher killed between podman create and podman start.
attach_cgroup o3
vm "sudo -n $CTL attach $CG $PIN_ROOT/o3 $common $HOOKS8" > /dev/null
record_session o3 "$CG"
# shellcheck disable=SC2086
podman create --name o3 --restart=no --cgroup-parent="$PARENT" --label "$LABEL=o3" --label "$LABEL_CG=$CG" \
    $SESSION_OPTS "$PROBE_IMAGE" sh -c "$SESSION_CMD" > /dev/null 2>&1
# st: a stopped session; lv: a live one.
launch st fresh "" "$HOOKS8"
podman kill st > /dev/null 2>&1
launch lv fresh "" "$HOOKS8"
state() { podman inspect --format '{{.State.Status}}' "$1"; }
check "the reconcile's sessions exist: o1, o2, o3, st stopped, lv live" eq2 "$(state st)" exited "$(state lv)" running
reconcile fail
check "a listing that fails removes nothing: $(printf '%s\n' "$R_OUT" | grep '^reconcile listing')" \
    eq2 "$(field removed "$R_OUT")" 0 "$(has 'listing=failed' "$R_OUT"; echo $?)" 0
reconcile
check "the two orphans are removed, pins and cgroups: o1 $(action_of o1), o2 $(action_of o2)" \
    eq2 "$(action_of o1)" removed "$(action_of o2)" removed
check "o3 (a created container), st (stopped) and lv (live) stay: $(action_of o3) $(action_of st) $(action_of lv)" \
    eq2 "$(action_of o3)$(action_of st)" keptkept "$(action_of lv)" kept
check "nothing else was removed: $(printf '%s\n' "$R_OUT" | grep '^reconcile sessions')" \
    [ "$(field removed "$R_OUT")" = 2 ]
check "o1's and o2's pins and cgroups are gone, o3's and st's stay" \
    eq2 "$(vm "sudo -n ls -d $PIN_ROOT/o1 $PIN_ROOT/o2 2>/dev/null | wc -l | tr -d ' '")" 0 \
        "$(vm "sudo -n ls -d $PIN_ROOT/o3 $PIN_ROOT/st 2>/dev/null | wc -l | tr -d ' '")" 2
podman rm o3 > /dev/null 2>&1
reconcile
check "once its container is removed, o3's pins and cgroup go: $(action_of o3)" [ "$(action_of o3)" = removed ]
# The contradictions: c1, a container whose labels name another session's cgroup; c2, a cgroup
# whose identity changed since the record; c4, a pin directory whose links name another cgroup.
attach_cgroup c1
vm "sudo -n $CTL attach $CG $PIN_ROOT/c1 $common $HOOKS8" > /dev/null
record_session c1 "$CG"
podman create --name c1 --cgroup-parent="$PARENT" --label "$LABEL=c1" --label "$LABEL_CG=/elsewhere" "$PROBE_IMAGE" \
    true > /dev/null 2>&1
attach_cgroup c2
vm "sudo -n $CTL attach $CG $PIN_ROOT/c2 $common $HOOKS8" > /dev/null
record_session c2 "$CG"
C2_ID=$(cgroup_id "$CG")
remove_cgroup c2
attach_cgroup c2
info "c2's cgroup recreated at its path: identity $C2_ID before, $(cgroup_id "$CG") after"
attach_cgroup c3
vm "sudo -n $CTL attach $CG $PIN_ROOT/c3 $common $HOOKS8" > /dev/null
attach_cgroup c4
vm "sudo -n mv $PIN_ROOT/c3 $PIN_ROOT/c4" > /dev/null
record_session c4 "$CG"
reconcile
check "a container whose label names another cgroup leaves c1 unassociated and kept: $(action_of c1) $(reason_of c1)" \
    eq2 "$(action_of c1)" kept "$(reason_of c1)" identity-contradicted
check "a cgroup whose identity changed is refused: $(action_of c2) $(reason_of c2)" \
    eq2 "$(action_of c2)" refused "$(reason_of c2)" cgroup-identity
check "a pin directory whose links name another cgroup is refused: $(action_of c4) $(reason_of c4)" \
    eq2 "$(action_of c4)" refused "$(reason_of c4)" pin-names-another-cgroup
check "nothing was removed for them" [ "$(field removed "$R_OUT")" = 0 ]
podman rm -f c1 > /dev/null 2>&1
vm "sudo -n $CTL unpin $PIN_ROOT/c1; sudo -n $CTL unpin $PIN_ROOT/c2; sudo -n $CTL unpin $PIN_ROOT/c4
    rm -f $MACHINE_DIR/sessions/c1 $MACHINE_DIR/sessions/c2 $MACHINE_DIR/sessions/c4" > /dev/null
remove_cgroup c1
remove_cgroup c2
remove_cgroup c3
remove_cgroup c4
# A refusal removes nothing: c5's links hold one of c6's among their own, and c7's progs directory
# is a symlink; every pin of both must survive the reconcile.
attach_cgroup c5
vm "sudo -n $CTL attach $CG $PIN_ROOT/c5 $common $HOOKS8" > /dev/null
record_session c5 "$CG"
attach_cgroup c6
vm "sudo -n $CTL attach $CG $PIN_ROOT/c6 $common $HOOKS8" > /dev/null
vm "sudo -n mv $PIN_ROOT/c6/links/inode_setattr $PIN_ROOT/c5/links/zz-foreign" > /dev/null
attach_cgroup c7
vm "sudo -n $CTL attach $CG $PIN_ROOT/c7 $common $HOOKS8" > /dev/null
record_session c7 "$CG"
vm "sudo -n mv $PIN_ROOT/c7/progs $PIN_ROOT/c7/progs-real && sudo -n ln -s progs-real $PIN_ROOT/c7/progs" \
    > /dev/null
reconcile
pins_of() { vm "sudo -n sh -c 'ls $PIN_ROOT/$1/$2 2>/dev/null | wc -l'" | tr -d ' '; }
check "one foreign link among a session's pins refuses it: $(action_of c5) $(reason_of c5)" \
    eq2 "$(action_of c5)" refused "$(reason_of c5)" pin-names-another-cgroup
check "and every pin of c5 survives: $(pins_of c5 links) links, $(pins_of c5 progs) programs" \
    eq2 "$(pins_of c5 links)" 9 "$(pins_of c5 progs)" 8
check "a progs directory that is a symlink refuses the session: $(action_of c7) $(reason_of c7)" \
    eq2 "$(action_of c7)" refused "$(reason_of c7)" pins-open
check "and every link of c7 survives: $(pins_of c7 links) links" [ "$(pins_of c7 links)" = 8 ]
vm "sudo -n rm $PIN_ROOT/c7/progs && sudo -n mv $PIN_ROOT/c7/progs-real $PIN_ROOT/c7/progs
    sudo -n $CTL unpin $PIN_ROOT/c5; sudo -n $CTL unpin $PIN_ROOT/c6; sudo -n $CTL unpin $PIN_ROOT/c7
    rm -f $MACHINE_DIR/sessions/c5 $MACHINE_DIR/sessions/c7" > /dev/null
remove_cgroup c5
remove_cgroup c6
remove_cgroup c7
# The cleanup's refusals, each with a valid empty cgroup and a defective pin path or record.
attach_cgroup r1
release_hold r1
R1_ID=$(cgroup_id "$CG")
R1_CG=$CG
r=$(vm "sudo -n $CTL reconcile $PIN_ROOT --manager $MANAGER --session ../r1 $R1_CG $R1_ID \
    --session r1 $SLICE_ROOT/../r1 $R1_ID")
printf '%s\n' "$r" | sed 's/^/  /' | tee -a "$TRANSCRIPT"
check "a session name and a cgroup path with a relative component are refused" \
    eq2 "$(count_lines 'action=refused reason=name' "$r")" 1 \
        "$(count_lines 'action=refused reason=cgroup-outside-slice' "$r")" 1
symlink=$(vm "sudo -n mkdir -p $PIN_ROOT/real && sudo -n ln -s $PIN_ROOT/real $PIN_ROOT/r2 2>&1 && echo LINKED")
if has LINKED "$symlink"; then
    r=$(vm "sudo -n $CTL reconcile $PIN_ROOT --manager $MANAGER --session r2 $R1_CG $R1_ID")
    printf '%s\n' "$r" | sed 's/^/  /' | tee -a "$TRANSCRIPT"
    check "a symlink in place of the pin directory is refused: $(printf '%s\n' "$r" | grep 'session=r2' | cut -c1-90)" \
        has 'session=r2 action=refused reason=pins-open' "$r"
    vm "sudo -n rm $PIN_ROOT/r2; sudo -n rmdir $PIN_ROOT/real" > /dev/null
else
    info "bpffs refused the symlink: $(printf '%s' "$symlink" | tr '\n' ' '); the row is not constructible here"
fi
cg_symlink=$(vm "ln -s $R1_CG /sys/fs/cgroup$APP_SLICE/ko-agent-bpf4-r3 2>&1 && echo LINKED || echo REFUSED")
info "a symlink in place of a cgroup directory: cgroup2 answers $(printf '%s' "$cg_symlink" | tr '\n' ' ')"
vm "sudo -n mkdir -p $PIN_ROOT/r4 && sudo -n mount -t tmpfs tmpfs $PIN_ROOT/r4" > /dev/null
r=$(vm "sudo -n $CTL reconcile $PIN_ROOT --manager $MANAGER --session r4 $R1_CG $R1_ID")
printf '%s\n' "$r" | sed 's/^/  /' | tee -a "$TRANSCRIPT"
check "a mount on the pin directory is refused: $(printf '%s\n' "$r" | grep 'session=r4' | cut -c1-90)" \
    has 'session=r4 action=refused reason=pins-open' "$r"
vm "sudo -n umount $PIN_ROOT/r4; sudo -n rmdir $PIN_ROOT/r4" > /dev/null
r=$(vm "sudo -n $CTL reconcile $PIN_ROOT --manager $MANAGER --session r1 $R1_CG $((R1_ID + 1))")
check "a cgroup whose recorded identity differs from the directory's is refused, nothing removed" \
    eq2 "$(has 'session=r1 action=refused reason=cgroup-identity' "$r"; echo $?)" 0 \
        "$(vm "test -d $R1_CG && echo PRESENT")" PRESENT
remove_cgroup r1

# ---------------------------------------------------------------------------
step "the costs of the launch's steps"
# ---------------------------------------------------------------------------
info "install, the verifier over nine programs (tags): $(field ms "$tags") ms"
info "step 2 at launch, the controller: load, fill, attach = $COST_ATTACH ms; step 2 at a recreate," \
    "attach-pinned: $COST_PINNED ms after check-pins $COST_CHECK ms"
info "step 3 at launch: read-back $COST_VERIFY ms, proof fixture $COST_PROOF ms ($(field ops "$L_PROOF") operations)"

# ---------------------------------------------------------------------------
step "a machine restart with a stopped session present: pins, cgroups, and nothing starts it"
# ---------------------------------------------------------------------------
# lv runs and st is stopped; both have pins. After the restart the pins and the attach cgroups are
# gone, the containers are not running, and podman-restart.service starts neither. The stop ends
# every session on the machine, so the driver asks first.
while :; do
    log "The next rows stop the podman machine, which ends every session running on it. Stop it now? [Y/n]"
    read -r answer < /dev/tty || answer=n
    case $answer in
        "" | y | Y | yes | Yes | YES) answer=y; break ;;
        n | N | no | No | NO) break ;;
        *) log "Answer y or n." ;;
    esac
done
if [ "$answer" != y ]; then
    info "skipped: the machine restart rows were declined"
    podman rm -f st lv > /dev/null 2>&1
    forget_session st
    forget_session lv
    [ "$failed" -eq 0 ] || exit 1
    exit 0
fi
podman kill lv > /dev/null 2>&1
before=$(vm "sudo -n ls $PIN_ROOT | tr '\n' ' '")
info "pins before the restart: $before"
info "podman machine stop at $(date +%H:%M:%S)"
podman machine stop >> "$TRANSCRIPT" 2>&1
info "podman machine start at $(date +%H:%M:%S)"
podman machine start >> "$TRANSCRIPT" 2>&1
info "machine started at $(date +%H:%M:%S)"
i=0
while [ $i -lt 60 ] && ! podman machine ssh true > /dev/null 2>&1; do sleep 2; i=$((i + 1)); done
sleep 15
mount_fs
check "after the machine restart no pin survives: $(vm "sudo -n ls $PIN_ROOT 2>&1 | tr '\n' ' '")" \
    [ "$(vm "sudo -n test -e $PIN_ROOT && echo PRESENT || echo ABSENT")" = ABSENT ]
check "the attach cgroups are gone" \
    [ "$(vm "find /sys/fs/cgroup/user.slice -type d -name 'ko-agent-bpf4-*' 2>/dev/null | wc -l | tr -d ' '")" = 0 ]
running() { podman inspect --format '{{.State.Running}}' "$1"; }
check "the stopped containers stay stopped: st $(state st), lv $(state lv)" \
    eq2 "$(running st)" false "$(running lv)" false
reconcile
check "the reconcile after the restart keeps the sessions that still have containers: $(action_of st) $(action_of lv)" \
    eq2 "$(action_of st)" kept "$(action_of lv)" kept
podman rm -f st lv > /dev/null 2>&1
forget_session st
forget_session lv

[ "$failed" -eq 0 ] || exit 1
