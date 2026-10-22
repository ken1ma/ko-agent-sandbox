#!/bin/sh
# Phase 2 of doc/plan-bpf-lsm-cgroup.md ("Phases", 2) on the macOS podman machine, in one run.
# Run it on the HOST, from the repository root, with the default machine running:
#
#     bpf/probe/phase2/phase2.sh [OUTDIR]
#
# It builds the probe image (Containerfile), extracts /out into the machine under
# ~/.local/share/ko-agent-sandbox/bpf-probe2, and runs the phase's rows through `podman machine
# ssh` and the machine's sudo, each printed as PASS, FAIL or INFO. The transcript and the files the
# rows produce land in OUTDIR (default: out/ beside this script, ignored by git). Send OUTDIR back;
# the transcript is what the plan's "Inventory" columns and Phase 2's gate are filled from.
# On Windows, phase2.ps1.
#
# The rows, in order: the environment; the verifier's answer to every inventory program and to the
# representative program, with the latter's full log for `inode_rename`; the inventory's operations
# (mutate.c) under each hook, in batches of eight hooks per slot pool, recording which hooks each
# operation reaches and whether a refusal reaches the caller as EPERM; the representative program
# attached with the defaults' rules filled to the map's capacity, deciding the corpus (mutate.c) on
# a fixture laid out as a workspace, and ordinary git in a clone of this repository; the walk's
# cost at the clone's deepest file, at depth 32 and at depth 63, under the policy and on the bare
# bind; a host-side mount inside the tree, made before and after the attach; a nested podman under
# the attribute hooks, recording and then refusing; the jited barrier.
#
# It writes a fixture under $HOME/.cache (the share the machine mounts), two attach cgroups with
# their transient units, pins under /sys/fs/bpf/ko-agent-bpf-phase2 in the machine, disk images
# attached inside the fixture, and containers named ko-agent-bpf2-*; all are removed on exit.
set -u

PROBE_IMAGE=ko-agent-bpf-probe:phase2
MACHINE_DIR=.local/share/ko-agent-sandbox/bpf-probe2
CTL=./$MACHINE_DIR/controller
MUTATE=/out/mutate
PIN_ROOT=/sys/fs/bpf/ko-agent-bpf-phase2
FIX=$HOME/.cache/ko-agent-bpf-phase2.$$
WALK_COUNT=2000
# shellcheck disable=SC1007
PROBE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(cd "$PROBE_DIR/../../.." && pwd)
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
    vm "for d in $PIN_ROOT/*; do sudo -n $CTL unpin \$d; done; sudo -n rmdir $PIN_ROOT 2>/dev/null; true" > /dev/null
    vm "systemctl --user stop ko-agent-bpf2-hold1 ko-agent-bpf2-hold2 ko-agent-bpf2-1.slice ko-agent-bpf2-2.slice \
        2>/dev/null; true" > /dev/null
    vm "rmdir /sys/fs/cgroup/user.slice/user-*.slice/user@*.service/app.slice/ko-agent-bpf2-? 2>/dev/null; true" \
        > /dev/null
    podman rm -f ko-agent-bpf2-nested > /dev/null 2>&1
    for when in before after; do
        [ -d "${TREE:-/nonexistent}/hostmount-$when" ] && hdiutil detach "$TREE/hostmount-$when" > /dev/null 2>&1
    done
    # An overlay's work directory is left mode 0 on the share.
    chmod -R u+rwX "$FIX" 2>/dev/null
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
vm "sudo -n sh -c 'findmnt -n /sys/kernel/security >/dev/null || mount -t securityfs securityfs /sys/kernel/security'
    sudo -n sh -c 'findmnt -n /sys/fs/bpf >/dev/null || mount -t bpf bpf /sys/fs/bpf'" > /dev/null
info "lsm=$(vm 'sudo -n cat /sys/kernel/security/lsm')"
info "sysctl io_uring_disabled=$(vm 'cat /proc/sys/kernel/io_uring_disabled 2>/dev/null || echo absent')"
vm "findmnt -T $HOME -o TARGET,SOURCE,FSTYPE,OPTIONS" > "$OUT/findmnt.txt"
FS_TYPE=$(vm "findmnt -T $HOME -n -o FSTYPE")
info "share: $(sed -n 2p "$OUT/findmnt.txt")"
vm "sudo -n mkdir -p $PIN_ROOT" > /dev/null
mkdir -p "$FIX"

# ---------------------------------------------------------------------------
step "build and install the probe"
# ---------------------------------------------------------------------------
if ! podman build --build-arg "BUILD_KERNEL=$KERNEL_VM" -t "$PROBE_IMAGE" "$PROBE_DIR" >> "$TRANSCRIPT" 2>&1; then
    log "the probe image failed to build; the build log is in $TRANSCRIPT"
    exit 2
fi
vm "set -eu; mkdir -p $MACHINE_DIR
    podman create --replace --name ko-agent-bpf2-extract $PROBE_IMAGE >/dev/null
    podman cp ko-agent-bpf2-extract:/out/. $MACHINE_DIR/
    podman rm ko-agent-bpf2-extract >/dev/null
    test -x $MACHINE_DIR/controller" > /dev/null
check "probe installed in the machine" [ $? -eq 0 ]
vm "cat $MACHINE_DIR/clang-version.txt $MACHINE_DIR/build-kernel.txt $MACHINE_DIR/objects.sha256" > "$OUT/build.txt"
for obj in inventory classify; do vm "cat $MACHINE_DIR/$obj.bpf.asm" > "$OUT/$obj.bpf.asm"; done
info "$(tr '\n' ' ' < "$OUT/build.txt")"

# ---------------------------------------------------------------------------
step "verifier: every inventory program, then the representative program"
# ---------------------------------------------------------------------------
load=$(vm "sudo -n $CTL load inventory.bpf.o")
load_status=$?
printf '%s\n' "$load" > "$OUT/verifier-inventory.txt"
printf '%s\n' "$load" | grep -E '^(load|verifier) ' | sed 's/^/  /' | tee -a "$TRANSCRIPT"
check "every inventory program loads, alone and together: $(printf '%s\n' "$load" | grep -c ' ok=1') loads" \
    eq2 "$(printf '%s\n' "$load" | grep -c ' ok=1')" 34 "$load_status" 0
load=$(vm "sudo -n $CTL load classify.bpf.o")
load_status=$?
printf '%s\n' "$load" > "$OUT/verifier-classify.txt"
printf '%s\n' "$load" | grep -E '^(load|verifier|prog) ' | sed 's/^/  /' | tee -a "$TRANSCRIPT"
check "the representative program's eight hooks load, alone and together" \
    eq2 "$(printf '%s\n' "$load" | grep -c ' ok=1')" 9 "$load_status" 0
# The full log of the largest program, two walks and two positions, is this phase's record.
vm "sudo -n $CTL verifier-log classify.bpf.o inode_rename /tmp/inode_rename.log" | grep '^verifier ' \
    | tee -a "$TRANSCRIPT"
vm "gzip -c /tmp/inode_rename.log | base64" | base64 --decode > "$OUT/classify-inode_rename.log.gz" 2>/dev/null
info "the log is in $OUT/classify-inode_rename.log.gz"

# ---------------------------------------------------------------------------
step "fixture, clone and the attach cgroups"
# ---------------------------------------------------------------------------
APP_SLICE=/user.slice/user-$UID_VM.slice/user@$UID_VM.service/app.slice
attach_cgroup() { # attach_cgroup N: sets CG, the cgroup's sysfs path, and PARENT, the --cgroup-parent value
    if [ "$MANAGER" = systemd ]; then
        vm "systemctl --user stop ko-agent-bpf2-hold$1 2>/dev/null; systemctl --user reset-failed 2>/dev/null
            systemd-run --user --unit=ko-agent-bpf2-hold$1 --slice=ko-agent-bpf2-$1.slice /usr/bin/sleep 3600" \
            > /dev/null
        CG=$(vm "find /sys/fs/cgroup/user.slice -type d -name ko-agent-bpf2-$1.slice 2>/dev/null | head -1")
        PARENT=ko-agent-bpf2-$1.slice
    else
        PARENT=$APP_SLICE/ko-agent-bpf2-$1
        CG=/sys/fs/cgroup$PARENT
        vm "mkdir -p $CG" > /dev/null
    fi
}
attach_cgroup 1
CG1=$CG
PARENT1=$PARENT
check "attach cgroup 1 exists under the user's manager: $CG1" [ -n "$CG1" ]
# The containers: the probe image holds the exerciser at /out/mutate and the tools the rows need;
# --userns=keep-id so files on the share are the user's.
# The exerciser runs without podman's seccomp profile, which answers file_setattr and io_uring_setup
# with ENOSYS and refuses a mount in a user namespace before the kernel does: the rows ask what the
# hooks see. SELinux stays as it is: the FIFO row measures what refuses a FIFO on the share.
EXERCISER_OPTS="--userns=keep-id --security-opt seccomp=unconfined --volume $FIX:$FIX"
in_slice() { # in_slice SHELL-SCRIPT: run it in a container under attach cgroup 1
    # shellcheck disable=SC2086
    podman run --rm --cgroup-parent="$PARENT1" $EXERCISER_OPTS "$PROBE_IMAGE" sh -c "$1" 2>&1 | tee -a "$TRANSCRIPT"
}
outside() {
    # shellcheck disable=SC2086
    podman run --rm $EXERCISER_OPTS "$PROBE_IMAGE" sh -c "$1" 2>&1 | tee -a "$TRANSCRIPT"
}
# Rows 50 and 51 mount inside a user namespace, which SELinux refuses to container_t (EACCES): they
# run with label=disable, as the sandbox's nesting mode does. No other row runs so: the FIFO row's
# refusal is then what the share's label gets.
in_slice_unlabeled() {
    # shellcheck disable=SC2086
    podman run --rm --cgroup-parent="$PARENT1" $EXERCISER_OPTS --security-opt label=disable "$PROBE_IMAGE" \
        sh -c "$1" 2>&1 | tee -a "$TRANSCRIPT"
}
TREE=$FIX/tree
REPO=$FIX/repo
outside "$MUTATE make-tree $TREE" > /dev/null
git clone --quiet "$REPO_DIR" "$REPO" 2>&1 | tee -a "$TRANSCRIPT"
fixture_present() { [ -f "$TREE/.git/config" ] && [ -d "$REPO/.git" ]; }
check "the fixture and a clone of this repository exist on the share" fixture_present
DEEPEST=$(git -C "$REPO" ls-files | awk -F/ 'NF > max { max = NF; deepest = $0 } END { print deepest }')
DEEPEST_DEPTH=$(printf '%s\n' "$DEEPEST" | awk -F/ '{ print NF }')
info "the clone's deepest tracked file: $DEEPEST (depth $DEEPEST_DEPTH below the root)"
# Files at depth 32 and 63 below the fixture root, on make-tree's chain of 70 directories.
deep_file() { # deep_file DEPTH: the path of a file at DEPTH components below $TREE
    path=$TREE/deep
    i=2
    while [ $i -lt "$1" ]; do path=$path/d; i=$((i + 1)); done
    printf '%s/f%s\n' "$path" "$1"
}
DEEP32=$(deep_file 32)
DEEP63=$(deep_file 63)
echo x > "$DEEP32"
echo x > "$DEEP63"
# The host-side mount made before the attach: a disk image at a directory inside the tree, the
# recorded root, where an ordinary directory's write is allowed ("Mounts").
host_mount() { # host_mount NAME: attaches a small APFS image at $TREE/hostmount-NAME
    hdiutil create -quiet -size 8m -fs APFS -volname "kab2-$1" "$FIX/hostmount-$1.dmg" \
        && mkdir -p "$TREE/hostmount-$1" \
        && hdiutil attach -quiet -mountpoint "$TREE/hostmount-$1" "$FIX/hostmount-$1.dmg"
}
if host_mount before; then
    info "host mount before the attach: $(vm "findmnt -n -T $TREE/hostmount-before -o TARGET,FSTYPE | tail -1")"
else
    info "host mount before the attach: hdiutil failed, not measured"
fi

# ---------------------------------------------------------------------------
step "the inventory under every hook, eight hooks per batch"
# ---------------------------------------------------------------------------
# Each batch attaches at most eight hooks, under the ten slots, runs the operations on allowed and on
# deny names, and unpins its links; the hits map is pinned apart, so the batches count into one
# table, read after the last. A hook whose own refusal a row claims shares no batch with a hook the
# same operation reaches first: the path_* hooks precede the inode_* ones, file_open the hooks on an
# open descriptor, file_truncate inode_setattr, and mmap_file file_mprotect.
BATCH1="path_mknod path_mkdir path_symlink path_link path_rename path_unlink path_rmdir path_truncate"
BATCH2="inode_create inode_mknod inode_mkdir inode_symlink inode_link inode_rename inode_unlink inode_rmdir"
BATCH3="file_open inode_setxattr inode_removexattr inode_set_acl inode_remove_acl path_chmod path_chown \
inode_permission"
BATCH4="inode_setattr file_permission mmap_file file_ioctl file_ioctl_compat inode_file_setattr file_receive"
BATCH5="file_truncate file_mprotect"
# The attribute hooks of the nested-podman rows, attached to cgroup 2.
NESTED_HOOKS="inode_setattr inode_setxattr inode_removexattr inode_set_acl inode_remove_acl inode_file_setattr \
file_ioctl file_ioctl_compat"
batch_of() { # batch_of HOOK: the number of the batch that attaches HOOK
    n=0
    for progs in "$BATCH1" "$BATCH2" "$BATCH3" "$BATCH4" "$BATCH5"; do
        n=$((n + 1))
        has " $1 " " $progs " && { echo $n; return; }
    done
}
batch=0
for progs in "$BATCH1" "$BATCH2" "$BATCH3" "$BATCH4" "$BATCH5"; do
    batch=$((batch + 1))
    # shellcheck disable=SC2086
    attach=$(vm "sudo -n $CTL attach inventory.bpf.o $CG1 $PIN_ROOT/inv$batch --keep-going \
        --pin-maps $PIN_ROOT/inv-maps $progs")
    check "batch $batch attached: $(printf '%s\n' "$attach" | grep '^attached ')" [ "$(field failed "$attach")" = 0 ]
    mkdir -p "$FIX/b$batch"
    outside "$MUTATE prepare $FIX/b$batch allow && $MUTATE prepare $FIX/b$batch deny" > /dev/null
    for mode in allow deny; do
        in_slice "$MUTATE inventory $FIX/b$batch $mode skip=50,51" > "$OUT/inventory-b$batch-$mode.txt"
        in_slice_unlabeled "$MUTATE inventory $FIX/b$batch $mode only=50,51" >> "$OUT/inventory-b$batch-$mode.txt"
        # The hits after the allowed run alone: a hook's counts before its batch's deny run adds to them.
        [ "$mode" = allow ] && vm "sudo -n $CTL hits $PIN_ROOT/inv-maps" > "$OUT/hits-allow-b$batch.txt"
    done
    # The hits read from the shared pinned map after the last batch, when every batch has counted.
    [ "$batch" -eq 5 ] && vm "sudo -n $CTL hits $PIN_ROOT/inv-maps" > "$OUT/hits.txt"
    vm "sudo -n $CTL unpin $PIN_ROOT/inv$batch" > /dev/null
done
# A run that stops early, at an exerciser error, would leave later operations unmeasured.
check "every batch's allowed and deny runs report all 55 operations" \
    [ "$(cat "$OUT"/inventory-b?-allow.txt "$OUT"/inventory-b?-deny.txt | grep -c '^op=')" = 550 ]
# One line per operation: its label, the hooks it reached, `*` on a hook that refused the deny name,
# and the batches whose deny run answered EPERM.
awk '
    FILENAME ~ /inventory-b1-allow/ && /^op=/ { label[substr($1, 4)] = substr($2, 7); allowed[substr($1, 4)] = $3 }
    FILENAME ~ /inventory-b[0-9]-deny/ && /^op=/ {
        if (match(FILENAME, /b[0-9]/)) b = substr(FILENAME, RSTART + 1, 1)
        if ($3 == "result=EPERM") eperm[substr($1, 4)] = eperm[substr($1, 4)] b
    }
    FILENAME ~ /hits/ && /^hit / {
        op = substr($2, 4); hook = substr($3, 6); calls = substr($4, 7); denied = substr($5, 8)
        hooks[op] = hooks[op] " " hook "(" calls (denied > 0 ? "*" : "") ")"
    }
    END {
        for (op = 1; op <= 55; op++) {
            key = sprintf("%02d", op)
            printf "row op=%s %s %s hooks=[%s] eperm_in_batches=%s\n", key, label[key], allowed[key], hooks[key],
                (eperm[key] == "" ? "-" : eperm[key])
        }
    }' "$OUT/inventory-b1-allow.txt" "$OUT"/inventory-b?-deny.txt "$OUT/hits.txt" > "$OUT/inventory-table.txt"
sed 's/^/  /' "$OUT/inventory-table.txt" | tee -a "$TRANSCRIPT"
hooks_of() { sed -n "s/^row op=$1 .*hooks=\[\(.*\)\].*/\1/p" "$OUT/inventory-table.txt"; }
eperm_of() { sed -n "s/^row op=$1 .*eperm_in_batches=\(.*\)/\1/p" "$OUT/inventory-table.txt"; }
reached() { # reached OP HOOK...: every HOOK is in OP's hook list
    op=$1
    shift
    for hook in "$@"; do has " $hook(" " $(hooks_of "$op")" || return 1; done
}
denied_by() { # denied_by OP HOOK: HOOK's program counted a refusal of OP's deny name
    hooks_of "$1" | grep -q " $2([0-9]*\*)"
}
refused_by() { # refused_by OP HOOK: denied_by, and OP's deny run answered EPERM in HOOK's batch
    denied_by "$1" "$2" && has "$(batch_of "$2")" "$(eperm_of "$1")"
}
allow_calls() { # allow_calls OP HOOK: HOOK's calls for OP in the allowed run of HOOK's batch
    sed -n "s/^hit op=$1 hook=$2 calls=\([0-9]*\).*/\1/p" "$OUT/hits-allow-b$(batch_of "$2").txt"
}
refused_all() { # refused_all HOOK OP...: refused_by holds for every OP
    hook=$1
    shift
    for op in "$@"; do refused_by "$op" "$hook" || return 1; done
}
check "creat, openat, openat2 and mknod of a regular file reach inode_create, and are refused there" \
    eq2 "$(reached 01 inode_create path_mknod && reached 02 inode_create && reached 03 inode_create && \
        reached 04 inode_create; echo $?)" 0 \
        "$(refused_all inode_create 01 02 03 04; echo $?)" 0
check "a socket bind reaches inode_mknod and is refused there" \
    eq2 "$(reached 06 inode_mknod; echo $?)" 0 "$(refused_by 06 inode_mknod; echo $?)" 0
# A FIFO on the share: an earlier LSM may refuse it before the hook (SELinux, on the machine).
fifo_avc=$(vm "sudo -n dmesg | grep 'avc: .*fifo_file' | tail -1 | cut -c1-200")
info "mkfifo: $(sed -n 's/^row op=05 mkfifo //p' "$OUT/inventory-table.txt"); the last fifo_file AVC: ${fifo_avc:-none}"
check "symlink reaches inode_symlink and is refused there" \
    eq2 "$(reached 08 inode_symlink; echo $?)" 0 "$(refused_by 08 inode_symlink; echo $?)" 0
check "link by name, by AT_EMPTY_PATH and by /proc/self/fd reach inode_link, refused by either name" \
    eq2 "$(reached 09 inode_link && reached 10 inode_link && reached 11 inode_link && reached 12 inode_link; \
        echo $?)" 0 \
        "$(refused_all inode_link 09 10 11 12; echo $?)" 0
tmpfile_result=$(sed -n 's/^row op=49 tmpfile result=\([^ ]*\).*/\1/p' "$OUT/inventory-table.txt")
if [ "$tmpfile_result" = ok ]; then
    check "a tmpfile's link reaches inode_link" reached 13 inode_link
else
    info "a tmpfile's link: O_TMPFILE is unsupported on the share ($tmpfile_result)"
fi
check "rename, by either name, RENAME_WHITEOUT and RENAME_EXCHANGE reach inode_rename and are refused there" \
    eq2 "$(reached 14 inode_rename && reached 15 inode_rename && reached 16 inode_rename && reached 17 inode_rename; \
        echo $?)" 0 "$(refused_all inode_rename 14 15 17; echo $?)" 0
# The allowed run's counts: a refused exchange ends at its first call, so the deny run adds unequally.
exchange_calls=$(allow_calls 17 inode_rename)
rename_calls=$(allow_calls 14 inode_rename)
check "RENAME_EXCHANGE calls inode_rename twice: $exchange_calls calls against $rename_calls for a rename" \
    eq2 "$exchange_calls" "$((${rename_calls:-0} * 2))" "${rename_calls:+set}" set
check "unlink reaches inode_unlink and is refused there" \
    eq2 "$(reached 18 inode_unlink; echo $?)" 0 "$(refused_by 18 inode_unlink; echo $?)" 0
check "open for writing, O_RDONLY|O_TRUNC and O_WRONLY|O_TRUNC reach file_open and are refused there" \
    eq2 "$(reached 21 file_open && reached 22 file_open && reached 24 file_open && reached 25 file_open; echo $?)" 0 \
        "$(refused_all file_open 21 22 24 25; echo $?)" 0
check "O_RDONLY|O_TRUNC, chmod, chown, truncate, utimensat and fchmodat reach inode_setattr, refused there" \
    eq2 "$(reached 24 inode_setattr && reached 31 inode_setattr && reached 32 inode_setattr && \
        reached 33 inode_setattr && reached 34 inode_setattr && reached 35 inode_setattr; echo $?)" 0 \
        "$(refused_all inode_setattr 24 31 33 34 35; echo $?)" 0
check "setxattr and removexattr reach their hooks; an ACL set reaches inode_set_acl and not inode_setxattr" \
    eq2 "$(reached 37 inode_setxattr && reached 38 inode_removexattr && reached 39 inode_set_acl; echo $?)" 0 \
        "$(has " inode_setxattr(" " $(hooks_of 39)"; echo $?)" 1
check "FS_IOC_SETFLAGS and FS_IOC_FSSETXATTR on a read-only descriptor reach file_ioctl and are refused there" \
    eq2 "$(reached 41 file_ioctl && reached 42 file_ioctl; echo $?)" 0 \
        "$(refused_all file_ioctl 41 42; echo $?)" 0
ioctl_arg_of() { sed -n "s/^hit op=$1 hook=file_ioctl .*arg=\(0x[0-9a-f]*\).*/\1/p" "$OUT/hits.txt" | head -1; }
high_arg=$(ioctl_arg_of 47)
check "an ioctl command with a bit above 32 set reaches the hook as the 32-bit command: $high_arg" \
    eq2 "$high_arg" "$(ioctl_arg_of 41)" "${high_arg:+set}" set
check "a descriptor passed over a socket reaches file_receive, and a refused one is dropped with MSG_CTRUNC" \
    eq2 "$(reached 54 file_receive && denied_by 54 file_receive; echo $?)" 0 \
        "$(grep -c 'op=54 .*received=no ctrunc=1' "$OUT/inventory-b$(batch_of file_receive)-deny.txt")" 1
info "share support: $(grep -E '^op=(37|39|41|42|43|44|45|46|49|50|51|52|53|55) ' "$OUT/inventory-b1-allow.txt" | \
    sed 's/^op=[0-9]* label=//' | tr '\n' ';')"
info "io_uring_setup with label=disable: $(in_slice_unlabeled "$MUTATE inventory $FIX/b5 allow only=53" | tr '\n' ' ')"
info "overlayfs kernel messages: $(vm "sudo -n dmesg | grep -i overlayfs | tail -3 | cut -c1-160 | tr '\n' ';'")"
info "the machine's last AVC denials: $(vm "sudo -n dmesg | grep 'avc: ' | tail -3 | cut -c1-160 | tr '\n' ';'")"
vm "sudo -n $CTL unpin $PIN_ROOT/inv-maps" > /dev/null

# ---------------------------------------------------------------------------
step "the representative program: the rules filled to the map, the corpus, git, the walk's cost"
# ---------------------------------------------------------------------------
# The rule map holds 128 lines: the launcher's defaults, then filler lines up to the capacity.
RULES=$FIX/rules.txt
sed 's/#.*//' "$REPO_DIR/src/main/resources/agentsandbox/file-rule-defaults" | awk 'NF == 2' > "$RULES"
i=$(wc -l < "$RULES")
while [ "$i" -lt 128 ]; do echo "read-only zz-filler-$i" >> "$RULES"; i=$((i + 1)); done
attach=$(vm "sudo -n $CTL attach classify.bpf.o $CG1 $PIN_ROOT/classify --fs-type $FS_TYPE --rules $RULES \
    --root workspace=$TREE --root gitdir=$TREE/.git/modules/sub --root workspace=$REPO \
    file_open inode_create inode_mknod inode_symlink inode_link inode_rename inode_unlink inode_setattr")
printf '%s\n' "$attach" | grep -E '^(root|policy|attached) ' | sed 's/^/  /' | tee -a "$TRANSCRIPT"
check "the representative program attached with 128 rules and three roots" \
    eq2 "$(field count "$attach")" 8 "$(field rule_count "$attach")" 128
representative_rows() { # the rows that need the attached program
    PIN=$PIN_ROOT/classify/file_open
    corpus=$(in_slice "$MUTATE corpus $TREE")
    printf '%s\n' "$corpus" | grep -e MISMATCH -e UNSUPPORTED | sed 's/^/  /' | tee -a "$TRANSCRIPT"
    check "the corpus: $(printf '%s\n' "$corpus" | grep '^corpus ')" [ "$(field mismatches "$corpus")" = 0 ]
    info "$(vm "sudo -n $CTL last-decision $PIN")"
    git_ok=$(in_slice "cd $REPO && git status --short > /dev/null && git add -A && \
        git -c user.name=probe -c user.email=probe@example.invalid commit -q --allow-empty -m probe && \
        git checkout -q -b probe && git log -1 --oneline > /dev/null && git gc -q && echo GIT_OK")
    check "ordinary git in the clone: status, add, commit, branch, log, gc" has GIT_OK "$git_ok"
    git_config=$(in_slice "cd $REPO && (git config probe.key value 2>&1 || echo CONFIG_REFUSED) && \
        (git init -q sub2 2>&1 || echo INIT_REFUSED)")
    check "git config and git init in the clone are refused" \
        eq2 "$(has CONFIG_REFUSED "$git_config"; echo $?)" 0 "$(has INIT_REFUSED "$git_config"; echo $?)" 0
    walk_cost() { # walk_cost LABEL PATH: the exerciser's loops under the policy and on the bare bind
        under=$(in_slice "$MUTATE walk-cost $2 $WALK_COUNT")
        bare=$(outside "$MUTATE walk-cost $2 $WALK_COUNT")
        info "walk cost, $1: policy open_rdwr=$(field open_rdwr_ns "$under")" \
            "open_rdonly=$(field open_rdonly_ns "$under")" \
            "lstat=$(field lstat_ns "$under") ns; bare open_rdwr=$(field open_rdwr_ns "$bare")" \
            "open_rdonly=$(field open_rdonly_ns "$bare") lstat=$(field lstat_ns "$bare") ns;" \
            "failed=$(field failed "$under")"
    }
    walk_cost "the clone's deepest file, depth $DEEPEST_DEPTH" "$REPO/$DEEPEST"
    walk_cost "depth 32" "$DEEP32"
    walk_cost "depth 63" "$DEEP63"
    stats=$(vm "sudo -n $CTL stats $PIN")
    printf '%s\n' "$stats" | sed 's/^/  /' | tee -a "$TRANSCRIPT"
    printf '%s\n' "$stats" > "$OUT/stats.txt"
    check "every walk settled: no walk gave up" [ "$(printf '%s\n' "$stats" | grep -c ' gave_up=0 ')" = 8 ]
    # The host-side mount made after the attach, and a write inside each from under the policy,
    # beside the control: a write in an ordinary directory of the tree.
    if host_mount after; then
        info "host mount after the attach: $(vm "findmnt -n -T $TREE/hostmount-after -o TARGET,FSTYPE | tail -1")"
    else
        info "host mount after the attach: hdiutil failed, not measured"
    fi
    mkdir -p "$TREE/hostmount-control"
    control=$(in_slice "(echo x > $TREE/hostmount-control/kab2-write) 2>&1 && echo WRITE_OK || echo WRITE_FAIL")
    check "a write in an ordinary directory of the tree, beside the host mounts, is allowed" has WRITE_OK "$control"
    for when in before after; do
        [ -d "$TREE/hostmount-$when" ] || continue
        mount_stat=$(vm "$CTL statx $TREE/hostmount-$when")
        tree_stat=$(vm "$CTL statx $TREE")
        write=$(in_slice "(echo x > $TREE/hostmount-$when/kab2-write) 2>&1 && echo WRITE_OK || echo WRITE_FAIL")
        info "host mount $when the attach: mkdev=$(field mkdev "$mount_stat") against the tree's" \
            "$(field mkdev "$tree_stat"), mode=$(field mode "$mount_stat");" \
            "a write inside it under the policy: $(printf '%s\n' "$write" | tr '\n' ' ')"
        check "a write inside the host mount made $when the attach is refused under the policy" \
            has WRITE_FAIL "$write"
    done
    jited=$(vm "sudo -n $CTL jited $PIN /tmp/file_open.jited")
    info "$jited"
    barrier_seen() {
        [ -n "$(field fetch_add_insns "$1")" ] && [ "$(field fetch_add_insns "$1")" != 0 ] && {
            [ "$(field ldaddal "$1")" != 0 ] || [ "$(field dmb_ish "$1")" != 0 ] || [ "$(field lock_xadd "$1")" != 0 ]
        }
    }
    check "the xlated program holds the atomic fetch-add and the jited one a barrier instruction" barrier_seen "$jited"
    vm "sudo -n $CTL unpin $PIN_ROOT/classify" > /dev/null
}
if [ "$(field count "$attach")" = 8 ]; then
    representative_rows
else
    info "the corpus, git, walk, host-mount and barrier rows need the attach: skipped"
fi

# ---------------------------------------------------------------------------
step "a nested podman under the attribute hooks: recorded, then refused"
# ---------------------------------------------------------------------------
# The later version's measurement ("Phases", 2): a rootless podman inside a container launched
# with the same-uid loosenings (AgentSandboxLauncher.NestingLoosenings) and configured as
# ko-sandbox-install-podman configures it, pulling, running, executing into and removing a
# container, with the xattr, ACL, file_setattr and ioctl hooks counting every call; then the same
# with those hooks refusing every call.
attach_cgroup 2
CG2=$CG
PARENT2=$PARENT
# shellcheck disable=SC2016
nested_script='set -u
export HOME=/tmp/home XDG_RUNTIME_DIR=/tmp/xdg
mkdir -p $HOME/.config/containers $XDG_RUNTIME_DIR
printf "[containers]\nnetns = \"host\"\nutsns = \"host\"\ncgroups = \"disabled\"\n" \
    > $HOME/.config/containers/containers.conf
printf "[engine]\nevents_logger = \"file\"\n" \
    >> $HOME/.config/containers/containers.conf
printf "{ \"default\": [ { \"type\": \"insecureAcceptAnything\" } ] }\n" > $HOME/.config/containers/policy.json
printf "unqualified-search-registries = [\"docker.io\"]\n" > $HOME/.config/containers/registries.conf
printf "[storage]\ndriver = \"overlay\"\n[storage.options]\nignore_chown_errors = \"true\"\n" \
    > $HOME/.config/containers/storage.conf
r() {
    if "$@" > /tmp/step.out 2>&1; then echo "nested $1 $2 $3: ok"
    else echo "nested $1 $2 $3: failed: $(tail -2 /tmp/step.out | tr "\n" " ")"; fi
}
r podman pull -q docker.io/library/alpine:3.22
r podman run --rm docker.io/library/alpine:3.22 true
r podman run -d --name inner docker.io/library/alpine:3.22 sleep 120
r podman exec inner true
r podman rm -f inner
r podman rmi docker.io/library/alpine:3.22'
nested_run() { # nested_run record|refuse: the script in a container under attach cgroup 2 with the loosenings
    # `/tmp` is a tmpfs as the sandbox's is: containers/storage refuses the overlay driver over an
    # overlay graphroot without a mount program, and the sandbox's graphroot is on `~`, a volume.
    # In refuse mode the hooks start refusing once the container runs: its creation, which the
    # outer podman does inside the cgroup, is not what they refuse.
    podman rm -f ko-agent-bpf2-nested > /dev/null 2>&1
    start=$(podman run -d --name ko-agent-bpf2-nested --cgroup-parent="$PARENT2" --userns=keep-id --tmpfs /tmp \
        --security-opt=unmask=ALL --security-opt=label=disable --cap-add=SYS_CHROOT \
        "$PROBE_IMAGE" sh -c "sleep 3; $nested_script" 2>&1) || echo "nested-run start failed: $start"
    [ "$1" = refuse ] && vm "sudo -n $CTL deny-all $NPIN 1" > /dev/null
    podman wait ko-agent-bpf2-nested > /dev/null 2>&1
    podman logs ko-agent-bpf2-nested 2>&1 | tee -a "$TRANSCRIPT"
    podman rm -f ko-agent-bpf2-nested > /dev/null 2>&1
}
# shellcheck disable=SC2086
attach=$(vm "sudo -n $CTL attach inventory.bpf.o $CG2 $PIN_ROOT/nested --keep-going $NESTED_HOOKS")
NPIN=$PIN_ROOT/nested/inode_setxattr
check "the attribute hooks attached to cgroup 2" [ "$(field failed "$attach")" = 0 ]
vm "sudo -n $CTL reset $NPIN" > /dev/null
recorded=$(nested_run record)
totals=$(vm "sudo -n $CTL totals $NPIN")
printf '%s\n' "$totals" | grep -E "hook=($(printf '%s' "$NESTED_HOOKS" | tr ' ' '|')) " | sed 's/^/  /' | \
    tee -a "$TRANSCRIPT"
check "the nested podman pulled, ran, executed into and removed a container while the hooks recorded" \
    [ "$(printf '%s\n' "$recorded" | grep -c ': ok$')" = 6 ]
refused=$(nested_run refuse)
info "with the attribute hooks refusing: $(printf '%s\n' "$refused" | grep '^nested' | tr '\n' ';')"
totals=$(vm "sudo -n $CTL totals $NPIN")
printf '%s\n' "$totals" | grep -E "hook=($(printf '%s' "$NESTED_HOOKS" | tr ' ' '|')) " | sed 's/^/  /' | \
    tee -a "$TRANSCRIPT"
vm "sudo -n $CTL unpin $PIN_ROOT/nested" > /dev/null

[ "$failed" -eq 0 ] || exit 1
