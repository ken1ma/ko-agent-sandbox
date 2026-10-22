#!/bin/sh
# Phase 3 of doc/plan-bpf-lsm-cgroup.md ("Phases", 3) on the macOS podman machine, in one run.
# Run it on the HOST, from the repository root, with the default machine running:
#
#     bpf/probe/phase3/phase3.sh [OUTDIR]
#
# It builds the probe image (Containerfile), extracts /out into the machine under
# ~/.local/share/ko-agent-sandbox/bpf-probe3, and runs the phase's rows through `podman machine
# ssh` and the machine's sudo, each printed as PASS, FAIL or INFO. The transcript and the files the
# rows produce land in OUTDIR (default: out-macos/ beside this script, ignored by git; the Windows
# driver writes out-wsl/, so the two machines' outputs sit side by side). Send OUTDIR back;
# the transcript is what "Phase 3 on macOS" and the phase's gate are filled from. On Windows,
# phase3.ps1.
#
# The rows, in order: the environment and the kernel's preemption mode; the verifier's answer to
# the policy program's nine hooks, with the full log of the two largest; the corpus (exercise.c)
# on a fixture laid out as a workspace, with the defaults' rules, a freed file, a relocated hook
# directory and a symlinked `.claude` (the alias), and on a workspace whose `.git` is a pointer
# file with host-made hard links; ordinary git in a clone of this repository; the torn-name race;
# the concurrency storm; the socket rules by default; a second host share; host git in a
# session-made `.git` without HEAD; the walk's cost and the jited barrier; the NTFS short-name form
# under its flag; under `--unix-sockets`, the socket corpus and descriptors passed between four
# sandboxes, a live session, a second session of the workspace under a later rule file, a session
# of another workspace and a read-only session; and the namespaces and mounts a generated seccomp
# profile refuses.
#
# It writes a fixture under $HOME/.cache (the share the machine mounts), a directory under
# /private/tmp for the second share, four attach cgroups with their transient units, a podman
# volume and a second one standing for `~`, pins under /sys/fs/bpf/ko-agent-bpf-phase3 in the
# machine, and containers named ko-agent-bpf3-*; all are removed on exit.
set -u

PROBE_IMAGE=ko-agent-bpf-probe:phase3
MACHINE_DIR=.local/share/ko-agent-sandbox/bpf-probe3
CTL=./$MACHINE_DIR/controller
EXERCISE=/out/exercise
PIN_ROOT=/sys/fs/bpf/ko-agent-bpf-phase3
FIX=$HOME/.cache/ko-agent-bpf-phase3.$$
SHARE2=/private/tmp/ko-agent-bpf-phase3.$$
VOL=ko-agent-bpf3-vol
VOL2=ko-agent-bpf3-home
WALK_COUNT=2000
RACE_SECONDS=5
STORM_PROCS=16
STORM_SECONDS=5
HOOKS8="file_open inode_create inode_mknod inode_symlink inode_link inode_rename inode_unlink inode_setattr"
HOOKS9="$HOOKS8 file_receive"
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
# The sum of KEY over every line of INPUT holding it.
sum_field() { printf '%s\n' "$2" | sed -n "s/.* $1=\([0-9]*\).*/\1/p" | awk '{ s += $1 } END { print s + 0 }'; }
step() { log ""; log "== $*"; }

cleanup() {
    step "cleanup"
    podman rm -f ko-agent-bpf3-srv ko-agent-bpf3-rcv ko-agent-bpf3-slot > /dev/null 2>&1
    vm "[ -x $CTL ] && for d in $PIN_ROOT/*; do sudo -n $CTL unpin \$d; done
        sudo -n rmdir $PIN_ROOT 2>/dev/null; true" > /dev/null
    vm "systemctl --user stop ko-agent-bpf3-hold1 ko-agent-bpf3-hold2 ko-agent-bpf3-hold3 ko-agent-bpf3-hold4 \
        ko-agent-bpf3-1.slice ko-agent-bpf3-2.slice ko-agent-bpf3-3.slice ko-agent-bpf3-4.slice 2>/dev/null; true" \
        > /dev/null
    vm "rmdir /sys/fs/cgroup/user.slice/user-*.slice/user@*.service/app.slice/ko-agent-bpf3-? 2>/dev/null; true" \
        > /dev/null
    podman volume rm -f "$VOL" "$VOL2" > /dev/null 2>&1
    rm -rf "$SHARE2"
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
    sudo -n sh -c 'findmnt -n /sys/fs/bpf >/dev/null || mount -t bpf bpf /sys/fs/bpf'
    sudo -n sh -c 'findmnt -n /sys/kernel/debug >/dev/null || mount -t debugfs debugfs /sys/kernel/debug'" \
    > /dev/null
info "lsm=$(vm 'sudo -n cat /sys/kernel/security/lsm')"
# The preemption mode decides whether a task can be preempted inside the program ("Phases", 3).
info "preemption mode: $(vm 'sudo -n cat /sys/kernel/debug/sched/preempt 2>/dev/null || echo unavailable')," \
    "cpus=$(vm nproc)"
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
    podman create --replace --name ko-agent-bpf3-extract $PROBE_IMAGE >/dev/null
    podman cp ko-agent-bpf3-extract:/out/. $MACHINE_DIR/
    podman rm ko-agent-bpf3-extract >/dev/null
    test -x $MACHINE_DIR/controller" > /dev/null
check "probe installed in the machine" [ $? -eq 0 ]
vm "cat $MACHINE_DIR/clang-version.txt $MACHINE_DIR/build-kernel.txt $MACHINE_DIR/objects.sha256" > "$OUT/build.txt"
vm "cat $MACHINE_DIR/policy.bpf.asm" > "$OUT/policy.bpf.asm"
info "$(tr '\n' ' ' < "$OUT/build.txt")"

# ---------------------------------------------------------------------------
step "verifier: the policy program's nine hooks"
# ---------------------------------------------------------------------------
load=$(vm "sudo -n $CTL load policy.bpf.o")
load_status=$?
printf '%s\n' "$load" > "$OUT/verifier-policy.txt"
printf '%s\n' "$load" | grep -E '^(load|verifier|prog) ' | sed 's/^/  /' | tee -a "$TRANSCRIPT"
check "the policy program's nine hooks load, alone and together" \
    eq2 "$(printf '%s\n' "$load" | grep -c ' ok=1')" 10 "$load_status" 0
max_insns=$(printf '%s\n' "$load" | sed -n 's/^prog .*verified_insns=\([0-9]*\).*/\1/p' | sort -n | tail -1)
info "the most instructions the verifier processed for one program: ${max_insns:-none}, of the limit 1,000,000"
for prog in inode_rename inode_symlink; do
    vm "sudo -n $CTL verifier-log policy.bpf.o $prog /tmp/$prog.log" | grep '^verifier ' | tee -a "$TRANSCRIPT"
    vm "gzip -c /tmp/$prog.log | base64" | base64 --decode > "$OUT/policy-$prog.log.gz" 2>/dev/null
done
info "the logs are in $OUT/policy-inode_rename.log.gz and policy-inode_symlink.log.gz"

# ---------------------------------------------------------------------------
step "fixtures, clone, volume and the attach cgroups"
# ---------------------------------------------------------------------------
APP_SLICE=/user.slice/user-$UID_VM.slice/user@$UID_VM.service/app.slice
attach_cgroup() { # attach_cgroup N: sets CG, the cgroup's sysfs path, and PARENT, the --cgroup-parent value
    if [ "$MANAGER" = systemd ]; then
        vm "systemctl --user stop ko-agent-bpf3-hold$1 2>/dev/null; systemctl --user reset-failed 2>/dev/null
            systemd-run --user --unit=ko-agent-bpf3-hold$1 --slice=ko-agent-bpf3-$1.slice /usr/bin/sleep 3600" \
            > /dev/null
        CG=$(vm "find /sys/fs/cgroup/user.slice -type d -name ko-agent-bpf3-$1.slice 2>/dev/null | head -1")
        PARENT=ko-agent-bpf3-$1.slice
    else
        PARENT=$APP_SLICE/ko-agent-bpf3-$1
        CG=/sys/fs/cgroup$PARENT
        vm "mkdir -p $CG" > /dev/null
    fi
}
attach_cgroup 1; CG1=$CG; PARENT1=$PARENT
attach_cgroup 2; CG2=$CG; PARENT2=$PARENT
attach_cgroup 3; CG3=$CG; PARENT3=$PARENT
attach_cgroup 4; CG4=$CG; PARENT4=$PARENT
four_cgroups() { [ -n "$CG1" ] && [ -n "$CG2" ] && [ -n "$CG3" ] && [ -n "$CG4" ]; }
check "four attach cgroups exist under the user's manager: $CG1" four_cgroups
# The persistent volume, whose root the policy records, and a second volume standing for `~`,
# which shares its superblock ("Environment evidence").
podman volume create "$VOL" > /dev/null 2>&1
podman volume create "$VOL2" > /dev/null 2>&1
VOLMP=$(vm "podman volume inspect --format '{{.Mountpoint}}' $VOL")
VOL_FS=$(vm "findmnt -T $VOLMP -n -o FSTYPE")
info "the volume's mountpoint in the machine: $VOLMP, on $VOL_FS"
# The containers: the probe image holds the exerciser at /out/exercise and git; --userns=keep-id so
# files on the share are the user's; the volume at /vol. The exerciser runs without podman's seccomp
# profile, so that what a row sees is the hooks' answer; one row runs under a generated profile.
EXERCISER_OPTS="--userns=keep-id --security-opt seccomp=unconfined --volume $FIX:$FIX --volume $VOL:/vol \
--volume $VOL2:/home2"
in_cg() { # in_cg N SHELL-SCRIPT: run it in a container under attach cgroup N
    eval "parent=\$PARENT$1"
    # shellcheck disable=SC2086
    podman run --rm --cgroup-parent="$parent" $EXERCISER_OPTS "$PROBE_IMAGE" sh -c "$2" 2>&1 | tee -a "$TRANSCRIPT"
}
outside() {
    # shellcheck disable=SC2086
    podman run --rm $EXERCISER_OPTS "$PROBE_IMAGE" sh -c "$1" 2>&1 | tee -a "$TRANSCRIPT"
}
TREE=$FIX/tree
PTR=$FIX/tree-ptr
REPO=$FIX/repo
outside "$EXERCISE make-tree $TREE" > /dev/null
# The host-made hard links to the guarded files, made on the host as the filter's test makes them,
# and to the submodule worktree's pointer file, in another directory.
host_links() {
    ln "$PTR/.git" "$PTR/GIT~1" && ln "$PTR/.ko-agent-sandbox" "$PTR/KO-AGE~1" &&
        ln "$TREE/submod/.git" "$TREE/apps/submod-pointer"
}
host_links
check "the host made hard links to the pointer file, the launcher's file and the submodule's pointer file" \
    [ "$(stat -f %i "$PTR/.git")" = "$(stat -f %i "$PTR/GIT~1")" ]
git clone --quiet "$REPO_DIR" "$REPO" 2>&1 | tee -a "$TRANSCRIPT"
fixture_present() { [ -f "$TREE/.git/config" ] && [ -f "$PTR/.git" ] && [ -d "$REPO/.git" ]; }
check "the fixtures and a clone of this repository exist on the share" fixture_present
fixture_check=$(outside "$EXERCISE check $TREE")
check "the fixture holds every operand the corpus needs: $(printf '%s\n' "$fixture_check" | tail -1)" \
    [ "$(field gaps "$fixture_check")" = 0 ]
# The fixture is laid out again after the check, which ran the allowed cases on it.
rm -rf "$TREE" "$PTR"
outside "$EXERCISE make-tree $TREE" > /dev/null
host_links
DEEPEST=$(git -C "$REPO" ls-files | awk -F/ 'NF > max { max = NF; deepest = $0 } END { print deepest }')
DEEPEST_DEPTH=$(printf '%s\n' "$DEEPEST" | awk -F/ '{ print NF }')
# The rule files: the launcher's defaults, a workspace line freeing one file, filler lines up to
# the map's capacity, then the guard's anchored lines: a relocated hook directory, the traversed
# component and the end of the `.claude` symlink with its alias context. RULES_B has a workspace
# line in place of the last filler, as a later rule file would, at the same 128 lines.
RULES_A=$FIX/rules-a.txt
RULES_B=$FIX/rules-b.txt
sed 's/#.*//' "$REPO_DIR/src/main/resources/agentsandbox/file-rule-defaults" | awk 'NF == 2' > "$RULES_A"
echo "writable .vscode/settings.json" >> "$RULES_A"
# macOS's wc pads its count with spaces, which would become a third token of the filler lines.
i=$(wc -l < "$RULES_A" | tr -d ' ')
while [ "$i" -lt 124 ]; do echo "read-only zz-filler-$i" >> "$RULES_A"; i=$((i + 1)); done
cp "$RULES_A" "$RULES_B"
echo "read-only zz-filler-last" >> "$RULES_A"
echo "read-only README.md" >> "$RULES_B"
# An anchored line stands first, ahead of every floating line: an alias context computed by the
# wrong indices would then name the wrong lines, which the alias cases catch.
for rules in "$RULES_A" "$RULES_B"; do
    {
        echo "read-only githooks anchored"
        cat "$rules"
        echo "pinned-path shared anchored"
        echo "pinned-path shared/claude anchored alias=.claude"
    } > "$rules.tmp"
    mv "$rules.tmp" "$rules"
done
info "rule lines: $(wc -l < "$RULES_A" | tr -d ' ') in A, $(wc -l < "$RULES_B" | tr -d ' ') in B"
# The guarded objects: the pointer files and the `.git` directories of the fixture and the clone,
# so that the gitdir cases run under a recorded `.git` directory, with the workspace's rules and
# depth kept above it.
ROOTS_A="--root workspace=$TREE --root workspace=$PTR --root workspace=$REPO --root gitdir=$TREE/.git/modules/sub \
--root guarded-git=$PTR/.git --root guarded-git=$TREE/submod/.git --root guarded-git=$TREE/.git \
--root guarded-git=$REPO/.git --root guarded-sandbox=$PTR/.ko-agent-sandbox \
--root guarded-sandbox=$TREE/.ko-agent-sandbox --root volume=$VOLMP --vol-fs-type $VOL_FS"
attach_a() { # attach_a FLAGS HOOKS: the live session's policy on cgroup 1, FLAGS as --flags or `-`
    flags=$1
    [ "$flags" = - ] && flags= || flags="--flags $flags"
    vm "sudo -n $CTL unpin $PIN_ROOT/a" > /dev/null
    # shellcheck disable=SC2086
    attach=$(vm "sudo -n $CTL attach policy.bpf.o $CG1 $PIN_ROOT/a --fs-type $FS_TYPE --rules $RULES_A $flags \
        $ROOTS_A $2")
    printf '%s\n' "$attach" | grep -E '^(root|alias|policy|attached) ' | sed 's/^/  /' | tee -a "$TRANSCRIPT"
    PIN=$PIN_ROOT/a/file_open
}
attach_a - "$HOOKS8"
check "the live session's policy attached with 128 rules, one alias and eleven roots" \
    eq2 "$(field count "$attach")" 8 "$(field rule_count "$attach")" 128
check "the alias context of .claude holds the five .claude lines as partial matches" \
    [ "$(printf '%s\n' "$attach" | sed -n 's/^alias .*partial_lines=\(.*\)/\1/p' | tr -cd ',' | wc -c)" -ge 5 ]

# ---------------------------------------------------------------------------
step "the corpus, git in the clone, the race, the storm, sockets, a second share"
# ---------------------------------------------------------------------------
corpus=$(in_cg 1 "$EXERCISE corpus $TREE")
printf '%s\n' "$corpus" | grep -e MISMATCH -e UNSUPPORTED | sed 's/^/  /' | tee -a "$TRANSCRIPT"
check "the corpus: $(printf '%s\n' "$corpus" | grep '^corpus ')" [ "$(field mismatches "$corpus")" = 0 ]
info "$(vm "sudo -n $CTL last-decision $PIN")"
git_ok=$(in_cg 1 "cd $REPO && git status --short > /dev/null && git add -A && \
    git -c user.name=probe -c user.email=probe@example.invalid commit -q --allow-empty -m probe && \
    git checkout -q -b probe && git log -1 --oneline > /dev/null && git gc -q && echo GIT_OK")
check "ordinary git in the clone: status, add, commit, branch, log, gc" has GIT_OK "$git_ok"
git_config=$(in_cg 1 "cd $REPO && (git config probe.key value 2>&1 || echo CONFIG_REFUSED) && \
    (git init -q sub2 2>&1 || echo INIT_REFUSED)")
check "git config and git init in the clone are refused" \
    eq2 "$(has CONFIG_REFUSED "$git_config"; echo $?)" 0 "$(has INIT_REFUSED "$git_config"; echo $?)" 0
# Host git in a session-made `.git` without HEAD: git walks past it to the workspace's gitdir.
host_git=$(outside "cd $TREE/sub && git rev-parse --absolute-git-dir 2>&1")
check "git outside the policy in sub/, whose .git has no HEAD, finds the workspace's gitdir: $host_git" \
    has "$TREE/.git" "$host_git"
# The torn-name race: the walks that overlapped a rename are the retries.
vm "sudo -n $CTL reset-stats $PIN" > /dev/null
race=$(in_cg 1 "$EXERCISE race $TREE $RACE_SECONDS")
stats=$(vm "sudo -n $CTL stats $PIN")
printf '%s\n' "$stats" | sed 's/^/  /' | tee -a "$TRANSCRIPT"
check "the race: $(printf '%s\n' "$race" | grep '^race ' | tr '\n' ' ')" \
    eq2 "$(field succeeded "$race")" 0 "$(sum_field gave_up "$stats")" 0
check "the race ran: retries above zero, $(sum_field retries "$stats") walks overlapped a rename" \
    [ "$(sum_field retries "$stats")" -gt 0 ]
# The storm: every decision counted, none wrong, and no call denied for want of a slot.
vm "sudo -n $CTL reset-stats $PIN" > /dev/null
storm=$(in_cg 1 "$EXERCISE storm $TREE $STORM_PROCS $STORM_SECONDS")
stats=$(vm "sudo -n $CTL stats $PIN")
printf '%s\n' "$stats" | sed 's/^/  /' | tee -a "$TRANSCRIPT"
printf '%s\n' "$storm" | grep '^storm process' | sed 's/^/  /' | tee -a "$TRANSCRIPT"
check "the storm: $(printf '%s\n' "$storm" | grep '^storm processes')" [ "$(field failed "$storm")" = 0 ]
info "reentry: $(sum_field reentry "$stats") calls denied for want of a slot; the deepest nesting on one CPU:" \
    "slot $(printf '%s\n' "$stats" | sed -n 's/.* nested_max=\([0-9]*\).*/\1/p' | sort -n | tail -1)"
# The slots exhausted by hand: the guard word is set while a container already up sleeps, so no
# call of the runtime's is in flight, and read back by that container's write once the word is
# set. With all four slots marked taken on every CPU a write on the share is denied and counted;
# with three it runs in the fourth; freed, it runs in the first again.
slot_write() { # slot_write MASK NAME: sets the guard to MASK under a sleeping container, which then writes NAME
    podman rm -f ko-agent-bpf3-slot > /dev/null 2>&1
    # shellcheck disable=SC2086
    podman run -d --name ko-agent-bpf3-slot --cgroup-parent="$PARENT1" $EXERCISER_OPTS "$PROBE_IMAGE" sh -c \
        "sleep 3; (echo x > $TREE/apps/$2) 2>&1 && echo SLOT_OK || echo SLOT_REFUSED" > /dev/null 2>&1
    sleep 1
    vm "sudo -n $CTL reset-stats $PIN; sudo -n $CTL guard $PIN $1" > /dev/null
    podman wait ko-agent-bpf3-slot > /dev/null 2>&1
    vm "sudo -n $CTL guard $PIN 0" > /dev/null
    podman logs ko-agent-bpf3-slot 2>&1 | tee -a "$TRANSCRIPT"
    podman rm -f ko-agent-bpf3-slot > /dev/null 2>&1
}
create_nested() { printf '%s\n' "$1" | grep 'hook=inode_create' | sed -n 's/.* nested_max=\([0-9]*\).*/\1/p'; }
full=$(slot_write 0xf slot-full)
stats=$(vm "sudo -n $CTL stats $PIN")
check "with every slot taken a write on the share is refused and counted as reentry: $(sum_field reentry "$stats")" \
    eq2 "$(has SLOT_REFUSED "$full"; echo $?)" 0 "$([ "$(sum_field reentry "$stats")" -gt 0 ]; echo $?)" 0
three=$(slot_write 0x7 slot-three)
stats=$(vm "sudo -n $CTL stats $PIN")
check "with three slots taken a write runs in the fourth: nested_max 3, no reentry" \
    eq2 "$(has SLOT_OK "$three"; echo $?)" 0 "$(create_nested "$stats")" 3
freed=$(slot_write 0 slot-freed)
stats=$(vm "sudo -n $CTL stats $PIN")
check "with the slots freed a write runs in the first again" \
    eq2 "$(has SLOT_OK "$freed"; echo $?)" 0 "$(create_nested "$stats")" 0
# Sockets by default: refused beneath the volume, allowed under /home2, the stand-in for `~` on
# the volume's superblock, from where a bound socket cannot be renamed or linked beneath the
# volume; a `mv` into the workspace crosses superblocks and recreates the socket by mknod, which
# is refused too.
sockets=$(in_cg 1 "$EXERCISE bind /vol/s; $EXERCISE bind /home2/s; \
    (mv /home2/s /vol/s 2>&1 && echo MV_VOL_OK || echo MV_VOL_REFUSED); \
    (ln /home2/s /vol/s 2>&1 && echo LN_VOL_OK || echo LN_VOL_REFUSED); \
    (mv /home2/s $TREE/apps/s 2>&1 && echo MV_WS_OK || echo MV_WS_REFUSED)")
check "a socket is refused beneath the volume and allowed under /home2" \
    eq2 "$(printf '%s\n' "$sockets" | sed -n 's/^bind path=\/vol\/s result=\(.*\)/\1/p')" EPERM \
        "$(printf '%s\n' "$sockets" | sed -n 's/^bind path=\/home2\/s result=\(.*\)/\1/p')" ok
check "a socket bound under /home2 cannot be renamed or linked beneath the volume, nor moved into the workspace" \
    eq2 "$(has MV_VOL_REFUSED "$sockets" && has LN_VOL_REFUSED "$sockets"; echo $?)" 0 \
        "$(has MV_WS_REFUSED "$sockets"; echo $?)" 0
# A second host share, bound into a container under the policy: on its superblock, of the root's
# type, no walk meets a root.
mkdir -p "$SHARE2"
share2_type=$(vm "findmnt -T $SHARE2 -n -o FSTYPE")
share2_target=$(vm "findmnt -T $SHARE2 -n -o TARGET")
if [ "$share2_type" = "$FS_TYPE" ] && [ "$share2_target" != "$(vm "findmnt -T $HOME -n -o TARGET")" ]; then
    share2=$(podman run --rm --cgroup-parent="$PARENT1" --userns=keep-id --security-opt seccomp=unconfined \
        --volume "$SHARE2:/share2" "$PROBE_IMAGE" sh -c "(echo x > /share2/f) 2>&1 && echo W_OK || echo W_REFUSED; \
        (mkdir /share2/d) 2>&1 && echo MKDIR_OK || echo MKDIR_REFUSED" 2>&1 | tee -a "$TRANSCRIPT")
    check "a write on a second share of the same type, bound into the container, is refused: $share2" \
        has W_REFUSED "$share2"
else
    info "second share: $SHARE2 is on $share2_type, the same mount as the fixture or another type; not measured"
fi
walk=$(in_cg 1 "$EXERCISE walk-cost $REPO/$DEEPEST $WALK_COUNT")
bare=$(outside "$EXERCISE walk-cost $REPO/$DEEPEST $WALK_COUNT")
info "walk cost at the clone's deepest file, depth $DEEPEST_DEPTH: policy open_rdwr=$(field open_rdwr_ns "$walk")" \
    "bare open_rdwr=$(field open_rdwr_ns "$bare") ns; failed=$(field failed "$walk")"
jited=$(vm "sudo -n $CTL jited $PIN /tmp/file_open.jited")
info "$jited"
barrier_seen() {
    [ -n "$(field fetch_add_insns "$1")" ] && [ "$(field fetch_add_insns "$1")" != 0 ] && {
        [ "$(field ldaddal "$1")" != 0 ] || [ "$(field dmb_ish "$1")" != 0 ] || [ "$(field lock_xadd "$1")" != 0 ]
    }
}
check "the xlated program holds the atomic fetch-add and the jited one a barrier instruction" barrier_seen "$jited"

# ---------------------------------------------------------------------------
step "the NTFS short-name form, under its flag"
# ---------------------------------------------------------------------------
attach_a short-names "$HOOKS8"
check "the policy attached again with the short-names flag" \
    eq2 "$(field count "$attach")" 8 "$(field flags "$attach")" 1
corpus=$(in_cg 1 "$EXERCISE corpus $TREE short")
printf '%s\n' "$corpus" | grep -e MISMATCH -e UNSUPPORTED | sed 's/^/  /' | tee -a "$TRANSCRIPT"
check "the short-name corpus: $(printf '%s\n' "$corpus" | grep '^corpus ')" [ "$(field mismatches "$corpus")" = 0 ]

# ---------------------------------------------------------------------------
step "--unix-sockets: four sandboxes, the socket corpus and descriptors between them"
# ---------------------------------------------------------------------------
# A, the live session (cgroup 1), and B, a second session of the workspace under a later rule
# file (cgroup 2), each with file_receive; C, a session of another workspace, the clone (cgroup
# 3); D, a --workspace=read-only session, a policy with no root (cgroup 4).
attach_a unix-sockets "$HOOKS9"
check "A attached with nine hooks under unix-sockets" \
    eq2 "$(field count "$attach")" 9 "$(field flags "$attach")" 2
# What the runtime passes into a starting container reaches file_receive first: a container
# that does nothing, then the hook's last decision and counts.
start=$(in_cg 1 "echo STARTED")
check "a container starts under A with file_receive attached" has STARTED "$start"
info "$(vm "sudo -n $CTL last-decision $PIN_ROOT/a/file_receive")"
info "$(vm "sudo -n $CTL stats $PIN_ROOT/a/file_receive" | grep 'hook=file_receive')"
# What the runtime leaves open: the first process and a process of its own hold no descriptor
# beyond the standard three.
fds=$(in_cg 1 "$EXERCISE fds")
check "the container's first process holds no descriptor of the runtime's: $(printf '%s\n' "$fds" | tail -1)" \
    [ "$(field beyond_standard "$fds")" = 0 ]
# shellcheck disable=SC2086
attach=$(vm "sudo -n $CTL attach policy.bpf.o $CG2 $PIN_ROOT/b --fs-type $FS_TYPE --rules $RULES_B \
    --flags unix-sockets $ROOTS_A $HOOKS9")
check "B attached with nine hooks and the later rule file" \
    eq2 "$(field count "$attach")" 9 "$(field rule_count "$attach")" 128
attach=$(vm "sudo -n $CTL attach policy.bpf.o $CG3 $PIN_ROOT/c --fs-type $FS_TYPE --rules $RULES_A \
    --flags unix-sockets --root workspace=$REPO --root volume=$VOLMP --vol-fs-type $VOL_FS $HOOKS9")
check "C, another workspace's session, attached" [ "$(field count "$attach")" = 9 ]
attach=$(vm "sudo -n $CTL attach policy.bpf.o $CG4 $PIN_ROOT/d --fs-type $FS_TYPE --flags unix-sockets $HOOKS9")
check "D, a read-only session's policy with no root, attached" [ "$(field count "$attach")" = 9 ]
query=$(vm "sudo -n $CTL query $CG1")
info "$(printf '%s\n' "$query" | grep '^slots ')"
check "four sandboxes hold nine hooks of the ten slots" [ "$(field hooks_in_use "$query")" = 9 ]
corpus=$(in_cg 1 "$EXERCISE corpus $TREE unix")
printf '%s\n' "$corpus" | grep -e MISMATCH -e UNSUPPORTED | sed 's/^/  /' | tee -a "$TRANSCRIPT"
check "the socket corpus under unix-sockets: $(printf '%s\n' "$corpus" | grep '^corpus ')" \
    [ "$(field mismatches "$corpus")" = 0 ]
# A and B differ in policy: README.md is writable to A and not to B.
readme=$(in_cg 1 "(echo x >> $TREE/README.md) 2>&1 && echo A_OK || echo A_REFUSED")
readme_b=$(in_cg 2 "(echo x >> $TREE/README.md) 2>&1 && echo B_OK || echo B_REFUSED")
check "A writes README.md and B, under the later rule file, cannot" \
    eq2 "$(has A_OK "$readme"; echo $?)" 0 "$(has B_REFUSED "$readme_b"; echo $?)" 0
# D: nothing on the share opens for writing, /tmp does, reading works.
ro=$(in_cg 4 "(echo x > $TREE/apps/ro) 2>&1 && echo WS_OK || echo WS_REFUSED; (echo x > /tmp/ro) && echo TMP_OK; \
    cat $TREE/README.md > /dev/null && echo READ_OK")
check "D cannot write on the share, writes /tmp and reads the workspace" \
    eq2 "$(has WS_REFUSED "$ro" && has TMP_OK "$ro"; echo $?)" 0 "$(has READ_OK "$ro"; echo $?)" 0
# Descriptors over a socket in the volume. serve runs detached in the sender's sandbox; receive
# in the receiver's.
pass_fds() { # pass_fds SENDER-CG RECEIVER-CG SOCK SPECS -- ACTIONS: sets RECV to the receiver's output
    sender=$1
    receiver=$2
    sock=$3
    shift 3
    specs=
    while [ $# -gt 0 ] && [ "$1" != -- ]; do specs="$specs $1"; shift; done
    [ $# -gt 0 ] && shift
    eval "sparent=\$PARENT$sender"
    podman rm -f ko-agent-bpf3-srv > /dev/null 2>&1
    # shellcheck disable=SC2086
    podman run -d --name ko-agent-bpf3-srv --cgroup-parent="$sparent" $EXERCISER_OPTS "$PROBE_IMAGE" \
        $EXERCISE serve "$sock" $specs > /dev/null 2>&1
    i=0
    while [ $i -lt 50 ] && ! podman logs ko-agent-bpf3-srv 2>&1 | grep -q 'serve listening'; do
        sleep 0.2
        i=$((i + 1))
    done
    RECV=$(in_cg "$receiver" "$EXERCISE receive $sock $*")
    podman wait ko-agent-bpf3-srv > /dev/null 2>&1
    podman logs ko-agent-bpf3-srv 2>&1 | tee -a "$TRANSCRIPT" > /dev/null
    podman rm -f ko-agent-bpf3-srv > /dev/null 2>&1
}
received() { eq2 "$(field received "$RECV")" "$1" "$(field ctrunc "$RECV")" "$2"; }
same=$(in_cg 1 "$EXERCISE serve /vol/s0 pipe pair ro:$TREE/README.md > /tmp/serve.log & sleep 1; \
    $EXERCISE receive /vol/s0; wait; cat /tmp/serve.log")
check "a pipe, a socket pair's end and a workspace file pass between two processes of one container" \
    eq2 "$(field received "$same")" 3 "$(field ctrunc "$same")" 0
pass_fds 1 2 /vol/s1 "ro:$TREE/ordinary" "rw:$TREE/README.md" "ro:$TREE/ordinary"
check "B gets the first of three descriptors from A and MSG_CTRUNC: the writable README.md is refused by B's rules" \
    received 1 1
pass_fds 1 2 /vol/s2 "rw:$TREE/ordinary" "ro:$TREE/README.md" -- write:0 reopen:1
check "B gets a writable descriptor of a file its rules allow, and a read-only one, writes the first" \
    eq2 "$(field received "$RECV")" 2 "$(printf '%s\n' "$RECV" | sed -n 's/.*action=write:0 result=\(.*\)/\1/p')" ok
check "B cannot reopen the read-only descriptor of README.md for writing" \
    [ "$(printf '%s\n' "$RECV" | sed -n 's/.*action=reopen:1 result=\(.*\)/\1/p')" = EPERM ]
pass_fds 1 2 /vol/s3 "dir:/" "dir:/tmp" "dir:$TREE"
check "B gets no directory descriptor from A: its container root, its /tmp, the receiver's own root" received 0 1
pass_fds 1 3 /vol/s4 "ro:$TREE/ordinary" "ro:$TREE/ordinary"
check "C, another workspace's session, gets no descriptor of this workspace" received 0 1
pass_fds 1 4 /vol/s5 "ro:$TREE/ordinary" "rw:$TREE/ordinary"
check "D, the read-only session, gets no descriptor of the share" received 0 1
pass_fds 2 1 /vol/s6 "dir:/" "pipe"
check "A gets no directory descriptor from B, and the pipe after it is dropped with it" received 0 1
pass_fds 2 1 /vol/s7 "pipe" "dir:/tmp"
check "A gets the pipe before a refused directory descriptor from B" received 1 1
# The sender gone before the receiver reads: the receiver connects and then waits for a marker
# the driver makes once the sender's container has ended and been removed, so its mount
# namespace is torn down; the hook's record of the refusal must then show no namespace.
pass_fds_after_exit() { # pass_fds_after_exit SOCK SPECS... : A sends and exits, B reads after A is gone
    sock=$1
    shift
    podman rm -f ko-agent-bpf3-srv ko-agent-bpf3-rcv > /dev/null 2>&1
    # shellcheck disable=SC2086
    podman run -d --name ko-agent-bpf3-srv --cgroup-parent="$PARENT1" $EXERCISER_OPTS "$PROBE_IMAGE" \
        $EXERCISE serve "$sock" then-exit "$@" > /dev/null 2>&1
    i=0
    while [ $i -lt 50 ] && ! podman logs ko-agent-bpf3-srv 2>&1 | grep -q 'serve listening'; do
        sleep 0.2
        i=$((i + 1))
    done
    # shellcheck disable=SC2086
    podman run -d --name ko-agent-bpf3-rcv --cgroup-parent="$PARENT2" $EXERCISER_OPTS "$PROBE_IMAGE" \
        $EXERCISE receive "$sock" "wait-for:$sock.gone" > /dev/null 2>&1
    podman wait ko-agent-bpf3-srv > /dev/null 2>&1
    podman logs ko-agent-bpf3-srv 2>&1 | tee -a "$TRANSCRIPT" > /dev/null
    podman rm -f ko-agent-bpf3-srv > /dev/null 2>&1
    vm "touch $VOLMP/$(basename "$sock").gone" > /dev/null
    podman wait ko-agent-bpf3-rcv > /dev/null 2>&1
    RECV=$(podman logs ko-agent-bpf3-rcv 2>&1 | tee -a "$TRANSCRIPT")
    podman rm -f ko-agent-bpf3-rcv > /dev/null 2>&1
}
pass_fds_after_exit /vol/s8 "rw:$TREE/README.md" "dir:$TREE" "ro:$TREE/ordinary"
last=$(vm "sudo -n $CTL last-decision $PIN_ROOT/b/file_receive")
info "$last"
check "B, receiving after A's container ended, gets neither the writable README.md nor the directory" \
    received 0 1
check "the refused descriptor's mount was in no namespace: the sender's was torn down before the read" \
    eq2 "$(field ns_inum "$last")" 0 "$(field name "$last")" README.md
pass_fds_after_exit /vol/s9 "ro:$TREE/ordinary"
check "B, receiving after A's container ended, gets a read-only share file its policy allows" received 1 0
stats=$(vm "sudo -n $CTL stats $PIN_ROOT/b/file_receive")
info "$(printf '%s\n' "$stats" | grep 'hook=file_receive')"
vm "sudo -n $CTL unpin $PIN_ROOT/a; sudo -n $CTL unpin $PIN_ROOT/b; sudo -n $CTL unpin $PIN_ROOT/c
    sudo -n $CTL unpin $PIN_ROOT/d" > /dev/null

# ---------------------------------------------------------------------------
step "the namespaces and mounts a generated seccomp profile refuses"
# ---------------------------------------------------------------------------
# The profile "Mounts" relies on, derived from the machine's default as the TODO item plans it: a
# user namespace refused with EPERM by the flag of clone and unshare, clone3 answered ENOSYS, and
# the mount family answered EPERM by rules of its own, since the machine's default action is
# ENOSYS. The default is the machine's own file, which its podman serves; it is read without
# the transcript, which its 1,100 lines would bury.
podman machine ssh "cat /usr/share/containers/seccomp.json" > "$FIX/seccomp-default.json" 2>/dev/null
python3 - "$FIX/seccomp-default.json" "$FIX/seccomp.json" <<'EOF'
import json, sys
profile = json.load(open(sys.argv[1]))
mounts = ["mount", "fsopen", "fsconfig", "fsmount", "fspick", "move_mount", "open_tree", "open_tree_attr",
          "mount_setattr", "umount2", "umount", "pivot_root"]
family = set(mounts) | {"clone", "clone3", "unshare"}
for entry in profile["syscalls"]:
    entry["names"] = [name for name in entry["names"] if name not in family]
profile["syscalls"] = [entry for entry in profile["syscalls"] if entry["names"]]
CLONE_NEWUSER = 0x10000000
rules = [{"names": ["clone3"], "action": "SCMP_ACT_ERRNO", "errnoRet": 38},
         {"names": mounts, "action": "SCMP_ACT_ERRNO", "errnoRet": 1}]
for name in ("clone", "unshare"):
    rules.append({"names": [name], "action": "SCMP_ACT_ERRNO", "errnoRet": 1,
        "args": [{"index": 0, "value": CLONE_NEWUSER, "valueTwo": CLONE_NEWUSER, "op": "SCMP_CMP_MASKED_EQ"}]})
    rules.append({"names": [name], "action": "SCMP_ACT_ALLOW",
        "args": [{"index": 0, "value": CLONE_NEWUSER, "valueTwo": 0, "op": "SCMP_CMP_MASKED_EQ"}]})
profile["syscalls"] = rules + profile["syscalls"]
json.dump(profile, open(sys.argv[2], "w"))
EOF
ns=$(podman run --rm --cgroup-parent="$PARENT1" --userns=keep-id --security-opt "seccomp=$FIX/seccomp.json" \
    --volume "$FIX:$FIX" "$PROBE_IMAGE" sh -c "$EXERCISE namespaces; echo CHILD_RAN" 2>&1 | tee -a "$TRANSCRIPT")
ns_refused() { # every syscall the profile refuses answered EPERM, clone3's ENOSYS aside
    for call in unshare_newuser unshare_newns mount fsopen open_tree move_mount fsmount fspick mount_setattr \
        umount2 pivot_root; do
        [ "$(printf '%s\n' "$ns" | sed -n "s/^namespaces $call=\(.*\)/\1/p")" = EPERM ] || return 1
    done
}
check "under the generated profile a user namespace and every mount syscall answer EPERM, and a child still runs" \
    eq2 "$(ns_refused; echo $?)" 0 "$(has CHILD_RAN "$ns"; echo $?)" 0

[ "$failed" -eq 0 ] || exit 1
