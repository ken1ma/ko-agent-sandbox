#!/bin/sh
# Does the podman machine give memory back to macOS after a build inside it? doc/run-on-host.md, "The
# measurement behind the feature", records the answer; run this after a podman, libkrun or macOS upgrade
# and update it.
#
#   sh src/probe/machine-memory-return.sh [<command that builds inside the sandbox...>]
#
# Run it on macOS from the project directory, right after `podman machine restart`, with no session on the
# machine. The probe checks both: an uptime under ten minutes, which shows a recent start and not that
# nothing ran since, and no running container.
# Default command: java -jar target/dist/ko-agent-sandbox.jar sbt test — the build the premise measured.
# PRESSURE=no skips the last phase, which allocates host memory with memory_pressure(1).
#
# It prints what decides the answer before measuring: the machine's provider and memory, and the
# libkrun the host's krunkit loads. libkrun frees reported guest pages with MADV_FREE from v1.19.0
# (containers/libkrun pull 703, merged 2026-06-03, on the stable-1.19.x branch); v1.18 and older use
# MADV_DONTNEED, which does nothing on macOS. The guest's side is already known: the machine kernel
# binds virtio_balloon with the free-page-reporting feature negotiated (read from sysfs in a session,
# 2026-09-22).
#
# Then it samples the VM process every 5 s through four phases and summarizes each:
#   baseline  60 s before the build
#   build     the command, run on this host so the sampler sees the machine grow
#   after     600 s once the command has exited
#   pressure  60 s under memory_pressure -l warn, then 60 s more
# Pages freed with MADV_FREE stay in the process's resident size until macOS needs them, so a return
# shows in the pressure phase, not in "after". Per-process counters alone do not decide it either way:
# the pull request above reports reclamation that Activity Monitor's per-process figure did not show,
# and macOS can compress a process's pages, which lowers its resident size without discarding them.
# So each sample has the VM's resident size (ps RSS), top's MEM and CMPRS for the same pid, and the
# host's free pages, the pages stored in and occupied by the compressor (vm_stat: stored counts the
# original pages, occupied the space they take), swap in use (vm.swapusage) and pressure level
# (kern.memorystatus_vm_pressure_level, blank where the sysctl is absent). Read the summary's columns
# together, as evidence rather than proof:
#   - resident size falls under pressure while CMPRS, the compressor's stored pages and swap in use
#     stay put: consistent with the pages being discarded;
#   - resident size falls by about what CMPRS, stored pages or swap gain: consistent with the pages
#     being compressed or swapped out, still held;
#   - anything else, a flat resident size included: inconclusive, with the host's free pages and
#     pressure level during the pressure phase as the remaining evidence.
# A pressure phase whose memory_pressure exits before its 60 s is reported invalid, with its output
# kept beside the samples. Samples go to a CSV the summary names; keep it with the result.
#
# A machine that has run sessions is already fully resident at baseline: the build phase shows no
# growth, and what the pressure phase undoes is whatever the guest freed earlier, not the build. So
# the probe refuses a machine up for more than ten minutes. On a freshly restarted one the guest's
# untouched memory is not resident on the host, the build's growth shows, and the pressure phase has
# that growth to undo. The resident size can exceed the machine's memory (13.4 GiB for a 12 GiB
# machine after a build, 2026-09-22), so read the columns as differences between phases.
set -u

if [ "$(uname -s)" != "Darwin" ]; then
    echo "This probe measures a macOS host's podman machine; this is $(uname -s). Run it on macOS." >&2
    exit 2
fi
if [ -n "${KO_AGENT_SANDBOX_EGRESS_RULESET:-}" ] || [ -d /etc/ko-agent-sandbox ]; then
    echo "This looks like a sandbox session. Run the probe on the host instead." >&2
    exit 2
fi
if [ $# -eq 0 ]; then
    if [ ! -f target/dist/ko-agent-sandbox.jar ]; then
        echo "target/dist/ko-agent-sandbox.jar is missing: run 'sbt dist' first, or pass a build command." >&2
        exit 2
    fi
    # The launcher's start prompt would otherwise wait inside the "build" phase, on a user reading a
    # sampler's output rather than the launch's lines.
    KO_AGENT_SANDBOX_SESSION_START=immediate
    export KO_AGENT_SANDBOX_SESSION_START
    set -- java -jar target/dist/ko-agent-sandbox.jar sbt test
fi

say() { printf '%-28s %s\n' "$1" "$2"; }

echo "== What decides the answer"
say "macOS" "$(sw_vers -productVersion) $(uname -m)"
say "podman" "$(podman --version 2>&1)"
say "machine provider" "$(podman machine info --format '{{.Host.VMType}}' 2>&1)"
say "machine memory (MiB)" "$(podman machine inspect --format '{{.Resources.Memory}}' 2>&1)"
say "machine state" "$(podman machine inspect --format '{{.State}}' 2>&1)"
uptime_s=$(podman machine ssh -- cut -d. -f1 /proc/uptime 2>&1)
case "$uptime_s" in
    '' | *[!0-9]*) echo "Cannot read the machine's uptime over podman machine ssh: $uptime_s" >&2; exit 2 ;;
esac
say "machine uptime (s)" "$uptime_s"
if [ "$uptime_s" -gt 600 ]; then
    echo "The machine has been up longer than ten minutes: run 'podman machine restart', then this probe." >&2
    exit 2
fi
if [ -n "$(podman ps -q 2>&1)" ]; then
    echo "Containers are running on the machine; end those sessions first:" >&2
    podman ps >&2
    exit 2
fi
krunkit=$(command -v krunkit || true)
if [ -n "$krunkit" ]; then
    say "krunkit" "$krunkit"
    # otool prints the dylib krunkit loads; its install name carries the version Homebrew built, and
    # brew lists the formula versions. Either one at or above 1.19.0 means MADV_FREE.
    otool -L "$krunkit" 2>/dev/null | grep -i libkrun | sed 's/^[[:space:]]*/    /'
    if command -v brew >/dev/null 2>&1; then
        say "brew versions" "$(brew list --versions libkrun krunkit 2>&1 | tr '\n' ' ')"
    fi
else
    say "krunkit" "MISSING (the provider above is not libkrun, or krunkit is not on PATH)"
fi

pids=$(pgrep -x krunkit || true)
if [ -z "$pids" ]; then
    echo "No krunkit process: start the machine (podman machine start) and run again." >&2
    exit 2
fi
say "VM process(es)" "$(echo "$pids" | tr '\n' ' ')"
echo

# Kept after the run: the summary names it.
samples_dir=$(mktemp -d -t machine-memory-return)
csv=$samples_dir/samples.csv
phase_file=$samples_dir/phase
echo baseline > "$phase_file"
echo "epoch,phase,pid,rss_kb,top_mem_kb,top_cmprs_kb,host_free_kb,host_compressor_stored_kb," \
    "host_compressor_occupied_kb,host_swap_used_kb,host_pressure_level" | tr -d ' ' > "$csv"

# top prints sizes as 1024K, 512M, 2G, sometimes with a trailing + or -; vm_stat prints page counts.
to_kb() {
    printf '%s' "$1" | awk '{
        v = $0; sub(/[+-]$/, "", v); u = substr(v, length(v)); n = substr(v, 1, length(v) - 1)
        if (u == "K") print n; else if (u == "M") print n * 1024; else if (u == "G") print n * 1048576
        else if (u == "B") print int(n / 1024); else print v
    }'
}
sample_once() {
    now=$(date +%s); phase=$(cat "$phase_file")
    page=$(vm_stat | awk 'NR == 1 { gsub(/[^0-9]/, "", $0); print }')
    free=$(vm_stat | awk -F: '/^Pages free/ { gsub(/[^0-9]/, "", $2); print $2 }')
    stored=$(vm_stat | awk -F: '/^Pages stored in compressor/ { gsub(/[^0-9]/, "", $2); print $2 }')
    occupied=$(vm_stat | awk -F: '/^Pages occupied by compressor/ { gsub(/[^0-9]/, "", $2); print $2 }')
    free_kb=$((free * page / 1024)); stored_kb=$((stored * page / 1024)); occupied_kb=$((occupied * page / 1024))
    swap=$(sysctl -n vm.swapusage 2>/dev/null |
        awk '{ for (i = 1; i <= NF; i++) if ($i == "used") print $(i + 2) }')
    swap_kb=$(to_kb "$swap")
    level=$(sysctl -n kern.memorystatus_vm_pressure_level 2>/dev/null)
    for pid in $pids; do
        rss=$(ps -o rss= -p "$pid" | tr -d ' ')
        [ -n "$rss" ] || continue
        line=$(top -l 1 -pid "$pid" -stats pid,mem,cmprs 2>/dev/null |
            awk -v p="$pid" '$1 == p { print $2, $3 }')
        mem=$(to_kb "${line%% *}"); cmprs=$(to_kb "${line##* }")
        echo "$now,$phase,$pid,$rss,$mem,$cmprs,$free_kb,$stored_kb,$occupied_kb,$swap_kb,$level" >> "$csv"
    done
}
sampler() { while :; do sample_once; sleep 5; done; }
sampler &
sampler_pid=$!
cleanup() {
    kill "$sampler_pid" 2>/dev/null
    [ -n "${pressure_pid:-}" ] && kill "$pressure_pid" 2>/dev/null
    rm -f "$phase_file"
    return 0
}
# A signal must end the run: a handler that only cleans up would let the build and the pressure phase follow.
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "== baseline: 60 s"
sleep 60
echo "== build: $*"
echo build > "$phase_file"
start=$(date +%s)
"$@"
status=$?
# macOS's /bin/sh, bash 3.2, mis-parses a $( ) nested in $(( )) (2026-09-22), hence the named variables.
end=$(date +%s)
elapsed=$((end - start))
echo "command exited $status after $elapsed s"
echo "== after: 600 s"
echo after > "$phase_file"
sleep 600
pressure_note=
if [ "${PRESSURE:-yes}" != no ] && command -v memory_pressure >/dev/null 2>&1; then
    echo "== pressure: memory_pressure -l warn for 60 s, then 60 s more"
    echo pressure > "$phase_file"
    pressure_log=$samples_dir/memory_pressure.log
    memory_pressure -l warn > "$pressure_log" 2>&1 &
    pressure_pid=$!
    sleep 60
    if kill -0 "$pressure_pid" 2>/dev/null; then
        kill "$pressure_pid" 2>/dev/null; wait "$pressure_pid" 2>/dev/null
        echo released > "$phase_file"
        sleep 60
    else
        wait "$pressure_pid"
        pressure_note="pressure phase INVALID: memory_pressure exited with status $? before its 60 s; see $pressure_log"
        echo "$pressure_note" >&2
    fi
    pressure_pid=
fi
kill "$sampler_pid" 2>/dev/null; wait "$sampler_pid" 2>/dev/null

echo
echo "== summary (MiB): first, peak and last sample of each phase; samples in $csv"
awk -F, '
BEGIN { split("4 6 7 8 10", col, " "); ncol = 5 }
NR > 1 {
    key = $2 "," $3
    if (!(key in seen)) {
        seen[key] = 1; order[++n] = key
        for (i = 1; i <= ncol; i++) { first[key, i] = $col[i]; peak[key, i] = $col[i] }
    }
    for (i = 1; i <= ncol; i++) { if ($col[i] + 0 > peak[key, i] + 0) peak[key, i] = $col[i]; last[key, i] = $col[i] }
    level[key] = $11
}
END {
    printf "%-9s %-6s | %-20s | %-20s | %-20s | %-20s | %-20s | %s\n", "phase", "pid",
        "VM RSS", "VM CMPRS", "host free", "compressor stored", "host swap used", "pressure level"
    printf "%-9s %-6s | %-20s | %-20s | %-20s | %-20s | %-20s | %s\n", "", "",
        "first  peak  last", "first  peak  last", "first  peak  last", "first  peak  last", "first  peak  last", "last"
    for (k = 1; k <= n; k++) {
        key = order[k]; split(key, kp, ",")
        printf "%-9s %-6s", kp[1], kp[2]
        for (i = 1; i <= ncol; i++)
            printf " | %6d %6d %6d", first[key, i] / 1024, peak[key, i] / 1024, last[key, i] / 1024
        printf " | %s\n", level[key]
    }
}' "$csv"
[ -z "$pressure_note" ] || echo "$pressure_note"
