#!/bin/sh
# What the broker's session assumes — doc/plan-host-build-daemons-and-gradle.md, Phase 1 and its
# "Must verify" list — measured before the broker encodes any of it. Three groups of rows:
#
#   L1-L4  SBPL: a loopback listener on port 0 under (local ip "localhost:*"), its control, and an
#          exact-port outbound rule that reaches its port and not the neighbor's
#   S1-S6  sbt 1.13.0 and 2.0.8, one scratch project each: a server started by the owner's command
#          line publishes its portfile before a deadline; a client with its own tmp attaches and
#          forks nothing; the client's unix-socket rule; a TERMed client cancels its exec, and what
#          the forked JVM does; where sbt 2 writes its proc entry; the wrong-directory control,
#          then a protocol shutdown at the socket recorded before it
#   M1-M7  Mill 1.1.9, one scratch project: the stock ./mill under the daemon profile leaves a
#          daemon behind its denied connect; the port from lsof; a client confined to that port,
#          and to the neighbor; the command's environment reaching the build; a TERMed client
#          mid-command; MILL_SERVER_TIMEOUT_MILLIS; a foreign daemon whose fingerprint differs
#
# Run it on macOS, from this repository's root, in a host terminal, with the cs-installed sbt on
# PATH and JAVA_HOME (or `cs java-home`) naming a JDK. It downloads what the two sbt versions and
# Mill need, unconfined, into the user's own caches — the provisioning the wrapper requires of the
# user — and confines only the rows. About ten minutes on a warm cache. On any FAIL the scratch
# tree under /private/tmp is kept and named; INFO rows are measurements with no expected answer.
#
# Every process it starts runs in a group whose leader stays alive as the group's proof, the
# wrapper's own registration (RunOnHostSession.registeredSpawn): the leader installs the closed
# environment, publishes the child's exit status beside its record, and stays; every wait has a
# deadline, a deadline passed is a FAIL that ends the group, and cleanup signals only groups whose
# leader is still alive. A denial row passes only on the operating system's own refusal in the
# process's output, or on the behavior sbt documents for it, never on a bare failure.
#
# The confined rows use (allow default) profiles that deny network* and then allow one rule, so
# each measures the network rule alone: the filesystem rules are the gate's to measure, and a
# deny-default profile here would chase grants the question is not about.

set -u

if [ "$(uname -s)" != "Darwin" ]; then
    echo "This probe measures a macOS host; this is $(uname -s). Run it on macOS." >&2
    exit 2
fi
if [ -n "${KO_AGENT_SANDBOX_EGRESS_RULESET:-}" ] || [ -d /etc/ko-agent-sandbox ]; then
    echo "This looks like a sandbox session. Run the probe in a host terminal instead." >&2
    exit 2
fi
if [ ! -f src/probe/mill-fixture/mill ]; then
    echo "Run from the repository root; src/probe/mill-fixture/mill is not here." >&2
    exit 2
fi

pass=0; fail=0
report() { # PASS|FAIL|INFO label detail
    printf '%-4s  %-58s  %s\n' "$1" "$2" "$3"
    case "$1" in PASS) pass=$((pass + 1)) ;; FAIL) fail=$((fail + 1)) ;; esac
}

JAVA_HOME=${JAVA_HOME:-$(cs java-home 2>/dev/null)}
if [ ! -x "${JAVA_HOME:-}/bin/java" ]; then
    echo "JAVA_HOME does not name a JDK and cs java-home gave none" >&2
    exit 2
fi
sbt_script=$(command -v sbt) || { echo "no sbt on PATH; cs install sbt" >&2; exit 2; }
case "$sbt_script" in /*) ;; *) sbt_script=$(cd "$(dirname "$sbt_script")" && pwd)/sbt ;; esac
account=$(id -un); uid=$(id -u)
system_path="$JAVA_HOME/bin:/usr/bin:/bin:/usr/sbin:/sbin"
denied='Operation not permitted'

work=$(mktemp -d /private/tmp/ko-probe.XXXXXX)   # short: sbt's boot socket path budget

# --- groups --------------------------------------------------------------------------------------

leaders=$work/leaders   # `<pid> <lstart>` per live leader, the wrapper's own record
: > "$leaders"
probe_env=""   # a file of NAME=VALUE lines the leader installs as the whole environment; "" inherits
# Start COMMAND in DIR as the child of a new group's leader, which publishes the child's exit
# status to RECORD.exit and then stays. Redirections on the call reach the child. Sets `leader`.
group_start() { # record dir command...
    rm -f "$1.exit" "$1.timeout"
    PROBE_ENV_FILE="$probe_env" perl -e '
        setpgrp(0, 0) or exit 71;
        my ($record, $dir, @command) = @ARGV;
        chdir $dir or exit 71;
        if (my $file = $ENV{PROBE_ENV_FILE}) {
            open(my $in, "<", $file) or exit 71;
            my %env;
            while (my $line = <$in>) { chomp $line; my ($name, $value) = split /=/, $line, 2; $env{$name} = $value; }
            %ENV = %env;
        } else { delete $ENV{PROBE_ENV_FILE}; }
        my $pid = fork;
        exit 71 unless defined $pid;
        if ($pid == 0) { exec { $command[0] } @command or exit 71; }
        waitpid($pid, 0);
        my $status = ($? & 127) ? 128 + ($? & 127) : $? >> 8;
        open(my $out, ">", "$record.exit.pending") or exit 71;
        print $out "$status\n";
        close($out) or exit 71;
        rename("$record.exit.pending", "$record.exit") or exit 71;
        sleep 3600 while 1;' "$@" </dev/null &
    leader=$!
    printf '%s %s\n' "$leader" "$(lstart_of "$leader")" >> "$leaders"
}
exited() { [ -f "$1.exit" ] || [ -f "$1.timeout" ]; }
# The child's exit status; 124 when its deadline passed; `none` when neither was recorded.
status_of() {
    if [ -f "$1.timeout" ]; then echo 124
    else cat "$1.exit" 2>/dev/null || echo none; fi
}
# End a group behind its recorded leader only — alive, with the start time recorded when it
# was made, as the wrapper proves a group before signalling it — and retire the record: a pgid
# whose leader died may be someone else's by now.
end_group() { # leader
    recorded=$(sed -n "s/^$1 //p" "$leaders" | head -1)
    if [ -n "$recorded" ] && [ "$(lstart_of "$1")" = "$recorded" ]; then
        /bin/kill -TERM -- "-$1" 2>/dev/null
        until_true 5 sh -c "[ -z \"\$(ps -o pid= -g $1)\" ]" || /bin/kill -KILL -- "-$1" 2>/dev/null
    fi
    grep -v "^$1 " "$leaders" > "$leaders.new"; mv "$leaders.new" "$leaders"
}
# COMMAND in DIR, bounded, its group ended after it: the exit status in `status`, 124 when the
# deadline passed — recorded as RECORD.timeout, so status_of and failed say so afterwards — and 71
# when the leader could not start it. False unless 0.
bounded() { # seconds record dir command...
    limit=$1; record=$2; shift 2
    group_start "$record" "$@"
    until_true "$limit" exited "$record" || : > "$record.timeout"
    end_group "$leader"
    status=$(status_of "$record")
    [ "$status" -eq 0 ]
}

# The run's logs, tables and records under the project, where the sandbox can read them; the
# scratch tree itself stays short for sbt's socket paths, and its build trees are not copied.
logs=$PWD/log/run-on-host-broker-session
save_logs() {
    rm -rf "$logs" && mkdir -p "$logs" || return
    (cd "$work" && find . -type f \
        \( -name '*.log' -o -name 'sockets-*' -o -name '*.exit' -o -name '*.timeout' -o -name '*.sb' \
           -o -name 'env*' -o -name 'timeline*' -o -name '*.scan*' -o -name 'l5*' -o -name 'settle*' \) \
        -not -path '*/out/*' -not -path '*/target/*' -not -path '*/global/*' -not -path '*/ivy/*' \
        -not -path './mill/tmp/*' | while read -r file; do
            mkdir -p "$logs/$(dirname "$file")" && cp "$file" "$logs/$file"
        done)
    echo "logs: log/run-on-host-broker-session/"
}
cleanup() {
    for leader in $(cut -d' ' -f1 "$leaders"); do end_group "$leader"; done
    # Whatever an ended group re-parented away: by cwd under the scratch tree.
    for pid in $(with_cwd . "$work"); do kill -KILL "$pid" 2>/dev/null; done
    save_logs
    if [ "$fail" -eq 0 ]; then rm -rf "$work"; else echo "kept for inspection: $work"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# --- helpers -------------------------------------------------------------------------------------

# Bounded wait for a condition: until SECONDS COMMAND...
until_true() {
    limit=$(( $1 * 10 )); shift
    while [ "$limit" -gt 0 ]; do
        "$@" && return 0
        sleep 0.1; limit=$((limit - 1))
    done
    return 1
}
gone() { ! kill -0 "$1" 2>/dev/null; }
has_line() { grep -q -- "$1" "$2" 2>/dev/null; }

# Processes by command-line pattern whose cwd is a directory or under it — the gate's own test,
# with one lsof for every process rather than one per candidate.
with_cwd() { # pattern dir
    lsof -d cwd -Fpn 2>/dev/null | awk -v dir="$2" '
        /^p/ { pid = substr($0, 2) }
        /^n/ { path = substr($0, 2); if (path == dir || index(path, dir "/") == 1) print pid }' |
    while read -r pid; do
        ps -o command= -p "$pid" 2>/dev/null | grep -q -- "$1" && printf '%s\n' "$pid"
    done
}
lstart_of() { ps -o lstart= -p "$1" 2>/dev/null | sed 's/^ *//'; }
# The process's UNIX sockets as lsof lists them, kept in a file. An observation is lsof exiting
# 0 — it exits 1 for a scan it could not complete, a partial table included — with a nonempty
# table, since a live sbt server always holds its listening socket; anything else is a failed
# observation, never an idle server: false.
# The checked scan: every descriptor of every process of this user, one tab-separated
# `pid command fd device name type` row each, in FILE, taken as one listing so that a server's rows
# and its peers come from the same moment. Apple's lsof skips a process whose proc_pidinfo fails
# with EPERM or ESRCH without a word; reports a process whose descriptors it cannot enumerate as
# an entry whose fd is `err` (dproc.c); and reports one descriptor it cannot read under its
# number as `<kind>: <reason>`, the kind from the kernel's descriptor listing, so
# `socket: Operation not permitted` may hide a client where `vnode: FD unavailable` — a file
# closed between listing and reading, as Spotlight's indexer does during a scan — cannot
# (dproc.c, dfile.c err2nm, dsock.c). With `-u`, every file of the user's processes inherits the
# selection (proc.c alloc_lfile), so those entries are in this listing where a `-a -p <pid> -U`
# table would drop them. The scan is complete only when lsof exits 0 with nothing on stderr,
# every process of this user alive before and after it has a row, and no row is an error that
# can hide a socket: an `err` entry, a `socket:` one, or an `unknown file type`; otherwise
# FILE.reason says why and the scan is unknown, never idle. No name lsof writes for a readable
# socket has those forms: paths start with `/`, peers with `->`, addresses with a digit or `[`.
# "This user's processes" is by effective uid on both sides, lsof's notion: `ps -u` selects by
# real uid, which a setuid `login` from the terminal keeps while running as root, unreadable to
# lsof and no client of anything.
rows() {
    awk -F '\t' 'BEGIN { OFS = "\t" } /^p/ { pid = substr($0, 2) } /^c/ { cmd = substr($0, 2) }
        /^f/ { fd = substr($0, 2); dev = ""; type = "" } /^t/ { type = substr($0, 2) }
        /^d/ { dev = substr($0, 2) } /^n/ { print pid, cmd, fd, dev, substr($0, 2), type }'
}
# Live: this user's by effective uid, and not a zombie, which holds no descriptor for lsof to list.
live_pids() { ps -eo pid=,uid=,stat= | awk -v u="$uid" '$2 == u && $3 !~ /^Z/ { print $1 }' | sort; }
scan() { # file
    out=$1
    live_pids > "$out.before"
    lsof -u "$account" -nP -Fpcftdn > "$out.raw" 2>"$out.err"; scan_status=$?
    live_pids > "$out.after"
    rows < "$out.raw" > "$out"
    sed -n 's/^p//p' "$out.raw" | sort -u > "$out.seen"
    comm -12 "$out.before" "$out.after" | comm -23 - "$out.seen" > "$out.missed"
    awk -F '\t' '$3 ~ /^ *err$/ || $5 ~ /^socket: / || $5 ~ /^unknown file type: /' "$out" > "$out.errors"
    if [ "$scan_status" -ne 0 ]; then echo "lsof exit $scan_status" > "$out.reason"
    elif [ -s "$out.err" ]; then echo "lsof stderr: $(first_line "$out.err")" > "$out.reason"
    elif [ -s "$out.missed" ]; then echo "$(wc -l < "$out.missed" | tr -d ' ') live processes missed" > "$out.reason"
    elif [ -s "$out.errors" ]; then echo "$(wc -l < "$out.errors" | tr -d ' ') descriptor errors" > "$out.reason"
    else rm -f "$out.reason"; fi
    ! [ -f "$out.reason" ]
}
# The UNIX sockets of a pid from a scan, and what they mean: Apple's lsof
# (dialects/darwin/libproc/dsock.c) names a socket by its bound path when it has one, which
# XNU's unp_connect copies from the listener onto each accepted socket, and by `->0x<peer pcb>`
# only when it has none; the DEVICE field is the socket's own pcb. So a server's clients are its
# rows named by the socket path beyond the listener, a row named `->` is a socket the server
# opened, and a client's socket names the server-side pcb it is connected to.
socket_table() { # scan pid file: the pid's UNIX-socket rows, nonempty required
    awk -F '\t' -v p="$2" '$1 == p && $6 == "unix"' "$1" > "$3" && [ -s "$3" ]
}
named() { awk -F '\t' -v p="$2" '$5 == p' "$1" | wc -l | tr -d ' '; } # table path: listener + accepted
# The live clients of a server table's path-named sockets: `pid command` of every socket in the
# same scan named `->` one of their pcbs. Usage: peers scan table path
peers() {
    awk -F '\t' -v p="$3" 'NR == FNR { if ($5 == p) pcb["->" $4] = 1; next } ($5 in pcb) { print $1, $2 }' "$2" "$1"
}
show_table() { sed 's/^/        /' "$@"; } # file, or stdin
listen_ports() { # pid: the TCP ports it listens on
    lsof -a -p "$1" -iTCP -sTCP:LISTEN -nP -Fn 2>/dev/null | sed -n 's/^n.*:\([0-9]*\)$/\1/p' | sort -u
}
profile() { # file rule...: an allow-default profile that denies network* and allows the rules
    out=$1; shift
    { echo '(version 1)'; echo '(allow default)'; echo '(deny network*)'
      for rule in "$@"; do echo "$rule"; done; } > "$out"
}
# The wrapper's closed environment, minus the proxy, as a file for the group leader.
write_env() { # file tmp runtime-dir extra-java-tool-options [NAME=VALUE...]
    out=$1; tmp=$2; runtime=$3; extra=$4; shift 4
    { printf 'PATH=%s\nJAVA_HOME=%s\nHOME=%s\nUSER=%s\nLOGNAME=%s\n' \
          "$system_path" "$JAVA_HOME" "$HOME" "$account" "$account"
      printf 'TMPDIR=%s\nXDG_RUNTIME_DIR=%s\n' "$tmp" "$runtime"
      printf 'JAVA_TOOL_OPTIONS=-Djava.io.tmpdir=%s -Djava.net.preferIPv4Stack=true %s\n' "$tmp" "$extra"
      for pair in "$@"; do printf '%s\n' "$pair"; done; } > "$out"
}
first_line() { grep -v '^$' "$1" 2>/dev/null | grep -v 'Picked up' | head -1 | cut -c1-70; }
# The wording of a failed bounded run, for a FAIL detail.
failed() { # record log
    case "$(status_of "$1")" in
        124) echo "deadline passed; group ended" ;;
        71) echo "the leader could not start it" ;;
        *) echo "exit $(status_of "$1"): $(first_line "$2")$(cause "$2")" ;;
    esac
}
cause() { grep -m1 'Caused by' "$1" 2>/dev/null | sed 's/^/; /' | cut -c1-90; }

echo "machine: macOS $(sw_vers -productVersion), $(uname -m); $("$JAVA_HOME/bin/java" -version 2>&1 | head -1)"
echo "sbt script: $sbt_script"
echo "scratch: $work"

# --- L: the SBPL rules ---------------------------------------------------------------------------

echo
echo "L: SBPL loopback rules"
cat > "$work/listener.py" <<'PY'
# Bind port 0 on loopback, print the port, accept one connection or time out; exit 0 on accept.
import socket, sys
s = socket.socket()
s.bind(("127.0.0.1", 0))
s.listen(1)
print(s.getsockname()[1], flush=True)
s.settimeout(15)
try:
    s.accept()
except socket.timeout:
    sys.exit(3)
PY
listener_row() { # label profile bind|deny
    : > "$work/l-port"
    group_start "$work/listener" "$work" /usr/bin/sandbox-exec -f "$2" python3 "$work/listener.py" \
        >"$work/l-port" 2>"$work/l.err"
    lpid=$leader
    if until_true 5 sh -c "[ -s '$work/l-port' ]"; then
        port=$(head -1 "$work/l-port")
        /bin/bash -c "exec 3<>/dev/tcp/127.0.0.1/$port" 2>/dev/null
        until_true 20 exited "$work/listener" || : > "$work/listener.timeout"
        if [ "$3" = bind ] && [ "$(status_of "$work/listener")" = 0 ]
        then report PASS "$1" "bound port $port, accepted a connection"
        elif [ "$3" = bind ]
        then report FAIL "$1" "bound port $port; $(failed "$work/listener" "$work/l.err")"
        else report FAIL "$1" "bound port $port without a rule"; fi
    else
        until_true 20 exited "$work/listener" || : > "$work/listener.timeout"
        if [ "$3" = deny ] && [ "$(status_of "$work/listener")" != 124 ] && has_line "$denied" "$work/l.err"
        then report PASS "$1" "bind denied: $(first_line "$work/l.err")"
        else report FAIL "$1" "no port; $(failed "$work/listener" "$work/l.err")"; fi
    fi
    end_group "$lpid"
}
profile "$work/l1.sb" '(allow network-bind network-inbound (local ip "localhost:*"))'
listener_row "L1 bind port 0 + accept under (local ip localhost:*)" "$work/l1.sb" bind
profile "$work/l2.sb"
listener_row "L2 control: no rule denies the bind" "$work/l2.sb" deny

cat > "$work/two.py" <<'PY'
import socket, time
a, b = socket.socket(), socket.socket()
for s in (a, b):
    s.bind(("127.0.0.1", 0)); s.listen(1)
print(a.getsockname()[1], b.getsockname()[1], flush=True)
time.sleep(60)
PY
group_start "$work/two" "$work" python3 "$work/two.py" >"$work/l-two" 2>/dev/null
two_leader=$leader
until_true 5 sh -c "[ -s '$work/l-two' ]"
read -r p_ok p_other < "$work/l-two"
profile "$work/l3.sb" "(allow network-outbound (remote ip \"localhost:$p_ok\"))"
if /usr/bin/sandbox-exec -f "$work/l3.sb" /bin/bash -c "exec 3<>/dev/tcp/127.0.0.1/$p_ok" 2>"$work/l3.err"
then report PASS "L3 exact-port outbound reaches its port" "localhost:$p_ok"
else report FAIL "L3 exact-port outbound reaches its port" "$(first_line "$work/l3.err")"; fi
if /usr/bin/sandbox-exec -f "$work/l3.sb" /bin/bash -c "exec 3<>/dev/tcp/127.0.0.1/$p_other" 2>"$work/l4.err"
then report FAIL "L4 exact-port outbound denies the neighbor" "connected to $p_other"
elif has_line "$denied" "$work/l4.err"
then report PASS "L4 exact-port outbound denies the neighbor" "denied: $(first_line "$work/l4.err")"
else report FAIL "L4 exact-port outbound denies the neighbor" "failed otherwise: $(first_line "$work/l4.err")"; fi
end_group "$two_leader"

# L5: whether the checked scan can be complete on this host at all: taken once here, idle.
if scan "$work/l5"
then report PASS "L5 the checked scan is complete" "$(wc -l < "$work/l5.seen" | tr -d ' ') processes"
else
    report FAIL "L5 the checked scan is complete" "$(cat "$work/l5.reason")"
    for pid in $(head -5 "$work/l5.missed"); do ps -o pid=,user=,comm= -p "$pid" | sed 's/^/        /'; done
    head -5 "$work/l5.errors" | show_table
fi

# --- S: sbt, per version -------------------------------------------------------------------------

cat > "$work/shutdown.py" <<'PY'
# sbt's local-socket shutdown at a given socket path (SbtServerShutdown, session-recovery.sh M4).
import socket, sys, time, uuid
deadline = time.monotonic() + 120
s = socket.socket(socket.AF_UNIX)
s.settimeout(120)
s.connect(sys.argv[1])
def send(msg):
    body = msg.encode()
    s.sendall(f"Content-Length: {len(body) + 2}\r\n\r\n".encode() + body + b"\r\n")
opts = '{"skipAnalysis":true,"canWork":true,"subscribeToAll":false}'
send('{ "jsonrpc": "2.0", "id": "%s", "method": "initialize",'
     ' "params": { "initializationOptions": %s } }' % (uuid.uuid4(), opts))
try:
    s.recv(4096)
except OSError:
    pass
send('{ "jsonrpc": "2.0", "id": "%s", "method": "sbt/exec",'
     ' "params": { "commandLine": "shutdown" } }' % uuid.uuid4())
try:
    while s.recv(4096) and time.monotonic() < deadline:
        pass
except OSError:
    pass
PY

sbt_rows() { # version
    version=$1
    d=$work/s${version%%.*}
    proj=$d/proj; srv=$d/srv; cmd=$d/cmd; global=$d/global; ivy=$d/ivy
    mkdir -p "$proj/project" "$proj/src/main/scala" "$srv" "$cmd" "$global" "$ivy"
    echo "sbt.version=$version" > "$proj/project/build.properties"
    printf 'fork := true\n' > "$proj/build.sbt"
    cat > "$proj/src/main/scala/Main.scala" <<'SCALA'
object Main {
  def main(args: Array[String]): Unit = {
    println("probe-main")
    Thread.sleep(120000)
  }
}
SCALA
    portfile=$proj/project/target/active.json
    # The server JVM: java with -Dsbt.script, and neither the script that execs it nor the
    # group's leader, whose own arguments carry that same option.
    servers() { with_cwd '^\([^ ]*/\)\{0,1\}java .*-Dsbt\.script=' "$proj"; }
    no_servers() { [ -z "$(servers)" ]; }
    # srv is the owner's directory and the socket budget, tmp the process's own; `-Dsbt.global.base`
    # puts the sbt 2 proc registry where the plan says it goes. The server's file, and a client's.
    sbt_opts() { echo "-Djava.util.prefs.userRoot=$1 -Dsbt.global.base=$global -Dsbt.ivy.home=$ivy"; }
    write_env "$d/env-srv" "$srv" "$srv" "$(sbt_opts "$srv")" "SBT_GLOBAL_SERVER_DIR=$srv"
    write_env "$d/env-cmd" "$cmd" "$srv" "$(sbt_opts "$cmd")" "SBT_GLOBAL_SERVER_DIR=$srv"
    # A client with its own tmp, attaching to the portfile; bounded. Usage: client record log args...
    client() {
        record=$1; log=$2; shift 2
        probe_env=$d/env-cmd
        bounded 300 "$record" "$proj" "$@" >"$log" 2>&1
    }
    client_args="--jvm-client -batch -java-home $JAVA_HOME"

    echo
    echo "S: sbt $version"
    # S1: the owner's command line — NetworkClient.serverCommand's, which the client passes
    # -Dsbt.script to and not -batch — in a group of its own, stdio as the plan says.
    probe_env=$d/env-srv
    group_start "$d/server" "$proj" "$sbt_script" "-Dsbt.script=$sbt_script" --detach-stdio --server \
        >"$d/server-out.log" 2>"$d/server-err.log"
    server_leader=$leader
    started=$(date +%s)
    portfile_or_dead() { [ -f "$portfile" ] || exited "$d/server"; }
    until_true 420 portfile_or_dead
    if [ -f "$portfile" ]; then
        report PASS "S1 owner-started server publishes the portfile" \
            "$(( $(date +%s) - started ))s; $(cat "$portfile")"
    else
        report FAIL "S1 owner-started server publishes the portfile" "$(failed "$d/server" "$d/server-err.log")"
        end_group "$server_leader"
        return
    fi
    server=$(servers | head -1)
    if [ -z "$server" ]; then
        report FAIL "S1 server process found by cwd" "none"
        end_group "$server_leader"
        return
    fi
    server_start=$(lstart_of "$server")
    case "$(cat "$portfile")" in
        *"local://$srv/"*) report PASS "S1 socket under the owner's directory" "$srv" ;;
        *) report FAIL "S1 socket under the owner's directory" "$(cat "$portfile")" ;;
    esac
    socket=$(sed -n 's/.*"uri" *: *"local:\/\/\([^"]*\)".*/\1/p' "$portfile")

    # S2: a client with its own tmp attaches; the server is the same process and there is one.
    # shellcheck disable=SC2086
    if client "$d/about" "$d/client-about.log" "$sbt_script" $client_args about \
        && [ "$(lstart_of "$server")" = "$server_start" ] && [ "$(servers | wc -l | tr -d ' ')" -eq 1 ]
    then
        report PASS "S2 client attaches; same server, no fork" "pid $server"
        if scan "$d/scan-idle" && socket_table "$d/scan-idle" "$server" "$d/sockets-idle"
        then report INFO "S2 idle server's UNIX sockets" \
            "$(named "$d/sockets-idle" "$socket") named by the socket path; $(grep -c -- '->' "$d/sockets-idle") ->"
        else report FAIL "S2 idle server's UNIX sockets" \
            "$(cat "$d/scan-idle.reason" 2>/dev/null || echo "no sockets for pid $server")"; fi
    else report FAIL "S2 client attaches; same server, no fork" \
        "servers: $(servers | tr '\n' ' '); $(failed "$d/about" "$d/client-about.log")"; fi

    # S3: the client's unix-socket rule, the right directory.
    profile "$d/client.sb" "(allow network-outbound (remote unix-socket (subpath \"$srv\")))"
    # shellcheck disable=SC2086
    if client "$d/about-sb" "$d/client-sb.log" /usr/bin/sandbox-exec -f "$d/client.sb" "$sbt_script" $client_args about
    then report PASS "S3 client under (remote unix-socket (subpath owner-tmp))" "attached"
    else report FAIL "S3 client under (remote unix-socket (subpath owner-tmp))" \
        "$(failed "$d/about-sb" "$d/client-sb.log")"; fi

    # S4: a TERMed client mid-run: the exec is cancelled; the forked JVM does what it does.
    probe_env=$d/env-cmd
    # shellcheck disable=SC2086
    group_start "$d/run" "$proj" "$sbt_script" $client_args run >"$d/client-run.log" 2>&1
    run_leader=$leader
    forked() { pgrep -f -- "$proj/target" 2>/dev/null | head -1; }
    if until_true 300 has_line probe-main "$d/client-run.log" && [ -n "$(forked)" ]; then
        forked_pid=$(forked)
        # The idle detector for a confined sbt server (plan 7.3), on the server JVM and never its
        # group leader, and with no baseline, as a broker taking over has none: the clients of the
        # server's path-named sockets, as `peers` finds them. Measured first on the already-busy
        # server, then after the client is gone, then with an unrelated UNIX connection the server
        # itself opened beside a connected client; the tables follow each row.
        detector() { # label table expected-peers: PASS when the live-peer count is the expected one
            if ! scan "$2.scan"
            then report FAIL "$1" "unknown: $(cat "$2.scan.reason")"; return; fi
            if ! socket_table "$2.scan" "$server" "$2"
            then report FAIL "$1" "no sockets for pid $server"; return; fi
            found=$(peers "$2.scan" "$2" "$socket")
            count=$(printf '%s' "$found" | grep -c .)
            found=$(printf '%s' "${found:-none}" | tr '\n' ',')
            detail="$(named "$2" "$socket") named by the socket path; live peers: $found"
            if [ "$count" -eq "$3" ]; then report PASS "$1" "$detail"; else report FAIL "$1" "$detail"; fi
            show_table "$2"
        }
        detector "S4 detector: busy server, no baseline" "$d/sockets-busy" 1
        end_group "$run_leader"
        settled() {
            scan "$d/settle.scan" && socket_table "$d/settle.scan" "$server" "$d/settle" \
                && [ "$(peers "$d/settle.scan" "$d/settle" "$socket" | grep -c .)" -eq 0 ]
        }
        until_true 20 settled
        detector "S4 detector: none after the client is gone" "$d/sockets-after" 0
        if until_true 20 gone "$forked_pid"
        then report INFO "S4 forked JVM after the client's TERM" "ended within 20s: the cancel reached it"
        else
            report INFO "S4 forked JVM after the client's TERM" "alive after 20s; killed"
            kill "$forked_pid" 2>/dev/null
        fi
        # shellcheck disable=SC2086
        if [ "$(lstart_of "$server")" = "$server_start" ] \
            && client "$d/after" "$d/client-after.log" "$sbt_script" $client_args about
        then report PASS "S4 server answers after a cancelled command" "pid $server"
        else report FAIL "S4 server answers after a cancelled command" "$(failed "$d/after" "$d/client-after.log")"; fi
        # The third case: the server holds a UNIX connection that is no client of its own — one
        # its build opened to an unrelated listener — while a client is connected. The candidate
        # counts both; the kept table shows what tells them apart, if anything does.
        group_start "$d/unrelated" "$d" python3 -c 'import socket, sys, time
s = socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); s.listen(1); print("bound", flush=True)
time.sleep(60)' "$d/unrelated.sock" >"$d/unrelated.log" 2>&1
        unrelated_leader=$leader
        # The fixture proves its own setup by its own markers, never by the detector under test:
        # the listener says `bound`, the eval says `probe-connected` once connected, and only then
        # is the table captured — whatever the detector counts in it.
        if ! until_true 5 has_line bound "$d/unrelated.log"; then
            report FAIL "S4 unrelated listener bound" "$(first_line "$d/unrelated.log")"
        else
            evaluate="eval { val c = java.nio.channels.SocketChannel.open(java.net.StandardProtocolFamily.UNIX); \
c.connect(java.net.UnixDomainSocketAddress.of(\"$d/unrelated.sock\")); println(\"probe-connected\"); \
Thread.sleep(20000); c.close(); 0 }"
            probe_env=$d/env-cmd
            # shellcheck disable=SC2086
            group_start "$d/eval" "$proj" "$sbt_script" $client_args "$evaluate" >"$d/client-eval.log" 2>&1
            eval_leader=$leader
            if ! until_true 120 has_line probe-connected "$d/client-eval.log"; then
                report FAIL "S4 the server opened the unrelated connection" \
                    "no probe-connected within 120s: $(first_line "$d/client-eval.log")"
            else
                detector "S4 detector: one client beside an unrelated connection" "$d/sockets-unrelated" 1
            fi
            end_group "$eval_leader"
        fi
        end_group "$unrelated_leader"
    else
        report FAIL "S4 run reaches its forked JVM" "$(failed "$d/run" "$d/client-run.log")"
        end_group "$run_leader"
    fi

    # S5: the proc registry (sbt 2): under the global base, and nowhere under the user's caches.
    ours=$(find "$global" -path '*/proc/*.json' 2>/dev/null | head -3 | tr '\n' ' ')
    theirs=$(find "$HOME/.cache/sbt" "$HOME/Library/Caches/sbt" -path "*/proc/$server.json" 2>/dev/null | tr '\n' ' ')
    case "$version" in
        2.*)
            if [ -n "$ours" ] && [ -z "$theirs" ]
            then report PASS "S5 proc entry under the global base only" "$ours"
            else report FAIL "S5 proc entry under the global base only" \
                "ours: ${ours:-none}; user caches: ${theirs:-none}"; fi ;;
        *) report INFO "S5 proc entries (sbt 1 has no registry)" "ours: ${ours:-none}; user caches: ${theirs:-none}" ;;
    esac

    # S6: the wrong-directory control, last: a client whose connect is denied treats the server
    # as dead — deletes the portfile and starts a server of its own, which the profile denies too
    # — so the row is bounded by its own deadline, the denial is read from its output or from the
    # portfile it replaced, and what it left of the owner's server is measured before the shutdown.
    profile "$d/wrong.sb" "(allow network-outbound (remote unix-socket (subpath \"$cmd\")))"
    before=$(cat "$portfile")
    probe_env=$d/env-cmd
    # shellcheck disable=SC2086
    group_start "$d/wrong" "$proj" /usr/bin/sandbox-exec -f "$d/wrong.sb" "$sbt_script" $client_args about \
        >"$d/client-wrong.log" 2>&1
    wrong_leader=$leader
    # A timeline while it runs, one line per change: the owner's server, the portfile, the socket
    # file, the servers the client spawns, and their stderr file, which the client deletes at
    # its exit, copied while it exists. The order says what ended the owner's server, if
    # anything did.
    timeline() {
        state="server=$(gone "$server" && echo gone || echo alive) portfile=$([ -f "$portfile" ] && echo present \
|| echo absent) socket=$([ -S "$socket" ] && echo present || echo absent) \
servers=$(servers | grep -v "^$server\$" | tr '\n' ',')"
        if [ "$state" != "$last" ]; then
            printf '%s %s\n' "$(( $(date +%s) - started ))s" "$state" >> "$d/timeline"
            last=$state
        fi
        for err in "$cmd"/sbt-server-err*.log; do [ -f "$err" ] && cp "$err" "$d/second-server-err.log"; done
        exited "$d/wrong"
    }
    started=$(date +%s); last=""
    until_true 120 timeline || : > "$d/wrong.timeout"
    end_group "$wrong_leader"
    wrong=$(failed "$d/wrong" "$d/client-wrong.log")
    if [ "$(status_of "$d/wrong")" = 0 ]
    then report FAIL "S6 control: wrong directory is denied" "the client attached"
    elif has_line "$denied" "$d/client-wrong.log"
    then report PASS "S6 control: wrong directory is denied" \
        "$wrong; $(grep -m1 -- "$denied" "$d/client-wrong.log" | cut -c1-60)"
    elif [ "$(cat "$portfile" 2>/dev/null)" != "$before" ]
    then report PASS "S6 control: wrong directory is denied" "$wrong; the client replaced the portfile"
    else report FAIL "S6 control: wrong directory is denied" "failed otherwise: $wrong"; fi
    if [ "$(cat "$portfile" 2>/dev/null)" = "$before" ]
    then report INFO "S6 portfile after the denied client" "kept"
    else report INFO "S6 portfile after the denied client" "changed: $(cat "$portfile" 2>/dev/null || echo deleted)"; fi
    report INFO "S6 socket file after the denied client" "$([ -S "$socket" ] && echo kept || echo gone)"
    if [ "$(lstart_of "$server")" = "$server_start" ]
    then report INFO "S6 server after the denied client" "alive, pid $server"
    else
        report INFO "S6 server after the denied client" \
            "gone, exit $(status_of "$d/server"); servers now: $(servers | tr '\n' ' '); the timeline follows"
        sed 's/^/        /' "$d/timeline"
        tail -5 "$d/server-out.log" "$d/server-err.log" "$d/second-server-err.log" 2>/dev/null | sed 's/^/        /'
    fi

    if ! [ -S "$socket" ]
    then report INFO "S6 protocol shutdown at the recorded socket" "skipped: the socket file is gone"
    elif [ "$(lstart_of "$server")" != "$server_start" ]
    then report INFO "S6 protocol shutdown at the recorded socket" "skipped: the server is gone"
    else
        probe_env=""
        bounded 150 "$d/shutdown" "$proj" python3 "$work/shutdown.py" "$socket" >"$d/shutdown.log" 2>&1
        if [ "$status" -eq 0 ] && until_true 60 no_servers
        then report PASS "S6 protocol shutdown at the recorded socket ends the server" ""
        else report FAIL "S6 protocol shutdown at the recorded socket ends the server" \
            "$(servers | tr '\n' ' ') still here; $(failed "$d/shutdown" "$d/shutdown.log")"; fi
    fi
    end_group "$server_leader"
}

sbt_rows 1.13.0
sbt_rows 2.0.8

# --- M: Mill 1.1.9 -------------------------------------------------------------------------------

echo
echo "M: Mill 1.1.9"
mp=$work/mill
mkdir -p "$mp/app/src" "$mp/tmp"
cp src/probe/mill-fixture/mill "$mp/mill" && chmod +x "$mp/mill"
cat > "$mp/build.mill" <<'MILL'
//| mill-version: 1.1.9
//| mill-jvm-version: system
package build
import mill.*, scalalib.*

object app extends ScalaModule {
  def scalaVersion = "3.8.4"
}

def probeEnv() = Task.Command {
  println("PROBE_ENV=" + Task.env.getOrElse("PROBE_ENV", "unset"))
}
MILL
cat > "$mp/app/src/App.scala" <<'SCALA'
object App {
  def main(args: Array[String]): Unit = {
    println("probe-main")
    Thread.sleep(120000)
  }
}
SCALA
daemons() { with_cwd 'mill.daemon.MillDaemonMain' "$mp/out/mill-daemon"; }
no_daemons() { [ -z "$(daemons)" ]; }
end_daemons() { for pid in $(daemons); do kill "$pid" 2>/dev/null; done; until_true 20 no_daemons; }
# The download folder as the bootstrap derives it (RunOnHostPrereqs.millDownloadDir), resolved
# once here and given to the confined rows the way the wrapper gives it, so provisioning and the
# rows agree on it whatever MILL_FINAL_DOWNLOAD_FOLDER or XDG_CACHE_HOME the host has set.
mill_downloads=${MILL_FINAL_DOWNLOAD_FOLDER:-${XDG_CACHE_HOME:-$HOME/.cache}/mill/download}
export MILL_FINAL_DOWNLOAD_FOLDER="$mill_downloads"
downloads="MILL_FINAL_DOWNLOAD_FOLDER=$mill_downloads"
write_env "$mp/env" "$mp/tmp" "$mp/tmp" "" "$downloads"
write_env "$mp/env-first" "$mp/tmp" "$mp/tmp" "" "$downloads" PROBE_ENV=first
write_env "$mp/env-second" "$mp/tmp" "$mp/tmp" "" "$downloads" PROBE_ENV=second
write_env "$mp/env-timeout" "$mp/tmp" "$mp/tmp" "" "$downloads" MILL_SERVER_TIMEOUT_MILLIS=5000
run_client() { # record log command...: a confined client in the closed environment, bounded
    record=$1; log=$2; shift 2
    probe_env=$mp/env
    bounded 300 "$record" "$mp" "$@" >"$log" 2>&1
}
# The starter: the client of M2 — ./mill until M2 chooses — under the daemon profile, in a group
# of its own, with the given environment file. Sets starter_leader, and daemon to the
# MillDaemonMain in that group, or empty.
start_daemon() { # env-file
    probe_env=$1
    # shellcheck disable=SC2086
    group_start "$mp/starter" "$mp" /usr/bin/sandbox-exec -f "$mp/daemon.sb" ${mill_client:-./mill} version \
        >"$mp/starter.log" 2>&1
    starter_leader=$leader
    if ! until_true 120 exited "$mp/starter"; then
        : > "$mp/starter.timeout"
        report FAIL "starter ./mill version under the daemon profile" "$(failed "$mp/starter" "$mp/starter.log")"
        end_group "$starter_leader"
    fi
    daemon=$(ps -eo pid=,pgid=,command= |
        awk -v g="$starter_leader" '$2 == g && /MillDaemonMain/ { print $1 }' | head -1)
}
profile "$mp/daemon.sb" '(allow network-bind network-inbound (local ip "localhost:*"))'

# Provisioning, unconfined but in a group of its own that ends with it, daemon included: the
# executable, the daemon classpath memo, the compiler.
echo "provisioning mill 1.1.9 and its compiler, unconfined (can take a few minutes)"
probe_env=""
if ! bounded 900 "$mp/provision" "$mp" ./mill app.compile >"$mp/provision.log" 2>&1; then
    report FAIL "M0 unconfined ./mill app.compile" \
        "$(failed "$mp/provision" "$mp/provision.log"); the log's tail follows"
    tail -8 "$mp/provision.log" | sed 's/^/        /'
    end_daemons
else
    end_daemons
    # The JVM launcher too — `-jvm` makes the bootstrap fetch mill-dist's executable assembly,
    # run by the PATH's java — for the M2 candidate that needs it.
    bounded 600 "$mp/provision-jvm" "$mp" /usr/bin/env MILL_VERSION=1.1.9-jvm ./mill version \
        >"$mp/provision-jvm.log" 2>&1 \
        || report INFO "M0 unconfined JVM launcher" "$(failed "$mp/provision-jvm" "$mp/provision-jvm.log")"
    end_daemons

    # M1: the starter's connect is denied; the daemon stays, in the starter's group.
    start_daemon "$mp/env"
    if [ -n "$daemon" ] && ! gone "$daemon" && has_line "$denied" "$mp/starter.log"; then
        report PASS "M1 daemon survives the starter's denied connect" \
            "starter exit $(status_of "$mp/starter"); daemon pid $daemon in group $starter_leader"
    else
        report FAIL "M1 daemon survives the starter's denied connect" \
            "daemon: ${daemon:-none}; denial in log: $(has_line "$denied" "$mp/starter.log" && echo yes || echo no); \
$(failed "$mp/starter" "$mp/starter.log")"
    fi
    port=$(listen_ports "${daemon:-0}" | head -1)
    ports=$(listen_ports "${daemon:-0}" | wc -l | tr -d ' ')
    filed=$(cat "$mp/out/mill-daemon/socketPort" 2>/dev/null)
    if [ -n "$port" ] && [ "$ports" -eq 1 ]
    then report PASS "M1 one listening port from lsof" "port $port; socketPort file says ${filed:-nothing}"
    else report FAIL "M1 one listening port from lsof" "ports: $(listen_ports "${daemon:-0}" | tr '\n' ' ')"; fi
    idle=$(lsof -a -p "${daemon:-0}" -iTCP -sTCP:ESTABLISHED -nP 2>/dev/null | grep -c ":${port:-0}")
    if [ -n "$port" ] && [ "$idle" -eq 0 ]
    then report PASS "M1 an idle daemon has no established connection" "port $port"
    else report FAIL "M1 an idle daemon has no established connection" "$idle on port ${port:-none}"; fi

    if [ -n "$port" ]; then
        profile "$mp/client.sb" "(allow network-outbound (remote ip \"localhost:$port\"))"
        profile "$mp/neighbor.sb" "(allow network-outbound (remote ip \"localhost:$((port + 1))\"))"
        # M2: a client confined to the daemon's port. The native launcher is a GraalVM image: it
        # takes no JAVA_TOOL_OPTIONS, so the environment's preferIPv4Stack never reaches it and its
        # connect is dual-stack, v4-mapped, which the "localhost" class denies (run-on-host.md
        # "Network"). Three candidates, in order; the first that runs is the client of the rows
        # after: the native launcher as is, the property on its command line for the image's
        # runtime to consume, and the JVM launcher, which takes the environment's options.
        mill_client=""
        for candidate in "./mill" \
            "./mill -Djava.net.preferIPv4Stack=true" \
            "/usr/bin/env MILL_VERSION=1.1.9-jvm ./mill"
        do
            attempt=$((${attempt:-0} + 1))
            # shellcheck disable=SC2086
            if run_client "$mp/m2-$attempt" "$mp/m2-$attempt.log" \
                /usr/bin/sandbox-exec -f "$mp/client.sb" $candidate version && ! gone "$daemon"
            then
                report PASS "M2 exact-port client: $candidate" "$(tail -1 "$mp/m2-$attempt.log" | cut -c1-40)"
                mill_client=$candidate
                break
            else report INFO "M2 exact-port client: $candidate" "$(failed "$mp/m2-$attempt" "$mp/m2-$attempt.log")"; fi
        done
        if [ -z "$mill_client" ]; then
            report FAIL "M2 a client under the exact-port rule runs a command" "no candidate did"
            mill_client="./mill"
        fi
        # M3: the neighbor's port: denied by the OS, bounded by the launcher's retry, daemon untouched.
        # shellcheck disable=SC2086
        if run_client "$mp/m3" "$mp/m3.log" /usr/bin/sandbox-exec -f "$mp/neighbor.sb" $mill_client version
        then report FAIL "M3 client under the neighbor's port is denied" "the command ran"
        elif [ "$status" -eq 124 ] || ! has_line "$denied" "$mp/m3.log"
        then report FAIL "M3 client under the neighbor's port is denied" \
            "failed otherwise: $(failed "$mp/m3" "$mp/m3.log")"
        elif ! gone "$daemon"
        then report PASS "M3 client under the neighbor's port is denied" "$denied; daemon $daemon still alive"
        else report FAIL "M3 client under the neighbor's port is denied" "denied, but the daemon is gone"; fi
        # M4: each command's environment reaches the build (Task.env).
        probe_env=$mp/env-first
        # shellcheck disable=SC2086
        bounded 300 "$mp/m4a" "$mp" /usr/bin/sandbox-exec -f "$mp/client.sb" $mill_client probeEnv >"$mp/m4a.log" 2>&1
        a_status=$status
        probe_env=$mp/env-second
        # shellcheck disable=SC2086
        bounded 300 "$mp/m4b" "$mp" /usr/bin/sandbox-exec -f "$mp/client.sb" $mill_client probeEnv >"$mp/m4b.log" 2>&1
        if [ "$a_status" -eq 0 ] && [ "$status" -eq 0 ] \
            && has_line PROBE_ENV=first "$mp/m4a.log" && has_line PROBE_ENV=second "$mp/m4b.log"
        then report PASS "M4 each command's environment reaches the build" "Task.env"
        else
            found=$(grep -h PROBE_ENV "$mp/m4a.log" "$mp/m4b.log" 2>/dev/null | head -2 | tr '\n' ' ')
            report FAIL "M4 each command's environment reaches the build" \
                "${found}a: $(failed "$mp/m4a" "$mp/m4a.log"); b: $(failed "$mp/m4b" "$mp/m4b.log")"
        fi
        # M5: a TERMed client mid-command: Server.scala says the daemon shuts itself down.
        probe_env=$mp/env
        # shellcheck disable=SC2086
        group_start "$mp/m5" "$mp" /usr/bin/sandbox-exec -f "$mp/client.sb" $mill_client app.run >"$mp/m5.log" 2>&1
        run_leader=$leader
        if until_true 180 has_line probe-main "$mp/m5.log"; then
            # The idle observation the broker's foreign-daemon rule rests on (plan 7.3): a running
            # command is an established connection on the daemon's port, and none once it ends.
            busy=$(lsof -a -p "$daemon" -iTCP -sTCP:ESTABLISHED -nP 2>/dev/null | grep -c ":$port")
            if [ "$busy" -gt 0 ]
            then report PASS "M5 a running command is an established connection" "$busy on port $port"
            else report FAIL "M5 a running command is an established connection" "none on port $port"; fi
            end_group "$run_leader"
            if until_true 30 gone "$daemon"
            then report INFO "M5 daemon after a client TERMed mid-command" "gone within 30s, as Server.scala says"
            else report INFO "M5 daemon after a client TERMed mid-command" "still alive after 30s"; fi
            forked=$(pgrep -f -- "$mp/out/app" 2>/dev/null | head -1)
            if [ -n "$forked" ]
            then report INFO "M5 forked run JVM after the TERM" "alive ($forked); killed"; kill "$forked" 2>/dev/null
            else report INFO "M5 forked run JVM after the TERM" "gone"; fi
        else
            report FAIL "M5 app.run reaches its forked JVM" "$(failed "$mp/m5" "$mp/m5.log")"
            end_group "$run_leader"
        fi
        end_daemons
    fi
    end_group "$starter_leader"

    # M6: the accept timeout, set through the starter's environment. Mill starts its idle clock
    # at a client's disconnect (Server.ConnectionTracker), never at the daemon's start, so one
    # exact-port client runs first; a daemon nobody connected to would never expire.
    start_daemon "$mp/env-timeout"
    if [ -n "$daemon" ] && ! gone "$daemon"; then
        report PASS "M6 daemon survives the denied connect of ${mill_client:-./mill}" "daemon pid $daemon"
        port6=$(listen_ports "$daemon" | head -1)
        profile "$mp/client6.sb" "(allow network-outbound (remote ip \"localhost:${port6:-0}\"))"
        # shellcheck disable=SC2086
        run_client "$mp/m6" "$mp/m6.log" /usr/bin/sandbox-exec -f "$mp/client6.sb" ${mill_client:-./mill} version \
            || report FAIL "M6 a client connects before the timeout is measured" "$(failed "$mp/m6" "$mp/m6.log")"
        started=$(date +%s)
        if until_true 40 gone "$daemon"
        then report PASS "M6 daemon exits after MILL_SERVER_TIMEOUT_MILLIS idle" \
            "$(( $(date +%s) - started ))s after the starter, ${mill_client:-./mill}"
        else
            report FAIL "M6 daemon exits after MILL_SERVER_TIMEOUT_MILLIS idle" "alive after 40s; killed"
            kill "$daemon"
        fi
    else
        report FAIL "M6 daemon started for the timeout row" "daemon: none; $(failed "$mp/starter" "$mp/starter.log")"
    fi
    end_daemons
    end_group "$starter_leader"

    # M7: a foreign daemon whose fingerprint differs (a JAVA_OPTS the closed environment lacks),
    # kept alive in its own group, then the starter: ServerLauncher removes the foreign processId
    # on the mismatch before it probes the lock — the window the plan's 7.2 step 0 leaves open.
    probe_env=""
    group_start "$mp/foreign" "$mp" env JAVA_OPTS=-Dprobe.foreign=1 ./mill version >"$mp/m7-foreign.log" 2>&1
    foreign_leader=$leader
    if ! until_true 300 exited "$mp/foreign"; then
        : > "$mp/foreign.timeout"
        report FAIL "M7 unconfined ./mill leaves a daemon" "$(failed "$mp/foreign" "$mp/m7-foreign.log")"
    elif foreign=$(daemons | head -1) && [ -n "$foreign" ]; then
        start_daemon "$mp/env"
        if gone "$foreign"
        then report INFO "M7 foreign daemon after the starter's fingerprint mismatch" \
            "ended by the starter (ServerLauncher); ours: ${daemon:-none}"
        else report INFO "M7 foreign daemon after the starter's fingerprint mismatch" \
            "alive; starter exit $(status_of "$mp/starter"); ours: ${daemon:-none}"; fi
        end_group "$starter_leader"
    else
        report FAIL "M7 unconfined ./mill leaves a daemon" "$(failed "$mp/foreign" "$mp/m7-foreign.log")"
    fi
    end_group "$foreign_leader"
    end_daemons
fi

echo
echo "PASS $pass  FAIL $fail"
[ "$fail" -eq 0 ]
