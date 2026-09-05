#!/bin/sh
# What the wrapper's orphan recovery and proxy hosting assume, measured before the wrapper encodes
# them. Five measurements:
#
#   M1  the egress proxy runs on macOS from its dist jars, admits repo1.maven.org through a
#       replacement rules (deny defaults plus one read line), refuses everything else, and binds where the
#       codebase says — wildcard :3128, the fact the wrapper's bind option exists to change
#   M2  a local-mode sbt server's portfile carries no token
#   M3  the sbt server stays in the client's process group after the client exits
#   M4  the tokenless initialize + sbt/exec shutdown handshake, sent to the socket's pathname
#       after its directory is renamed, ends the server
#   M5  the server's socket is <serverDir>/<half-sha1 of the portfile path's file:// URI>/sock —
#       the derivation the wrapper's auto-shutdown sends to (RunOnHostSandbox.sbtServerSocket).
#       It runs after M2 in the script, because M4 ends the server and takes the portfile with it
#
# Run it on the Mac, from this repository's root, when sbt or the proxy changes. It builds the
# proxy dist if absent, boots one sbt 2.0.7 server in a scratch project under /private/tmp, and
# ends what it started; on a FAIL it keeps the scratch tree and names it.

set -u

if [ "$(uname -s)" != "Darwin" ]; then
    echo "This probe measures a macOS host; this is $(uname -s). Run it on the Mac." >&2
    exit 2
fi
if [ -n "${KO_AGENT_SANDBOX_EGRESS_RULESET:-}" ] || [ -d /etc/ko-agent-sandbox ]; then
    echo "This looks like a sandbox session. Run the probe in a host terminal instead." >&2
    exit 2
fi
if [ ! -f container/ko-agent-egress-proxy/app/build.sbt ]; then
    echo "Run from the repository root; container/ko-agent-egress-proxy/app is not here." >&2
    exit 2
fi

pass=0; fail=0
report() { # PASS|FAIL label detail
    printf '%-4s  %-52s  %s\n' "$1" "$2" "$3"
    case "$1" in PASS) pass=$((pass + 1)) ;; FAIL) fail=$((fail + 1)) ;; esac
}

JAVA="$(cs java-home 2>/dev/null)/bin/java"
[ -x "$JAVA" ] || JAVA=java

work=$(mktemp -d /private/tmp/ko-probe.XXXXXX)   # short: the boot socket path budget is 53
proxy_pid=""
leader=""
cleanup() {
    [ -n "$proxy_pid" ] && kill "$proxy_pid" 2>/dev/null
    # End every process still in the probe's group — the orphan class this probe exists to end.
    [ -n "$leader" ] && kill -TERM -- "-$leader" 2>/dev/null
    if [ "$fail" -eq 0 ]; then rm -rf "$work"; else echo "kept for inspection: $work"; fi
}
trap cleanup EXIT INT TERM

# --- M1: the proxy, hosted on macOS ------------------------------------------------------------

dist=container/ko-agent-egress-proxy/app/target/dist/agent-egress-proxy.jar
proxy_src=container/ko-agent-egress-proxy/app/src/main/scala/AgentEgressProxy.scala
if [ ! -f "$dist" ] || [ "$proxy_src" -nt "$dist" ]; then
    echo "building the proxy dist (absent or older than its source)"
    ( cd container/ko-agent-egress-proxy/app && sbt dist ) >"$work/dist.log" 2>&1 \
        || { echo "proxy dist build failed:"; tail -20 "$work/dist.log"; exit 1; }
fi

if lsof -nP -iTCP:3128 -sTCP:LISTEN >/dev/null 2>&1; then
    report FAIL "M1 port 3128 free before start" "something already listens; stop it and re-run"
else
    EGRESS_PROFILE=deny-unless-allowed EGRESS_RULE='deny defaults
allow https://repo1.maven.org/ read' "$JAVA" -jar "$dist" 2>"$work/proxy.log" &
    proxy_pid=$!
    tries=0; m1_ready=1
    until grep -q 'agent-egress-proxy listening' "$work/proxy.log" 2>/dev/null; do
        tries=$((tries + 1))
        if [ "$tries" -gt 30 ] || ! kill -0 "$proxy_pid" 2>/dev/null; then
            report FAIL "M1 proxy starts on macOS" "no ready line; log tail follows"
            tail -5 "$work/proxy.log"
            m1_ready=0
            break
        fi
        sleep 0.5
    done
    if [ "$m1_ready" -eq 1 ]; then
        report PASS "M1 proxy starts on macOS" "$(grep 'listening' "$work/proxy.log" | head -1)"
        report INFO "M1 bound address (expect wildcard :3128)" \
            "$(lsof -nP -a -p "$proxy_pid" -iTCP -sTCP:LISTEN 2>/dev/null | tail -1)"
        code=$(curl -sS -x http://127.0.0.1:3128 -o /dev/null -w '%{http_code}' \
            https://repo1.maven.org/maven2/ 2>"$work/curl-allow.err") \
            && [ "$code" = 200 ] \
            && report PASS "M1 repo1.maven.org through replacement rules" "HTTP $code" \
            || report FAIL "M1 repo1.maven.org through replacement rules" \
                "code=${code:-none} $(head -1 "$work/curl-allow.err" 2>/dev/null)"
        if curl -sS -m 10 -x http://127.0.0.1:3128 -o /dev/null \
            https://example.com/ 2>"$work/curl-deny.err"; then
            report FAIL "M1 unlisted host refused" "example.com connected"
        else
            report PASS "M1 unlisted host refused" \
                "$(grep 'deny.*example.com' "$work/proxy.log" | head -1 || head -1 "$work/curl-deny.err")"
        fi
        kill "$proxy_pid" 2>/dev/null; wait "$proxy_pid" 2>/dev/null; proxy_pid=""
    fi
fi

# --- one sbt 2.0.7 server in a scratch project, its state under probe-owned directories --------

mkdir -p "$work/proj/project" "$work/srv"
echo "sbt.version=2.0.7" > "$work/proj/project/build.properties"
: > "$work/proj/build.sbt"

echo "booting a scratch sbt server (can take a minute)"
( cd "$work/proj" && SBT_GLOBAL_SERVER_DIR="$work/srv" XDG_RUNTIME_DIR="$work/srv" \
    exec perl -e 'setpgrp(0, 0); exec @ARGV or die $!' sbt --jvm-client -batch about \
) >"$work/client.log" 2>&1 &
leader=$!
wait "$leader" 2>/dev/null \
    || { report FAIL "scratch client run" "exit $?; log tail follows"; tail -10 "$work/client.log"; exit 1; }

# --- M2: the local portfile carries no token ---------------------------------------------------

portfile="$work/proj/project/target/active.json"
if [ ! -f "$portfile" ]; then
    report FAIL "M2 portfile exists after the client run" "$portfile missing"
    exit 1
fi
if grep -q 'token' "$portfile"; then
    report FAIL "M2 local portfile carries no token" "$(cat "$portfile")"
else
    report PASS "M2 local portfile carries no token" "$(cat "$portfile")"
fi

# --- M5: the server socket derives from the portfile path's URI (before M4 ends the server) ----

derived=$(python3 - "$portfile" "$work/srv" <<'PY'
import hashlib, sys
portfile, srv = sys.argv[1:3]
uri = "file://" + portfile   # java Path.toUri spelling for an absolute file: file:///private/...
print(f"{srv}/{hashlib.sha1(uri.encode()).hexdigest()[:20]}/sock")
PY
)
actual=$(python3 -c \
    'import json,sys; print(json.load(open(sys.argv[1]))["uri"].removeprefix("local://"))' \
    "$portfile")
if [ "$derived" = "$actual" ]; then
    report PASS "M5 socket derives from the portfile URI" "$actual"
else
    report FAIL "M5 socket derives from the portfile URI" "derived $derived, portfile $actual"
fi

# --- M3: the server survives in the client's process group -------------------------------------

survivors=$(ps -eo pid,pgid,command | awk -v g="$leader" '$2 == g { print $1 }')
if [ -n "$survivors" ]; then
    report PASS "M3 server in the dead client's group" "pgid $leader, pids: $(echo $survivors)"
    ps -eo pid,pgid,lstart,command | awk -v g="$leader" '$2 == g' | cut -c1-110
else
    report FAIL "M3 server in the dead client's group" "group $leader is empty after client exit"
    exit 1
fi

# --- M4: rename the server directory, shut down through the moved socket -----------------------

mv "$work/srv" "$work/gone"
python3 - "$portfile" "$work/srv" "$work/gone" <<'PY'
import json, socket, sys, time, uuid

portfile, old, new = sys.argv[1:4]
port = json.load(open(portfile))
path = port["uri"].removeprefix("local://")
moved = new + path.removeprefix(old) if path.startswith(old) else path
print(f"socket (moved): {moved}")

s = socket.socket(socket.AF_UNIX)
s.settimeout(10)
s.connect(moved)

def send(msg):
    body = msg.encode()
    s.sendall(f"Content-Length: {len(body) + 2}\r\n\r\n".encode() + body + b"\r\n")

def read_frame():
    def take(n):
        chunk = s.recv(n)
        if not chunk:
            raise ConnectionError("server closed the socket")
        return chunk
    data = b""
    while b"\r\n\r\n" not in data:
        data += take(1)
    length = int(data.split(b"Content-Length:")[1].split(b"\r\n")[0])
    body = b""
    while len(body) < length:
        body += take(length - len(body))
    return body.decode(errors="replace")

opts = '{"skipAnalysis":true,"canWork":true,"subscribeToAll":false}'
send('{ "jsonrpc": "2.0", "id": "%s", "method": "initialize",'
     ' "params": { "initializationOptions": %s } }' % (uuid.uuid4(), opts))
try:
    print(f"init response: {read_frame()[:200]}")
except OSError:
    print("init response: none within 10s (continuing)")
send('{ "jsonrpc": "2.0", "id": "%s", "method": "sbt/exec",'
     ' "params": { "commandLine": "shutdown" } }' % uuid.uuid4())
try:
    while True:
        print(f"then: {read_frame()[:200]}")
except OSError:
    pass
PY

deadline=60
while [ "$deadline" -gt 0 ]; do
    still=$(ps -eo pgid | awk -v g="$leader" '$1 == g' | head -1)
    [ -z "$still" ] && break
    sleep 1; deadline=$((deadline - 1))
done
if [ -z "$(ps -eo pgid | awk -v g="$leader" '$1 == g' | head -1)" ]; then
    report PASS "M4 shutdown at the moved socket ends the server" "group $leader empty"
    leader=""
else
    report FAIL "M4 shutdown at the moved socket ends the server" \
        "group $leader still has members after 60s; they will be TERMed on exit"
fi

echo
echo "PASS $pass  FAIL $fail"
[ "$fail" -eq 0 ]
