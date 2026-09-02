#!/bin/sh
# Which SBPL spelling admits a TCP connect to the loopback proxy port — measured with must-fail
# controls, the answers SeatbeltProfile's proxy rule encodes.
#
# Run it on the Mac, on each new macOS release: the spelling and its controls are SBPL behavior
# a release can change. ~10 seconds.
set -u
port=45071
python3 - "$port" <<'PY' &
import socket, sys, time
s = socket.socket()
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(5)
time.sleep(30)
PY
listener=$!
sleep 1

try() { # label rule
    cat > /tmp/loopback-rule.sb <<EOF
(version 1)
(deny default)
(allow process-exec* (subpath "/"))
(allow file-read* (subpath "/"))
$2
EOF
    if /usr/bin/sandbox-exec -f /tmp/loopback-rule.sb \
        /bin/bash -c "exec 3<>/dev/tcp/127.0.0.1/$port" 2>/tmp/loopback-rule.err
    then printf 'CONNECTS  %s\n' "$1"
    else printf 'denied    %-46s %s\n' "$1" "$(head -1 /tmp/loopback-rule.err | cut -c1-60)"; fi
}

try "no rule (control: must stay denied)" ""
try '(remote tcp "localhost:PORT")' "(allow network-outbound (remote tcp \"localhost:$port\"))"
try '(remote ip "localhost:PORT")' "(allow network-outbound (remote ip \"localhost:$port\"))"
try '(remote tcp "127.0.0.1:PORT")' "(allow network-outbound (remote tcp \"127.0.0.1:$port\"))"
try '(remote ip "127.0.0.1:PORT")' "(allow network-outbound (remote ip \"127.0.0.1:$port\"))"
try '(remote ip "*:PORT")' "(allow network-outbound (remote ip \"*:$port\"))"
try 'wrong port (control: must stay denied)' '(allow network-outbound (remote tcp "localhost:1"))'

kill "$listener" 2>/dev/null
