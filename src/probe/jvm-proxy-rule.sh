#!/bin/sh
# Measures whether a JVM under the generated profile reaches the build proxy through the standard proxy properties.
# Three rows separate the failures that the run-on-host checks cannot tell apart:
# - with the properties and a live proxy, the JVM must fetch;
# - without the properties, the profile must deny the direct path;
# - with the properties and no proxy, connect must fail with "connection refused", which proves that the profile
#   allows the port and that nothing listened.
# A fourth row adds java.net.preferIPv4Stack; its comment below gives the reason.
#
#   sh src/probe/jvm-proxy-rule.sh <the sbt.sb that SeatbeltCheck emits>
#
# SeatbeltCheck emits it into src/test/run-on-host/out-macos/seatbelt/emitted/.
#
# The emitted profile grants port 51234 (EmitRunOnHostProfile's constant), so the script binds the proxy there.
# Run the script on macOS from the repository root on each new macOS or JDK release, because either release can change
# the JVM's path to the proxy under the profile.
set -u
profile=${1:?usage: sh src/probe/jvm-proxy-rule.sh <sbt.sb>}
[ -f "$profile" ] || { echo "$profile does not exist" >&2; exit 2; }
JAVA="${JAVA_HOME:?JAVA_HOME must name the granted JDK}/bin/java"

# Work under the workspace, not /tmp: the profile grants reads here, and the JVM must read F.java through the
# profile. The java launcher silently treats an unreadable source path as a class name.
mkdir -p target/jvm-proxy-rule && work=$(mktemp -d target/jvm-proxy-rule/run.XXXXXX)
cat > "$work/F.java" <<'EOF'
public class F {
    public static void main(String[] args) throws Exception {
        var in = new java.net.URL("https://repo1.maven.org/maven2/").openStream();
        System.out.println("fetched " + in.readAllBytes().length + " bytes");
    }
}
EOF

dist=ko-agent-egress-proxy/app/target/dist/ko-agent-egress-proxy.jar
proxy_src=ko-agent-egress-proxy/app/src/main/scala/AgentEgressProxy.scala
if [ ! -f "$dist" ] || [ "$proxy_src" -nt "$dist" ]; then
    echo "building the proxy dist (sources are newer)"
    ( cd ko-agent-egress-proxy/app && sbt dist ) >/tmp/jvm-proxy-dist.log 2>&1 \
        || { echo "proxy dist build failed:"; tail -20 /tmp/jvm-proxy-dist.log; exit 1; }
fi

proxy_pid=""
cleanup() { [ -n "$proxy_pid" ] && kill "$proxy_pid" 2>/dev/null; rm -rf "$work"; }
trap cleanup EXIT INT TERM

EGRESS_PROFILE=deny-unless-allowed EGRESS_RULE='deny defaults
allow https://repo1.maven.org/ read' EGRESS_BIND=127.0.0.1:51234 "$JAVA" -jar "$dist" 2>"$work/proxy.log" &
proxy_pid=$!
tries=0
until grep -q 'listening on :51234' "$work/proxy.log" 2>/dev/null; do
    tries=$((tries + 1))
    [ "$tries" -gt 30 ] && { echo "proxy did not start:"; cat "$work/proxy.log"; exit 1; }
    sleep 0.5
done

row() { # label java-args...
    label=$1; shift
    if /usr/bin/sandbox-exec -f "$profile" "$JAVA" "$@" "$work/F.java" >"$work/row.log" 2>&1
    then printf '%-44s %s\n' "$label" "$(tail -1 "$work/row.log")"
    else printf '%-44s FAILED: %s\n' "$label" \
        "$(grep -m1 -E 'Exception|Error' "$work/row.log" | cut -c1-100)"; fi
}

row "with props, proxy live (must fetch)" \
    -Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=51234
# Java connects through dual-stack AF_INET6 sockets and reaches 127.0.0.1 as the v4-mapped ::ffff:127.0.0.1. If
# the "localhost" class covers only native 127.0.0.1 and ::1, this row passes where the row above fails.
row "with props and preferIPv4Stack" \
    -Djava.net.preferIPv4Stack=true -Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=51234
row "no props (control: direct must be denied)"
kill "$proxy_pid" 2>/dev/null; wait "$proxy_pid" 2>/dev/null; proxy_pid=""
row "with props, proxy stopped (must be refused)" \
    -Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=51234
grep -c 'allow repo1.maven.org CONNECT' "$work/proxy.log" | sed 's/^/proxy CONNECTs seen: /'
