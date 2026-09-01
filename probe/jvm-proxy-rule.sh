#!/bin/sh
# Does a JVM under the generated profile reach the build proxy through the standard proxy
# properties? Three rows split the failure the gate cannot: with props and a live proxy (must
# fetch), without props (must be denied — the direct path), with props and no proxy (must be
# refused by connect, proving the profile admits the port and nothing listened).
#
#   sh probe/jvm-proxy-rule.sh <emitted gate-sbt.sb from a gate run>
#
# The emitted profile grants port 51234 (EmitBuildProfile's constant), so the proxy is bound
# there. Run it on the Mac from the repository root, on each new macOS or JDK release: the JVM's
# path to the proxy under the profile is what either can move.
set -u
profile=${1:?usage: sh probe/jvm-proxy-rule.sh <gate-sbt.sb>}
[ -f "$profile" ] || { echo "$profile does not exist" >&2; exit 2; }
JAVA="${JAVA_HOME:?JAVA_HOME must name the granted JDK}/bin/java"

# Under the project, not /tmp: the profile grants reads here, and the JVM must read F.java
# through it (an unreadable path silently degrades to class-name interpretation).
mkdir -p target/gate && work=$(mktemp -d target/gate/jvm-proxy.XXXXXX)
cat > "$work/F.java" <<'EOF'
public class F {
    public static void main(String[] args) throws Exception {
        var in = new java.net.URL("https://repo1.maven.org/maven2/").openStream();
        System.out.println("fetched " + in.readAllBytes().length + " bytes");
    }
}
EOF

dist=container/ko-agent-egress-proxy/app/target/dist/agent-egress-proxy.jar
proxy_src=container/ko-agent-egress-proxy/app/src/main/scala/AgentEgressProxy.scala
if [ ! -f "$dist" ] || [ "$proxy_src" -nt "$dist" ]; then
    echo "building the proxy dist (sources are newer)"
    ( cd container/ko-agent-egress-proxy/app && sbt dist ) >/tmp/jvm-proxy-dist.log 2>&1 \
        || { echo "proxy dist build failed:"; tail -20 /tmp/jvm-proxy-dist.log; exit 1; }
fi

proxy_pid=""
cleanup() { [ -n "$proxy_pid" ] && kill "$proxy_pid" 2>/dev/null; rm -rf "$work"; }
trap cleanup EXIT INT TERM

EGRESS_PROFILE=deny-unless-allowed EGRESS_ALLOWED='-**
+host repo1.maven.org' EGRESS_BIND=127.0.0.1:51234 "$JAVA" -jar "$dist" 2>"$work/proxy.log" &
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
# Java connects through dual-stack AF_INET6 sockets, reaching 127.0.0.1 as v4-mapped
# ::ffff:127.0.0.1; if the "localhost" class covers only native 127.0.0.1 and ::1, this row
# passes where the one above fails.
row "with props and preferIPv4Stack" \
    -Djava.net.preferIPv4Stack=true -Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=51234
row "no props (control: direct must be denied)"
kill "$proxy_pid" 2>/dev/null; wait "$proxy_pid" 2>/dev/null; proxy_pid=""
row "with props, proxy stopped (must be refused)" \
    -Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=51234
grep -c 'allow repo1.maven.org CONNECT' "$work/proxy.log" | sed 's/^/proxy CONNECTs seen: /'
