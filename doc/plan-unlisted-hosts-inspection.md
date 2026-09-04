# Plan: inspected reads for the hosts no line names, under `allow-unless-denied`

## Outcome

Under `allow-unless-denied` a host no line names is inspected and `read`: `GET` and `HEAD`
without a body, every request in the audit log, every write refused with the reason and the next
step. The opaque tunnel becomes what a line grants — the defaults' model-provider groups, and a
project's own `tunnel` line — and nothing a request can reach by naming a host nobody wrote down.

Today that host is an opaque, writable, unlogged tunnel: the profile admits every public host
and, for each of them outside the narrowing set, gives up the two things inspection buys, the
refusal of writes and the record of what was asked. Those are the exfiltration channel
the design exists to close (SECURITY.md, "Exfiltration through an allowed host"). After this plan
the profile's remaining channel is the one every inspected host has, the URL of a permitted read.

The profile keeps its name: the names sit on the admission axis — whether a host can be reached —
and every public host is still allowed unless a line denies it. What moves is its treatment.

## The trade, stated first

Inspecting a host means presenting a leaf certificate that names it, and a host nobody listed has
no name in the leaf the launcher minted at launch. So the proxy must mint leaves as hosts are first
seen, and minting needs a CA key inside the proxy container — the one thing SECURITY.md, "Who
holds the CA key", rules out, because the proxy is the process facing the internet, and under this
profile it faces all of it.

The condition that makes the trade acceptable: the key is a **CA minted for the run**, trusted by
that session alone, written under the run's TLS directory and pruned with it. The project CA never
enters the container, so nothing a compromised proxy could mint outlives the run or is honoured by
another session. What such a compromise gains during the run is precise: a leaf for a tunnel host,
so the sandbox's model traffic and provider tokens could be read — the thing no other profile
allows. Set against it is what every unlisted host loses: writes, and silence. The proxy is a
memory-safe program with no query surface (design.md, "No HTTP query surface on the proxy"), and a
compromise of it is the class SECURITY.md already places at the edge under "Container, runtime and
kernel escape"; the run scope is defence in depth against that class, bought because it costs one
keypair per launch.

## Semantics after the change

1. **Admission** is unchanged: every public hostname on port 443, minus the `deny` lines — a
   whole-host deny, a `**.domain` pattern, a provider group — with the denial patterns kept as
   patterns and matched at `CONNECT` time, as now.
1. **Treatment.** A host with a resolved scope has the treatment its lines give it. Every other
   admitted host is inspected with the root scope `read`, nothing else: no `git-fetch` (a clone
   from an unlisted forge fails at its first request, and the project writes the line), no
   `method=`.
1. **Every line is consulted.** Today `deny defaults` and a `tunnel` allow are skipped because
   neither could narrow while every unlisted host is a tunnel. Once it is a `read`, both matter:
   `tunnel` is
   how a project says a host must stay opaque — an API that writes, WebSockets, HTTP/2, a pinned
   certificate — and `deny defaults` turns the defaults' tunnels into unlisted-host reads, the
   lockdown `deny defaults` + `allow model-provider anthropic` meaning under this profile
   "everything readable, one provider opaque". The resolver's one special case for the profile
   (`PolicyHelper.scala`, `defaultsGiveWay`: the defaults' tunnel giving way to a project's
   inspecting line where `deny defaults` was not consulted) has no reason left and is removed.
1. **The resolved policy** lists the tunnel hosts, which it drops today as pointless while
   every unlisted host is a tunnel: they are now the exception set, in the digest and printed as
   `allow … tunnel` lines after the denial patterns. The profile line reads
   `egress profile: allow-unless-denied; default: public HTTPS read`.
1. **The two identity checks** stay and gain a third. The static leaf must name exactly the
   inspected hosts the policy resolved, as now. The run CA key must be present exactly when the
   profile is this one: absent under it, or present under any other, the proxy refuses to start.
1. **Clients** that need HTTP/2, WebSockets or a pinned certificate on an unlisted host fail the
   handshake or the upgrade, as they do on a catalog host today, until the project's `tunnel`
   line names the host. Claude Code's WebFetch, package managers and registry pulls are reads.

## Trust material

The launcher, under this profile only, at each launch:

- mints a run CA (`BouncyCastleHelper.mintCa`, the run suffix in its name, validity the launch
  bound plus a margin, never the project CA's years), into the run directory
  `tls/<project>/run-<suffix>/`, private permissions, pruned with the run's other copies;
- signs the static leaf for the inspected set with it, per run, in place of the cached
  `leaf.crt` the project CA signs — the cache is keyed to the project CA and does not apply;
- assembles the sandbox's bundle and the JDK store from the image's roots plus the run CA, in
  place of the project CA, so the session trusts the run's signer and nothing the project CA
  signed;
- mounts `ca.crt` and `ca.key` read-only into the proxy beside the leaf, named by two new
  variables, `EGRESS_TLS_CA_CERTIFICATE` and `EGRESS_TLS_CA_PRIVATE_KEY`, and passes neither under
  any other profile.

The project CA is not touched by such a launch: its reissue schedule, its cached leaf and the
sessions of other profiles are as they were.

## The proxy

- **Minting.** On the first `CONNECT` to an admitted host without a scope, a leaf for that one
  name — EC P-256, `SHA256withECDSA`, `serverAuth`, validity the run's — signed by the run CA and
  kept in a per-run map; the second connection reuses it. One `SSLContext` per leaf, chosen by the
  `CONNECT` host, which the existing SNI check already proves equal to the name the client will
  verify. Keypair generation is milliseconds; the map is bounded by the hosts a session reaches.
- **The X.509 builder.** The proxy has no dependency today and JCA cannot build a certificate
  (`build.sbt` records why the launcher depends on `bcpkix`). Two ways: add `bcpkix` to the proxy's
  build and its native-image configuration, or write the TBSCertificate DER by hand — a
  sequence of a dozen fields, signed through JCA's `Signature` — with the launcher's BouncyCastle
  parser as the test oracle. The recommendation is the encoder: it is small, it keeps the image
  dependency-free, and a certificate the JDK's own `CertificateFactory` parses and the launcher's
  `parseCertificate` accepts is the whole acceptance test. Decide at implementation if the
  encoder's size passes two hundred lines.
- **The tunnel decision** moves from "no scope → tunnel" to "no scope → inspect as `read`", and
  `TlsInspection.inspects` answers by the static set or the minted map. The audit line for a
  tunnel stays the `CONNECT` alone; a read on an unlisted host logs its method and target like
  any inspected request, with the reason `read (the public-HTTPS default)` where the log names
  the scope.
- **Fail closed everywhere new.** A leaf that cannot be minted, a signature that fails, a CA key
  that does not answer its certificate: the connection is refused and logged as `error`, never
  tunnelled through.

## Documents

- `doc/egress-proxy.md`, "Choosing an egress profile": the item's mechanics sentence and the
  "not consulted" sentence; "TLS inspection": the run CA.
- SECURITY.md: "Who holds the CA key" gains the profile's exception with the trade above, in that
  order — the run scope, then what a compromise gains; "Adding hosts, not patterns" keeps the
  unmintable argument for a wildcard *grant* (the static leaf still enumerates its names) and
  says where minting is dynamic and why that is not a grant; the audit samples gain a read
  on an unlisted host; "What is inside TLS" is unchanged, the tunnels being the same hosts.
- The agent's authority section under the profile: "reachable for reading, inspected and logged;
  the hosts listed with `tunnel` opaque; the hosts under a `deny` line refused" — and the
  refused-on-purpose closing stays.
- The launch banner keeps the red: every public host is still admitted, and the URL channel
  with it.
- The `--help` text, if its profile summary names the tunnel default.

## Tests

- Proxy: a minted leaf parses in JCA and in BouncyCastle, chains to the run CA, names the host
  and nothing else, and is reused on the second connection; a `POST` to an unlisted host is a
  `403` with the reason and a `deny` line, a `GET` is relayed and logged with its target; a
  project's `tunnel` line under the profile stays an opaque tunnel; `deny defaults` under the
  profile makes the model endpoints inspected reads; the three identity checks each refuse a
  start; a CA key that does not match its certificate refuses a start.
- Launcher: the run CA is minted under this profile alone, lives in the run directory, is pruned
  with it, is what the bundle and the JDK store hold, and is what the static leaf chains to; no
  CA key is mounted under the other three profiles (`AgentSandboxLauncherTest`, the mount
  argument tests).
- Integration (`EgressPolicyTest`, a launch with `--egress=allow-unless-denied`): an unlisted
  host answers a `GET` and refuses a `POST`, and presents the run CA's leaf; a defaults tunnel
  host presents the origin's own certificate — the treatments told apart by the certificate,
  as the session test already phrases it.

## Delivery order

1. The resolver: every line consulted, the tunnel hosts kept, the special case removed, the
   profile line — with the proxy tests, under the current tunnel treatment, so the policy change
   lands and is reviewed alone.
1. The X.509 encoder, or `bcpkix`, with the parse-and-chain tests.
1. The proxy's minting path and identity checks; the treatment flip.
1. The launcher's run CA, mounts and bundle; the integration test.
1. The documents and the agent's text.

## Deliberate exclusions

- **Minting under any other profile.** No CA key enters the container there; the static leaf
  remains the whole inspected set, and a wildcard grant remains unmintable.
- **A signing broker on the host** — the proxy asking the launcher to sign each leaf, the key
  never leaving the host. It keeps the letter of "Who holds the CA key" and loses its sense: the
  broker is a signing oracle for whatever the proxy asks, so the key's location no longer bounds
  what a compromised proxy can mint, only where the bytes sit; and it adds a channel and a
  round trip per host. The run scope bounds the same thing better.
- **`git-fetch` or `method=` on unlisted hosts.** Unlisted hosts being read-only is the point;
  a clone from an unlisted forge is one line the project writes and reviews.
- **Caching minted leaves across runs.** They die with the CA that signed them.
